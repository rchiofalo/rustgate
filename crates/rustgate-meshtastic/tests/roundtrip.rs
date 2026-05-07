// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the Meshtastic codec.
//!
//! Mirrors the `tests/` shape used by the other codec crates in the
//! workspace (rustgate-cot, rustgate-mavlink, rustgate-asterix,
//! rustgate-stanag4586). Pins the encode/decode round trip against
//! the public API surface so refactors to the internal helpers do
//! not silently regress wire compatibility.

#![allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp, unused_results)]

use std::collections::BTreeMap;
use std::time::SystemTime;

use bytes::Bytes;
use proptest::prelude::*;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};
use rustgate_meshtastic::{
    Contact, Group, MAX_PAYLOAD_BYTES, MeshtasticCodec, MeshtasticError, PayloadVariant, Pli,
    Status, TakPacket, decode_tak_packet, encode_tak_packet,
};

/// Build a representative `TakPacket` with a PLI payload, contact,
/// group, and status — the typical Meshtastic frame on a busy
/// tactical mesh.
fn realistic_packet() -> TakPacket {
    TakPacket {
        is_compressed: false,
        contact: Some(Contact {
            callsign: "Bravo-1".into(),
            device_callsign: "!a1b2c3d4".into(),
        }),
        group: Some(Group { role: 1, team: 2 }),
        status: Some(Status { battery: 73 }),
        payload_variant: Some(PayloadVariant::Pli(Pli::from_position_floats(
            38.889_722_2,
            -77.008_889,
            100.0,
            5.0,
            90.0,
        ))),
    }
}

#[test]
fn pli_round_trip_preserves_position_within_lsb() {
    let original = realistic_packet();
    let bytes = encode_tak_packet(&original).expect("encode");
    assert!(
        bytes.len() <= MAX_PAYLOAD_BYTES,
        "encoded {} bytes > cap {MAX_PAYLOAD_BYTES}",
        bytes.len()
    );
    let decoded = decode_tak_packet(&bytes).expect("decode");
    assert_eq!(decoded, original, "round-trip mismatch");
}

#[test]
fn pli_only_entity_fits_well_inside_cap() {
    // Pin the field-pruning behaviour: a position-bearing entity
    // with only the essential PLI fields populated should encode
    // to well under the 237-byte cap. If a future change adds
    // mandatory framing overhead that pushes a minimal frame above
    // ~50 bytes we want the test to fail here so the cost is
    // visible.
    let codec = MeshtasticCodec::new();
    let entity = Entity {
        uid: "meshtastic-!feedface".into(),
        kind: EntityKind::Ground,
        position: Some(Position {
            lat: 0.0,
            lon: 0.0,
            hae_meters: None,
        }),
        velocity: None,
        timestamp: SystemTime::UNIX_EPOCH,
        callsign: None,
        mil_std_2525_sidc: None,
        attributes: BTreeMap::new(),
    };
    let bytes: Bytes = codec.from_entity(&entity).expect("encode");
    assert!(
        bytes.len() < 50,
        "minimal PLI entity encoded to {} bytes — expected < 50",
        bytes.len()
    );
    assert!(bytes.len() <= MAX_PAYLOAD_BYTES);
}

#[test]
fn payload_too_large_is_rejected() {
    // Build a packet with an oversized opaque detail blob. The
    // encoder must surface PayloadTooLarge rather than emit a
    // frame the transport will refuse.
    let packet = TakPacket {
        is_compressed: false,
        contact: None,
        group: None,
        status: None,
        payload_variant: Some(PayloadVariant::Detail(vec![0u8; MAX_PAYLOAD_BYTES + 1])),
    };
    let err = encode_tak_packet(&packet).expect_err("must fail");
    match err {
        MeshtasticError::PayloadTooLarge { bytes } => {
            assert!(bytes > MAX_PAYLOAD_BYTES);
        }
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
}

#[test]
fn malformed_inputs_return_typed_errors_no_panics() {
    let codec = MeshtasticCodec::new();
    // Truncated varint: a continuation byte with no follow-up.
    let err = codec.to_entity(&[0x80]).expect_err("truncated varint");
    assert!(matches!(
        err,
        MeshtasticError::TruncatedVarint | MeshtasticError::Truncated
    ));

    // Wire type 3 (deprecated/unused) on an unknown field.
    let mut buf: Vec<u8> = Vec::new();
    // tag = (99 << 3) | 3 → 99 * 8 + 3 = 795
    let tag: u64 = (99 << 3) | 3;
    let mut value = tag;
    while value >= 0x80 {
        buf.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
    let err = codec.to_entity(&buf).expect_err("unknown wire type");
    match err {
        MeshtasticError::UnknownWireType { wire_type } => assert_eq!(wire_type, 3),
        other => panic!("expected UnknownWireType, got {other:?}"),
    }
}

#[test]
fn entity_codec_round_trip_preserves_callsign_and_kind() {
    let codec = MeshtasticCodec::new();
    let mut attrs: BTreeMap<String, AttributeValue> = BTreeMap::new();
    let _ = attrs.insert(
        "meshtastic.contact.device_callsign".into(),
        AttributeValue::Str("!feedface".into()),
    );
    let _ = attrs.insert("meshtastic.group.role".into(), AttributeValue::Int(1));
    let _ = attrs.insert("meshtastic.status.battery".into(), AttributeValue::Int(82));
    let original = Entity {
        uid: "meshtastic-!feedface".into(),
        kind: EntityKind::Ground,
        position: Some(Position {
            lat: 51.5074,
            lon: -0.1278,
            hae_meters: Some(35.0),
        }),
        velocity: Some(Velocity {
            speed_m_s: 1.4,
            course_deg: 45.0,
        }),
        timestamp: SystemTime::UNIX_EPOCH,
        callsign: Some("Charlie-2".into()),
        mil_std_2525_sidc: None,
        attributes: attrs,
    };

    let bytes = codec.from_entity(&original).expect("encode");
    assert!(bytes.len() <= MAX_PAYLOAD_BYTES);
    let decoded = codec.to_entity(&bytes).expect("decode");

    assert_eq!(decoded.uid, original.uid);
    assert_eq!(decoded.kind, EntityKind::Ground);
    assert_eq!(decoded.callsign.as_deref(), Some("Charlie-2"));
    let p1 = original.position.expect("p1");
    let p2 = decoded.position.expect("p2");
    // sfixed32 LSB ≈ 1e-7 deg → ~1.1cm at equator. Allow 1e-6 deg.
    assert!((p1.lat - p2.lat).abs() < 1e-6, "lat drift {p1:?} {p2:?}");
    assert!((p1.lon - p2.lon).abs() < 1e-6, "lon drift {p1:?} {p2:?}");
    // Battery attribute should round-trip.
    let battery = decoded
        .attributes
        .get("meshtastic.status.battery")
        .expect("battery attr");
    assert_eq!(battery, &AttributeValue::Int(82));
}

#[test]
fn chat_only_entity_round_trips_through_codec() {
    let codec = MeshtasticCodec::new();
    let mut attrs: BTreeMap<String, AttributeValue> = BTreeMap::new();
    let _ = attrs.insert(
        "meshtastic.chat.message".into(),
        AttributeValue::Str("rendezvous at 1730".into()),
    );
    let _ = attrs.insert(
        "meshtastic.chat.to_callsign".into(),
        AttributeValue::Str("Charlie-2".into()),
    );
    let original = Entity {
        uid: "meshtastic-!feedface".into(),
        kind: EntityKind::Track,
        position: None,
        velocity: None,
        timestamp: SystemTime::UNIX_EPOCH,
        callsign: Some("Bravo-1".into()),
        mil_std_2525_sidc: None,
        attributes: attrs,
    };

    let bytes = codec.from_entity(&original).expect("encode");
    let decoded = codec.to_entity(&bytes).expect("decode");
    let msg = decoded
        .attributes
        .get("meshtastic.chat.message")
        .expect("message attr");
    assert_eq!(msg, &AttributeValue::Str("rendezvous at 1730".into()));
}

#[test]
fn compressed_oversize_chat_message_rejected_by_encoder() {
    // Build a chat-only entity with a body that, alone, exceeds the
    // 237-byte cap. The encoder must reject it cleanly.
    let codec = MeshtasticCodec::new();
    let body: String = "x".repeat(MAX_PAYLOAD_BYTES + 50);
    let mut attrs: BTreeMap<String, AttributeValue> = BTreeMap::new();
    let _ = attrs.insert("meshtastic.chat.message".into(), AttributeValue::Str(body));
    let entity = Entity {
        uid: "meshtastic-anonymous".into(),
        kind: EntityKind::Track,
        position: None,
        velocity: None,
        timestamp: SystemTime::UNIX_EPOCH,
        callsign: None,
        mil_std_2525_sidc: None,
        attributes: attrs,
    };
    let err = codec.from_entity(&entity).expect_err("must fail");
    assert!(matches!(err, MeshtasticError::PayloadTooLarge { .. }));
}

proptest! {
    /// Random valid lat/lon coords round-trip with bounded
    /// precision loss. The wire-format LSB is `1e-7` degrees
    /// (≈ 1.1 cm at the equator); we allow up to one LSB of
    /// drift after the round trip.
    #[test]
    fn proptest_pli_position_round_trips_within_lsb(
        lat in -90.0_f64..=90.0_f64,
        lon in -180.0_f64..=180.0_f64,
        alt in -10_000.0_f64..=20_000.0_f64,
        speed in 0.0_f64..=300.0_f64,
        course in 0.0_f64..360.0_f64,
    ) {
        let pli = Pli::from_position_floats(lat, lon, alt, speed, course);
        let bytes = encode_tak_packet(&TakPacket {
            payload_variant: Some(PayloadVariant::Pli(pli.clone())),
            ..TakPacket::default()
        }).expect("encode");
        prop_assert!(bytes.len() <= MAX_PAYLOAD_BYTES);
        let decoded = decode_tak_packet(&bytes).expect("decode");
        let recovered = match decoded.payload_variant {
            Some(PayloadVariant::Pli(p)) => p,
            other => panic!("expected PLI, got {other:?}"),
        };
        // Coordinate precision: ≤ 1 LSB on each axis.
        prop_assert_eq!(recovered.latitude_i, pli.latitude_i);
        prop_assert_eq!(recovered.longitude_i, pli.longitude_i);
        prop_assert_eq!(recovered.altitude, pli.altitude);
        prop_assert_eq!(recovered.speed, pli.speed);
        prop_assert_eq!(recovered.course, pli.course);
    }
}
