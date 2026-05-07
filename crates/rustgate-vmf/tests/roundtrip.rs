// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the VMF codec — end-to-end wire round-trips
//! that exercise [`rustgate_vmf::VmfCodec`] through the full
//! decode → re-encode → decode pipeline. These complement the
//! per-module unit tests in `src/bitstream.rs`, `src/header.rs`,
//! `src/k05_1.rs`, and `src/codec.rs` by validating the public
//! surface a downstream router consumer would see.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::SystemTime;

use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};
use rustgate_vmf::{
    Classification, Dtg, K051PositionReport, MessageId, VMF_HEADER_VERSION, VmfCodec,
    VmfEntityError, VmfHeader, VmfMessage, decode_message, encode_k05_1,
};

#[test]
fn k05_1_full_round_trip_through_entity_codec() {
    let codec = VmfCodec;
    let header = VmfHeader {
        version: VMF_HEADER_VERSION,
        originator_urn: 0x12_3456,
        recipient_urn: Some(0xAB_CDEF),
        message_id: Some(MessageId::K05_1),
        classification: Classification::Confidential,
        dtg: Some(Dtg {
            posix_seconds: 1_700_000_000,
            microseconds: 750_000,
        }),
    };
    let body = K051PositionReport {
        reporting_urn: 0x12_3456,
        latitude_deg: 38.879_5,
        longitude_deg: -77.103_4,
        altitude_m: Some(45),
        speed_m_per_s: Some(2.7),
        course_deg: Some(187.5),
        unit_identifier: Some("BRAVO2".into()),
    };
    let frame = encode_k05_1(&header, &body).expect("encode");

    let entity = codec.to_entity(&frame).expect("decode 1");
    assert_eq!(entity.uid, "vmf-00123456");
    assert_eq!(entity.callsign.as_deref(), Some("BRAVO2"));

    let frame2 = codec.from_entity(&entity).expect("re-encode");
    let entity2 = codec.to_entity(&frame2).expect("decode 2");
    assert_eq!(entity.uid, entity2.uid);
    let p1 = entity.position.expect("position 1");
    let p2 = entity2.position.expect("position 2");
    assert!((p1.lat - p2.lat).abs() < 1e-4);
    assert!((p1.lon - p2.lon).abs() < 1e-4);
    let v1 = entity.velocity.expect("velocity 1");
    let v2 = entity2.velocity.expect("velocity 2");
    assert!((v1.speed_m_s - v2.speed_m_s).abs() < 0.1);
    assert!((v1.course_deg - v2.course_deg).abs() < 1.0);
}

#[test]
fn unknown_message_type_decodes_header_keeps_body() {
    // K06.1-style header + body. Wire form survives the round-trip
    // even though the codec does not yet decode this body type.
    let header = VmfHeader {
        version: VMF_HEADER_VERSION,
        originator_urn: 1,
        recipient_urn: None,
        message_id: Some(MessageId {
            fad: 0,
            msg_num: 6,
            subnumber: 1,
        }),
        classification: Classification::Unclassified,
        dtg: None,
    };
    let mut w = rustgate_vmf::BitWriter::new();
    header.encode(&mut w).expect("encode header");
    w.write_bytes(&[0xCA, 0xFE, 0xBA, 0xBE]);
    let bytes = w.into_bytes();

    let (decoded_header, message) = decode_message(&bytes).expect("decode");
    assert_eq!(decoded_header.originator_urn, 1);
    match message {
        VmfMessage::Unknown { message_type, body } => {
            assert_ne!(message_type, MessageId::K05_1.as_u16());
            assert!(body.contains(&0xCA));
        }
        other => panic!("expected Unknown message, got {other:?}"),
    }
}

#[test]
fn encode_from_entity_carries_attributes_into_header() {
    // An Entity with `vmf.recipient_urn` and `vmf.dtg_posix_seconds`
    // attributes must produce a wire frame whose header round-trips
    // those values.
    let codec = VmfCodec;
    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    let _ = attributes.insert("vmf.recipient_urn".into(), AttributeValue::Int(0x55_6677));
    let _ = attributes.insert(
        "vmf.dtg_posix_seconds".into(),
        AttributeValue::Int(1_700_000_000),
    );
    let _ = attributes.insert("vmf.classification".into(), AttributeValue::Int(2));
    let entity = Entity {
        uid: "vmf-00112233".into(),
        kind: EntityKind::Ground,
        position: Some(Position {
            lat: 38.0,
            lon: -77.0,
            hae_meters: Some(50.0),
        }),
        velocity: Some(Velocity {
            speed_m_s: 5.0,
            course_deg: 180.0,
        }),
        timestamp: SystemTime::UNIX_EPOCH,
        callsign: Some("CHARLIE".into()),
        mil_std_2525_sidc: None,
        attributes,
    };

    let frame = codec.from_entity(&entity).expect("encode");
    let entity2 = codec.to_entity(&frame).expect("decode");
    assert_eq!(
        entity2.attributes.get("vmf.recipient_urn"),
        Some(&AttributeValue::Int(0x55_6677))
    );
    assert_eq!(
        entity2.attributes.get("vmf.classification_label"),
        Some(&AttributeValue::Str("secret".into()))
    );
    assert_eq!(
        entity2.attributes.get("vmf.dtg_posix_seconds"),
        Some(&AttributeValue::Int(1_700_000_000))
    );
}

#[test]
fn malformed_frame_returns_typed_error_no_panic() {
    let codec = VmfCodec;
    // 2 bytes — too short for even the version + compression FPI +
    // header-size fields, let alone the 24-bit URN.
    let bytes = [0x10u8, 0x00];
    let err = codec.to_entity(&bytes).expect_err("must fail");
    assert!(matches!(err, VmfEntityError::Decode(_)));
}
