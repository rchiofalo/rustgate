// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the SAPIENT codec.
//!
//! Mirrors the `tests/` shape used by the other codec crates in the
//! workspace (rustgate-cot, rustgate-mavlink, rustgate-asterix,
//! rustgate-stanag4586, rustgate-meshtastic, rustgate-vmf,
//! rustgate-dis). Pins the encode/decode round trip against the
//! public API surface so refactors to the internal helpers do not
//! silently regress wire compatibility.

#![allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp, unused_results)]

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use proptest::prelude::*;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};
use rustgate_sapient::{
    Classification, DetectionLocation, DetectionReport, EnuVelocity, Location,
    LocationCoordinateSystem, LocationDatum, MAX_PAYLOAD_BYTES, SAPIENT_FIELD_DETECTION_REPORT,
    SapientCodec, SapientError, SapientMessage, SapientPayload, Timestamp, decode_sapient_message,
    encode_sapient_message,
};

fn realistic_message() -> SapientMessage {
    SapientMessage {
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_789,
        }),
        node_id: "11111111-2222-3333-4444-555555555555".into(),
        destination_id: String::new(),
        content: Some(SapientPayload::DetectionReport(Box::new(DetectionReport {
            report_id: "01H8FF8DPXTGYP01H8FF8DPXTG01".into(),
            object_id: "01H8FF8DPXTGYP01H8FF8DPXTG02".into(),
            task_id: String::new(),
            state: String::new(),
            location: Some(DetectionLocation::Location(Location {
                x: -77.008_889,
                y: 38.889_722_2,
                z: Some(50.0),
                x_error: None,
                y_error: None,
                z_error: None,
                coordinate_system: LocationCoordinateSystem::LatLngDegM,
                datum: LocationDatum::Wgs84Ellipsoid,
                utm_zone: String::new(),
            })),
            detection_confidence: Some(0.81),
            classification: vec![Classification {
                kind: "UAV".into(),
                confidence: Some(0.78),
            }],
            enu_velocity: Some(EnuVelocity {
                east_rate: 5.0,
                north_rate: 3.0,
                up_rate: Some(0.5),
            }),
            colour: "red".into(),
            id: "tail-N12345".into(),
        }))),
        additional_information: String::new(),
    }
}

#[test]
fn detection_report_round_trip_preserves_bytes() {
    let original = realistic_message();
    let bytes = encode_sapient_message(&original).expect("encode");
    let decoded = decode_sapient_message(&bytes).expect("decode");
    assert_eq!(decoded, original);
}

#[test]
fn other_arm_round_trip_byte_exact() {
    // A future / non-MVP arm rides as `Other`. Round-trip MUST
    // preserve the bytes verbatim — that is the forward-compat
    // guarantee for the seven non-DetectionReport content arms.
    let opaque = bytes::Bytes::from_static(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x42]);
    let msg = SapientMessage {
        timestamp: None,
        node_id: "node-1".into(),
        destination_id: String::new(),
        content: Some(SapientPayload::Other {
            field_number: 6, // status_report
            bytes: opaque.clone(),
        }),
        additional_information: String::new(),
    };
    let bytes = encode_sapient_message(&msg).expect("encode");
    let decoded = decode_sapient_message(&bytes).expect("decode");
    match decoded.content {
        Some(SapientPayload::Other {
            field_number,
            bytes,
        }) => {
            assert_eq!(field_number, 6);
            assert_eq!(bytes, opaque);
        }
        other => panic!("expected Other arm, got {other:?}"),
    }
}

#[test]
fn entity_codec_round_trip_preserves_position_and_classification() {
    let codec = SapientCodec::new();
    let mut attrs: BTreeMap<String, AttributeValue> = BTreeMap::new();
    let _ = attrs.insert(
        "sapient.node_id".into(),
        AttributeValue::Str("11111111-2222-3333-4444-555555555555".into()),
    );
    let _ = attrs.insert(
        "sapient.object_id".into(),
        AttributeValue::Str("01H1OBJECT".into()),
    );
    let _ = attrs.insert(
        "sapient.report_id".into(),
        AttributeValue::Str("01H1REPORT".into()),
    );
    let _ = attrs.insert(
        "sapient.classification.0.kind".into(),
        AttributeValue::Str("UAV".into()),
    );
    let _ = attrs.insert(
        "sapient.classification.0.confidence".into(),
        AttributeValue::Float(0.78),
    );
    let _ = attrs.insert(
        "sapient.location.coordinate_system".into(),
        AttributeValue::Int(i64::from(LocationCoordinateSystem::LatLngDegM.to_wire())),
    );
    let _ = attrs.insert(
        "sapient.location.datum".into(),
        AttributeValue::Int(i64::from(LocationDatum::Wgs84Ellipsoid.to_wire())),
    );
    let original = Entity {
        uid: "sapient-01H1OBJECT".into(),
        kind: EntityKind::Aircraft,
        position: Some(Position {
            lat: 51.5074,
            lon: -0.1278,
            hae_meters: Some(100.0),
        }),
        velocity: Some(Velocity {
            speed_m_s: 12.5,
            course_deg: 45.0,
        }),
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        callsign: None,
        mil_std_2525_sidc: None,
        attributes: attrs,
    };

    let bytes = codec.from_entity(&original).expect("encode");
    let decoded = codec.to_entity(&bytes).expect("decode");
    assert_eq!(decoded.uid, original.uid);
    assert_eq!(decoded.kind, EntityKind::Aircraft);
    let p1 = original.position.expect("p1");
    let p2 = decoded.position.expect("p2");
    // SAPIENT lat/lon ride as IEEE-754 doubles — round-trip is bit-exact.
    assert_eq!(p1.lat, p2.lat);
    assert_eq!(p1.lon, p2.lon);
    assert_eq!(p1.hae_meters, p2.hae_meters);
    // Classification top should round-trip.
    let kind_attr = decoded
        .attributes
        .get("sapient.classification.top.kind")
        .or_else(|| decoded.attributes.get("sapient.classification.0.kind"))
        .expect("classification kind");
    match kind_attr {
        AttributeValue::Str(s) => assert_eq!(s, "UAV"),
        other => panic!("unexpected attr variant: {other:?}"),
    }
}

#[test]
fn malformed_inputs_return_typed_errors_no_panics() {
    let codec = SapientCodec::new();
    // Truncated varint.
    let err = codec.to_entity(&[0x80]).expect_err("truncated varint");
    assert!(matches!(
        err,
        SapientError::TruncatedVarint | SapientError::Truncated
    ));

    // Wire type 3 (deprecated) on an unknown field.
    let mut buf: Vec<u8> = Vec::new();
    let tag: u64 = (99 << 3) | 3;
    let mut value = tag;
    while value >= 0x80 {
        buf.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
    let err = codec.to_entity(&buf).expect_err("unknown wire type");
    match err {
        SapientError::UnknownWireType { wire_type } => assert_eq!(wire_type, 3),
        other => panic!("expected UnknownWireType, got {other:?}"),
    }
}

#[test]
fn over_cap_payload_returns_typed_error() {
    let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
    let err = decode_sapient_message(&oversized).expect_err("must fail");
    assert!(matches!(err, SapientError::PayloadTooLarge { .. }));
}

#[test]
fn detection_report_field_number_constant_matches_wire_form() {
    // Pin the symbolic constant against the actual on-wire field
    // number — a future schema revision that renumbered the
    // DetectionReport arm should fail this test loudly.
    assert_eq!(SAPIENT_FIELD_DETECTION_REPORT, 7);
}

#[test]
fn entity_without_position_is_unsupported() {
    let codec = SapientCodec::new();
    let entity = Entity {
        uid: "anonymous".into(),
        kind: EntityKind::Track,
        position: None,
        velocity: None,
        timestamp: SystemTime::UNIX_EPOCH,
        callsign: None,
        mil_std_2525_sidc: None,
        attributes: BTreeMap::new(),
    };
    let err = codec.from_entity(&entity).expect_err("must fail");
    assert!(matches!(err, SapientError::UnsupportedEntity(_)));
}

proptest! {
    /// Random valid lat/lon coords round-trip with bit-exact
    /// precision through the encode → decode path.
    #[test]
    fn proptest_location_round_trips_bit_exact(
        lat in -90.0_f64..=90.0_f64,
        lon in -180.0_f64..=180.0_f64,
        alt in -10_000.0_f64..=20_000.0_f64,
        confidence in 0.0_f32..=1.0_f32,
    ) {
        let dr = DetectionReport {
            report_id: "01H1".into(),
            object_id: "01H2".into(),
            location: Some(DetectionLocation::Location(Location {
                x: lon,
                y: lat,
                z: Some(alt),
                coordinate_system: LocationCoordinateSystem::LatLngDegM,
                datum: LocationDatum::Wgs84Ellipsoid,
                ..Location::default()
            })),
            detection_confidence: Some(confidence),
            ..DetectionReport::default()
        };
        let msg = SapientMessage {
            content: Some(SapientPayload::DetectionReport(Box::new(dr.clone()))),
            ..SapientMessage::default()
        };
        let bytes = encode_sapient_message(&msg).expect("encode");
        prop_assert!(bytes.len() <= MAX_PAYLOAD_BYTES);
        let decoded = decode_sapient_message(&bytes).expect("decode");
        let recovered = match decoded.content {
            Some(SapientPayload::DetectionReport(d)) => d,
            other => panic!("expected DetectionReport, got {other:?}"),
        };
        // IEEE-754 round-trip is bit-exact through the wire form.
        match (recovered.location, dr.location) {
            (Some(DetectionLocation::Location(a)), Some(DetectionLocation::Location(b))) => {
                prop_assert_eq!(a.x.to_bits(), b.x.to_bits());
                prop_assert_eq!(a.y.to_bits(), b.y.to_bits());
                prop_assert_eq!(a.z.map(f64::to_bits), b.z.map(f64::to_bits));
            }
            other => panic!("location mismatch: {other:?}"),
        }
        prop_assert_eq!(
            recovered.detection_confidence.map(f32::to_bits),
            dr.detection_confidence.map(f32::to_bits)
        );
    }
}
