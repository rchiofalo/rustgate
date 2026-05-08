// Copyright © 2026 Roberto Chiofalo.

//! Integration round-trip tests for the Link 16 / JREAP-C codec.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};
use rustgate_link16::{
    IffCodes, J2_2AirTrack, JREAP_DEFAULT_TCP_PORT, JREAP_HEADER_LEN, JreapFrame, JreapMessageType,
    JseriesKinematics, JseriesMessage, LINK16_PREFIX, Link16Codec, Link16EntityError, Link16Error,
    PlatformType,
};

fn sample_track() -> J2_2AirTrack {
    J2_2AirTrack {
        track_number: 0xCAFE_F00D,
        latitude_micro_deg: 38_897_700, // White House, DC.
        longitude_micro_deg: -77_036_500,
        altitude_m: 8_500,
        platform_type: PlatformType::Aircraft,
        iff: IffCodes {
            status_byte: 0b0000_0010,
            mode_3_code: 0o7700, // emergency squawk
        },
        kinematics: JseriesKinematics {
            speed_cm_s: 30_000,
            course_centideg: 18_000, // due south
            climb_rate_dm_s: 25,
        },
    }
}

fn build_frame(track: &J2_2AirTrack) -> Bytes {
    let mut body: Vec<u8> = Vec::new();
    track.encode_into(&mut body).expect("encode body");
    let header = JreapFrame::new(JreapMessageType::JseriesData, body.len() as u32);
    let mut out: Vec<u8> = Vec::new();
    header.encode_into(&mut out);
    out.extend_from_slice(&body);
    Bytes::from(out)
}

#[test]
fn full_wire_round_trip_preserves_every_field() {
    let track = sample_track();
    let frame = build_frame(&track);

    // Wire-layer round-trip via the lower-level entry points.
    let header = JreapFrame::decode(&frame).expect("frame decode");
    assert_eq!(header.version, rustgate_link16::JREAP_C_VERSION);
    assert_eq!(header.message_type, JreapMessageType::JseriesData);

    let body = &frame[JREAP_HEADER_LEN..];
    let message = JseriesMessage::decode(body).expect("body decode");
    let decoded_track = match message {
        JseriesMessage::J2_2AirTrack(t) => t,
        JseriesMessage::Other { label, .. } => panic!("unexpected J-series label {label:#04x}"),
    };
    assert_eq!(decoded_track, track);

    // EntityCodec round-trip — same-codec must be byte-exact.
    let entity = Link16Codec.to_entity(&frame).expect("to_entity");
    let re_encoded = Link16Codec.from_entity(&entity).expect("from_entity");
    assert_eq!(re_encoded.as_ref(), frame.as_ref());
}

#[test]
fn unknown_jseries_label_passes_through_as_opaque() {
    // A multi-message stream may carry a J3.5 (Land Point) frame; the
    // MVP routes it as opaque bytes via JseriesMessage::Other so a
    // multi-message TCP stream can still be framed past unknown
    // labels.
    let mut body: Vec<u8> = vec![0u8; 16];
    body[0] = 0x35;
    body[1..].copy_from_slice(&[0xAA; 15]);
    let header = JreapFrame::new(JreapMessageType::JseriesData, body.len() as u32);
    let mut frame: Vec<u8> = Vec::new();
    header.encode_into(&mut frame);
    frame.extend_from_slice(&body);

    let parsed = JseriesMessage::decode(&body).expect("parse opaque body");
    match parsed {
        JseriesMessage::Other {
            label,
            body: opaque,
        } => {
            assert_eq!(label, 0x35);
            assert_eq!(opaque.as_ref(), body.as_slice());
        }
        JseriesMessage::J2_2AirTrack(_) => panic!("J3.5 must not parse as J2.2"),
    }

    // EntityCodec surface returns an UnsupportedJseriesLabel for the
    // operator log.
    let err = Link16Codec.to_entity(&frame).expect_err("must fail");
    assert!(matches!(
        err,
        Link16EntityError::UnsupportedJseriesLabel(0x35)
    ));
}

#[test]
fn cross_codec_entity_encodes_with_derived_track_number() {
    // An Entity from another codec (e.g. CoT) does not carry the
    // `link16.j2_2.*` integer attributes; the encoder must still
    // succeed by deriving the track-number from the UID and the
    // position fields from the float carriers.
    let entity = Entity {
        uid: "cross-codec-uid".into(),
        kind: EntityKind::Aircraft,
        position: Some(Position {
            lat: 40.0,
            lon: -74.0,
            hae_meters: Some(1_000.0),
        }),
        velocity: Some(Velocity {
            speed_m_s: 200.0,
            course_deg: 270.0,
        }),
        timestamp: SystemTime::now(),
        callsign: Some("alpha".into()),
        mil_std_2525_sidc: None,
        attributes: BTreeMap::new(),
    };
    let frame = Link16Codec.from_entity(&entity).expect("encode");
    let header = JreapFrame::decode(&frame).expect("header decode");
    assert_eq!(header.body_length as usize, J2_2AirTrack::BODY_LEN);
    assert_eq!(header.message_type, JreapMessageType::JseriesData);

    // Decoding back must yield the same lat/lon (within microdegree
    // precision) and the same speed/course (within centidegree
    // precision).
    let decoded = Link16Codec.to_entity(&frame).expect("decode");
    let pos = decoded.position.expect("position");
    assert!((pos.lat - 40.0).abs() < 1e-6);
    assert!((pos.lon - (-74.0)).abs() < 1e-6);
    let v = decoded.velocity.expect("velocity");
    assert!((v.speed_m_s - 200.0).abs() < 1e-2);
    assert!((v.course_deg - 270.0).abs() < 1e-2);
}

#[test]
fn unsupported_version_rejected_at_frame_layer() {
    // A JREAP-A frame (`0x01`) on a JREAP-C connection must be
    // rejected rather than mis-parsed.
    let mut frame = vec![0u8; JREAP_HEADER_LEN + J2_2AirTrack::BODY_LEN];
    frame[0] = 0x01;
    let err = JreapFrame::decode(&frame).expect_err("must fail");
    assert!(matches!(
        err,
        Link16Error::UnsupportedVersion {
            got: 0x01,
            expected: 0x03
        }
    ));
}

#[test]
fn frame_layer_truncated_body_surfaces_typed_error() {
    // The header declares 32 bytes of body but the buffer carries
    // only 10. The EntityCodec surface must yield an
    // `InvalidFrame` rather than silently truncating.
    let header = JreapFrame::new(JreapMessageType::JseriesData, 32);
    let mut frame: Vec<u8> = Vec::new();
    header.encode_into(&mut frame);
    frame.extend_from_slice(&[0u8; 10]);
    let err = Link16Codec.to_entity(&frame).expect_err("must fail");
    assert!(matches!(err, Link16EntityError::InvalidFrame(_)));
}

#[test]
fn attribute_carry_round_trips_track_number_exactly() {
    // An Entity with an explicit `link16.j2_2.track_number` carries
    // a different value from the UID-derived fallback — the explicit
    // attribute must win.
    let mut attributes = BTreeMap::new();
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.track_number"),
        AttributeValue::Int(0x4242_4242),
    );
    let entity = Entity {
        uid: "link16-deadbeef".into(),
        kind: EntityKind::Aircraft,
        position: Some(Position {
            lat: 0.0,
            lon: 0.0,
            hae_meters: Some(0.0),
        }),
        velocity: None,
        timestamp: SystemTime::now(),
        callsign: None,
        mil_std_2525_sidc: None,
        attributes,
    };
    let frame = Link16Codec.from_entity(&entity).expect("encode");
    let body = &frame[JREAP_HEADER_LEN..];
    let parsed = match JseriesMessage::decode(body).expect("decode") {
        JseriesMessage::J2_2AirTrack(t) => t,
        JseriesMessage::Other { .. } => panic!("expected J2.2"),
    };
    assert_eq!(parsed.track_number, 0x4242_4242);
}

#[test]
fn default_tcp_port_constant_is_4444() {
    // Pinning the constant guards against drift when a future
    // listener-wiring PR threads it through a config struct.
    assert_eq!(JREAP_DEFAULT_TCP_PORT, 4444);
}
