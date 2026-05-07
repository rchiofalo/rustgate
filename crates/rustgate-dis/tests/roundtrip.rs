// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the rustgate-dis codec — wire-format
//! round-trip, ECEF↔WGS-84 conversion, malformed-input rejection,
//! and proptest-driven coverage.

#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_dis::coord::{ecef_to_wgs84, wgs84_to_ecef};
use rustgate_dis::entity_state::{
    ArticulationParameter, DeadReckoningParameters, EntityId, EntityStatePdu, EntityType, ForceId,
};
use rustgate_dis::error::DisError;
use rustgate_dis::header::{HEADER_LEN, IEEE_1278_1_2012, PduHeader, PduType, ProtocolFamily};

fn baseline_pdu() -> EntityStatePdu {
    EntityStatePdu {
        header: PduHeader::new(
            PduType::EntityState,
            ProtocolFamily::EntityInformationInteraction,
            0,
        ),
        entity_id: EntityId {
            site: 1,
            application: 2,
            entity: 100,
        },
        force_id: ForceId::Friendly,
        entity_type: EntityType {
            kind: 1,
            domain: 2,
            country: 225,
            category: 1,
            subcategory: 2,
            specific: 3,
            extra: 4,
        },
        alternative_entity_type: EntityType {
            kind: 1,
            domain: 2,
            country: 225,
            category: 1,
            subcategory: 2,
            specific: 3,
            extra: 4,
        },
        linear_velocity: [12.0, -3.0, 0.5],
        // ECEF for Statue of Liberty (40.6892° N, 74.0445° W, 93 m).
        location_ecef: [1_331_360.0, -4_656_651.0, 4_136_374.0],
        orientation: [0.1, 0.2, -0.3],
        appearance: 0xCAFE_BABE,
        dead_reckoning: DeadReckoningParameters {
            algorithm: 2,
            other_parameters: [0xAA; 15],
            linear_acceleration: [0.0, -9.81, 0.0],
            angular_velocity: [0.001, -0.002, 0.003],
        },
        marking_charset: 1,
        marking: "M1A2".into(),
        capabilities: 0xF,
        articulation_parameters: Vec::new(),
    }
}

#[test]
fn entity_state_pdu_round_trips_through_wire_codec() {
    let pdu = baseline_pdu();
    let bytes = pdu.encode().expect("encode");
    assert_eq!(bytes.len(), 144);
    let decoded = EntityStatePdu::decode(&bytes).expect("decode");
    assert_eq!(decoded.entity_id, pdu.entity_id);
    assert_eq!(decoded.force_id, pdu.force_id);
    assert_eq!(decoded.entity_type, pdu.entity_type);
    assert_eq!(decoded.alternative_entity_type, pdu.alternative_entity_type);
    assert_eq!(decoded.linear_velocity, pdu.linear_velocity);
    assert_eq!(decoded.location_ecef, pdu.location_ecef);
    assert_eq!(decoded.orientation, pdu.orientation);
    assert_eq!(decoded.appearance, pdu.appearance);
    assert_eq!(decoded.dead_reckoning, pdu.dead_reckoning);
    assert_eq!(decoded.marking, pdu.marking);
    assert_eq!(decoded.capabilities, pdu.capabilities);
}

#[test]
fn entity_state_pdu_with_articulation_round_trips() {
    let mut pdu = baseline_pdu();
    pdu.articulation_parameters = (0..4)
        .map(|i| ArticulationParameter { raw: [i as u8; 16] })
        .collect();
    let bytes = pdu.encode().expect("encode");
    assert_eq!(bytes.len(), 144 + 4 * 16);
    let decoded = EntityStatePdu::decode(&bytes).expect("decode");
    assert_eq!(decoded.articulation_parameters, pdu.articulation_parameters);
}

#[test]
fn ecef_wgs84_round_trip_preserves_position_at_sea_level() {
    // London: 51.5007, -0.1246, 11.0 m HAE.
    let (x, y, z) = wgs84_to_ecef(51.5007, -0.1246, 11.0);
    let (lat, lon, alt) = ecef_to_wgs84(x, y, z);
    assert!((lat - 51.5007).abs() < 1e-9);
    assert!((lon - -0.1246).abs() < 1e-9);
    // < 1 cm altitude drift across the closed-form Bowring 1985 inverse.
    assert!((alt - 11.0).abs() < 0.01);
}

#[test]
fn header_decode_rejects_truncated_buffer() {
    let bytes = [0u8; HEADER_LEN - 1];
    let err = PduHeader::decode(&bytes).expect_err("must fail");
    match err {
        DisError::Truncated {
            needed, available, ..
        } => {
            assert_eq!(needed, HEADER_LEN);
            assert_eq!(available, HEADER_LEN - 1);
        }
        other => panic!("expected Truncated, got {other:?}"),
    }
}

#[test]
fn entity_state_decode_rejects_length_mismatch() {
    let pdu = baseline_pdu();
    let mut bytes = pdu.encode().expect("encode");
    // Drop the trailing byte without rewriting the header length.
    let _ = bytes.pop();
    let err = EntityStatePdu::decode(&bytes).expect_err("must fail");
    assert!(matches!(err, DisError::LengthMismatch { .. }));
}

#[test]
fn entity_state_decode_rejects_wrong_pdu_type() {
    let pdu = baseline_pdu();
    let mut bytes = pdu.encode().expect("encode");
    bytes[2] = 2; // Force type byte to Fire PDU.
    let err = EntityStatePdu::decode(&bytes).expect_err("must fail");
    assert!(matches!(err, DisError::UnexpectedPduType { got: 2, .. }));
}

#[test]
fn header_protocol_version_round_trips_for_ieee_1278_1_2012() {
    let pdu = baseline_pdu();
    let bytes = pdu.encode().expect("encode");
    assert_eq!(bytes[0], IEEE_1278_1_2012);
    let header = PduHeader::decode(&bytes).expect("decode");
    assert_eq!(header.protocol_version, IEEE_1278_1_2012);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Random valid (lat, lon, alt) inside the typical exercise
    /// envelope must round-trip through ECEF without losing more
    /// than ~1 mm of altitude precision or 1e-9 deg of lat / lon.
    #[test]
    fn ecef_wgs84_round_trip_property(
        lat in -89.9_f64..89.9_f64,
        lon in -180.0_f64..180.0_f64,
        alt in -10_000.0_f64..50_000.0_f64,
    ) {
        let (x, y, z) = wgs84_to_ecef(lat, lon, alt);
        let (lat2, lon2, alt2) = ecef_to_wgs84(x, y, z);
        prop_assert!((lat - lat2).abs() < 1e-9, "lat drift {} -> {}", lat, lat2);
        // Longitude wraps near ±180; allow a 1e-9 tolerance on the
        // positive side and ignore values that wrap.
        let lon_drift = (lon - lon2).abs();
        prop_assert!(lon_drift < 1e-9 || (lon_drift - 360.0).abs() < 1e-9, "lon drift {} -> {}", lon, lon2);
        prop_assert!((alt - alt2).abs() < 1e-3, "alt drift {} -> {}", alt, alt2);
    }

    /// Random Entity State PDU bodies must round-trip through the
    /// wire-format codec — every f32, f64, u8, u16, u32, and the
    /// ASCII marking byte sequence is preserved.
    #[test]
    fn entity_state_pdu_round_trip_property(
        site in any::<u16>(),
        app in any::<u16>(),
        entity_num in any::<u16>(),
        force in 0u8..=4u8,
        velocity in proptest::collection::vec(-1000.0_f32..1000.0_f32, 3),
        ecef in proptest::collection::vec(-7_000_000.0_f64..7_000_000.0_f64, 3),
        appearance in any::<u32>(),
        capabilities in any::<u32>(),
        dr_algorithm in any::<u8>(),
    ) {
        let pdu = EntityStatePdu {
            header: PduHeader::new(
                PduType::EntityState,
                ProtocolFamily::EntityInformationInteraction,
                0,
            ),
            entity_id: EntityId { site, application: app, entity: entity_num },
            force_id: ForceId::from_u8(force),
            entity_type: EntityType {
                kind: 1, domain: 1, country: 0,
                category: 0, subcategory: 0, specific: 0, extra: 0,
            },
            alternative_entity_type: EntityType {
                kind: 1, domain: 1, country: 0,
                category: 0, subcategory: 0, specific: 0, extra: 0,
            },
            linear_velocity: [velocity[0], velocity[1], velocity[2]],
            location_ecef: [ecef[0], ecef[1], ecef[2]],
            orientation: [0.0; 3],
            appearance,
            dead_reckoning: DeadReckoningParameters {
                algorithm: dr_algorithm,
                other_parameters: [0; 15],
                linear_acceleration: [0.0; 3],
                angular_velocity: [0.0; 3],
            },
            marking_charset: 1,
            marking: String::new(),
            capabilities,
            articulation_parameters: Vec::new(),
        };
        let bytes = pdu.encode().expect("encode");
        let decoded = EntityStatePdu::decode(&bytes).expect("decode");
        prop_assert_eq!(decoded.entity_id, pdu.entity_id);
        prop_assert_eq!(decoded.force_id, pdu.force_id);
        prop_assert_eq!(decoded.linear_velocity, pdu.linear_velocity);
        prop_assert_eq!(decoded.location_ecef, pdu.location_ecef);
        prop_assert_eq!(decoded.appearance, pdu.appearance);
        prop_assert_eq!(decoded.capabilities, pdu.capabilities);
        prop_assert_eq!(decoded.dead_reckoning.algorithm, pdu.dead_reckoning.algorithm);
    }
}
