// Copyright © 2026 Roberto Chiofalo.

//! Schema-parity test for the STANAG 4586 vehicle-position frame.
//!
//! Validates that a [`SchemaCodec`] built from
//! `schemas/vehicle_position.yaml` produces byte-identical encodings
//! to an **inline hand-rolled reference encoder** defined in this
//! test file for every arbitrary in-range input proptest generates.
//! This is the first cross-protocol confidence test for the
//! declarative XTCE-style schema vocabulary — if it holds for
//! STANAG 4586's fixed-offset big-endian layout (a `u32` vehicle
//! id, a `u8` flight-state byte, `f64` lat/lon, `f32`
//! alt/speed/heading, and a `u64` timestamp, with two reserved
//! padding regions), the schema runtime is sufficient to drive
//! that protocol without per-codec Rust.
//!
//! ## Why the reference encoder lives in the test file
//!
//! Previously this test called [`vehicle_position::encode`] for one
//! half of the round-trip. After PR #1390 (the STANAG full port)
//! that production `encode` was itself a thin wrapper over
//! `SchemaCodec`, so this parity test was silently round-tripping
//! `SchemaCodec` against `SchemaCodec` — encoder bugs that lose data
//! symmetrically (e.g. zeroing the buffer on a finite-float
//! rejection — the #1390 / #1393 regression) passed trivially. The
//! weekly-fuzz target caught what this proptest could not (#1394).
//!
//! The fix: keep an **independent** reference encoder *inside this
//! test file*, byte-coded against the documented wire layout from
//! the schema YAML's docstring. Even if the production `encode`
//! migrates back to a SchemaCodec-driven path in the future, this
//! reference encoder stays hand-coded and the parity assertion
//! remains a genuine cross-implementation comparison.
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)` yields
//!    the same 48 bytes the inline reference encoder produces for
//!    the same logical message. The schema runtime correctly
//!    zero-fills the two reserved gaps (offsets 5..8 and 36..40)
//!    without us declaring fields there.
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)` recovers
//!    all eight numeric fields from the wire bytes, and a subsequent
//!    re-encode round-trips byte-equal.
//! 3. **Public API round-trip** — `vehicle_position::encode` →
//!    `vehicle_position::decode` preserves every typed field of
//!    `VehiclePosition`. This is the invariant the weekly-fuzz
//!    target asserts; folding it into a proptest catches regressions
//!    at compile-time rather than weekly.
//!
//! ## What this does NOT prove
//!
//! - The `FlightState` enum byte → typed-variant mapping. v1
//!   schemas don't drive value-mapping at runtime; the byte appears
//!   in `Entity::attributes` and the round-trip path re-encodes the
//!   same byte. Typed-variant projection lands in a v2 schema
//!   feature.
//! - The lat ∈ `[-90, 90]` / lon ∈ `[-180, 180]` range guards in
//!   the production decoder. The schema declares range constraints
//!   for those fields; the proptest below only exercises in-range
//!   inputs (out-of-range rejection has its own dedicated test in
//!   `src/vehicle_position.rs`).
//! - Out-of-range NaN / inf inputs on lat/lon. The schema runtime's
//!   range guard does not reject NaN; the production wrapper has
//!   its own `is_nan()` check on top. The strategy below filters
//!   NaN on lat/lon so the parity assertion is over the well-
//!   defined domain the schema runtime accepts.

#![cfg(test)]
#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_codec_schema::SchemaCodec;
use rustgate_core::entity::EntityCodec;
use rustgate_stanag4586::vehicle_position::{
    self, FlightState, VEHICLE_POSITION_FRAME_LEN, VehiclePosition,
};

const SCHEMA_YAML: &str = include_str!("../schemas/vehicle_position.yaml");

/// Build the schema codec once per test run. The schema is
/// immutable after construction so re-parsing on every iteration
/// would just be CPU waste.
fn schema_codec() -> SchemaCodec {
    SchemaCodec::from_schema_text(SCHEMA_YAML).expect("schema must parse + validate")
}

/// **Inline, independent** reference encoder for the STANAG 4586
/// vehicle-position frame. Lives in the test file rather than
/// calling `vehicle_position::encode` so the parity assertion is a
/// genuine cross-implementation comparison even if the production
/// encoder migrates to a SchemaCodec-driven path.
///
/// Byte layout (lock-step with `schemas/vehicle_position.yaml`):
///
/// ```text
/// offset │ size │ field             │ type
/// ───────┼──────┼───────────────────┼──────────────────────────
///   0    │  4   │ vehicle_id        │ u32  big-endian
///   4    │  1   │ flight_state      │ u8   raw byte
///   5    │  3   │ reserved          │ zero-padded
///   8    │  8   │ latitude_deg      │ f64  big-endian
///  16    │  8   │ longitude_deg     │ f64  big-endian
///  24    │  4   │ altitude_msl_m    │ f32  big-endian
///  28    │  4   │ ground_speed_mps  │ f32  big-endian
///  32    │  4   │ heading_deg       │ f32  big-endian
///  36    │  4   │ reserved          │ zero-padded
///  40    │  8   │ timestamp_unix_ms │ u64  big-endian
/// ```
fn reference_encode(msg: &VehiclePosition) -> Vec<u8> {
    let mut buf = vec![0u8; VEHICLE_POSITION_FRAME_LEN];
    buf[0..4].copy_from_slice(&msg.vehicle_id.to_be_bytes());
    buf[4] = msg.flight_state.to_byte();
    // 5..8 reserved — stays zero.
    buf[8..16].copy_from_slice(&msg.latitude_deg.to_be_bytes());
    buf[16..24].copy_from_slice(&msg.longitude_deg.to_be_bytes());
    buf[24..28].copy_from_slice(&msg.altitude_msl_m.to_be_bytes());
    buf[28..32].copy_from_slice(&msg.ground_speed_mps.to_be_bytes());
    buf[32..36].copy_from_slice(&msg.heading_deg.to_be_bytes());
    // 36..40 reserved — stays zero.
    buf[40..48].copy_from_slice(&msg.timestamp_unix_ms.to_be_bytes());
    buf
}

/// Strategy for a flight-state byte that exercises both the named
/// variants (0x01–0x05) and the `Other(u8)` forward-compat path.
fn flight_state_strategy() -> impl Strategy<Value = FlightState> {
    any::<u8>().prop_map(FlightState::from_byte)
}

/// Strategy for a `VehiclePosition` constrained to the domain the
/// schema runtime's encoder accepts:
///
/// - lat ∈ `[-90, 90]`, lon ∈ `[-180, 180]` (the schema declares
///   these ranges; values outside surface as `OutOfRange` on
///   encode).
/// - alt/speed/heading filtered to finite — the schema runtime's
///   hardening pass rejects non-finite floats with `OutOfRange`.
///   The production wrapper bypasses SchemaCodec on the encode side
///   to preserve NaN per the legacy contract; this parity test
///   restricts to finite values because the half it asserts on
///   (`codec.from_entity`) does not accept them.
fn vehicle_position_strategy() -> impl Strategy<Value = VehiclePosition> {
    (
        any::<u32>(),
        flight_state_strategy(),
        -90.0f64..=90.0f64,
        -180.0f64..=180.0f64,
        any::<f32>().prop_filter("finite altitude", |v| v.is_finite()),
        any::<f32>().prop_filter("finite speed", |v| v.is_finite()),
        any::<f32>().prop_filter("finite heading", |v| v.is_finite()),
        any::<u64>(),
    )
        .prop_map(
            |(
                vehicle_id,
                flight_state,
                latitude_deg,
                longitude_deg,
                altitude_msl_m,
                ground_speed_mps,
                heading_deg,
                timestamp_unix_ms,
            )| VehiclePosition {
                vehicle_id,
                flight_state,
                latitude_deg,
                longitude_deg,
                altitude_msl_m,
                ground_speed_mps,
                heading_deg,
                timestamp_unix_ms,
            },
        )
}

/// Strategy for a `VehiclePosition` permitting NaN on altitude /
/// speed / heading. Used by the public-API round-trip proptest:
/// the production codec is documented as NaN-tolerant on those
/// fields (in-flight calibration ships signed / unwrapped values),
/// and the weekly-fuzz harness exercises that path. Folding the
/// same property into a proptest catches a #1390-class regression
/// (vehicle_id silently zeroed when encode rejects NaN altitude)
/// at compile-time rather than on the next weekly-fuzz run.
fn vehicle_position_nan_tolerant_strategy() -> impl Strategy<Value = VehiclePosition> {
    (
        any::<u32>(),
        flight_state_strategy(),
        -90.0f64..=90.0f64,
        -180.0f64..=180.0f64,
        any::<f32>(), // alt: NaN/inf allowed
        any::<f32>(), // speed: NaN/inf allowed
        any::<f32>(), // heading: NaN/inf allowed
        any::<u64>(),
    )
        .prop_map(
            |(
                vehicle_id,
                flight_state,
                latitude_deg,
                longitude_deg,
                altitude_msl_m,
                ground_speed_mps,
                heading_deg,
                timestamp_unix_ms,
            )| VehiclePosition {
                vehicle_id,
                flight_state,
                latitude_deg,
                longitude_deg,
                altitude_msl_m,
                ground_speed_mps,
                heading_deg,
                timestamp_unix_ms,
            },
        )
}

proptest! {
    /// **Path (a)** — Reference encoder → `SchemaCodec` decode →
    /// `SchemaCodec` re-encode must produce the same 48 bytes the
    /// reference encoder emitted. This is the wire-format invariant:
    /// offsets are stable, byte ordering is correct, reserved regions
    /// stay zero.
    ///
    /// The reference encoder lives inline in this test file rather
    /// than calling `vehicle_position::encode`, so the parity check is
    /// a genuine cross-implementation comparison — encoder bugs in the
    /// production codec (or in SchemaCodec) cannot pass this test
    /// symmetrically.
    #[test]
    fn schema_codec_byte_identical_to_reference(msg in vehicle_position_strategy()) {
        let reference = reference_encode(&msg);
        prop_assert_eq!(reference.len(), VEHICLE_POSITION_FRAME_LEN);

        let codec = schema_codec();
        let entity = codec.to_entity(&reference).expect("schema decode");
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &reference[..]);
    }

    /// **Path (c)** — Public-API round-trip:
    /// `vehicle_position::encode` → `vehicle_position::decode` must
    /// preserve every typed field of `VehiclePosition`.
    ///
    /// This is the invariant the weekly-fuzz target asserts. Folding
    /// it into a proptest catches `#1390`-class regressions (encoder
    /// silently zeros buffer when an inner step rejects NaN, losing
    /// the perfectly-valid `vehicle_id` / `flight_state` / lat / lon /
    /// timestamp fields) at compile-time rather than weekly. NaN on
    /// alt / speed / heading is in-domain per the codec's documented
    /// contract.
    #[test]
    fn public_api_round_trip_preserves_typed_fields(
        msg in vehicle_position_nan_tolerant_strategy(),
    ) {
        let bytes = vehicle_position::encode(&msg);
        prop_assert_eq!(bytes.len(), VEHICLE_POSITION_FRAME_LEN);

        let decoded = vehicle_position::decode(&bytes).expect("public-API round-trip");

        // Typed-field assertions: every byte the encoder wrote must
        // show up at the matching offset on decode. NaN-tolerant
        // float fields use `is_nan()` because IEEE-754 NaN != NaN.
        prop_assert_eq!(decoded.vehicle_id, msg.vehicle_id);
        prop_assert_eq!(decoded.flight_state, msg.flight_state);
        prop_assert_eq!(decoded.latitude_deg, msg.latitude_deg);
        prop_assert_eq!(decoded.longitude_deg, msg.longitude_deg);
        prop_assert_eq!(decoded.timestamp_unix_ms, msg.timestamp_unix_ms);

        if msg.altitude_msl_m.is_nan() {
            prop_assert!(decoded.altitude_msl_m.is_nan());
        } else {
            prop_assert_eq!(decoded.altitude_msl_m, msg.altitude_msl_m);
        }
        if msg.ground_speed_mps.is_nan() {
            prop_assert!(decoded.ground_speed_mps.is_nan());
        } else {
            prop_assert_eq!(decoded.ground_speed_mps, msg.ground_speed_mps);
        }
        if msg.heading_deg.is_nan() {
            prop_assert!(decoded.heading_deg.is_nan());
        } else {
            prop_assert_eq!(decoded.heading_deg, msg.heading_deg);
        }
    }
}
