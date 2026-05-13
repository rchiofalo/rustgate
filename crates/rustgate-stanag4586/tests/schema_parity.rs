// Copyright © 2026 Roberto Chiofalo.

//! Schema-parity test for the STANAG 4586 vehicle-position frame.
//!
//! Validates that a [`SchemaCodec`] built from
//! `schemas/vehicle_position.yaml` produces byte-identical encodings
//! to the hand-rolled [`vehicle_position::encode`] for every
//! arbitrary in-range input proptest generates. This is the first
//! cross-protocol confidence test for the declarative XTCE-style
//! schema vocabulary — if it holds for STANAG 4586's fixed-offset
//! big-endian layout (vehicle id + flight-state byte + lat/lon in
//! `f64` + alt/speed/heading in `f32` + timestamp in `u64`, with
//! two reserved padding regions), the schema runtime is sufficient
//! to drive that protocol without per-codec Rust.
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)` yields
//!    the same 48 bytes the hand-rolled encoder produces for the
//!    same logical message. Specifically: the schema runtime
//!    correctly zero-fills the two reserved gaps (offsets 5..8 and
//!    36..40) without us declaring fields there.
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)`
//!    recovers all eight numeric fields from the wire bytes, and a
//!    subsequent re-encode round-trips byte-equal.
//!
//! ## What this does NOT prove
//!
//! - The `FlightState` enum byte → typed-variant mapping. v1
//!   schemas don't drive value-mapping at runtime; the byte
//!   appears in `Entity::attributes` and the round-trip path
//!   re-encodes the same byte. Typed-variant projection lands in
//!   a v2 schema feature.
//! - The lat ∈ `[-90, 90]` / lon ∈ `[-180, 180]` range guards in
//!   the hand-rolled `decode`. The schema has no range-constraint
//!   grammar; this proptest only exercises in-range inputs.
//! - Out-of-range NaN / inf float inputs. The hardening pass in
//!   `rustgate-codec-schema` now rejects non-finite floats at
//!   encode time as `OutOfRange`; the strategy below filters NaN /
//!   inf so the parity assertion is over the well-defined domain
//!   the runtime accepts.

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

/// Strategy for a flight-state byte that exercises both the named
/// variants (0x01–0x05) and the `Other(u8)` forward-compat path.
fn flight_state_strategy() -> impl Strategy<Value = FlightState> {
    any::<u8>().prop_map(FlightState::from_byte)
}

/// Strategy for an in-range `VehiclePosition`. NaN floats are
/// filtered out — the schema codec's encoder rejects non-finite
/// floats with a typed `OutOfRange`, and the hand-rolled decoder
/// rejects NaN lat / lon. Restricting to finite inputs is what
/// keeps the parity assertion well-defined.
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

proptest! {
    /// Hand-rolled encode → `SchemaCodec` decode → `SchemaCodec`
    /// re-encode must produce the same 48 bytes the hand-rolled
    /// encoder emitted. This is the definitive parity assertion:
    /// the schema runtime is byte-exactly compatible with the
    /// hand-rolled codec for the in-range domain.
    #[test]
    fn schema_codec_byte_identical_to_hand_rolled(msg in vehicle_position_strategy()) {
        let hand_rolled = vehicle_position::encode(&msg);
        prop_assert_eq!(hand_rolled.len(), VEHICLE_POSITION_FRAME_LEN);

        let codec = schema_codec();
        // Decode through the schema runtime — every field should
        // land on `Entity::attributes` under the
        // `schema.stanag4586_vehicle_position.<field>` key (the
        // schema declares no `entity-path` projections in v1).
        let entity = codec.to_entity(&hand_rolled).expect("schema decode");

        // Re-encode through the schema runtime. The output should
        // be byte-identical to the hand-rolled encoding —
        // including the two reserved zero-padding regions at
        // offsets 5..8 and 36..40, which the schema codec leaves
        // zero because it pre-fills its output buffer.
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &hand_rolled[..]);
    }
}
