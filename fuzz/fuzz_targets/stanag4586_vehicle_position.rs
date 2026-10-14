// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the STANAG 4586 LOI 2-3 vehicle-position decoder.
//!
//! `rustgate_stanag4586::vehicle_position::decode` accepts an arbitrary
//! byte slice from the wire and returns a typed `VehiclePosition` or a
//! `Stanag4586Error`. Several traits make it worth fuzzing:
//!
//! - The 48-byte fixed wire frame is decoded from `bytes::Buf` cursor
//!   primitives that panic on under-read; an off-by-one on the
//!   `FrameTooShort` length guard would surface as a panic before the
//!   first useful byte is read.
//! - Two reserved blocks (3 bytes between `flight_state` and lat/lon, 4
//!   bytes between heading and timestamp) are zero-filled on encode but
//!   accepted-without-validation on decode for forward compatibility —
//!   the decoder must therefore tolerate any byte pattern in those
//!   regions including patterns that look like valid IEEE-754 floats
//!   straddling the field boundary.
//! - Lat/lon range checks (`lat ∈ [-90, 90]`, `lon ∈ [-180, 180]`)
//!   surface as `FieldOutOfRange` rather than silent clamping. The
//!   check uses `is_finite()` defensively — a regression that dropped
//!   the NaN guard would let NaN flow through (NaN comparisons are
//!   always false, so a naive range check accepts it).
//! - `FlightState::Other(u8)` round-trips arbitrary bytes; a regression
//!   in the named-variant table would surface as a corrupted variant
//!   on decode.
//!
//! The fuzz target also exercises **self-stability**: every `Ok(_)`
//! return must round-trip through `encode → decode` byte-identical.
//! A regression that, say, swapped the encode-side endianness without
//! updating decode would fail this invariant.
//!
//! Truncation, range violations, and NaN are all *expected* error
//! paths; the fuzzer's job is to make sure they don't panic or
//! underflow on the way out.

use libfuzzer_sys::fuzz_target;
use rustgate_stanag4586::vehicle_position;

fuzz_target!(|data: &[u8]| {
    let Ok(decoded) = vehicle_position::decode(data) else {
        // Truncation / range / NaN-on-validated-fields — all in scope
        // for the documented error surface; the fuzzer's job is to
        // make sure they don't panic. No further action.
        return;
    };
    // Self-stability: a successful decode round-trips through
    // encode → decode bit-identical. A regression in either direction
    // (endianness flip on encode, off-by-one offset on decode) fails
    // here.
    let bytes = vehicle_position::encode(&decoded);
    let again = vehicle_position::decode(&bytes)
        .expect("re-decode of own encoded output must succeed");
    // NaN handling: by design, the decoder validates `latitude_deg`
    // and `longitude_deg` against `is_finite()` (so NaN never makes
    // it past `decode`), but `altitude_msl_m`, `ground_speed_mps`,
    // and `heading_deg` are intentionally **not** range-checked
    // because senders may transmit signed or unwrapped values during
    // turn integration / in-flight calibration. A NaN that flows
    // through any of those three fields is therefore legal-decode-
    // output, but `NaN != NaN` per IEEE-754, so a direct
    // `assert_eq!` comparison spuriously fails. Compare via
    // `to_be_bytes` so equal NaN bit patterns round-trip cleanly,
    // which is the actually-load-bearing property: a regression in
    // encode/decode that perturbs the wire bytes will still fail
    // loudly.
    assert_eq!(
        decoded.vehicle_id, again.vehicle_id,
        "vehicle_id must round-trip"
    );
    assert_eq!(
        decoded.flight_state, again.flight_state,
        "flight_state must round-trip"
    );
    assert_eq!(
        decoded.latitude_deg.to_be_bytes(),
        again.latitude_deg.to_be_bytes(),
        "latitude_deg must round-trip bit-identical"
    );
    assert_eq!(
        decoded.longitude_deg.to_be_bytes(),
        again.longitude_deg.to_be_bytes(),
        "longitude_deg must round-trip bit-identical"
    );
    assert_eq!(
        decoded.altitude_msl_m.to_be_bytes(),
        again.altitude_msl_m.to_be_bytes(),
        "altitude_msl_m must round-trip bit-identical (NaN-tolerant)"
    );
    assert_eq!(
        decoded.ground_speed_mps.to_be_bytes(),
        again.ground_speed_mps.to_be_bytes(),
        "ground_speed_mps must round-trip bit-identical (NaN-tolerant)"
    );
    assert_eq!(
        decoded.heading_deg.to_be_bytes(),
        again.heading_deg.to_be_bytes(),
        "heading_deg must round-trip bit-identical (NaN-tolerant)"
    );
    assert_eq!(
        decoded.timestamp_unix_ms, again.timestamp_unix_ms,
        "timestamp_unix_ms must round-trip"
    );
});
