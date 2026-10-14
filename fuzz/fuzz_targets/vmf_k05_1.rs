// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Round-trip fuzz target for the VMF K05.1 Position Report.
//!
//! Mirrors the
//! [`stanag4586_vehicle_position`][stanag-fuzz] safety net: every
//! `Ok(_)` from [`decode_message`] that produces a K05.1 must
//! survive a subsequent `encode → decode` round-trip with every
//! typed field bit-identical. The lesson from the
//! [#1393][nan-regression] STANAG 4586 NaN regression is the
//! reason this target exists: the in-tree
//! [`tests/schema_parity_k05_1.rs`][schema-parity] proptest
//! exercises the SchemaCodec path against an inline reference
//! encoder, but the **public-API round-trip** through the
//! production codec is a separate invariant. A regression that
//! silently zeros a field on encode (the #1393 STANAG pattern)
//! would pass the parity test but fail this fuzzer.
//!
//! This safety net is deliberately added **before** the
//! production K05.1 codec is migrated to a SchemaCodec-driven
//! implementation — the migration itself (a follow-up PR) is the
//! exact class of refactor #1393 surfaced as risky.
//!
//! [stanag-fuzz]: ../stanag4586_vehicle_position.rs
//! [nan-regression]: https://github.com/rchiofalo/rustgate/pull/1393
//! [schema-parity]: ../../crates/rustgate-vmf/tests/schema_parity_k05_1.rs
//!
//! # Why VMF K05.1 in particular
//!
//! - The K05.1 wire format is the most bit-dense codec in the
//!   workspace (172 bits in the all-fields-present case, 4-level
//!   FPI cascade). The `vmf_decode` fuzz target already exists
//!   but only tests decode panics; nothing in CI today catches
//!   silent field-drop on the encode side.
//! - K05.1 carries signed 25-bit latitude and signed 26-bit
//!   longitude — non-power-of-two-width signed fields are an
//!   off-by-one magnet on sign extension.
//! - Optional fields (altitude / speed / course / unit_identifier)
//!   are each gated by an FPI bit; a regression in the FPI logic
//!   could selectively drop one field while preserving the others
//!   — exactly the failure mode the parity test misses by
//!   construction (the proptest happens to be on data the parity
//!   path doesn't observe).
//!
//! # What this catches that the parity test doesn't
//!
//! - **`vehicle_id`-class field-zeroing regressions** on encode.
//! - **Sign-extension off-by-one** that flips a positive 25-bit
//!   value to negative or vice versa.
//! - **FPI cascade desync** where the encode side writes one set
//!   of FPI bits and the decode side reads a different set.
//! - **Calibration drift** between encode and decode (the wrapper
//!   currently does this math; the SchemaCodec migration must not
//!   change the LSB-level scaling).
//!
//! # What it does NOT catch
//!
//! - Silent bit corruption inside a field (NaN-like patterns that
//!   round-trip the bit pattern without being meaningful). The
//!   schema-parity test pins those.
//! - Wire-format spec compliance against a real MIL-STD-6017
//!   sender. That's a separate integration concern.

use libfuzzer_sys::fuzz_target;
use rustgate_vmf::{VmfMessage, decode_message, encode_k05_1};

fuzz_target!(|data: &[u8]| {
    // Phase 1: arbitrary bytes → decode. Truncation, range
    // violations, and bit-cursor underflow are all expected
    // error paths; the fuzzer's job is to confirm they don't
    // panic. Drop the result on the error path.
    let Ok((header, message)) = decode_message(data) else {
        return;
    };
    // Phase 2: only K05.1 has a structured encode path today
    // (`encode_k05_1`); `VmfMessage::Unknown` carries opaque
    // residual bytes the encoder cannot re-serialise. Skip the
    // round-trip arm for non-K05.1 — the `vmf_decode` fuzz
    // target already covers the panic-free decode surface for
    // all message types.
    let VmfMessage::K05_1(decoded) = message else {
        return;
    };
    // Phase 3: round-trip the typed body. Encode → decode →
    // assert every field bit-identical. A regression that zeros
    // a field on encode (the #1393 STANAG pattern) fails the
    // first assert below; one that drops an FPI without dropping
    // its payload field fails the second.
    let Ok(bytes) = encode_k05_1(&header, &decoded) else {
        // The production encoder is allowed to reject inputs that
        // the production decoder accepted (e.g. lat/lon outside
        // `[-90, 90]` / `[-180, 180]` survive decode but the
        // encode-side range guard rejects them with
        // `EncodeOverflow`). This is the documented asymmetry; the
        // fuzzer's job is to confirm the error path is graceful
        // (no panic).
        return;
    };
    let Ok((header_again, message_again)) = decode_message(&bytes) else {
        panic!(
            "re-decode of own encoded K05.1 must succeed (header={header:?}, body={decoded:?})"
        );
    };
    let VmfMessage::K05_1(again) = message_again else {
        panic!(
            "re-decode of encoded K05.1 must yield K05.1, got {message_again:?} (original header={header:?})"
        );
    };

    // Header invariants. The encode path rebuilds the header from
    // the body's reporting URN + the original header's metadata;
    // not every header byte round-trips bit-identical (e.g.
    // `header_size` may be recomputed) but the message-id
    // discriminator and originator URN must.
    assert_eq!(
        header.originator_urn, header_again.originator_urn,
        "originator URN must round-trip"
    );
    assert_eq!(
        header.message_id, header_again.message_id,
        "message_id discriminator must round-trip"
    );

    // Body invariants. Every typed field must survive the
    // round-trip. The float fields (latitude_deg, longitude_deg,
    // speed_m_per_s, course_deg) round-trip exact-to-LSB of the
    // wire encoding per the codec's documented precision; compare
    // via `to_be_bytes` so equal NaN / sub-normal bit patterns
    // don't spuriously diverge under `f64 == f64`.
    assert_eq!(
        decoded.reporting_urn, again.reporting_urn,
        "reporting_urn must round-trip"
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
        decoded.altitude_m, again.altitude_m,
        "altitude_m must round-trip (Option<i16> equality)"
    );
    // Speed / course round-trip as `Option<f64>`; compare via
    // `to_be_bytes` to handle the same NaN-bit-pattern concern
    // the lat/lon fields have.
    match (decoded.speed_m_per_s, again.speed_m_per_s) {
        (None, None) => {}
        (Some(a), Some(b)) => assert_eq!(
            a.to_be_bytes(),
            b.to_be_bytes(),
            "speed_m_per_s must round-trip bit-identical"
        ),
        (a, b) => panic!("speed_m_per_s FPI dropped: original={a:?}, again={b:?}"),
    }
    match (decoded.course_deg, again.course_deg) {
        (None, None) => {}
        (Some(a), Some(b)) => assert_eq!(
            a.to_be_bytes(),
            b.to_be_bytes(),
            "course_deg must round-trip bit-identical"
        ),
        (a, b) => panic!("course_deg FPI dropped: original={a:?}, again={b:?}"),
    }
    assert_eq!(
        decoded.unit_identifier, again.unit_identifier,
        "unit_identifier must round-trip (Option<String> equality)"
    );
});
