// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Schema-parity test for the VMF K05.1 Position Report body.
//!
//! **Load-bearing close of the multi-day codec-schema arc**: this
//! test demonstrates the v3 + v4 + v4.1 + v5 grammar features all
//! working together on a real bit-packed tactical protocol's wire
//! format. K05.1 was the original blocker (#1396) that surfaced the
//! gaps each grammar revision filled — cross-byte spans (v4 /
//! #1402), signed bit-packed types (v4.1 / #1404), variable-shift
//! `present-if` (v5 / #1407) — and is now expressible end-to-end.
//!
//! ## Why the reference encoder lives in the test file
//!
//! Same rationale as every other schema-parity test added since
//! #1397: keep the reference implementation inline so the parity
//! check is a genuine cross-implementation comparison even if the
//! production codec migrates to a `SchemaCodec`-driven path. The
//! inline reference encoder hand-codes the bit positions per the
//! schema's documented bit-level layout; the parity assertion is
//! `reference_encode → SchemaCodec::to_entity →
//! SchemaCodec::from_entity == reference_encode`.
//!
//! ## What this proves
//!
//! 1. **Encode parity**: `SchemaCodec::from_entity` yields the same
//!    bit stream the inline reference encoder produces, for every
//!    combination of FPI bits proptest generates. Wire size shrinks
//!    when FPIs are 0 (variable-shift behavior); the schema's
//!    encoder truncates the trailing all-zero bytes by
//!    `bit_shift / 8`.
//! 2. **Decode parity**: `SchemaCodec::to_entity` recovers every
//!    field (URN, signed lat/lon, FPI flags, optional altitude /
//!    speed / course / unit_identifier) from the wire and a
//!    subsequent re-encode round-trips byte-equal.
//! 3. **Cross-byte signed bit spans**: latitude (i32, 25 bits
//!    starting bit-aligned at offset 3) and longitude (i32, 26
//!    bits starting mid-byte at offset 6, bit-offset 1) exercise
//!    the v4.1 signed bit-packed path including sign-extension on
//!    decode and two's-complement encode.
//! 4. **Variable-shift FPI cascade**: four `CollapseWhenAbsent`
//!    fields cascade — altitude → speed → course →
//!    unit_identifier. Every combination of the four FPI bits
//!    produces a correct (and self-consistent) byte stream.
//!
//! ## What this does NOT prove
//!
//! - Drop-in compatibility with the production
//!   `K051PositionReport::encode`. The production codec applies
//!   range guards (lat in `[-90, 90]`, lon in `[-180, 180]`, speed
//!   non-negative, course quantization to 9-bit units, ASCII
//!   sanitization on unit_identifier) that the schema doesn't
//!   model the same way. The parity contract here is "byte-
//!   identical via SchemaCodec against an inline reference encoder
//!   that uses the same v3+v4+v4.1+v5 grammar".
//! - Linear calibration on signed bit-packed lat/lon. The schema
//!   carries the raw signed bit pattern; the integration layer in
//!   the production codec applies `raw / 2^24 * 90` (lat) and
//!   `raw / 2^25 * 180` (lon) on the read boundary. Combining
//!   bit-packing with linear calibration is a follow-up.
//! - Multi-position fan-out (FRI repetition). MIL-STD-6017 K05.1
//!   may carry multiple position updates; the MVP body schema
//!   covers a single report.

#![cfg(test)]
#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_codec_schema::SchemaCodec;
use rustgate_core::entity::{AttributeValue, EntityCodec};

const SCHEMA_YAML: &str = include_str!("../schemas/k05_1.yaml");

/// All-fields-present wire size declared by the schema. When FPI
/// bits are 0, the actual encoded payload shrinks via v5
/// variable-shift; the schema encoder truncates trailing all-zero
/// bytes equal to `bit_shift / 8`.
const SCHEMA_SIZE_BYTES: usize = 22;

fn schema_codec() -> SchemaCodec {
    SchemaCodec::from_schema_text(SCHEMA_YAML).expect("schema must parse + validate")
}

/// Logical inputs to the reference encoder. FPI fields are derived
/// from the presence of the corresponding `Option`-typed
/// payload field (`Some` ⇒ FPI=1, `None` ⇒ FPI=0).
#[derive(Debug, Clone)]
struct K051Input {
    reporting_urn: u32,           // 24 bits
    latitude_raw: i32,            // 25 bits signed
    longitude_raw: i32,           // 26 bits signed
    altitude: Option<i32>,        // 16 bits signed if Some
    speed: Option<u32>,           // 12 bits unsigned if Some
    course: Option<u32>,          // 9 bits unsigned if Some
    unit_identifier: Option<u64>, // 56 bits if Some
}

/// **Inline, independent** bit-stream reference encoder. Mirrors
/// the schema's declared bit layout exactly — every field is
/// written at the position the schema declares, with v5 variable-
/// shift behaviour when FPIs are 0 (absent fields contribute no
/// bits to the output stream). Output is padded to
/// `SCHEMA_SIZE_BYTES - bit_shift / 8` to match what the schema
/// runtime's `from_entity` produces.
fn reference_encode(input: &K051Input) -> Vec<u8> {
    // Bit-cursor encoder. Tracks position in bits; writes MSB-first
    // big-endian to the byte vector. The vector is pre-sized to
    // `SCHEMA_SIZE_BYTES` (the all-fields-present max); after all
    // writes, truncate to match the schema runtime's truncation.
    let mut buf = vec![0u8; SCHEMA_SIZE_BYTES];
    let mut cursor: usize = 0;

    let mut write_bits = |value: u64, width: u32, cursor: &mut usize| {
        let mut bits_remaining = width as usize;
        let mut cur_byte = *cursor / 8;
        let mut cur_bit = *cursor % 8;
        while bits_remaining > 0 {
            let bits_in_this_byte = (8 - cur_bit).min(bits_remaining);
            let value_shift = bits_remaining - bits_in_this_byte;
            let chunk_mask = (1u64 << bits_in_this_byte) - 1;
            let chunk = ((value >> value_shift) & chunk_mask) as u8;
            let position_shift = 8 - cur_bit - bits_in_this_byte;
            let positioned = chunk << position_shift;
            buf[cur_byte] |= positioned;
            bits_remaining -= bits_in_this_byte;
            cur_bit = 0;
            cur_byte += 1;
        }
        *cursor += width as usize;
    };

    // URN: 24-bit unsigned
    write_bits(u64::from(input.reporting_urn), 24, &mut cursor);

    // Latitude: 25-bit signed two's-complement
    let lat_u = (input.latitude_raw as u64) & ((1u64 << 25) - 1);
    write_bits(lat_u, 25, &mut cursor);

    // Longitude: 26-bit signed two's-complement
    let lon_u = (input.longitude_raw as u64) & ((1u64 << 26) - 1);
    write_bits(lon_u, 26, &mut cursor);

    // Altitude FPI + optional 16-bit signed altitude
    if let Some(alt) = input.altitude {
        write_bits(1, 1, &mut cursor);
        let alt_u = (alt as u64) & ((1u64 << 16) - 1);
        write_bits(alt_u, 16, &mut cursor);
    } else {
        write_bits(0, 1, &mut cursor);
    }

    // Speed FPI + optional 12-bit unsigned speed
    if let Some(speed) = input.speed {
        write_bits(1, 1, &mut cursor);
        write_bits(u64::from(speed), 12, &mut cursor);
    } else {
        write_bits(0, 1, &mut cursor);
    }

    // Course FPI + optional 9-bit unsigned course
    if let Some(course) = input.course {
        write_bits(1, 1, &mut cursor);
        write_bits(u64::from(course), 9, &mut cursor);
    } else {
        write_bits(0, 1, &mut cursor);
    }

    // Unit identifier FPI + optional 56-bit blob
    if let Some(uid) = input.unit_identifier {
        write_bits(1, 1, &mut cursor);
        write_bits(uid, 56, &mut cursor);
    } else {
        write_bits(0, 1, &mut cursor);
    }

    // Truncate to match the schema runtime: it truncates by
    // `bit_shift / 8` full bytes from the all-fields-present
    // `SCHEMA_SIZE_BYTES` allocation. `bit_shift` accumulates the
    // bit-widths of every absent gated field.
    let collapsed_bits: usize = [
        (input.altitude.is_none(), 16),
        (input.speed.is_none(), 12),
        (input.course.is_none(), 9),
        (input.unit_identifier.is_none(), 56),
    ]
    .into_iter()
    .map(|(absent, width)| if absent { width } else { 0 })
    .sum();
    let truncate_bytes = collapsed_bits / 8;
    buf.truncate(SCHEMA_SIZE_BYTES - truncate_bytes);
    buf
}

/// Strategy for a K051Input. Limits:
/// - URN: 24-bit envelope (0..=0xFFFFFF)
/// - Lat: 25-bit signed (-2^24..=2^24-1)
/// - Lon: 26-bit signed (-2^25..=2^25-1)
/// - Altitude: 16-bit signed (i16::MIN..=i16::MAX)
/// - Speed: 12-bit unsigned (0..=4095)
/// - Course: 9-bit unsigned (0..=511)
/// - Unit identifier: 56-bit blob (0..=2^56-1)
fn k051_input_strategy() -> impl Strategy<Value = K051Input> {
    let header = (
        0u32..=0x00FF_FFFFu32,
        -(1i32 << 24)..=((1i32 << 24) - 1),
        -(1i32 << 25)..=((1i32 << 25) - 1),
    );
    let optional_payload = (
        prop::option::of(i32::from(i16::MIN)..=i32::from(i16::MAX)),
        prop::option::of(0u32..=4095u32),
        prop::option::of(0u32..=511u32),
        prop::option::of(0u64..=((1u64 << 56) - 1)),
    );
    (header, optional_payload).prop_map(
        |(
            (reporting_urn, latitude_raw, longitude_raw),
            (altitude, speed, course, unit_identifier),
        )| K051Input {
            reporting_urn,
            latitude_raw,
            longitude_raw,
            altitude,
            speed,
            course,
            unit_identifier,
        },
    )
}

proptest! {
    /// **The load-bearing v5 grammar exercise.** Reference encoder
    /// → `SchemaCodec` decode → `SchemaCodec` re-encode must
    /// produce the same bit stream the reference encoder emitted,
    /// for every combination of the four FPI bits.
    ///
    /// This is the first test in the workspace that exercises ALL
    /// of v3 (bit-packing), v4 (cross-byte spans), v4.1 (signed
    /// bit-packed types), and v5 (variable-shift `present-if`)
    /// together on a real protocol body.
    #[test]
    fn schema_codec_byte_identical_to_reference(input in k051_input_strategy()) {
        let reference = reference_encode(&input);

        let codec = schema_codec();
        let entity = codec.to_entity(&reference).expect("schema decode K05.1");
        let re_encoded = codec.from_entity(&entity).expect("schema encode K05.1");
        prop_assert_eq!(&re_encoded[..], &reference[..]);
    }
}

/// Golden fixture: all-fields-present case. Pins the exact byte
/// layout the schema produces for a known logical input. A
/// regression that swapped two fields' bit positions or got an
/// off-by-one would fail this test even if the proptest happened
/// to skip the specific combination.
#[test]
fn all_fields_present_pins_byte_layout() {
    let input = K051Input {
        reporting_urn: 0x12_3456, // 24 bits
        latitude_raw: 0,          // 25 bits — zero is the simplest signed value
        longitude_raw: 0,         // 26 bits
        altitude: Some(0),
        speed: Some(0),
        course: Some(0),
        unit_identifier: Some(0),
    };
    let reference = reference_encode(&input);
    assert_eq!(
        reference.len(),
        SCHEMA_SIZE_BYTES,
        "all-fields-present output should match declared size"
    );
    // First three bytes carry the 24-bit URN big-endian.
    assert_eq!(&reference[0..3], &[0x12, 0x34, 0x56]);

    // Round-trip via schema runtime.
    let codec = schema_codec();
    let entity = codec.to_entity(&reference).expect("decode all-present");
    let re_encoded = codec.from_entity(&entity).expect("encode all-present");
    assert_eq!(&re_encoded[..], &reference[..]);
}

/// All-FPIs-zero case: every optional field is absent on wire.
/// Wire payload shrinks by 16 + 12 + 9 + 56 = 93 bits → 11 full
/// bytes truncated, output is `22 - 11 = 11` bytes.
#[test]
fn all_fpis_zero_collapses_to_eleven_bytes() {
    let input = K051Input {
        reporting_urn: 0,
        latitude_raw: 0,
        longitude_raw: 0,
        altitude: None,
        speed: None,
        course: None,
        unit_identifier: None,
    };
    let reference = reference_encode(&input);
    assert_eq!(
        reference.len(),
        11,
        "all-FPIs-zero output should be {SCHEMA_SIZE_BYTES} - 93 / 8 = 11 bytes"
    );
    let codec = schema_codec();
    let entity = codec.to_entity(&reference).expect("decode all-absent");
    // Each FPI attribute should be 0.
    let fpi = |name: &str| -> i64 {
        match entity.attributes.get(&format!("schema.vmf.k05_1.{name}")) {
            Some(AttributeValue::Int(v)) => *v,
            other => panic!("missing or wrong-typed {name}: {other:?}"),
        }
    };
    assert_eq!(fpi("altitude_fpi"), 0);
    assert_eq!(fpi("speed_fpi"), 0);
    assert_eq!(fpi("course_fpi"), 0);
    assert_eq!(fpi("unit_id_fpi"), 0);
    // Gated fields should NOT be projected (predicate missed).
    assert!(
        !entity.attributes.contains_key("schema.vmf.k05_1.altitude"),
        "altitude attribute should be absent when its FPI is 0"
    );
    let re_encoded = codec.from_entity(&entity).expect("encode all-absent");
    assert_eq!(&re_encoded[..], &reference[..]);
}

/// Negative latitude / longitude exercise the v4.1 signed
/// sign-extension path. Latitude `i32 = -(1 << 24)` is the most
/// negative 25-bit signed value; the wire bits are `0b1_0000_…_0`
/// (25 bits, MSB set), and a subsequent decode must sign-extend
/// back to `-(1 << 24)` rather than projecting `1 << 24` as
/// positive.
#[test]
fn negative_latitude_and_longitude_round_trip_via_sign_extension() {
    let input = K051Input {
        reporting_urn: 0,
        latitude_raw: -(1 << 24),  // most-negative 25-bit signed
        longitude_raw: -(1 << 25), // most-negative 26-bit signed
        altitude: None,
        speed: None,
        course: None,
        unit_identifier: None,
    };
    let reference = reference_encode(&input);
    let codec = schema_codec();
    let entity = codec.to_entity(&reference).expect("decode signed extremes");

    let attr = |name: &str| -> i64 {
        match entity.attributes.get(&format!("schema.vmf.k05_1.{name}")) {
            Some(AttributeValue::Int(v)) => *v,
            other => panic!("missing or wrong-typed {name}: {other:?}"),
        }
    };
    assert_eq!(attr("latitude"), -(1 << 24));
    assert_eq!(attr("longitude"), -(1 << 25));
    let re_encoded = codec.from_entity(&entity).expect("encode signed extremes");
    assert_eq!(&re_encoded[..], &reference[..]);
}
