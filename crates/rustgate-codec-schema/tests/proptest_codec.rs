// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Property-based tests for the schema-driven codec.
//!
//! These tests generate arbitrary single-field fixed-offset schemas
//! + matching payloads, then assert that:
//!
//! 1. **Decode never panics** on payloads sized to the schema. The
//!    codec is the runtime boundary that takes operator-supplied
//!    bytes and projects them onto `Entity`; an operator schema +
//!    arbitrary payload bytes must never crash the process.
//! 2. **Round-trip is byte-exact** through the attribute-fallback
//!    path. A field with no `entity_path` lands on
//!    `Entity::attributes` under `schema.<protocol>.<field>`; the
//!    encode side reads it back and reproduces the original bytes
//!    (modulo the documented uid simplification, which we sidestep
//!    here by never setting `entity_path: "uid"`).
//!
//! The strategies generate one field per schema rather than
//! arbitrary multi-field schemas — multi-field overlap detection is
//! covered by the unit tests in `schema.rs`, and a single-field
//! schema is enough to exercise every primitive type + endianness
//! + calibration combination the runtime cares about.

#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_codec_schema::SchemaCodec;
use rustgate_core::entity::EntityCodec;

/// Strategy for the 10 numeric `FieldType` kinds the runtime
/// projects to `Entity::attributes`. We skip `bytes` / `utf8` here
/// because their decode produces `AttributeValue::Str` and the
/// round-trip story is exercised by dedicated unit tests in
/// `codec.rs`.
fn numeric_kind_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("u8"),
        Just("u16"),
        Just("u32"),
        Just("u64"),
        Just("i8"),
        Just("i16"),
        Just("i32"),
        Just("i64"),
        Just("f32"),
        Just("f64"),
    ]
}

fn endian_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("little"), Just("big")]
}

fn kind_size(kind: &str) -> usize {
    match kind {
        "u8" | "i8" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" => 8,
        _ => unreachable!("numeric_kind_strategy returns only fixed-size kinds"),
    }
}

/// Build a single-field schema as a YAML string. The codec parses
/// YAML, so generating the wire form directly catches any
/// disagreement between serde tagging and the parser.
fn build_schema(kind: &str, endian: &str) -> String {
    let size = kind_size(kind);
    format!(
        r#"
schema-version: "1"
protocol-name: "proptest.fixed"
message-types:
  - name: "M"
    size-bytes: {size}
    fields:
      - name: "v"
        offset: 0
        field-type: {{ kind: {kind} }}
        endian: {endian}
"#
    )
}

proptest! {
    /// Decode never panics on payloads of the schema's declared
    /// size. Float payloads include the full `f32::from_bits` /
    /// `f64::from_bits` range so NaN / subnormal / infinity inputs
    /// are exercised.
    #[test]
    fn decode_does_not_panic(
        kind in numeric_kind_strategy(),
        endian in endian_strategy(),
        payload in prop::collection::vec(any::<u8>(), 1..=8),
    ) {
        let size = kind_size(kind);
        // Skip cases where the random payload is smaller than the
        // schema requires — the codec rightly returns
        // PayloadTooShort there, which is well-tested elsewhere.
        prop_assume!(payload.len() >= size);

        let yaml = build_schema(kind, endian);
        let codec = SchemaCodec::from_schema_text(&yaml).unwrap();
        // The result may be Ok or Err depending on whether the
        // float bits map to NaN etc., but neither case must panic.
        let _ = codec.to_entity(&payload[..size]);
    }

    /// Integer round-trip is byte-exact through the attribute
    /// fallback. Floats are exercised in a separate proptest
    /// because NaN payloads do not survive the `Entity::attributes`
    /// `AttributeValue::Float` representation (the
    /// hash-cn-safe-equality on `f64` treats NaN ≠ NaN).
    #[test]
    fn integer_payload_round_trips_byte_exact(
        kind in prop_oneof![
            Just("u8"), Just("u16"), Just("u32"), Just("u64"),
            Just("i8"), Just("i16"), Just("i32"), Just("i64"),
        ],
        endian in endian_strategy(),
        bits in any::<u64>(),
    ) {
        let size = kind_size(kind);
        let yaml = build_schema(kind, endian);
        let codec = SchemaCodec::from_schema_text(&yaml).unwrap();

        // Build the payload from the bottom `size` bytes of the
        // generated u64, using the schema's declared endian so the
        // round-trip is well-defined.
        let mut payload = vec![0u8; size];
        let raw_bytes = if endian == "little" {
            bits.to_le_bytes()
        } else {
            bits.to_be_bytes()
        };
        // For LE: take the low bytes. For BE: take the high bytes.
        if endian == "little" {
            payload.copy_from_slice(&raw_bytes[..size]);
        } else {
            payload.copy_from_slice(&raw_bytes[8 - size..]);
        }

        let entity = codec.to_entity(&payload).unwrap();
        let re_encoded = codec.from_entity(&entity).unwrap();
        prop_assert_eq!(&re_encoded[..], &payload[..]);
    }
}
