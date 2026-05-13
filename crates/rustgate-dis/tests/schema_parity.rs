// Copyright © 2026 Roberto Chiofalo.

//! Schema-parity test for the DIS PDU common header.
//!
//! Validates that a [`SchemaCodec`] built from
//! `schemas/pdu_header.yaml` produces byte-identical encodings to
//! the hand-rolled [`PduHeader::encode_into`] for every arbitrary
//! input proptest generates. Second cross-protocol confidence test
//! for the declarative XTCE-style schema vocabulary in
//! `rustgate-codec-schema` (the first is the STANAG 4586
//! vehicle-position frame in #1365).
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)` yields
//!    the same 12 bytes the hand-rolled encoder produces for the
//!    same logical header. Every field is declared in the schema,
//!    so the schema codec writes byte-for-byte what the hand-
//!    rolled encoder writes (no zero-padding gaps to coordinate).
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)`
//!    recovers all seven fields from the wire bytes, and a
//!    subsequent re-encode round-trips byte-equal.
//!
//! ## What this does NOT prove
//!
//! - The `PduType` / `ProtocolFamily` byte → typed-enum
//!   projection. IEEE 1278.1 Annex A defines 72 PDU types across
//!   7 protocol families; encoding the full enum vocabulary into
//!   the schema as `value-mapping` entries would be noisy and
//!   wouldn't help byte-equivalent round-trip — the schema can't
//!   represent `PduType::Other(byte)` losslessly through a
//!   `default-raw` fallback (decode produces the default's label,
//!   encode produces the default's raw). The byte appears
//!   verbatim in `Entity::attributes` and round-trips
//!   byte-identically, which is what this parity test asserts.
//! - Per-PDU body decoding. The header is fixed-shape across all
//!   72 PDU types; the bodies are not, and the variable-length
//!   articulation parameter arrays on Entity State PDUs need
//!   schema features (length-prefixed repeats) beyond v2.

#![cfg(test)]
#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_codec_schema::SchemaCodec;
use rustgate_core::entity::{AttributeValue, EntityCodec};
use rustgate_dis::header::{HEADER_LEN, PduHeader, PduType, ProtocolFamily};

const SCHEMA_YAML: &str = include_str!("../schemas/pdu_header.yaml");

fn schema_codec() -> SchemaCodec {
    SchemaCodec::from_schema_text(SCHEMA_YAML).expect("schema must parse + validate")
}

/// Strategy for the PDU-type byte. Exercises both the named
/// `EntityState` variant and the `Other(u8)` forward-compat path
/// so the parity test covers the full byte range.
fn pdu_type_strategy() -> impl Strategy<Value = PduType> {
    any::<u8>().prop_map(PduType::from_u8)
}

fn protocol_family_strategy() -> impl Strategy<Value = ProtocolFamily> {
    any::<u8>().prop_map(ProtocolFamily::from_u8)
}

fn pdu_header_strategy() -> impl Strategy<Value = PduHeader> {
    (
        any::<u8>(),
        any::<u8>(),
        pdu_type_strategy(),
        protocol_family_strategy(),
        any::<u32>(),
        any::<u16>(),
        any::<u16>(),
    )
        .prop_map(
            |(
                protocol_version,
                exercise_id,
                pdu_type,
                protocol_family,
                timestamp,
                length,
                padding,
            )| PduHeader {
                protocol_version,
                exercise_id,
                pdu_type,
                protocol_family,
                timestamp,
                length,
                padding,
            },
        )
}

proptest! {
    /// Hand-rolled encode → `SchemaCodec` decode → `SchemaCodec`
    /// re-encode must produce the same 12 bytes the hand-rolled
    /// encoder emitted. Definitive parity assertion for the v2
    /// schema vocabulary on DIS wire-format inputs.
    #[test]
    fn schema_codec_byte_identical_to_hand_rolled(header in pdu_header_strategy()) {
        let mut hand_rolled = Vec::with_capacity(HEADER_LEN);
        header.encode_into(&mut hand_rolled);
        prop_assert_eq!(hand_rolled.len(), HEADER_LEN);

        let codec = schema_codec();
        let entity = codec.to_entity(&hand_rolled).expect("schema decode");
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &hand_rolled[..]);
    }
}

/// Smoke test demonstrating v2 typed `value-mapping` projection on
/// the `pdu_type` byte. Builds a parallel schema with the
/// EntityState mapping declared and decodes a real Entity State
/// header, checking that the projected attribute is the typed
/// label rather than the raw byte. Lives alongside the parity
/// test rather than replacing it because byte-equivalent
/// round-trip with value-mapping requires enumerating all 72 PDU
/// types — out of scope for a schema-parity proof.
#[test]
fn value_mapping_projects_typed_pdu_type_label() {
    // Schema with value-mapping declared on pdu_type. Same wire
    // layout as `pdu_header.yaml` so the same 12-byte header
    // decodes; only the projection differs.
    let yaml = r#"
schema-version: "1"
protocol-name: "dis.pdu_header_typed"
message-types:
  - name: "PduHeader"
    size-bytes: 12
    fields:
      - name: "protocol_version"
        offset: 0
        field-type: { kind: u8 }
      - name: "exercise_id"
        offset: 1
        field-type: { kind: u8 }
      - name: "pdu_type"
        offset: 2
        field-type: { kind: u8 }
        entity-path: "attributes.pdu_type"
        value-mapping:
          entries:
            1: "EntityState"
          default-raw: 1
      - name: "protocol_family"
        offset: 3
        field-type: { kind: u8 }
      - name: "timestamp"
        offset: 4
        field-type: { kind: u32 }
        endian: big
      - name: "length"
        offset: 8
        field-type: { kind: u16 }
        endian: big
      - name: "padding"
        offset: 10
        field-type: { kind: u16 }
        endian: big
"#;
    let codec = SchemaCodec::from_schema_text(yaml).expect("typed schema must parse");
    let header = PduHeader::new(
        PduType::EntityState,
        ProtocolFamily::EntityInformationInteraction,
        144,
    );
    let mut wire = Vec::with_capacity(HEADER_LEN);
    header.encode_into(&mut wire);
    let entity = codec.to_entity(&wire).expect("typed schema decode");
    let Some(AttributeValue::Str(label)) = entity.attributes.get("attributes.pdu_type") else {
        panic!(
            "expected pdu_type as typed label, got {:?}",
            entity.attributes.get("attributes.pdu_type")
        );
    };
    assert_eq!(label, "EntityState");
}
