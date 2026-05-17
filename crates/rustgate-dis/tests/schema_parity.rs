// Copyright © 2026 Roberto Chiofalo.

//! Schema-parity test for the DIS PDU common header.
//!
//! Validates that a [`SchemaCodec`] built from
//! `schemas/pdu_header.yaml` produces byte-identical encodings to
//! an **inline hand-rolled reference encoder** defined in this test
//! file for every arbitrary input proptest generates. Second
//! cross-protocol confidence test for the declarative XTCE-style
//! schema vocabulary in `rustgate-codec-schema` (the first is the
//! STANAG 4586 vehicle-position frame in #1365).
//!
//! ## Why the reference encoder lives in the test file
//!
//! Previously this test called `PduHeader::encode_into` for one
//! half of the round-trip. If the production codec ever migrates
//! to a SchemaCodec-driven path (as STANAG 4586 did in #1390), the
//! parity test would silently become a SchemaCodec-vs-SchemaCodec
//! round-trip — encoder bugs that lose data symmetrically (e.g.
//! buffer zeroing on a finite-float rejection, the #1393 STANAG
//! regression) pass trivially. See #1394 for the full discussion.
//!
//! The fix: keep an **independent** reference encoder *inside this
//! test file*, byte-coded against the documented wire layout. Even
//! if `PduHeader::encode_into` migrates to SchemaCodec internally
//! tomorrow, this reference encoder stays hand-coded and the parity
//! assertion remains a genuine cross-implementation comparison.
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)` yields
//!    the same 12 bytes the inline reference encoder produces for
//!    the same logical header. Every field is declared in the
//!    schema, so the schema codec writes byte-for-byte what the
//!    reference encoder writes (no zero-padding gaps to coordinate).
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)` recovers
//!    all seven fields from the wire bytes, and a subsequent
//!    re-encode round-trips byte-equal.
//! 3. **Public API round-trip** — `PduHeader::encode_into` →
//!    `PduHeader::decode` preserves every typed field of
//!    `PduHeader`. This is the typed-API invariant — encoder bugs
//!    that lose data (e.g. zeroing the buffer) fail here even if
//!    they pass the bytes-against-bytes parity assertion above.
//!
//! ## What this does NOT prove
//!
//! - The `PduType` / `ProtocolFamily` byte → typed-enum
//!   projection. IEEE 1278.1 Annex A defines 72 PDU types across 7
//!   protocol families; encoding the full enum vocabulary into the
//!   schema as `value-mapping` entries would be noisy and wouldn't
//!   help byte-equivalent round-trip — the schema can't represent
//!   `PduType::Other(byte)` losslessly through a `default-raw`
//!   fallback. The byte appears verbatim in `Entity::attributes`
//!   and round-trips byte-identically, which is what the parity
//!   test asserts.
//! - Per-PDU body decoding. The header is fixed-shape across all 72
//!   PDU types; the bodies are not, and the variable-length
//!   articulation parameter arrays on Entity State PDUs need schema
//!   features (length-prefixed repeats) beyond v2.

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

/// **Inline, independent** reference encoder for the DIS PDU
/// common header. Lives in the test file rather than calling
/// `PduHeader::encode_into` so the parity assertion is a genuine
/// cross-implementation comparison even if the production encoder
/// migrates to a SchemaCodec-driven path (the #1394 risk after the
/// STANAG full port in #1390).
///
/// Byte layout (lock-step with `schemas/pdu_header.yaml`):
///
/// ```text
/// offset │ size │ field            │ type
/// ───────┼──────┼──────────────────┼──────────────────────────
///   0    │  1   │ protocol_version │ u8
///   1    │  1   │ exercise_id      │ u8
///   2    │  1   │ pdu_type         │ u8 (enum byte)
///   3    │  1   │ protocol_family  │ u8 (enum byte)
///   4    │  4   │ timestamp        │ u32  big-endian
///   8    │  2   │ length           │ u16  big-endian
///  10    │  2   │ padding          │ u16  big-endian
/// ```
fn reference_encode(header: &PduHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN);
    buf.push(header.protocol_version);
    buf.push(header.exercise_id);
    buf.push(header.pdu_type.to_u8());
    buf.push(header.protocol_family.to_u8());
    buf.extend_from_slice(&header.timestamp.to_be_bytes());
    buf.extend_from_slice(&header.length.to_be_bytes());
    buf.extend_from_slice(&header.padding.to_be_bytes());
    buf
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
    /// **Path (a)** — Reference encoder → `SchemaCodec` decode →
    /// `SchemaCodec` re-encode must produce the same 12 bytes the
    /// reference encoder emitted. Wire-format invariant: offsets are
    /// stable, byte ordering is correct.
    ///
    /// The reference encoder lives inline in this test file rather
    /// than calling `PduHeader::encode_into`, so the parity check is a
    /// genuine cross-implementation comparison — encoder bugs in the
    /// production codec (or in SchemaCodec) cannot pass this test
    /// symmetrically.
    #[test]
    fn schema_codec_byte_identical_to_reference(header in pdu_header_strategy()) {
        let reference = reference_encode(&header);
        prop_assert_eq!(reference.len(), HEADER_LEN);

        let codec = schema_codec();
        let entity = codec.to_entity(&reference).expect("schema decode");
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &reference[..]);
    }

    /// **Path (c)** — Public-API round-trip:
    /// `PduHeader::encode_into` → `PduHeader::decode` must preserve
    /// every typed field of `PduHeader`.
    ///
    /// Catches the same class of regression the weekly-fuzz harness
    /// catches — encoder bugs that silently drop fields (e.g. zeroing
    /// the buffer) fail here even if the bytes-against-bytes parity
    /// assertion above passed symmetrically. This is the load-bearing
    /// invariant for the typed wrapper API.
    #[test]
    fn public_api_round_trip_preserves_typed_fields(header in pdu_header_strategy()) {
        let mut bytes = Vec::with_capacity(HEADER_LEN);
        header.encode_into(&mut bytes);
        prop_assert_eq!(bytes.len(), HEADER_LEN);

        let decoded = PduHeader::decode(&bytes).expect("public-API round-trip");

        prop_assert_eq!(decoded.protocol_version, header.protocol_version);
        prop_assert_eq!(decoded.exercise_id, header.exercise_id);
        prop_assert_eq!(decoded.pdu_type, header.pdu_type);
        prop_assert_eq!(decoded.protocol_family, header.protocol_family);
        prop_assert_eq!(decoded.timestamp, header.timestamp);
        prop_assert_eq!(decoded.length, header.length);
        prop_assert_eq!(decoded.padding, header.padding);
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
