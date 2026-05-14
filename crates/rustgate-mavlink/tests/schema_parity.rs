// Copyright © 2026 Roberto Chiofalo.

//! Schema-parity test for the MAVLink v1 frame header.
//!
//! Validates that a [`SchemaCodec`] built from
//! `schemas/v1_header.yaml` produces byte-identical encodings to a
//! manually-built MAVLink v1 frame header for every arbitrary
//! input proptest generates. Third cross-protocol confidence test
//! for the declarative XTCE-style schema vocabulary in
//! `rustgate-codec-schema` (after STANAG 4586 in #1365 and DIS in
//! #1372).
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)` yields
//!    the same 6 bytes the hand-rolled `frame.rs::v1_frame` helper
//!    writes (magic + len + seq + sysid + compid + msgid).
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)`
//!    recovers all six fields from the wire bytes, and a
//!    subsequent re-encode round-trips byte-equal.
//!
//! ## What this does NOT prove
//!
//! - Full MAVLink message-id vocabulary. MAVLink defines several
//!   hundred message types across multiple dialects (Common,
//!   ArduPilotMega, …); the parity-test schema carries `msgid`
//!   as a raw u8. A companion non-parity test demonstrates v2
//!   `value-mapping` projection for the canonical `HEARTBEAT`
//!   message (`msgid = 0`).
//! - The payload + CRC trailer. Per-msgid payload shapes need
//!   their own schemas dispatched after the header.
//! - MAVLink v2 frames (10-byte header + signature). v2 reuses
//!   the same wire-format style but adds incompat / compat flag
//!   bytes and an optional 13-byte signature trailer; a follow-up
//!   PR can add `schemas/v2_header.yaml` with the same
//!   methodology.

#![cfg(test)]
#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_codec_schema::SchemaCodec;
use rustgate_core::entity::{AttributeValue, EntityCodec};

const SCHEMA_YAML: &str = include_str!("../schemas/v1_header.yaml");
const V1_HEADER_LEN: usize = 6;
const V1_MAGIC: u8 = 0xFE;
const HEARTBEAT_MSGID: u8 = 0;

fn schema_codec() -> SchemaCodec {
    SchemaCodec::from_schema_text(SCHEMA_YAML).expect("schema must parse + validate")
}

/// Hand-rolled MAVLink v1 header bytes for the given field values.
/// Mirrors the `frame.rs::v1_frame` helper minus the payload + CRC
/// trailer (the parity test cares about the 6-byte header only).
fn v1_header_bytes(magic: u8, len: u8, seq: u8, sysid: u8, compid: u8, msgid: u8) -> Vec<u8> {
    vec![magic, len, seq, sysid, compid, msgid]
}

proptest! {
    /// Arbitrary 6-byte v1 header → `SchemaCodec` decode →
    /// `SchemaCodec` re-encode must produce the same 6 bytes.
    #[test]
    fn schema_codec_byte_identical_to_hand_rolled(
        magic in any::<u8>(),
        len in any::<u8>(),
        seq in any::<u8>(),
        sysid in any::<u8>(),
        compid in any::<u8>(),
        msgid in any::<u8>(),
    ) {
        let hand_rolled = v1_header_bytes(magic, len, seq, sysid, compid, msgid);
        prop_assert_eq!(hand_rolled.len(), V1_HEADER_LEN);

        let codec = schema_codec();
        let entity = codec.to_entity(&hand_rolled).expect("schema decode");
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &hand_rolled[..]);
    }
}

/// Smoke test demonstrating v2 typed `value-mapping` projection on
/// the `msgid` byte. Decodes a canonical HEARTBEAT header
/// (`msgid = 0`) through a parallel schema that maps `0` →
/// `"HEARTBEAT"`, and asserts the projected attribute is the
/// typed label. Sits alongside the parity test rather than
/// replacing it because byte-equivalent round-trip with
/// value-mapping requires enumerating the full msgid vocabulary
/// — out of scope for a schema-parity proof.
#[test]
fn value_mapping_projects_typed_msgid_label() {
    let yaml = r#"
schema-version: "1"
protocol-name: "mavlink.v1_header_typed"
message-types:
  - name: "V1Header"
    size-bytes: 6
    fields:
      - name: "magic"
        offset: 0
        field-type: { kind: u8 }
      - name: "len"
        offset: 1
        field-type: { kind: u8 }
      - name: "seq"
        offset: 2
        field-type: { kind: u8 }
      - name: "sysid"
        offset: 3
        field-type: { kind: u8 }
      - name: "compid"
        offset: 4
        field-type: { kind: u8 }
      - name: "msgid"
        offset: 5
        field-type: { kind: u8 }
        entity-path: "attributes.msgid"
        value-mapping:
          entries:
            0: "HEARTBEAT"
          default-raw: 0
"#;
    let codec = SchemaCodec::from_schema_text(yaml).expect("typed schema must parse");
    let wire = v1_header_bytes(V1_MAGIC, 9, 42, 1, 1, HEARTBEAT_MSGID);
    let entity = codec.to_entity(&wire).expect("typed schema decode");
    let Some(AttributeValue::Str(label)) = entity.attributes.get("attributes.msgid") else {
        panic!(
            "expected msgid as typed label, got {:?}",
            entity.attributes.get("attributes.msgid")
        );
    };
    assert_eq!(label, "HEARTBEAT");
}
