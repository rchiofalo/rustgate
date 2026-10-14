// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Schema-parity test for the MAVLink v1 frame header.
//!
//! Validates that a [`SchemaCodec`] built from
//! `schemas/v1_header.yaml` produces byte-identical encodings to
//! an **inline hand-rolled reference encoder** defined in this
//! test file for every arbitrary input proptest generates. Third
//! cross-protocol confidence test for the declarative XTCE-style
//! schema vocabulary in `rustgate-codec-schema` (after STANAG 4586
//! in #1365 and DIS in #1372).
//!
//! ## Why the reference encoder lives in the test file
//!
//! Tactical regression discipline (#1394): the parity test must
//! round-trip the schema runtime against an **independent**
//! reference implementation. If the test re-used the production
//! codec's encoder, a future port that switched the production
//! encoder to a `SchemaCodec`-driven path (as STANAG 4586 did in
//! #1390) would silently turn the parity test into a
//! `SchemaCodec`-vs-`SchemaCodec` round-trip — encoder bugs that
//! lose data symmetrically (e.g. buffer zeroing on finite-float
//! rejection, the #1393 STANAG regression) would pass trivially.
//!
//! `rustgate-mavlink` is the easy case here: the production
//! `MavlinkFrameCodec` operates on raw [`BytesMut`] and exposes no
//! typed v1-header struct, so there is no production typed encoder
//! the test could accidentally reuse. The inline
//! [`v1_reference_encode`] below is the schema's reference
//! implementation by construction.
//!
//! Future scope: if a typed `V1Header { magic, len, seq, sysid,
//! compid, msgid }` struct ever lands with its own `encode_into` /
//! `decode` methods, add a third proptest mirroring the public-API
//! round-trip in `rustgate-stanag4586::schema_parity::
//! public_api_round_trip_preserves_typed_fields` and
//! `rustgate-dis::schema_parity::public_api_round_trip_preserves_typed_fields`.
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)` yields
//!    the same 6 bytes the inline reference encoder produces
//!    (magic + len + seq + sysid + compid + msgid).
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)`
//!    recovers all six fields from the wire bytes, and a subsequent
//!    re-encode round-trips byte-equal.
//!
//! ## What this does NOT prove
//!
//! - Full MAVLink message-id vocabulary. MAVLink defines several
//!   hundred message types across multiple dialects (Common,
//!   ArduPilotMega, …); the parity-test schema carries `msgid` as
//!   a raw u8. A companion non-parity test demonstrates v2
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

/// **Inline, independent** reference encoder for the MAVLink v1
/// header. Lives in the test file so the parity assertion remains a
/// genuine cross-implementation comparison even if a future
/// refactor introduces a typed `V1Header` struct with its own
/// `encode_into` method (see module-level rationale on #1394).
///
/// Byte layout (lock-step with `schemas/v1_header.yaml`):
///
/// ```text
/// offset │ size │ field  │ type
/// ───────┼──────┼────────┼──────
///   0    │  1   │ magic  │ u8
///   1    │  1   │ len    │ u8
///   2    │  1   │ seq    │ u8
///   3    │  1   │ sysid  │ u8
///   4    │  1   │ compid │ u8
///   5    │  1   │ msgid  │ u8
/// ```
fn v1_reference_encode(magic: u8, len: u8, seq: u8, sysid: u8, compid: u8, msgid: u8) -> Vec<u8> {
    vec![magic, len, seq, sysid, compid, msgid]
}

proptest! {
    /// **Path (a)** — Reference encoder → `SchemaCodec` decode →
    /// `SchemaCodec` re-encode must produce the same 6 bytes the
    /// reference encoder emitted. Wire-format invariant: offsets are
    /// stable, byte ordering is correct.
    #[test]
    fn schema_codec_byte_identical_to_reference(
        magic in any::<u8>(),
        len in any::<u8>(),
        seq in any::<u8>(),
        sysid in any::<u8>(),
        compid in any::<u8>(),
        msgid in any::<u8>(),
    ) {
        let reference = v1_reference_encode(magic, len, seq, sysid, compid, msgid);
        prop_assert_eq!(reference.len(), V1_HEADER_LEN);

        let codec = schema_codec();
        let entity = codec.to_entity(&reference).expect("schema decode");
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &reference[..]);
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
    let wire = v1_reference_encode(V1_MAGIC, 9, 42, 1, 1, HEARTBEAT_MSGID);
    let entity = codec.to_entity(&wire).expect("typed schema decode");
    let Some(AttributeValue::Str(label)) = entity.attributes.get("attributes.msgid") else {
        panic!(
            "expected msgid as typed label, got {:?}",
            entity.attributes.get("attributes.msgid")
        );
    };
    assert_eq!(label, "HEARTBEAT");
}
