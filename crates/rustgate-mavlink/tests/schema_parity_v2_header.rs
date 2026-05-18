// Copyright © 2026 Roberto Chiofalo.

//! Schema-parity test for the MAVLink v2 frame header.
//!
//! Mirrors the v1 header parity test ([`schema_parity.rs`]) for
//! MAVLink v2's 10-byte header. v2 extends v1 with two flag bytes
//! (incompat_flags / compat_flags), a 24-bit message id carried as
//! three little-endian bytes (msgid_lo / msgid_mid / msgid_hi), and
//! an optional 13-byte signature trailer gated by
//! `incompat_flags & MAVLINK_IFLAG_SIGNED (= 0x01)` — the signature
//! is out of scope for this header parity test (it sits after the
//! CRC trailer and needs a variable-tail schema feature beyond
//! v3-style fixed `repeat`).
//!
//! ## Why the reference encoder lives in the test file
//!
//! Same rationale as the existing
//! `tests/schema_parity.rs` for the v1 header — see #1394 / #1397.
//! Keeping the reference implementation inline means the parity
//! check stays a genuine cross-implementation comparison even if a
//! future PR introduces a typed `V2Header` struct in
//! `rustgate-mavlink`. Encoder bugs that lose data symmetrically
//! cannot pass trivially.
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)` yields
//!    the same 10 bytes the inline reference encoder produces.
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)`
//!    recovers all ten fields from the wire bytes, and a
//!    subsequent re-encode round-trips byte-equal.
//!
//! ## What this does NOT prove
//!
//! - The signature trailer (13 bytes, gated by IFLAG_SIGNED). The
//!   trailer is variable-presence (0 or 13 bytes appended after the
//!   CRC) — the v5 grammar's variable-shift `present-if` (#1396 /
//!   v5 follow-up) is the natural target for this.
//! - Per-msgid payload shapes. v2 payloads are still msgid-
//!   dependent and dispatched at the call site, same as v1.
//! - The 24-bit msgid recombination. The schema carries three
//!   independent u8 bytes; the typed projection
//!   `(msgid_hi << 16) | (msgid_mid << 8) | msgid_lo` lives in the
//!   `rustgate-mavlink::frame` wrapper.

#![cfg(test)]
#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_codec_schema::SchemaCodec;
use rustgate_core::entity::{AttributeValue, EntityCodec};

const SCHEMA_YAML: &str = include_str!("../schemas/v2_header.yaml");
const V2_HEADER_LEN: usize = 10;
const V2_MAGIC: u8 = 0xFD;
const HEARTBEAT_MSGID: u8 = 0;

fn schema_codec() -> SchemaCodec {
    SchemaCodec::from_schema_text(SCHEMA_YAML).expect("schema must parse + validate")
}

/// **Inline, independent** reference encoder for the MAVLink v2
/// header. Byte-coded against `schemas/v2_header.yaml` so the
/// parity assertion is a genuine cross-implementation comparison.
#[allow(clippy::too_many_arguments)]
fn v2_reference_encode(
    magic: u8,
    len: u8,
    incompat_flags: u8,
    compat_flags: u8,
    seq: u8,
    sysid: u8,
    compid: u8,
    msgid_lo: u8,
    msgid_mid: u8,
    msgid_hi: u8,
) -> Vec<u8> {
    vec![
        magic,
        len,
        incompat_flags,
        compat_flags,
        seq,
        sysid,
        compid,
        msgid_lo,
        msgid_mid,
        msgid_hi,
    ]
}

proptest! {
    /// **Path (a)** — Reference encoder → `SchemaCodec` decode →
    /// `SchemaCodec` re-encode must produce the same 10 bytes the
    /// reference encoder emitted. Wire-format invariant for the v2
    /// header: offsets are stable, byte ordering is correct,
    /// little-endian msgid bytes round-trip in declared order.
    #[test]
    fn schema_codec_byte_identical_to_reference(
        magic in any::<u8>(),
        len in any::<u8>(),
        incompat_flags in any::<u8>(),
        compat_flags in any::<u8>(),
        seq in any::<u8>(),
        sysid in any::<u8>(),
        compid in any::<u8>(),
        msgid_lo in any::<u8>(),
        msgid_mid in any::<u8>(),
        msgid_hi in any::<u8>(),
    ) {
        let reference = v2_reference_encode(
            magic, len, incompat_flags, compat_flags, seq, sysid, compid,
            msgid_lo, msgid_mid, msgid_hi,
        );
        prop_assert_eq!(reference.len(), V2_HEADER_LEN);

        let codec = schema_codec();
        let entity = codec.to_entity(&reference).expect("schema decode");
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &reference[..]);
    }
}

/// Smoke test: a v2 HEARTBEAT header (msgid = 0, IFLAG_SIGNED off)
/// decodes through the schema and projects every byte to its
/// declared attribute. Pins the magic byte value (`0xFD`) and the
/// little-endian msgid layout (lo / mid / hi at offsets 7 / 8 / 9).
#[test]
fn heartbeat_header_decodes_each_field() {
    let codec = schema_codec();
    // HEARTBEAT: magic=0xFD, len=9 (HEARTBEAT payload), incompat=0
    // (unsigned), compat=0, seq=42, sysid=1, compid=1, msgid=0.
    let wire = v2_reference_encode(V2_MAGIC, 9, 0, 0, 42, 1, 1, HEARTBEAT_MSGID, 0, 0);
    let entity = codec.to_entity(&wire).expect("decode HEARTBEAT");
    // Every field projects to `Entity::attributes` under
    // `schema.mavlink.v2_header.<field>` (no `entity-path` declared).
    let attr = |name: &str| -> Option<i64> {
        match entity
            .attributes
            .get(&format!("schema.mavlink.v2_header.{name}"))
        {
            Some(AttributeValue::Int(v)) => Some(*v),
            _ => None,
        }
    };
    assert_eq!(attr("magic"), Some(0xFD));
    assert_eq!(attr("len"), Some(9));
    assert_eq!(attr("incompat_flags"), Some(0));
    assert_eq!(attr("compat_flags"), Some(0));
    assert_eq!(attr("seq"), Some(42));
    assert_eq!(attr("sysid"), Some(1));
    assert_eq!(attr("compid"), Some(1));
    assert_eq!(attr("msgid_lo"), Some(0));
    assert_eq!(attr("msgid_mid"), Some(0));
    assert_eq!(attr("msgid_hi"), Some(0));
}

/// Smoke test for the IFLAG_SIGNED bit: a header with
/// `incompat_flags = 0x01` decodes the flag byte and a re-encode
/// preserves it. This is the bit the v5-grammar variable-shift
/// `present-if` would key off of when the signature trailer
/// schema lands.
#[test]
fn iflag_signed_round_trips_through_incompat_flags() {
    let codec = schema_codec();
    let wire = v2_reference_encode(V2_MAGIC, 0, 0x01, 0, 0, 1, 1, 0, 0, 0);
    let entity = codec.to_entity(&wire).expect("decode IFLAG_SIGNED");
    let Some(AttributeValue::Int(flag)) = entity
        .attributes
        .get("schema.mavlink.v2_header.incompat_flags")
    else {
        panic!(
            "expected incompat_flags as Int, got {:?}",
            entity
                .attributes
                .get("schema.mavlink.v2_header.incompat_flags")
        );
    };
    assert_eq!(*flag, 0x01);
    let re_encoded = codec.from_entity(&entity).expect("re-encode");
    assert_eq!(&re_encoded[..], &wire[..]);
}

/// Smoke test for the 24-bit msgid spread across three little-
/// endian bytes. `0x123456` decomposes to `lo = 0x56, mid = 0x34,
/// hi = 0x12`. Pins that the schema does NOT byte-reverse the
/// msgid bytes (the wrapper recombines in little-endian order).
#[test]
fn msgid_24_bit_decomposes_little_endian() {
    let codec = schema_codec();
    let wire = v2_reference_encode(V2_MAGIC, 0, 0, 0, 0, 1, 1, 0x56, 0x34, 0x12);
    let entity = codec.to_entity(&wire).expect("decode wide msgid");
    let attr = |name: &str| -> i64 {
        match entity
            .attributes
            .get(&format!("schema.mavlink.v2_header.{name}"))
        {
            Some(AttributeValue::Int(v)) => *v,
            other => panic!("missing or wrong-typed {name}: {other:?}"),
        }
    };
    assert_eq!(attr("msgid_lo"), 0x56);
    assert_eq!(attr("msgid_mid"), 0x34);
    assert_eq!(attr("msgid_hi"), 0x12);
    // Verify wrapper-style recombination: hi << 16 | mid << 8 | lo.
    let combined = (attr("msgid_hi") << 16) | (attr("msgid_mid") << 8) | attr("msgid_lo");
    assert_eq!(combined, 0x12_3456);
}
