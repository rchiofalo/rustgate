// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Schema-parity test for the Link 16 JREAP-C frame header (STANAG
//! 5518).
//!
//! Validates that a [`SchemaCodec`] built from
//! `schemas/jreap_header.yaml` produces byte-identical encodings to
//! an **inline hand-rolled reference encoder** for every arbitrary
//! 16-byte header proptest generates. Fifth cross-protocol
//! confidence test for the declarative schema vocabulary after
//! STANAG 4586 (#1365), DIS (#1373, #1395, #1400), MAVLink (#1375,
//! v2 #1406), and VMF K05.1 (#1396).
//!
//! ## Why the reference encoder lives in the test file
//!
//! Same rationale as the existing schema-parity tests — see #1394
//! / #1397. Keeping the reference implementation inline means the
//! parity check stays a genuine cross-implementation comparison
//! even if `JreapFrame::encode_into` later migrates to a
//! SchemaCodec-driven path. Encoder bugs that lose data
//! symmetrically (e.g. the #1393 STANAG class of regression where
//! a buffer-zeroing fallback silently dropped fields) cannot pass
//! trivially.
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)` yields
//!    the same 16 bytes the inline reference encoder produces.
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)`
//!    recovers all seven fields from the wire bytes, and a
//!    subsequent re-encode round-trips byte-equal.
//! 3. **Public API round-trip** — `JreapFrame::encode_into` →
//!    `JreapFrame::decode` preserves every typed field of the
//!    wrapper struct, **for the JREAP-C version (`0x03`) only**
//!    (the wrapper rejects other versions at decode time per its
//!    spec contract).
//!
//! ## What this does NOT prove
//!
//! - The `JreapMessageType` enum byte → typed-variant mapping.
//!   v2 `value-mapping` could encode the dispatch but the typed
//!   `Other(byte)` arm is lossy-by-design for unknown bytes; the
//!   schema carries the raw byte verbatim and the wrapper's
//!   typed projection lives in Rust.
//! - Per-message-type body shapes. J2.2 / J3.x / J7.x / J12.x
//!   each need their own body schema dispatched after the header.

#![cfg(test)]
#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_codec_schema::SchemaCodec;
use rustgate_core::entity::EntityCodec;
use rustgate_link16::header::{JREAP_HEADER_LEN, JreapFrame, JreapMessageType};

const SCHEMA_YAML: &str = include_str!("../schemas/jreap_header.yaml");

/// Wire-byte value for JREAP-C. The hand-rolled `JreapFrame::decode`
/// rejects any other version with `Link16Error::UnsupportedVersion`,
/// so the public-API round-trip proptest pins this constant.
const JREAP_C_VERSION: u8 = 0x03;

fn schema_codec() -> SchemaCodec {
    SchemaCodec::from_schema_text(SCHEMA_YAML).expect("schema must parse + validate")
}

/// **Inline, independent** reference encoder for the JREAP-C
/// frame header. Byte-coded against `schemas/jreap_header.yaml`
/// so the parity assertion is a genuine cross-implementation
/// comparison even if `JreapFrame::encode_into` migrates to a
/// SchemaCodec-driven path in the future.
fn reference_encode(
    version: u8,
    message_type: u8,
    exercise_id: u8,
    reserved: u8,
    sequence: u32,
    timestamp: u32,
    body_length: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(JREAP_HEADER_LEN);
    buf.push(version);
    buf.push(message_type);
    buf.push(exercise_id);
    buf.push(reserved);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(&body_length.to_be_bytes());
    buf
}

proptest! {
    /// **Path (a)** — Reference encoder → `SchemaCodec` decode →
    /// `SchemaCodec` re-encode must produce the same 16 bytes the
    /// reference encoder emitted. The wire-format invariant: byte
    /// offsets are stable, big-endian u32 ordering is correct,
    /// the reserved byte round-trips verbatim.
    ///
    /// Proptest generates the full 256-value range for each u8
    /// field and the full u32 range for sequence/timestamp/
    /// body_length, including the `version != 0x03` non-JREAP-C
    /// cases the wrapper rejects at decode (the schema-parity
    /// half makes no such constraint — it carries the raw byte).
    #[test]
    fn schema_codec_byte_identical_to_reference(
        version in any::<u8>(),
        message_type in any::<u8>(),
        exercise_id in any::<u8>(),
        reserved in any::<u8>(),
        sequence in any::<u32>(),
        timestamp in any::<u32>(),
        body_length in any::<u32>(),
    ) {
        let reference = reference_encode(
            version, message_type, exercise_id, reserved, sequence, timestamp, body_length,
        );
        prop_assert_eq!(reference.len(), JREAP_HEADER_LEN);

        let codec = schema_codec();
        let entity = codec.to_entity(&reference).expect("schema decode");
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &reference[..]);
    }

    /// **Path (c)** — Public-API round-trip: `JreapFrame::encode_into`
    /// → `JreapFrame::decode` must preserve every typed field. The
    /// `version` field is pinned to `0x03` (JREAP-C) because the
    /// wrapper-side decode rejects any other version, so the
    /// proptest restricts the strategy to that domain.
    #[test]
    fn public_api_round_trip_preserves_typed_fields(
        message_type_byte in any::<u8>(),
        exercise_id in any::<u8>(),
        reserved in any::<u8>(),
        sequence in any::<u32>(),
        timestamp in any::<u32>(),
        body_length in any::<u32>(),
    ) {
        let frame = JreapFrame {
            version: JREAP_C_VERSION,
            message_type: JreapMessageType::from_u8(message_type_byte),
            exercise_id,
            reserved,
            sequence,
            timestamp,
            body_length,
        };
        let mut bytes = Vec::with_capacity(JREAP_HEADER_LEN);
        frame.encode_into(&mut bytes);
        prop_assert_eq!(bytes.len(), JREAP_HEADER_LEN);

        let decoded = JreapFrame::decode(&bytes).expect("public-API round-trip");

        prop_assert_eq!(decoded.version, frame.version);
        prop_assert_eq!(decoded.message_type, frame.message_type);
        prop_assert_eq!(decoded.exercise_id, frame.exercise_id);
        prop_assert_eq!(decoded.reserved, frame.reserved);
        prop_assert_eq!(decoded.sequence, frame.sequence);
        prop_assert_eq!(decoded.timestamp, frame.timestamp);
        prop_assert_eq!(decoded.body_length, frame.body_length);
    }
}

/// Golden fixture: a canonical JREAP-C header pinned against a
/// known byte pattern. Pins the wire layout (offsets, big-endian
/// u32 ordering) against off-by-one regressions that would slip
/// past the proptest if it happened to skip the specific values
/// below.
#[test]
fn canonical_header_pins_byte_layout() {
    // version=0x03, message_type=0x01 (JseriesData), exercise=0x11,
    // reserved=0x00, sequence=0x12345678, timestamp=0x6553_5300,
    // body_length=0x100.
    let reference = reference_encode(0x03, 0x01, 0x11, 0x00, 0x12345678, 0x65535300, 0x100);
    assert_eq!(
        reference,
        vec![
            0x03, 0x01, 0x11, 0x00, // version, message_type, exercise, reserved
            0x12, 0x34, 0x56, 0x78, // sequence (big-endian u32)
            0x65, 0x53, 0x53, 0x00, // timestamp (big-endian u32)
            0x00, 0x00, 0x01, 0x00, // body_length (big-endian u32)
        ]
    );

    // Schema round-trip pins the same byte layout.
    let codec = schema_codec();
    let entity = codec.to_entity(&reference).expect("decode canonical");
    let re_encoded = codec.from_entity(&entity).expect("encode canonical");
    assert_eq!(&re_encoded[..], &reference[..]);

    // Public API also decodes the same bytes.
    let decoded = JreapFrame::decode(&reference).expect("decode canonical via wrapper");
    assert_eq!(decoded.version, 0x03);
    assert_eq!(decoded.message_type, JreapMessageType::JseriesData);
    assert_eq!(decoded.exercise_id, 0x11);
    assert_eq!(decoded.reserved, 0x00);
    assert_eq!(decoded.sequence, 0x12345678);
    assert_eq!(decoded.timestamp, 0x65535300);
    assert_eq!(decoded.body_length, 0x100);
}
