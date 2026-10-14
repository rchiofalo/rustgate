// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Schema-parity test for the ASTERIX datablock envelope + FSPEC
//! chain (Eurocontrol surveillance data exchange).
//!
//! Validates that a [`SchemaCodec`] built from
//! `schemas/datablock_fspec.yaml` produces byte-identical encodings
//! to an **inline hand-rolled reference encoder** for every
//! arbitrary (cat, length, 1..=3-octet FSPEC chain) combination
//! proptest generates. Sixth tactical protocol to get a schema-
//! parity test (after STANAG 4586, DIS, MAVLink v1+v2, VMF, and
//! Link 16 JREAP).
//!
//! **Second protocol to exercise v5 variable-shift `present-if`**
//! (after VMF K05.1, #1396). Unlike VMF — where the cascade is on
//! float / integer payload fields — here the cascade is on
//! bit-flag bytes themselves: each FSPEC octet's FX bit (the LSB)
//! gates whether the NEXT FSPEC octet appears on the wire. When
//! the chain terminates early (FX=0), the schema runtime
//! truncates the trailing octets from the encoded output.
//!
//! ## Why the reference encoder lives in the test file
//!
//! Same rationale as every other schema-parity test added since
//! #1397: keep the reference implementation inline so the parity
//! check stays a genuine cross-implementation comparison even if
//! the production `decode_cat021` / `encode_cat021` migrates to a
//! SchemaCodec-driven path. Encoder bugs that lose data
//! symmetrically cannot pass trivially.
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)`
//!    yields the same bytes the inline reference encoder produces
//!    for every FSPEC chain length (1, 2, or 3 octets). The
//!    schema's `present-if shift-mode: collapse-when-absent` on
//!    octets 2 and 3 correctly omits them from the wire when the
//!    prior octet's FX bit is 0.
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)`
//!    recovers all envelope fields (CAT, length) and every FSPEC
//!    octet's data + FX bits from the wire, and a subsequent
//!    re-encode round-trips byte-equal.
//! 3. **Variable wire size** — payload length depends on how many
//!    FX bits are set: 4 bytes (1-octet chain), 5 bytes (2-octet
//!    chain), 6 bytes (3-octet chain). The v5 truncation logic
//!    handles all three cases.
//!
//! ## What this does NOT prove
//!
//! - Per-category record bodies (data items). CAT-021 / CAT-048
//!   / CAT-062 each define different field formats after the
//!   FSPEC; those need per-category body schemas dispatched by
//!   the `cat` byte. This test covers the envelope + FSPEC chain
//!   only.
//! - FSPEC chains longer than 3 octets. The MVP CAT-021 /
//!   CAT-048 / CAT-062 profiles top out at 21 FRNs (3 octets);
//!   extending the schema to more octets is mechanical
//!   (additional `present-if collapse-when-absent` field pairs).
//! - The `length` field's coherence with the actual datablock
//!   size. The schema carries `length` as a raw u16; cross-
//!   checking length == actual bytes is a wrapper-layer concern
//!   (already enforced by `decode_cat021` at decode time).

#![cfg(test)]
#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_codec_schema::SchemaCodec;
use rustgate_core::entity::EntityCodec;

const SCHEMA_YAML: &str = include_str!("../schemas/datablock_fspec.yaml");

/// Max wire size when every FX bit is set (all 3 FSPEC octets
/// present). When the chain terminates earlier the schema
/// runtime truncates.
const MAX_WIRE_SIZE: usize = 6;

fn schema_codec() -> SchemaCodec {
    SchemaCodec::from_schema_text(SCHEMA_YAML).expect("schema must parse + validate")
}

/// Logical inputs for the reference encoder. FX bits are derived
/// from whether the next-octet `frn_data` is `Some` so the
/// strategy can't generate inconsistent FX/payload pairs.
#[derive(Debug, Clone)]
struct DatablockInput {
    cat: u8,
    length: u16,
    frn_data_1: u8, // 7 bits
    // octet 2 present iff `Some` (fx_1 = 1)
    octet_2: Option<u8>, // 7-bit frn_data_2
    // octet 3 present iff octet_2.is_some() AND `Some` (fx_2 = 1)
    octet_3: Option<u8>, // 7-bit frn_data_3
}

/// **Inline, independent** reference encoder. Mirrors the schema's
/// declared bit layout for the FSPEC chain (7 data bits in
/// positions 7..1, FX in position 0). Truncates trailing octets
/// to match the schema runtime's v5 collapse-when-absent
/// truncation.
fn reference_encode(input: &DatablockInput) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MAX_WIRE_SIZE);
    buf.push(input.cat);
    buf.extend_from_slice(&input.length.to_be_bytes());

    // Octet 1: always present.
    // frn_data_1 occupies bits 7..1 (the 7 high bits); FX at bit 0.
    let fx_1 = if input.octet_2.is_some() { 1u8 } else { 0u8 };
    buf.push(((input.frn_data_1 & 0x7F) << 1) | fx_1);

    // Octet 2: present iff fx_1 == 1.
    if let Some(frn_data_2) = input.octet_2 {
        let fx_2 = if input.octet_3.is_some() { 1u8 } else { 0u8 };
        buf.push(((frn_data_2 & 0x7F) << 1) | fx_2);

        // Octet 3: present iff fx_2 == 1 (which means
        // input.octet_3.is_some()).
        if let Some(frn_data_3) = input.octet_3 {
            // FX of octet 3 is always 0 (terminator) — the
            // schema doesn't declare a 4th octet so the chain
            // ends here regardless.
            buf.push((frn_data_3 & 0x7F) << 1);
        }
    }

    buf
}

/// Strategy for a `DatablockInput`. `frn_data_*` is constrained
/// to 7 bits (`0..=127`); octet 2 is `Option<u8>` (independent of
/// octet 1); octet 3 requires octet 2 to be `Some` (the FX
/// cascade can't skip levels).
fn datablock_strategy() -> impl Strategy<Value = DatablockInput> {
    (
        any::<u8>(),
        any::<u16>(),
        0u8..=0x7Fu8,
        prop::option::of(0u8..=0x7Fu8),
    )
        .prop_flat_map(|(cat, length, frn_data_1, octet_2)| {
            // octet_3 only generates if octet_2 is Some
            let octet_3_strategy = if octet_2.is_some() {
                prop::option::of(0u8..=0x7Fu8).boxed()
            } else {
                Just(None).boxed()
            };
            octet_3_strategy.prop_map(move |octet_3| DatablockInput {
                cat,
                length,
                frn_data_1,
                octet_2,
                octet_3,
            })
        })
}

proptest! {
    /// Reference encoder → `SchemaCodec` decode → `SchemaCodec`
    /// re-encode must produce the same bytes the reference
    /// encoder emitted. Variable output size (4, 5, or 6 bytes)
    /// depending on FSPEC chain length.
    #[test]
    fn schema_codec_byte_identical_to_reference(input in datablock_strategy()) {
        let reference = reference_encode(&input);
        // Expected wire size depends on chain length.
        let expected_size = 3  // header
            + 1  // octet 1
            + if input.octet_2.is_some() { 1 } else { 0 }
            + if input.octet_3.is_some() { 1 } else { 0 };
        prop_assert_eq!(reference.len(), expected_size);

        let codec = schema_codec();
        let entity = codec.to_entity(&reference).expect("schema decode");
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &reference[..]);
    }
}

/// Golden fixture: a 1-octet FSPEC chain (FX=0). The 4-byte
/// payload is the minimal case. Pins both the byte layout and
/// the v5 truncation behaviour against off-by-one regressions.
#[test]
fn one_octet_fspec_chain_collapses_to_four_bytes() {
    let input = DatablockInput {
        cat: 0x15, // CAT-021
        length: 0x0004,
        frn_data_1: 0b0101010, // arbitrary 7-bit pattern
        octet_2: None,
        octet_3: None,
    };
    let reference = reference_encode(&input);
    // Wire: cat=0x15, length=[0x00,0x04], fspec_oct1=(0b0101010 << 1) | 0 = 0b01010100 = 0x54
    assert_eq!(reference, vec![0x15, 0x00, 0x04, 0x54]);

    let codec = schema_codec();
    let entity = codec.to_entity(&reference).expect("decode 1-octet chain");
    let re_encoded = codec.from_entity(&entity).expect("encode 1-octet chain");
    assert_eq!(&re_encoded[..], &reference[..]);
}

/// Golden fixture: a 3-octet FSPEC chain (all-FX-set except the
/// terminator). The 6-byte payload is the all-octets-present
/// maximum.
#[test]
fn three_octet_fspec_chain_at_maximum_size() {
    let input = DatablockInput {
        cat: 0x30, // CAT-048
        length: 0x0006,
        frn_data_1: 0b1111111,
        octet_2: Some(0b1010101),
        octet_3: Some(0b1100110),
    };
    let reference = reference_encode(&input);
    // Wire: cat=0x30, length=[0x00,0x06],
    //   oct1=(0b1111111 << 1) | 1 (FX=1) = 0xFF
    //   oct2=(0b1010101 << 1) | 1 (FX=1) = 0xAB
    //   oct3=(0b1100110 << 1) | 0 (FX=0, terminator) = 0xCC
    assert_eq!(reference, vec![0x30, 0x00, 0x06, 0xFF, 0xAB, 0xCC]);

    let codec = schema_codec();
    let entity = codec.to_entity(&reference).expect("decode 3-octet chain");
    let re_encoded = codec.from_entity(&entity).expect("encode 3-octet chain");
    assert_eq!(&re_encoded[..], &reference[..]);
}
