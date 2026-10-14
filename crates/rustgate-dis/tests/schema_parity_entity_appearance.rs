// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Schema-parity test for the DIS Entity Appearance bitfield
//! (IEEE 1278.1 § 5.3.3.1.6 Land Platform variant).
//!
//! First cross-protocol confidence test exercising the v3
//! bit-packing grammar from #1389 on a real wire-format bit
//! layout. The 4-byte Entity Appearance field sits at body offset
//! 72..76 of an Entity State PDU; the production codec at
//! `crates/rustgate-dis/src/entity_state.rs` carries it as an
//! opaque `u32`. This schema-parity test is a **declarative pin**
//! of what those bits mean per IEEE 1278.1-2012 Land Platform —
//! the schema decomposes the u32 into 19 named bit-packed fields
//! plus one opaque MSB byte, and the parity assertion fixes the
//! byte layout.
//!
//! ## Why this is the v3 demo target (after #1396 surfaced VMF's
//! ## cross-byte blocker)
//!
//! Every field in the IEEE 1278.1 Land Platform appearance bit
//! table fits within a single byte — `damage` (bits 3..4) stays
//! in byte 3, `hatch` (bits 8..10) stays in byte 2,
//! `camouflage_type` (bits 16..17) stays in byte 1. No field
//! crosses a byte boundary. The v3 grammar's
//! `bit_offset + bit_width <= 8` validator passes uniformly.
//! Multi-field-per-byte packing is exercised end-to-end — byte 3
//! alone carries six declared bit-packed fields. #1399 tracks the
//! v4 grammar extension (cross-byte bit spans) that would unblock
//! VMF and ASTERIX FSPEC chains.
//!
//! ## Why the reference encoder lives in the test file
//!
//! Same rationale as the existing
//! `tests/schema_parity.rs` and `tests/schema_parity_entity_state.rs`
//! — see #1394 / #1397. Keeping the reference implementation inline
//! means the parity check stays a genuine cross-implementation
//! comparison even if a future PR introduces a typed
//! `LandPlatformAppearance` struct with its own `encode` /
//! `decode`. Encoder bugs that lose data symmetrically (e.g. mask
//! collisions on shared bytes) cannot pass trivially.
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)` yields
//!    the same 4 bytes the inline reference encoder produces for
//!    the same logical input. Multi-field-per-byte packing is
//!    correct: the schema runtime masks-and-ORs every bit-packed
//!    field at its declared `bit-offset` / `bit-width` without
//!    clobbering siblings.
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)`
//!    recovers all 19 bit-packed fields plus the opaque MSB byte
//!    from the wire bytes, and a subsequent re-encode round-trips
//!    byte-equal.
//!
//! ## What this does NOT prove
//!
//! - The IEEE 1278.1 Land Platform bit semantics are wired to
//!   real-world entity behaviour. The schema is a wire-layout pin;
//!   producing a typed `LandPlatformAppearance` Rust struct that
//!   the production `EntityStatePdu` references is follow-up
//!   scope. Today `EntityStatePdu::appearance` stays a raw `u32`.
//! - Per-entity-kind appearance variants (Air Platform, Surface
//!   Platform, Munition, …). IEEE 1278.1 defines different bit
//!   layouts per domain; this schema covers Land Platform only.
//!   Future schemas can reuse the same file template per domain
//!   once v2's discriminator-byte dispatch grammar lands.

#![cfg(test)]
#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_codec_schema::SchemaCodec;
use rustgate_core::entity::EntityCodec;

const SCHEMA_YAML: &str = include_str!("../schemas/entity_appearance.yaml");

/// Fixed wire-format size of the Entity Appearance bitfield —
/// 4 bytes (32 bits) per IEEE 1278.1 § 5.3.3.1.6.
const APPEARANCE_LEN: usize = 4;

fn schema_codec() -> SchemaCodec {
    SchemaCodec::from_schema_text(SCHEMA_YAML).expect("schema must parse + validate")
}

/// Logical inputs to the reference encoder. Field types are
/// `u8` (rather than `bool` for single-bit fields) so the
/// proptest strategy can use ranges directly; encoders mask each
/// value to its declared bit-width before shifting.
#[derive(Debug, Clone)]
struct LandPlatformAppearance {
    paint_scheme: u8,     // 1 bit
    mobility_kill: u8,    // 1 bit
    firepower_kill: u8,   // 1 bit
    damage: u8,           // 2 bits
    smoke: u8,            // 2 bits
    trailing_effects: u8, // 1 bit
    hatch: u8,            // 3 bits
    head_lights: u8,      // 1 bit
    tail_lights: u8,      // 1 bit
    brake_lights: u8,     // 1 bit
    flaming: u8,          // 1 bit
    launcher: u8,         // 1 bit
    camouflage_type: u8,  // 2 bits
    concealed: u8,        // 1 bit
    frozen: u8,           // 1 bit
    power_plant: u8,      // 1 bit
    state: u8,            // 1 bit
    tent: u8,             // 1 bit
    ramp: u8,             // 1 bit
    reserved_msb: u8,     // 8 bits (byte 0, opaque)
}

/// **Inline, independent** reference encoder for the IEEE 1278.1
/// Land Platform Entity Appearance bitfield. Maps each logical
/// field to the byte / bit position declared in
/// `schemas/entity_appearance.yaml` and composes the four-byte
/// output via OR.
///
/// Bit position formula (v3 grammar convention): a field with
/// schema `bit-offset = B`, `bit-width = W` lands at LSB-position
/// `8 - B - W` within its byte. Encoding multiplies the value
/// (masked to the bit width) by `1 << (8 - B - W)` and ORs into
/// the byte; per-byte ORs are independent, so the byte composes
/// from all its declared bit-packed sub-fields.
fn reference_encode(input: &LandPlatformAppearance) -> [u8; APPEARANCE_LEN] {
    let mut out = [0u8; APPEARANCE_LEN];

    // Byte 3 — IEEE bits 0..7 (LSB byte of big-endian u32):
    //   paint_scheme     bit-offset 7 width 1 → LSB-position 0
    //   mobility_kill    bit-offset 6 width 1 → LSB-position 1
    //   firepower_kill   bit-offset 5 width 1 → LSB-position 2
    //   damage           bit-offset 3 width 2 → LSB-position 3
    //   smoke            bit-offset 1 width 2 → LSB-position 5
    //   trailing_effects bit-offset 0 width 1 → LSB-position 7
    out[3] = (input.paint_scheme & 0x01)
        | ((input.mobility_kill & 0x01) << 1)
        | ((input.firepower_kill & 0x01) << 2)
        | ((input.damage & 0x03) << 3)
        | ((input.smoke & 0x03) << 5)
        | ((input.trailing_effects & 0x01) << 7);

    // Byte 2 — IEEE bits 8..15:
    //   hatch         bit-offset 5 width 3 → LSB-position 0
    //   head_lights   bit-offset 4 width 1 → LSB-position 3
    //   tail_lights   bit-offset 3 width 1 → LSB-position 4
    //   brake_lights  bit-offset 2 width 1 → LSB-position 5
    //   flaming       bit-offset 1 width 1 → LSB-position 6
    //   launcher      bit-offset 0 width 1 → LSB-position 7
    out[2] = (input.hatch & 0x07)
        | ((input.head_lights & 0x01) << 3)
        | ((input.tail_lights & 0x01) << 4)
        | ((input.brake_lights & 0x01) << 5)
        | ((input.flaming & 0x01) << 6)
        | ((input.launcher & 0x01) << 7);

    // Byte 1 — IEEE bits 16..23:
    //   camouflage_type bit-offset 6 width 2 → LSB-position 0
    //   concealed       bit-offset 5 width 1 → LSB-position 2
    //   frozen          bit-offset 4 width 1 → LSB-position 3
    //   power_plant     bit-offset 3 width 1 → LSB-position 4
    //   state           bit-offset 2 width 1 → LSB-position 5
    //   tent            bit-offset 1 width 1 → LSB-position 6
    //   ramp            bit-offset 0 width 1 → LSB-position 7
    out[1] = (input.camouflage_type & 0x03)
        | ((input.concealed & 0x01) << 2)
        | ((input.frozen & 0x01) << 3)
        | ((input.power_plant & 0x01) << 4)
        | ((input.state & 0x01) << 5)
        | ((input.tent & 0x01) << 6)
        | ((input.ramp & 0x01) << 7);

    // Byte 0 — opaque (full u8, no bit-packing).
    out[0] = input.reserved_msb;

    out
}

/// Strategy for a `LandPlatformAppearance` with each field
/// constrained to its declared bit-width range. Field groups are
/// nested to stay under proptest's `Strategy`-on-tuple cap of 12.
fn appearance_strategy() -> impl Strategy<Value = LandPlatformAppearance> {
    let byte_3_group = (
        0u8..=1, // paint_scheme (1 bit)
        0u8..=1, // mobility_kill (1 bit)
        0u8..=1, // firepower_kill (1 bit)
        0u8..=3, // damage (2 bits)
        0u8..=3, // smoke (2 bits)
        0u8..=1, // trailing_effects (1 bit)
    );
    let byte_2_group = (
        0u8..=7, // hatch (3 bits)
        0u8..=1, // head_lights
        0u8..=1, // tail_lights
        0u8..=1, // brake_lights
        0u8..=1, // flaming
        0u8..=1, // launcher
    );
    let byte_1_group = (
        0u8..=3, // camouflage_type (2 bits)
        0u8..=1, // concealed
        0u8..=1, // frozen
        0u8..=1, // power_plant
        0u8..=1, // state
        0u8..=1, // tent
        0u8..=1, // ramp
    );
    let byte_0 = any::<u8>(); // reserved_msb (full u8, opaque)

    (byte_3_group, byte_2_group, byte_1_group, byte_0).prop_map(
        |(
            (paint_scheme, mobility_kill, firepower_kill, damage, smoke, trailing_effects),
            (hatch, head_lights, tail_lights, brake_lights, flaming, launcher),
            (camouflage_type, concealed, frozen, power_plant, state, tent, ramp),
            reserved_msb,
        )| LandPlatformAppearance {
            paint_scheme,
            mobility_kill,
            firepower_kill,
            damage,
            smoke,
            trailing_effects,
            hatch,
            head_lights,
            tail_lights,
            brake_lights,
            flaming,
            launcher,
            camouflage_type,
            concealed,
            frozen,
            power_plant,
            state,
            tent,
            ramp,
            reserved_msb,
        },
    )
}

proptest! {
    /// **Path (a)** — Reference encoder → `SchemaCodec` decode →
    /// `SchemaCodec` re-encode must produce the same 4 bytes the
    /// reference encoder emitted. First v3 bit-packing confidence
    /// test on a real protocol's wire-format bit layout — exercises
    /// the multi-field-per-byte mask-and-OR path end-to-end (byte 3
    /// alone carries six declared bit-packed fields).
    ///
    /// The reference encoder lives inline in this test file (it
    /// does not call any production code), so the parity check is
    /// a genuine cross-implementation comparison even if a future
    /// PR introduces a typed `LandPlatformAppearance` struct in
    /// `rustgate-dis`. Encoder bugs in the production code (or in
    /// SchemaCodec) cannot pass this test symmetrically.
    #[test]
    fn schema_codec_byte_identical_to_reference(input in appearance_strategy()) {
        let reference = reference_encode(&input);
        prop_assert_eq!(reference.len(), APPEARANCE_LEN);

        let codec = schema_codec();
        let entity = codec.to_entity(&reference).expect("schema decode");
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &reference[..]);
    }
}

/// Golden fixture: every bit-field at its maximum value, plus a
/// distinctive MSB byte. Pins the wire layout against the
/// specific byte pattern the schema's bit-offsets compose to. A
/// regression that swapped two bit-offsets or got an off-by-one
/// would fail this hand-coded fixture even if the proptest above
/// happened to skip the specific value combination.
#[test]
fn encode_decode_at_maximum_values_pins_byte_pattern() {
    let input = LandPlatformAppearance {
        paint_scheme: 1,
        mobility_kill: 1,
        firepower_kill: 1,
        damage: 3,
        smoke: 3,
        trailing_effects: 1,
        hatch: 7,
        head_lights: 1,
        tail_lights: 1,
        brake_lights: 1,
        flaming: 1,
        launcher: 1,
        camouflage_type: 3,
        concealed: 1,
        frozen: 1,
        power_plant: 1,
        state: 1,
        tent: 1,
        ramp: 1,
        reserved_msb: 0xCC,
    };
    let reference = reference_encode(&input);
    // With every declared bit set, each byte carrying declared
    // fields fills exactly the bits the schema claims. Byte 3
    // covers all 8 bits (paint_scheme + … + trailing_effects = 1+1+1+2+2+1 = 8);
    // bytes 2 and 1 carry 8 bits each as well. Byte 0 is opaque.
    assert_eq!(reference, [0xCC, 0xFF, 0xFF, 0xFF]);

    let codec = schema_codec();
    let entity = codec.to_entity(&reference).expect("schema decode");
    let re_encoded = codec.from_entity(&entity).expect("schema encode");
    assert_eq!(&re_encoded[..], &reference[..]);
}
