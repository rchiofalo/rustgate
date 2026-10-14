// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Schema-parity test for the DIS Entity State PDU body.
//!
//! Validates that a [`SchemaCodec`] built from
//! `schemas/entity_state.yaml` produces byte-identical encodings to
//! an **inline hand-rolled reference encoder** for every arbitrary
//! `(entity_id, force_id, num_articulation_parameters, …,
//! articulation_parameters: Vec<[u8; 16]>)` combination proptest
//! generates. First confidence test exercising the v3 schema
//! grammar's variable-length repeat (`count-from`) on a real
//! protocol body — `pdu_header.yaml` only covered the
//! fixed-12-byte common header (#1373); this covers the 132-byte
//! fixed prefix plus the `N×16-byte` articulation parameters tail
//! that #1387 unlocked.
//!
//! ## Why the reference encoder lives in the test file
//!
//! Same rationale as the existing
//! `tests/schema_parity.rs` (header parity) — see #1394 / #1397.
//! Keeping the reference implementation inline means the parity
//! check stays a genuine cross-implementation comparison even if
//! `EntityStatePdu::encode` later migrates to a SchemaCodec-driven
//! path. Encoder bugs that lose data symmetrically (e.g. buffer
//! zeroing on a finite-float rejection, the #1393 STANAG class of
//! regression) cannot pass trivially.
//!
//! ## What this proves
//!
//! 1. **Encode parity** — `SchemaCodec::from_entity(entity)` yields
//!    the same `132 + 16×count` bytes the inline reference encoder
//!    produces for the same logical body. The schema runtime
//!    correctly resolves the `count-from: num_articulation_parameters`
//!    repeat at runtime — it reads the count byte from the entity
//!    attribute, multiplies by `record-size-bytes: 16`, and writes
//!    that many tail bytes from the `articulation_parameters`
//!    attribute.
//! 2. **Decode parity** — `SchemaCodec::to_entity(payload)`
//!    recovers all thirteen body fields plus the variable-length
//!    tail from the wire bytes, and a subsequent re-encode round-
//!    trips byte-equal.
//! 3. **Public API round-trip** — `EntityStatePdu::encode →
//!    EntityStatePdu::decode` preserves every typed field of the
//!    typed wrapper (within the marking-NUL-strip semantics of the
//!    production codec — the proptest constrains marking to
//!    NUL-free ASCII so the lossy NUL-strip / re-pad path doesn't
//!    confound the assertion).
//!
//! ## What this does NOT prove
//!
//! - Per-composite typed projection. `entity_id` decomposes to
//!   `(site, application, entity)`, `entity_type` to 7 fields,
//!   `dead_reckoning` to 4 sub-fields, each articulation record to
//!   5 typed fields. The schema treats each composite as an opaque
//!   `bytes` blob because (a) the parity contract is byte-equivalence
//!   and (b) the schema runtime's f32/f64 encoder rejects non-finite
//!   inputs per #1362, so typed primitive splits would need NaN
//!   filtering at the strategy level just to make the round-trip
//!   well-defined. Typed projection lands when the schema grows
//!   nested-record / submessage grammar.
//! - The 144-byte total PDU. This test covers the BODY only — the
//!   12-byte header sits in `schemas/pdu_header.yaml` with its own
//!   parity test (`tests/schema_parity.rs`). A future schema
//!   feature ("schema chaining" / "header + body") will let one
//!   schema reference another; until then, the two parity tests
//!   are independent and the production codec composes them at the
//!   call-site.
//! - ECEF ↔ WGS-84 coordinate conversion. The wire bytes encode
//!   ECEF directly; the `rustgate_dis::coord` module owns the
//!   WGS-84 projection and is out of scope for the parity test.

#![cfg(test)]
#![allow(clippy::panic, clippy::unwrap_used)]

use proptest::prelude::*;
use rustgate_codec_schema::SchemaCodec;
use rustgate_core::entity::EntityCodec;
use rustgate_dis::entity_state::{
    ARTICULATION_PARAMETER_LEN, ArticulationParameter, DeadReckoningParameters,
    ENTITY_STATE_FIXED_BODY_LEN, EntityId, EntityStatePdu, EntityType, ForceId,
};
use rustgate_dis::header::{HEADER_LEN, PduHeader, PduType, ProtocolFamily};

const SCHEMA_YAML: &str = include_str!("../schemas/entity_state.yaml");

/// Cap on the articulation-parameter count proptest generates.
/// Each iteration produces `132 + 16×count` body bytes, so a low
/// cap keeps the run fast while still exercising the
/// `count-from` repeat path (count = 0 covers the empty-tail edge,
/// count > 0 covers the non-empty path).
const MAX_ARTICULATION_PARAMETERS: u8 = 8;

fn schema_codec() -> SchemaCodec {
    SchemaCodec::from_schema_text(SCHEMA_YAML).expect("schema must parse + validate")
}

/// Inputs to the reference encoder. The `num_articulation_parameters`
/// byte at body offset 7 is derived from `articulation_parameters.len()`
/// — proptest cannot have it generate independently because that
/// would let `count == 3` ride alongside `articulation_parameters.len() == 5`
/// and decode/encode would disagree about the tail length.
#[derive(Debug, Clone)]
struct EntityStateBodyInput {
    entity_id: [u8; 6],
    force_id: u8,
    entity_type: [u8; 8],
    alternative_entity_type: [u8; 8],
    linear_velocity: [u8; 12],
    location_ecef: [u8; 24],
    orientation: [u8; 12],
    appearance: u32,
    dead_reckoning: [u8; 40],
    marking_charset: u8,
    marking: [u8; 11],
    capabilities: u32,
    articulation_parameters: Vec<[u8; 16]>,
}

/// **Inline, independent** reference encoder for the DIS Entity
/// State PDU body. Byte-coded against
/// `schemas/entity_state.yaml` so the parity assertion is a
/// genuine cross-implementation comparison even if
/// `EntityStatePdu::encode` migrates to a SchemaCodec-driven path
/// in the future.
fn reference_encode(input: &EntityStateBodyInput) -> Vec<u8> {
    let count = input.articulation_parameters.len();
    let total = ENTITY_STATE_FIXED_BODY_LEN + count * ARTICULATION_PARAMETER_LEN;
    let mut buf = vec![0u8; total];
    buf[0..6].copy_from_slice(&input.entity_id);
    buf[6] = input.force_id;
    // `count` is bounded by `MAX_ARTICULATION_PARAMETERS` (≤ u8::MAX)
    // by the strategy, so this cast is total.
    buf[7] = count as u8;
    buf[8..16].copy_from_slice(&input.entity_type);
    buf[16..24].copy_from_slice(&input.alternative_entity_type);
    buf[24..36].copy_from_slice(&input.linear_velocity);
    buf[36..60].copy_from_slice(&input.location_ecef);
    buf[60..72].copy_from_slice(&input.orientation);
    buf[72..76].copy_from_slice(&input.appearance.to_be_bytes());
    buf[76..116].copy_from_slice(&input.dead_reckoning);
    buf[116] = input.marking_charset;
    buf[117..128].copy_from_slice(&input.marking);
    buf[128..132].copy_from_slice(&input.capabilities.to_be_bytes());
    for (i, record) in input.articulation_parameters.iter().enumerate() {
        let start = ENTITY_STATE_FIXED_BODY_LEN + i * ARTICULATION_PARAMETER_LEN;
        let end = start + ARTICULATION_PARAMETER_LEN;
        buf[start..end].copy_from_slice(record);
    }
    buf
}

/// Strategy for a fixed-size `[u8; N]` array. proptest's
/// `Arbitrary` impl for arrays maxes out at a small N; we need
/// `[u8; 40]` for `dead_reckoning`, so build a generic helper
/// driven by `prop::collection::vec` and a `copy_from_slice` into
/// a stack array.
fn fixed_bytes_strategy<const N: usize>() -> impl Strategy<Value = [u8; N]> {
    prop::collection::vec(any::<u8>(), N).prop_map(|v| {
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    })
}

/// Strategy for an `EntityStateBodyInput`. The articulation list
/// length is bounded by [`MAX_ARTICULATION_PARAMETERS`] so each
/// proptest iteration stays cheap; the per-record bytes are still
/// fully arbitrary, exercising the schema runtime's repeat-write
/// path with non-zero record contents (zero-buffer fallbacks would
/// otherwise pass the byte-identical assertion trivially).
///
/// Field tuples are nested to stay under proptest's
/// `Strategy`-on-tuple cap of 12 elements: header / type / float-
/// composite / opaque-tail-byte fields are grouped into
/// sub-tuples.
fn body_input_strategy() -> impl Strategy<Value = EntityStateBodyInput> {
    let identity_group = (
        fixed_bytes_strategy::<6>(), // entity_id
        any::<u8>(),                 // force_id
        fixed_bytes_strategy::<8>(), // entity_type
        fixed_bytes_strategy::<8>(), // alternative_entity_type
    );
    let float_group = (
        fixed_bytes_strategy::<12>(), // linear_velocity
        fixed_bytes_strategy::<24>(), // location_ecef
        fixed_bytes_strategy::<12>(), // orientation
    );
    let scalar_group = (
        any::<u32>(),                 // appearance
        fixed_bytes_strategy::<40>(), // dead_reckoning
        any::<u8>(),                  // marking_charset
        fixed_bytes_strategy::<11>(), // marking
        any::<u32>(),                 // capabilities
    );
    let tail_group = prop::collection::vec(
        fixed_bytes_strategy::<{ ARTICULATION_PARAMETER_LEN }>(),
        0..=usize::from(MAX_ARTICULATION_PARAMETERS),
    );
    (identity_group, float_group, scalar_group, tail_group).prop_map(
        |(
            (entity_id, force_id, entity_type, alternative_entity_type),
            (linear_velocity, location_ecef, orientation),
            (appearance, dead_reckoning, marking_charset, marking, capabilities),
            articulation_parameters,
        )| EntityStateBodyInput {
            entity_id,
            force_id,
            entity_type,
            alternative_entity_type,
            linear_velocity,
            location_ecef,
            orientation,
            appearance,
            dead_reckoning,
            marking_charset,
            marking,
            capabilities,
            articulation_parameters,
        },
    )
}

proptest! {
    /// **Path (a)** — Reference encoder → `SchemaCodec` decode →
    /// `SchemaCodec` re-encode must produce the same
    /// `132 + 16×count` bytes the reference encoder emitted.
    /// Definitive parity assertion for the v3 schema vocabulary's
    /// variable-length repeat on the load-bearing DIS body.
    ///
    /// The reference encoder lives inline in this test file rather
    /// than calling `EntityStatePdu::encode`, so the parity check
    /// is a genuine cross-implementation comparison — encoder bugs
    /// in the production codec (or in SchemaCodec) cannot pass
    /// this test symmetrically.
    #[test]
    fn schema_codec_byte_identical_to_reference(input in body_input_strategy()) {
        let reference = reference_encode(&input);
        prop_assert_eq!(
            reference.len(),
            ENTITY_STATE_FIXED_BODY_LEN + input.articulation_parameters.len() * ARTICULATION_PARAMETER_LEN
        );

        let codec = schema_codec();
        let entity = codec.to_entity(&reference).expect("schema decode");
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        prop_assert_eq!(&re_encoded[..], &reference[..]);
    }
}

/// Strategy for an `EntityStatePdu` constrained to the domain the
/// production codec round-trips byte-for-byte. The marking field
/// is restricted to NUL-free ASCII with length ≤ 11 because the
/// production `encode_marking` / `decode_marking` strip trailing
/// NULs on decode and re-pad on encode — that round-trip is lossy
/// for any input that already contains internal NULs. Marking
/// content outside this domain has its own (production) test
/// coverage; this proptest sticks to the well-defined subset so
/// the typed-API assertion below is unambiguous.
fn entity_state_pdu_strategy() -> impl Strategy<Value = EntityStatePdu> {
    // Field groups are nested to stay under proptest's
    // `Strategy`-on-tuple cap of 12 elements. Each group has a
    // self-evident theme so the `prop_map` body's destructuring
    // reads naturally.
    let header_group = (
        any::<u8>(),  // protocol_version
        any::<u8>(),  // exercise_id
        any::<u32>(), // timestamp
        any::<u16>(), // padding
    );
    // pdu_type / protocol_family are pinned by
    // `EntityStatePdu::encode` to EntityState /
    // EntityInformationInteraction so the strategy doesn't drive
    // them.
    let identity_group = (
        any::<(u16, u16, u16)>(),               // entity_id (site, app, entity)
        any::<u8>(),                            // force_id raw byte
        any::<(u8, u8, u16, u8, u8, u8, u8)>(), // entity_type tuple
        any::<(u8, u8, u16, u8, u8, u8, u8)>(), // alt entity_type tuple
    );
    let dead_reckoning_group = (
        any::<u8>(),                  // algorithm
        fixed_bytes_strategy::<15>(), // other_parameters
        prop::array::uniform3(any::<f32>().prop_filter("finite", |v| v.is_finite())),
        prop::array::uniform3(any::<f32>().prop_filter("finite", |v| v.is_finite())),
    );
    // Float vectors restricted to finite — NaN-vs-NaN comparison
    // in the public-API assertion below would always fail, and
    // the typed wrapper's [f32/f64; 3] fields propagate the bit
    // pattern verbatim either way.
    let kinematics_group = (
        prop::array::uniform3(any::<f32>().prop_filter("finite", |v| v.is_finite())),
        prop::array::uniform3(any::<f64>().prop_filter("finite", |v| v.is_finite())),
        prop::array::uniform3(any::<f32>().prop_filter("finite", |v| v.is_finite())),
    );
    let scalar_group = (
        any::<u32>(), // appearance
        any::<u32>(), // capabilities
        any::<u8>(),  // marking_charset
        // Marking: 0..=11 ASCII chars, no NUL — the production
        // codec's NUL-strip-and-re-pad round-trip is byte-equivalent
        // only on this domain.
        prop::collection::vec(0x20u8..=0x7Eu8, 0..=11)
            .prop_map(|v| v.into_iter().map(|b| b as char).collect::<String>()),
    );
    let tail_group = prop::collection::vec(
        fixed_bytes_strategy::<{ ARTICULATION_PARAMETER_LEN }>(),
        0..=usize::from(MAX_ARTICULATION_PARAMETERS),
    );
    (
        header_group,
        identity_group,
        dead_reckoning_group,
        kinematics_group,
        scalar_group,
        tail_group,
    )
        .prop_map(
            |(
                (protocol_version, exercise_id, timestamp, padding),
                ((site, application, entity), force_byte, et_tuple, alt_et_tuple),
                (dr_algorithm, dr_other, dr_linear_acc, dr_angular_vel),
                (linear_velocity, location_ecef, orientation),
                (appearance, capabilities, marking_charset, marking),
                articulation_raw,
            )| {
                let header = PduHeader {
                    protocol_version,
                    exercise_id,
                    pdu_type: PduType::EntityState,
                    protocol_family: ProtocolFamily::EntityInformationInteraction,
                    timestamp,
                    // Overwritten by encode() with the real total length.
                    length: 0,
                    padding,
                };
                let entity_type = EntityType {
                    kind: et_tuple.0,
                    domain: et_tuple.1,
                    country: et_tuple.2,
                    category: et_tuple.3,
                    subcategory: et_tuple.4,
                    specific: et_tuple.5,
                    extra: et_tuple.6,
                };
                let alternative_entity_type = EntityType {
                    kind: alt_et_tuple.0,
                    domain: alt_et_tuple.1,
                    country: alt_et_tuple.2,
                    category: alt_et_tuple.3,
                    subcategory: alt_et_tuple.4,
                    specific: alt_et_tuple.5,
                    extra: alt_et_tuple.6,
                };
                let dead_reckoning = DeadReckoningParameters {
                    algorithm: dr_algorithm,
                    other_parameters: dr_other,
                    linear_acceleration: dr_linear_acc,
                    angular_velocity: dr_angular_vel,
                };
                let articulation_parameters = articulation_raw
                    .into_iter()
                    .map(|raw| ArticulationParameter { raw })
                    .collect();
                EntityStatePdu {
                    header,
                    entity_id: EntityId {
                        site,
                        application,
                        entity,
                    },
                    force_id: ForceId::from_u8(force_byte),
                    entity_type,
                    alternative_entity_type,
                    linear_velocity,
                    location_ecef,
                    orientation,
                    appearance,
                    dead_reckoning,
                    marking_charset,
                    marking,
                    capabilities,
                    articulation_parameters,
                }
            },
        )
}

proptest! {
    /// **Path (c)** — Public-API round-trip:
    /// `EntityStatePdu::encode` → `EntityStatePdu::decode` must
    /// preserve every typed field of the wrapper struct.
    ///
    /// Catches the same class of regression the weekly-fuzz harness
    /// catches — encoder bugs that silently drop fields would fail
    /// here even if path (a) above passed symmetrically. Restricted
    /// to (NaN-free floats + NUL-free ASCII marking) per the codec's
    /// documented round-trip domain (see `entity_state_pdu_strategy`).
    #[test]
    fn public_api_round_trip_preserves_typed_fields(pdu in entity_state_pdu_strategy()) {
        let bytes = pdu.encode().expect("encode");
        // `encode()` overwrites length / pdu_type / protocol_family,
        // so reconstruct what the encoded PDU's header should look like
        // for the assertion.
        let mut expected_header = pdu.header;
        expected_header.pdu_type = PduType::EntityState;
        expected_header.protocol_family = ProtocolFamily::EntityInformationInteraction;
        expected_header.length = u16::try_from(
            HEADER_LEN
                + ENTITY_STATE_FIXED_BODY_LEN
                + pdu.articulation_parameters.len() * ARTICULATION_PARAMETER_LEN,
        )
        .expect("PDU length fits in u16");

        let decoded = EntityStatePdu::decode(&bytes).expect("public-API round-trip");

        prop_assert_eq!(decoded.header, expected_header);
        prop_assert_eq!(decoded.entity_id, pdu.entity_id);
        prop_assert_eq!(decoded.force_id, pdu.force_id);
        prop_assert_eq!(decoded.entity_type, pdu.entity_type);
        prop_assert_eq!(decoded.alternative_entity_type, pdu.alternative_entity_type);
        prop_assert_eq!(decoded.linear_velocity, pdu.linear_velocity);
        prop_assert_eq!(decoded.location_ecef, pdu.location_ecef);
        prop_assert_eq!(decoded.orientation, pdu.orientation);
        prop_assert_eq!(decoded.appearance, pdu.appearance);
        prop_assert_eq!(decoded.dead_reckoning, pdu.dead_reckoning);
        prop_assert_eq!(decoded.marking_charset, pdu.marking_charset);
        prop_assert_eq!(decoded.marking, pdu.marking);
        prop_assert_eq!(decoded.capabilities, pdu.capabilities);
        prop_assert_eq!(
            decoded.articulation_parameters,
            pdu.articulation_parameters
        );
    }
}
