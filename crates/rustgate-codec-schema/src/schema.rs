// Copyright © 2026 Roberto Chiofalo.

//! [`Schema`] type — the declarative wire-format description that
//! drives [`crate::SchemaCodec`].
//!
//! Schemas are YAML / JSON / RON documents an operator writes once
//! per protocol. The wire format ships in `rustgate-codec-schema`'s
//! versioning lockstep with the runtime that parses it, so a schema
//! committed today will still parse against a future codec runtime
//! as long as the [`SchemaVersion`] tag is supported.
//!
//! ## Document shape
//!
//! [`FieldType`] is internally tagged on `kind`, so the wire form
//! for a field type is `{ kind: <name> }`, NOT the YAML `!<name> {}`
//! tag syntax some other schema formats use:
//!
//! ```yaml
//! schema-version: "1"
//! protocol-name: "example.fixed-binary"
//! message-types:
//!   - name: "Position Report"
//!     id: 1
//!     size-bytes: 24
//!     fields:
//!       - name: "track-id"
//!         offset: 0
//!         field-type: { kind: u32 }
//!         endian: big
//!         entity-path: "uid"
//!       - name: "latitude-microdeg"
//!         offset: 4
//!         field-type: { kind: i32 }
//!         endian: big
//!         calibration: { scale: 1e-6, offset: 0.0 }
//!         entity-path: "position.lat"
//!       - name: "longitude-microdeg"
//!         offset: 8
//!         field-type: { kind: i32 }
//!         endian: big
//!         calibration: { scale: 1e-6, offset: 0.0 }
//!         entity-path: "position.lon"
//! ```
//!
//! ## Field type vocabulary
//!
//! [`FieldType`] covers the primitive integer / float types plus
//! fixed-length byte slices and fixed-length UTF-8 strings.
//! Variable-length fields and bit-packed fields are intentionally
//! out of scope — the goal is to make 80% of wire formats codable
//! with 0% Rust per protocol, not to be a complete IDL.
//!
//! ## Conditional fields (v3)
//!
//! [`PresentIfSpec`] on [`FieldDef::present_if`] lets a field's
//! projection depend on the raw integer value of another field
//! that decoded earlier in the same message. The wire bytes stay
//! fixed-offset (so subsequent offsets never shift); only the
//! projection onto [`Entity`](rustgate_core::entity::Entity) is
//! gated. See the [`PresentIfSpec`] type for the full semantics.
//!
//! ## Bit-packed sub-byte fields (v3)
//!
//! [`FieldDef::bit_offset`] + [`FieldDef::bit_width`] declare a
//! field that occupies a contiguous bit range within ONE byte at the
//! declared `offset`. `bit_offset` is measured from the MSB of that
//! byte (big-endian bit ordering — the MSB at byte N is bit-position
//! 0); `bit_width` is the width of the extracted integer in bits.
//! Two bit-packed fields at the same byte offset are legal as long
//! as their bit ranges don't overlap, so the canonical packed flag
//! byte (VMF FPI / FRI / GPI indicators, ASTERIX FSPEC bits) is
//! schema-fiable. Cross-byte fields (e.g. a 12-bit field spanning
//! the low nibble of byte N and high nibble of byte N+1) are
//! deferred to a v4 grammar.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::SchemaError;

/// Schema document version. The wire schema declares its own
/// [`SchemaVersion`] so the runtime can dispatch on it — older
/// schemas keep parsing after we add v2 features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SchemaVersion {
    /// Schema language version 1 — the shape this PR ships.
    #[default]
    #[serde(rename = "1")]
    V1,
}

/// Byte ordering for multi-byte primitive types. Single-byte types
/// (`u8`, `i8`) ignore this field but operators still set it for
/// schema cleanliness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    /// Little-endian (LSB at lowest address). The default for x86 /
    /// ARM / RISC-V CPU-native wire formats.
    #[default]
    Little,
    /// Big-endian (MSB at lowest address). The "network byte
    /// order" used by every IETF / IEEE 1278 / STANAG protocol.
    Big,
}

/// Inclusive range constraint applied to a field's *physical* value
/// (post-calibration on decode, pre-reverse-calibration on encode).
/// Used to guard against values that fit the wire type but are
/// semantically invalid — e.g. WGS-84 latitude wraps to `[-90, 90]`
/// even though `f64` happily holds `200.0`.
///
/// On decode, an out-of-range payload surfaces as
/// [`crate::SchemaCodecError::OutOfRange`] *before* any
/// `Entity::attributes` projection happens — the field-level error
/// names the offending value so an operator can correlate to the
/// wire bytes that produced it. On encode, the symmetric check
/// fires *before* the bytes are written, so a buggy upstream that
/// stuffs lat = 200 into the entity fails the encode call instead
/// of shipping a garbled frame.
///
/// `min` / `max` are inclusive. Both are required when `range` is
/// present — the half-open case (only `min`, only `max`) doesn't
/// show up in real protocols and the explicit form is easier to
/// read in a schema diff.
///
/// Range constraints compose with [`Calibration`]: the decoded
/// physical value (after applying calibration) is what the range
/// is compared against. For integer fields without calibration the
/// physical value equals the raw integer, so the range applies
/// directly to the wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Range {
    /// Inclusive lower bound on the physical value. Must be finite.
    pub min: f64,
    /// Inclusive upper bound on the physical value. Must be finite
    /// and `>= min`.
    pub max: f64,
}

/// Linear calibration applied during decode:
/// `physical = raw * scale + offset`.
/// Reversed on encode: `raw = (physical - offset) / scale`.
///
/// Required for integer fields that carry scaled-physical quantities
/// (e.g. latitude in microdegrees stored as `i32`). Skip when the
/// raw integer is already the physical value (e.g. an entity count
/// or a track ID).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Calibration {
    /// Multiplier applied during decode. Must be non-zero and
    /// finite.
    pub scale: f64,
    /// Additive offset applied during decode. Must be finite.
    #[serde(default)]
    pub offset: f64,
}

impl Default for Calibration {
    fn default() -> Self {
        // Identity calibration: passes the raw value through
        // unchanged. Operators omit this in schemas where the raw
        // integer is the physical value.
        Self {
            scale: 1.0,
            offset: 0.0,
        }
    }
}

/// Primitive wire-format type for a single [`FieldDef`]. The
/// internal layout (signed / unsigned, byte width) determines how
/// many bytes the field consumes; for variable-length types
/// (`Bytes`, `Utf8`) the runtime requires a `length_bytes`
/// declaration on the field itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum FieldType {
    /// 8-bit unsigned integer.
    U8,
    /// 16-bit unsigned integer.
    U16,
    /// 32-bit unsigned integer.
    U32,
    /// 64-bit unsigned integer.
    U64,
    /// 8-bit signed two's complement.
    I8,
    /// 16-bit signed two's complement.
    I16,
    /// 32-bit signed two's complement.
    I32,
    /// 64-bit signed two's complement.
    I64,
    /// IEEE-754 single precision.
    F32,
    /// IEEE-754 double precision.
    F64,
    /// Fixed-length raw bytes. The runtime requires `length_bytes`
    /// to be set on the [`FieldDef`].
    Bytes,
    /// Fixed-length UTF-8 string. Trailing NUL bytes are stripped on
    /// decode; encode pads with NULs to fill the declared length.
    /// Decode fails with [`crate::SchemaCodecError::Utf8`] if the
    /// bytes are not valid UTF-8.
    Utf8,
}

impl FieldType {
    /// Byte width of this primitive when fixed (returns `None` for
    /// `Bytes` and `Utf8` which require an explicit `length_bytes`
    /// on the field).
    #[must_use]
    pub fn fixed_size(self) -> Option<usize> {
        match self {
            Self::U8 | Self::I8 => Some(1),
            Self::U16 | Self::I16 => Some(2),
            Self::U32 | Self::I32 | Self::F32 => Some(4),
            Self::U64 | Self::I64 | Self::F64 => Some(8),
            Self::Bytes | Self::Utf8 => None,
        }
    }

    /// Stable lowercase tag for tracing and metrics labels.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Bytes => "bytes",
            Self::Utf8 => "utf8",
        }
    }
}

/// Optional enum-style mapping between wire-raw integer values and
/// the string the [`Entity`](rustgate_core::entity::Entity) shape
/// expects. Used for affiliation / category / status codes that
/// hand-written codecs would normally `match` on.
///
/// Example schema fragment:
///
/// ```yaml
/// - name: "affiliation"
///   offset: 12
///   field-type: { kind: u8 }
///   value-mapping:
///     entries:
///       0: "unknown"
///       1: "friend"
///       2: "neutral"
///       3: "hostile"
///     default-raw: 0
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ValueMapping {
    /// Wire raw value → string label.
    pub entries: BTreeMap<i64, String>,
    /// When the encoder cannot find an entry for a value (e.g.
    /// an Entity carries `"pending"` but the schema only knows
    /// the four NATO affiliations), use this raw value as the
    /// fallback. `None` means the encoder fails the call instead
    /// of inventing a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_raw: Option<i64>,
}

/// Variable-length-array layout for a [`FieldDef`]. When set on a
/// `Bytes`-typed field, the field's wire span becomes
/// `record_size_bytes × <count>`, where `<count>` is the raw integer
/// value of another field that decoded earlier in the same
/// [`MessageType`] (named via [`RepeatSpec::count_from`]).
///
/// The v3.0 grammar surfaces the N records as a single
/// [`crate::SchemaCodecError`]-free `Bytes` slice on the decoded
/// `Entity`; the consumer is responsible for parsing the inner record
/// shape. Nested typed-record schemas (where each record carries its
/// own field list) are explicitly out of scope for v3 — that's a v4
/// feature.
///
/// Real protocols use this for variable-length arrays whose count is
/// carried in a preceding flag/length byte:
///
/// - DIS Entity State PDU `articulation_params_count` (u8 at offset
///   132) preceding an array of 16-byte articulation records.
/// - ASTERIX repetitive items: a 1-byte "REP" prefix preceding N
///   copies of a fixed-size sub-record.
/// - MAVLink v2 variable-length payload (`len` byte in the header
///   driving 0..=255 payload bytes).
/// - Link 16 word-3 extensions (a count byte preceding N extension
///   words).
///
/// Mutually exclusive with [`FieldDef::length_bytes`]: a field is
/// either fixed-length (the existing `length_bytes` path) or
/// count-driven (this new `repeat` path), never both. The validator
/// rejects schemas that declare both.
///
/// Example schema fragment — `articulation_params_count` (`u8` at
/// offset 132) drives 16-byte articulation records starting at offset
/// 133:
///
/// ```yaml
/// - name: "articulation_params_count"
///   offset: 132
///   field-type: { kind: u8 }
/// - name: "articulation_params"
///   offset: 133
///   field-type: { kind: bytes }
///   repeat:
///     count-from: "articulation_params_count"
///     record-size-bytes: 16
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RepeatSpec {
    /// Name of an earlier-parsed integer field that holds the record
    /// count. Must reference another field in the same `MessageType`
    /// declared at a STRICTLY LOWER offset (so the decoder has
    /// already read it by the time the repeat field is evaluated)
    /// and must be one of the integer types (`u8`..`u64`,
    /// `i8`..`i64`).
    pub count_from: String,
    /// Size in bytes of EACH element. `record_size_bytes × <count>`
    /// must fit inside the message's declared `size_bytes`. Must be
    /// non-zero (a zero-size record schema has no semantic meaning
    /// and would silently let the field alias subsequent offsets).
    pub record_size_bytes: usize,
}

/// Predicate declaring that a field is present on the wire only when
/// another field in the same `MessageType` carries a specific integer
/// value. The first v3 grammar feature — call this *sparse projection*
/// rather than the more familiar *variable-shift* semantics from
/// hand-rolled codecs:
///
/// - The bytes at the conditional field's declared offset stay
///   allocated whether or not the predicate matches (wire layout
///   remains fixed-offset, so subsequent offsets never slide).
/// - When the predicate matches, the field projects to
///   `Entity::attributes` / the declared `entity_path` exactly like
///   an unconditional field.
/// - When the predicate does NOT match, decode skips the projection
///   (no attribute written, no entity_path target updated) and encode
///   leaves the offset bytes at their pre-filled zero value.
///
/// Real protocols use this for fields whose presence is gated on a
/// preceding flag byte: DIS articulation parameters (present only
/// when `articulation_params_count > 0`), MAVLink v2 signatures
/// (present only when `incompat_flags & IFLAG_SIGNED`), ASTERIX FRNs
/// (present only when the matching FSPEC bit is set). The fixed-
/// offset interpretation here covers the cases where the
/// conditional field occupies a reserved slot whether or not it is
/// "used"; protocols where the field actually disappears from the
/// wire (variable-shift) are a separate v4 feature.
///
/// Example schema fragment — a `signature` byte that is meaningful
/// only when the preceding `flags` byte is `1`:
///
/// ```yaml
/// - name: "flags"
///   offset: 0
///   field-type: { kind: u8 }
///   entity-path: "attributes.flags"
/// - name: "signature"
///   offset: 1
///   field-type: { kind: u8 }
///   entity-path: "attributes.signature"
///   present-if:
///     field: "flags"
///     value: 1
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PresentIfSpec {
    /// Name of the field whose decoded raw integer value the
    /// predicate compares against. Must reference another field in
    /// the same `MessageType` declared at a STRICTLY LOWER offset
    /// (so the decoder has already read it by the time the
    /// conditional field is evaluated).
    pub field: String,
    /// Integer value the referenced field must equal for the
    /// conditional field to project. Compared against the
    /// referenced field's raw wire integer (NOT calibrated /
    /// value-mapped) — the predicate operates on the byte-level
    /// representation so the v3 grammar stays decidable without
    /// modelling the runtime's projection pipeline.
    pub value: i64,
}

/// One field in a [`MessageType`]'s payload. The runtime reads
/// each field at the declared `offset` with the type-determined
/// width, applies the optional calibration, and projects the
/// result onto the declared `entity_path` on the
/// [`Entity`](rustgate_core::entity::Entity) value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FieldDef {
    /// Operator-facing field name. Used for error reporting and
    /// metric labels. Must be unique within the message type.
    pub name: String,
    /// Byte offset within the message payload where this field
    /// starts.
    pub offset: usize,
    /// Wire type.
    pub field_type: FieldType,
    /// Endian for multi-byte primitives. Ignored for `u8` / `i8` /
    /// `bytes` / `utf8`.
    #[serde(default)]
    pub endian: Endian,
    /// Length in bytes — required for `Bytes` and `Utf8` field
    /// types, ignored for fixed-width primitives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length_bytes: Option<usize>,
    /// Linear calibration applied during decode (`physical = raw *
    /// scale + offset`) and reversed during encode. Defaults to the
    /// identity calibration when omitted.
    #[serde(default, skip_serializing_if = "is_identity_calibration")]
    pub calibration: Option<Calibration>,
    /// Enum-style mapping between wire raw values and the strings
    /// the [`Entity`](rustgate_core::entity::Entity) shape carries.
    /// Applies only to integer field types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_mapping: Option<ValueMapping>,
    /// Inclusive `[min, max]` range constraint on the physical
    /// value (post-calibration on decode, pre-reverse-calibration
    /// on encode). Decode + encode both reject values outside the
    /// range with [`crate::SchemaCodecError::OutOfRange`]. Skip when
    /// the field's wire type already constrains the value (e.g. a
    /// `u8` flag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<Range>,
    /// Optional conditional-projection predicate. When set, the
    /// field is projected to `Entity` only when the referenced
    /// field's raw integer value equals the declared value; the
    /// wire bytes stay at the declared offset regardless. See
    /// [`PresentIfSpec`] for the full semantics and the rationale
    /// for the fixed-offset (sparse-projection) interpretation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present_if: Option<PresentIfSpec>,
    /// Optional variable-length-array layout. When set on a `Bytes`
    /// field, the field's wire span is `record_size_bytes × <count>`
    /// where `<count>` is the raw integer value of another
    /// earlier-decoded field named by [`RepeatSpec::count_from`].
    /// Mutually exclusive with [`FieldDef::length_bytes`] and
    /// restricted to `Bytes`-typed fields in v3 — see [`RepeatSpec`]
    /// for the full semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeat: Option<RepeatSpec>,
    /// Sub-byte field start offset, in BITS, measured from the
    /// MSB of the byte at `offset` (BIG-endian bit ordering — the
    /// MSB at byte N is bit-position 0). Range `[0, 7]`. Must be
    /// declared together with [`FieldDef::bit_width`]; the validator
    /// rejects one without the other.
    ///
    /// Bit-packed fields read ONE byte at `offset` and project an
    /// integer subrange of that byte — see the [`FieldDef::bit_width`]
    /// docs for the full extraction rule and the v3 grammar's
    /// single-byte limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit_offset: Option<u8>,
    /// Sub-byte field width, in BITS. Range `[1, 8]`. The field
    /// fits entirely within ONE byte: `bit_offset + bit_width <= 8`.
    /// Cross-byte bit-packed fields are intentionally deferred to a
    /// v4 grammar.
    ///
    /// When set, the field's `field_type` must be `u8` — the runtime
    /// reads the single byte at `offset`, extracts
    /// `(byte >> (8 - bit_offset - bit_width)) & ((1 << bit_width) - 1)`,
    /// and projects the result as a `u64`. Bit-packed fields cannot
    /// combine with `length_bytes`, `repeat`, or `value_mapping`
    /// (incoherent in v3 — pick one). `calibration` and `range` ARE
    /// allowed (operators may want scaled tiny flag values), though
    /// `range.max` must fit `bit_width` bits.
    ///
    /// Two bit-packed fields at the same byte offset ARE legal as
    /// long as their bit ranges don't overlap. This is the canonical
    /// shape for packed flag bytes (VMF FPI/FRI/GPI indicators,
    /// ASTERIX FSPEC bitmaps, Link 16 J-series sub-words).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit_width: Option<u8>,
    /// Dotted path on the [`Entity`](rustgate_core::entity::Entity)
    /// shape the decoded value projects onto. Supported paths:
    /// `uid`, `callsign`, `mil_std_2525_sidc`, `position.lat`,
    /// `position.lon`, `position.hae_meters`, `velocity.speed_m_s`,
    /// `velocity.course_deg`, `kind`, `attributes.<key>`. Optional —
    /// fields without an `entity_path` are preserved in
    /// `Entity::attributes` under `schema.<message>.<field>` for
    /// round-trip without contributing to first-class fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_path: Option<String>,
}

impl FieldDef {
    /// Whether this field is declared as a bit-packed sub-byte field
    /// (both `bit_offset` and `bit_width` set). Centralised so the
    /// decoder, encoder, and validator stay in lockstep on the
    /// "is bit-packed?" question.
    #[must_use]
    pub fn is_bit_packed(&self) -> bool {
        self.bit_offset.is_some() && self.bit_width.is_some()
    }
}

fn is_identity_calibration(opt: &Option<Calibration>) -> bool {
    match opt {
        None => true,
        Some(c) => c.scale == 1.0 && c.offset == 0.0,
    }
}

/// One message type in a [`Schema`]. A schema declares one or more
/// message types; the runtime dispatches between them on the
/// schema's `discriminator_offset` if more than one is declared,
/// otherwise the single type matches every payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MessageType {
    /// Operator-facing name (used for tracing and metrics labels).
    pub name: String,
    /// Wire discriminator value — the byte (or short) at the
    /// schema's `discriminator_offset` must match this for the
    /// runtime to dispatch this message type. Ignored when the
    /// schema has only one message type.
    #[serde(default)]
    pub id: i64,
    /// Payload size in bytes. The runtime rejects payloads shorter
    /// than this with [`crate::SchemaCodecError::PayloadTooShort`].
    /// Payloads longer than this are accepted; the trailing bytes
    /// land on `Entity::attributes` under
    /// `schema.<message>.trailing-bytes` for round-trip
    /// preservation.
    pub size_bytes: usize,
    /// Fields, ordered low-to-high by `offset`. The validator
    /// rejects schemas whose field ranges overlap.
    pub fields: Vec<FieldDef>,
}

/// Top-level schema document. Holds the protocol identifier,
/// schema-language version, optional dispatcher offset, and one or
/// more [`MessageType`] entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Schema {
    /// Schema-language version of *this* document. Allows the
    /// runtime to refuse documents that use features it doesn't
    /// support.
    pub schema_version: SchemaVersion,
    /// Protocol name (e.g. `"example.fixed-binary"`,
    /// `"nffi.position-report"`). Used in tracing fields and
    /// metrics labels.
    pub protocol_name: String,
    /// Byte offset where the runtime reads the message-type
    /// discriminator. Required when the schema has more than one
    /// `MessageType`; ignored when only one type is declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discriminator_offset: Option<usize>,
    /// One or more message types.
    pub message_types: Vec<MessageType>,
}

impl Schema {
    /// Parse a schema document from a YAML / JSON string. The
    /// runtime dispatches on file content rather than file
    /// extension — the same parser handles both serialisations.
    pub fn parse(text: &str) -> Result<Self, SchemaError> {
        serde_yaml::from_str(text).map_err(|e| SchemaError::Parse(e.to_string()))
    }

    /// Validate the schema's structural invariants:
    /// - Field offsets in each message are sorted ascending and
    ///   do not overlap.
    /// - Every field fits within the declared `size_bytes`.
    /// - `discriminator_offset` (when present) points inside the
    ///   message payload.
    /// - Calibration coefficients are finite.
    /// - Variable-length fields (`Bytes`, `Utf8`) declare
    ///   `length_bytes`.
    ///
    /// Call after `parse` and before any codec construction so
    /// operator typos surface at startup rather than on the first
    /// payload.
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.message_types.is_empty() {
            return Err(SchemaError::Validation {
                message: "schema must declare at least one message_types entry".to_string(),
            });
        }
        // Multi-message dispatch requires a `discriminator_offset`
        // declaring where the runtime reads the 1-byte
        // message-type tag, plus each message-type carrying a
        // unique `id` in `0..=255`. Single-message schemas may
        // omit the discriminator_offset.
        if self.message_types.len() > 1 {
            let Some(off) = self.discriminator_offset else {
                return Err(SchemaError::Validation {
                    message: format!(
                        "schema declares {} message types but no discriminator_offset; multi-message dispatch needs the byte offset where the runtime reads the message-type tag",
                        self.message_types.len()
                    ),
                });
            };
            let mut seen_ids: std::collections::BTreeMap<i64, &str> =
                std::collections::BTreeMap::new();
            for mt in &self.message_types {
                if !(0..=255).contains(&mt.id) {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` has id {} but multi-message dispatch requires id in 0..=255 (1-byte discriminator)",
                            mt.name, mt.id
                        ),
                    });
                }
                if let Some(prior) = seen_ids.insert(mt.id, mt.name.as_str()) {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` and message `{}` both declare id {}; multi-message discriminator ids must be unique",
                            prior, mt.name, mt.id
                        ),
                    });
                }
                if off >= mt.size_bytes {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "discriminator_offset {} is outside message `{}` size {}",
                            off, mt.name, mt.size_bytes
                        ),
                    });
                }
            }
        }
        for mt in &self.message_types {
            self.validate_message_type(mt)?;
        }
        Ok(())
    }

    fn validate_message_type(&self, mt: &MessageType) -> Result<(), SchemaError> {
        let mut sorted = mt.fields.clone();
        sorted.sort_by_key(|f| f.offset);
        let mut prev_end = 0usize;
        // Per-byte bit usage for bit-packed fields. Each entry tracks
        // which bits (MSB = bit position 0) of a byte are already
        // claimed by a prior bit-packed field. Two bit-packed fields
        // at the same byte offset are LEGAL as long as their bit
        // ranges don't overlap — the canonical packed flag-byte
        // pattern. Non-bit-packed fields at the same offset are still
        // rejected by the `f.offset < prev_end` overlap check, which
        // fires before we ever look at this map.
        let mut bit_usage: BTreeMap<usize, u8> = BTreeMap::new();
        for f in &sorted {
            // Bit-packed validation runs first so the size computation
            // below knows to use 1 byte and the overlap check knows
            // to consult the bit-usage map. The grammar is: both
            // `bit_offset` and `bit_width` must be set together, with
            // `bit_offset` in `[0, 7]`, `bit_width` in `[1, 8]`, and
            // `bit_offset + bit_width <= 8` (single-byte limit).
            if f.bit_offset.is_some() != f.bit_width.is_some() {
                return Err(SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` declares `bit_offset` without `bit_width` (or vice versa); both are required together",
                        mt.name, f.name
                    ),
                });
            }
            if let (Some(bo), Some(bw)) = (f.bit_offset, f.bit_width) {
                if bo >= 8 {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` bit_offset {bo} must be in `[0, 7]` (single-byte limit)",
                            mt.name, f.name
                        ),
                    });
                }
                if bw == 0 || bw > 8 {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` bit_width {bw} must be in `[1, 8]`",
                            mt.name, f.name
                        ),
                    });
                }
                if (bo as u16) + (bw as u16) > 8 {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` bit_offset {bo} + bit_width {bw} > 8 (cross-byte bit fields are a v4 feature)",
                            mt.name, f.name
                        ),
                    });
                }
                // Bit-packed fields read ONE byte and project an
                // integer subrange — the field_type must be `u8`. Any
                // other primitive width would be incoherent (a `u16`
                // bit-packed field would either ignore the second byte
                // or silently widen the extraction, both surprises).
                if !matches!(f.field_type, FieldType::U8) {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` type `{}` does not support bit-packing (v3 bit-packed fields require `u8` field type)",
                            mt.name,
                            f.name,
                            f.field_type.as_str()
                        ),
                    });
                }
                // Bit-packed fields cannot combine with any of the
                // length / repeat / value-mapping mechanisms — each
                // describes a different wire shape and the runtime
                // would have to pick one. v3 picks the simplest:
                // declare bit-packing, get a single-byte sub-range
                // projection; declare value-mapping, get a labelled
                // wire integer; declare both, fail at schema-load.
                if f.length_bytes.is_some() {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` cannot combine bit-packing with `length_bytes`",
                            mt.name, f.name
                        ),
                    });
                }
                if f.repeat.is_some() {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` cannot combine bit-packing with `repeat`",
                            mt.name, f.name
                        ),
                    });
                }
                if f.value_mapping.is_some() {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` cannot combine bit-packing with `value_mapping`",
                            mt.name, f.name
                        ),
                    });
                }
                // `range.max` must fit in `bit_width` bits — a 3-bit
                // field can hold `[0, 7]`, so `range: { min: 0, max:
                // 8 }` is impossible to satisfy and surfaces a
                // schema bug rather than letting every encode fail.
                // Skip this check when `calibration` is present: the
                // physical range is `raw * scale + offset` which can
                // legitimately exceed the bit-width's raw bound (a
                // 1-bit calibrated as `scale: 10.0` produces `[0,
                // 10]`).
                if let Some(range) = &f.range
                    && f.calibration.is_none()
                {
                    let max_raw = ((1u64 << bw) - 1) as f64;
                    if range.max > max_raw {
                        return Err(SchemaError::Validation {
                            message: format!(
                                "message `{}` field `{}` range max ({}) exceeds bit_width {bw} capacity (max raw value {max_raw})",
                                mt.name, f.name, range.max
                            ),
                        });
                    }
                }
            }
            // `repeat` and `length_bytes` are mutually exclusive: a
            // field is either fixed-length (`length_bytes`) or
            // count-driven (`repeat`), never both. Catching this at
            // schema-load avoids the runtime having to decide which
            // wins, which it can't sensibly do.
            if f.repeat.is_some() && f.length_bytes.is_some() {
                return Err(SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` declares both `length_bytes` and `repeat` (mutually exclusive)",
                        mt.name, f.name
                    ),
                });
            }
            // v3 repeat is `Bytes`-only — nested typed-record arrays
            // (each element with its own field list) are a v4
            // feature. Surface the misconfiguration at schema-load
            // rather than letting the decoder ignore a misplaced
            // `repeat` on, say, a `u32` field.
            if let Some(spec) = &f.repeat {
                if !matches!(f.field_type, FieldType::Bytes) {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` type `{}` does not support `repeat` (v3 repeat requires `bytes` field type)",
                            mt.name,
                            f.name,
                            f.field_type.as_str()
                        ),
                    });
                }
                if spec.record_size_bytes == 0 {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` repeat record-size-bytes must be > 0 (zero-size records have no semantic meaning)",
                            mt.name, f.name
                        ),
                    });
                }
            }
            let size = match (&f.repeat, f.field_type.fixed_size()) {
                // Repeat fields: the dynamic span is unknown at
                // validation time. The validator uses
                // `record_size_bytes × max_count_for_field_type` as a
                // conservative upper bound — `u8` → 255 records,
                // `u16` → 65_535, etc. — so subsequent fields cannot
                // alias the repeat region for any in-range count. The
                // dynamic length check (`record_size_bytes × actual
                // count ≤ remaining_bytes`) fires on every decode in
                // `decode_field`.
                (Some(spec), _) => {
                    spec.record_size_bytes
                        .saturating_mul(max_count_for_repeat_field(
                            &mt.fields,
                            spec.count_from.as_str(),
                        ))
                }
                (None, Some(s)) => s,
                (None, None) => f.length_bytes.ok_or_else(|| SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` type `{}` requires `length_bytes`",
                        mt.name,
                        f.name,
                        f.field_type.as_str()
                    ),
                })?,
            };
            // Reject zero-size variable-length fields. A `length-bytes: 0`
            // declaration has no semantic meaning (the field reads/writes
            // zero bytes) and silently breaks the overlap-detection loop:
            // `prev_end` does not advance, so the next field at the same
            // offset passes the `f.offset < prev_end` check and the runtime
            // accepts an aliased schema.
            //
            // `repeat` fields skip this check — a count of zero is
            // semantically meaningful (the array is empty) and the
            // field still has a documented offset. The
            // `record_size_bytes == 0` guard above already rejects the
            // pathological case where a "repeat" with no per-element
            // size would alias subsequent fields.
            if size == 0 && f.repeat.is_none() {
                return Err(SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` type `{}` declares zero size (length-bytes must be > 0 for variable-length fields)",
                        mt.name,
                        f.name,
                        f.field_type.as_str()
                    ),
                });
            }
            // Byte-range overlap check. Bit-packed fields sharing the
            // same byte offset are LEGAL — multiple bit-fields packing
            // a single byte is the canonical shape this feature
            // unlocks. For that case the check is deferred to the
            // bit-range overlap test below (which examines
            // `bit_usage`). The standard byte-range overlap still
            // fires when a bit-packed field collides with a wider
            // non-bit-packed field, or when one bit-packed field's
            // byte sits inside another field's byte range.
            let byte_shared_with_bit_packed_neighbour =
                f.is_bit_packed() && bit_usage.contains_key(&f.offset);
            if f.offset < prev_end && !byte_shared_with_bit_packed_neighbour {
                return Err(SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` at offset {} overlaps prior field (ends at {})",
                        mt.name, f.name, f.offset, prev_end
                    ),
                });
            }
            // Bit-range overlap check. For each bit-packed field,
            // build the bitmask of bit positions it claims (MSB =
            // bit 0) and confirm no prior bit-packed field at the
            // same byte already claimed any of those bits. The
            // `bit_usage` map is the per-message tracker the loop
            // accumulates as it walks sorted fields.
            if let (Some(bo), Some(bw)) = (f.bit_offset, f.bit_width) {
                // Safe: bw is in [1, 8], so the shift-by-bw can
                // produce up to 256 — fits in `u16`. Cast back to
                // `u8` after subtracting 1.
                let mask = (((1u16 << bw) - 1) as u8) << (8 - bo - bw);
                let used = bit_usage.entry(f.offset).or_insert(0);
                if (*used & mask) != 0 {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` bit_offset {bo}+bit_width {bw} overlaps prior bit-packed field at byte offset {} (claimed bits 0b{:08b}, new bits 0b{mask:08b})",
                            mt.name, f.name, f.offset, *used
                        ),
                    });
                }
                *used |= mask;
            }
            // For `repeat` fields, the per-payload end is dynamic
            // (`record_size_bytes × actual_count`). The static check
            // here only ensures the field can hold *something* —
            // that its declared offset still lies inside `size_bytes`.
            // The dynamic bound (`record_size_bytes × count ≤
            // remaining`) is enforced on every decode in
            // `decode_field`. Use saturating math when computing
            // `prev_end` so a `u8`-count × 16-byte record (max-span
            // 4080) does not wrap and falsely accept a later field
            // that aliases the repeat region.
            let end = if f.repeat.is_some() {
                if f.offset > mt.size_bytes {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` offset {} is past message size {} (repeat field with zero count would still start past end)",
                            mt.name, f.name, f.offset, mt.size_bytes
                        ),
                    });
                }
                // The max-possible span (`size`) is what blocks
                // subsequent fields from aliasing the repeat region.
                // Cap at `mt.size_bytes` so a generous count-type
                // (u8 → 4080 byte max-span on a 16-byte record) does
                // not reject every schema where the repeat is sized
                // to be the message's tail.
                f.offset.saturating_add(size).min(mt.size_bytes)
            } else {
                let end = f
                    .offset
                    .checked_add(size)
                    .ok_or_else(|| SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` size overflow at offset {}",
                            mt.name, f.name, f.offset
                        ),
                    })?;
                if end > mt.size_bytes {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` ends at byte {} but message size is {}",
                            mt.name, f.name, end, mt.size_bytes
                        ),
                    });
                }
                end
            };
            if let Some(cal) = &f.calibration {
                if !cal.scale.is_finite() || !cal.offset.is_finite() {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` calibration coefficients must be finite",
                            mt.name, f.name
                        ),
                    });
                }
                if cal.scale == 0.0 {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` calibration scale must be non-zero",
                            mt.name, f.name
                        ),
                    });
                }
            }
            if let Some(range) = &f.range {
                if !range.min.is_finite() || !range.max.is_finite() {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` range bounds must be finite",
                            mt.name, f.name
                        ),
                    });
                }
                if range.max < range.min {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` range max ({}) is less than min ({})",
                            mt.name, f.name, range.max, range.min
                        ),
                    });
                }
            }
            if let Some(vm) = &f.value_mapping {
                if vm.entries.is_empty() {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` value-mapping must declare at least one entry",
                            mt.name, f.name
                        ),
                    });
                }
                // Value mapping only makes sense on integer fields —
                // the entries map raw int → label string, and a
                // float / bytes / utf8 field would have no
                // meaningful raw int to look up.
                if !matches!(
                    f.field_type,
                    FieldType::U8
                        | FieldType::U16
                        | FieldType::U32
                        | FieldType::U64
                        | FieldType::I8
                        | FieldType::I16
                        | FieldType::I32
                        | FieldType::I64
                ) {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` type `{}` does not support value-mapping (integer types only)",
                            mt.name,
                            f.name,
                            f.field_type.as_str()
                        ),
                    });
                }
                // Value mapping replaces the raw integer with a
                // label string; calibration and range constraints
                // both operate on the numeric value and are
                // incoherent with the string projection. Reject
                // these combinations at schema-load.
                if f.calibration.is_some() {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` cannot combine value-mapping with calibration",
                            mt.name, f.name
                        ),
                    });
                }
                if f.range.is_some() {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` cannot combine value-mapping with range constraints",
                            mt.name, f.name
                        ),
                    });
                }
                if f.present_if.is_some() {
                    // Reject when both apply to the SAME field.
                    // The field's projection is already conditional
                    // via the mapping's default-raw / UnmappedValue
                    // semantics; layering present-if on top muddies
                    // which mechanism the operator expected to fire.
                    // present-if referencing OTHER fields with
                    // value-mapping is fine — the predicate
                    // operates on the raw integer regardless.
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` cannot combine value-mapping with present-if on the same field",
                            mt.name, f.name
                        ),
                    });
                }
                if let Some(default_raw) = vm.default_raw
                    && !vm.entries.contains_key(&default_raw)
                {
                    return Err(SchemaError::Validation {
                        message: format!(
                            "message `{}` field `{}` value-mapping default-raw {} has no matching entry",
                            mt.name, f.name, default_raw
                        ),
                    });
                }
            }
            prev_end = end;
        }
        // Second pass: validate present-if predicates now that we
        // have the full set of field offsets resolved. Each
        // predicate's referenced field must (a) exist in the same
        // message-type, (b) sit at a STRICTLY lower offset (so the
        // decoder has read it before the conditional field is
        // evaluated), and (c) be an integer type — floats / bytes /
        // utf8 have no decidable "equals this raw integer" test.
        for f in &mt.fields {
            let Some(predicate) = &f.present_if else {
                continue;
            };
            let referenced = mt
                .fields
                .iter()
                .find(|other| other.name == predicate.field)
                .ok_or_else(|| SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` present-if references unknown field `{}`",
                        mt.name, f.name, predicate.field
                    ),
                })?;
            if referenced.offset >= f.offset {
                // Equal offsets are also rejected — the validator's
                // overlap check already prevents two fields from
                // sharing an offset for non-zero sizes, but the
                // strict-less rule is the load-bearing one: the
                // decoder reads fields in declared order, so a
                // forward-referenced predicate would evaluate
                // against bytes the decoder has not seen yet.
                return Err(SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` present-if references field `{}` at offset {} which must precede field offset {} (must be parsed earlier)",
                        mt.name, f.name, predicate.field, referenced.offset, f.offset
                    ),
                });
            }
            if !matches!(
                referenced.field_type,
                FieldType::U8
                    | FieldType::U16
                    | FieldType::U32
                    | FieldType::U64
                    | FieldType::I8
                    | FieldType::I16
                    | FieldType::I32
                    | FieldType::I64
            ) {
                return Err(SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` present-if references field `{}` of type `{}` (integer types only)",
                        mt.name,
                        f.name,
                        predicate.field,
                        referenced.field_type.as_str()
                    ),
                });
            }
        }
        // Third pass: validate `repeat` count-from references now
        // that the per-field overlap loop has already accepted the
        // wire layout. Each repeat's `count_from` must (a) exist in
        // the same message-type, (b) sit at a STRICTLY lower offset
        // (so the decoder has the raw count before it reads the
        // array), and (c) be an integer type — floats / bytes / utf8
        // cannot carry a meaningful array count. Mirrors the
        // present-if second pass for shape and error vocabulary.
        for f in &mt.fields {
            let Some(spec) = &f.repeat else {
                continue;
            };
            let referenced = mt
                .fields
                .iter()
                .find(|other| other.name == spec.count_from)
                .ok_or_else(|| SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` repeat references unknown count_from field `{}`",
                        mt.name, f.name, spec.count_from
                    ),
                })?;
            if referenced.offset >= f.offset {
                return Err(SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` repeat count_from field `{}` at offset {} must precede field offset {} (count must be parsed earlier)",
                        mt.name, f.name, spec.count_from, referenced.offset, f.offset
                    ),
                });
            }
            if !matches!(
                referenced.field_type,
                FieldType::U8
                    | FieldType::U16
                    | FieldType::U32
                    | FieldType::U64
                    | FieldType::I8
                    | FieldType::I16
                    | FieldType::I32
                    | FieldType::I64
            ) {
                return Err(SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` repeat count_from references field `{}` of type `{}` (integer types only)",
                        mt.name,
                        f.name,
                        spec.count_from,
                        referenced.field_type.as_str()
                    ),
                });
            }
        }
        if let Some(off) = self.discriminator_offset
            && off >= mt.size_bytes
        {
            return Err(SchemaError::Validation {
                message: format!(
                    "discriminator_offset {} is outside message `{}` size {}",
                    off, mt.name, mt.size_bytes
                ),
            });
        }
        Ok(())
    }
}

/// Upper bound on the count a `repeat.count_from` field can carry,
/// derived from the field's wire type. Used by the first-pass overlap
/// check in [`Schema::validate_message_type`]: a `u8` count caps the
/// array at 255 records, a `u16` at 65 535, etc. The lookup is
/// best-effort — when the named field is missing or non-integer (the
/// second-pass loop rejects both), the function returns `0` so the
/// overlap check leaves the repeat span empty (no false-positive
/// rejections on schemas that will fail validation anyway).
///
/// Signed integer types use their `MAX` as the upper bound — a
/// negative count is meaningless and would be rejected at decode
/// time. The validator's job here is to bound the static layout, not
/// to model the dynamic count behaviour.
fn max_count_for_repeat_field(fields: &[FieldDef], count_from: &str) -> usize {
    let Some(f) = fields.iter().find(|f| f.name == count_from) else {
        return 0;
    };
    match f.field_type {
        FieldType::U8 => u8::MAX as usize,
        FieldType::U16 => u16::MAX as usize,
        FieldType::U32 => u32::MAX as usize,
        // `u64` and `i64` saturate at `usize::MAX` on 64-bit targets
        // and at `u32::MAX` on 32-bit; both are larger than any real
        // array fits in a packet so the cap on `size_bytes` already
        // bounds the meaningful span.
        FieldType::U64 => usize::MAX,
        FieldType::I8 => i8::MAX as usize,
        FieldType::I16 => i16::MAX as usize,
        FieldType::I32 => i32::MAX as usize,
        FieldType::I64 => usize::MAX,
        // Non-integer types fail the second-pass check; return 0
        // here so the overlap loop doesn't falsely accept the
        // surrounding fields.
        FieldType::F32 | FieldType::F64 | FieldType::Bytes | FieldType::Utf8 => 0,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The module-level doc on this file shows operators a YAML
    /// example for a position-report schema. This test re-parses
    /// the same shape so the doc and runtime can't silently drift —
    /// previously the doc used `field-type: !u32 {}` (YAML tag
    /// syntax) but `FieldType` is `#[serde(tag = "kind")]`
    /// (internally tagged), so the operator-copyable example failed
    /// to parse.
    #[test]
    fn module_doc_position_report_example_parses() {
        let yaml = r#"
schema-version: "1"
protocol-name: "example.fixed-binary"
message-types:
  - name: "Position Report"
    id: 1
    size-bytes: 24
    fields:
      - name: "track-id"
        offset: 0
        field-type: { kind: u32 }
        endian: big
        entity-path: "uid"
      - name: "latitude-microdeg"
        offset: 4
        field-type: { kind: i32 }
        endian: big
        calibration: { scale: 1e-6, offset: 0.0 }
        entity-path: "position.lat"
      - name: "longitude-microdeg"
        offset: 8
        field-type: { kind: i32 }
        endian: big
        calibration: { scale: 1e-6, offset: 0.0 }
        entity-path: "position.lon"
"#;
        let schema = Schema::parse(yaml).expect("doc example must parse");
        schema.validate().expect("doc example must validate");
        assert_eq!(schema.message_types[0].fields.len(), 3);
    }

    #[test]
    fn parses_minimal_schema() {
        let yaml = r#"
schema-version: "1"
protocol-name: "example.minimal"
message-types:
  - name: "Test"
    size-bytes: 4
    fields:
      - name: "count"
        offset: 0
        field-type: { kind: u32 }
        endian: big
"#;
        let schema = Schema::parse(yaml).unwrap();
        assert_eq!(schema.protocol_name, "example.minimal");
        assert_eq!(schema.message_types.len(), 1);
        assert_eq!(schema.message_types[0].fields.len(), 1);
        schema.validate().unwrap();
    }

    #[test]
    fn rejects_overlapping_fields() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "Overlap"
    size-bytes: 8
    fields:
      - name: "a"
        offset: 0
        field-type: { kind: u32 }
      - name: "b"
        offset: 2
        field-type: { kind: u32 }
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("overlaps"), "got: {message}");
    }

    #[test]
    fn rejects_field_beyond_message_size() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "TooBig"
    size-bytes: 4
    fields:
      - name: "value"
        offset: 0
        field-type: { kind: u64 }
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("ends at byte 8"), "got: {message}");
    }

    #[test]
    fn accepts_multi_message_with_discriminator_offset() {
        // v2 multi-message dispatch: schema with N message-types
        // plus a `discriminator-offset` validates cleanly. Each
        // message-type carries a unique `id` byte; the codec reads
        // the byte at the discriminator offset to pick the variant.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
discriminator-offset: 0
message-types:
  - name: "A"
    id: 1
    size-bytes: 4
    fields: []
  - name: "B"
    id: 2
    size-bytes: 4
    fields: []
"#;
        let schema = Schema::parse(yaml).unwrap();
        schema
            .validate()
            .expect("multi-message schema must validate");
    }

    #[test]
    fn rejects_multi_message_without_discriminator_offset() {
        // Multi-message schemas MUST declare where the runtime
        // reads the discriminator byte; otherwise dispatch is
        // ambiguous and would silently mis-decode.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "A"
    id: 1
    size-bytes: 4
    fields: []
  - name: "B"
    id: 2
    size-bytes: 4
    fields: []
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("no discriminator_offset"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_multi_message_with_duplicate_ids() {
        // Two message-types claiming the same discriminator byte
        // is unrecoverable — the runtime can't dispatch
        // deterministically. Caught at schema-load, not on first
        // payload.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
discriminator-offset: 0
message-types:
  - name: "A"
    id: 1
    size-bytes: 4
    fields: []
  - name: "B"
    id: 1
    size-bytes: 4
    fields: []
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("must be unique"), "got: {message}");
    }

    #[test]
    fn rejects_multi_message_with_id_outside_byte_range() {
        // The runtime reads a single byte at the discriminator
        // offset, so `id` values outside `0..=255` could never be
        // matched. Catch the misconfiguration at schema-load.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
discriminator-offset: 0
message-types:
  - name: "A"
    id: 1
    size-bytes: 4
    fields: []
  - name: "B"
    id: 300
    size-bytes: 4
    fields: []
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("0..=255"), "got: {message}");
    }

    #[test]
    fn rejects_bytes_field_with_zero_length() {
        // Closes the validator hole where `length-bytes: 0` on a
        // Bytes / Utf8 field silently produced size=0, which left
        // `prev_end` unchanged and let a subsequent field at the same
        // offset slip past the overlap check.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "ZeroLen"
    size-bytes: 8
    fields:
      - name: "blob"
        offset: 0
        field-type: { kind: bytes }
        length-bytes: 0
      - name: "v"
        offset: 0
        field-type: { kind: u32 }
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("zero size"),
            "expected zero-size rejection, got: {message}"
        );
    }

    #[test]
    fn rejects_bytes_field_without_length() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "NoLen"
    size-bytes: 8
    fields:
      - name: "blob"
        offset: 0
        field-type: { kind: bytes }
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("length_bytes"), "got: {message}");
    }

    #[test]
    fn rejects_calibration_with_zero_scale() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 4
    fields:
      - name: "scaled"
        offset: 0
        field-type: { kind: i32 }
        calibration: { scale: 0.0, offset: 1.0 }
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("scale must be non-zero"), "got: {message}");
    }

    #[test]
    fn rejects_range_with_nan_or_inf() {
        // serde_yaml accepts the YAML 1.2 special-float literals
        // `.nan`, `.inf`, `-.inf`. The validator catches them
        // before the codec sees a half-defined range bound.
        for bad in [".nan", ".inf", "-.inf"] {
            let yaml = format!(
                r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 8
    fields:
      - name: "v"
        offset: 0
        field-type: {{ kind: f64 }}
        range: {{ min: {bad}, max: 1.0 }}
"#
            );
            let schema = Schema::parse(&yaml)
                .unwrap_or_else(|e| panic!("schema with range min={bad} should parse, got: {e:?}"));
            let err = schema.validate().unwrap_err();
            let SchemaError::Validation { message } = err else {
                panic!("expected validation error");
            };
            assert!(
                message.contains("range bounds must be finite"),
                "got: {message}"
            );
        }
    }

    #[test]
    fn rejects_range_with_max_less_than_min() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 8
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: f64 }
        range: { min: 10.0, max: 1.0 }
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("less than min"), "got: {message}");
    }

    #[test]
    fn rejects_value_mapping_on_non_integer_field() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 4
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: f32 }
        value-mapping:
          entries:
            0: "zero"
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("integer types only"), "got: {message}");
    }

    #[test]
    fn rejects_value_mapping_combined_with_calibration() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u8 }
        calibration: { scale: 2.0 }
        value-mapping:
          entries:
            0: "off"
            1: "on"
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("cannot combine value-mapping with calibration"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_value_mapping_combined_with_range() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u8 }
        range: { min: 0.0, max: 10.0 }
        value-mapping:
          entries:
            0: "off"
            1: "on"
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("cannot combine value-mapping with range"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_value_mapping_with_default_pointing_nowhere() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u8 }
        value-mapping:
          entries:
            0: "off"
            1: "on"
          default-raw: 99
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("default-raw 99 has no matching entry"),
            "got: {message}"
        );
    }

    #[test]
    fn accepts_present_if_referencing_earlier_integer_field() {
        // Positive case: a conditional `signature` byte gated on an
        // earlier `flags` byte (integer, lower offset) validates
        // cleanly. Pins the happy path of the v3 grammar so
        // subsequent refactors of validate_message_type can't
        // silently regress to rejecting well-formed schemas.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 2
    fields:
      - name: "flags"
        offset: 0
        field-type: { kind: u8 }
      - name: "signature"
        offset: 1
        field-type: { kind: u8 }
        present-if:
          field: "flags"
          value: 1
"#;
        let schema = Schema::parse(yaml).unwrap();
        schema
            .validate()
            .expect("present-if on earlier integer field must validate");
    }

    #[test]
    fn rejects_present_if_referencing_unknown_field() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u8 }
        present-if:
          field: "nope"
          value: 1
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("references unknown field `nope`"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_present_if_referencing_field_at_later_offset() {
        // Forward references break the decoder: the conditional
        // field is evaluated when the predicate's target hasn't
        // been read yet. Equal offsets are also rejected here
        // (the validator's strict-less rule).
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 2
    fields:
      - name: "early"
        offset: 0
        field-type: { kind: u8 }
        present-if:
          field: "late"
          value: 1
      - name: "late"
        offset: 1
        field-type: { kind: u8 }
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("must precede field offset"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_present_if_referencing_float_field() {
        // Floats have no meaningful equality test for a wire
        // predicate (NaN, signed zero, denormals all complicate
        // the semantics). The validator rejects non-integer
        // predicate targets at schema-load.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 12
    fields:
      - name: "x"
        offset: 0
        field-type: { kind: f64 }
      - name: "y"
        offset: 8
        field-type: { kind: u32 }
        present-if:
          field: "x"
          value: 0
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("integer types only"), "got: {message}");
    }

    #[test]
    fn rejects_present_if_combined_with_value_mapping_on_same_field() {
        // value-mapping already conditions the field's projection
        // on its raw integer (via default-raw / UnmappedValue);
        // layering present-if on top would muddy which mechanism
        // the operator expected to fire. Rejected at schema-load.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 2
    fields:
      - name: "flags"
        offset: 0
        field-type: { kind: u8 }
      - name: "status"
        offset: 1
        field-type: { kind: u8 }
        present-if:
          field: "flags"
          value: 1
        value-mapping:
          entries:
            0: "off"
            1: "on"
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("cannot combine value-mapping with present-if"),
            "got: {message}"
        );
    }

    #[test]
    fn accepts_repeat_field_with_earlier_integer_count() {
        // Positive case: a `Bytes` field with a `repeat` spec
        // referencing an earlier `u8` count validates cleanly. Pins
        // the happy path for the v3 grammar — modelled on the DIS
        // articulation-parameter shape (u8 count at offset 0, 16-byte
        // records starting at offset 1).
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "count"
        offset: 0
        field-type: { kind: u8 }
      - name: "records"
        offset: 1
        field-type: { kind: bytes }
        repeat:
          count-from: "count"
          record-size-bytes: 16
"#;
        let schema = Schema::parse(yaml).unwrap();
        schema
            .validate()
            .expect("repeat with earlier u8 count must validate");
    }

    #[test]
    fn rejects_repeat_on_non_bytes_field_type() {
        // v3 repeat is `Bytes`-only — nested-typed record arrays
        // are a v4 feature. A `repeat` declared on a non-`Bytes`
        // field must fail at schema-load so operators don't ship a
        // schema the runtime would silently mis-decode.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "count"
        offset: 0
        field-type: { kind: u8 }
      - name: "records"
        offset: 1
        field-type: { kind: u32 }
        repeat:
          count-from: "count"
          record-size-bytes: 16
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("does not support `repeat`"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_repeat_referencing_unknown_count_field() {
        // Misspelled `count_from` references must fail at schema-load
        // rather than producing a runtime "field not found" mystery
        // on every payload.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "count"
        offset: 0
        field-type: { kind: u8 }
      - name: "records"
        offset: 1
        field-type: { kind: bytes }
        repeat:
          count-from: "nope"
          record-size-bytes: 16
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("repeat references unknown count_from field `nope`"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_repeat_referencing_non_integer_count_field() {
        // A `count_from` field of type `f64` (or `bytes`/`utf8`) has
        // no decidable raw-integer count. Caught at schema-load so the
        // decoder never has to handle a "what count?" runtime error.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 8
    fields:
      - name: "count"
        offset: 0
        field-type: { kind: f64 }
      - name: "records"
        offset: 8
        field-type: { kind: bytes }
        repeat:
          count-from: "count"
          record-size-bytes: 16
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("integer types only"), "got: {message}");
    }

    #[test]
    fn rejects_repeat_referencing_forward_count_field() {
        // Forward references break the decoder: the repeat field is
        // evaluated when the count hasn't been read yet. In the
        // common case the repeat's max-span at offset 0 overlaps the
        // forward `count_from` (the first-pass overlap check fires);
        // for narrower repeats that don't overlap, the second-pass
        // strict-less rule catches it. Either way the schema must
        // fail to validate.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 2
    fields:
      - name: "trailer"
        offset: 0
        field-type: { kind: bytes }
        repeat:
          count-from: "trailer_count"
          record-size-bytes: 1
      - name: "trailer_count"
        offset: 1
        field-type: { kind: u8 }
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        // Accept either error message — both correctly catch the
        // forward-reference bug. Operators see one or the other
        // depending on whether the repeat span happens to cover the
        // forward count field.
        assert!(
            message.contains("overlaps") || message.contains("must precede field offset"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_repeat_with_zero_record_size_bytes() {
        // `record_size_bytes == 0` has no semantic meaning (every
        // count maps to zero bytes) and breaks the overlap-detection
        // loop. Surface at schema-load.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "count"
        offset: 0
        field-type: { kind: u8 }
      - name: "records"
        offset: 1
        field-type: { kind: bytes }
        repeat:
          count-from: "count"
          record-size-bytes: 0
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("record-size-bytes must be > 0"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_repeat_combined_with_length_bytes() {
        // `length_bytes` and `repeat` are mutually exclusive — the
        // wire layout is either fixed-length or count-driven, not
        // both. Catching at schema-load avoids the runtime having to
        // decide which wins.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "count"
        offset: 0
        field-type: { kind: u8 }
      - name: "records"
        offset: 1
        field-type: { kind: bytes }
        length-bytes: 16
        repeat:
          count-from: "count"
          record-size-bytes: 16
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("declares both `length_bytes` and `repeat`"),
            "got: {message}"
        );
    }

    #[test]
    fn field_type_fixed_size_vocabulary_is_stable() {
        assert_eq!(FieldType::U8.fixed_size(), Some(1));
        assert_eq!(FieldType::U16.fixed_size(), Some(2));
        assert_eq!(FieldType::U32.fixed_size(), Some(4));
        assert_eq!(FieldType::U64.fixed_size(), Some(8));
        assert_eq!(FieldType::I8.fixed_size(), Some(1));
        assert_eq!(FieldType::I16.fixed_size(), Some(2));
        assert_eq!(FieldType::I32.fixed_size(), Some(4));
        assert_eq!(FieldType::I64.fixed_size(), Some(8));
        assert_eq!(FieldType::F32.fixed_size(), Some(4));
        assert_eq!(FieldType::F64.fixed_size(), Some(8));
        assert_eq!(FieldType::Bytes.fixed_size(), None);
        assert_eq!(FieldType::Utf8.fixed_size(), None);
    }

    #[test]
    fn field_type_as_str_pins_closed_label_vocabulary() {
        for (ft, tag) in [
            (FieldType::U8, "u8"),
            (FieldType::U16, "u16"),
            (FieldType::U32, "u32"),
            (FieldType::U64, "u64"),
            (FieldType::I8, "i8"),
            (FieldType::I16, "i16"),
            (FieldType::I32, "i32"),
            (FieldType::I64, "i64"),
            (FieldType::F32, "f32"),
            (FieldType::F64, "f64"),
            (FieldType::Bytes, "bytes"),
            (FieldType::Utf8, "utf8"),
        ] {
            assert_eq!(ft.as_str(), tag);
        }
    }

    #[test]
    fn calibration_default_is_identity() {
        let cal = Calibration::default();
        assert_eq!(cal.scale, 1.0);
        assert_eq!(cal.offset, 0.0);
    }

    #[test]
    fn accepts_bit_packed_fields_sharing_byte_without_overlap() {
        // Positive case: three bit-packed fields claiming bits 0,
        // 1, and 2..=4 of the byte at offset 0 validate cleanly. This
        // is the canonical "packed flag byte" shape (VMF FPI / FRI /
        // GPI, ASTERIX FSPEC bits) and must be accepted.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "fpi"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 0
        bit-width: 1
      - name: "fri"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 1
        bit-width: 1
      - name: "category"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 2
        bit-width: 3
"#;
        let schema = Schema::parse(yaml).unwrap();
        schema
            .validate()
            .expect("non-overlapping bit-packed fields must validate");
    }

    #[test]
    fn rejects_bit_offset_without_bit_width() {
        // Both fields must be set together — declaring one without
        // the other is incoherent and almost always indicates an
        // operator typo.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 0
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("`bit_offset` without `bit_width`"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_bit_offset_out_of_range() {
        // `bit_offset` must fit in `[0, 7]` — anything else cannot
        // index into a byte's bit positions.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 8
        bit-width: 1
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("bit_offset 8 must be in `[0, 7]`"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_bit_offset_plus_width_exceeds_byte() {
        // `bit_offset + bit_width <= 8` is the load-bearing v3
        // single-byte limit. A field declaring `bit_offset=5,
        // bit_width=4` would span bits 5..=8 — into the next byte
        // — and is a v4 feature.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 5
        bit-width: 4
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(message.contains("cross-byte bit fields"), "got: {message}");
    }

    #[test]
    fn rejects_bit_packed_combined_with_length_bytes() {
        // `length_bytes` describes a multi-byte fixed-length span;
        // bit-packing describes a sub-byte range. The two are
        // incoherent.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 0
        bit-width: 1
        length-bytes: 1
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("cannot combine bit-packing with `length_bytes`"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_bit_packed_combined_with_value_mapping() {
        // Value-mapping replaces the raw integer with a string label;
        // the bit-packed grammar projects a U64 sub-range. Layering
        // both on the same field is incoherent.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 0
        bit-width: 1
        value-mapping:
          entries:
            0: "off"
            1: "on"
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("cannot combine bit-packing with `value_mapping`"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_bit_packed_fields_with_overlapping_bit_ranges() {
        // Two bit-packed fields at the same byte offset whose bit
        // ranges intersect are unsatisfiable on encode (both would
        // need to write the same bits) and ambiguous on decode (each
        // sees a value the other wrote). Catch at schema-load.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "a"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 0
        bit-width: 3
      - name: "b"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 2
        bit-width: 3
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("overlaps prior bit-packed field"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_bit_packed_on_non_u8_field_type() {
        // v3 bit-packed grammar is `u8`-only: the runtime reads
        // exactly one byte and projects an integer sub-range. Wider
        // field types would either ignore the second byte or
        // silently widen the extraction — both surprises.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 2
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u16 }
        bit-offset: 0
        bit-width: 1
"#;
        let schema = Schema::parse(yaml).unwrap();
        let err = schema.validate().unwrap_err();
        let SchemaError::Validation { message } = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("require `u8` field type"),
            "got: {message}"
        );
    }
}
