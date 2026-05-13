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
//! Variable-length fields, bit-packed fields, nested containers,
//! and conditional fields are intentionally out of scope for v1 —
//! the goal is to make 80% of wire formats codable with 0% Rust per
//! protocol, not to be a complete IDL.

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
        // Multi-message dispatch is v2. The v1 codec runtime always
        // selects the first message type, which would silently
        // mis-decode payloads that match a non-first variant.
        // Reject the schema at startup instead so operators see the
        // gap during a schema-load step, not after the first payload
        // surprises them. The `discriminator_offset` field stays in
        // the grammar so v2 schemas don't need a wire-format change.
        if self.message_types.len() > 1 {
            return Err(SchemaError::Validation {
                message: format!(
                    "schema declares {} message types but multi-message dispatch is not yet implemented (v2); split into separate schemas dispatched at the call site",
                    self.message_types.len()
                ),
            });
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
        for f in &sorted {
            let size = match f.field_type.fixed_size() {
                Some(s) => s,
                None => f.length_bytes.ok_or_else(|| SchemaError::Validation {
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
            if size == 0 {
                return Err(SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` type `{}` declares zero size (length-bytes must be > 0 for variable-length fields)",
                        mt.name,
                        f.name,
                        f.field_type.as_str()
                    ),
                });
            }
            if f.offset < prev_end {
                return Err(SchemaError::Validation {
                    message: format!(
                        "message `{}` field `{}` at offset {} overlaps prior field (ends at {})",
                        mt.name, f.name, f.offset, prev_end
                    ),
                });
            }
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
            prev_end = end;
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
    fn rejects_multi_message_schemas() {
        // v1 codec runtime always selects the first message type;
        // accepting a multi-message schema would silently mis-decode
        // payloads that match the non-first variant. `validate` must
        // reject the schema at startup so the gap surfaces during
        // schema-load, not on the first payload. Covers both the
        // discriminator-present and discriminator-absent cases.
        let with_discriminator = r#"
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
        let without_discriminator = r#"
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
        for yaml in [with_discriminator, without_discriminator] {
            let schema = Schema::parse(yaml).unwrap();
            let err = schema.validate().unwrap_err();
            let SchemaError::Validation { message } = err else {
                panic!("expected validation error");
            };
            assert!(
                message.contains("multi-message dispatch is not yet implemented"),
                "got: {message}"
            );
        }
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
}
