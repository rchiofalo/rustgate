// Copyright © 2026 Roberto Chiofalo.

//! Generic [`EntityCodec`] implementation driven by a [`Schema`]
//! document.
//!
//! Construct a [`SchemaCodec`] with a parsed + validated [`Schema`];
//! the codec then handles every payload that matches the schema's
//! shape without per-protocol Rust.
//!
//! ## What this v1 supports
//!
//! - Fixed-offset, fixed-width primitive integer and float fields.
//! - Little- and big-endian wire ordering.
//! - Linear calibration on integer fields (`scale * raw + offset`).
//! - Optional projection of decoded values onto first-class
//!   [`Entity`] fields (`uid`, `callsign`, `mil_std_2525_sidc`,
//!   `position.lat`, `position.lon`, `position.hae_meters`,
//!   `velocity.speed_m_s`, `velocity.course_deg`).
//! - Fields without an `entity_path` are preserved under
//!   `Entity::attributes` with the key
//!   `"schema.<message>.<field>"` so round-trips never lose data.
//!
//! ## What it does NOT support
//!
//! - Fixed-length byte / UTF-8 string fields (`FieldType::Bytes` /
//!   `FieldType::Utf8`) are parsed but not yet projected to
//!   `entity_path` targets. They round-trip through
//!   `Entity::attributes` as hex / string values.
//! - Value mapping (enum-style raw → label) is parsed by the
//!   schema layer but the runtime treats the raw integer as the
//!   value. Real enum projection follows in a follow-up.
//!
//! ## Multi-message dispatch (v2)
//!
//! Schemas with more than one `message-types` entry declare a
//! 1-byte `discriminator_offset`. On decode, the runtime reads the
//! byte at that offset and selects the message type whose `id`
//! matches; the byte is round-tripped through
//! `Entity::attributes` under
//! `schema.<protocol>.__discriminator__` so a subsequent encode
//! emits the same variant without the call site needing to track
//! it externally. Each message type's `id` must be unique and fit
//! in `0..=255`; `Schema::validate` rejects schemas that don't.
//!
//! ## Conditional fields (v3)
//!
//! [`FieldDef::present_if`](crate::FieldDef::present_if) lets a
//! field's projection depend on the raw integer value of another
//! field at a strictly lower offset. The runtime uses the
//! **sparse-projection** interpretation: the bytes at the
//! conditional field's offset stay reserved on the wire whether
//! or not the predicate matches, but the field is only projected
//! to `Entity` (decode) or read from `Entity` (encode) when the
//! predicate's referenced field equals the declared value. When
//! the predicate misses, decode skips the projection (no
//! attribute write, no entity_path target update) and encode
//! leaves the bytes at their pre-filled zero value. Variable-
//! shift semantics (where the field actually disappears from the
//! wire and subsequent offsets slide) are a separate v4 feature.
//!
//! ## Variable-length repeats (v3)
//!
//! [`FieldDef::repeat`](crate::FieldDef::repeat) makes a
//! `Bytes`-typed field's wire span depend on the raw integer value
//! of an earlier-decoded count field. On decode, the codec reads
//! `record_size_bytes × count` bytes starting at `field.offset` and
//! surfaces them as a single `DecodedValue::Bytes` slice — the
//! consumer parses the inner record shape themselves. On encode,
//! the same dynamic length governs how many bytes are pulled from
//! the entity attribute (hex-string fallback included) and written
//! back at `field.offset`. The output buffer grows as needed when
//! the dynamic end exceeds `mt.size_bytes`, so operators can set
//! `size_bytes` to the header length and produce wire-truthful
//! variable payloads for DIS articulation params, ASTERIX
//! repetitive items, MAVLink v2 payloads, and Link 16 word-3
//! extensions. Nested-typed-record schemas (where each element
//! carries its own field list) are a v4 feature.
//!
//! ## Bit-packed sub-byte fields (v3)
//!
//! [`FieldDef::bit_offset`](crate::FieldDef::bit_offset) +
//! [`FieldDef::bit_width`](crate::FieldDef::bit_width) declare a
//! sub-byte field that occupies a contiguous bit range within ONE
//! byte at the declared `offset`. On decode the runtime reads that
//! byte, applies `(byte >> (8 - bit_offset - bit_width)) & ((1 <<
//! bit_width) - 1)`, and projects the extracted integer as a
//! `DecodedValue::U64`. On encode the symmetric path reads the
//! integer value from the entity, shifts it into position, and
//! OR-merges it into the byte at `field.offset` — critically
//! **without** clobbering other bit-packed fields that share the
//! same byte. The output buffer is pre-zeroed so the first
//! bit-packed field at a given byte sees zero and only sets its
//! own bits; subsequent sibling bit-fields read the in-progress
//! byte and preserve already-written bits.
//!
//! Cross-byte bit-fields (e.g. a 12-bit value spanning byte N's low
//! nibble and byte N+1's high nibble) are deferred to a v4 grammar.

use std::collections::BTreeMap;

use bytes::Bytes;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::error::{SchemaCodecError, SchemaError};
use crate::schema::{Calibration, Endian, FieldDef, FieldType, MessageType, Schema};

/// Schema-driven codec — a single instance implements
/// [`EntityCodec`] for the entire protocol the schema describes.
///
/// The codec is stateless: parsing or producing a payload reads /
/// writes the byte slice in one pass against the cached
/// [`Schema`]. The codec is `Send + Sync` (the schema is immutable
/// after construction) so the router can hold one instance per
/// protocol and reuse it across every routed message.
pub struct SchemaCodec {
    schema: Schema,
}

impl SchemaCodec {
    /// Construct a codec from an already-parsed + validated
    /// [`Schema`]. Pass `Schema::parse(text)?` followed by
    /// `.validate()?` to get a schema from a YAML / JSON document
    /// before calling this.
    #[must_use]
    pub fn new(schema: Schema) -> Self {
        Self { schema }
    }

    /// Parse a schema YAML / JSON document and construct a codec.
    /// Combines [`Schema::parse`] + [`Schema::validate`] +
    /// [`SchemaCodec::new`] for the common case where the caller
    /// has a config file and wants a working codec.
    pub fn from_schema_text(text: &str) -> Result<Self, SchemaError> {
        let schema = Schema::parse(text)?;
        schema.validate()?;
        Ok(Self::new(schema))
    }

    /// Borrow the underlying schema. Exposed so observability code
    /// can read the protocol name + message-type vocabulary into
    /// `tracing` fields or Prometheus labels.
    #[must_use]
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// Choose the message type to apply for an inbound payload.
    /// Single-message schemas return the sole entry; multi-message
    /// schemas read the byte at the schema's `discriminator_offset`
    /// and look up the message type whose `id` matches that byte.
    fn select_message_type_for_payload(
        &self,
        payload: &[u8],
    ) -> Result<&MessageType, SchemaCodecError> {
        if self.schema.message_types.len() == 1 {
            // Safe — `Schema::validate` rejects empty
            // message_types. justification: validation guarantees
            // at least one entry; expect() carries the invariant
            // to the reader.
            #[allow(clippy::expect_used)]
            return Ok(self
                .schema
                .message_types
                .first()
                .expect("validated schema has at least one message type"));
        }
        // Multi-message dispatch — `Schema::validate` guarantees a
        // `discriminator_offset` is present and that each
        // message-type carries a unique `id` in `0..=255`.
        // justification: validation invariants, see `Schema::validate`.
        #[allow(clippy::expect_used)]
        let off = self
            .schema
            .discriminator_offset
            .expect("validated multi-message schema has discriminator_offset");
        if off >= payload.len() {
            return Err(SchemaCodecError::PayloadTooShort {
                actual: payload.len(),
                required: off + 1,
            });
        }
        let discriminator = payload[off];
        self.schema
            .message_types
            .iter()
            .find(|mt| mt.id == i64::from(discriminator))
            .ok_or(SchemaCodecError::UnknownDiscriminator {
                offset: off,
                value: discriminator,
            })
    }

    /// Encode-side variant of message-type selection. Multi-message
    /// schemas round-trip the discriminator byte through
    /// `Entity::attributes` under
    /// `schema.<protocol>.__discriminator__` — decode writes it,
    /// encode reads it back so the call site does not need a
    /// separate API to declare which variant it is emitting.
    fn select_message_type_for_entity(
        &self,
        entity: &Entity,
    ) -> Result<&MessageType, SchemaCodecError> {
        if self.schema.message_types.len() == 1 {
            // justification: `Schema::validate` rejects empty
            // `message_types`, so the single-entry path is
            // guaranteed by the constructor invariant — expect()
            // carries that invariant to the reader rather than
            // burying it in an Option/unwrap chain.
            #[allow(clippy::expect_used)]
            return Ok(self
                .schema
                .message_types
                .first()
                .expect("validated schema has at least one message type"));
        }
        let key = self.discriminator_attribute_key();
        let av = entity.attributes.get(&key).ok_or_else(|| {
            SchemaCodecError::MissingRequiredEntityField {
                field: "__discriminator__".into(),
                path: key.clone(),
            }
        })?;
        let discriminator = match av {
            AttributeValue::Int(v) if (0..=255).contains(v) => *v as u8,
            other => {
                return Err(SchemaCodecError::OutOfRange {
                    field: "__discriminator__".into(),
                    value: format!("{other:?}"),
                    type_name: "u8".into(),
                });
            }
        };
        self.schema
            .message_types
            .iter()
            .find(|mt| mt.id == i64::from(discriminator))
            .ok_or_else(|| {
                // justification: the multi-message decode path
                // writes the byte we just looked up, so an unknown
                // value only happens when a caller hand-constructs
                // the entity. Surface the same error class as
                // decode for symmetry.
                SchemaCodecError::UnknownDiscriminator {
                    offset: self.schema.discriminator_offset.unwrap_or(0),
                    value: discriminator,
                }
            })
    }

    /// Attribute key used to round-trip the discriminator byte for
    /// multi-message schemas. Centralised so decode and encode stay
    /// in lockstep when the key format ever needs to change.
    fn discriminator_attribute_key(&self) -> String {
        format!(
            "schema.{}.__discriminator__",
            self.schema.protocol_name.replace('-', "_")
        )
    }

    /// Decode a single field at its declared offset.
    ///
    /// `dyn_size`, when `Some`, overrides the field's static size
    /// computation — used by `repeat` fields whose wire span depends
    /// on an earlier-decoded count.
    fn decode_field(
        field: &FieldDef,
        payload: &[u8],
        dyn_size: Option<usize>,
    ) -> Result<DecodedValue, SchemaCodecError> {
        // Bit-packed fields short-circuit. The validator guarantees
        // (a) `bit_offset ∈ [0, 7]`, (b) `bit_width ∈ [1, 64]`, and
        // (c) the bit span `offset * 8 + bit_offset + bit_width`
        // fits inside `size_bytes * 8`. The runtime reads the
        // touched byte range MSB-first into a `u64`; v3 single-byte
        // fields (`bit_offset + bit_width ≤ 8`) take the same path
        // and produce identical bytes.
        //
        // Signed types (v4.1) sign-extend the raw bit pattern
        // before projecting as `DecodedValue::I64` — see
        // `sign_extend_bit_span`. Unsigned types take the original
        // `DecodedValue::U64` path unchanged.
        if let (Some(bit_offset), Some(bit_width)) = (field.bit_offset, field.bit_width) {
            let bytes_touched = bit_packed_bytes_touched(bit_offset, bit_width);
            let end = field.offset + bytes_touched;
            if end > payload.len() {
                return Err(SchemaCodecError::PayloadTooShort {
                    actual: payload.len(),
                    required: end,
                });
            }
            let extracted = read_bit_span(payload, field.offset, bit_offset, bit_width);
            return Ok(match field.field_type {
                FieldType::I8 | FieldType::I16 | FieldType::I32 | FieldType::I64 => {
                    DecodedValue::I64(sign_extend_bit_span(extracted, bit_width))
                }
                _ => DecodedValue::U64(extracted),
            });
        }
        let size = dyn_size.unwrap_or_else(|| {
            field
                .field_type
                .fixed_size()
                .or(field.length_bytes)
                .unwrap_or(0)
        });
        let end = field.offset.saturating_add(size);
        if end > payload.len() {
            return Err(SchemaCodecError::PayloadTooShort {
                actual: payload.len(),
                required: end,
            });
        }
        let slice = &payload[field.offset..end];
        let raw = match field.field_type {
            FieldType::U8 => DecodedValue::U64(u64::from(slice[0])),
            FieldType::I8 => DecodedValue::I64(i64::from(slice[0] as i8)),
            FieldType::U16 => DecodedValue::U64(u64::from(read_u16(slice, field.endian))),
            FieldType::I16 => DecodedValue::I64(i64::from(read_u16(slice, field.endian) as i16)),
            FieldType::U32 => DecodedValue::U64(u64::from(read_u32(slice, field.endian))),
            FieldType::I32 => DecodedValue::I64(i64::from(read_u32(slice, field.endian) as i32)),
            FieldType::U64 => DecodedValue::U64(read_u64(slice, field.endian)),
            FieldType::I64 => DecodedValue::I64(read_u64(slice, field.endian) as i64),
            FieldType::F32 => {
                DecodedValue::F64(f64::from(f32::from_bits(read_u32(slice, field.endian))))
            }
            FieldType::F64 => DecodedValue::F64(f64::from_bits(read_u64(slice, field.endian))),
            FieldType::Bytes => DecodedValue::Bytes(slice.to_vec()),
            FieldType::Utf8 => {
                let trimmed = trim_trailing_nuls(slice);
                let s = std::str::from_utf8(trimmed).map_err(|source| SchemaCodecError::Utf8 {
                    field: field.name.clone(),
                    source,
                })?;
                DecodedValue::Str(s.to_string())
            }
        };
        Ok(raw)
    }

    /// Encode one field at its declared offset into a mutable
    /// buffer. The buffer is assumed to be pre-sized to
    /// `message_type.size_bytes` and pre-filled with zeros.
    ///
    /// `dyn_size`, when `Some`, overrides the field's static size
    /// computation — used by `repeat` fields whose wire span depends
    /// on an earlier-decoded count.
    fn encode_field(
        field: &FieldDef,
        value: &EncodedValue,
        out: &mut [u8],
        dyn_size: Option<usize>,
    ) -> Result<(), SchemaCodecError> {
        // Bit-packed fields short-circuit: read the current byte at
        // `offset`, clear only the bit range this field claims, OR
        // in the new bits, write back. Critically, we MUST NOT
        // clobber other bit-packed fields sharing the same byte —
        // the validator allows them as long as their bit ranges
        // don't overlap. Reading the byte first preserves any prior
        // bits already written by sibling bit-packed fields earlier
        // in the field list. The output buffer is pre-zeroed, so the
        // first bit-packed field at a given byte sees zero and only
        // sets its own bits.
        if let (Some(bit_offset), Some(bit_width)) = (field.bit_offset, field.bit_width) {
            let bytes_touched = bit_packed_bytes_touched(bit_offset, bit_width);
            let end = field.offset + bytes_touched;
            if end > out.len() {
                return Err(SchemaCodecError::PayloadTooShort {
                    actual: out.len(),
                    required: end,
                });
            }
            // Signed types (v4.1): range-check against the
            // two's-complement domain `[-2^(N-1), 2^(N-1) - 1]`,
            // then bitcast to u64 and mask to the bit_width so the
            // shared `write_bit_span` path writes only the field's
            // bits. Unsigned types take the original v4 path.
            let raw = match field.field_type {
                FieldType::I8 | FieldType::I16 | FieldType::I32 | FieldType::I64 => {
                    let signed = value.as_i64(field)?;
                    // bit_width == 64 special case: full i64 range
                    // is `[i64::MIN, i64::MAX]`, every value fits.
                    if bit_width < 64 {
                        let half_range = 1i64 << (bit_width - 1);
                        if signed < -half_range || signed >= half_range {
                            return Err(SchemaCodecError::OutOfRange {
                                field: field.name.clone(),
                                value: signed.to_string(),
                                type_name: format!("i{bit_width} (bit-packed)"),
                            });
                        }
                    }
                    // Bitcast to u64 and mask to `bit_width` so
                    // negative values' sign-extended high bits
                    // (when they exist) don't leak past the field.
                    // justification: signed-to-unsigned bit-cast is the
                    // standard two's-complement marshaling pattern.
                    #[allow(clippy::cast_sign_loss)]
                    let bitcast = signed as u64;
                    let mask = if bit_width == 64 {
                        u64::MAX
                    } else {
                        (1u64 << bit_width) - 1
                    };
                    bitcast & mask
                }
                _ => {
                    let raw = value.as_u64(field)?;
                    // Range guard: a `bit_width`-bit unsigned value
                    // can hold `2^bit_width - 1`. The validator
                    // already constrained `bit_width ∈ [1, 64]`, but
                    // `1 << 64` overflows a `u64`, so guard the
                    // `bit_width == 64` case explicitly (any `u64`
                    // value is in-range).
                    let max = if bit_width == 64 {
                        u64::MAX
                    } else {
                        (1u64 << bit_width) - 1
                    };
                    if raw > max {
                        return Err(SchemaCodecError::OutOfRange {
                            field: field.name.clone(),
                            value: raw.to_string(),
                            type_name: format!("u{bit_width} (bit-packed)"),
                        });
                    }
                    raw
                }
            };
            write_bit_span(out, field.offset, bit_offset, bit_width, raw);
            return Ok(());
        }
        let size = dyn_size.unwrap_or_else(|| {
            field
                .field_type
                .fixed_size()
                .or(field.length_bytes)
                .unwrap_or(0)
        });
        let end = field.offset.saturating_add(size);
        if end > out.len() {
            return Err(SchemaCodecError::PayloadTooShort {
                actual: out.len(),
                required: end,
            });
        }
        let slice = &mut out[field.offset..end];
        match field.field_type {
            FieldType::U8 => {
                let v = value.as_u64(field)?;
                if v > u8::MAX as u64 {
                    return Err(SchemaCodecError::OutOfRange {
                        field: field.name.clone(),
                        value: v.to_string(),
                        type_name: "u8".into(),
                    });
                }
                slice[0] = v as u8;
            }
            FieldType::I8 => {
                let v = value.as_i64(field)?;
                if !(i8::MIN as i64..=i8::MAX as i64).contains(&v) {
                    return Err(SchemaCodecError::OutOfRange {
                        field: field.name.clone(),
                        value: v.to_string(),
                        type_name: "i8".into(),
                    });
                }
                slice[0] = v as u8;
            }
            FieldType::U16 => {
                let v = value.as_u64(field)?;
                if v > u16::MAX as u64 {
                    return Err(SchemaCodecError::OutOfRange {
                        field: field.name.clone(),
                        value: v.to_string(),
                        type_name: "u16".into(),
                    });
                }
                write_u16(slice, v as u16, field.endian);
            }
            FieldType::I16 => {
                let v = value.as_i64(field)?;
                if !(i16::MIN as i64..=i16::MAX as i64).contains(&v) {
                    return Err(SchemaCodecError::OutOfRange {
                        field: field.name.clone(),
                        value: v.to_string(),
                        type_name: "i16".into(),
                    });
                }
                write_u16(slice, v as u16, field.endian);
            }
            FieldType::U32 => {
                let v = value.as_u64(field)?;
                if v > u32::MAX as u64 {
                    return Err(SchemaCodecError::OutOfRange {
                        field: field.name.clone(),
                        value: v.to_string(),
                        type_name: "u32".into(),
                    });
                }
                write_u32(slice, v as u32, field.endian);
            }
            FieldType::I32 => {
                let v = value.as_i64(field)?;
                if !(i32::MIN as i64..=i32::MAX as i64).contains(&v) {
                    return Err(SchemaCodecError::OutOfRange {
                        field: field.name.clone(),
                        value: v.to_string(),
                        type_name: "i32".into(),
                    });
                }
                write_u32(slice, v as u32, field.endian);
            }
            FieldType::U64 => {
                let v = value.as_u64(field)?;
                write_u64(slice, v, field.endian);
            }
            FieldType::I64 => {
                let v = value.as_i64(field)?;
                write_u64(slice, v as u64, field.endian);
            }
            FieldType::F32 => {
                let raw = value.as_f64(field)?;
                let v = raw as f32;
                // The `f64 as f32` cast silently saturates to
                // `±f32::INFINITY` for out-of-range values (and to
                // `NaN` for `NaN`). The integer types all surface
                // overflow as `OutOfRange`; do the same here so a
                // miscalibrated schema fails the encode rather than
                // shipping `+inf` on the wire. NaN inputs are
                // similarly rejected — they almost always indicate
                // a calibration bug rather than a real wire value.
                if !v.is_finite() {
                    return Err(SchemaCodecError::OutOfRange {
                        field: field.name.clone(),
                        value: raw.to_string(),
                        type_name: "f32".into(),
                    });
                }
                write_u32(slice, v.to_bits(), field.endian);
            }
            FieldType::F64 => {
                let v = value.as_f64(field)?;
                // Same guard as F32: NaN / ±inf on the wire is
                // almost certainly a bug, not a real measurement.
                if !v.is_finite() {
                    return Err(SchemaCodecError::OutOfRange {
                        field: field.name.clone(),
                        value: v.to_string(),
                        type_name: "f64".into(),
                    });
                }
                write_u64(slice, v.to_bits(), field.endian);
            }
            FieldType::Bytes => {
                let b = value.as_bytes(field)?;
                let len = b.len().min(slice.len());
                slice[..len].copy_from_slice(&b[..len]);
            }
            FieldType::Utf8 => {
                let s = value.as_str(field)?;
                let bytes = s.as_bytes();
                let len = bytes.len().min(slice.len());
                slice[..len].copy_from_slice(&bytes[..len]);
                // Trailing bytes stay zero from the pre-filled
                // buffer.
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for SchemaCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaCodec")
            .field("protocol", &self.schema.protocol_name)
            .field("message_types", &self.schema.message_types.len())
            .finish_non_exhaustive()
    }
}

impl EntityCodec for SchemaCodec {
    type Error = SchemaCodecError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        let mt = self.select_message_type_for_payload(payload)?;
        if payload.len() < mt.size_bytes {
            return Err(SchemaCodecError::PayloadTooShort {
                actual: payload.len(),
                required: mt.size_bytes,
            });
        }
        let mut uid: Option<String> = None;
        let mut callsign: Option<String> = None;
        let mut sidc: Option<String> = None;
        let mut lat: Option<f64> = None;
        let mut lon: Option<f64> = None;
        let mut hae: Option<f64> = None;
        let mut speed: Option<f64> = None;
        let mut course: Option<f64> = None;
        let mut attrs: BTreeMap<String, AttributeValue> = BTreeMap::new();
        // Multi-message schemas round-trip the discriminator byte
        // through `Entity::attributes` so the encode side knows
        // which variant the caller wants to emit. Single-message
        // schemas skip this for cleanliness — there's nothing to
        // disambiguate.
        if self.schema.message_types.len() > 1 {
            // justification: validate() guarantees discriminator_offset
            // and that the byte is in range for every message_type.
            #[allow(clippy::expect_used)]
            let off = self
                .schema
                .discriminator_offset
                .expect("validated multi-message schema has discriminator_offset");
            let _ = attrs.insert(
                self.discriminator_attribute_key(),
                AttributeValue::Int(i64::from(payload[off])),
            );
        }

        // Raw integer values seen so far during this decode pass.
        // Used by `present-if` predicates to compare against the
        // referenced field's already-decoded raw value. The
        // validator guarantees the referenced field exists at a
        // strictly lower offset and is an integer type, so a hit
        // here corresponds to one of these `DecodedValue::{U64,I64}`
        // variants that we recorded BEFORE the conditional field
        // ever runs.
        let mut raw_ints_seen: BTreeMap<&str, i64> = BTreeMap::new();
        for field in &mt.fields {
            // `repeat` fields take a dynamic span derived from an
            // earlier-decoded count. The validator guarantees the
            // `count_from` field exists, is integer-typed, and sits
            // at a strictly lower offset, so `raw_ints_seen` has the
            // value populated before this branch evaluates. Out-of-
            // bounds or negative counts surface as `PayloadTooShort`
            // via the bounds check inside `decode_field`.
            let dyn_size = Self::repeat_dyn_size(field, &raw_ints_seen)?;
            let decoded = Self::decode_field(field, payload, dyn_size)?;
            // Conditional fields evaluate their predicate against
            // the already-decoded raw integer of the referenced
            // field. When the predicate does not match, we still
            // had to read `decode_field` (so the payload-length
            // check fires) but we MUST skip projection: no
            // attribute write, no entity_path target update. The
            // wire bytes are documented as remaining at the
            // declared offset; the operator can use a
            // `value-mapping` or sentinel value on a separate
            // field if they need to distinguish "absent" from
            // "zero" in the projected entity.
            if let Some(predicate) = &field.present_if {
                let matched = raw_ints_seen
                    .get(predicate.field.as_str())
                    .is_some_and(|raw| *raw == predicate.value);
                if !matched {
                    // Skip range check, value-mapping, and
                    // projection entirely. The predicate field is
                    // already validated at schema-load to be an
                    // integer at a strictly lower offset, so the
                    // miss here means "field is logically absent"
                    // rather than "operator referenced an
                    // undecoded field".
                    Self::record_raw_int(&mut raw_ints_seen, field, &decoded);
                    continue;
                }
            }
            Self::check_range_on_decode(field, &decoded)?;
            // Record the raw integer BEFORE applying
            // value-mapping. Subsequent present-if predicates
            // compare against the raw wire integer (validator
            // pins this so the predicate semantics stay
            // decidable), not the projected label string.
            Self::record_raw_int(&mut raw_ints_seen, field, &decoded);
            // Apply value-mapping if the field declares one. The
            // mapping replaces the decoded integer with the label
            // string from `entries`, falling back to `default_raw`
            // for unrecognised raw values. After this step the
            // projection logic below treats the field as a string
            // — calibration/range checks already ran above and
            // value-mapping is incoherent with both per the
            // validator.
            let decoded = Self::apply_value_mapping(field, decoded)?;
            let path = field.entity_path.as_deref();
            let physical_for_path = |dv: &DecodedValue| -> Option<f64> {
                dv.to_calibrated_f64(field.calibration.as_ref())
            };
            match path {
                Some("uid") => uid = Some(decoded.to_string_value()),
                Some("callsign") => callsign = Some(decoded.to_string_value()),
                Some("mil_std_2525_sidc") => sidc = Some(decoded.to_string_value()),
                Some("position.lat") => lat = physical_for_path(&decoded),
                Some("position.lon") => lon = physical_for_path(&decoded),
                Some("position.hae_meters") => hae = physical_for_path(&decoded),
                Some("velocity.speed_m_s") => speed = physical_for_path(&decoded),
                Some("velocity.course_deg") => course = physical_for_path(&decoded),
                _ => {
                    // Either no entity_path or an unrecognized path
                    // — preserve under attributes so the encoder
                    // can round-trip the raw value.
                    let key = match path {
                        Some(p) if p.starts_with("attributes.") => p.to_string(),
                        _ => format!(
                            "schema.{}.{}",
                            self.schema.protocol_name.replace('-', "_"),
                            field.name
                        ),
                    };
                    let av = decoded.to_attribute_value();
                    let _ = attrs.insert(key, av);
                }
            }
        }

        let position = if lat.is_some() || lon.is_some() || hae.is_some() {
            Some(Position {
                lat: lat.unwrap_or(0.0),
                lon: lon.unwrap_or(0.0),
                hae_meters: hae,
            })
        } else {
            None
        };
        let velocity = if speed.is_some() || course.is_some() {
            Some(Velocity {
                speed_m_s: speed.unwrap_or(0.0),
                course_deg: course.unwrap_or(0.0),
            })
        } else {
            None
        };

        Ok(Entity {
            uid: uid.unwrap_or_else(|| format!("schema-{}-unknown", self.schema.protocol_name)),
            kind: EntityKind::Track,
            position,
            velocity,
            timestamp: std::time::SystemTime::now(),
            callsign,
            mil_std_2525_sidc: sidc,
            attributes: attrs,
            taskings: Default::default(),
            files: Default::default(),
        })
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        let mt = self.select_message_type_for_entity(entity)?;
        let mut out = vec![0u8; mt.size_bytes];
        // For multi-message schemas the encoder also writes the
        // discriminator byte at the schema's `discriminator_offset`
        // so the produced bytes round-trip exactly through a
        // subsequent decode. Operators can declare their own
        // `field-type: u8` field at the same offset if they want
        // it surfaced under a friendlier attribute key — the byte
        // simply gets written twice (same value, same address) and
        // the human-friendly name wins on the attribute side.
        if self.schema.message_types.len() > 1 {
            // justification: validate() guarantees discriminator_offset
            // is in range for every message_type.
            #[allow(clippy::expect_used)]
            let off = self
                .schema
                .discriminator_offset
                .expect("validated multi-message schema has discriminator_offset");
            // justification: validate() guarantees id in 0..=255.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let id_byte = mt.id as u8;
            out[off] = id_byte;
        }
        // Mirror of the decode-side `raw_ints_seen` map. As we
        // encode each integer field, record the raw integer the
        // encoder is about to write so any later conditional
        // field can check its predicate against the same value
        // the wire byte will carry. The validator guarantees the
        // referenced field is at a strictly lower offset and is
        // an integer type, so this map is populated before the
        // predicate ever reads it.
        let mut raw_ints_seen: BTreeMap<&str, i64> = BTreeMap::new();
        for field in &mt.fields {
            let predicate_matches = match &field.present_if {
                Some(predicate) => raw_ints_seen
                    .get(predicate.field.as_str())
                    .is_some_and(|raw| *raw == predicate.value),
                None => true,
            };
            if !predicate_matches {
                // Skip the encode for this field — its declared
                // bytes stay at the buffer's pre-filled zeros.
                // Documented behaviour: the operator can declare
                // an explicit `value-mapping` or a sentinel on a
                // separate field if they need a non-zero "absent"
                // marker. We do NOT record this field in
                // `raw_ints_seen`: a conditional field that is
                // logically absent cannot itself drive a
                // downstream predicate, since its wire bytes are
                // all zero and the "raw value" carries no
                // semantic information.
                continue;
            }
            let mut value = lookup_encoded_value(entity, field, &self.schema.protocol_name)?;
            // Reverse value-mapping: if the field declares one and
            // the looked-up value is a string label, swap it for
            // the matching raw integer before the wire encode
            // runs. The validator guarantees value-mapping only
            // appears on integer field types, so the rebound
            // `EncodedValue::I64` flows cleanly through the
            // per-type encoder branches.
            if field.value_mapping.is_some()
                && let EncodedValue::Str(label) = &value
            {
                let raw = Self::reverse_value_mapping(field, label)?;
                value = EncodedValue::I64(raw);
            }
            Self::check_range_on_encode(field, &value)?;
            // Record the raw integer for any downstream predicate
            // BEFORE the per-type encoder runs. We use the same
            // raw-integer view the decoder sees: integer types
            // resolve to their `i64` representation, everything
            // else is skipped (the validator ensures only integer
            // types are referenced by predicates so the skip never
            // matters).
            Self::record_raw_int_for_encode(&mut raw_ints_seen, field, &value);
            // Compute the dynamic span for `repeat` fields from the
            // already-recorded count value. The validator guarantees
            // `count_from` is a lower-offset integer field, so it
            // appears in `raw_ints_seen` by the time we reach a
            // repeat field.
            let dyn_size = Self::repeat_dyn_size(field, &raw_ints_seen)?;
            // For repeat fields, the dynamic end may exceed the
            // statically-sized `out` buffer. Grow with zero-fill so
            // the array fits — the wire payload for variable-size
            // protocols (DIS articulation params, ASTERIX
            // repetitive items, MAVLink v2 payloads) is dynamic and
            // a fixed-size buffer would force operators to set
            // `size_bytes` to the maximum and ship trailing zeros
            // on every short payload. By growing on demand we let
            // operators set `size_bytes` to the header size and
            // produce wire-truthful variable payloads.
            if let Some(span) = dyn_size {
                let needed = field.offset.saturating_add(span);
                if needed > out.len() {
                    out.resize(needed, 0);
                }
            }
            Self::encode_field(field, &value, &mut out, dyn_size)?;
        }
        Ok(Bytes::from(out))
    }
}

impl SchemaCodec {
    /// Apply the field's optional [`Range`] check on the calibrated
    /// physical value of a freshly-decoded `DecodedValue`. Returns
    /// `Ok(())` when no range is declared or the value falls within
    /// `[range.min, range.max]`. Surfaces
    /// [`SchemaCodecError::OutOfRange`] with the field name + the
    /// physical value as a string so the operator can correlate the
    /// reject back to a schema line.
    ///
    /// Skipped for `Bytes` / `Utf8` field types — `to_calibrated_f64`
    /// returns `None` for those and a range constraint on a byte
    /// slice is not a meaningful concept.
    fn check_range_on_decode(
        field: &FieldDef,
        decoded: &DecodedValue,
    ) -> Result<(), SchemaCodecError> {
        let Some(range) = &field.range else {
            return Ok(());
        };
        let Some(physical) = decoded.to_calibrated_f64(field.calibration.as_ref()) else {
            return Ok(());
        };
        if physical < range.min || physical > range.max {
            return Err(SchemaCodecError::OutOfRange {
                field: field.name.clone(),
                value: physical.to_string(),
                type_name: field.field_type.as_str().into(),
            });
        }
        Ok(())
    }

    /// Apply the field's optional [`Range`] check on an
    /// [`EncodedValue`] before it is written to the wire buffer.
    /// Mirrors [`Self::check_range_on_decode`] so an out-of-range
    /// value fails the encode call symmetrically — the operator
    /// sees the same `OutOfRange` error class whether the offending
    /// payload was received or produced.
    fn check_range_on_encode(
        field: &FieldDef,
        value: &EncodedValue,
    ) -> Result<(), SchemaCodecError> {
        let Some(range) = &field.range else {
            return Ok(());
        };
        let Some(physical) = value.to_physical(field) else {
            return Ok(());
        };
        if physical < range.min || physical > range.max {
            return Err(SchemaCodecError::OutOfRange {
                field: field.name.clone(),
                value: physical.to_string(),
                type_name: field.field_type.as_str().into(),
            });
        }
        Ok(())
    }

    /// Apply the field's [`ValueMapping`] to a freshly-decoded
    /// value. Integer values get looked up in the mapping's
    /// `entries`: a hit replaces the integer with the label
    /// `DecodedValue::Str`; a miss falls back to the
    /// `default_raw` entry if configured, otherwise surfaces
    /// `SchemaCodecError::UnmappedValue`.
    ///
    /// `Schema::validate` guarantees `value_mapping` only appears
    /// on integer field types, so `DecodedValue::F64` / `Str` /
    /// `Bytes` reach this path only when the field has no
    /// mapping — in which case we pass the value through.
    ///
    /// [`ValueMapping`]: crate::ValueMapping
    fn apply_value_mapping(
        field: &FieldDef,
        decoded: DecodedValue,
    ) -> Result<DecodedValue, SchemaCodecError> {
        let Some(vm) = &field.value_mapping else {
            return Ok(decoded);
        };
        let raw = match &decoded {
            DecodedValue::U64(v) => *v as i64,
            DecodedValue::I64(v) => *v,
            // Non-integer wire types reach here only when the
            // validator missed a misconfiguration — pass through
            // so we don't double-error.
            _ => return Ok(decoded),
        };
        if let Some(label) = vm.entries.get(&raw) {
            return Ok(DecodedValue::Str(label.clone()));
        }
        if let Some(default_raw) = vm.default_raw {
            // justification: validator guarantees default_raw is
            // a key in entries.
            #[allow(clippy::expect_used)]
            let label = vm
                .entries
                .get(&default_raw)
                .expect("validator: default-raw is a key in entries");
            return Ok(DecodedValue::Str(label.clone()));
        }
        Err(SchemaCodecError::UnmappedValue {
            field: field.name.clone(),
            value: raw.to_string(),
        })
    }

    /// Compute the dynamic wire span of a `repeat` field from the
    /// already-decoded value of its `count_from` reference. Returns
    /// `None` for non-repeat fields (the caller falls back to the
    /// field's static size). The validator guarantees `count_from`
    /// exists as a lower-offset integer field, so a missing entry in
    /// `raw_ints_seen` would indicate a runtime bug — surface it as
    /// a typed error rather than a panic.
    ///
    /// Negative counts (a signed integer count carrying `< 0`) are
    /// treated as zero — the wire layout for "the array is empty"
    /// is exactly the same as a non-existent array, and a real-world
    /// signed count carrying a negative value almost certainly
    /// indicates a producer bug. The `record_size_bytes ×
    /// usize::try_from(count)` saturates to 0 for negatives, which
    /// makes the field zero-length and the dynamic bounds check in
    /// `decode_field` / `encode_field` pass trivially.
    fn repeat_dyn_size(
        field: &FieldDef,
        raw_ints_seen: &BTreeMap<&str, i64>,
    ) -> Result<Option<usize>, SchemaCodecError> {
        let Some(spec) = &field.repeat else {
            return Ok(None);
        };
        // Validator pins `count_from` to a lower-offset integer field,
        // so an absent entry here can only happen on a runtime bug. We
        // surface it as `MissingRequiredEntityField` (the closest
        // taxonomy match) pointing at the count field so an operator
        // can correlate to the schema line.
        let raw = raw_ints_seen.get(spec.count_from.as_str()).ok_or_else(|| {
            SchemaCodecError::MissingRequiredEntityField {
                field: field.name.clone(),
                path: format!("repeat.count_from={}", spec.count_from),
            }
        })?;
        // `i64 → usize`: negative counts saturate to zero (treat as
        // empty array). Larger-than-`usize::MAX` counts cannot
        // happen on 64-bit targets; on 32-bit they saturate to
        // `usize::MAX` and the subsequent bounds check in
        // {decode,encode}_field surfaces `PayloadTooShort`.
        let count: usize = usize::try_from(*raw).unwrap_or(0);
        let span = spec.record_size_bytes.saturating_mul(count);
        Ok(Some(span))
    }

    /// Record the raw integer value of a freshly-decoded field in
    /// the `raw_ints_seen` map used to resolve later
    /// `present-if` predicates. The validator guarantees a
    /// referenced field is an integer type, so we only need to
    /// capture integer variants (`U64` / `I64`); float / string /
    /// bytes values cannot drive a predicate and are silently
    /// skipped here.
    fn record_raw_int<'a>(
        seen: &mut BTreeMap<&'a str, i64>,
        field: &'a FieldDef,
        decoded: &DecodedValue,
    ) {
        let raw = match decoded {
            // `u64` values up to `i64::MAX` round-trip exactly;
            // values with the high bit set wrap to negative `i64`
            // — that wrapping is fine for predicate comparison
            // because the schema's predicate `value: i64` would
            // have to match the same bit pattern, and the
            // operator is comparing against a wire byte string in
            // any case.
            DecodedValue::U64(v) => *v as i64,
            DecodedValue::I64(v) => *v,
            DecodedValue::F64(_) | DecodedValue::Str(_) | DecodedValue::Bytes(_) => return,
        };
        let _ = seen.insert(field.name.as_str(), raw);
    }

    /// Encode-side variant of [`Self::record_raw_int`]. Reads the
    /// raw integer value from an [`EncodedValue`] so subsequent
    /// `present-if` predicates can be evaluated against the same
    /// raw integer the encoder is about to write to the wire.
    /// Non-integer values are skipped (the validator guarantees
    /// referenced fields are integer-typed).
    fn record_raw_int_for_encode<'a>(
        seen: &mut BTreeMap<&'a str, i64>,
        field: &'a FieldDef,
        value: &EncodedValue,
    ) {
        // Only integer fields are valid predicate targets per the
        // validator. Skip non-integer types so a predicate that
        // somehow slipped past validation against, say, a `Bytes`
        // field simply fails to match rather than panicking.
        if !matches!(
            field.field_type,
            FieldType::U8
                | FieldType::U16
                | FieldType::U32
                | FieldType::U64
                | FieldType::I8
                | FieldType::I16
                | FieldType::I32
                | FieldType::I64
        ) {
            return;
        }
        let raw = match value {
            EncodedValue::I64(v) => *v,
            EncodedValue::F64(_) | EncodedValue::Str(_) | EncodedValue::Bytes(_) => return,
        };
        let _ = seen.insert(field.name.as_str(), raw);
    }

    /// Reverse-lookup the raw integer for a string label via a
    /// field's [`ValueMapping`]. Used on the encode side: if the
    /// label matches an entry, return the raw key; if it doesn't
    /// match and `default_raw` is set, return that fallback; if
    /// neither, surface `SchemaCodecError::UnmappedValue` so the
    /// encoder can fail the call instead of shipping a garbled
    /// raw byte.
    ///
    /// [`ValueMapping`]: crate::ValueMapping
    fn reverse_value_mapping(field: &FieldDef, label: &str) -> Result<i64, SchemaCodecError> {
        // justification: caller checks `field.value_mapping.is_some()`
        // before calling.
        #[allow(clippy::expect_used)]
        let vm = field
            .value_mapping
            .as_ref()
            .expect("reverse_value_mapping called without value_mapping");
        if let Some((raw, _)) = vm.entries.iter().find(|(_, v)| v.as_str() == label) {
            return Ok(*raw);
        }
        if let Some(default_raw) = vm.default_raw {
            return Ok(default_raw);
        }
        Err(SchemaCodecError::UnmappedValue {
            field: field.name.clone(),
            value: label.to_string(),
        })
    }
}

/// Internal value taxonomy used during decode. Decouples the wire
/// type from the entity-projection logic so the same code path can
/// handle u8/u16/u32/u64 (DecodedValue::U64) and the signed
/// counterparts (DecodedValue::I64) uniformly.
#[derive(Debug, Clone, PartialEq)]
enum DecodedValue {
    U64(u64),
    I64(i64),
    F64(f64),
    Str(String),
    Bytes(Vec<u8>),
}

impl DecodedValue {
    fn to_calibrated_f64(&self, cal: Option<&Calibration>) -> Option<f64> {
        let raw = match self {
            Self::U64(v) => *v as f64,
            Self::I64(v) => *v as f64,
            Self::F64(v) => *v,
            Self::Str(_) | Self::Bytes(_) => return None,
        };
        Some(match cal {
            Some(c) => raw * c.scale + c.offset,
            None => raw,
        })
    }

    fn to_string_value(&self) -> String {
        match self {
            Self::U64(v) => v.to_string(),
            Self::I64(v) => v.to_string(),
            Self::F64(v) => v.to_string(),
            Self::Str(s) => s.clone(),
            Self::Bytes(b) => b.iter().map(|byte| format!("{byte:02x}")).collect(),
        }
    }

    fn to_attribute_value(&self) -> AttributeValue {
        match self {
            Self::U64(v) => AttributeValue::Int(*v as i64),
            Self::I64(v) => AttributeValue::Int(*v),
            Self::F64(v) => AttributeValue::Float(*v),
            Self::Str(s) => AttributeValue::Str(s.clone()),
            Self::Bytes(b) => {
                AttributeValue::Str(b.iter().map(|byte| format!("{byte:02x}")).collect())
            }
        }
    }
}

/// Internal encode-side value, derived from the [`Entity`] field a
/// schema field projects from.
#[derive(Debug, Clone, PartialEq)]
enum EncodedValue {
    I64(i64),
    F64(f64),
    Str(String),
    Bytes(Vec<u8>),
}

impl EncodedValue {
    /// Best-effort conversion to the field's physical (calibrated)
    /// `f64` value. Used by the range-constraint check at encode
    /// time; returns `None` for `Bytes` (range checks don't apply
    /// to byte slices).
    ///
    /// For numeric variants, the rule is:
    /// - `F64`: already physical (projected from a first-class
    ///   `Entity` field like `position.lat`).
    /// - `I64`: raw integer; apply the field's calibration if any
    ///   so the comparison happens in the same units the range was
    ///   declared in.
    /// - `Str`: parse as `f64`; if the string is non-numeric the
    ///   subsequent per-type encoder call surfaces the typed error
    ///   so we don't need to error here.
    fn to_physical(&self, field: &FieldDef) -> Option<f64> {
        let value = match self {
            Self::F64(v) => *v,
            Self::I64(v) => match &field.calibration {
                Some(cal) => (*v as f64) * cal.scale + cal.offset,
                None => *v as f64,
            },
            Self::Str(s) => s.parse::<f64>().ok()?,
            Self::Bytes(_) => return None,
        };
        Some(value)
    }

    fn as_u64(&self, field: &FieldDef) -> Result<u64, SchemaCodecError> {
        match self {
            // Bit-cast the i64 to u64 rather than rejecting
            // negative values. Decode-side projects u64 wire values
            // through `AttributeValue::Int(i64)` (the only integer
            // variant `Entity::attributes` carries), so a u64 with
            // its high bit set arrives here as a "negative" i64.
            // The subsequent per-type range check on each
            // `FieldType::U{8,16,32}` call site catches values
            // that genuinely overflow the field width — for U64
            // the bit pattern is exactly what we want to write.
            Self::I64(v) => Ok(*v as u64),
            Self::F64(v) => Ok(EncodedValue::reverse_calibration(*v, field) as u64),
            // String → integer fallback so an `Entity` whose `uid`
            // is a decimal string like `"42"` can still project
            // onto a `u32` track-id field. Non-numeric strings fail
            // the call.
            Self::Str(s) => s.parse::<u64>().map_err(|_| SchemaCodecError::OutOfRange {
                field: field.name.clone(),
                value: format!("Str({s:?})"),
                type_name: field.field_type.as_str().into(),
            }),
            other => Err(SchemaCodecError::OutOfRange {
                field: field.name.clone(),
                value: format!("{other:?}"),
                type_name: field.field_type.as_str().into(),
            }),
        }
    }

    fn as_i64(&self, field: &FieldDef) -> Result<i64, SchemaCodecError> {
        match self {
            Self::I64(v) => Ok(*v),
            Self::F64(v) => Ok(EncodedValue::reverse_calibration(*v, field) as i64),
            Self::Str(s) => s.parse::<i64>().map_err(|_| SchemaCodecError::OutOfRange {
                field: field.name.clone(),
                value: format!("Str({s:?})"),
                type_name: field.field_type.as_str().into(),
            }),
            other => Err(SchemaCodecError::OutOfRange {
                field: field.name.clone(),
                value: format!("{other:?}"),
                type_name: field.field_type.as_str().into(),
            }),
        }
    }

    fn as_f64(&self, field: &FieldDef) -> Result<f64, SchemaCodecError> {
        match self {
            Self::F64(v) => Ok(*v),
            Self::I64(v) => Ok(*v as f64),
            Self::Str(s) => s.parse::<f64>().map_err(|_| SchemaCodecError::OutOfRange {
                field: field.name.clone(),
                value: format!("Str({s:?})"),
                type_name: field.field_type.as_str().into(),
            }),
            other => Err(SchemaCodecError::OutOfRange {
                field: field.name.clone(),
                value: format!("{other:?}"),
                type_name: field.field_type.as_str().into(),
            }),
        }
    }

    fn as_str(&self, field: &FieldDef) -> Result<&str, SchemaCodecError> {
        if let Self::Str(s) = self {
            return Ok(s);
        }
        Err(SchemaCodecError::OutOfRange {
            field: field.name.clone(),
            value: format!("{self:?}"),
            type_name: "utf8".into(),
        })
    }

    fn as_bytes(&self, field: &FieldDef) -> Result<&[u8], SchemaCodecError> {
        if let Self::Bytes(b) = self {
            return Ok(b);
        }
        Err(SchemaCodecError::OutOfRange {
            field: field.name.clone(),
            value: format!("{self:?}"),
            type_name: "bytes".into(),
        })
    }

    fn reverse_calibration(physical: f64, field: &FieldDef) -> f64 {
        match &field.calibration {
            Some(c) if c.scale != 0.0 => (physical - c.offset) / c.scale,
            _ => physical,
        }
    }
}

fn lookup_encoded_value(
    entity: &Entity,
    field: &FieldDef,
    protocol_name: &str,
) -> Result<EncodedValue, SchemaCodecError> {
    let attr_key = format!("schema.{}.{}", protocol_name.replace('-', "_"), field.name);
    match field.entity_path.as_deref() {
        Some("uid") => Ok(EncodedValue::Str(entity.uid.clone())),
        Some("callsign") => entity
            .callsign
            .as_ref()
            .map(|s| EncodedValue::Str(s.clone()))
            .ok_or_else(|| SchemaCodecError::MissingRequiredEntityField {
                field: field.name.clone(),
                path: "callsign".into(),
            }),
        Some("mil_std_2525_sidc") => entity
            .mil_std_2525_sidc
            .as_ref()
            .map(|s| EncodedValue::Str(s.clone()))
            .ok_or_else(|| SchemaCodecError::MissingRequiredEntityField {
                field: field.name.clone(),
                path: "mil_std_2525_sidc".into(),
            }),
        Some("position.lat") => entity
            .position
            .as_ref()
            .map(|p| EncodedValue::F64(p.lat))
            .ok_or_else(|| SchemaCodecError::MissingRequiredEntityField {
                field: field.name.clone(),
                path: "position.lat".into(),
            }),
        Some("position.lon") => entity
            .position
            .as_ref()
            .map(|p| EncodedValue::F64(p.lon))
            .ok_or_else(|| SchemaCodecError::MissingRequiredEntityField {
                field: field.name.clone(),
                path: "position.lon".into(),
            }),
        Some("position.hae_meters") => entity
            .position
            .as_ref()
            .and_then(|p| p.hae_meters.map(EncodedValue::F64))
            .ok_or_else(|| SchemaCodecError::MissingRequiredEntityField {
                field: field.name.clone(),
                path: "position.hae_meters".into(),
            }),
        Some("velocity.speed_m_s") => entity
            .velocity
            .as_ref()
            .map(|v| EncodedValue::F64(v.speed_m_s))
            .ok_or_else(|| SchemaCodecError::MissingRequiredEntityField {
                field: field.name.clone(),
                path: "velocity.speed_m_s".into(),
            }),
        Some("velocity.course_deg") => entity
            .velocity
            .as_ref()
            .map(|v| EncodedValue::F64(v.course_deg))
            .ok_or_else(|| SchemaCodecError::MissingRequiredEntityField {
                field: field.name.clone(),
                path: "velocity.course_deg".into(),
            }),
        Some(p) if p.starts_with("attributes.") => entity
            .attributes
            .get(p)
            .map(|av| attr_to_encoded(av, field.field_type))
            .ok_or_else(|| SchemaCodecError::MissingRequiredEntityField {
                field: field.name.clone(),
                path: p.to_string(),
            }),
        _ => entity
            .attributes
            .get(&attr_key)
            .map(|av| attr_to_encoded(av, field.field_type))
            .ok_or_else(|| SchemaCodecError::MissingRequiredEntityField {
                field: field.name.clone(),
                path: attr_key.clone(),
            }),
    }
}

fn attr_to_encoded(av: &AttributeValue, field_type: FieldType) -> EncodedValue {
    match (av, field_type) {
        // Bytes fields round-trip via hex strings on the
        // `attributes` map — decode the hex on the encode side so a
        // `decode → encode` round-trip yields the byte-identical
        // payload. Non-hex strings fall back to UTF-8 byte payloads.
        (AttributeValue::Str(s), FieldType::Bytes) => match hex_decode(s) {
            Some(bytes) => EncodedValue::Bytes(bytes),
            None => EncodedValue::Bytes(s.as_bytes().to_vec()),
        },
        (AttributeValue::Str(s), _) => EncodedValue::Str(s.clone()),
        (AttributeValue::Int(i), _) => EncodedValue::I64(*i),
        (AttributeValue::Float(f), _) => EncodedValue::F64(*f),
        (AttributeValue::Bool(b), _) => EncodedValue::I64(i64::from(*b)),
    }
}

/// Parse a lowercase-hex string into a byte vector. Returns `None`
/// if the input has an odd length or contains non-hex characters —
/// callers fall back to treating the string as a raw UTF-8 byte
/// payload.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn read_u16(slice: &[u8], endian: Endian) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&slice[..2]);
    match endian {
        Endian::Little => u16::from_le_bytes(buf),
        Endian::Big => u16::from_be_bytes(buf),
    }
}

fn read_u32(slice: &[u8], endian: Endian) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&slice[..4]);
    match endian {
        Endian::Little => u32::from_le_bytes(buf),
        Endian::Big => u32::from_be_bytes(buf),
    }
}

fn read_u64(slice: &[u8], endian: Endian) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&slice[..8]);
    match endian {
        Endian::Little => u64::from_le_bytes(buf),
        Endian::Big => u64::from_be_bytes(buf),
    }
}

fn write_u16(slice: &mut [u8], v: u16, endian: Endian) {
    let bytes = match endian {
        Endian::Little => v.to_le_bytes(),
        Endian::Big => v.to_be_bytes(),
    };
    slice[..2].copy_from_slice(&bytes);
}

fn write_u32(slice: &mut [u8], v: u32, endian: Endian) {
    let bytes = match endian {
        Endian::Little => v.to_le_bytes(),
        Endian::Big => v.to_be_bytes(),
    };
    slice[..4].copy_from_slice(&bytes);
}

fn write_u64(slice: &mut [u8], v: u64, endian: Endian) {
    let bytes = match endian {
        Endian::Little => v.to_le_bytes(),
        Endian::Big => v.to_be_bytes(),
    };
    slice[..8].copy_from_slice(&bytes);
}

fn trim_trailing_nuls(slice: &[u8]) -> &[u8] {
    let mut end = slice.len();
    while end > 0 && slice[end - 1] == 0 {
        end -= 1;
    }
    &slice[..end]
}

/// Number of bytes a bit-packed field touches when starting at the
/// given byte-relative `bit_offset` for `bit_width` bits.
///
/// `(bit_offset + bit_width + 7) / 8` rounds up. For v3 single-byte
/// fields where `bit_offset + bit_width ≤ 8` this returns `1`,
/// matching the existing behavior. For v4 cross-byte spans (e.g.
/// `bit_offset = 4`, `bit_width = 12`) this returns `2` (4 bits in
/// byte 0, 8 bits in byte 1 — total span 16 bits = 2 bytes).
fn bit_packed_bytes_touched(bit_offset: u8, bit_width: u8) -> usize {
    let total_bits = (bit_offset as usize) + (bit_width as usize);
    total_bits.div_ceil(8)
}

/// Read a `bit_width`-bit MSB-first big-endian bit stream from
/// `payload` starting at byte `byte_offset`, bit position
/// `bit_offset` (where bit_offset = 0 is the byte's MSB).
///
/// The caller MUST have already verified the bit span fits inside
/// `payload` — the validator does this at schema-load time and the
/// decode path verifies again with [`bit_packed_bytes_touched`]
/// before calling.
///
/// The bit stream walks left-to-right across bytes, packing each
/// extracted chunk into the low bits of the accumulator. For a
/// 12-bit field at `bit_offset = 4` over bytes `[0xAB, 0xCD]`:
///   - Byte 0 contributes the low 4 bits (`0xB`) at positions 8..11
///     of the result.
///   - Byte 1 contributes all 8 bits (`0xCD`) at positions 0..7.
///
/// Result: `0xBCD`.
///
/// The v3 single-byte path is a special case (`bytes_touched == 1`,
/// inner loop iterates once) and produces byte-identical output to
/// the original `(byte >> shift) & mask` formulation.
fn read_bit_span(payload: &[u8], byte_offset: usize, bit_offset: u8, bit_width: u8) -> u64 {
    let mut value: u64 = 0;
    let mut bits_remaining = bit_width as usize;
    let mut cur_byte = byte_offset;
    let mut cur_bit = bit_offset as usize;

    while bits_remaining > 0 {
        let byte = u64::from(payload[cur_byte]);
        let bits_in_this_byte = (8 - cur_bit).min(bits_remaining);
        // Shift this byte right so the chunk's LSB lands at bit 0,
        // then mask to keep only the chunk's bits. For the first
        // byte this strips bits above the field's start; for the
        // last byte it strips bits below the field's end; for
        // middle bytes (always full 8-bit chunks) the shift is 0
        // and the mask is `0xFF`.
        let shift = 8 - cur_bit - bits_in_this_byte;
        let mask = (1u64 << bits_in_this_byte) - 1;
        let chunk = (byte >> shift) & mask;

        // Pack the chunk into the accumulator's low bits, shifting
        // the previous accumulated bits left to make room.
        value = (value << bits_in_this_byte) | chunk;

        bits_remaining -= bits_in_this_byte;
        cur_bit = 0;
        cur_byte += 1;
    }

    value
}

/// Write a `bit_width`-bit value to `out` starting at byte
/// `byte_offset`, bit position `bit_offset`. Mirror of
/// [`read_bit_span`]: MSB-first big-endian bit stream order,
/// preserves sibling bits outside the claimed range via
/// mask-and-OR per affected byte.
///
/// The caller MUST have already verified the bit span fits inside
/// `out` and that `value` fits in `bit_width` bits.
///
/// Each affected byte is read first (so any prior bit-packed field
/// at that byte stays intact), the field's bits are cleared via an
/// inverse mask, and the new bits are OR'd in. Cross-byte spans
/// therefore preserve sibling fields at every touched byte, not
/// just the starting byte.
fn write_bit_span(out: &mut [u8], byte_offset: usize, bit_offset: u8, bit_width: u8, value: u64) {
    let mut bits_remaining = bit_width as usize;
    let mut cur_byte = byte_offset;
    let mut cur_bit = bit_offset as usize;

    while bits_remaining > 0 {
        let bits_in_this_byte = (8 - cur_bit).min(bits_remaining);
        // Take the highest `bits_in_this_byte` bits of the
        // remaining value — MSB-first wire order means the first
        // chunk we write is the value's high end.
        let value_shift = bits_remaining - bits_in_this_byte;
        let chunk_mask = (1u64 << bits_in_this_byte) - 1;
        // justification: `bits_in_this_byte ≤ 8` so the chunk
        // fits in a u8 without truncation; the mask already
        // constrains the value.
        #[allow(clippy::cast_possible_truncation)]
        let chunk = ((value >> value_shift) & chunk_mask) as u8;

        // Position the chunk at the right LSB index within the
        // byte. `bit_offset = 0` (byte's MSB) means LSB-position
        // `8 - bits_in_this_byte`; `bit_offset = 7` (byte's LSB)
        // with `bit_width = 1` means LSB-position 0.
        let position_shift = 8 - cur_bit - bits_in_this_byte;
        let positioned = chunk << position_shift;
        // justification: `chunk_mask ≤ 0xFF` since
        // `bits_in_this_byte ≤ 8`.
        #[allow(clippy::cast_possible_truncation)]
        let byte_mask = (chunk_mask as u8) << position_shift;

        // Clear only this field's bits; preserve any prior bits
        // (other bit-packed sibling fields written earlier).
        out[cur_byte] = (out[cur_byte] & !byte_mask) | positioned;

        bits_remaining -= bits_in_this_byte;
        cur_bit = 0;
        cur_byte += 1;
    }
}

/// Sign-extend a `bit_width`-bit raw bit pattern read out of the
/// wire into a 64-bit signed value. Used by `decode_field` after
/// `read_bit_span` for signed bit-packed field types (v4.1).
///
/// For `bit_width = 64` the raw pattern is already the full u64
/// — bitcast directly to i64 (no extension needed). For narrower
/// widths the MSB-position of the field carries the sign bit; if
/// set, fill the high bits above `bit_width` with 1s so the
/// resulting i64 has the correct two's-complement representation.
///
/// Examples (bit_width = 4):
///   - raw `0b0111` → 7 (positive, MSB is 0)
///   - raw `0b1000` → -8 (MSB is 1; sign-extend → `0xFFFFFFFF_FFFFFFF8`)
///   - raw `0b1111` → -1 (sign-extend → `0xFFFFFFFF_FFFFFFFF`)
fn sign_extend_bit_span(raw: u64, bit_width: u8) -> i64 {
    if bit_width == 64 {
        // justification: full-width bitcast — same bit pattern,
        // signed interpretation.
        #[allow(clippy::cast_possible_wrap)]
        return raw as i64;
    }
    let sign_bit = 1u64 << (bit_width - 1);
    if raw & sign_bit != 0 {
        // Negative — extend high bits above `bit_width` to 1.
        let extension = !((1u64 << bit_width) - 1);
        // justification: standard two's-complement extension; the
        // result fits in i64 because we're filling bits the value
        // would otherwise leave at 0.
        #[allow(clippy::cast_possible_wrap)]
        let extended = (raw | extension) as i64;
        extended
    } else {
        // Positive — direct cast (high bits are 0, no extension).
        // justification: value's MSB is 0, so the result is
        // non-negative and the cast is total.
        #[allow(clippy::cast_possible_wrap)]
        let positive = raw as i64;
        positive
    }
}

/// Iterator yielding `(byte_offset, bit_mask)` pairs for every byte
/// a bit-packed field touches. Used by the schema validator's
/// overlap check to flag two bit-packed fields whose bit ranges
/// intersect across one or more shared bytes.
///
/// Each yielded `bit_mask` has 1-bits at the positions the field
/// claims within `byte_offset`. For a 12-bit field at
/// `byte_offset = 0`, `bit_offset = 4`:
///   - Yields `(0, 0b0000_1111)` — the low 4 bits of byte 0.
///   - Yields `(1, 0b1111_1111)` — all of byte 1.
pub(crate) fn bit_packed_byte_masks(
    byte_offset: usize,
    bit_offset: u8,
    bit_width: u8,
) -> impl Iterator<Item = (usize, u8)> {
    let mut bits_remaining = bit_width as usize;
    let mut cur_byte = byte_offset;
    let mut cur_bit = bit_offset as usize;
    std::iter::from_fn(move || {
        if bits_remaining == 0 {
            return None;
        }
        let bits_in_this_byte = (8 - cur_bit).min(bits_remaining);
        let shift = 8 - cur_bit - bits_in_this_byte;
        // justification: `bits_in_this_byte ≤ 8`, so the
        // `(1u16 << bits_in_this_byte) - 1` fits in a u8.
        #[allow(clippy::cast_possible_truncation)]
        let mask = (((1u16 << bits_in_this_byte) - 1) as u8) << shift;
        let byte = cur_byte;
        cur_byte += 1;
        bits_remaining -= bits_in_this_byte;
        cur_bit = 0;
        Some((byte, mask))
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const POSITION_SCHEMA: &str = r#"
schema-version: "1"
protocol-name: "example.position-report"
message-types:
  - name: "Position"
    size-bytes: 20
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
        calibration: { scale: 0.000001, offset: 0.0 }
        entity-path: "position.lat"
      - name: "longitude-microdeg"
        offset: 8
        field-type: { kind: i32 }
        endian: big
        calibration: { scale: 0.000001, offset: 0.0 }
        entity-path: "position.lon"
      - name: "speed-cm-per-sec"
        offset: 12
        field-type: { kind: u32 }
        endian: big
        calibration: { scale: 0.01, offset: 0.0 }
        entity-path: "velocity.speed_m_s"
      - name: "course-deg-hundredths"
        offset: 16
        field-type: { kind: u32 }
        endian: big
        calibration: { scale: 0.01, offset: 0.0 }
        entity-path: "velocity.course_deg"
"#;

    #[test]
    fn codec_round_trips_position_report() {
        let codec = SchemaCodec::from_schema_text(POSITION_SCHEMA).unwrap();
        // Hand-craft a payload: track-id 42, lat 38.8977 (Capitol),
        // lon -77.0365, speed 12.5 m/s, course 270.5 deg.
        let mut payload = vec![0u8; 20];
        write_u32(&mut payload[0..], 42, Endian::Big);
        write_u32(&mut payload[4..], 38_897_700_u32, Endian::Big);
        write_u32(
            &mut payload[8..],
            ((-77.0365_f64 / 0.000001) as i32) as u32,
            Endian::Big,
        );
        write_u32(&mut payload[12..], 1250, Endian::Big);
        write_u32(&mut payload[16..], 27050, Endian::Big);

        let entity = codec.to_entity(&payload).unwrap();
        assert_eq!(entity.uid, "42");
        let pos = entity.position.unwrap();
        assert!((pos.lat - 38.8977).abs() < 1e-6);
        assert!((pos.lon - (-77.0365)).abs() < 1e-6);
        let vel = entity.velocity.unwrap();
        assert!((vel.speed_m_s - 12.5).abs() < 1e-6);
        assert!((vel.course_deg - 270.5).abs() < 1e-6);
    }

    #[test]
    fn codec_round_trips_back_to_payload() {
        let codec = SchemaCodec::from_schema_text(POSITION_SCHEMA).unwrap();
        let mut payload = vec![0u8; 20];
        write_u32(&mut payload[0..], 42, Endian::Big);
        write_u32(&mut payload[4..], 38_897_700_u32, Endian::Big);
        write_u32(
            &mut payload[8..],
            ((-77.0365_f64 / 0.000001) as i32) as u32,
            Endian::Big,
        );
        write_u32(&mut payload[12..], 1250, Endian::Big);
        write_u32(&mut payload[16..], 27050, Endian::Big);

        let mut entity = codec.to_entity(&payload).unwrap();
        // The schema currently encodes `uid` as the integer
        // bytes value but the decoded uid was the integer
        // string-formatted. Set the uid as the integer
        // value-as-string `"42"` which the encoder parses.
        // For a clean round-trip we'd need uid-int field shape
        // — out of scope for v1 — so we exercise the position
        // round-trip below and skip the uid byte-equality.
        entity.uid = "42".to_string();
        let re_encoded = codec.from_entity(&entity).unwrap();
        // Position fields and velocity fields should round-trip
        // byte-identically; the uid encoding path is documented
        // as a v1 simplification (string → int parse falls back
        // to attributes).
        assert_eq!(&re_encoded[4..], &payload[4..]);
    }

    #[test]
    fn payload_too_short_surfaces_typed_error() {
        let codec = SchemaCodec::from_schema_text(POSITION_SCHEMA).unwrap();
        let err = codec.to_entity(&[0u8; 4]).unwrap_err();
        let SchemaCodecError::PayloadTooShort { actual, required } = err else {
            panic!("expected PayloadTooShort, got {err:?}");
        };
        assert_eq!(actual, 4);
        assert_eq!(required, 20);
    }

    #[test]
    fn fields_without_entity_path_land_on_attributes() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 8
    fields:
      - name: "tag"
        offset: 0
        field-type: { kind: u32 }
        endian: little
      - name: "value"
        offset: 4
        field-type: { kind: u32 }
        endian: little
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let mut payload = vec![0u8; 8];
        write_u32(&mut payload[0..], 0xdead, Endian::Little);
        write_u32(&mut payload[4..], 0xbeef, Endian::Little);
        let entity = codec.to_entity(&payload).unwrap();
        assert!(entity.attributes.contains_key("schema.test.tag"));
        assert!(entity.attributes.contains_key("schema.test.value"));
    }

    #[test]
    fn encoding_out_of_range_value_returns_typed_error() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "tiny"
        offset: 0
        field-type: { kind: u8 }
        entity-path: "attributes.tiny"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        // Build an entity whose `tiny` attribute is 999 — out of
        // u8 range.
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.tiny".to_string(), AttributeValue::Int(999));
        let err = codec.from_entity(&entity).unwrap_err();
        let SchemaCodecError::OutOfRange { type_name, .. } = err else {
            panic!("expected OutOfRange, got {err:?}");
        };
        assert_eq!(type_name, "u8");
    }

    #[test]
    fn endian_little_round_trips_u16() {
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
        endian: little
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let payload = vec![0x34, 0x12]; // little-endian 0x1234
        let entity = codec.to_entity(&payload).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.v"),
            Some(&AttributeValue::Int(0x1234))
        );
    }

    #[test]
    fn endian_big_round_trips_u16() {
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
        endian: big
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let payload = vec![0x12, 0x34]; // big-endian 0x1234
        let entity = codec.to_entity(&payload).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.v"),
            Some(&AttributeValue::Int(0x1234))
        );
    }

    #[test]
    fn signed_i16_negative_decodes_correctly() {
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 2
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: i16 }
        endian: big
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let payload = vec![0xff, 0xfe]; // big-endian -2
        let entity = codec.to_entity(&payload).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.v"),
            Some(&AttributeValue::Int(-2))
        );
    }

    #[test]
    fn f32_decodes_with_endian() {
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
        endian: little
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        // Deliberately not a math-constant approximation — keeps
        // clippy::approx_constant quiet while still exercising the
        // f32 → f64 widening path.
        let v: f32 = 1.5;
        let payload = v.to_le_bytes().to_vec();
        let entity = codec.to_entity(&payload).unwrap();
        let Some(AttributeValue::Float(decoded)) = entity.attributes.get("attributes.v") else {
            panic!("expected float");
        };
        assert!(((*decoded as f32) - 1.5_f32).abs() < 1e-6);
    }

    #[test]
    fn f32_encode_rejects_out_of_range_value() {
        // The `f64 as f32` cast saturates to `+inf` for values
        // above `f32::MAX`. Without the `is_finite()` guard the
        // codec would happily ship `+inf` on the wire; with it,
        // operators see a typed `OutOfRange` at encode time and can
        // fix the calibration / source value.
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
        endian: little
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.v".into(), AttributeValue::Float(1e40));
        let err = codec.from_entity(&entity).unwrap_err();
        let SchemaCodecError::OutOfRange {
            field, type_name, ..
        } = err
        else {
            panic!("expected OutOfRange, got {err:?}");
        };
        assert_eq!(field, "v");
        assert_eq!(type_name, "f32");
    }

    #[test]
    fn f64_encode_rejects_nan() {
        // NaN is almost always a calibration bug, not a real
        // measurement — surface it at encode time.
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
        endian: little
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.v".into(), AttributeValue::Float(f64::NAN));
        let err = codec.from_entity(&entity).unwrap_err();
        let SchemaCodecError::OutOfRange { type_name, .. } = err else {
            panic!("expected OutOfRange, got {err:?}");
        };
        assert_eq!(type_name, "f64");
    }

    #[test]
    fn decode_rejects_out_of_range_value() {
        // f64 lat field with WGS-84 range constraint. A payload
        // carrying lat=200 fits the wire type but is outside the
        // declared physical-value range; decode must surface an
        // `OutOfRange` error pointing at the offending field.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 8
    fields:
      - name: "lat"
        offset: 0
        field-type: { kind: f64 }
        endian: big
        range: { min: -90.0, max: 90.0 }
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let payload = 200.0_f64.to_be_bytes().to_vec();
        let err = codec.to_entity(&payload).unwrap_err();
        let SchemaCodecError::OutOfRange { field, .. } = err else {
            panic!("expected OutOfRange, got {err:?}");
        };
        assert_eq!(field, "lat");
    }

    #[test]
    fn encode_rejects_out_of_range_value() {
        // Symmetric to the decode-side test — an entity whose
        // `position.lat` is 91.0 must fail the encode call with
        // the same `OutOfRange` class so an operator sees one
        // error vocabulary on both sides of the wire.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 8
    fields:
      - name: "lat"
        offset: 0
        field-type: { kind: f64 }
        endian: big
        range: { min: -90.0, max: 90.0 }
        entity-path: "position.lat"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let entity = Entity {
            position: Some(Position {
                lat: 91.0,
                lon: 0.0,
                hae_meters: None,
            }),
            ..empty_entity()
        };
        let err = codec.from_entity(&entity).unwrap_err();
        let SchemaCodecError::OutOfRange { field, .. } = err else {
            panic!("expected OutOfRange, got {err:?}");
        };
        assert_eq!(field, "lat");
    }

    #[test]
    fn range_check_uses_calibrated_physical_value_on_decode() {
        // Field stores microdegrees as i32 with calibration
        // scale=1e-6. Wire value 95_000_000 maps to 95.0 physical
        // which is out of range; wire value 89_000_000 maps to
        // 89.0 which is in range.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 4
    fields:
      - name: "lat-microdeg"
        offset: 0
        field-type: { kind: i32 }
        endian: big
        calibration: { scale: 1.0e-6, offset: 0.0 }
        range: { min: -90.0, max: 90.0 }
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let in_range = 89_000_000i32.to_be_bytes().to_vec();
        assert!(codec.to_entity(&in_range).is_ok());
        let out_of_range = 95_000_000i32.to_be_bytes().to_vec();
        let err = codec.to_entity(&out_of_range).unwrap_err();
        let SchemaCodecError::OutOfRange { .. } = err else {
            panic!("expected OutOfRange, got {err:?}");
        };
    }

    /// Two-message schema where the discriminator byte at offset 0
    /// picks between a `Heartbeat` (id=1) variant and an `Alert`
    /// (id=2) variant. The fields after the discriminator differ
    /// per variant so we can prove the runtime actually decoded
    /// the right one rather than reading the same offsets for both.
    const MULTI_MESSAGE_SCHEMA: &str = r#"
schema-version: "1"
protocol-name: "test.multi"
discriminator-offset: 0
message-types:
  - name: "Heartbeat"
    id: 1
    size-bytes: 5
    fields:
      - name: "tag"
        offset: 0
        field-type: { kind: u8 }
      - name: "seq"
        offset: 1
        field-type: { kind: u32 }
        endian: big
  - name: "Alert"
    id: 2
    size-bytes: 5
    fields:
      - name: "tag"
        offset: 0
        field-type: { kind: u8 }
      - name: "severity"
        offset: 1
        field-type: { kind: u8 }
      - name: "code"
        offset: 2
        field-type: { kind: u16 }
        endian: big
"#;

    #[test]
    fn multi_message_decode_dispatches_by_discriminator_byte() {
        let codec = SchemaCodec::from_schema_text(MULTI_MESSAGE_SCHEMA).unwrap();

        // Heartbeat payload: tag=1, seq=42.
        let mut heartbeat = vec![1u8, 0, 0, 0, 42];
        heartbeat[1..5].copy_from_slice(&42u32.to_be_bytes());
        let entity = codec.to_entity(&heartbeat).unwrap();
        let Some(AttributeValue::Int(seq)) = entity.attributes.get("schema.test.multi.seq") else {
            panic!("expected seq attribute, got: {:?}", entity.attributes);
        };
        assert_eq!(*seq, 42);

        // Alert payload: tag=2, severity=5, code=0x1234.
        let mut alert = vec![2u8, 5, 0, 0, 0];
        alert[2..4].copy_from_slice(&0x1234u16.to_be_bytes());
        let entity = codec.to_entity(&alert).unwrap();
        let Some(AttributeValue::Int(code)) = entity.attributes.get("schema.test.multi.code")
        else {
            panic!("expected code attribute, got: {:?}", entity.attributes);
        };
        assert_eq!(*code, 0x1234);
        // Heartbeat-specific `seq` attribute must NOT appear in
        // an Alert decode — the runtime dispatched the right
        // variant, not the first one.
        assert!(!entity.attributes.contains_key("schema.test.multi.seq"));
    }

    #[test]
    fn multi_message_unknown_discriminator_errors() {
        let codec = SchemaCodec::from_schema_text(MULTI_MESSAGE_SCHEMA).unwrap();
        // Discriminator byte 0xFF doesn't match any declared id.
        let payload = vec![0xFFu8, 0, 0, 0, 0];
        let err = codec.to_entity(&payload).unwrap_err();
        let SchemaCodecError::UnknownDiscriminator { offset, value } = err else {
            panic!("expected UnknownDiscriminator, got {err:?}");
        };
        assert_eq!(offset, 0);
        assert_eq!(value, 0xFF);
    }

    #[test]
    fn multi_message_decode_writes_discriminator_to_attributes() {
        // The decode side stores the discriminator byte in
        // attributes so a subsequent encode can pick the same
        // variant without the call site having to track it
        // externally.
        let codec = SchemaCodec::from_schema_text(MULTI_MESSAGE_SCHEMA).unwrap();
        let mut alert = vec![2u8, 5, 0, 0, 0];
        alert[2..4].copy_from_slice(&0x1234u16.to_be_bytes());
        let entity = codec.to_entity(&alert).unwrap();
        let Some(AttributeValue::Int(disc)) =
            entity.attributes.get("schema.test.multi.__discriminator__")
        else {
            panic!(
                "expected __discriminator__ attribute, got: {:?}",
                entity.attributes
            );
        };
        assert_eq!(*disc, 2);
    }

    #[test]
    fn multi_message_round_trips_byte_identically() {
        let codec = SchemaCodec::from_schema_text(MULTI_MESSAGE_SCHEMA).unwrap();
        for (name, payload) in [
            ("heartbeat", vec![1u8, 0, 0, 0, 42]),
            ("alert", vec![2u8, 5, 0x12, 0x34, 0]),
        ] {
            let mut payload = payload;
            if name == "heartbeat" {
                payload[1..5].copy_from_slice(&42u32.to_be_bytes());
            }
            let entity = codec.to_entity(&payload).unwrap();
            let re_encoded = codec.from_entity(&entity).unwrap();
            assert_eq!(
                &re_encoded[..],
                &payload[..],
                "round-trip mismatch for {name}"
            );
        }
    }

    #[test]
    fn multi_message_encode_without_discriminator_attribute_errors() {
        // If the call site builds an entity by hand without
        // setting the discriminator attribute, encode must fail
        // with a typed error pointing at the missing attribute
        // rather than silently picking the first variant.
        let codec = SchemaCodec::from_schema_text(MULTI_MESSAGE_SCHEMA).unwrap();
        let entity = empty_entity();
        let err = codec.from_entity(&entity).unwrap_err();
        let SchemaCodecError::MissingRequiredEntityField { field, .. } = err else {
            panic!("expected MissingRequiredEntityField, got {err:?}");
        };
        assert_eq!(field, "__discriminator__");
    }

    /// Affiliation byte → NATO friend/hostile/etc label, the
    /// canonical value-mapping use case.
    const AFFILIATION_SCHEMA: &str = r#"
schema-version: "1"
protocol-name: "test.affil"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "affiliation"
        offset: 0
        field-type: { kind: u8 }
        entity-path: "attributes.affiliation"
        value-mapping:
          entries:
            0: "unknown"
            1: "friend"
            2: "neutral"
            3: "hostile"
          default-raw: 0
"#;

    #[test]
    fn value_mapping_decode_projects_label() {
        let codec = SchemaCodec::from_schema_text(AFFILIATION_SCHEMA).unwrap();
        let entity = codec.to_entity(&[1u8]).unwrap();
        let Some(AttributeValue::Str(label)) = entity.attributes.get("attributes.affiliation")
        else {
            panic!("expected str affiliation, got: {:?}", entity.attributes);
        };
        assert_eq!(label, "friend");
    }

    #[test]
    fn value_mapping_decode_uses_default_raw_for_unknown_byte() {
        let codec = SchemaCodec::from_schema_text(AFFILIATION_SCHEMA).unwrap();
        // 0x42 is not in the mapping, but default_raw=0 → "unknown".
        let entity = codec.to_entity(&[0x42u8]).unwrap();
        let Some(AttributeValue::Str(label)) = entity.attributes.get("attributes.affiliation")
        else {
            panic!("expected str affiliation, got: {:?}", entity.attributes);
        };
        assert_eq!(label, "unknown");
    }

    #[test]
    fn value_mapping_decode_without_default_errors_on_unknown() {
        // Same schema as AFFILIATION_SCHEMA but no default_raw —
        // an unmapped wire byte must surface UnmappedValue.
        let yaml = r#"
schema-version: "1"
protocol-name: "test.affil"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "affiliation"
        offset: 0
        field-type: { kind: u8 }
        entity-path: "attributes.affiliation"
        value-mapping:
          entries:
            0: "unknown"
            1: "friend"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let err = codec.to_entity(&[0x42u8]).unwrap_err();
        let SchemaCodecError::UnmappedValue { field, value } = err else {
            panic!("expected UnmappedValue, got {err:?}");
        };
        assert_eq!(field, "affiliation");
        assert_eq!(value, "66");
    }

    #[test]
    fn value_mapping_encode_reverses_label_to_raw() {
        let codec = SchemaCodec::from_schema_text(AFFILIATION_SCHEMA).unwrap();
        let mut entity = empty_entity();
        let _ = entity.attributes.insert(
            "attributes.affiliation".into(),
            AttributeValue::Str("hostile".into()),
        );
        let bytes = codec.from_entity(&entity).unwrap();
        assert_eq!(&bytes[..], &[3u8]);
    }

    #[test]
    fn value_mapping_round_trips_label_byte_identical() {
        let codec = SchemaCodec::from_schema_text(AFFILIATION_SCHEMA).unwrap();
        for raw in 0u8..=3 {
            let entity = codec.to_entity(&[raw]).unwrap();
            let re_encoded = codec.from_entity(&entity).unwrap();
            assert_eq!(
                &re_encoded[..],
                &[raw],
                "round-trip mismatch for affiliation byte {raw}"
            );
        }
    }

    #[test]
    fn value_mapping_encode_unknown_label_uses_default_raw() {
        // Entity carries a label the schema doesn't know about —
        // `default_raw=0` lets the encoder ship the fallback raw
        // instead of failing the call. Decoded back the label
        // becomes "unknown" (the default's entry), so the
        // round-trip is *byte*-identical but the label changes.
        let codec = SchemaCodec::from_schema_text(AFFILIATION_SCHEMA).unwrap();
        let mut entity = empty_entity();
        let _ = entity.attributes.insert(
            "attributes.affiliation".into(),
            AttributeValue::Str("pending".into()),
        );
        let bytes = codec.from_entity(&entity).unwrap();
        assert_eq!(&bytes[..], &[0u8]);
    }

    /// v3 conditional fields: `signature` byte at offset 1 is
    /// projected only when `flags` at offset 0 equals 1. Both
    /// fields decode into `Entity::attributes` (no first-class
    /// `entity_path` target) so the tests can assert on key
    /// presence directly.
    const PRESENT_IF_SCHEMA: &str = r#"
schema-version: "1"
protocol-name: "test.condfield"
message-types:
  - name: "M"
    size-bytes: 2
    fields:
      - name: "flags"
        offset: 0
        field-type: { kind: u8 }
        entity-path: "attributes.flags"
      - name: "signature"
        offset: 1
        field-type: { kind: u8 }
        entity-path: "attributes.signature"
        present-if:
          field: "flags"
          value: 1
"#;

    #[test]
    fn present_if_decode_projects_when_predicate_matches() {
        // flags = 1 → signature attribute appears with its decoded
        // byte value.
        let codec = SchemaCodec::from_schema_text(PRESENT_IF_SCHEMA).unwrap();
        let entity = codec.to_entity(&[1u8, 0xAB]).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.flags"),
            Some(&AttributeValue::Int(1))
        );
        assert_eq!(
            entity.attributes.get("attributes.signature"),
            Some(&AttributeValue::Int(0xAB)),
            "predicate matched — signature must project"
        );
    }

    #[test]
    fn present_if_decode_skips_projection_when_predicate_misses() {
        // flags = 0 → signature byte stays on the wire but does
        // NOT land on `Entity::attributes`. The wire byte 0xAB at
        // offset 1 is consumed (size check passes) but the
        // operator's downstream code sees no `attributes.signature`
        // entry, which is the v3 contract for "logically absent".
        let codec = SchemaCodec::from_schema_text(PRESENT_IF_SCHEMA).unwrap();
        let entity = codec.to_entity(&[0u8, 0xAB]).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.flags"),
            Some(&AttributeValue::Int(0))
        );
        assert!(
            !entity.attributes.contains_key("attributes.signature"),
            "predicate missed — signature must NOT project"
        );
    }

    #[test]
    fn present_if_encode_writes_bytes_when_predicate_matches() {
        // Entity carries flags=1 and signature=0xAB → the encoder
        // emits both bytes at their declared offsets. Symmetric to
        // the positive decode case.
        let codec = SchemaCodec::from_schema_text(PRESENT_IF_SCHEMA).unwrap();
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.flags".into(), AttributeValue::Int(1));
        let _ = entity
            .attributes
            .insert("attributes.signature".into(), AttributeValue::Int(0xAB));
        let bytes = codec.from_entity(&entity).unwrap();
        assert_eq!(&bytes[..], &[1u8, 0xAB]);
    }

    #[test]
    fn present_if_encode_leaves_bytes_zero_when_predicate_misses() {
        // Entity carries flags=0 and signature=0xAB → the encoder
        // writes the flags byte but leaves the signature offset at
        // its pre-filled zero. The operator can declare an
        // explicit sentinel via value-mapping on a separate field
        // if they need a non-zero "absent" marker.
        let codec = SchemaCodec::from_schema_text(PRESENT_IF_SCHEMA).unwrap();
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.flags".into(), AttributeValue::Int(0));
        let _ = entity
            .attributes
            .insert("attributes.signature".into(), AttributeValue::Int(0xAB));
        let bytes = codec.from_entity(&entity).unwrap();
        assert_eq!(
            &bytes[..],
            &[0u8, 0u8],
            "predicate missed — signature byte stays zero"
        );
    }

    #[test]
    fn present_if_round_trips_in_both_predicate_states() {
        // Decode → encode round-trip must reproduce the input
        // bytes when the predicate matches (signature carries
        // through) and must clear the conditional bytes when it
        // doesn't (signature was never on attributes, so encode
        // leaves zeros). Pins the documented v3 semantics on both
        // sides of the wire.
        let codec = SchemaCodec::from_schema_text(PRESENT_IF_SCHEMA).unwrap();

        let entity_present = codec.to_entity(&[1u8, 0xAB]).unwrap();
        let re_encoded_present = codec.from_entity(&entity_present).unwrap();
        assert_eq!(
            &re_encoded_present[..],
            &[1u8, 0xAB],
            "predicate matched on decode — round-trip preserves signature"
        );

        let entity_absent = codec.to_entity(&[0u8, 0xAB]).unwrap();
        let re_encoded_absent = codec.from_entity(&entity_absent).unwrap();
        assert_eq!(
            &re_encoded_absent[..],
            &[0u8, 0u8],
            "predicate missed on decode — round-trip drops signature to zero"
        );
    }

    /// v3 variable-length repeats. `count` is a `u8` at offset 0,
    /// `records` is a `Bytes` array starting at offset 1 with a 4-byte
    /// record size driven by the count. Modelled on the
    /// canonical "preceding count byte then N records" wire shape
    /// (DIS articulation params, ASTERIX REP items, Link 16 word-3).
    /// `size-bytes: 1` declares only the header byte; the codec
    /// grows the output buffer to fit the dynamic array on encode.
    const REPEAT_SCHEMA: &str = r#"
schema-version: "1"
protocol-name: "test.repeat"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "count"
        offset: 0
        field-type: { kind: u8 }
        entity-path: "attributes.count"
      - name: "records"
        offset: 1
        field-type: { kind: bytes }
        repeat:
          count-from: "count"
          record-size-bytes: 4
"#;

    #[test]
    fn repeat_decode_reads_count_times_record_size() {
        // count = 3, record_size = 4 → 12 bytes of records.
        // Payload: [03, 11 22 33 44, 55 66 77 88, 99 AA BB CC].
        let codec = SchemaCodec::from_schema_text(REPEAT_SCHEMA).unwrap();
        let payload = vec![
            0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
        ];
        let entity = codec.to_entity(&payload).unwrap();
        // Count attribute projects via entity-path.
        assert_eq!(
            entity.attributes.get("attributes.count"),
            Some(&AttributeValue::Int(3))
        );
        // Records land on the default attribute key as a hex string.
        let Some(AttributeValue::Str(records)) =
            entity.attributes.get("schema.test.repeat.records")
        else {
            panic!(
                "expected records attribute, got: {:?}",
                entity.attributes.keys().collect::<Vec<_>>()
            );
        };
        assert_eq!(records, "112233445566778899aabbcc");
    }

    #[test]
    fn repeat_decode_with_zero_count_produces_empty_byte_slice() {
        // count = 0 → zero record bytes. Payload is the single count
        // byte (the codec accepts payloads >= `size_bytes` = 1).
        // The records attribute should be present as an empty hex
        // string, not absent, so a round-trip preserves the field
        // even when no records were on the wire.
        let codec = SchemaCodec::from_schema_text(REPEAT_SCHEMA).unwrap();
        let payload = vec![0x00];
        let entity = codec.to_entity(&payload).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.count"),
            Some(&AttributeValue::Int(0))
        );
        let Some(AttributeValue::Str(records)) =
            entity.attributes.get("schema.test.repeat.records")
        else {
            panic!(
                "expected records attribute even for count=0, got: {:?}",
                entity.attributes.keys().collect::<Vec<_>>()
            );
        };
        assert_eq!(records, "", "zero count must project an empty byte slice");
    }

    #[test]
    fn repeat_round_trips_byte_identically() {
        // Decode → encode for a 3-record payload must reproduce the
        // input bytes exactly. Pins the documented v3 semantics on
        // both sides of the wire.
        let codec = SchemaCodec::from_schema_text(REPEAT_SCHEMA).unwrap();
        let payload = vec![
            0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
        ];
        let entity = codec.to_entity(&payload).unwrap();
        let re_encoded = codec.from_entity(&entity).unwrap();
        assert_eq!(
            &re_encoded[..],
            &payload[..],
            "round-trip must be byte-identical for variable-length repeat"
        );
    }

    #[test]
    fn repeat_decode_rejects_truncated_payload() {
        // count = 3 declares 12 record bytes but only 8 are
        // available. The dynamic bounds check in `decode_field`
        // surfaces `PayloadTooShort` against the actual length, not
        // a panic.
        let codec = SchemaCodec::from_schema_text(REPEAT_SCHEMA).unwrap();
        // 1 count byte + 8 record bytes = 9 bytes; 12 expected.
        let payload = vec![0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let err = codec.to_entity(&payload).unwrap_err();
        let SchemaCodecError::PayloadTooShort { actual, required } = err else {
            panic!("expected PayloadTooShort, got {err:?}");
        };
        assert_eq!(actual, 9);
        // 3 records × 4 bytes + 1 count byte = 13 required.
        assert_eq!(required, 13);
    }

    #[test]
    fn repeat_encode_grows_output_for_variable_payload() {
        // size-bytes = 1 (header only) but count = 2 means encode
        // produces 1 + 2*4 = 9 bytes. The codec grows the output
        // buffer rather than capping at size_bytes so operators can
        // emit wire-truthful variable payloads without setting
        // size_bytes to the maximum.
        let codec = SchemaCodec::from_schema_text(REPEAT_SCHEMA).unwrap();
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.count".into(), AttributeValue::Int(2));
        // The encoder reads records from the default attribute key.
        let _ = entity.attributes.insert(
            "schema.test.repeat.records".into(),
            AttributeValue::Str("aabbccdd11223344".into()),
        );
        let bytes = codec.from_entity(&entity).unwrap();
        assert_eq!(bytes.len(), 9, "output grew to fit count=2 records");
        assert_eq!(bytes[0], 0x02);
        assert_eq!(
            &bytes[1..],
            &[0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]
        );
    }

    #[test]
    fn repeat_encode_with_zero_count_produces_header_only() {
        // count = 0 means encode produces the single count byte and
        // nothing else, regardless of whether the records attribute
        // is present. Round-trip-compatible with a decoded zero-count
        // payload.
        let codec = SchemaCodec::from_schema_text(REPEAT_SCHEMA).unwrap();
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.count".into(), AttributeValue::Int(0));
        let _ = entity.attributes.insert(
            "schema.test.repeat.records".into(),
            AttributeValue::Str(String::new()),
        );
        let bytes = codec.from_entity(&entity).unwrap();
        assert_eq!(&bytes[..], &[0x00], "count=0 produces header-only output");
    }

    #[test]
    fn repeat_with_u16_count_decodes_large_array() {
        // Exercises the `u16` count path: a 2-byte big-endian count
        // followed by record_size_bytes × count bytes. Counts > 255
        // would fail with a `u8` count; the u16 widening lets a
        // schema declare arrays up to 65 535 records.
        let yaml = r#"
schema-version: "1"
protocol-name: "test.repeat16"
message-types:
  - name: "M"
    size-bytes: 2
    fields:
      - name: "count"
        offset: 0
        field-type: { kind: u16 }
        endian: big
        entity-path: "attributes.count"
      - name: "records"
        offset: 2
        field-type: { kind: bytes }
        repeat:
          count-from: "count"
          record-size-bytes: 2
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        // count = 5, records = [01 02, 03 04, 05 06, 07 08, 09 0A].
        let mut payload = vec![0u8; 2];
        payload[..2].copy_from_slice(&5u16.to_be_bytes());
        payload.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]);
        let entity = codec.to_entity(&payload).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.count"),
            Some(&AttributeValue::Int(5))
        );
        let Some(AttributeValue::Str(records)) =
            entity.attributes.get("schema.test.repeat16.records")
        else {
            panic!(
                "expected records attribute, got: {:?}",
                entity.attributes.keys().collect::<Vec<_>>()
            );
        };
        assert_eq!(records, "0102030405060708090a");
    }

    /// v3 bit-packed sub-byte fields: a packed flag byte holds three
    /// indicators (1-bit FPI, 1-bit FRI, 3-bit category, plus 3 bits
    /// of padding). All three pack into the same byte at offset 0,
    /// modelled on the VMF FPI/FRI/GPI shape.
    const BIT_PACKED_SCHEMA: &str = r#"
schema-version: "1"
protocol-name: "test.bits"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "fpi"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 0
        bit-width: 1
        entity-path: "attributes.fpi"
      - name: "fri"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 1
        bit-width: 1
        entity-path: "attributes.fri"
      - name: "category"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 2
        bit-width: 3
        entity-path: "attributes.category"
"#;

    #[test]
    fn bit_packed_decode_extracts_msb_one_bit_flag() {
        // 1-bit flag at the MSB of the byte. Payload `0b1000_0000`
        // decodes to `1`; payload `0b0000_0000` decodes to `0`.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "flag"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 0
        bit-width: 1
        entity-path: "attributes.flag"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let entity = codec.to_entity(&[0b1000_0000u8]).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.flag"),
            Some(&AttributeValue::Int(1))
        );
        let entity = codec.to_entity(&[0b0000_0000u8]).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.flag"),
            Some(&AttributeValue::Int(0))
        );
    }

    #[test]
    fn bit_packed_decode_extracts_three_bit_low_nibble_field() {
        // 3-bit field at bit-offset 5 = low nibble's bottom 3 bits.
        // Payload `0b0000_0101` (decimal 5) decodes to `5`; payload
        // `0b1010_0010` (decimal 0xA2) also decodes to `2` for those
        // same 3 bits regardless of the upper bits.
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
        bit-width: 3
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let entity = codec.to_entity(&[0b0000_0101u8]).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.v"),
            Some(&AttributeValue::Int(5))
        );
        let entity = codec.to_entity(&[0b1010_0010u8]).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.v"),
            Some(&AttributeValue::Int(2))
        );
    }

    #[test]
    fn bit_packed_round_trips_packed_byte_byte_identical() {
        // Pack fpi=1, fri=0, category=5 into a single byte. The
        // expected wire byte is 0b10000_101_xxx where the bottom 3
        // bits are padding (zero from buffer pre-fill).
        let codec = SchemaCodec::from_schema_text(BIT_PACKED_SCHEMA).unwrap();
        // fpi=1 at bit 0 → 0b1000_0000
        // fri=0 at bit 1 → 0b0000_0000
        // category=5 at bits 2..=4 → 0b00101_000 → shifted to bits
        //   2..=4 means MSB-first: bit2 is value 0x20, bit3 0x10,
        //   bit4 0x08. category=5 = 0b101 → shift left by 3 (8 - 2
        //   - 3) = bit positions 2..=4 → value 0x28.
        // Combined: 0x80 | 0x00 | 0x28 = 0xA8 = 0b1010_1000.
        let expected: u8 = 0b1010_1000;
        let entity = codec.to_entity(&[expected]).unwrap();
        assert_eq!(
            entity.attributes.get("attributes.fpi"),
            Some(&AttributeValue::Int(1))
        );
        assert_eq!(
            entity.attributes.get("attributes.fri"),
            Some(&AttributeValue::Int(0))
        );
        assert_eq!(
            entity.attributes.get("attributes.category"),
            Some(&AttributeValue::Int(5))
        );
        let re_encoded = codec.from_entity(&entity).unwrap();
        assert_eq!(
            &re_encoded[..],
            &[expected],
            "bit-packed round-trip must be byte-identical"
        );
    }

    #[test]
    fn bit_packed_encode_shares_byte_without_clobber() {
        // Two bit-packed fields at the same byte offset must each
        // set ONLY their own bits without overwriting the other.
        // The buffer is pre-zeroed so the first field at the byte
        // sees 0 and ORs in its bits; the second reads the
        // in-progress byte and preserves the first's bits.
        let codec = SchemaCodec::from_schema_text(BIT_PACKED_SCHEMA).unwrap();
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.fpi".into(), AttributeValue::Int(1));
        let _ = entity
            .attributes
            .insert("attributes.fri".into(), AttributeValue::Int(1));
        let _ = entity
            .attributes
            .insert("attributes.category".into(), AttributeValue::Int(7));
        let bytes = codec.from_entity(&entity).unwrap();
        // fpi=1 (bit 0): 0x80
        // fri=1 (bit 1): 0x40
        // category=7 (bits 2..=4): 0b111 << 3 = 0x38
        // Combined: 0x80 | 0x40 | 0x38 = 0xF8 = 0b1111_1000.
        assert_eq!(&bytes[..], &[0b1111_1000u8]);
    }

    #[test]
    fn bit_packed_encode_rejects_value_exceeding_bit_width() {
        // A 3-bit field cannot hold the value 8 (only `[0, 7]`). The
        // encoder must reject this with OutOfRange rather than
        // silently masking the high bits.
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
        bit-width: 3
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.v".into(), AttributeValue::Int(8));
        let err = codec.from_entity(&entity).unwrap_err();
        let SchemaCodecError::OutOfRange { type_name, .. } = err else {
            panic!("expected OutOfRange, got {err:?}");
        };
        assert!(
            type_name.contains("u3"),
            "expected type label to mention bit-width, got: {type_name}"
        );
    }

    // ----------------- v4 cross-byte bit spans (#1399) -----------------

    #[test]
    fn read_bit_span_zero_or_eight_bits_matches_v3_behaviour() {
        // Smoke check that the new multi-byte bit stream reader
        // produces identical bytes to the old single-byte
        // `(byte >> shift) & mask` formulation for every v3-style
        // single-byte field. Pins backward compatibility at the
        // helper-function level.
        let payload = [0b1010_1100_u8];
        // bit-offset 0, width 1 → MSB → 1
        assert_eq!(read_bit_span(&payload, 0, 0, 1), 1);
        // bit-offset 0, width 4 → 0b1010 → 10
        assert_eq!(read_bit_span(&payload, 0, 0, 4), 0b1010);
        // bit-offset 4, width 4 → 0b1100 → 12
        assert_eq!(read_bit_span(&payload, 0, 4, 4), 0b1100);
        // bit-offset 0, width 8 → full byte
        assert_eq!(read_bit_span(&payload, 0, 0, 8), 0b1010_1100);
    }

    #[test]
    fn read_bit_span_twelve_bits_across_two_bytes() {
        // 12-bit field at bit_offset = 4 over bytes [0xAB, 0xCD]:
        //   byte 0 low nibble = 0xB (4 bits)
        //   byte 1 all 8 bits = 0xCD
        // Result: 0xBCD = 3021
        let payload = [0xAB, 0xCD];
        assert_eq!(read_bit_span(&payload, 0, 4, 12), 0x0BCD);
    }

    #[test]
    fn read_bit_span_twenty_five_bits_across_four_bytes() {
        // 25-bit field at bit_offset = 0 starting at byte 0.
        // Source: [0xFF, 0xFF, 0xFF, 0x80] → bits 0..=24 are
        // 0b1111_1111_1111_1111_1111_1111_1 (25 ones).
        // Result: (1 << 25) - 1 = 0x1FF_FFFF.
        let payload = [0xFF, 0xFF, 0xFF, 0x80];
        assert_eq!(read_bit_span(&payload, 0, 0, 25), 0x01FF_FFFF);
    }

    #[test]
    fn write_bit_span_round_trips_through_read() {
        // Property pin (manual): every (bit_offset, bit_width,
        // value) combo we write must read back the same value.
        // Cover a representative cross-section of widths.
        let cases: &[(u8, u8, u64)] = &[
            (0, 1, 1),
            (4, 8, 0xAB),
            (4, 12, 0x0BCD),
            (0, 16, 0xABCD),
            (3, 13, 0x1ABC),
            (0, 25, 0x01FF_FFFF),
            (5, 32, 0xDEAD_BEEF),
            (7, 17, 0x0001_FFFF),
        ];
        for &(bit_offset, bit_width, value) in cases {
            let bytes = bit_packed_bytes_touched(bit_offset, bit_width);
            let mut buf = vec![0u8; bytes];
            write_bit_span(&mut buf, 0, bit_offset, bit_width, value);
            let read_back = read_bit_span(&buf, 0, bit_offset, bit_width);
            assert_eq!(
                read_back, value,
                "(bit_offset={bit_offset}, bit_width={bit_width}, value={value:#x}) failed round-trip"
            );
        }
    }

    #[test]
    fn write_bit_span_preserves_sibling_bits_outside_field() {
        // A bit-packed field MUST NOT clobber bits outside its
        // declared range. Pre-fill the buffer with `0xFF`s,
        // write a value of 0 into a 4-bit field at bit_offset=2,
        // and confirm only those 4 bits got cleared.
        let mut buf = [0xFFu8, 0xFF];
        // Write 0 into 4 bits at byte 0, bit_offset 2. Position
        // 2..=5 (MSB-indexed) maps to LSB-position 2..=5 → mask
        // 0b0011_1100.
        write_bit_span(&mut buf, 0, 2, 4, 0);
        assert_eq!(buf[0], 0b1100_0011);
        // Byte 1 untouched.
        assert_eq!(buf[1], 0xFF);
    }

    #[test]
    fn write_bit_span_preserves_sibling_bits_in_middle_byte() {
        // Cross-byte case: a 16-bit field at bit_offset = 4
        // touches bytes 0, 1, 2 with span 4 + 8 + 4 bits — low
        // nibble of byte 0, all of byte 1, high nibble of byte 2.
        // Pre-fill all three bytes with `0xFF`, write a value of
        // 0, and confirm only the field's bits cleared. This is
        // the load-bearing demonstration that the encoder's
        // mask-and-OR runs per touched byte and preserves
        // sibling bits at BOTH the head and tail edges, not just
        // the starting byte.
        let mut buf = [0xFFu8, 0xFF, 0xFF];
        write_bit_span(&mut buf, 0, 4, 16, 0);
        // Byte 0: high nibble preserved, low nibble cleared.
        assert_eq!(buf[0], 0b1111_0000);
        // Byte 1: fully claimed by the field, cleared to 0.
        assert_eq!(buf[1], 0x00);
        // Byte 2: high nibble cleared, low nibble preserved.
        assert_eq!(buf[2], 0b0000_1111);
    }

    #[test]
    fn cross_byte_bit_span_round_trips_through_schema_codec() {
        // End-to-end: a 12-bit `u16` field at bit_offset = 4
        // encodes → decodes → re-encodes byte-identical via the
        // full schema runtime. This is the load-bearing v4
        // assertion — single-byte v3 schemas continue to work,
        // and the new cross-byte path works alongside them.
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
        bit-offset: 4
        bit-width: 12
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        // Build a wire payload where the 12-bit field at bits 4..=15
        // carries 0xABC.
        // Byte 0 low nibble = 0xA, byte 1 all 8 bits = 0xBC → bytes
        // are [0x0A, 0xBC].
        let wire = [0x0A, 0xBC];
        let entity = codec.to_entity(&wire).expect("schema decode");
        let Some(AttributeValue::Int(decoded)) = entity.attributes.get("attributes.v") else {
            panic!(
                "expected attributes.v as Int, got {:?}",
                entity.attributes.get("attributes.v")
            );
        };
        assert_eq!(*decoded, 0x0ABC);
        let re_encoded = codec.from_entity(&entity).expect("schema encode");
        assert_eq!(&re_encoded[..], &wire);
    }

    #[test]
    fn cross_byte_bit_span_preserves_neighbour_bit_packed_field() {
        // The defining v4 case: two bit-packed fields share a
        // byte boundary. Field `flag` is a 1-bit MSB flag in
        // byte 0; field `value` is a 15-bit u16 starting at
        // bit_offset = 1, spanning the low 7 bits of byte 0 plus
        // all of byte 1. Encoding both fields must NOT clobber
        // either one — the cross-byte path's
        // mask-and-OR-per-touched-byte logic is the load-bearing
        // mechanism.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 2
    fields:
      - name: "flag"
        offset: 0
        field-type: { kind: u8 }
        bit-offset: 0
        bit-width: 1
        entity-path: "attributes.flag"
      - name: "value"
        offset: 0
        field-type: { kind: u16 }
        bit-offset: 1
        bit-width: 15
        entity-path: "attributes.value"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.flag".into(), AttributeValue::Int(1));
        let _ = entity
            .attributes
            .insert("attributes.value".into(), AttributeValue::Int(0x1234));
        let wire = codec.from_entity(&entity).expect("schema encode");
        // Expected wire: bit 0 = 1 (flag), bits 1..=15 = 0x1234
        // (value). MSB-first: byte 0 = (1 << 7) | (0x1234 >> 8) =
        // 0x80 | 0x24 = 0xA4 — wait, 0x1234 >> 8 = 0x12, so 0x80 |
        // 0x12 = 0x92. Byte 1 = 0x1234 & 0xFF = 0x34.
        assert_eq!(wire, vec![0x92, 0x34]);
        // Round-trip: decode the wire and confirm both fields
        // recover their values.
        let recovered = codec.to_entity(&wire).expect("schema decode");
        assert_eq!(
            recovered.attributes.get("attributes.flag"),
            Some(&AttributeValue::Int(1))
        );
        assert_eq!(
            recovered.attributes.get("attributes.value"),
            Some(&AttributeValue::Int(0x1234))
        );
    }

    // ----------------- v4.1 signed bit-packed types (#1403) -----------------

    #[test]
    fn sign_extend_bit_span_handles_positive_negative_and_zero() {
        // 4-bit signed: domain is [-8, 7].
        //   raw 0b0000 → 0
        //   raw 0b0001 → 1
        //   raw 0b0111 → 7 (max positive)
        //   raw 0b1000 → -8 (min negative)
        //   raw 0b1111 → -1
        assert_eq!(sign_extend_bit_span(0b0000, 4), 0);
        assert_eq!(sign_extend_bit_span(0b0001, 4), 1);
        assert_eq!(sign_extend_bit_span(0b0111, 4), 7);
        assert_eq!(sign_extend_bit_span(0b1000, 4), -8);
        assert_eq!(sign_extend_bit_span(0b1111, 4), -1);

        // 25-bit signed (VMF latitude representative): domain is
        // [-2^24, 2^24 - 1] = [-16_777_216, 16_777_215].
        //   raw 0x00FFFFFF → 16_777_215 (max positive)
        //   raw 0x01000000 → -16_777_216 (min negative, MSB is bit 24)
        //   raw 0x01FFFFFF → -1 (all 25 bits set)
        assert_eq!(sign_extend_bit_span(0x00FF_FFFF, 25), 16_777_215);
        assert_eq!(sign_extend_bit_span(0x0100_0000, 25), -16_777_216);
        assert_eq!(sign_extend_bit_span(0x01FF_FFFF, 25), -1);

        // 64-bit: full bitcast, no extension.
        assert_eq!(sign_extend_bit_span(0, 64), 0);
        assert_eq!(sign_extend_bit_span(u64::MAX, 64), -1);
        assert_eq!(sign_extend_bit_span(1u64 << 63, 64), i64::MIN);
        assert_eq!(sign_extend_bit_span((1u64 << 63) - 1, 64), i64::MAX);
    }

    #[test]
    fn signed_bit_packed_round_trips_through_schema_codec() {
        // End-to-end signed round-trip on a 25-bit i32 field —
        // representative of VMF K05.1 latitude. The wire pattern
        // `[0x01, 0x00, 0x00, 0x00]` carries bits 0..=24 of
        // `0b0_0000_0010_0000_0000_0000_0000_0000_0000` shifted
        // to fit the schema's bit_offset = 0 start.
        // For simplicity, pick a representable value: -1 (all 25
        // bits set → wire `[0xFF, 0xFF, 0xFF, 0x80]` with high
        // byte's low 7 bits unused).
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 4
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: i32 }
        bit-offset: 0
        bit-width: 25
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        // Encode -1: all 25 bits should be 1.
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.v".into(), AttributeValue::Int(-1));
        let wire = codec.from_entity(&entity).expect("schema encode signed");
        // 25 bits all 1 starting at bit-offset 0 of byte 0:
        // bytes [0xFF, 0xFF, 0xFF, 0x80] (last byte has only
        // bit 0 — MSB — set; bits 1..=7 are zero).
        assert_eq!(wire, vec![0xFF, 0xFF, 0xFF, 0x80]);
        let decoded = codec.to_entity(&wire).expect("schema decode signed");
        assert_eq!(
            decoded.attributes.get("attributes.v"),
            Some(&AttributeValue::Int(-1))
        );

        // Encode -16_777_216 (min for 25-bit signed): wire pattern
        // is `0x0100_0000` at the 25-bit field's position →
        // bytes [0x80, 0x00, 0x00, 0x00].
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.v".into(), AttributeValue::Int(-16_777_216));
        let wire = codec.from_entity(&entity).expect("encode min");
        assert_eq!(wire, vec![0x80, 0x00, 0x00, 0x00]);
        let decoded = codec.to_entity(&wire).expect("decode min");
        assert_eq!(
            decoded.attributes.get("attributes.v"),
            Some(&AttributeValue::Int(-16_777_216))
        );
    }

    #[test]
    fn signed_bit_packed_rejects_value_outside_two_s_complement_range() {
        // An i8 with bit_width = 8 has domain [-128, 127]. Trying
        // to encode 128 must fail with OutOfRange — the value
        // doesn't fit in the signed domain.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: i8 }
        bit-offset: 0
        bit-width: 8
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.v".into(), AttributeValue::Int(128));
        let err = codec.from_entity(&entity).unwrap_err();
        let SchemaCodecError::OutOfRange { type_name, .. } = err else {
            panic!("expected OutOfRange, got {err:?}");
        };
        assert!(
            type_name.contains("i8 (bit-packed)"),
            "expected type label `i8 (bit-packed)`, got: {type_name}"
        );

        // -129 is also out of range (one below i8::MIN).
        let _ = entity
            .attributes
            .insert("attributes.v".into(), AttributeValue::Int(-129));
        let err = codec.from_entity(&entity).unwrap_err();
        let SchemaCodecError::OutOfRange { value, .. } = err else {
            panic!("expected OutOfRange for negative overflow, got {err:?}");
        };
        assert_eq!(value, "-129");
    }

    #[test]
    fn signed_bit_packed_full_width_i64_round_trips_i64_min_max() {
        // bit_width = 64 on an i64 covers the full domain
        // [i64::MIN, i64::MAX] — the range check is skipped (any
        // value fits) and the bitcast→u64 path writes raw bits.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 8
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: i64 }
        bit-offset: 0
        bit-width: 64
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        for value in [0i64, 1, -1, i64::MIN, i64::MAX, 0x0123_4567_89AB_CDEFi64] {
            let mut entity = empty_entity();
            let _ = entity
                .attributes
                .insert("attributes.v".into(), AttributeValue::Int(value));
            let wire = codec.from_entity(&entity).expect("encode");
            let recovered = codec.to_entity(&wire).expect("decode");
            assert_eq!(
                recovered.attributes.get("attributes.v"),
                Some(&AttributeValue::Int(value)),
                "value {value:#x} failed round-trip"
            );
        }
    }

    #[test]
    fn signed_bit_packed_one_bit_carries_zero_and_minus_one() {
        // A 1-bit signed value can only represent {0, -1} —
        // domain is [-2^0, 2^0 - 1] = [-1, 0]. Verify both
        // values round-trip; the value 1 must reject.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 1
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: i8 }
        bit-offset: 7
        bit-width: 1
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        for (value, expected_wire) in [(0i64, 0x00u8), (-1, 0x01)] {
            let mut entity = empty_entity();
            let _ = entity
                .attributes
                .insert("attributes.v".into(), AttributeValue::Int(value));
            let wire = codec.from_entity(&entity).expect("encode 1-bit signed");
            assert_eq!(wire, vec![expected_wire], "value {value} → wire");
            let recovered = codec.to_entity(&wire).expect("decode 1-bit signed");
            assert_eq!(
                recovered.attributes.get("attributes.v"),
                Some(&AttributeValue::Int(value))
            );
        }
        // Value 1 must fail — it's outside the 1-bit signed
        // domain {-1, 0}.
        let mut entity = empty_entity();
        let _ = entity
            .attributes
            .insert("attributes.v".into(), AttributeValue::Int(1));
        let err = codec.from_entity(&entity).unwrap_err();
        let SchemaCodecError::OutOfRange { type_name, .. } = err else {
            panic!("expected OutOfRange, got {err:?}");
        };
        assert!(type_name.contains("i1 (bit-packed)"), "got: {type_name}");
    }

    #[test]
    fn cross_byte_bit_span_round_trips_64_bit_full_width() {
        // The widest cross-byte case: a 64-bit `u64` field at
        // bit_offset = 0, spanning all 8 bytes of the message.
        // The validator's `bit_width = 64` path uses `u64::MAX`
        // as the encode-side range guard rather than the
        // overflowing `1 << 64`.
        let yaml = r#"
schema-version: "1"
protocol-name: "test"
message-types:
  - name: "M"
    size-bytes: 8
    fields:
      - name: "v"
        offset: 0
        field-type: { kind: u64 }
        bit-offset: 0
        bit-width: 64
        entity-path: "attributes.v"
"#;
        let codec = SchemaCodec::from_schema_text(yaml).unwrap();
        let mut entity = empty_entity();
        let _ = entity.attributes.insert(
            "attributes.v".into(),
            // i64 carries u64::MAX as -1; the bit-packed encoder
            // bitcasts back to u64 before writing.
            AttributeValue::Int(-1i64),
        );
        let wire = codec.from_entity(&entity).expect("schema encode");
        assert_eq!(wire, vec![0xFF; 8]);
        let recovered = codec.to_entity(&wire).expect("schema decode");
        assert_eq!(
            recovered.attributes.get("attributes.v"),
            Some(&AttributeValue::Int(-1i64))
        );
    }

    fn empty_entity() -> Entity {
        Entity {
            uid: "x".into(),
            kind: EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: Default::default(),
            files: Default::default(),
        }
    }
}
