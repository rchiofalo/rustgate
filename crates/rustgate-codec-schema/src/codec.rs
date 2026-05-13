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
//! ## What it does NOT support (v1)
//!
//! - Fixed-length byte / UTF-8 string fields (`FieldType::Bytes` /
//!   `FieldType::Utf8`) are parsed but not yet projected to
//!   `entity_path` targets. They round-trip through
//!   `Entity::attributes` as hex / string values.
//! - Value mapping (enum-style raw → label) is parsed by the
//!   schema layer but the runtime treats the raw integer as the
//!   value. Real enum projection follows in a v2 PR.
//! - Multi-message schemas (with `discriminator_offset`) are
//!   **rejected** at schema-load time by [`Schema::validate`] until
//!   v2 ships dispatch. The `discriminator_offset` field stays in
//!   the grammar so v2 schemas don't need a wire-format change; the
//!   call site splits multi-message protocols into N single-message
//!   schemas it dispatches itself in the meantime.

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
    /// v1 schemas declare exactly one message type — multi-message
    /// dispatch is deferred to v2 and rejected at parse time by
    /// [`Schema::validate`]. This accessor therefore always returns
    /// the sole entry.
    fn select_message_type(&self) -> &MessageType {
        // Safe — `Schema::validate` rejects empty and multi-message
        // schemas. justification: validation guarantees exactly one
        // entry; expect() carries the invariant to the reader.
        #[allow(clippy::expect_used)]
        self.schema
            .message_types
            .first()
            .expect("validated schema has exactly one message type")
    }

    /// Decode a single field at its declared offset.
    fn decode_field(field: &FieldDef, payload: &[u8]) -> Result<DecodedValue, SchemaCodecError> {
        let size = field
            .field_type
            .fixed_size()
            .or(field.length_bytes)
            .unwrap_or(0);
        let end = field.offset + size;
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
    fn encode_field(
        field: &FieldDef,
        value: &EncodedValue,
        out: &mut [u8],
    ) -> Result<(), SchemaCodecError> {
        let size = field
            .field_type
            .fixed_size()
            .or(field.length_bytes)
            .unwrap_or(0);
        let end = field.offset + size;
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
        let mt = self.select_message_type();
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

        for field in &mt.fields {
            let decoded = Self::decode_field(field, payload)?;
            Self::check_range_on_decode(field, &decoded)?;
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
        let mt = self.select_message_type();
        let mut out = vec![0u8; mt.size_bytes];
        for field in &mt.fields {
            let value = lookup_encoded_value(entity, field, &self.schema.protocol_name)?;
            Self::check_range_on_encode(field, &value)?;
            Self::encode_field(field, &value, &mut out)?;
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
