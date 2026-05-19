// Copyright © 2026 Roberto Chiofalo.

//! K05.1 Position Report — VMF's Position Location Information (PLI)
//! message.
//!
//! The K05.1 Position Report is the Army/USMC equivalent of the CoT
//! `<event type="a-f-G-U-C">` PLI event: every Blue Force Tracker
//! position update on a SINCGARS-ASIP or EPLRS radio is a K05.1.
//!
//! # Bit layout (MVP scope)
//!
//! Fields are bit-packed end-to-end and gated by Field Presence
//! Indicators (FPIs). The MVP carries the strictly-required subset:
//!
//! | Field                        | Bits | Notes                                                              |
//! |------------------------------|------|--------------------------------------------------------------------|
//! | Reporting unit URN           | 24   | The unit whose position this report describes (often == header originator) |
//! | Latitude                     | 25   | Two's-complement, LSB ≈ 90 / 2^24 deg → ≈ 5.4 × 10⁻⁶ deg          |
//! | Longitude                    | 26   | Two's-complement, LSB ≈ 180 / 2^25 deg → ≈ 5.4 × 10⁻⁶ deg         |
//! | Altitude FPI                 | 1    | When 1, altitude in metres follows                                 |
//! | Altitude (m)                 | 16   | Two's-complement signed integer metres                             |
//! | Speed FPI                    | 1    | When 1, ground speed in 0.1 m/s units follows                      |
//! | Speed (0.1 m/s)              | 12   | Unsigned                                                           |
//! | Course FPI                   | 1    | When 1, course in `360 / 2^9 ≈ 0.703°` units follows               |
//! | Course (units)               | 9    | Unsigned, 0..=511 mapped to `[0, 360)` deg                         |
//! | Unit identifier FPI          | 1    | When 1, a free-form 7-byte identifier follows                      |
//! | Unit identifier              | 56   | 7 ASCII bytes                                                      |
//!
//! # Out of scope for MVP
//!
//! - Position quality / accuracy fields (carried under the
//!   `vmf.k05_1.*` Entity attribute namespace by encoder consumers
//!   when present, but not first-class on `K051PositionReport`).
//! - Multi-position fan-out (FRI repetition). MIL-STD-6017 K05.1 may
//!   carry multiple position updates for a sub-unit; the MVP decodes
//!   only the first one and surfaces the count via the
//!   `record_count` attribute on the [`crate::codec::VmfCodec`]
//!   integration layer.

use std::sync::OnceLock;

use rustgate_codec_schema::{SchemaCodec, bitstream};
use rustgate_core::entity::{AttributeValue, EntityCodec};

use crate::bitstream::{BitReader, BitWriter};
use crate::error::VmfError;

/// Embedded body schema. Parsed once on first use by
/// [`schema_codec`] — the YAML is a `const &str` baked in at
/// compile time and the resulting `SchemaCodec` is immutable, so
/// re-parsing on every decode would be CPU waste.
const SCHEMA_YAML: &str = include_str!("../schemas/k05_1.yaml");

/// Attribute key prefix the schema runtime produces for K05.1
/// fields (no `entity-path` declared, so every field goes under
/// `schema.<protocol-name>.<field>`).
const ATTR_PREFIX: &str = "schema.vmf.k05_1.";

/// Cached [`SchemaCodec`] built from the embedded K05.1 body
/// schema. `OnceLock` is the workspace-standard pattern (banned:
/// `once_cell::sync::Lazy`).
fn schema_codec() -> &'static SchemaCodec {
    static CODEC: OnceLock<SchemaCodec> = OnceLock::new();
    CODEC.get_or_init(|| {
        // justification: the embedded schema is validated at workspace-
        // test time by `tests/schema_parity_k05_1.rs` — a parse failure
        // here would mean an invalid YAML committed to `schemas/`,
        // which CI catches before any caller reaches this code path.
        // Falling back via `Result` would force every callsite into
        // error-handling boilerplate for an invariant the build
        // already guarantees.
        #[allow(clippy::expect_used)]
        SchemaCodec::from_schema_text(SCHEMA_YAML)
            .expect("embedded k05_1.yaml schema must parse and validate")
    })
}

/// Latitude/longitude bit widths and LSB scaling. The 25/26 layout
/// pinned here is the most common MIL-STD-6017 form; some VMF
/// dialects use 24/25 (older M22/M23 variants) — those decode under
/// `VmfMessage::Unknown` rather than misparsing as K05.1.
const LAT_BITS: u32 = 25;
const LON_BITS: u32 = 26;
const LAT_SCALE_DENOM: f64 = (1u64 << 24) as f64;
const LON_SCALE_DENOM: f64 = (1u64 << 25) as f64;

/// Course units: 9 bits map to `[0, 360)` degrees.
const COURSE_BITS: u32 = 9;
const COURSE_DENOM: f64 = (1u32 << 9) as f64;

/// Speed units: 12 bits in 0.1 m/s.
const SPEED_BITS: u32 = 12;
const SPEED_LSB_M_PER_S: f64 = 0.1;

/// Unit identifier: 7 ASCII bytes.
const UNIT_ID_LEN: usize = 7;

/// K05.1 Position Report body.
///
/// Round-trip discipline: the same instance encodes and decodes
/// bit-identically through [`Self::encode`] / [`Self::decode`]. Across
/// floating-point latitude/longitude the round-trip is exact to the
/// LSB of the wire encoding (≈ 60 cm at the equator).
#[derive(Debug, Clone, PartialEq)]
pub struct K051PositionReport {
    /// URN (unit reference number) of the unit whose position this
    /// report describes. Often equal to the header originator but
    /// distinguishable when the radio is reporting a slaved
    /// vehicle/sub-unit position.
    pub reporting_urn: u32,
    /// WGS-84 latitude in decimal degrees, `[-90, 90]`.
    pub latitude_deg: f64,
    /// WGS-84 longitude in decimal degrees, `[-180, 180]`.
    pub longitude_deg: f64,
    /// Altitude in metres (MSL on the wire — the codec preserves the
    /// raw value; the integration layer converts to HAE if needed).
    /// `None` when the reporting unit omitted altitude (e.g. ground
    /// dismount with no GPS altitude lock).
    pub altitude_m: Option<i16>,
    /// Ground speed in metres per second, non-negative. `None` when
    /// the reporting unit is stationary or omitted speed.
    pub speed_m_per_s: Option<f64>,
    /// Course over ground in degrees clockwise from true north,
    /// `[0, 360)`. `None` when the reporting unit is stationary or
    /// omitted course.
    pub course_deg: Option<f64>,
    /// Free-form unit callsign / identifier. Up to 7 ASCII bytes.
    /// `None` when the reporting unit omitted it. ASCII characters
    /// outside `[0x20, 0x7E]` are replaced with `'?'` on decode so a
    /// hostile sender cannot inject control bytes into operator
    /// dashboards.
    pub unit_identifier: Option<String>,
}

impl K051PositionReport {
    /// Construct a minimal K05.1 with the required position fields
    /// only; optional fields default to `None`.
    #[must_use]
    pub fn new(reporting_urn: u32, latitude_deg: f64, longitude_deg: f64) -> Self {
        Self {
            reporting_urn,
            latitude_deg,
            longitude_deg,
            altitude_m: None,
            speed_m_per_s: None,
            course_deg: None,
            unit_identifier: None,
        }
    }

    /// Decode a K05.1 body from a bit reader positioned at the first
    /// bit of the body. The header is decoded separately (see
    /// [`crate::header::VmfHeader::decode`]).
    ///
    /// **Schema-driven decode (since I2)**: the bit-stream parse is
    /// delegated to the [`SchemaCodec`] built from
    /// `schemas/k05_1.yaml`. The wrapper retains range guards
    /// (lat ∈ `[-90, 90]`, lon ∈ `[-180, 180]`), calibration math
    /// (raw → degrees / m·s⁻¹), and `unit_identifier` sanitization
    /// (non-printable ASCII → `?`, trailing padding trimmed). The
    /// schema runtime handles the bit-cursor + FPI cascade via v5
    /// variable-shift `present-if`.
    pub fn decode(reader: &mut BitReader<'_>) -> Result<Self, VmfError> {
        // Extract the body slice from the BitReader's current
        // position. The header decode left the cursor at the
        // body's first bit; we slice the underlying payload from
        // that byte forward, then shift_left by the bit-offset so
        // the body's first bit lands at byte 0 bit 0 of a new
        // buffer (the schema runtime's contract).
        let body_start_bit = reader.position_bits();
        let body_byte_offset = body_start_bit / 8;
        let body_bit_offset = (body_start_bit % 8) as u8;
        let payload = reader.payload();
        let remaining = payload.get(body_byte_offset..).ok_or(VmfError::Truncated {
            field: "k05_1.body",
            needed_bits: 79,
        })?;
        let body_bytes = bitstream::shift_left(remaining, body_bit_offset);

        // Run the schema decode. `PayloadTooShort` from the schema
        // runtime maps to `VmfError::Truncated` so existing callers
        // matching on that variant keep working; everything else
        // surfaces as `InvalidValue` with the schema error's
        // display string.
        let entity = schema_codec().to_entity(&body_bytes).map_err(|e| match e {
            rustgate_codec_schema::error::SchemaCodecError::PayloadTooShort {
                required, ..
            } => VmfError::Truncated {
                field: "k05_1.body",
                needed_bits: u32::try_from(required.saturating_mul(8)).unwrap_or(u32::MAX),
            },
            other => VmfError::InvalidValue {
                field: "k05_1.schema",
                detail: other.to_string(),
            },
        })?;

        // Project the schema attributes back to typed fields. Each
        // helper reads `schema.vmf.k05_1.<name>` and applies the
        // calibration / sanitization the wrapper layer owns.
        let reporting_urn = read_u32_attr(&entity, "reporting_urn")?;
        let lat_raw = read_i32_attr(&entity, "latitude")?;
        let lon_raw = read_i32_attr(&entity, "longitude")?;
        let latitude_deg = decode_latitude(lat_raw)?;
        let longitude_deg = decode_longitude(lon_raw)?;

        let altitude_fpi = read_u8_attr(&entity, "altitude_fpi")?;
        let altitude_m = if altitude_fpi == 1 {
            // i32 raw extracted by schema; cast back to i16 — schema
            // already constrained to 16-bit signed range.
            let raw = read_i32_attr(&entity, "altitude")?;
            Some(raw as i16)
        } else {
            None
        };
        let speed_fpi = read_u8_attr(&entity, "speed_fpi")?;
        let speed_m_per_s = if speed_fpi == 1 {
            let raw = read_u32_attr(&entity, "speed")?;
            Some(f64::from(raw) * SPEED_LSB_M_PER_S)
        } else {
            None
        };
        let course_fpi = read_u8_attr(&entity, "course_fpi")?;
        let course_deg = if course_fpi == 1 {
            let raw = read_u32_attr(&entity, "course")?;
            Some(f64::from(raw) * 360.0 / COURSE_DENOM)
        } else {
            None
        };
        let unit_id_fpi = read_u8_attr(&entity, "unit_id_fpi")?;
        let unit_identifier = if unit_id_fpi == 1 {
            // The schema declares `unit_identifier` as a 56-bit u64
            // (bit-packed integer — the schema grammar's bit-packing
            // path only carries integer types). Decompose MSB-first
            // back to the 7 wire bytes; this matches how the
            // hand-rolled encoder writes them.
            let raw = read_u64_attr(&entity, "unit_identifier")?;
            let raw_bytes: [u8; UNIT_ID_LEN] = [
                ((raw >> 48) & 0xFF) as u8,
                ((raw >> 40) & 0xFF) as u8,
                ((raw >> 32) & 0xFF) as u8,
                ((raw >> 24) & 0xFF) as u8,
                ((raw >> 16) & 0xFF) as u8,
                ((raw >> 8) & 0xFF) as u8,
                (raw & 0xFF) as u8,
            ];
            // Sanitize: non-printable bytes become '?' so a hostile
            // sender cannot inject CR/LF / terminal control codes
            // through the operator dashboard.
            let mut out = String::with_capacity(UNIT_ID_LEN);
            for &b in raw_bytes.iter() {
                if (0x20..=0x7E).contains(&b) {
                    out.push(b as char);
                } else {
                    out.push('?');
                }
            }
            // Trim trailing whitespace / null padding to match the
            // common convention on tactical radios.
            Some(out.trim_end_matches([' ', '\0', '?']).to_string())
        } else {
            None
        };

        // Compute bits consumed and advance the reader so downstream
        // callers see the cursor at the right position. v5
        // variable-shift `present-if` collapses absent fields on the
        // wire, so the consumed-bit count is the SUM of always-present
        // bits plus the conditional contributions.
        let bits_consumed = 24  // reporting_urn
            + LAT_BITS as usize
            + LON_BITS as usize
            + 1 + if altitude_m.is_some() { 16 } else { 0 }
            + 1 + if speed_m_per_s.is_some() { SPEED_BITS as usize } else { 0 }
            + 1 + if course_deg.is_some() { COURSE_BITS as usize } else { 0 }
            + 1 + if unit_identifier.is_some() { UNIT_ID_LEN * 8 } else { 0 };
        reader.advance_bits(bits_consumed)?;

        Ok(Self {
            reporting_urn,
            latitude_deg,
            longitude_deg,
            altitude_m,
            speed_m_per_s,
            course_deg,
            unit_identifier,
        })
    }

    /// Encode this position report into the supplied bit writer.
    pub fn encode(&self, writer: &mut BitWriter) -> Result<(), VmfError> {
        // URN bounds: 24-bit envelope.
        if self.reporting_urn > 0x00FF_FFFF {
            return Err(VmfError::EncodeOverflow {
                field: "k05_1.reporting_urn",
                detail: format!("URN 0x{:X} exceeds 24-bit envelope", self.reporting_urn),
            });
        }
        writer.write_bits(self.reporting_urn, 24, "k05_1.reporting_urn")?;

        // Position: validate envelope and quantize. The raw bit field
        // is signed two's-complement; saturate at the extremes so a
        // legitimate value at the edge of the float range cannot
        // overflow the bit width.
        let lat_raw = encode_latitude(self.latitude_deg)?;
        let lon_raw = encode_longitude(self.longitude_deg)?;
        writer.write_bits_signed(lat_raw, LAT_BITS, "k05_1.latitude")?;
        writer.write_bits_signed(lon_raw, LON_BITS, "k05_1.longitude")?;

        match self.altitude_m {
            Some(alt) => {
                writer.write_bit(true, "k05_1.altitude_fpi")?;
                writer.write_bits_signed(i32::from(alt), 16, "k05_1.altitude")?;
            }
            None => writer.write_bit(false, "k05_1.altitude_fpi")?,
        }
        match self.speed_m_per_s {
            Some(speed) => {
                writer.write_bit(true, "k05_1.speed_fpi")?;
                if !speed.is_finite() || speed < 0.0 {
                    return Err(VmfError::EncodeOverflow {
                        field: "k05_1.speed",
                        detail: format!("speed {speed} is non-finite or negative"),
                    });
                }
                let raw = (speed / SPEED_LSB_M_PER_S).round();
                let max = f64::from((1u32 << SPEED_BITS) - 1);
                let raw_u = raw.clamp(0.0, max) as u32;
                writer.write_bits(raw_u, SPEED_BITS, "k05_1.speed")?;
            }
            None => writer.write_bit(false, "k05_1.speed_fpi")?,
        }
        match self.course_deg {
            Some(course) => {
                writer.write_bit(true, "k05_1.course_fpi")?;
                if !course.is_finite() {
                    return Err(VmfError::EncodeOverflow {
                        field: "k05_1.course",
                        detail: format!("course {course} is non-finite"),
                    });
                }
                let mut normalised = course % 360.0;
                if normalised < 0.0 {
                    normalised += 360.0;
                }
                let raw = (normalised * COURSE_DENOM / 360.0).round();
                let max = f64::from((1u32 << COURSE_BITS) - 1);
                let raw_u = raw.clamp(0.0, max) as u32;
                writer.write_bits(raw_u, COURSE_BITS, "k05_1.course")?;
            }
            None => writer.write_bit(false, "k05_1.course_fpi")?,
        }
        match &self.unit_identifier {
            Some(id) => {
                writer.write_bit(true, "k05_1.unit_id_fpi")?;
                let mut out = [0x20u8; UNIT_ID_LEN]; // ASCII space pad
                for (i, &b) in id.as_bytes().iter().take(UNIT_ID_LEN).enumerate() {
                    let safe = if (0x20..=0x7E).contains(&b) { b } else { b'?' };
                    if let Some(slot) = out.get_mut(i) {
                        *slot = safe;
                    }
                }
                // Write byte-by-byte at the bit level rather than via
                // `write_bytes`, which pads to a byte boundary — the
                // FPI immediately preceding this field almost always
                // leaves the cursor on a non-byte boundary, and the
                // wire format expects the identifier to follow with no
                // pad bits between.
                for &byte in out.iter() {
                    writer.write_bits(u32::from(byte), 8, "k05_1.unit_id")?;
                }
            }
            None => writer.write_bit(false, "k05_1.unit_id_fpi")?,
        }
        Ok(())
    }
}

/// Read a `u32`-typed attribute from the schema-decoded entity.
/// The schema runtime projects every integer field through
/// [`AttributeValue::Int`] (`i64`); cast back to `u32` with a
/// bounded check so a malformed schema (or a future field-width
/// change) surfaces as a typed error rather than a silent
/// truncation.
fn read_u32_attr(
    entity: &rustgate_core::entity::Entity,
    short_name: &'static str,
) -> Result<u32, VmfError> {
    let key = format!("{ATTR_PREFIX}{short_name}");
    let av = entity.attributes.get(&key).ok_or(VmfError::InvalidValue {
        field: short_name_to_static(short_name),
        detail: format!("schema decode missing attribute `{key}`"),
    })?;
    match av {
        AttributeValue::Int(v) if *v >= 0 && *v <= i64::from(u32::MAX) => {
            // justification: the guard above constrains the value to
            // the u32 range; the cast is exact.
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            Ok(*v as u32)
        }
        AttributeValue::Int(v) => Err(VmfError::InvalidValue {
            field: short_name_to_static(short_name),
            detail: format!("value {v} does not fit in u32"),
        }),
        other => Err(VmfError::InvalidValue {
            field: short_name_to_static(short_name),
            detail: format!("expected Int attribute, got {other:?}"),
        }),
    }
}

/// Read an `i32`-typed attribute. The schema's signed bit-packed
/// fields (latitude, longitude, altitude) project as
/// [`AttributeValue::Int`] (`i64`); cast back with a bounded
/// check that catches a misconfigured schema.
fn read_i32_attr(
    entity: &rustgate_core::entity::Entity,
    short_name: &'static str,
) -> Result<i32, VmfError> {
    let key = format!("{ATTR_PREFIX}{short_name}");
    let av = entity.attributes.get(&key).ok_or(VmfError::InvalidValue {
        field: short_name_to_static(short_name),
        detail: format!("schema decode missing attribute `{key}`"),
    })?;
    match av {
        AttributeValue::Int(v) if *v >= i64::from(i32::MIN) && *v <= i64::from(i32::MAX) => {
            // justification: bounded by the guard above.
            #[allow(clippy::cast_possible_truncation)]
            Ok(*v as i32)
        }
        AttributeValue::Int(v) => Err(VmfError::InvalidValue {
            field: short_name_to_static(short_name),
            detail: format!("value {v} does not fit in i32"),
        }),
        other => Err(VmfError::InvalidValue {
            field: short_name_to_static(short_name),
            detail: format!("expected Int attribute, got {other:?}"),
        }),
    }
}

/// Read a `u8`-typed attribute (used for the FPI flag bits).
fn read_u8_attr(
    entity: &rustgate_core::entity::Entity,
    short_name: &'static str,
) -> Result<u8, VmfError> {
    let key = format!("{ATTR_PREFIX}{short_name}");
    let av = entity.attributes.get(&key).ok_or(VmfError::InvalidValue {
        field: short_name_to_static(short_name),
        detail: format!("schema decode missing attribute `{key}`"),
    })?;
    match av {
        AttributeValue::Int(v) if *v >= 0 && *v <= i64::from(u8::MAX) => {
            // justification: bounded by the guard above.
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            Ok(*v as u8)
        }
        AttributeValue::Int(v) => Err(VmfError::InvalidValue {
            field: short_name_to_static(short_name),
            detail: format!("value {v} does not fit in u8"),
        }),
        other => Err(VmfError::InvalidValue {
            field: short_name_to_static(short_name),
            detail: format!("expected Int attribute, got {other:?}"),
        }),
    }
}

/// Read a `u64`-typed attribute (used for the 56-bit
/// `unit_identifier` field — the schema runtime carries it as
/// a bit-packed u64 since the grammar's bit-packing path is
/// integer-only). Negative values surface from i64 → u64
/// bit-casts the validator allows; we mask the high bits to the
/// declared 56-bit width to be safe.
fn read_u64_attr(
    entity: &rustgate_core::entity::Entity,
    short_name: &'static str,
) -> Result<u64, VmfError> {
    let key = format!("{ATTR_PREFIX}{short_name}");
    let av = entity.attributes.get(&key).ok_or(VmfError::InvalidValue {
        field: short_name_to_static(short_name),
        detail: format!("schema decode missing attribute `{key}`"),
    })?;
    match av {
        AttributeValue::Int(v) => {
            // justification: bit-cast — every i64 maps to a unique
            // u64. The caller masks to the schema's declared
            // bit-width before consuming, so high bits don't leak.
            #[allow(clippy::cast_sign_loss)]
            let raw = *v as u64;
            Ok(raw)
        }
        other => Err(VmfError::InvalidValue {
            field: short_name_to_static(short_name),
            detail: format!("expected Int attribute, got {other:?}"),
        }),
    }
}

/// Map a short field name to a `&'static str` for `VmfError`'s
/// `field: &'static str` discipline. The schema's field names are
/// stable across the schema YAML and the production code so an
/// inline match arm is the right shape.
fn short_name_to_static(name: &str) -> &'static str {
    match name {
        "reporting_urn" => "k05_1.reporting_urn",
        "latitude" => "k05_1.latitude",
        "longitude" => "k05_1.longitude",
        "altitude_fpi" => "k05_1.altitude_fpi",
        "altitude" => "k05_1.altitude",
        "speed_fpi" => "k05_1.speed_fpi",
        "speed" => "k05_1.speed",
        "course_fpi" => "k05_1.course_fpi",
        "course" => "k05_1.course",
        "unit_id_fpi" => "k05_1.unit_id_fpi",
        "unit_identifier" => "k05_1.unit_id",
        _ => "k05_1.unknown",
    }
}

/// Decode the wire-format latitude raw integer into decimal degrees.
fn decode_latitude(raw: i32) -> Result<f64, VmfError> {
    let deg = f64::from(raw) * 90.0 / LAT_SCALE_DENOM;
    if !(-90.0..=90.0).contains(&deg) {
        // Should be unreachable for a well-formed wire frame because
        // the bit width caps the magnitude — but a value at the very
        // edge could rounding-error past the boundary. Clamp rather
        // than reject so a benign rounding artefact at ±90.0 does
        // not surface as an InvalidValue.
        return Ok(deg.clamp(-90.0, 90.0));
    }
    Ok(deg)
}

/// Decode the wire-format longitude raw integer into decimal degrees.
fn decode_longitude(raw: i32) -> Result<f64, VmfError> {
    let deg = f64::from(raw) * 180.0 / LON_SCALE_DENOM;
    if !(-180.0..=180.0).contains(&deg) {
        return Ok(deg.clamp(-180.0, 180.0));
    }
    Ok(deg)
}

/// Encode decimal-degree latitude into the wire-format raw integer.
fn encode_latitude(deg: f64) -> Result<i32, VmfError> {
    if !deg.is_finite() {
        return Err(VmfError::EncodeOverflow {
            field: "k05_1.latitude",
            detail: format!("non-finite value {deg}"),
        });
    }
    if !(-90.0..=90.0).contains(&deg) {
        return Err(VmfError::EncodeOverflow {
            field: "k05_1.latitude",
            detail: format!("value {deg} outside [-90, 90]"),
        });
    }
    let raw = (deg * LAT_SCALE_DENOM / 90.0).round();
    let max = f64::from((1i32 << (LAT_BITS - 1)) - 1);
    let min = -f64::from(1i32 << (LAT_BITS - 1));
    Ok(raw.clamp(min, max) as i32)
}

/// Encode decimal-degree longitude into the wire-format raw integer.
fn encode_longitude(deg: f64) -> Result<i32, VmfError> {
    if !deg.is_finite() {
        return Err(VmfError::EncodeOverflow {
            field: "k05_1.longitude",
            detail: format!("non-finite value {deg}"),
        });
    }
    if !(-180.0..=180.0).contains(&deg) {
        return Err(VmfError::EncodeOverflow {
            field: "k05_1.longitude",
            detail: format!("value {deg} outside [-180, 180]"),
        });
    }
    let raw = (deg * LON_SCALE_DENOM / 180.0).round();
    let max = f64::from((1i32 << (LON_BITS - 1)) - 1);
    let min = -f64::from(1i32 << (LON_BITS - 1));
    Ok(raw.clamp(min, max) as i32)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn position_round_trips_minimal() {
        let body = K051PositionReport::new(0x12_3456, 38.5, -77.0);
        let mut w = BitWriter::new();
        body.encode(&mut w).unwrap();
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        let decoded = K051PositionReport::decode(&mut r).unwrap();
        assert_eq!(decoded.reporting_urn, 0x12_3456);
        assert!((decoded.latitude_deg - 38.5).abs() < 1e-4);
        assert!((decoded.longitude_deg + 77.0).abs() < 1e-4);
        assert!(decoded.altitude_m.is_none());
        assert!(decoded.speed_m_per_s.is_none());
        assert!(decoded.course_deg.is_none());
        assert!(decoded.unit_identifier.is_none());
    }

    #[test]
    fn position_round_trips_full() {
        let body = K051PositionReport {
            reporting_urn: 0xAB_CDEF,
            latitude_deg: 51.5,
            longitude_deg: -0.1,
            altitude_m: Some(150),
            speed_m_per_s: Some(15.5),
            course_deg: Some(89.4),
            unit_identifier: Some("BFTC123".into()),
        };
        let mut w = BitWriter::new();
        body.encode(&mut w).unwrap();
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        let decoded = K051PositionReport::decode(&mut r).unwrap();
        assert_eq!(decoded.reporting_urn, body.reporting_urn);
        assert!((decoded.latitude_deg - body.latitude_deg).abs() < 1e-4);
        assert!((decoded.longitude_deg - body.longitude_deg).abs() < 1e-4);
        assert_eq!(decoded.altitude_m, body.altitude_m);
        let s1 = body.speed_m_per_s.unwrap();
        let s2 = decoded.speed_m_per_s.unwrap();
        assert!((s1 - s2).abs() < SPEED_LSB_M_PER_S);
        let c1 = body.course_deg.unwrap();
        let c2 = decoded.course_deg.unwrap();
        assert!((c1 - c2).abs() < 360.0 / COURSE_DENOM);
        assert_eq!(decoded.unit_identifier.as_deref(), Some("BFTC123"));
    }

    #[test]
    fn position_rejects_out_of_range_lat_on_encode() {
        let body = K051PositionReport::new(1, 91.0, 0.0);
        let mut w = BitWriter::new();
        let err = body.encode(&mut w).unwrap_err();
        assert!(matches!(
            err,
            VmfError::EncodeOverflow {
                field: "k05_1.latitude",
                ..
            }
        ));
    }

    #[test]
    fn position_rejects_out_of_range_lon_on_encode() {
        let body = K051PositionReport::new(1, 0.0, 181.0);
        let mut w = BitWriter::new();
        let err = body.encode(&mut w).unwrap_err();
        assert!(matches!(
            err,
            VmfError::EncodeOverflow {
                field: "k05_1.longitude",
                ..
            }
        ));
    }

    #[test]
    fn position_rejects_oversize_urn_on_encode() {
        let body = K051PositionReport::new(0x0100_0000, 0.0, 0.0);
        let mut w = BitWriter::new();
        let err = body.encode(&mut w).unwrap_err();
        assert!(matches!(
            err,
            VmfError::EncodeOverflow {
                field: "k05_1.reporting_urn",
                ..
            }
        ));
    }

    #[test]
    fn position_normalises_negative_course() {
        let body = K051PositionReport {
            reporting_urn: 1,
            latitude_deg: 0.0,
            longitude_deg: 0.0,
            altitude_m: None,
            speed_m_per_s: None,
            course_deg: Some(-90.0), // → 270.0 after normalisation
            unit_identifier: None,
        };
        let mut w = BitWriter::new();
        body.encode(&mut w).unwrap();
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        let decoded = K051PositionReport::decode(&mut r).unwrap();
        let c = decoded.course_deg.unwrap();
        assert!((c - 270.0).abs() < 360.0 / COURSE_DENOM, "decoded={c}");
    }

    #[test]
    fn position_unit_id_strips_control_bytes() {
        // Hand-craft a body that smuggles a CR/LF into the unit-id
        // slot. The decoder must replace control bytes with '?' so
        // they cannot reach the operator dashboard.
        let body = K051PositionReport {
            reporting_urn: 1,
            latitude_deg: 0.0,
            longitude_deg: 0.0,
            altitude_m: None,
            speed_m_per_s: None,
            course_deg: None,
            unit_identifier: Some("AB\r\nCDE".into()),
        };
        let mut w = BitWriter::new();
        body.encode(&mut w).unwrap();
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        let decoded = K051PositionReport::decode(&mut r).unwrap();
        let id = decoded.unit_identifier.unwrap();
        assert!(!id.contains('\r'));
        assert!(!id.contains('\n'));
    }

    #[test]
    fn position_truncation_returns_typed_error() {
        // Only 3 bytes of body — far less than the 24-bit URN + 51-bit
        // lat/lon header needs.
        let bytes = [0x00u8, 0x00, 0x00];
        let mut r = BitReader::new(&bytes);
        let err = K051PositionReport::decode(&mut r).unwrap_err();
        assert!(matches!(err, VmfError::Truncated { .. }));
    }
}
