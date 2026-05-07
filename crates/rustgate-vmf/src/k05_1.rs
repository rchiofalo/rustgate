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

use crate::bitstream::{BitReader, BitWriter};
use crate::error::VmfError;

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
    pub fn decode(reader: &mut BitReader<'_>) -> Result<Self, VmfError> {
        let reporting_urn = reader.read_bits(24, "k05_1.reporting_urn")?;
        let lat_raw = reader.read_bits_signed(LAT_BITS, "k05_1.latitude")?;
        let lon_raw = reader.read_bits_signed(LON_BITS, "k05_1.longitude")?;
        let latitude_deg = decode_latitude(lat_raw)?;
        let longitude_deg = decode_longitude(lon_raw)?;

        let altitude_m = if reader.read_bit("k05_1.altitude_fpi")? {
            let raw = reader.read_bits_signed(16, "k05_1.altitude")?;
            Some(raw as i16)
        } else {
            None
        };
        let speed_m_per_s = if reader.read_bit("k05_1.speed_fpi")? {
            let raw = reader.read_bits(SPEED_BITS, "k05_1.speed")?;
            Some(f64::from(raw) * SPEED_LSB_M_PER_S)
        } else {
            None
        };
        let course_deg = if reader.read_bit("k05_1.course_fpi")? {
            let raw = reader.read_bits(COURSE_BITS, "k05_1.course")?;
            Some(f64::from(raw) * 360.0 / COURSE_DENOM)
        } else {
            None
        };
        let unit_identifier = if reader.read_bit("k05_1.unit_id_fpi")? {
            // Read 7 bytes one byte at a time to tolerate a non-byte-
            // aligned cursor — the FPI bit above almost always leaves
            // the cursor on a non-byte boundary, so a `read_bytes`
            // call would surface a misalignment error even on
            // well-formed input.
            let mut raw = [0u8; UNIT_ID_LEN];
            for slot in raw.iter_mut() {
                *slot = reader.read_bits(8, "k05_1.unit_id")? as u8;
            }
            // Sanitize: non-printable bytes become '?' so an attacker
            // cannot ship CR/LF or terminal control codes through the
            // operator dashboard.
            let mut out = String::with_capacity(UNIT_ID_LEN);
            for &b in raw.iter() {
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
