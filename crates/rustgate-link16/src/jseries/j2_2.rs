// Copyright © 2026 Roberto Chiofalo.

//! J2.2 — Air Track (MIL-STD-6016 message label 2, sublabel 2).
//!
//! J2.2 is the canonical Link 16 message for the "where is the
//! fighter / how fast is it going / what is its IFF status" payload.
//! Every Air Operations Center, AWACS aircraft, and tactical command
//! post on a Link 16 net broadcasts and consumes J2.2 — and JREAP-C
//! gateways tunnel the same J2.2 payload to coalition systems
//! reachable only over IP.
//!
//! # Wire layout (MVP byte-aligned subset)
//!
//! | Offset | Size | Field                | Notes                                                            |
//! |--------|------|----------------------|------------------------------------------------------------------|
//! | 0      | 1    | label                | `0x22` (J2.2 label/sublabel packed)                              |
//! | 1      | 4    | track_number         | `u32` big-endian; STN (Source Track Number) per MIL-STD-6016     |
//! | 5      | 4    | latitude_micro_deg   | `i32` big-endian, microdegrees north (negative = south)          |
//! | 9      | 4    | longitude_micro_deg  | `i32` big-endian, microdegrees east (negative = west)            |
//! | 13     | 4    | altitude_m           | `i32` big-endian, metres above WGS-84 ellipsoid                  |
//! | 17     | 1    | platform_type        | See [`PlatformType`]                                             |
//! | 18     | 1    | iff_status_byte      | Packed IFF flags; raw byte preserved in [`IffCodes::status_byte`]|
//! | 19     | 2    | iff_mode_3_code      | `u16` big-endian, octal-encoded ATC squawk                       |
//! | 21     | 4    | speed_cm_s           | `u32` big-endian, ground speed in centimetres per second         |
//! | 25     | 2    | course_centideg      | `u16` big-endian, course in centidegrees `[0, 36000)`            |
//! | 27     | 2    | climb_rate_dm_s      | `i16` big-endian, climb rate in decimetres per second            |
//!
//! Total body length = **29 bytes**. The byte-aligned form keeps the
//! parser simple and reviewable; a follow-up PR can layer the bit-
//! packed MIL-STD-6016 form behind the same struct shape if a
//! deployment needs the wire-level form.
//!
//! # Spec assumption (MVP)
//!
//! MIL-STD-6016 is restricted-distribution. Field choices and widths
//! above are the layered subset published in open-literature
//! interoperability guides (NATO STANAG 5616 cross-references, AFRL
//! technical reports, vendor integration manuals for the open-source
//! SIMPLE / JREAP test harnesses). Where open literature leaves a
//! field ambiguous, the codec uses the most common width and
//! documents the choice inline. A reviewer with access to the closed
//! spec can correct individual widths without touching the codec
//! scaffolding.

use crate::error::Link16Error;

/// J2.2 Air Track body in the canonical typed form.
///
/// Decoded from / encoded to the wire shape via [`Self::decode`] and
/// [`Self::encode_into`]. The `latitude_micro_deg` /
/// `longitude_micro_deg` integer encoding gives roughly 1.1 cm
/// precision globally — finer than the J2.2 source data (a fighter
/// INS / GPS hybrid is good to a metre or so), so the codec can
/// round-trip a real position carry without precision loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct J2_2AirTrack {
    /// Source Track Number (STN). Stable identifier the originating
    /// platform assigns to the track for the lifetime of the contact.
    pub track_number: u32,
    /// Latitude in microdegrees, north positive. Range
    /// `[-90_000_000, 90_000_000]`; the codec validates this on
    /// decode and on encode.
    pub latitude_micro_deg: i32,
    /// Longitude in microdegrees, east positive. Range
    /// `[-180_000_000, 180_000_000]`; the codec validates this on
    /// decode and on encode.
    pub longitude_micro_deg: i32,
    /// Altitude in metres above the WGS-84 ellipsoid. Negative values
    /// permitted (Death Valley operations, sub-surface contacts in a
    /// joint Link 16 / Link 22 fan-out).
    pub altitude_m: i32,
    /// Platform classification. See [`PlatformType`].
    pub platform_type: PlatformType,
    /// IFF / SIF / Mode-S response codes. See [`IffCodes`].
    pub iff: IffCodes,
    /// Kinematics — speed, course, climb rate. See [`JseriesKinematics`].
    pub kinematics: JseriesKinematics,
}

impl J2_2AirTrack {
    /// Wire byte for the J2.2 label / sublabel pair.
    ///
    /// MIL-STD-6016 packs the J-series label and sublabel into one
    /// byte: high nibble = label, low nibble = sublabel. J2.2 → `0x22`.
    pub const LABEL: u8 = 0x22;

    /// Total wire body length (header label + payload fields).
    pub const BODY_LEN: usize = 29;

    /// Decode a J2.2 message from a frame-body slice.
    ///
    /// The leading byte is expected to be [`Self::LABEL`]; non-J2.2
    /// labels surface as [`Link16Error::UnexpectedMessageType`].
    pub fn decode(body: &[u8]) -> Result<Self, Link16Error> {
        if body.len() < Self::BODY_LEN {
            return Err(Link16Error::Truncated {
                field: "J2_2AirTrack",
                needed: Self::BODY_LEN,
                available: body.len(),
            });
        }
        let label = body[0];
        if label != Self::LABEL {
            return Err(Link16Error::UnexpectedMessageType {
                expected: Self::LABEL,
                got: label,
            });
        }
        let track_number = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
        let latitude_micro_deg = i32::from_be_bytes([body[5], body[6], body[7], body[8]]);
        let longitude_micro_deg = i32::from_be_bytes([body[9], body[10], body[11], body[12]]);
        let altitude_m = i32::from_be_bytes([body[13], body[14], body[15], body[16]]);
        let platform_type = PlatformType::from_u8(body[17]);
        let iff_status_byte = body[18];
        let iff_mode_3_code = u16::from_be_bytes([body[19], body[20]]);
        let speed_cm_s = u32::from_be_bytes([body[21], body[22], body[23], body[24]]);
        let course_centideg = u16::from_be_bytes([body[25], body[26]]);
        let climb_rate_dm_s = i16::from_be_bytes([body[27], body[28]]);

        validate_latitude(latitude_micro_deg)?;
        validate_longitude(longitude_micro_deg)?;
        validate_course(course_centideg)?;

        Ok(Self {
            track_number,
            latitude_micro_deg,
            longitude_micro_deg,
            altitude_m,
            platform_type,
            iff: IffCodes {
                status_byte: iff_status_byte,
                mode_3_code: iff_mode_3_code,
            },
            kinematics: JseriesKinematics {
                speed_cm_s,
                course_centideg,
                climb_rate_dm_s,
            },
        })
    }

    /// Encode the J2.2 message into the supplied byte sink.
    ///
    /// Writes [`Self::BODY_LEN`] bytes including the leading label.
    /// Validates field envelopes before serialising — out-of-range
    /// latitude / longitude / course surface as
    /// [`Link16Error::InvalidValue`] without polluting `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), Link16Error> {
        validate_latitude(self.latitude_micro_deg)?;
        validate_longitude(self.longitude_micro_deg)?;
        validate_course(self.kinematics.course_centideg)?;

        out.push(Self::LABEL);
        out.extend_from_slice(&self.track_number.to_be_bytes());
        out.extend_from_slice(&self.latitude_micro_deg.to_be_bytes());
        out.extend_from_slice(&self.longitude_micro_deg.to_be_bytes());
        out.extend_from_slice(&self.altitude_m.to_be_bytes());
        out.push(self.platform_type.to_u8());
        out.push(self.iff.status_byte);
        out.extend_from_slice(&self.iff.mode_3_code.to_be_bytes());
        out.extend_from_slice(&self.kinematics.speed_cm_s.to_be_bytes());
        out.extend_from_slice(&self.kinematics.course_centideg.to_be_bytes());
        out.extend_from_slice(&self.kinematics.climb_rate_dm_s.to_be_bytes());
        Ok(())
    }

    /// Convenience: latitude in WGS-84 decimal degrees.
    #[must_use]
    pub fn latitude_deg(&self) -> f64 {
        f64::from(self.latitude_micro_deg) / 1_000_000.0
    }

    /// Convenience: longitude in WGS-84 decimal degrees.
    #[must_use]
    pub fn longitude_deg(&self) -> f64 {
        f64::from(self.longitude_micro_deg) / 1_000_000.0
    }
}

/// IFF / SIF / Mode-S response codes carried alongside a J2.2 track.
///
/// The `status_byte` is preserved as a raw byte rather than a typed
/// flag set because IFF code semantics depend on the at-issue NATO
/// IFF tables and are deployment-specific. The integration layer
/// (not this codec) resolves the byte against the configured table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IffCodes {
    /// Packed IFF status byte. Carries Mode-1, Mode-2, and Mode-S
    /// presence/value flags per the at-issue NATO IFF table; the
    /// codec preserves the byte verbatim.
    pub status_byte: u8,
    /// IFF Mode-3/A code (ATC squawk). Octal-encoded as `u16`; e.g.
    /// squawk `7700` (emergency) is `0o7700` = `0x0FC0`.
    pub mode_3_code: u16,
}

/// Kinematics carried alongside a J2.2 track.
///
/// Speed and course form the polar pair that downstream consumers
/// fold into a Cartesian velocity (or vice versa); climb rate is
/// reported separately for systems that need to draw the
/// vertical-rate symbol on a tactical display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JseriesKinematics {
    /// Ground speed in centimetres per second. The cm/s integer
    /// encoding keeps the wire form deterministic and round-trips
    /// without precision loss.
    pub speed_cm_s: u32,
    /// Course over ground in centidegrees (`0..36000`), measured
    /// clockwise from true north. The `[0, 36000)` envelope is
    /// validated on decode and on encode.
    pub course_centideg: u16,
    /// Climb rate in decimetres per second. Positive = ascending,
    /// negative = descending.
    pub climb_rate_dm_s: i16,
}

/// J2.2 platform type enumeration.
///
/// MIL-STD-6016 defines roughly 30 platform-type codes; the MVP
/// names the four most-used (Aircraft, Helicopter, Missile,
/// Unknown) and folds every other code into [`PlatformType::Other`]
/// for forward compatibility — a follow-up PR can extend the named
/// set without breaking call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformType {
    /// Fixed-wing aircraft.
    Aircraft,
    /// Rotary-wing aircraft.
    Helicopter,
    /// Missile / munition.
    Missile,
    /// Track classification not yet determined.
    Unknown,
    /// Any platform code the MVP does not name explicitly. The
    /// wrapped byte is the wire value.
    Other(u8),
}

impl PlatformType {
    /// Wire byte for fixed-wing aircraft per MIL-STD-6016.
    pub const AIRCRAFT: u8 = 0x01;
    /// Wire byte for rotary-wing aircraft.
    pub const HELICOPTER: u8 = 0x02;
    /// Wire byte for a missile / munition.
    pub const MISSILE: u8 = 0x03;
    /// Wire byte for an undetermined classification.
    pub const UNKNOWN: u8 = 0x00;

    /// Decode a wire byte into a typed [`PlatformType`].
    #[must_use]
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            Self::AIRCRAFT => Self::Aircraft,
            Self::HELICOPTER => Self::Helicopter,
            Self::MISSILE => Self::Missile,
            Self::UNKNOWN => Self::Unknown,
            other => Self::Other(other),
        }
    }

    /// Convert back to the wire byte.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Aircraft => Self::AIRCRAFT,
            Self::Helicopter => Self::HELICOPTER,
            Self::Missile => Self::MISSILE,
            Self::Unknown => Self::UNKNOWN,
            Self::Other(v) => v,
        }
    }
}

fn validate_latitude(value: i32) -> Result<(), Link16Error> {
    if !(-90_000_000..=90_000_000).contains(&value) {
        return Err(Link16Error::InvalidValue {
            field: "latitude_micro_deg",
            reason: "out of range [-90_000_000, 90_000_000]",
        });
    }
    Ok(())
}

fn validate_longitude(value: i32) -> Result<(), Link16Error> {
    if !(-180_000_000..=180_000_000).contains(&value) {
        return Err(Link16Error::InvalidValue {
            field: "longitude_micro_deg",
            reason: "out of range [-180_000_000, 180_000_000]",
        });
    }
    Ok(())
}

fn validate_course(value: u16) -> Result<(), Link16Error> {
    if value >= 36_000 {
        return Err(Link16Error::InvalidValue {
            field: "course_centideg",
            reason: "out of range [0, 36000)",
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_track() -> J2_2AirTrack {
        J2_2AirTrack {
            track_number: 0xDEAD_BEEF,
            latitude_micro_deg: 40_689_247, // Statue of Liberty.
            longitude_micro_deg: -74_044_502,
            altitude_m: 12_500,
            platform_type: PlatformType::Aircraft,
            iff: IffCodes {
                status_byte: 0b0000_0011,
                mode_3_code: 0o1200,
            },
            kinematics: JseriesKinematics {
                speed_cm_s: 25_000,    // 250 m/s ≈ 486 kt
                course_centideg: 9000, // due east
                climb_rate_dm_s: -50,  // descending 5 m/s
            },
        }
    }

    #[test]
    fn round_trips_through_decode_encode() {
        let track = sample_track();
        let mut bytes = Vec::with_capacity(J2_2AirTrack::BODY_LEN);
        track.encode_into(&mut bytes).expect("encode");
        assert_eq!(bytes.len(), J2_2AirTrack::BODY_LEN);
        let decoded = J2_2AirTrack::decode(&bytes).expect("decode");
        assert_eq!(decoded, track);
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let bytes = vec![0u8; J2_2AirTrack::BODY_LEN - 1];
        let err = J2_2AirTrack::decode(&bytes).expect_err("must fail");
        assert!(matches!(err, Link16Error::Truncated { .. }));
    }

    #[test]
    fn decode_rejects_wrong_label() {
        let mut bytes = vec![0u8; J2_2AirTrack::BODY_LEN];
        bytes[0] = 0x35; // J3.5 label, not J2.2
        let err = J2_2AirTrack::decode(&bytes).expect_err("must fail");
        assert!(matches!(
            err,
            Link16Error::UnexpectedMessageType {
                expected: 0x22,
                got: 0x35
            }
        ));
    }

    #[test]
    fn encode_rejects_out_of_range_latitude() {
        let mut track = sample_track();
        track.latitude_micro_deg = 91_000_000;
        let mut bytes = Vec::new();
        let err = track.encode_into(&mut bytes).expect_err("must fail");
        assert!(matches!(
            err,
            Link16Error::InvalidValue {
                field: "latitude_micro_deg",
                ..
            }
        ));
        assert!(bytes.is_empty(), "encoder must not partially emit");
    }

    #[test]
    fn encode_rejects_out_of_range_longitude() {
        let mut track = sample_track();
        track.longitude_micro_deg = -181_000_000;
        let mut bytes = Vec::new();
        let err = track.encode_into(&mut bytes).expect_err("must fail");
        assert!(matches!(
            err,
            Link16Error::InvalidValue {
                field: "longitude_micro_deg",
                ..
            }
        ));
    }

    #[test]
    fn encode_rejects_course_at_boundary() {
        let mut track = sample_track();
        track.kinematics.course_centideg = 36_000;
        let mut bytes = Vec::new();
        let err = track.encode_into(&mut bytes).expect_err("must fail");
        assert!(matches!(
            err,
            Link16Error::InvalidValue {
                field: "course_centideg",
                ..
            }
        ));
    }

    #[test]
    fn platform_type_round_trips_for_all_byte_values() {
        for byte in 0u8..=255u8 {
            assert_eq!(PlatformType::from_u8(byte).to_u8(), byte);
        }
    }

    #[test]
    fn label_byte_matches_mil_std_6016_packing() {
        // MIL-STD-6016 packs label/sublabel as high/low nibbles.
        // J2.2 → high=2, low=2 → 0x22.
        assert_eq!(J2_2AirTrack::LABEL, 0x22);
    }

    #[test]
    fn latitude_deg_helper_round_trips() {
        let track = sample_track();
        let lat = track.latitude_deg();
        assert!((lat - 40.689247).abs() < 1e-9);
    }

    #[test]
    fn longitude_deg_helper_round_trips() {
        let track = sample_track();
        let lon = track.longitude_deg();
        assert!((lon - (-74.044502)).abs() < 1e-9);
    }
}
