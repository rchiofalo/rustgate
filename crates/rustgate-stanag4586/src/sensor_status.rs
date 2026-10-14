// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! STANAG 4586 LOI 2-3 sensor-status telemetry message.
//!
//! Carries the sensor-payload health and pointing state stream that
//! any LOI 2-3 deployment needs to display alongside the vehicle
//! position frame ([`crate::vehicle_position`]). The two messages are
//! emitted from the same VSM at different rates: the vehicle-position
//! frame typically streams at 10–50 Hz so a moving-map can render the
//! platform smoothly, while sensor-status streams more slowly (1–5 Hz
//! is typical) because the sensor's pointing state changes far less
//! frequently than the platform's position.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`SENSOR_STATUS_FRAME_LEN`] = 32 bytes.
//!
//! ```text
//! offset │ size │ field             │ type
//! ───────┼──────┼───────────────────┼──────────────────────────
//!   0    │  4   │ sensor_id         │ u32  big-endian
//!   4    │  1   │ sensor_type       │ u8   enum value (see below)
//!   5    │  1   │ operational_state │ u8   enum value (see below)
//!   6    │  2   │ reserved          │ zero-padded — must be 0 on encode
//!   8    │  4   │ azimuth_deg       │ f32  big-endian IEEE-754
//!  12    │  4   │ elevation_deg     │ f32  big-endian IEEE-754
//!  16    │  4   │ field_of_view_deg │ f32  big-endian IEEE-754
//!  20    │  4   │ reserved          │ zero-padded — must be 0 on encode
//!  24    │  8   │ timestamp_unix_ms │ u64  big-endian
//! ```
//!
//! The two reserved blocks are zero-filled on encode. The decoder
//! does NOT validate that they are zero on the wire so a future
//! protocol revision that allocates them stays backward-compatible
//! at the frame-length level — `decode` will simply ignore the
//! bytes until those fields are wired into the struct.
//!
//! # Field semantics
//!
//! - `sensor_id` — opaque platform-assigned identifier disambiguating
//!   multiple sensors on the same airframe (e.g. an EO/IR turret with
//!   distinct wavelengths streamed as two `SensorStatus` frames with
//!   distinct `sensor_id`s but the same parent `vehicle_id`).
//! - `sensor_type` — sensor modality. See [`SensorType`].
//! - `operational_state` — health and operational readiness. See
//!   [`OperationalState`].
//! - `azimuth_deg` / `elevation_deg` — current pointing in the
//!   platform-relative reference frame. NOT range-checked because
//!   senders use signed or unwrapped values during slew integration;
//!   consumers that need normalised `[0, 360)` azimuth normalise
//!   downstream. Negative elevation indicates pointing below the
//!   horizon.
//! - `field_of_view_deg` — current angular FOV, degrees. A telephoto
//!   zoom narrows this; a wide-angle widens it. Range-checked to be
//!   strictly positive on decode (a zero or negative FOV is a wire-
//!   format mismatch — silent acceptance would hide the upstream
//!   defect).
//! - `timestamp_unix_ms` — milliseconds since the Unix epoch.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a sensor-status frame.
///
/// The frame is fixed-length by spec — there are no variable trailers
/// or option fields. Like [`crate::vehicle_position::VEHICLE_POSITION_FRAME_LEN`],
/// this makes the codec a straight slice-into-struct transformation
/// with no length prefix needed.
pub const SENSOR_STATUS_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_SENSOR_ID: usize = 0;
const OFF_SENSOR_TYPE: usize = 4;
const OFF_OPERATIONAL_STATE: usize = 5;
// 6..8 reserved (2 bytes)
const OFF_AZIMUTH: usize = 8;
const OFF_ELEVATION: usize = 12;
const OFF_FIELD_OF_VIEW: usize = 16;
// 20..24 reserved (4 bytes)
const OFF_TIMESTAMP: usize = 24;

/// Sensor modality enumeration carried in byte offset 4 of the frame.
///
/// Mirrors the publicly documented STANAG 4586 sensor-type byte
/// values. [`SensorType::Other`] preserves any byte the decoder does
/// not recognise so a future spec revision that allocates new sensor
/// types stays decodable rather than being rejected at the framing
/// layer.
///
/// # Wire byte values
///
/// | byte  | variant                |
/// |-------|------------------------|
/// | `0x01`| `ElectroOptical`       |
/// | `0x02`| `Infrared`             |
/// | `0x03`| `SyntheticApertureRadar` |
/// | `0x04`| `Lidar`                |
/// | `0x05`| `SignalsIntelligence`  |
/// | other | `Other(byte)`          |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensorType {
    /// Electro-optical (visible-light) imager.
    ElectroOptical,
    /// Infrared (thermal) imager.
    Infrared,
    /// Synthetic-aperture radar imager.
    SyntheticApertureRadar,
    /// LiDAR / laser-rangefinder sensor.
    Lidar,
    /// SIGINT (signals intelligence) sensor.
    SignalsIntelligence,
    /// Forward-compat catch-all for byte values this version of the
    /// codec does not recognise. Carries the raw wire byte so logs
    /// can show what was observed.
    Other(u8),
}

impl SensorType {
    /// Map a wire byte into the typed enum. Forward-compatible — any
    /// unknown byte (including `0x00`) is preserved as
    /// [`SensorType::Other`] rather than rejected.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::ElectroOptical,
            0x02 => Self::Infrared,
            0x03 => Self::SyntheticApertureRadar,
            0x04 => Self::Lidar,
            0x05 => Self::SignalsIntelligence,
            _ => Self::Other(b),
        }
    }

    /// Map the typed enum back into its wire byte. The round-trip
    /// `from_byte(x.to_byte()) == x` holds for every named variant
    /// and for `Other(b)` where `b` is any byte the named-variant
    /// table does not cover.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::ElectroOptical => 0x01,
            Self::Infrared => 0x02,
            Self::SyntheticApertureRadar => 0x03,
            Self::Lidar => 0x04,
            Self::SignalsIntelligence => 0x05,
            Self::Other(b) => b,
        }
    }
}

/// Operational-state enumeration carried in byte offset 5 of the
/// frame. Reflects the sensor's health and readiness independent of
/// pointing — a sensor can be `Operational` and yet pointed off-
/// target, or `Calibrating` and not yet producing useful data.
///
/// # Wire byte values
///
/// | byte  | variant         |
/// |-------|-----------------|
/// | `0x01`| `Off`           |
/// | `0x02`| `Standby`       |
/// | `0x03`| `Operational`   |
/// | `0x04`| `Calibrating`   |
/// | `0x05`| `Failed`        |
/// | other | `Other(byte)`   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationalState {
    /// Powered down.
    Off,
    /// Powered, warm, not actively imaging.
    Standby,
    /// Actively imaging and producing valid data.
    Operational,
    /// Mid-calibration cycle; data may be present but is not
    /// guaranteed to be valid.
    Calibrating,
    /// Sensor reports a hardware fault — data is not trustworthy and
    /// the operator should escalate to maintenance.
    Failed,
    /// Forward-compat catch-all for byte values this version of the
    /// codec does not recognise.
    Other(u8),
}

impl OperationalState {
    /// Map a wire byte into the typed enum.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Off,
            0x02 => Self::Standby,
            0x03 => Self::Operational,
            0x04 => Self::Calibrating,
            0x05 => Self::Failed,
            _ => Self::Other(b),
        }
    }

    /// Map the typed enum back into its wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Off => 0x01,
            Self::Standby => 0x02,
            Self::Operational => 0x03,
            Self::Calibrating => 0x04,
            Self::Failed => 0x05,
            Self::Other(b) => b,
        }
    }
}

/// LOI 2-3 sensor-status telemetry message.
///
/// Decoded form of the 32-byte wire frame documented at the module
/// level. Construct via [`decode`] (from a wire byte slice) or by
/// hand for tests / synthetic generators; round-trip via [`encode`]
/// or [`encode_into`].
#[derive(Debug, Clone, PartialEq)]
pub struct SensorStatus {
    /// Platform-assigned sensor identifier.
    pub sensor_id: u32,
    /// Sensor modality.
    pub sensor_type: SensorType,
    /// Sensor health / operational readiness.
    pub operational_state: OperationalState,
    /// Pointing azimuth, degrees (platform-relative reference frame,
    /// not range-checked).
    pub azimuth_deg: f32,
    /// Pointing elevation, degrees (negative = below horizon, not
    /// range-checked).
    pub elevation_deg: f32,
    /// Current angular field-of-view, degrees. Strictly positive on
    /// decode.
    pub field_of_view_deg: f32,
    /// Milliseconds since the Unix epoch.
    pub timestamp_unix_ms: u64,
}

impl SensorStatus {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    ///
    /// Convenience wrapper around [`encode`] for callers that want
    /// the most ergonomic form. For zero-extra-allocation use cases
    /// (when the encoded frame is the body of a larger packet) call
    /// [`encode_into`] directly.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a sensor-status frame into a freshly allocated `Vec<u8>`.
pub fn encode(msg: &SensorStatus) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(SENSOR_STATUS_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode a sensor-status frame, appending to a caller-supplied
/// [`BytesMut`]. The destination is **not** cleared; existing bytes
/// are preserved before the encoded frame so the same buffer can
/// carry a length-prefix or surrounding envelope.
pub fn encode_into(msg: &SensorStatus, buf: &mut BytesMut) {
    buf.put_u32(msg.sensor_id);
    buf.put_u8(msg.sensor_type.to_byte());
    buf.put_u8(msg.operational_state.to_byte());
    // 2 reserved bytes, zero-filled.
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_f32(msg.azimuth_deg);
    buf.put_f32(msg.elevation_deg);
    buf.put_f32(msg.field_of_view_deg);
    // 4 reserved bytes, zero-filled.
    buf.put_u32(0);
    buf.put_u64(msg.timestamp_unix_ms);
}

/// Decode a sensor-status frame from a wire byte slice.
///
/// Returns an error if the slice is shorter than
/// [`SENSOR_STATUS_FRAME_LEN`] or if the FOV is non-positive.
/// Trailing bytes beyond the fixed length are explicitly ignored —
/// see the module-level note on forward compatibility.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
/// - [`Stanag4586Error::FieldOutOfRange`] if `field_of_view_deg <= 0`
///   or is NaN. (A non-positive FOV is meaningless and is a strong
///   signal of byte-swap or wrong-message-type.)
pub fn decode(bytes: &[u8]) -> Result<SensorStatus, Stanag4586Error> {
    if bytes.len() < SENSOR_STATUS_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: SENSOR_STATUS_FRAME_LEN,
        });
    }

    let mut cursor = &bytes[..SENSOR_STATUS_FRAME_LEN];
    let sensor_id = cursor.get_u32();
    let sensor_type = SensorType::from_byte(cursor.get_u8());
    let operational_state = OperationalState::from_byte(cursor.get_u8());
    // Skip 2 reserved bytes — see module doc.
    let _ = cursor.get_u16();
    let azimuth_deg = cursor.get_f32();
    let elevation_deg = cursor.get_f32();
    let field_of_view_deg = cursor.get_f32();
    // Skip 4 reserved bytes.
    let _ = cursor.get_u32();
    let timestamp_unix_ms = cursor.get_u64();

    if !(field_of_view_deg.is_finite()) || field_of_view_deg <= 0.0 {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "field_of_view_deg",
            value: field_of_view_deg.to_string(),
        });
    }

    debug_assert_eq!(
        cursor.remaining(),
        0,
        "cursor must be fully consumed after reading {SENSOR_STATUS_FRAME_LEN} bytes"
    );
    let _ = OFF_SENSOR_ID;
    let _ = OFF_SENSOR_TYPE;
    let _ = OFF_OPERATIONAL_STATE;
    let _ = OFF_AZIMUTH;
    let _ = OFF_ELEVATION;
    let _ = OFF_FIELD_OF_VIEW;
    let _ = OFF_TIMESTAMP;

    Ok(SensorStatus {
        sensor_id,
        sensor_type,
        operational_state,
        azimuth_deg,
        elevation_deg,
        field_of_view_deg,
        timestamp_unix_ms,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn fixture_full() -> SensorStatus {
        SensorStatus {
            sensor_id: 0x1122_3344,
            sensor_type: SensorType::Infrared,
            operational_state: OperationalState::Operational,
            azimuth_deg: 123.4,
            elevation_deg: -7.5,
            field_of_view_deg: 22.5,
            timestamp_unix_ms: 0xDEAD_BEEF_CAFE_0042,
        }
    }

    #[test]
    fn round_trip_full_fixture() {
        let msg = fixture_full();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), SENSOR_STATUS_FRAME_LEN);
        let decoded = decode(&bytes).expect("decode round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_via_encode_to_vec_method_matches_free_function() {
        let msg = fixture_full();
        assert_eq!(msg.encode_to_vec(), encode(&msg));
    }

    #[test]
    fn encode_into_appends_without_clearing_destination() {
        let mut buf = BytesMut::from(&b"prefix-"[..]);
        encode_into(&fixture_full(), &mut buf);
        assert!(buf.starts_with(b"prefix-"));
        assert_eq!(buf.len(), 7 + SENSOR_STATUS_FRAME_LEN);
    }

    #[test]
    fn decode_known_fixture_matches_expected_bytes() {
        // Hand-encoded golden fixture — pins every documented byte
        // offset against the IEEE-754 bit pattern. A regression that
        // swaps endianness or reorders fields fails this test even
        // though round-trip self-consistency tests would still pass.
        let msg = SensorStatus {
            sensor_id: 1,
            sensor_type: SensorType::ElectroOptical,
            operational_state: OperationalState::Standby,
            azimuth_deg: 1.0,
            elevation_deg: 2.0,
            field_of_view_deg: 3.0,
            timestamp_unix_ms: 0x0011_2233_4455_6677,
        };
        let bytes = encode(&msg);
        // sensor_id BE
        assert_eq!(&bytes[0..4], &[0x00, 0x00, 0x00, 0x01]);
        // sensor_type 0x01 (EO)
        assert_eq!(bytes[4], 0x01);
        // operational_state 0x02 (Standby)
        assert_eq!(bytes[5], 0x02);
        // 2 reserved zeros
        assert_eq!(&bytes[6..8], &[0x00, 0x00]);
        // azimuth = 1.0_f32 BE: 0x3F800000
        assert_eq!(&bytes[8..12], &[0x3F, 0x80, 0x00, 0x00]);
        // elevation = 2.0_f32 BE: 0x40000000
        assert_eq!(&bytes[12..16], &[0x40, 0x00, 0x00, 0x00]);
        // fov = 3.0_f32 BE: 0x40400000
        assert_eq!(&bytes[16..20], &[0x40, 0x40, 0x00, 0x00]);
        // 4 reserved zeros
        assert_eq!(&bytes[20..24], &[0x00, 0x00, 0x00, 0x00]);
        // timestamp BE
        assert_eq!(
            &bytes[24..32],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
    }

    #[test]
    fn decode_rejects_zero_field_of_view() {
        // FOV of 0 is meaningless — pin the rejection so a wire-
        // format mismatch surfaces fast rather than silently flowing
        // through to the display layer.
        let mut msg = fixture_full();
        msg.field_of_view_deg = 0.0;
        let bytes = encode(&msg);
        let err = decode(&bytes).expect_err("zero FOV must be rejected");
        match err {
            Stanag4586Error::FieldOutOfRange { field, .. } => {
                assert_eq!(field, "field_of_view_deg");
            }
            other => panic!("expected FieldOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_negative_field_of_view() {
        let mut msg = fixture_full();
        msg.field_of_view_deg = -1.0;
        let bytes = encode(&msg);
        assert!(matches!(
            decode(&bytes),
            Err(Stanag4586Error::FieldOutOfRange { .. })
        ));
    }

    #[test]
    fn decode_rejects_nan_field_of_view() {
        // Without an explicit !is_finite() check, the `<= 0` branch
        // would silently accept NaN (NaN comparisons are always
        // false). Pin that defensive check.
        let mut msg = fixture_full();
        msg.field_of_view_deg = f32::NAN;
        let bytes = encode(&msg);
        assert!(matches!(
            decode(&bytes),
            Err(Stanag4586Error::FieldOutOfRange { .. })
        ));
    }

    #[test]
    fn decode_truncation_returns_dedicated_variant() {
        for n in [0, 1, 7, 24, 31] {
            let bytes = vec![0u8; n];
            match decode(&bytes) {
                Err(Stanag4586Error::FrameTooShort { actual, expected }) => {
                    assert_eq!(actual, n);
                    assert_eq!(expected, SENSOR_STATUS_FRAME_LEN);
                }
                other => panic!("expected FrameTooShort for {n} bytes, got {other:?}"),
            }
        }
    }

    #[test]
    fn decode_extra_trailing_bytes_are_ignored() {
        // A future protocol revision that appends a trailer keeps
        // decoding the prefix unchanged.
        let msg = fixture_full();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(b"future-trailer-bytes");
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn sensor_type_to_byte_round_trips_for_known_variants() {
        for v in [
            SensorType::ElectroOptical,
            SensorType::Infrared,
            SensorType::SyntheticApertureRadar,
            SensorType::Lidar,
            SensorType::SignalsIntelligence,
        ] {
            assert_eq!(SensorType::from_byte(v.to_byte()), v);
        }
    }

    #[test]
    fn sensor_type_other_round_trips_arbitrary_byte() {
        // Every byte that does NOT collide with a named variant must
        // round-trip through `Other(b)`. Sweeping a few representative
        // edges (0x00, 0x10, 0xFF) is enough — the proptest below
        // exhaustively checks the rest.
        for b in [0x00, 0x06, 0x10, 0x42, 0xFF] {
            let v = SensorType::from_byte(b);
            assert_eq!(v, SensorType::Other(b));
            assert_eq!(v.to_byte(), b);
        }
    }

    #[test]
    fn operational_state_to_byte_round_trips_for_known_variants() {
        for v in [
            OperationalState::Off,
            OperationalState::Standby,
            OperationalState::Operational,
            OperationalState::Calibrating,
            OperationalState::Failed,
        ] {
            assert_eq!(OperationalState::from_byte(v.to_byte()), v);
        }
    }

    #[test]
    fn operational_state_other_round_trips_arbitrary_byte() {
        for b in [0x00, 0x06, 0x10, 0x42, 0xFF] {
            let v = OperationalState::from_byte(b);
            assert_eq!(v, OperationalState::Other(b));
            assert_eq!(v.to_byte(), b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn round_trip_via_proptest(
            sensor_id in any::<u32>(),
            sensor_type_byte in any::<u8>(),
            operational_state_byte in any::<u8>(),
            // FOV must be strictly positive AND finite — otherwise
            // decode() rejects, which is its own dedicated test.
            field_of_view_deg in (f32::MIN_POSITIVE..1_000_000.0_f32),
            // Azimuth / elevation / timestamp can be anything finite.
            azimuth_deg in any::<f32>().prop_filter("finite", |v| v.is_finite()),
            elevation_deg in any::<f32>().prop_filter("finite", |v| v.is_finite()),
            timestamp_unix_ms in any::<u64>(),
        ) {
            let msg = SensorStatus {
                sensor_id,
                sensor_type: SensorType::from_byte(sensor_type_byte),
                operational_state: OperationalState::from_byte(operational_state_byte),
                azimuth_deg,
                elevation_deg,
                field_of_view_deg,
                timestamp_unix_ms,
            };
            let bytes = encode(&msg);
            prop_assert_eq!(bytes.len(), SENSOR_STATUS_FRAME_LEN);
            let decoded = decode(&bytes).unwrap();
            prop_assert_eq!(decoded, msg);
        }
    }
}
