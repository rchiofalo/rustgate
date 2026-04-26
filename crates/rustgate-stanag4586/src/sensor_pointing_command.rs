// Copyright © 2026 Roberto Chiofalo.

//! STANAG 4586 LOI 4 sensor pointing command message.
//!
//! Carries the second **command-side** message in the
//! `rustgate-stanag4586` crate, following the waypoint upload frame
//! ([`crate::waypoint_command`]) that graduated the codec from a pure
//! read-side surface to its first LOI 4 command. Where waypoint upload
//! directs *the platform*, sensor pointing directs *a payload sensor*
//! mounted on that platform: a Ground Control Station emits one
//! `SensorPointingCommand` to slew an EO/IR turret (or any other
//! gimballed sensor reported via [`crate::sensor_status`]) to a
//! specified azimuth/elevation/zoom for ground-target tracking and ISR
//! collection.
//!
//! # Operational model
//!
//! Sensor pointing is the operator's primary interaction with a UAS
//! payload during an ISR mission. A typical workflow looks like:
//!
//! 1. The vehicle's [`crate::sensor_status`] stream tells the GCS what
//!    sensors are aboard, what type each is, and where each is
//!    currently pointing.
//! 2. The operator picks a sensor (by `sensor_id`) and a target — a
//!    geographic point of interest, a ground vehicle, or a fixed
//!    structure.
//! 3. The GCS emits a `SensorPointingCommand` to slew that sensor onto
//!    the target. The [`PointingMode`] selects the slew strategy:
//!    direct azimuth/elevation ([`PointingMode::SlewToAzEl`]),
//!    geographic-coordinate lock ([`PointingMode::GeoLock`]),
//!    moving-ground-target tracking ([`PointingMode::GroundTarget`]),
//!    or stow the sensor into its parked configuration
//!    ([`PointingMode::Stow`]) when the mission ends or the platform
//!    needs to land.
//! 4. The platform acknowledges via the (separate, future-PR) command
//!    response message and the next `sensor_status` frames reflect the
//!    new pointing state.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`SENSOR_POINTING_COMMAND_FRAME_LEN`] = 32
//! bytes.
//!
//! ```text
//! offset │ size │ field          │ type
//! ───────┼──────┼────────────────┼──────────────────────────
//!   0    │  4   │ vehicle_id     │ u32  big-endian
//!   4    │  4   │ sensor_id      │ u32  big-endian
//!   8    │  1   │ pointing_mode  │ u8   enum value (see below)
//!   9    │  3   │ reserved       │ zero-padded — must be 0 on encode
//!  12    │  4   │ azimuth_deg    │ f32  big-endian IEEE-754
//!  16    │  4   │ elevation_deg  │ f32  big-endian IEEE-754
//!  20    │  4   │ zoom_factor    │ f32  big-endian IEEE-754
//!  24    │  4   │ reserved       │ zero-padded — must be 0 on encode
//!  28    │  4   │ dwell_secs     │ u32  big-endian
//! ```
//!
//! Both reserved blocks are zero-filled on encode. The decoder does
//! NOT validate that they are zero on the wire so a future spec
//! revision that allocates the bytes (e.g. a per-command priority
//! flag, or a command sequence number for matching against the future
//! response message) stays backward-compatible at the frame-length
//! level.
//!
//! # Field semantics
//!
//! - `vehicle_id` — the target platform identifier. Matches the
//!   `vehicle_id` carried by the LOI 2-3 telemetry frames and the LOI
//!   4 [`crate::waypoint_command`] frame so a GCS can correlate
//!   "which sensor command did I send to which platform" against
//!   "which platform's telemetry am I currently displaying" by direct
//!   byte comparison.
//! - `sensor_id` — the target sensor on that vehicle. Matches the
//!   `sensor_id` field carried by [`crate::sensor_status`] so an
//!   operator UI can dispatch on `sensor_id` byte equality between the
//!   inbound status frame (the picker source) and the outbound
//!   pointing command (the target) without an intermediate lookup
//!   table.
//! - `pointing_mode` — which slew strategy the platform should use.
//!   See [`PointingMode`].
//! - `azimuth_deg` — target azimuth, decimal degrees. NaN explicitly
//!   rejected, but NOT range-checked: senders may emit unwrapped
//!   values (e.g. `540` during a slew integration crossing the
//!   `360`/`0` boundary) and the decoder must accept them — matches
//!   the discipline established by
//!   [`crate::vehicle_position::VehiclePosition::heading_deg`] and
//!   [`crate::sensor_status::SensorStatus::azimuth_deg`].
//! - `elevation_deg` — target elevation, decimal degrees. NaN
//!   explicitly rejected AND range-checked to `[-90, 90]` because
//!   mechanical sensor gimbals cannot physically exceed those bounds —
//!   an out-of-range elevation is a wire-format mismatch (wrong
//!   message type, byte-swap, …) and silent acceptance would hide the
//!   upstream defect.
//! - `zoom_factor` — non-negative, finite zoom multiplier. `1.0`
//!   represents wide-angle, `10.0` represents telephoto; the absolute
//!   units are sensor-dependent (the spec documents this as a ratio
//!   relative to the sensor's widest configured FOV). NaN and
//!   negative values explicitly rejected — a negative zoom has no
//!   physical meaning and is always a wire-format defect.
//! - `dwell_secs` — how long the platform should dwell at this
//!   pointing target before being free to re-task. `0` indicates
//!   indefinite dwell — the platform holds pointing until a follow-up
//!   command arrives. The codec does not range-check `dwell_secs`
//!   against any per-mission timeout — that is the GCS application
//!   layer's responsibility.
//!
//! # What is deliberately absent
//!
//! - **Other LOI 4 commands** — GCS handover, payload control, route
//!   upload, mission abort. Each is a separate follow-up PR with its
//!   own wire format and validation rules.
//! - **Response / acknowledgement messages** — the bidirectional
//!   command-response handshake (the platform's "pointing accepted"
//!   or "pointing rejected, sensor stowed for safety" reply) is a
//!   separate follow-up PR.
//! - **UDP/TCP listener wiring** — this module is pure encode/decode
//!   over `&[u8]`; the network glue is a separate change.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a sensor pointing command frame.
pub const SENSOR_POINTING_COMMAND_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_SENSOR_ID: usize = 4;
const OFF_POINTING_MODE: usize = 8;
// 9..12 reserved (3 bytes)
const OFF_AZIMUTH: usize = 12;
const OFF_ELEVATION: usize = 16;
const OFF_ZOOM: usize = 20;
// 24..28 reserved (4 bytes)
const OFF_DWELL_SECS: usize = 28;

/// Which slew strategy the platform should use to satisfy the
/// pointing command.
///
/// The four named variants cover the LOI 4 sensor-pointing
/// minimum-viable command vocabulary: direct azimuth/elevation slew
/// ([`PointingMode::SlewToAzEl`]), geographic-coordinate lock onto a
/// fixed point of interest ([`PointingMode::GeoLock`]), moving-ground-
/// target tracking ([`PointingMode::GroundTarget`]), or return the
/// sensor to its parked / stowed configuration
/// ([`PointingMode::Stow`]) at end-of-mission or before recovery.
/// [`PointingMode::Other`] preserves any unrecognised wire byte so a
/// future spec revision that allocates a new pointing strategy stays
/// decodable on a receiver running today's build — matches the same
/// forward-compat discipline used by every sibling LOI 2-3 / LOI 4
/// frame's enums.
///
/// # Wire byte values
///
/// | byte  | variant         |
/// |-------|-----------------|
/// | `0x01`| `SlewToAzEl`    |
/// | `0x02`| `GeoLock`       |
/// | `0x03`| `GroundTarget`  |
/// | `0x04`| `Stow`          |
/// | other | `Other(byte)`   |
///
/// `0x00` deliberately falls into [`PointingMode::Other`] rather than
/// having its own "Unknown" variant — the encode side never emits
/// `0x00` for a named mode, so observing one on decode means the
/// upstream sent something unintended and the operator should be
/// able to see the raw byte value in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointingMode {
    /// Slew to a specified azimuth and elevation in the platform-
    /// relative reference frame.
    SlewToAzEl,
    /// Lock onto a geographic coordinate; the sensor counter-rotates
    /// as the platform manoeuvres so the same point of interest stays
    /// centred in frame.
    GeoLock,
    /// Track a moving ground target identified to the sensor by an
    /// out-of-band designation (laser spot, manual track gate, …).
    GroundTarget,
    /// Return the sensor to its parked / stowed configuration.
    Stow,
    /// Forward-compat catch-all for pointing-mode bytes the spec may
    /// allocate in a future revision.
    Other(u8),
}

impl PointingMode {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::SlewToAzEl,
            0x02 => Self::GeoLock,
            0x03 => Self::GroundTarget,
            0x04 => Self::Stow,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::SlewToAzEl => 0x01,
            Self::GeoLock => 0x02,
            Self::GroundTarget => 0x03,
            Self::Stow => 0x04,
            Self::Other(b) => b,
        }
    }
}

/// LOI 4 sensor pointing command message.
#[derive(Debug, Clone, PartialEq)]
pub struct SensorPointingCommand {
    /// Target platform identifier (matches
    /// [`crate::vehicle_position::VehiclePosition::vehicle_id`]).
    pub vehicle_id: u32,
    /// Target sensor on the platform (matches
    /// [`crate::sensor_status::SensorStatus::sensor_id`]).
    pub sensor_id: u32,
    /// Slew strategy the platform should use.
    pub pointing_mode: PointingMode,
    /// Target azimuth, decimal degrees. Not range-checked — senders
    /// may emit unwrapped values during slew integration.
    pub azimuth_deg: f32,
    /// Target elevation, decimal degrees, range `[-90, 90]`.
    pub elevation_deg: f32,
    /// Zoom multiplier — `1.0` = widest configured FOV, larger values
    /// narrow the FOV (telephoto). Non-negative, finite.
    pub zoom_factor: f32,
    /// How long to dwell at this pointing target before re-tasking,
    /// seconds. `0` indicates indefinite dwell.
    pub dwell_secs: u32,
}

impl SensorPointingCommand {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a sensor pointing command frame into a freshly allocated
/// `Vec<u8>`.
#[must_use]
pub fn encode(msg: &SensorPointingCommand) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(SENSOR_POINTING_COMMAND_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
///
/// Useful when the encoded frame will be the body of a larger packet
/// and the caller wants to avoid the intermediate `Vec` allocation
/// of [`encode`]. Appends [`SENSOR_POINTING_COMMAND_FRAME_LEN`]
/// bytes; does not clear or truncate `buf`.
pub fn encode_into(msg: &SensorPointingCommand, buf: &mut BytesMut) {
    buf.reserve(SENSOR_POINTING_COMMAND_FRAME_LEN);
    buf.put_u32(msg.vehicle_id);
    buf.put_u32(msg.sensor_id);
    buf.put_u8(msg.pointing_mode.to_byte());
    // 3 reserved bytes.
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_f32(msg.azimuth_deg);
    buf.put_f32(msg.elevation_deg);
    buf.put_f32(msg.zoom_factor);
    // 4 reserved bytes.
    buf.put_u32(0);
    buf.put_u32(msg.dwell_secs);
}

/// Decode a sensor pointing command frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
/// - [`Stanag4586Error::FieldOutOfRange`] if `azimuth_deg` is NaN.
/// - [`Stanag4586Error::FieldOutOfRange`] if `elevation_deg` is NaN
///   or outside `[-90, 90]`.
/// - [`Stanag4586Error::FieldOutOfRange`] if `zoom_factor` is NaN or
///   negative.
///
/// Trailing bytes beyond [`SENSOR_POINTING_COMMAND_FRAME_LEN`] are
/// ignored; the codec is fixed-size and a future protocol revision
/// that appends fields keeps decoding the prefix unchanged.
///
/// Unrecognised `pointing_mode` bytes do NOT cause an error — they
/// surface as [`PointingMode::Other`] for forward compatibility.
pub fn decode(bytes: &[u8]) -> Result<SensorPointingCommand, Stanag4586Error> {
    if bytes.len() < SENSOR_POINTING_COMMAND_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: SENSOR_POINTING_COMMAND_FRAME_LEN,
        });
    }

    let mut cursor = &bytes[..SENSOR_POINTING_COMMAND_FRAME_LEN];
    let vehicle_id = cursor.get_u32();
    let sensor_id = cursor.get_u32();
    let pointing_mode = PointingMode::from_byte(cursor.get_u8());
    // Skip 3-byte reserved region.
    cursor.advance(3);
    let azimuth_deg = f32::from_bits(cursor.get_u32());
    let elevation_deg = f32::from_bits(cursor.get_u32());
    let zoom_factor = f32::from_bits(cursor.get_u32());
    // Skip 4-byte reserved region.
    cursor.advance(4);
    let dwell_secs = cursor.get_u32();

    debug_assert!(
        cursor.is_empty(),
        "fixed-size frame should be fully consumed; bug in offset constants"
    );
    let _ = OFF_VEHICLE_ID;
    let _ = OFF_SENSOR_ID;
    let _ = OFF_POINTING_MODE;
    let _ = OFF_AZIMUTH;
    let _ = OFF_ELEVATION;
    let _ = OFF_ZOOM;
    let _ = OFF_DWELL_SECS;

    if azimuth_deg.is_nan() {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "azimuth_deg",
            value: azimuth_deg.to_string(),
        });
    }
    if elevation_deg.is_nan() || !(-90.0..=90.0).contains(&elevation_deg) {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "elevation_deg",
            value: elevation_deg.to_string(),
        });
    }
    if !zoom_factor.is_finite() || zoom_factor < 0.0 {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "zoom_factor",
            value: zoom_factor.to_string(),
        });
    }

    Ok(SensorPointingCommand {
        vehicle_id,
        sensor_id,
        pointing_mode,
        azimuth_deg,
        elevation_deg,
        zoom_factor,
        dwell_secs,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Mid-range typical pointing-target fixture. Deliberately
    /// non-default values so an `assert_eq!` mismatch points at the
    /// right field.
    fn typical_pointing_command() -> SensorPointingCommand {
        SensorPointingCommand {
            vehicle_id: 0xA1B2_C3D4,
            sensor_id: 0x0102_0304,
            pointing_mode: PointingMode::GeoLock,
            azimuth_deg: 137.5,
            elevation_deg: -12.25,
            zoom_factor: 4.0,
            dwell_secs: 30,
        }
    }

    // ---- Round-trip ----

    #[test]
    fn round_trip_zero_valued_fixture() {
        // All-zero is a valid frame: vehicle_id=0, sensor_id=0,
        // pointing_mode defaults to Other(0) (forward-compat catch-all
        // preserves the byte), zero azimuth/elevation, zero zoom (a
        // boundary value at the documented non-negative cap), and
        // zero dwell (= indefinite). The round-trip must hold even at
        // this corner.
        let msg = SensorPointingCommand {
            vehicle_id: 0,
            sensor_id: 0,
            pointing_mode: PointingMode::Other(0),
            azimuth_deg: 0.0,
            elevation_deg: 0.0,
            zoom_factor: 0.0,
            dwell_secs: 0,
        };
        let bytes = encode(&msg);
        assert_eq!(bytes, vec![0u8; SENSOR_POINTING_COMMAND_FRAME_LEN]);
        let decoded = decode(&bytes).expect("zero round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_max_range_valid_fixture() {
        // Pin the upper edges of the integer fields and the gimbal
        // valid range. A regression that swapped a u32 to a smaller
        // type would silently truncate at the max value and fail
        // this test; a regression that tightened the elevation bound
        // by one ULP would reject the boundary value here.
        let msg = SensorPointingCommand {
            vehicle_id: u32::MAX,
            sensor_id: u32::MAX,
            pointing_mode: PointingMode::Stow,
            azimuth_deg: 359.999,
            elevation_deg: 90.0,
            zoom_factor: f32::MAX,
            dwell_secs: u32::MAX,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("max round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_typical_pointing_target_fixture() {
        let msg = typical_pointing_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), SENSOR_POINTING_COMMAND_FRAME_LEN);
        let decoded = decode(&bytes).expect("typical round-trip");
        assert_eq!(decoded, msg);
    }

    // ---- Golden-fixture decode ----

    #[test]
    fn decode_known_fixture_matches_expected_bytes() {
        // Hand-built golden fixture that pins every field at its
        // documented byte offset. The IEEE-754 big-endian byte
        // sequences for the three floats are computed in the test
        // source so a regression that swapped to little-endian could
        // pass the round-trip + proptest checks but would still fail
        // this byte-pinning check.
        //
        // Field values:
        //   vehicle_id    = 0x1122_3344
        //   sensor_id     = 0x5566_7788
        //   pointing_mode = 0x02 (GeoLock)
        //   azimuth_deg   = 180.0
        //   elevation_deg = -15.0
        //   zoom_factor   = 4.0
        //   dwell_secs    = 0x0000_003C  (= 60 seconds)
        let msg = SensorPointingCommand {
            vehicle_id: 0x1122_3344,
            sensor_id: 0x5566_7788,
            pointing_mode: PointingMode::GeoLock,
            azimuth_deg: 180.0,
            elevation_deg: -15.0,
            zoom_factor: 4.0,
            dwell_secs: 0x0000_003C,
        };
        let bytes = encode(&msg);
        let expected: [u8; SENSOR_POINTING_COMMAND_FRAME_LEN] = [
            // vehicle_id = 0x1122_3344 (big-endian)
            0x11, 0x22, 0x33, 0x44, //
            // sensor_id = 0x5566_7788 (big-endian)
            0x55, 0x66, 0x77, 0x88, //
            // pointing_mode = 0x02 (GeoLock)
            0x02, //
            // 3 reserved zero bytes
            0x00, 0x00, 0x00, //
            // azimuth_deg = 180.0 → IEEE-754 big-endian (0x43340000)
            0x43, 0x34, 0x00, 0x00, //
            // elevation_deg = -15.0 → IEEE-754 big-endian (0xC1700000)
            0xC1, 0x70, 0x00, 0x00, //
            // zoom_factor = 4.0 → IEEE-754 big-endian (0x40800000)
            0x40, 0x80, 0x00, 0x00, //
            // 4 reserved zero bytes
            0x00, 0x00, 0x00, 0x00, //
            // dwell_secs = 0x0000_003C (big-endian)
            0x00, 0x00, 0x00, 0x3C,
        ];
        assert_eq!(
            bytes.as_slice(),
            &expected[..],
            "encoded bytes must match the documented byte layout"
        );
        let decoded = decode(&expected).expect("golden decode");
        assert_eq!(decoded, msg);
    }

    // ---- NaN rejection ----

    #[test]
    fn decode_rejects_nan_azimuth_deg() {
        // NaN passes neither `<` nor `>` so a naive check would
        // accept it. Pin that we explicitly reject NaN as a sanity
        // gate — a NaN azimuth is never legitimate command input even
        // though azimuth itself is intentionally not range-checked.
        let mut wire = encode(&typical_pointing_command());
        wire[12..16].copy_from_slice(&f32::NAN.to_be_bytes());
        match decode(&wire) {
            Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "azimuth_deg");
            }
            other => panic!("expected FieldOutOfRange/azimuth_deg, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_nan_elevation_deg() {
        let mut wire = encode(&typical_pointing_command());
        wire[16..20].copy_from_slice(&f32::NAN.to_be_bytes());
        match decode(&wire) {
            Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "elevation_deg");
            }
            other => panic!("expected FieldOutOfRange/elevation_deg, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_nan_zoom_factor() {
        let mut wire = encode(&typical_pointing_command());
        wire[20..24].copy_from_slice(&f32::NAN.to_be_bytes());
        match decode(&wire) {
            Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "zoom_factor");
            }
            other => panic!("expected FieldOutOfRange/zoom_factor, got {other:?}"),
        }
    }

    // ---- Range rejection ----

    #[test]
    fn decode_rejects_elevation_above_90() {
        // 90.0 is the documented upper bound — `91.0` is one full
        // degree past the mechanical gimbal limit and must be
        // rejected. Pin both `90.0001_f32` (just past the boundary)
        // and a comfortable margin via `91.0` so a regression that
        // accidentally includes the upper open boundary is caught
        // even with f32 rounding noise.
        for elev in [90.0001_f32, 91.0_f32] {
            let mut wire = encode(&typical_pointing_command());
            wire[16..20].copy_from_slice(&elev.to_be_bytes());
            match decode(&wire) {
                Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                    assert_eq!(field, "elevation_deg");
                }
                other => {
                    panic!("expected FieldOutOfRange/elevation_deg for elev={elev}, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn decode_rejects_elevation_below_minus_90() {
        for elev in [-90.0001_f32, -91.0_f32] {
            let mut wire = encode(&typical_pointing_command());
            wire[16..20].copy_from_slice(&elev.to_be_bytes());
            match decode(&wire) {
                Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                    assert_eq!(field, "elevation_deg");
                }
                other => {
                    panic!("expected FieldOutOfRange/elevation_deg for elev={elev}, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn decode_rejects_negative_zoom_factor() {
        for zoom in [-0.0001_f32, -1.0_f32, f32::NEG_INFINITY] {
            let mut wire = encode(&typical_pointing_command());
            wire[20..24].copy_from_slice(&zoom.to_be_bytes());
            match decode(&wire) {
                Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                    assert_eq!(field, "zoom_factor");
                }
                other => {
                    panic!("expected FieldOutOfRange/zoom_factor for zoom={zoom}, got {other:?}")
                }
            }
        }
    }

    // ---- Truncation sweep ----

    #[test]
    fn decode_truncation_sweep_returns_frame_too_short() {
        for &len in &[0_usize, 1, 4, 8, 12, 20, 28, 31] {
            let bytes = vec![0u8; len];
            let err = decode(&bytes).expect_err("truncation must error");
            match err {
                Stanag4586Error::FrameTooShort { actual, expected } => {
                    assert_eq!(actual, len);
                    assert_eq!(expected, SENSOR_POINTING_COMMAND_FRAME_LEN);
                }
                other => panic!("expected FrameTooShort, got {other:?}"),
            }
        }
    }

    // ---- Trailing-bytes-ignored ----

    #[test]
    fn decode_extra_trailing_bytes_are_ignored() {
        // A future protocol revision that appends a trailer must
        // not break consumers reading the documented prefix. Pin
        // that ANY trailer is tolerated up to a 64-byte input.
        let msg = typical_pointing_command();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(&[0xAA; 32]);
        assert_eq!(bytes.len(), 64);
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
    }

    // ---- PointingMode enum round-trip ----

    #[test]
    fn pointing_mode_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, PointingMode)] = &[
            (0x01, PointingMode::SlewToAzEl),
            (0x02, PointingMode::GeoLock),
            (0x03, PointingMode::GroundTarget),
            (0x04, PointingMode::Stow),
            (0xFF, PointingMode::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = PointingMode::from_byte(*byte);
            assert_eq!(decoded, *expected, "from_byte mismatch for byte={byte:#x}");
            assert_eq!(
                decoded.to_byte(),
                *byte,
                "to_byte mismatch for {expected:?}"
            );
        }
        // Unknown bytes outside the named table also round-trip via
        // `Other`. 0x00 is in this set — the encode side never emits
        // it for a named mode, so observing it on decode means the
        // upstream sent something unintended.
        for byte in [0x00u8, 0x05, 0x42, 0xEE] {
            let decoded = PointingMode::from_byte(byte);
            assert_eq!(decoded, PointingMode::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- Convenience method parity ----

    #[test]
    fn encode_to_vec_method_matches_free_encode_function() {
        // The struct-method convenience wrapper must produce
        // byte-identical output to the free function — no surprises
        // for callers who switch between styles.
        let msg = typical_pointing_command();
        assert_eq!(msg.encode_to_vec(), encode(&msg));
    }

    #[test]
    fn encode_into_appends_without_clearing_destination() {
        // `encode_into` is documented as additive — it must not
        // truncate or reorder existing bytes in `buf`. Pin that the
        // prefix bytes survive intact and the appended frame starts
        // at the original length.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        encode_into(&typical_pointing_command(), &mut buf);
        assert_eq!(buf.len(), 3 + SENSOR_POINTING_COMMAND_FRAME_LEN);
        assert_eq!(&buf[0..3], &[0xAA, 0xBB, 0xCC]);
        let standalone = encode(&typical_pointing_command());
        assert_eq!(&buf[3..], &standalone[..]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        // Property test: any valid struct round-trips byte-for-byte.
        // Constrain elevation to the gimbal range and zoom to
        // non-negative finite so the decoder doesn't reject the
        // property input — out-of-range and NaN rejection are their
        // own dedicated tests. Azimuth is intentionally constrained
        // to finite only (no range bound) to mirror the documented
        // unwrapped-azimuth contract.
        #[test]
        fn round_trip_via_proptest(
            vehicle_id in any::<u32>(),
            sensor_id in any::<u32>(),
            mode_byte in any::<u8>(),
            azimuth_deg in any::<f32>().prop_filter("finite", |f| f.is_finite()),
            elevation_deg in -90.0_f32..=90.0_f32,
            zoom_factor in (0.0_f32..=1_000_000.0_f32),
            dwell_secs in any::<u32>(),
        ) {
            let original = SensorPointingCommand {
                vehicle_id,
                sensor_id,
                pointing_mode: PointingMode::from_byte(mode_byte),
                azimuth_deg,
                elevation_deg,
                zoom_factor,
                dwell_secs,
            };
            let bytes = encode(&original);
            prop_assert_eq!(bytes.len(), SENSOR_POINTING_COMMAND_FRAME_LEN);
            let decoded = decode(&bytes).expect("decode round-trip");
            prop_assert_eq!(decoded, original);
        }
    }
}
