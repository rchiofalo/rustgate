// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! STANAG 4586 LOI 4 waypoint upload command message.
//!
//! Carries the first **command-side** message in the
//! `rustgate-stanag4586` crate. The previously-shipped LOI 2-3
//! telemetry frames ([`crate::vehicle_position`],
//! [`crate::sensor_status`], [`crate::payload_status`],
//! [`crate::system_state`], [`crate::bit_report`]) all flow inbound
//! from the Vehicle Specific Module to the Ground Control Station
//! — they are the **read-side** of the LOI 2-3 boundary. LOI 4
//! graduates the conversation to the **write-side**: the GCS now
//! emits messages that *direct* the platform, starting with a single
//! waypoint upload command.
//!
//! # Operational model
//!
//! A route is a sequence of waypoints, each waypoint identified by a
//! per-route [`WaypointCommand::waypoint_id`] sequence number. A
//! typical mission ships a small route (a handful of waypoints) up
//! front and then mutates it incrementally — adding a new waypoint at
//! the end, replacing a single waypoint mid-route, or aborting the
//! current command and rolling back to a hold pattern. Each mutation
//! is one `WaypointCommand` frame.
//!
//! [`CommandKind`] selects which of the four named command verbs the
//! waypoint represents, with an [`CommandKind::Other`] forward-compat
//! catch-all preserving any unrecognised wire byte so a future spec
//! revision that allocates a new verb stays decodable on a receiver
//! running today's build.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`WAYPOINT_COMMAND_FRAME_LEN`] = 32 bytes.
//!
//! ```text
//! offset │ size │ field           │ type
//! ───────┼──────┼─────────────────┼──────────────────────────
//!   0    │  4   │ vehicle_id      │ u32  big-endian
//!   4    │  4   │ waypoint_id     │ u32  big-endian
//!   8    │  1   │ command_kind    │ u8   enum value (see below)
//!   9    │  3   │ reserved        │ zero-padded — must be 0 on encode
//!  12    │  8   │ latitude_deg    │ f64  big-endian IEEE-754, WGS-84
//!  20    │  8   │ longitude_deg   │ f64  big-endian IEEE-754, WGS-84
//!  28    │  4   │ altitude_msl_m  │ f32  big-endian IEEE-754, MSL metres
//! ```
//!
//! The reserved block is zero-filled on encode. The decoder does NOT
//! validate it — a future spec revision that allocates the bytes
//! (e.g. a per-waypoint speed override or arrival tolerance) stays
//! backward-compatible at the frame-length level.
//!
//! # Field semantics
//!
//! - `vehicle_id` — the target platform identifier. Matches the
//!   `vehicle_id` carried by the LOI 2-3 telemetry frames so a GCS
//!   can correlate "which waypoint did I send to which platform"
//!   against "which platform's telemetry am I currently displaying"
//!   by direct byte comparison.
//! - `waypoint_id` — the per-route sequence number for this
//!   waypoint. A route mutation that replaces an existing waypoint
//!   re-uses its `waypoint_id`; an append uses the next unused
//!   number. The codec does not validate the relationship between
//!   `waypoint_id` and any prior route state — that is the GCS
//!   application layer's responsibility.
//! - `command_kind` — which command verb the waypoint represents.
//!   See [`CommandKind`].
//! - `latitude_deg` / `longitude_deg` — WGS-84 decimal degrees, the
//!   target position for the waypoint. Range-checked on decode:
//!   `lat ∈ [-90, 90]`, `lon ∈ [-180, 180]`. NaN explicitly rejected.
//!   Out-of-range values surface as
//!   [`Stanag4586Error::FieldOutOfRange`] rather than being silently
//!   clamped — they are typically a wire-format mismatch (wrong
//!   message type, byte-swap, …) and silent acceptance would hide
//!   the upstream defect.
//! - `altitude_msl_m` — target altitude above mean sea level, metres.
//!   Negative values are legal (waypoints in Death Valley, water-borne
//!   recovery points reporting depth) and not range-checked. NaN
//!   explicitly rejected — matches the discipline established by
//!   [`crate::system_state`] for its f32 fields.
//!
//! # What is deliberately absent
//!
//! - **Other LOI 4 commands** — sensor pointing, GCS handover,
//!   payload control, mode change. Each is a separate follow-up PR
//!   with its own wire format and validation rules.
//! - **Response / acknowledgement messages** — the bidirectional
//!   command-response handshake (the platform's "waypoint accepted"
//!   or "waypoint rejected, route invariant violated" reply) is a
//!   separate follow-up PR.
//! - **UDP/TCP listener wiring** — this module is pure encode/decode
//!   over `&[u8]`; the network glue is a separate change.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a waypoint command frame.
pub const WAYPOINT_COMMAND_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_WAYPOINT_ID: usize = 4;
const OFF_COMMAND_KIND: usize = 8;
// 9..12 reserved (3 bytes)
const OFF_LATITUDE: usize = 12;
const OFF_LONGITUDE: usize = 20;
const OFF_ALTITUDE: usize = 28;

/// Which command verb the waypoint represents.
///
/// The four named variants cover the LOI 4 minimum-viable command
/// vocabulary: navigate to a position ([`CommandKind::Goto`]), hold a
/// pattern at a position ([`CommandKind::Loiter`]), descend to land
/// at a position ([`CommandKind::Land`]), or abort the current
/// command and revert to a safe-hold behaviour
/// ([`CommandKind::Abort`]). [`CommandKind::Other`] preserves any
/// unrecognised wire byte so a future spec revision that allocates a
/// new verb stays decodable on a receiver running today's build —
/// matches the same forward-compat discipline used by every sibling
/// LOI 2-3 frame's enums.
///
/// # Wire byte values
///
/// | byte  | variant       |
/// |-------|---------------|
/// | `0x01`| `Goto`        |
/// | `0x02`| `Loiter`      |
/// | `0x03`| `Land`        |
/// | `0x04`| `Abort`       |
/// | other | `Other(byte)` |
///
/// `0x00` deliberately falls into [`CommandKind::Other`] rather than
/// having its own "Unknown" variant — the encode side never emits
/// `0x00` for a named verb, so observing one on decode means the
/// upstream sent something unintended and the operator should be
/// able to see the raw byte value in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    /// Navigate to the waypoint position.
    Goto,
    /// Hold a pattern at the waypoint position.
    Loiter,
    /// Descend to land at the waypoint position.
    Land,
    /// Abort the current command and revert to safe-hold behaviour.
    Abort,
    /// Forward-compat catch-all for command bytes the spec may
    /// allocate in a future revision.
    Other(u8),
}

impl CommandKind {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::Goto,
            0x02 => Self::Loiter,
            0x03 => Self::Land,
            0x04 => Self::Abort,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Goto => 0x01,
            Self::Loiter => 0x02,
            Self::Land => 0x03,
            Self::Abort => 0x04,
            Self::Other(b) => b,
        }
    }
}

/// LOI 4 waypoint upload command message.
#[derive(Debug, Clone, PartialEq)]
pub struct WaypointCommand {
    /// Target platform identifier (matches
    /// [`crate::vehicle_position::VehiclePosition::vehicle_id`]).
    pub vehicle_id: u32,
    /// Per-route waypoint sequence number.
    pub waypoint_id: u32,
    /// Which command verb the waypoint represents.
    pub command_kind: CommandKind,
    /// WGS-84 latitude, decimal degrees, range `[-90, 90]`.
    pub latitude_deg: f64,
    /// WGS-84 longitude, decimal degrees, range `[-180, 180]`.
    pub longitude_deg: f64,
    /// Target altitude above mean sea level, metres.
    pub altitude_msl_m: f32,
}

impl WaypointCommand {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a waypoint command frame into a freshly allocated `Vec<u8>`.
#[must_use]
pub fn encode(msg: &WaypointCommand) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(WAYPOINT_COMMAND_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
///
/// Useful when the encoded frame will be the body of a larger packet
/// and the caller wants to avoid the intermediate `Vec` allocation
/// of [`encode`]. Appends [`WAYPOINT_COMMAND_FRAME_LEN`] bytes; does
/// not clear or truncate `buf`.
pub fn encode_into(msg: &WaypointCommand, buf: &mut BytesMut) {
    buf.reserve(WAYPOINT_COMMAND_FRAME_LEN);
    buf.put_u32(msg.vehicle_id);
    buf.put_u32(msg.waypoint_id);
    buf.put_u8(msg.command_kind.to_byte());
    // 3 reserved bytes.
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_f64(msg.latitude_deg);
    buf.put_f64(msg.longitude_deg);
    buf.put_f32(msg.altitude_msl_m);
}

/// Decode a waypoint command frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
/// - [`Stanag4586Error::FieldOutOfRange`] if `latitude_deg` is NaN or
///   outside `[-90, 90]`.
/// - [`Stanag4586Error::FieldOutOfRange`] if `longitude_deg` is NaN
///   or outside `[-180, 180]`.
/// - [`Stanag4586Error::FieldOutOfRange`] if `altitude_msl_m` is NaN.
///
/// Trailing bytes beyond [`WAYPOINT_COMMAND_FRAME_LEN`] are ignored;
/// the codec is fixed-size and a future protocol revision that
/// appends fields keeps decoding the prefix unchanged.
///
/// Unrecognised `command_kind` bytes do NOT cause an error — they
/// surface as [`CommandKind::Other`] for forward compatibility.
pub fn decode(bytes: &[u8]) -> Result<WaypointCommand, Stanag4586Error> {
    if bytes.len() < WAYPOINT_COMMAND_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: WAYPOINT_COMMAND_FRAME_LEN,
        });
    }

    let mut cursor = &bytes[..WAYPOINT_COMMAND_FRAME_LEN];
    let vehicle_id = cursor.get_u32();
    let waypoint_id = cursor.get_u32();
    let command_kind = CommandKind::from_byte(cursor.get_u8());
    // Skip 3-byte reserved region.
    cursor.advance(3);
    let latitude_deg = f64::from_bits(cursor.get_u64());
    let longitude_deg = f64::from_bits(cursor.get_u64());
    let altitude_msl_m = f32::from_bits(cursor.get_u32());

    debug_assert!(
        cursor.is_empty(),
        "fixed-size frame should be fully consumed; bug in offset constants"
    );
    let _ = OFF_VEHICLE_ID;
    let _ = OFF_WAYPOINT_ID;
    let _ = OFF_COMMAND_KIND;
    let _ = OFF_LATITUDE;
    let _ = OFF_LONGITUDE;
    let _ = OFF_ALTITUDE;

    if latitude_deg.is_nan() || !(-90.0..=90.0).contains(&latitude_deg) {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "latitude_deg",
            value: latitude_deg.to_string(),
        });
    }
    if longitude_deg.is_nan() || !(-180.0..=180.0).contains(&longitude_deg) {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "longitude_deg",
            value: longitude_deg.to_string(),
        });
    }
    if altitude_msl_m.is_nan() {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "altitude_msl_m",
            value: altitude_msl_m.to_string(),
        });
    }

    Ok(WaypointCommand {
        vehicle_id,
        waypoint_id,
        command_kind,
        latitude_deg,
        longitude_deg,
        altitude_msl_m,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Mid-range typical waypoint fixture. Deliberately non-default
    /// values so an `assert_eq!` mismatch points at the right field.
    fn typical_waypoint() -> WaypointCommand {
        WaypointCommand {
            vehicle_id: 0xA1B2_C3D4,
            waypoint_id: 7,
            command_kind: CommandKind::Goto,
            latitude_deg: 38.889_722_2,
            longitude_deg: -77.008_889,
            altitude_msl_m: 1234.5_f32,
        }
    }

    // ---- Round-trip ----

    #[test]
    fn round_trip_zero_valued_fixture() {
        // All-zero is a valid frame: vehicle_id=0, waypoint_id=0,
        // command_kind defaults to Other(0) (forward-compat catch-all
        // preserves the byte), all coordinates zero. The round-trip
        // must hold even at this corner.
        let msg = WaypointCommand {
            vehicle_id: 0,
            waypoint_id: 0,
            command_kind: CommandKind::Other(0),
            latitude_deg: 0.0,
            longitude_deg: 0.0,
            altitude_msl_m: 0.0,
        };
        let bytes = encode(&msg);
        assert_eq!(bytes, vec![0u8; WAYPOINT_COMMAND_FRAME_LEN]);
        let decoded = decode(&bytes).expect("zero round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_max_range_valid_fixture() {
        // Pin the upper edges of the integer fields and the WGS-84
        // valid range. A regression that swapped a u32 to a smaller
        // type would silently truncate at the max value and fail
        // this test; a regression that tightened the lat/lon bounds
        // by one ULP would reject the boundary value here.
        let msg = WaypointCommand {
            vehicle_id: u32::MAX,
            waypoint_id: u32::MAX,
            command_kind: CommandKind::Abort,
            latitude_deg: 90.0,
            longitude_deg: 180.0,
            altitude_msl_m: -413.0, // Dead Sea shore — sub-MSL is legal
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("max round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_typical_waypoint_fixture() {
        let msg = typical_waypoint();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), WAYPOINT_COMMAND_FRAME_LEN);
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
        //   vehicle_id     = 0x1122_3344
        //   waypoint_id    = 0xAABB_CCDD
        //   command_kind   = 0x01 (Goto)
        //   latitude_deg   = 37.7749
        //   longitude_deg  = -122.4194
        //   altitude_msl_m = 1500.0
        let msg = WaypointCommand {
            vehicle_id: 0x1122_3344,
            waypoint_id: 0xAABB_CCDD,
            command_kind: CommandKind::Goto,
            latitude_deg: 37.7749,
            longitude_deg: -122.4194,
            altitude_msl_m: 1500.0,
        };
        let bytes = encode(&msg);
        let expected: [u8; WAYPOINT_COMMAND_FRAME_LEN] = [
            // vehicle_id = 0x1122_3344 (big-endian)
            0x11, 0x22, 0x33, 0x44, //
            // waypoint_id = 0xAABB_CCDD (big-endian)
            0xAA, 0xBB, 0xCC, 0xDD, //
            // command_kind = 0x01 (Goto)
            0x01, //
            // 3 reserved zero bytes
            0x00, 0x00, 0x00, //
            // latitude_deg = 37.7749 → IEEE-754 big-endian
            0x40, 0x42, 0xE3, 0x2F, 0xEC, 0x56, 0xD5, 0xD0, //
            // longitude_deg = -122.4194 → IEEE-754 big-endian
            0xC0, 0x5E, 0x9A, 0xD7, 0x73, 0x18, 0xFC, 0x50, //
            // altitude_msl_m = 1500.0 → IEEE-754 big-endian (0x44BB8000)
            0x44, 0xBB, 0x80, 0x00,
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
    fn decode_rejects_nan_latitude_deg() {
        // NaN passes neither `<` nor `>` so a naive range check would
        // accept it. Pin that we explicitly reject NaN as a sanity
        // gate — a NaN coordinate is never legitimate command input.
        let mut wire = encode(&typical_waypoint());
        wire[12..20].copy_from_slice(&f64::NAN.to_be_bytes());
        match decode(&wire) {
            Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "latitude_deg");
            }
            other => panic!("expected FieldOutOfRange/latitude_deg, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_nan_longitude_deg() {
        let mut wire = encode(&typical_waypoint());
        wire[20..28].copy_from_slice(&f64::NAN.to_be_bytes());
        match decode(&wire) {
            Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "longitude_deg");
            }
            other => panic!("expected FieldOutOfRange/longitude_deg, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_nan_altitude_msl_m() {
        // Altitude is not range-checked (sub-MSL is legal) but NaN
        // is still poison and must be rejected — matches the
        // discipline established by `system_state` for its f32
        // fields.
        let mut wire = encode(&typical_waypoint());
        wire[28..32].copy_from_slice(&f32::NAN.to_be_bytes());
        match decode(&wire) {
            Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "altitude_msl_m");
            }
            other => panic!("expected FieldOutOfRange/altitude_msl_m, got {other:?}"),
        }
    }

    // ---- Range rejection ----

    #[test]
    fn decode_rejects_latitude_out_of_range() {
        for lat in [91.0_f64, -91.0_f64] {
            let mut wire = encode(&typical_waypoint());
            wire[12..20].copy_from_slice(&lat.to_be_bytes());
            match decode(&wire) {
                Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                    assert_eq!(field, "latitude_deg");
                }
                other => {
                    panic!("expected FieldOutOfRange/latitude_deg for lat={lat}, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn decode_rejects_longitude_out_of_range() {
        for lon in [180.0001_f64, -180.0001_f64] {
            let mut wire = encode(&typical_waypoint());
            wire[20..28].copy_from_slice(&lon.to_be_bytes());
            match decode(&wire) {
                Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                    assert_eq!(field, "longitude_deg");
                }
                other => {
                    panic!("expected FieldOutOfRange/longitude_deg for lon={lon}, got {other:?}")
                }
            }
        }
    }

    // ---- Truncation sweep ----

    #[test]
    fn decode_truncation_sweep_returns_frame_too_short() {
        for &len in &[0_usize, 1, 4, 12, 20, 28, 31] {
            let bytes = vec![0u8; len];
            let err = decode(&bytes).expect_err("truncation must error");
            match err {
                Stanag4586Error::FrameTooShort { actual, expected } => {
                    assert_eq!(actual, len);
                    assert_eq!(expected, WAYPOINT_COMMAND_FRAME_LEN);
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
        let msg = typical_waypoint();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(&[0xAA; 32]);
        assert_eq!(bytes.len(), 64);
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
    }

    // ---- CommandKind enum round-trip ----

    #[test]
    fn command_kind_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, CommandKind)] = &[
            (0x01, CommandKind::Goto),
            (0x02, CommandKind::Loiter),
            (0x03, CommandKind::Land),
            (0x04, CommandKind::Abort),
            (0xFF, CommandKind::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = CommandKind::from_byte(*byte);
            assert_eq!(decoded, *expected, "from_byte mismatch for byte={byte:#x}");
            assert_eq!(
                decoded.to_byte(),
                *byte,
                "to_byte mismatch for {expected:?}"
            );
        }
        // Unknown bytes outside the named table also round-trip via
        // `Other`. 0x00 is in this set — the encode side never emits
        // it for a named verb, so observing it on decode means the
        // upstream sent something unintended.
        for byte in [0x00u8, 0x05, 0x42, 0xEE] {
            let decoded = CommandKind::from_byte(byte);
            assert_eq!(decoded, CommandKind::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- Convenience method parity ----

    #[test]
    fn encode_to_vec_method_matches_free_encode_function() {
        // The struct-method convenience wrapper must produce
        // byte-identical output to the free function — no surprises
        // for callers who switch between styles.
        let msg = typical_waypoint();
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
        encode_into(&typical_waypoint(), &mut buf);
        assert_eq!(buf.len(), 3 + WAYPOINT_COMMAND_FRAME_LEN);
        assert_eq!(&buf[0..3], &[0xAA, 0xBB, 0xCC]);
        let standalone = encode(&typical_waypoint());
        assert_eq!(&buf[3..], &standalone[..]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        // Property test: any valid struct round-trips byte-for-byte.
        // Constrain lat/lon to the WGS-84 range and altitude to finite
        // f32 so the decoder doesn't reject the property input —
        // out-of-range and NaN rejection are their own dedicated tests.
        #[test]
        fn round_trip_via_proptest(
            vehicle_id in any::<u32>(),
            waypoint_id in any::<u32>(),
            command_byte in any::<u8>(),
            latitude_deg in -90.0_f64..=90.0_f64,
            longitude_deg in -180.0_f64..=180.0_f64,
            altitude_msl_m in any::<f32>().prop_filter("finite", |f| f.is_finite()),
        ) {
            let original = WaypointCommand {
                vehicle_id,
                waypoint_id,
                command_kind: CommandKind::from_byte(command_byte),
                latitude_deg,
                longitude_deg,
                altitude_msl_m,
            };
            let bytes = encode(&original);
            prop_assert_eq!(bytes.len(), WAYPOINT_COMMAND_FRAME_LEN);
            let decoded = decode(&bytes).expect("decode round-trip");
            prop_assert_eq!(decoded, original);
        }
    }
}
