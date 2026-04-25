// Copyright © 2026 Roberto Chiofalo.

//! STANAG 4586 LOI 2-3 vehicle position telemetry message.
//!
//! Carries the inbound vehicle state stream that any LOI 2 deployment
//! needs to display, log, and relay: position (lat/lon/alt), kinematic
//! state (ground speed, heading), the discrete flight-state enum, the
//! vehicle id, and a Unix-millis timestamp from the platform.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total frame
//! size is fixed at [`VEHICLE_POSITION_FRAME_LEN`] = 48 bytes.
//!
//! ```text
//! offset │ size │ field             │ type
//! ───────┼──────┼───────────────────┼──────────────────────────
//!   0    │  4   │ vehicle_id        │ u32  big-endian
//!   4    │  1   │ flight_state      │ u8   enum value (see below)
//!   5    │  3   │ reserved          │ zero-padded — must be 0 on encode
//!   8    │  8   │ latitude_deg      │ f64  big-endian IEEE-754
//!  16    │  8   │ longitude_deg     │ f64  big-endian IEEE-754
//!  24    │  4   │ altitude_msl_m    │ f32  big-endian IEEE-754
//!  28    │  4   │ ground_speed_mps  │ f32  big-endian IEEE-754
//!  32    │  4   │ heading_deg       │ f32  big-endian IEEE-754
//!  36    │  4   │ reserved          │ zero-padded — must be 0 on encode
//!  40    │  8   │ timestamp_unix_ms │ u64  big-endian
//! ```
//!
//! The two reserved blocks are zero-filled on encode. The decoder
//! does NOT validate that they are zero on the wire so a future
//! protocol revision that allocates them stays backward-compatible
//! at the frame-length level — `decode` will simply ignore the bytes
//! until those fields are wired into the struct.
//!
//! # Field semantics
//!
//! - `vehicle_id` — opaque platform identifier assigned by the GCS.
//!   Distinct from the MAVLink `system id` even when STANAG 4586 is
//!   wrapping MAVLink: the same physical UAV may have a MAVLink id
//!   chosen by the autopilot vendor and a STANAG vehicle id chosen
//!   by the GCS operator.
//! - `latitude_deg` / `longitude_deg` — WGS-84 decimal degrees.
//!   Range-checked on decode: lat ∈ [-90, 90], lon ∈ [-180, 180].
//!   Out-of-range values surface as
//!   [`Stanag4586Error::FieldOutOfRange`] rather than being silently
//!   clamped, because they are typically a wire-format mismatch
//!   (wrong message type, byte-swap, …) and silent acceptance would
//!   hide the upstream defect.
//! - `altitude_msl_m` — altitude above mean sea level, metres.
//!   Negative values are legal (Death Valley telemetry, water-borne
//!   platforms reporting depth) and not range-checked.
//! - `ground_speed_mps` — over-ground speed, m/s.
//! - `heading_deg` — true heading, degrees clockwise from north.
//!   Not range-checked because a sender may transmit signed or
//!   unwrapped headings during turn integration; consumers that
//!   need a normalised `[0, 360)` value normalise downstream.
//! - `flight_state` — discrete platform state. See [`FlightState`].
//!   An unrecognised byte does NOT cause decode failure; it surfaces
//!   as [`FlightState::Other`] so a firmware revision that adds new
//!   states stays compatible with older decoders.
//! - `timestamp_unix_ms` — milliseconds since the Unix epoch. The
//!   spec leaves clock source implementation-defined; the field is
//!   carried opaque. Monotonicity / freshness checks live in the
//!   session layer (future PR) where they can also detect replay.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a vehicle-position frame.
///
/// The frame is fixed-length by spec — there are no variable trailers
/// or option fields. This makes the codec a straight slice-into-struct
/// transformation with no length prefix needed.
pub const VEHICLE_POSITION_FRAME_LEN: usize = 48;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_FLIGHT_STATE: usize = 4;
// 5..8 reserved (3 bytes)
const OFF_LATITUDE: usize = 8;
const OFF_LONGITUDE: usize = 16;
const OFF_ALTITUDE: usize = 24;
const OFF_GROUND_SPEED: usize = 28;
const OFF_HEADING: usize = 32;
// 36..40 reserved (4 bytes)
const OFF_TIMESTAMP: usize = 40;

/// Discrete flight-state enum carried in byte offset 4 of the frame.
///
/// The byte values pinned here match the publicly documented STANAG
/// 4586 vehicle-state enumeration. [`FlightState::Other`] preserves
/// any byte the decoder does not recognise so a firmware revision
/// that introduces a new state survives this version of the codec
/// rather than being rejected at the framing layer — the decoder is
/// in the read path, where forward-compat matters more than strict
/// rejection.
///
/// # Wire byte values
///
/// | byte  | variant               |
/// |-------|-----------------------|
/// | `0x01`| `LaunchPreparation`   |
/// | `0x02`| `Loiter`              |
/// | `0x03`| `Transit`             |
/// | `0x04`| `ReturnToBase`        |
/// | `0x05`| `Landed`              |
/// | other | `Other(byte)`         |
///
/// `0x00` deliberately falls into [`FlightState::Other`] rather than
/// having its own "Unknown" variant — the encode side never emits
/// `0x00`, so observing one on decode means the upstream sent
/// something unintended and the operator should be able to see the
/// raw byte value in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlightState {
    /// Pre-flight on the launcher / runway.
    LaunchPreparation,
    /// Holding pattern, on station.
    Loiter,
    /// En route between waypoints.
    Transit,
    /// Returning to base / recovery point.
    ReturnToBase,
    /// On the ground, post-flight.
    Landed,
    /// Forward-compat catch-all for byte values this version of the
    /// codec does not recognise. Carries the raw wire byte so logs
    /// surface what the upstream actually sent.
    Other(u8),
}

impl FlightState {
    /// Wire-byte representation. Inverse of [`FlightState::from_byte`].
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::LaunchPreparation => 0x01,
            Self::Loiter => 0x02,
            Self::Transit => 0x03,
            Self::ReturnToBase => 0x04,
            Self::Landed => 0x05,
            Self::Other(b) => b,
        }
    }

    /// Decode a wire byte. Unknown bytes produce [`FlightState::Other`]
    /// rather than an error so a forward-revision firmware is still
    /// readable by an older codec.
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::LaunchPreparation,
            0x02 => Self::Loiter,
            0x03 => Self::Transit,
            0x04 => Self::ReturnToBase,
            0x05 => Self::Landed,
            other => Self::Other(other),
        }
    }
}

/// LOI 2-3 vehicle position telemetry message.
///
/// Construct directly and round-trip through [`encode`] / [`decode`].
/// `PartialEq` is derived so callers can assert exact equality — the
/// codec preserves every typed field across the round trip.
#[derive(Debug, Clone, PartialEq)]
pub struct VehiclePosition {
    /// GCS-assigned platform identifier. Big-endian on wire.
    pub vehicle_id: u32,
    /// Discrete platform state. See [`FlightState`].
    pub flight_state: FlightState,
    /// WGS-84 latitude, decimal degrees, range `[-90, 90]`.
    pub latitude_deg: f64,
    /// WGS-84 longitude, decimal degrees, range `[-180, 180]`.
    pub longitude_deg: f64,
    /// Altitude above mean sea level, metres.
    pub altitude_msl_m: f32,
    /// Ground speed, metres per second.
    pub ground_speed_mps: f32,
    /// True heading, degrees clockwise from north.
    pub heading_deg: f32,
    /// Platform-supplied timestamp, Unix milliseconds.
    pub timestamp_unix_ms: u64,
}

impl VehiclePosition {
    /// Encode `self` into a fresh [`Vec<u8>`] of exactly
    /// [`VEHICLE_POSITION_FRAME_LEN`] bytes.
    ///
    /// Convenience wrapper around the free [`encode`] function for
    /// callers that prefer a method receiver.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode `msg` into a fresh [`Vec<u8>`] of exactly
/// [`VEHICLE_POSITION_FRAME_LEN`] bytes.
///
/// All multi-byte fields are big-endian. Reserved padding regions are
/// zero-filled. The output is suitable for direct write to a UDP
/// socket or for nesting inside a higher-level container (length-
/// prefixed framing arrives in a follow-up PR).
#[must_use]
pub fn encode(msg: &VehiclePosition) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(VEHICLE_POSITION_FRAME_LEN);
    // Pre-zero the buffer so the two reserved regions are guaranteed
    // zero without per-region put_u24/put_u32 calls cluttering the
    // sequence. `resize` initialises to zero.
    buf.resize(VEHICLE_POSITION_FRAME_LEN, 0);

    // Write each field by absolute offset rather than sequentially via
    // `put_*`. Indexing keeps the wire layout visible at each line
    // (cross-checkable against the table at the top of this file) and
    // makes the encoder robust to a future field reordering: the only
    // way to break the on-wire byte order is to also update the
    // OFF_* constant.
    buf[OFF_VEHICLE_ID..OFF_VEHICLE_ID + 4].copy_from_slice(&msg.vehicle_id.to_be_bytes());
    buf[OFF_FLIGHT_STATE] = msg.flight_state.to_byte();
    // 5..8 reserved — already zero from the resize above.
    buf[OFF_LATITUDE..OFF_LATITUDE + 8].copy_from_slice(&msg.latitude_deg.to_be_bytes());
    buf[OFF_LONGITUDE..OFF_LONGITUDE + 8].copy_from_slice(&msg.longitude_deg.to_be_bytes());
    buf[OFF_ALTITUDE..OFF_ALTITUDE + 4].copy_from_slice(&msg.altitude_msl_m.to_be_bytes());
    buf[OFF_GROUND_SPEED..OFF_GROUND_SPEED + 4]
        .copy_from_slice(&msg.ground_speed_mps.to_be_bytes());
    buf[OFF_HEADING..OFF_HEADING + 4].copy_from_slice(&msg.heading_deg.to_be_bytes());
    // 36..40 reserved — already zero from the resize above.
    buf[OFF_TIMESTAMP..OFF_TIMESTAMP + 8].copy_from_slice(&msg.timestamp_unix_ms.to_be_bytes());

    buf.to_vec()
}

/// Decode a vehicle position frame from `bytes`.
///
/// Returns an error if:
///
/// - `bytes.len() < VEHICLE_POSITION_FRAME_LEN` —
///   [`Stanag4586Error::FrameTooShort`].
/// - `latitude_deg` or `longitude_deg` is outside the WGS-84 valid
///   range — [`Stanag4586Error::FieldOutOfRange`].
///
/// Trailing bytes beyond [`VEHICLE_POSITION_FRAME_LEN`] are ignored;
/// the codec is fixed-size and a future protocol revision that
/// appends fields keeps decoding the prefix unchanged.
///
/// Unrecognised `flight_state` bytes do NOT cause an error — they
/// surface as [`FlightState::Other`] for forward compatibility.
pub fn decode(bytes: &[u8]) -> Result<VehiclePosition, Stanag4586Error> {
    if bytes.len() < VEHICLE_POSITION_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: VEHICLE_POSITION_FRAME_LEN,
        });
    }

    // Slice the fixed-length prefix and read field-by-field. `Buf`
    // advances an internal cursor, so each `get_*` call moves past
    // the bytes it consumed. The order matches the wire layout.
    let mut cur = &bytes[..VEHICLE_POSITION_FRAME_LEN];
    let vehicle_id = cur.get_u32();
    let flight_state = FlightState::from_byte(cur.get_u8());
    // Skip 3-byte reserved region.
    cur.advance(3);
    let latitude_deg = f64::from_bits(cur.get_u64());
    let longitude_deg = f64::from_bits(cur.get_u64());
    let altitude_msl_m = f32::from_bits(cur.get_u32());
    let ground_speed_mps = f32::from_bits(cur.get_u32());
    let heading_deg = f32::from_bits(cur.get_u32());
    // Skip 4-byte reserved region.
    cur.advance(4);
    let timestamp_unix_ms = cur.get_u64();
    debug_assert!(
        cur.is_empty(),
        "fixed-size frame should be fully consumed; bug in offset constants"
    );

    if !(-90.0..=90.0).contains(&latitude_deg) || latitude_deg.is_nan() {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "latitude_deg",
            value: latitude_deg.to_string(),
        });
    }
    if !(-180.0..=180.0).contains(&longitude_deg) || longitude_deg.is_nan() {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "longitude_deg",
            value: longitude_deg.to_string(),
        });
    }

    Ok(VehiclePosition {
        vehicle_id,
        flight_state,
        latitude_deg,
        longitude_deg,
        altitude_msl_m,
        ground_speed_mps,
        heading_deg,
        timestamp_unix_ms,
    })
}

/// Encode `msg` directly into a [`BytesMut`] caller-supplied buffer.
///
/// Useful when the encoded frame will be the body of a larger packet
/// and the caller wants to avoid the intermediate `Vec` allocation
/// of [`encode`]. Appends [`VEHICLE_POSITION_FRAME_LEN`] bytes; does
/// not clear or truncate `dst`.
pub fn encode_into(msg: &VehiclePosition, dst: &mut BytesMut) {
    dst.reserve(VEHICLE_POSITION_FRAME_LEN);
    dst.put_u32(msg.vehicle_id);
    dst.put_u8(msg.flight_state.to_byte());
    // 3 reserved bytes.
    dst.put_u8(0);
    dst.put_u8(0);
    dst.put_u8(0);
    dst.put_f64(msg.latitude_deg);
    dst.put_f64(msg.longitude_deg);
    dst.put_f32(msg.altitude_msl_m);
    dst.put_f32(msg.ground_speed_mps);
    dst.put_f32(msg.heading_deg);
    // 4 reserved bytes.
    dst.put_u32(0);
    dst.put_u64(msg.timestamp_unix_ms);
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Build a non-trivial fixture so equality comparisons aren't
    /// passing because every field happens to be the type's default.
    fn sample() -> VehiclePosition {
        VehiclePosition {
            vehicle_id: 0xA1B2_C3D4,
            flight_state: FlightState::Transit,
            latitude_deg: 38.889_722_2,
            longitude_deg: -77.008_889,
            altitude_msl_m: 1234.5_f32,
            ground_speed_mps: 42.0_f32,
            heading_deg: 271.5_f32,
            timestamp_unix_ms: 1_700_000_000_123,
        }
    }

    // ---- Round-trip ----

    #[test]
    fn encode_decode_round_trip_preserves_fields() {
        let cases = [
            sample(),
            VehiclePosition {
                vehicle_id: 0,
                flight_state: FlightState::LaunchPreparation,
                latitude_deg: 0.0,
                longitude_deg: 0.0,
                altitude_msl_m: 0.0,
                ground_speed_mps: 0.0,
                heading_deg: 0.0,
                timestamp_unix_ms: 0,
            },
            VehiclePosition {
                vehicle_id: u32::MAX,
                flight_state: FlightState::Landed,
                latitude_deg: 90.0,
                longitude_deg: 180.0,
                altitude_msl_m: -413.0, // Dead Sea shore — sub-MSL is legal
                ground_speed_mps: 100.0,
                heading_deg: 359.999,
                timestamp_unix_ms: u64::MAX,
            },
            VehiclePosition {
                vehicle_id: 17,
                flight_state: FlightState::Other(0xEE),
                latitude_deg: -89.999_999,
                longitude_deg: -179.999_999,
                altitude_msl_m: f32::INFINITY, // bit-pattern preserved
                ground_speed_mps: f32::NEG_INFINITY,
                heading_deg: 0.0,
                timestamp_unix_ms: 1,
            },
        ];

        for original in cases {
            let bytes = encode(&original);
            assert_eq!(bytes.len(), VEHICLE_POSITION_FRAME_LEN);
            let decoded = decode(&bytes).expect("round-trip decode");
            assert_eq!(decoded, original, "round trip mismatch");
        }
    }

    proptest! {
        // Property test: any valid struct round-trips byte-for-byte.
        // Constrain lat/lon to the WGS-84 range so the decoder doesn't
        // reject the property input — out-of-range rejection is its
        // own dedicated test.
        #[test]
        fn proptest_round_trip(
            vehicle_id in any::<u32>(),
            state_byte in any::<u8>(),
            latitude_deg in -90.0_f64..=90.0_f64,
            longitude_deg in -180.0_f64..=180.0_f64,
            altitude_msl_m in any::<f32>().prop_filter("finite", |f| f.is_finite()),
            ground_speed_mps in any::<f32>().prop_filter("finite", |f| f.is_finite()),
            heading_deg in any::<f32>().prop_filter("finite", |f| f.is_finite()),
            timestamp_unix_ms in any::<u64>(),
        ) {
            let original = VehiclePosition {
                vehicle_id,
                flight_state: FlightState::from_byte(state_byte),
                latitude_deg,
                longitude_deg,
                altitude_msl_m,
                ground_speed_mps,
                heading_deg,
                timestamp_unix_ms,
            };
            let bytes = encode(&original);
            prop_assert_eq!(bytes.len(), VEHICLE_POSITION_FRAME_LEN);
            let decoded = decode(&bytes).expect("decode after encode");
            prop_assert_eq!(decoded, original);
        }
    }

    // ---- Golden fixture ----

    #[test]
    fn decode_known_fixture_matches_expected_fields() {
        // Hand-built fixture: every field placed at its documented
        // byte offset, big-endian. If the encode side regresses the
        // wire layout, this fixture's decode will produce wrong
        // values and the assertions fail. The byte values are derived
        // from the documented field set + NATO big-endian convention;
        // see CHANGELOG provenance note.
        //
        // Field values:
        //   vehicle_id        = 0x0000_002A (= 42)
        //   flight_state      = 0x03 (Transit)
        //   latitude_deg      = 51.5    (London-ish)
        //   longitude_deg     = -0.125
        //   altitude_msl_m    = 100.0
        //   ground_speed_mps  = 25.0
        //   heading_deg       = 90.0
        //   timestamp_unix_ms = 0x0000_0001_0000_0000 (= 4_294_967_296)
        let mut wire = [0u8; VEHICLE_POSITION_FRAME_LEN];
        wire[0..4].copy_from_slice(&42u32.to_be_bytes());
        wire[4] = 0x03;
        // 5..8 reserved (zero)
        wire[8..16].copy_from_slice(&51.5_f64.to_be_bytes());
        wire[16..24].copy_from_slice(&(-0.125_f64).to_be_bytes());
        wire[24..28].copy_from_slice(&100.0_f32.to_be_bytes());
        wire[28..32].copy_from_slice(&25.0_f32.to_be_bytes());
        wire[32..36].copy_from_slice(&90.0_f32.to_be_bytes());
        // 36..40 reserved (zero)
        wire[40..48].copy_from_slice(&4_294_967_296u64.to_be_bytes());

        let decoded = decode(&wire).expect("fixture decodes");
        assert_eq!(decoded.vehicle_id, 42);
        assert_eq!(decoded.flight_state, FlightState::Transit);
        assert_eq!(decoded.latitude_deg, 51.5);
        assert_eq!(decoded.longitude_deg, -0.125);
        assert_eq!(decoded.altitude_msl_m, 100.0);
        assert_eq!(decoded.ground_speed_mps, 25.0);
        assert_eq!(decoded.heading_deg, 90.0);
        assert_eq!(decoded.timestamp_unix_ms, 4_294_967_296);
    }

    // ---- Truncation ----

    #[test]
    fn decode_truncated_frame_returns_error() {
        // Anything below the fixed length must fail with the
        // dedicated truncation variant — never panic, never
        // attempt to decode garbage.
        for len in [0, 1, 7, 24, VEHICLE_POSITION_FRAME_LEN - 1] {
            let buf = vec![0u8; len];
            match decode(&buf) {
                Err(Stanag4586Error::FrameTooShort { actual, expected }) => {
                    assert_eq!(actual, len);
                    assert_eq!(expected, VEHICLE_POSITION_FRAME_LEN);
                }
                Err(other) => panic!("unexpected error variant: {other:?}"),
                Ok(_) => panic!("decoded a {len}-byte frame as if it were valid"),
            }
        }
    }

    #[test]
    fn decode_extra_trailing_bytes_are_ignored() {
        // Trailing bytes beyond the fixed length should not affect
        // decode. This pins forward-compatibility: a future protocol
        // revision that appends an extension trailer must still
        // round-trip through this decoder for the prefix.
        let mut bytes = encode(&sample());
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let decoded = decode(&bytes).expect("trailing bytes should not break decode");
        assert_eq!(decoded, sample());
    }

    // ---- Range validation ----

    #[test]
    fn decode_rejects_latitude_above_90() {
        let mut wire = encode(&sample());
        wire[8..16].copy_from_slice(&90.0001_f64.to_be_bytes());
        match decode(&wire) {
            Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "latitude_deg");
            }
            other => panic!("expected FieldOutOfRange/latitude_deg, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_longitude_below_neg180() {
        let mut wire = encode(&sample());
        wire[16..24].copy_from_slice(&(-180.0001_f64).to_be_bytes());
        match decode(&wire) {
            Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "longitude_deg");
            }
            other => panic!("expected FieldOutOfRange/longitude_deg, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_nan_latitude() {
        // NaN passes neither `<` nor `>` so a naive range check would
        // accept it. Pin that we explicitly reject NaN as a sanity
        // gate — a NaN coordinate is never legitimate telemetry and
        // would just propagate poison values into the rest of the
        // stack.
        let mut wire = encode(&sample());
        wire[8..16].copy_from_slice(&f64::NAN.to_be_bytes());
        assert!(matches!(
            decode(&wire),
            Err(Stanag4586Error::FieldOutOfRange {
                field: "latitude_deg",
                ..
            })
        ));
    }

    // ---- Flight state forward-compat ----

    #[test]
    fn flight_state_unknown_byte_falls_back_to_other() {
        // A byte value the codec does not recognise must surface as
        // FlightState::Other carrying the raw byte — never as a
        // decode error. This is the forward-compatibility contract.
        for byte in [0x00u8, 0x06, 0x10, 0x42, 0xFF] {
            let mut wire = encode(&sample());
            wire[OFF_FLIGHT_STATE] = byte;
            let decoded = decode(&wire).expect("unknown state byte must not error");
            assert_eq!(decoded.flight_state, FlightState::Other(byte));
        }
    }

    #[test]
    fn flight_state_to_byte_round_trips_for_known_variants() {
        // Pin the wire-byte ↔ variant table at the top of the file:
        // every named variant must round-trip its assigned byte.
        for variant in [
            FlightState::LaunchPreparation,
            FlightState::Loiter,
            FlightState::Transit,
            FlightState::ReturnToBase,
            FlightState::Landed,
        ] {
            let byte = variant.to_byte();
            assert_eq!(FlightState::from_byte(byte), variant);
        }
    }

    #[test]
    fn flight_state_other_round_trips_arbitrary_byte() {
        // The Other(byte) wrapper must preserve the byte verbatim
        // through both directions — not normalise to 0 or any other
        // sentinel. This is what lets the decoder be lossless across
        // a forward firmware revision.
        for byte in [0x00u8, 0x42, 0xEE, 0xFF] {
            assert_eq!(FlightState::Other(byte).to_byte(), byte);
            // The named variants 0x01..=0x05 won't survive a
            // from_byte round-trip from `Other(byte)` — they get
            // normalised to the named variant — so skip those bytes
            // for this assertion. That normalisation is the whole
            // point of having named variants in the first place.
            if !(0x01..=0x05).contains(&byte) {
                assert_eq!(FlightState::from_byte(byte), FlightState::Other(byte));
            }
        }
    }

    // ---- Wire-format pin ----

    #[test]
    fn encode_produces_documented_byte_layout() {
        // Pin the exact byte order documented at the top of the
        // file. A regression that swapped to little-endian, reordered
        // fields, or shrunk a reserved region would fail here even
        // if the property test still passed (the round trip is
        // self-consistent — it doesn't notice if both encode and
        // decode silently agreed on a byte-swap).
        let msg = VehiclePosition {
            vehicle_id: 0x1122_3344,
            flight_state: FlightState::Loiter,
            latitude_deg: 1.0,
            longitude_deg: 2.0,
            altitude_msl_m: 3.0,
            ground_speed_mps: 4.0,
            heading_deg: 5.0,
            timestamp_unix_ms: 0xDEAD_BEEF_CAFE_0042,
        };
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), VEHICLE_POSITION_FRAME_LEN);

        // vehicle_id big-endian
        assert_eq!(&bytes[0..4], &[0x11, 0x22, 0x33, 0x44]);
        // flight_state Loiter = 0x02
        assert_eq!(bytes[4], 0x02);
        // 5..8 reserved must be zero
        assert_eq!(&bytes[5..8], &[0, 0, 0]);
        // latitude_deg = 1.0 → IEEE-754 big-endian 0x3FF00000_00000000
        assert_eq!(
            &bytes[8..16],
            &[0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        // longitude_deg = 2.0 → 0x40000000_00000000
        assert_eq!(
            &bytes[16..24],
            &[0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        // altitude_msl_m = 3.0 → 0x40400000
        assert_eq!(&bytes[24..28], &[0x40, 0x40, 0x00, 0x00]);
        // ground_speed_mps = 4.0 → 0x40800000
        assert_eq!(&bytes[28..32], &[0x40, 0x80, 0x00, 0x00]);
        // heading_deg = 5.0 → 0x40A00000
        assert_eq!(&bytes[32..36], &[0x40, 0xA0, 0x00, 0x00]);
        // 36..40 reserved must be zero
        assert_eq!(&bytes[36..40], &[0, 0, 0, 0]);
        // timestamp_unix_ms big-endian
        assert_eq!(
            &bytes[40..48],
            &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x42]
        );
    }

    #[test]
    fn encode_into_appends_without_clearing_destination() {
        // `encode_into` is documented as additive — it must not
        // truncate or reorder existing bytes in `dst`. Pin that
        // the prefix bytes survive intact and the appended frame
        // starts at the original length.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        encode_into(&sample(), &mut buf);
        assert_eq!(buf.len(), 3 + VEHICLE_POSITION_FRAME_LEN);
        assert_eq!(&buf[0..3], &[0xAA, 0xBB, 0xCC]);
        // The appended slice should match what `encode` produces
        // standalone — pin both encode functions emit the same bytes.
        let standalone = encode(&sample());
        assert_eq!(&buf[3..], &standalone[..]);
    }

    #[test]
    fn encode_to_vec_method_matches_free_encode_function() {
        // The struct-method convenience wrapper must produce
        // byte-identical output to the free function — no surprises
        // for callers who switch between styles.
        let msg = sample();
        assert_eq!(msg.encode_to_vec(), encode(&msg));
    }
}
