// Copyright © 2026 Roberto Chiofalo.

//! STANAG 4586 LOI 2-3 system-state telemetry message.
//!
//! Carries the *vehicle's* health and operating-mode state — the
//! orthogonal axis to the three sibling LOI 2-3 telemetry frames:
//!
//! - [`crate::vehicle_position`] answers "where is it / how is it
//!   moving" (kinematic state).
//! - [`crate::sensor_status`] answers "where is it looking" (sensor
//!   pointing).
//! - [`crate::payload_status`] answers "what is happening with the
//!   data" (recorder / streamer / link health).
//! - [`SystemState`] (this module) answers "what is happening with
//!   the *vehicle*" (mode, mission phase, fuel, battery, uplink
//!   quality, BIT subsystem health flags).
//!
//! Together the four frames form the LOI 2-3 read-side surface that
//! any deployment needs before graduating to LOI 4+ command-side
//! work. System-state is typically streamed at 1–2 Hz — vehicle-mode
//! transitions are operator-visible events that change on the order
//! of seconds, distinct from the 10–50 Hz position stream and the
//! 1–5 Hz sensor / payload streams.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`SYSTEM_STATE_FRAME_LEN`] = 32 bytes.
//!
//! ```text
//! offset │ size │ field                   │ type
//! ───────┼──────┼─────────────────────────┼──────────────────────────
//!   0    │  4   │ vehicle_id              │ u32  big-endian
//!   4    │  1   │ operating_mode          │ u8   enum value (see below)
//!   5    │  1   │ mission_phase           │ u8   enum value (see below)
//!   6    │  2   │ bit_status_flags        │ u16  big-endian bitfield
//!   8    │  4   │ fuel_remaining_pct      │ f32  big-endian IEEE-754
//!  12    │  4   │ battery_remaining_pct   │ f32  big-endian IEEE-754
//!  16    │  4   │ uplink_quality_pct      │ f32  big-endian IEEE-754
//!  20    │  4   │ reserved                │ zero-padded — must be 0 on encode
//!  24    │  8   │ timestamp_unix_ms       │ u64  big-endian
//! ```
//!
//! The reserved block is zero-filled on encode. The decoder does
//! NOT validate it — a future protocol revision that allocates the
//! bytes stays backward-compatible at the frame-length level.
//!
//! # Field semantics
//!
//! - `vehicle_id` — opaque platform identifier matching the
//!   `vehicle_id` carried by the corresponding
//!   [`crate::vehicle_position::VehiclePosition`]. A LOI 2 deployment
//!   correlates the four frames per platform via this id.
//! - `operating_mode` — the autopilot's current control mode. See
//!   [`OperatingMode`].
//! - `mission_phase` — where the platform is in its mission
//!   timeline. See [`MissionPhase`].
//! - `bit_status_flags` — Built-In Test subsystem health bitfield.
//!   Each bit is a per-subsystem fault flag (`1 = fault`,
//!   `0 = OK`). Unknown bits are preserved verbatim across
//!   round-trip so a future spec revision that allocates a new bit
//!   stays decodable. See [`BitStatusFlags`] for the named bit
//!   constants.
//! - `fuel_remaining_pct` — fuel remaining as a percentage in
//!   `[0.0, 100.0]`. Range-checked on decode. Always present, even
//!   on electric platforms where fuel is conceptually irrelevant
//!   (sender emits `100.0` to mean "not applicable" — the spec does
//!   not provide a sentinel value for unused fields).
//! - `battery_remaining_pct` — battery state-of-charge as a
//!   percentage in `[0.0, 100.0]`. Range-checked on decode. Same
//!   "always present" semantics: a fuel-only platform sends `100.0`
//!   for battery, an electric platform sends `100.0` for fuel.
//! - `uplink_quality_pct` — measured C2 uplink quality as a
//!   percentage in `[0.0, 100.0]`. Operationally distinct from
//!   `payload_status::link_bandwidth_kbps` — that field is the
//!   *downlink* (vehicle → ground) data path; `uplink_quality_pct`
//!   here is the *uplink* (ground → vehicle) command-and-control
//!   path which has very different operational consequences when
//!   it degrades.
//! - `timestamp_unix_ms` — milliseconds since the Unix epoch.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a system-state frame.
pub const SYSTEM_STATE_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_OPERATING_MODE: usize = 4;
const OFF_MISSION_PHASE: usize = 5;
const OFF_BIT_FLAGS: usize = 6;
const OFF_FUEL_PCT: usize = 8;
const OFF_BATTERY_PCT: usize = 12;
const OFF_UPLINK_QUALITY: usize = 16;
// 20..24 reserved (4 bytes)
const OFF_TIMESTAMP: usize = 24;

/// Autopilot's current control mode.
///
/// # Wire byte values
///
/// | byte  | variant         |
/// |-------|-----------------|
/// | `0x01`| `Manual`        |
/// | `0x02`| `Autonomous`    |
/// | `0x03`| `ReturnToBase`  |
/// | `0x04`| `Hold`          |
/// | `0x05`| `Emergency`     |
/// | other | `Other(byte)`   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatingMode {
    /// Operator-in-the-loop manual control (joystick / RC).
    Manual,
    /// Flying its programmed mission script without operator input.
    Autonomous,
    /// Auto return-to-base in progress (typically triggered by fuel
    /// low, link lost, or operator abort).
    ReturnToBase,
    /// Holding station — orbiting a point or station-keeping at a
    /// waypoint awaiting further command.
    Hold,
    /// Emergency mode — flight termination, parachute, or other
    /// catastrophic-recovery state. Operationally significant: a
    /// ground station seeing this transition should escalate to the
    /// operator immediately.
    Emergency,
    /// Forward-compat catch-all.
    Other(u8),
}

impl OperatingMode {
    /// Map a wire byte into the typed enum.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Manual,
            0x02 => Self::Autonomous,
            0x03 => Self::ReturnToBase,
            0x04 => Self::Hold,
            0x05 => Self::Emergency,
            _ => Self::Other(b),
        }
    }

    /// Map the typed enum back into its wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Manual => 0x01,
            Self::Autonomous => 0x02,
            Self::ReturnToBase => 0x03,
            Self::Hold => 0x04,
            Self::Emergency => 0x05,
            Self::Other(b) => b,
        }
    }
}

/// Where the platform is in its mission timeline.
///
/// # Wire byte values
///
/// | byte  | variant      |
/// |-------|--------------|
/// | `0x01`| `Preflight`  |
/// | `0x02`| `Launch`     |
/// | `0x03`| `Cruise`     |
/// | `0x04`| `OnStation`  |
/// | `0x05`| `Recovery`   |
/// | `0x06`| `Landed`     |
/// | other | `Other(byte)`|
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MissionPhase {
    /// Preflight checks, on the ground, not yet airborne.
    Preflight,
    /// Takeoff or launch in progress.
    Launch,
    /// Cruising / enroute to the operating area.
    Cruise,
    /// On station at the operating area, executing the mission's
    /// observation / loiter / engagement script.
    OnStation,
    /// Recovery or return-to-base — heading home.
    Recovery,
    /// Landed and powered down (or otherwise off-mission).
    Landed,
    /// Forward-compat catch-all.
    Other(u8),
}

impl MissionPhase {
    /// Map a wire byte into the typed enum.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Preflight,
            0x02 => Self::Launch,
            0x03 => Self::Cruise,
            0x04 => Self::OnStation,
            0x05 => Self::Recovery,
            0x06 => Self::Landed,
            _ => Self::Other(b),
        }
    }

    /// Map the typed enum back into its wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Preflight => 0x01,
            Self::Launch => 0x02,
            Self::Cruise => 0x03,
            Self::OnStation => 0x04,
            Self::Recovery => 0x05,
            Self::Landed => 0x06,
            Self::Other(b) => b,
        }
    }
}

/// Built-In Test subsystem health bitfield.
///
/// Each bit signals a per-subsystem fault: `1 = fault`, `0 = OK`.
/// The wire format is a 16-bit big-endian word, so up to 16
/// subsystems can be reported simultaneously.
///
/// Unknown bits — those not in the named-constant table below —
/// are preserved verbatim across encode/decode so a future spec
/// revision that allocates a new bit stays decodable; consumers
/// can interrogate the raw `bits` field if they need to inspect
/// reserved bits for custom subsystem reporting.
///
/// # Named bit constants
///
/// | bit (mask) | subsystem        |
/// |------------|------------------|
/// | `0x0001`   | propulsion       |
/// | `0x0002`   | navigation       |
/// | `0x0004`   | autopilot        |
/// | `0x0008`   | comms            |
/// | `0x0010`   | payload          |
/// | `0x0020`   | electrical       |
/// | `0x0040`   | hydraulic        |
/// | `0x0080`   | flight controls  |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitStatusFlags {
    /// Raw 16-bit wire value. Public so callers can inspect bits
    /// not covered by the named-constant table without a setter
    /// boilerplate.
    pub bits: u16,
}

impl BitStatusFlags {
    /// Propulsion fault (engine / motor / thruster).
    pub const PROPULSION: u16 = 0x0001;
    /// Navigation fault (GPS / IMU / INS).
    pub const NAVIGATION: u16 = 0x0002;
    /// Autopilot fault (FCS computer or control loop).
    pub const AUTOPILOT: u16 = 0x0004;
    /// Communications fault (radios, datalink).
    pub const COMMS: u16 = 0x0008;
    /// Payload fault (sensor turret, recorder).
    pub const PAYLOAD: u16 = 0x0010;
    /// Electrical fault (battery, generator, bus).
    pub const ELECTRICAL: u16 = 0x0020;
    /// Hydraulic fault (control surfaces, landing gear).
    pub const HYDRAULIC: u16 = 0x0040;
    /// Flight-controls fault (servo, actuator, surface stuck).
    pub const FLIGHT_CONTROLS: u16 = 0x0080;

    /// Construct from a raw 16-bit wire value.
    pub fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// All-OK shorthand (no faults reported).
    pub fn ok() -> Self {
        Self { bits: 0 }
    }

    /// True if any of the named-subsystem bits is set.
    pub fn any_fault(self) -> bool {
        self.bits != 0
    }

    /// True if the given mask is fully set in `self.bits`.
    pub fn contains(self, mask: u16) -> bool {
        self.bits & mask == mask
    }
}

/// LOI 2-3 system-state telemetry message.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemState {
    /// Platform identifier (matches
    /// [`crate::vehicle_position::VehiclePosition::vehicle_id`]).
    pub vehicle_id: u32,
    /// Autopilot's current control mode.
    pub operating_mode: OperatingMode,
    /// Where the platform is in its mission timeline.
    pub mission_phase: MissionPhase,
    /// BIT subsystem health flags.
    pub bit_status_flags: BitStatusFlags,
    /// Fuel remaining, percentage `[0.0, 100.0]`.
    pub fuel_remaining_pct: f32,
    /// Battery state-of-charge, percentage `[0.0, 100.0]`.
    pub battery_remaining_pct: f32,
    /// C2 uplink quality, percentage `[0.0, 100.0]`.
    pub uplink_quality_pct: f32,
    /// Milliseconds since the Unix epoch.
    pub timestamp_unix_ms: u64,
}

impl SystemState {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a system-state frame into a freshly allocated `Vec<u8>`.
pub fn encode(msg: &SystemState) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(SYSTEM_STATE_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
pub fn encode_into(msg: &SystemState, buf: &mut BytesMut) {
    buf.put_u32(msg.vehicle_id);
    buf.put_u8(msg.operating_mode.to_byte());
    buf.put_u8(msg.mission_phase.to_byte());
    buf.put_u16(msg.bit_status_flags.bits);
    buf.put_f32(msg.fuel_remaining_pct);
    buf.put_f32(msg.battery_remaining_pct);
    buf.put_f32(msg.uplink_quality_pct);
    buf.put_u32(0); // 4 reserved bytes
    buf.put_u64(msg.timestamp_unix_ms);
}

/// Decode a system-state frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
/// - [`Stanag4586Error::FieldOutOfRange`] if any of
///   `fuel_remaining_pct`, `battery_remaining_pct`, or
///   `uplink_quality_pct` is outside `[0.0, 100.0]` or NaN.
pub fn decode(bytes: &[u8]) -> Result<SystemState, Stanag4586Error> {
    if bytes.len() < SYSTEM_STATE_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: SYSTEM_STATE_FRAME_LEN,
        });
    }
    let mut cursor = &bytes[..SYSTEM_STATE_FRAME_LEN];
    let vehicle_id = cursor.get_u32();
    let operating_mode = OperatingMode::from_byte(cursor.get_u8());
    let mission_phase = MissionPhase::from_byte(cursor.get_u8());
    let bit_status_flags = BitStatusFlags::from_bits(cursor.get_u16());
    let fuel_remaining_pct = cursor.get_f32();
    let battery_remaining_pct = cursor.get_f32();
    let uplink_quality_pct = cursor.get_f32();
    let _ = cursor.get_u32(); // reserved
    let timestamp_unix_ms = cursor.get_u64();

    if !fuel_remaining_pct.is_finite() || !(0.0..=100.0).contains(&fuel_remaining_pct) {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "fuel_remaining_pct",
            value: fuel_remaining_pct.to_string(),
        });
    }
    if !battery_remaining_pct.is_finite() || !(0.0..=100.0).contains(&battery_remaining_pct) {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "battery_remaining_pct",
            value: battery_remaining_pct.to_string(),
        });
    }
    if !uplink_quality_pct.is_finite() || !(0.0..=100.0).contains(&uplink_quality_pct) {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "uplink_quality_pct",
            value: uplink_quality_pct.to_string(),
        });
    }

    debug_assert_eq!(cursor.remaining(), 0);
    let _ = OFF_VEHICLE_ID;
    let _ = OFF_OPERATING_MODE;
    let _ = OFF_MISSION_PHASE;
    let _ = OFF_BIT_FLAGS;
    let _ = OFF_FUEL_PCT;
    let _ = OFF_BATTERY_PCT;
    let _ = OFF_UPLINK_QUALITY;
    let _ = OFF_TIMESTAMP;

    Ok(SystemState {
        vehicle_id,
        operating_mode,
        mission_phase,
        bit_status_flags,
        fuel_remaining_pct,
        battery_remaining_pct,
        uplink_quality_pct,
        timestamp_unix_ms,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn fixture() -> SystemState {
        SystemState {
            vehicle_id: 0xCAFE_BABE,
            operating_mode: OperatingMode::Autonomous,
            mission_phase: MissionPhase::OnStation,
            bit_status_flags: BitStatusFlags::from_bits(
                BitStatusFlags::COMMS | BitStatusFlags::PAYLOAD,
            ),
            fuel_remaining_pct: 73.5,
            battery_remaining_pct: 88.0,
            uplink_quality_pct: 95.5,
            timestamp_unix_ms: 0xDEAD_BEEF_0000_0042,
        }
    }

    #[test]
    fn round_trip_full_fixture() {
        let msg = fixture();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), SYSTEM_STATE_FRAME_LEN);
        let decoded = decode(&bytes).expect("decode round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_zero_valued_fixture() {
        // All-zero is a valid frame: vehicle_id=0, modes default to
        // Other(0) (forward-compat catch-all preserves the byte),
        // bit_status_flags=ok, all percentages 0, timestamp 0. The
        // round-trip must hold even at this corner because a freshly
        // booted UAV that has not yet populated any field will emit
        // exactly this frame and the decoder must not reject it.
        let msg = SystemState {
            vehicle_id: 0,
            operating_mode: OperatingMode::Other(0),
            mission_phase: MissionPhase::Other(0),
            bit_status_flags: BitStatusFlags::ok(),
            fuel_remaining_pct: 0.0,
            battery_remaining_pct: 0.0,
            uplink_quality_pct: 0.0,
            timestamp_unix_ms: 0,
        };
        let bytes = encode(&msg);
        assert_eq!(bytes, vec![0u8; SYSTEM_STATE_FRAME_LEN]);
        let decoded = decode(&bytes).expect("zero round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_max_valued_fixture() {
        // Pin the upper edges: max percentage (100.0) and max ids /
        // timestamps. A regression that compared `< 100.0` instead of
        // `<= 100.0` for one of the percent fields would silently
        // reject the spec-allowed maximum, so this test guards
        // against an off-by-one in the range check.
        let msg = SystemState {
            vehicle_id: u32::MAX,
            operating_mode: OperatingMode::Emergency,
            mission_phase: MissionPhase::Recovery,
            bit_status_flags: BitStatusFlags::from_bits(u16::MAX),
            fuel_remaining_pct: 100.0,
            battery_remaining_pct: 100.0,
            uplink_quality_pct: 100.0,
            timestamp_unix_ms: u64::MAX,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("max round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn decode_known_fixture_matches_expected_bytes() {
        // Hand-built golden fixture that pins every field at its
        // documented byte offset. A regression that swapped to
        // little-endian could pass the proptest round-trip and the
        // free-form fixtures above but would still fail this check
        // because the IEEE-754 byte sequences are pinned literally.
        //
        // Field values picked to produce easy-to-read big-endian
        // IEEE-754 patterns: 75.0 = 0x4296_0000, 50.0 = 0x4248_0000,
        // 90.0 = 0x42B4_0000.
        let msg = SystemState {
            vehicle_id: 0x1122_3344,
            operating_mode: OperatingMode::Autonomous,
            mission_phase: MissionPhase::Cruise,
            bit_status_flags: BitStatusFlags::from_bits(
                BitStatusFlags::NAVIGATION | BitStatusFlags::COMMS,
            ),
            fuel_remaining_pct: 75.0,
            battery_remaining_pct: 50.0,
            uplink_quality_pct: 90.0,
            timestamp_unix_ms: 0x0123_4567_89AB_CDEF,
        };
        let bytes = encode(&msg);
        let expected: [u8; SYSTEM_STATE_FRAME_LEN] = [
            // vehicle_id: 0x1122_3344
            0x11, 0x22, 0x33, 0x44, //
            // operating_mode: 0x02 (Autonomous)
            0x02, //
            // mission_phase: 0x03 (Cruise)
            0x03, //
            // bit_status_flags: NAVIGATION | COMMS = 0x000A
            0x00, 0x0A, //
            // fuel_remaining_pct: 75.0_f32 = 0x4296_0000
            0x42, 0x96, 0x00, 0x00, //
            // battery_remaining_pct: 50.0_f32 = 0x4248_0000
            0x42, 0x48, 0x00, 0x00, //
            // uplink_quality_pct: 90.0_f32 = 0x42B4_0000
            0x42, 0xB4, 0x00, 0x00, //
            // 4 reserved zero bytes
            0x00, 0x00, 0x00, 0x00, //
            // timestamp_unix_ms: 0x0123_4567_89AB_CDEF
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ];
        assert_eq!(
            bytes.as_slice(),
            &expected[..],
            "encoded bytes must match the documented byte layout"
        );
        let decoded = decode(&expected).expect("golden decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn decode_extra_trailing_bytes_are_ignored() {
        // A future protocol revision that appends a trailer must not
        // break consumers reading the documented prefix. Pin that
        // ANY trailer is tolerated: the decoder reads exactly 32
        // bytes and ignores everything after.
        let msg = fixture();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(&[0xAA; 64]);
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn decode_truncation_sweep_returns_frame_too_short() {
        // Sweep a representative set of short inputs to pin that
        // `FrameTooShort` fires on every byte count below the fixed
        // length. Picks span all four quadrants: empty, tiny, mid,
        // and one-byte-short — the off-by-one most likely to land in
        // a future refactor that reads field-by-field rather than
        // bounds-checking up front.
        for &len in &[0_usize, 1, 7, 16, 23, 31] {
            let bytes = vec![0u8; len];
            let err = decode(&bytes).expect_err("truncation must error");
            match err {
                Stanag4586Error::FrameTooShort { actual, expected } => {
                    assert_eq!(actual, len);
                    assert_eq!(expected, SYSTEM_STATE_FRAME_LEN);
                }
                other => panic!("expected FrameTooShort, got {other:?}"),
            }
        }
    }

    fn fixture_with_field_value(field: &'static str, value: f32) -> Vec<u8> {
        let mut msg = fixture();
        match field {
            "fuel_remaining_pct" => msg.fuel_remaining_pct = value,
            "battery_remaining_pct" => msg.battery_remaining_pct = value,
            "uplink_quality_pct" => msg.uplink_quality_pct = value,
            other => panic!("unknown field: {other}"),
        }
        encode(&msg)
    }

    #[test]
    fn decode_rejects_negative_fuel_remaining_pct() {
        let bytes = fixture_with_field_value("fuel_remaining_pct", -0.1);
        let err = decode(&bytes).expect_err("negative fuel must reject");
        assert!(matches!(
            err,
            Stanag4586Error::FieldOutOfRange {
                field: "fuel_remaining_pct",
                ..
            }
        ));
    }

    #[test]
    fn decode_rejects_fuel_remaining_pct_above_100() {
        let bytes = fixture_with_field_value("fuel_remaining_pct", 100.0001);
        let err = decode(&bytes).expect_err("fuel >100 must reject");
        assert!(matches!(
            err,
            Stanag4586Error::FieldOutOfRange {
                field: "fuel_remaining_pct",
                ..
            }
        ));
    }

    #[test]
    fn decode_rejects_nan_fuel_remaining_pct() {
        // NaN is the load-bearing rejection: a naive `0.0 <= x <=
        // 100.0` range check silently accepts NaN because every
        // comparison involving NaN is false. The explicit
        // `is_finite()` guard is what stops a silent round-trip of
        // a poisoned value into downstream consumers.
        let bytes = fixture_with_field_value("fuel_remaining_pct", f32::NAN);
        let err = decode(&bytes).expect_err("NaN fuel must reject");
        assert!(matches!(
            err,
            Stanag4586Error::FieldOutOfRange {
                field: "fuel_remaining_pct",
                ..
            }
        ));
    }

    #[test]
    fn decode_rejects_negative_battery_remaining_pct() {
        let bytes = fixture_with_field_value("battery_remaining_pct", -0.1);
        let err = decode(&bytes).expect_err("negative battery must reject");
        assert!(matches!(
            err,
            Stanag4586Error::FieldOutOfRange {
                field: "battery_remaining_pct",
                ..
            }
        ));
    }

    #[test]
    fn decode_rejects_nan_battery_remaining_pct() {
        let bytes = fixture_with_field_value("battery_remaining_pct", f32::NAN);
        let err = decode(&bytes).expect_err("NaN battery must reject");
        assert!(matches!(
            err,
            Stanag4586Error::FieldOutOfRange {
                field: "battery_remaining_pct",
                ..
            }
        ));
    }

    #[test]
    fn decode_rejects_negative_uplink_quality_pct() {
        let bytes = fixture_with_field_value("uplink_quality_pct", -0.1);
        let err = decode(&bytes).expect_err("negative uplink must reject");
        assert!(matches!(
            err,
            Stanag4586Error::FieldOutOfRange {
                field: "uplink_quality_pct",
                ..
            }
        ));
    }

    #[test]
    fn decode_rejects_nan_uplink_quality_pct() {
        let bytes = fixture_with_field_value("uplink_quality_pct", f32::NAN);
        let err = decode(&bytes).expect_err("NaN uplink must reject");
        assert!(matches!(
            err,
            Stanag4586Error::FieldOutOfRange {
                field: "uplink_quality_pct",
                ..
            }
        ));
    }

    #[test]
    fn operating_mode_known_variants_round_trip() {
        let cases: &[(OperatingMode, u8)] = &[
            (OperatingMode::Manual, 0x01),
            (OperatingMode::Autonomous, 0x02),
            (OperatingMode::ReturnToBase, 0x03),
            (OperatingMode::Hold, 0x04),
            (OperatingMode::Emergency, 0x05),
        ];
        for (variant, byte) in cases {
            assert_eq!(variant.to_byte(), *byte);
            assert_eq!(OperatingMode::from_byte(*byte), *variant);
        }
    }

    #[test]
    fn operating_mode_unknown_byte_preserved_as_other() {
        // A future spec revision allocating a new mode must round-trip
        // through `Other(byte)` so a deployment receiving a frame from
        // a newer firmware does not see its message rejected at the
        // framing layer.
        for byte in [0x00, 0x06, 0x42, 0xFE, 0xFF] {
            let mode = OperatingMode::from_byte(byte);
            assert_eq!(mode, OperatingMode::Other(byte));
            assert_eq!(mode.to_byte(), byte);
        }
    }

    #[test]
    fn mission_phase_known_variants_round_trip() {
        let cases: &[(MissionPhase, u8)] = &[
            (MissionPhase::Preflight, 0x01),
            (MissionPhase::Launch, 0x02),
            (MissionPhase::Cruise, 0x03),
            (MissionPhase::OnStation, 0x04),
            (MissionPhase::Recovery, 0x05),
            (MissionPhase::Landed, 0x06),
        ];
        for (variant, byte) in cases {
            assert_eq!(variant.to_byte(), *byte);
            assert_eq!(MissionPhase::from_byte(*byte), *variant);
        }
    }

    #[test]
    fn mission_phase_unknown_byte_preserved_as_other() {
        for byte in [0x00, 0x07, 0x42, 0xFE, 0xFF] {
            let phase = MissionPhase::from_byte(byte);
            assert_eq!(phase, MissionPhase::Other(byte));
            assert_eq!(phase.to_byte(), byte);
        }
    }

    #[test]
    fn bit_status_flags_named_constants_are_disjoint_powers_of_two() {
        // The named-bit table above MUST be an exclusive set: a
        // refactor that accidentally aliased two subsystems to the
        // same bit (e.g. typo `0x0008` for both `COMMS` and
        // `PAYLOAD`) would silently merge their fault reporting.
        // Pin the disjointness as a unit invariant.
        let bits = [
            BitStatusFlags::PROPULSION,
            BitStatusFlags::NAVIGATION,
            BitStatusFlags::AUTOPILOT,
            BitStatusFlags::COMMS,
            BitStatusFlags::PAYLOAD,
            BitStatusFlags::ELECTRICAL,
            BitStatusFlags::HYDRAULIC,
            BitStatusFlags::FLIGHT_CONTROLS,
        ];
        let mut seen = 0u16;
        for bit in bits {
            assert!(bit.is_power_of_two(), "{bit:#06x} must be a single bit");
            assert_eq!(seen & bit, 0, "{bit:#06x} aliases an earlier subsystem");
            seen |= bit;
        }
    }

    #[test]
    fn bit_status_flags_round_trip_preserves_unknown_bits() {
        // The wire format reserves bits 0x0100..=0x8000 for future
        // subsystems. A round-trip must preserve them verbatim so
        // a future spec revision allocating a bit (e.g. `LANDING_GEAR
        // = 0x0100`) decodes cleanly on a receiver running today's
        // build — the deployment can't roll out new firmware
        // simultaneously across every node.
        let unknown = BitStatusFlags::from_bits(0xF000 | BitStatusFlags::PROPULSION);
        let msg = SystemState {
            bit_status_flags: unknown,
            ..fixture()
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("round-trip");
        assert_eq!(decoded.bit_status_flags.bits, 0xF000 | 0x0001);
    }

    #[test]
    fn bit_status_flags_helpers_return_expected_values() {
        let ok = BitStatusFlags::ok();
        assert_eq!(ok.bits, 0);
        assert!(!ok.any_fault());
        assert!(!ok.contains(BitStatusFlags::COMMS));

        let comms_fault = BitStatusFlags::from_bits(BitStatusFlags::COMMS);
        assert!(comms_fault.any_fault());
        assert!(comms_fault.contains(BitStatusFlags::COMMS));
        assert!(!comms_fault.contains(BitStatusFlags::PROPULSION));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn round_trip_via_proptest(
            vehicle_id in any::<u32>(),
            mode_byte in any::<u8>(),
            phase_byte in any::<u8>(),
            bit_bits in any::<u16>(),
            fuel in 0.0_f32..=100.0,
            battery in 0.0_f32..=100.0,
            uplink in 0.0_f32..=100.0,
            timestamp_unix_ms in any::<u64>(),
        ) {
            let msg = SystemState {
                vehicle_id,
                operating_mode: OperatingMode::from_byte(mode_byte),
                mission_phase: MissionPhase::from_byte(phase_byte),
                bit_status_flags: BitStatusFlags::from_bits(bit_bits),
                fuel_remaining_pct: fuel,
                battery_remaining_pct: battery,
                uplink_quality_pct: uplink,
                timestamp_unix_ms,
            };
            let bytes = encode(&msg);
            prop_assert_eq!(bytes.len(), SYSTEM_STATE_FRAME_LEN);
            let decoded = decode(&bytes).expect("decode round-trip");
            prop_assert_eq!(decoded, msg);
        }
    }
}
