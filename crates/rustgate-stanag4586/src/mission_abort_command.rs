// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! STANAG 4586 LOI 4 mission abort command message.
//!
//! Carries the third **command-side** message in the
//! `rustgate-stanag4586` crate, following waypoint upload
//! ([`crate::waypoint_command`]) and sensor pointing
//! ([`crate::sensor_pointing_command`]). Where waypoint upload directs
//! *the platform* to navigate or hold and sensor pointing directs *a
//! payload sensor* to slew, mission abort directs *the entire mission*
//! to terminate: a Ground Control Station emits one
//! `MissionAbortCommand` to instruct a UAS to abandon its current
//! mission and execute a configurable abort behaviour (return-to-base,
//! divert to a saved fall-back coordinate, hold at present position,
//! land immediately, or loiter).
//!
//! # Operational model
//!
//! Mission abort is the operator's emergency lever — the message they
//! reach for when an ISR target is no longer worth pursuing, when
//! airspace deconfliction requires the platform to clear, when fuel
//! state forces a recovery, or when something safety-critical happened
//! upstream that the GCS detected and the platform did not. A typical
//! workflow looks like:
//!
//! 1. The vehicle's [`crate::vehicle_position`] /
//!    [`crate::system_state`] streams tell the GCS what mission the
//!    platform is currently flying (the `mission_id` field correlates
//!    against the vehicle's own bookkeeping) and where it is.
//! 2. The operator decides the mission must terminate. They pick an
//!    [`AbortBehaviour`] (return-to-base for a normal recovery, divert
//!    to a pre-published fall-back lat/lon for airspace
//!    deconfliction, hold for a pause-and-reassess, land immediately
//!    for a controlled emergency setdown, or loiter at present
//!    position) and a [`Priority`]
//!    ([`Priority::Normal`] for a graceful end-of-mission,
//!    [`Priority::Urgent`] for time-critical but non-emergency,
//!    [`Priority::Emergency`] for an unconditional immediate abort
//!    that the platform MUST honor even if mid-maneuver).
//! 3. The GCS emits a `MissionAbortCommand` carrying the chosen
//!    behaviour, priority, and (if the behaviour is
//!    [`AbortBehaviour::Divert`]) the divert lat/lon.
//! 4. The platform compares the inbound `mission_id` against its
//!    currently-active mission. If the IDs match, the abort is
//!    actioned; if they do not (because the platform has already
//!    transitioned to a follow-on mission), the abort is a no-op
//!    rather than aborting the wrong mission. This guard rule is the
//!    load-bearing reason `mission_id` exists on the wire.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`MISSION_ABORT_COMMAND_FRAME_LEN`] = 32
//! bytes.
//!
//! ```text
//! offset │ size │ field                │ type
//! ───────┼──────┼──────────────────────┼──────────────────────────
//!   0    │  4   │ vehicle_id           │ u32  big-endian
//!   4    │  4   │ mission_id           │ u32  big-endian
//!   8    │  1   │ abort_behaviour      │ u8   enum value (see below)
//!   9    │  1   │ priority             │ u8   enum value (see below)
//!  10    │  2   │ reserved             │ zero-padded — must be 0 on encode
//!  12    │  8   │ divert_latitude_deg  │ f64  big-endian IEEE-754, WGS-84
//!  20    │  8   │ divert_longitude_deg │ f64  big-endian IEEE-754, WGS-84
//!  28    │  4   │ timestamp_unix_ms    │ u32  big-endian (Unix epoch ms)
//! ```
//!
//! The reserved block is zero-filled on encode. The decoder does NOT
//! validate that it is zero on the wire so a future spec revision
//! that allocates the bytes (e.g. an abort-reason code, or a command
//! sequence number for matching against the future response message)
//! stays backward-compatible at the frame-length level.
//!
//! # Field semantics
//!
//! - `vehicle_id` — the target platform identifier. Matches the
//!   `vehicle_id` carried by the LOI 2-3 telemetry frames and the LOI
//!   4 [`crate::waypoint_command`] /
//!   [`crate::sensor_pointing_command`] frames so a GCS can correlate
//!   "which mission did I abort on which platform" against "which
//!   platform's telemetry am I currently displaying" by direct byte
//!   comparison without an intermediate lookup table.
//! - `mission_id` — the mission this abort applies to. The platform
//!   compares against its currently-active mission and ignores the
//!   abort if they do not match — this prevents a stale abort that
//!   crossed the wire after the vehicle already transitioned to a
//!   follow-on mission from terminating the wrong mission.
//! - `abort_behaviour` — which abort verb the platform should
//!   execute. See [`AbortBehaviour`].
//! - `priority` — how aggressively the platform should honor the
//!   abort. See [`Priority`]. `Emergency` is the load-bearing tier:
//!   the platform MUST action it immediately even if it is mid-
//!   maneuver, mid-slew, or in the middle of a sensor dwell that
//!   would normally be allowed to complete first.
//! - `divert_latitude_deg` / `divert_longitude_deg` — WGS-84 decimal
//!   degrees, the divert target if `abort_behaviour ==
//!   AbortBehaviour::Divert`. **Both fields are always present on
//!   the wire** and senders write `0.0, 0.0` when the abort behaviour
//!   does not require a divert position; the decoder accepts that
//!   sentinel rather than rejecting it as a wire-format defect — pin
//!   in test that `lat=0, lon=0` decodes cleanly. Range-checked on
//!   decode regardless of the abort behaviour: `lat ∈ [-90, 90]`,
//!   `lon ∈ [-180, 180]`. NaN explicitly rejected. Out-of-range
//!   values surface as [`Stanag4586Error::FieldOutOfRange`] rather
//!   than being silently clamped — they are typically a wire-format
//!   mismatch (wrong message type, byte-swap, …) and silent
//!   acceptance would hide the upstream defect.
//! - `timestamp_unix_ms` — when the GCS issued the abort, milliseconds
//!   since the Unix epoch. The platform may use it to discard a stale
//!   abort that lost a race against a follow-on command, or to
//!   timestamp the abort event in its own audit log for post-mission
//!   reconstruction. The codec does not validate the value (zero is
//!   legal — represents an unset/unknown timestamp).
//!
//! # What is deliberately absent
//!
//! - **Other LOI 4 commands** — GCS handover, payload control, route
//!   upload (multi-waypoint companion to
//!   [`crate::waypoint_command`]'s single-waypoint upload), mode
//!   change. Each is a separate follow-up PR with its own wire format
//!   and validation rules.
//! - **Response / acknowledgement messages** — the bidirectional
//!   command-response handshake (the platform's "abort accepted,
//!   executing return-to-base" or "abort rejected, mission already
//!   complete" reply) is a separate follow-up PR.
//! - **UDP/TCP listener wiring** — this module is pure encode/decode
//!   over `&[u8]`; the network glue is a separate change.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a mission abort command frame.
pub const MISSION_ABORT_COMMAND_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_MISSION_ID: usize = 4;
const OFF_ABORT_BEHAVIOUR: usize = 8;
const OFF_PRIORITY: usize = 9;
// 10..12 reserved (2 bytes)
const OFF_DIVERT_LATITUDE: usize = 12;
const OFF_DIVERT_LONGITUDE: usize = 20;
const OFF_TIMESTAMP: usize = 28;

/// Which abort verb the platform should execute.
///
/// The five named variants cover the LOI 4 mission-abort minimum-
/// viable command vocabulary: navigate back to the launch point
/// ([`AbortBehaviour::ReturnToBase`]), divert to a pre-published
/// fall-back coordinate carried in the same frame
/// ([`AbortBehaviour::Divert`]), hold at present position pending
/// further instruction ([`AbortBehaviour::Hold`]), execute an
/// immediate controlled landing at present position
/// ([`AbortBehaviour::LandImmediately`]), or loiter at present
/// position ([`AbortBehaviour::Loiter`]). [`AbortBehaviour::Other`]
/// preserves any unrecognised wire byte so a future spec revision
/// that allocates a new abort verb stays decodable on a receiver
/// running today's build — matches the same forward-compat discipline
/// used by every sibling LOI 2-3 / LOI 4 frame's enums.
///
/// # Wire byte values
///
/// | byte  | variant               |
/// |-------|-----------------------|
/// | `0x01`| `ReturnToBase`        |
/// | `0x02`| `Divert`              |
/// | `0x03`| `Hold`                |
/// | `0x04`| `LandImmediately`     |
/// | `0x05`| `Loiter`              |
/// | other | `Other(byte)`         |
///
/// `0x00` deliberately falls into [`AbortBehaviour::Other`] rather
/// than having its own "Unknown" variant — the encode side never
/// emits `0x00` for a named verb, so observing one on decode means
/// the upstream sent something unintended and the operator should be
/// able to see the raw byte value in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortBehaviour {
    /// Navigate back to the launch / recovery point.
    ReturnToBase,
    /// Divert to the lat/lon carried in the same frame.
    Divert,
    /// Hold at present position pending further instruction.
    Hold,
    /// Execute an immediate controlled landing at present position.
    LandImmediately,
    /// Loiter at present position.
    Loiter,
    /// Forward-compat catch-all for abort-behaviour bytes the spec
    /// may allocate in a future revision.
    Other(u8),
}

impl AbortBehaviour {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::ReturnToBase,
            0x02 => Self::Divert,
            0x03 => Self::Hold,
            0x04 => Self::LandImmediately,
            0x05 => Self::Loiter,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::ReturnToBase => 0x01,
            Self::Divert => 0x02,
            Self::Hold => 0x03,
            Self::LandImmediately => 0x04,
            Self::Loiter => 0x05,
            Self::Other(b) => b,
        }
    }
}

/// How aggressively the platform should honor the abort.
///
/// The three named variants cover the LOI 4 mission-abort priority
/// vocabulary: a graceful end-of-mission abort that may be queued
/// behind a current maneuver ([`Priority::Normal`]), a time-critical
/// but non-emergency abort that interrupts at the next safe boundary
/// ([`Priority::Urgent`]), and an unconditional immediate abort that
/// the platform MUST action even if mid-maneuver, mid-slew, or
/// mid-sensor-dwell ([`Priority::Emergency`]).
/// [`Priority::Other`] preserves any unrecognised wire byte for
/// forward compatibility.
///
/// # Wire byte values
///
/// | byte  | variant       |
/// |-------|---------------|
/// | `0x01`| `Normal`      |
/// | `0x02`| `Urgent`      |
/// | `0x03`| `Emergency`   |
/// | other | `Other(byte)` |
///
/// `0x00` deliberately falls into [`Priority::Other`] for the same
/// reason as the [`AbortBehaviour`] enum above — the encode side
/// never emits `0x00` for a named tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// Graceful end-of-mission; may be queued behind a current
    /// maneuver.
    Normal,
    /// Time-critical but non-emergency; interrupts at the next safe
    /// boundary.
    Urgent,
    /// Unconditional immediate abort; honored even mid-maneuver.
    Emergency,
    /// Forward-compat catch-all for priority bytes the spec may
    /// allocate in a future revision.
    Other(u8),
}

impl Priority {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::Normal,
            0x02 => Self::Urgent,
            0x03 => Self::Emergency,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Normal => 0x01,
            Self::Urgent => 0x02,
            Self::Emergency => 0x03,
            Self::Other(b) => b,
        }
    }
}

/// LOI 4 mission abort command message.
#[derive(Debug, Clone, PartialEq)]
pub struct MissionAbortCommand {
    /// Target platform identifier (matches
    /// [`crate::vehicle_position::VehiclePosition::vehicle_id`]).
    pub vehicle_id: u32,
    /// The mission this abort applies to. Platforms ignore the abort
    /// if this does not match their currently-active mission.
    pub mission_id: u32,
    /// Which abort verb the platform should execute.
    pub abort_behaviour: AbortBehaviour,
    /// How aggressively the platform should honor the abort.
    pub priority: Priority,
    /// WGS-84 latitude for the divert target if `abort_behaviour ==
    /// AbortBehaviour::Divert`. Senders write `0.0` when the
    /// behaviour does not require a divert position. Range
    /// `[-90, 90]`.
    pub divert_latitude_deg: f64,
    /// WGS-84 longitude for the divert target if `abort_behaviour ==
    /// AbortBehaviour::Divert`. Senders write `0.0` when the
    /// behaviour does not require a divert position. Range
    /// `[-180, 180]`.
    pub divert_longitude_deg: f64,
    /// When the GCS issued the abort, milliseconds since the Unix
    /// epoch. `0` represents an unset / unknown timestamp.
    pub timestamp_unix_ms: u32,
}

impl MissionAbortCommand {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a mission abort command frame into a freshly allocated
/// `Vec<u8>`.
#[must_use]
pub fn encode(msg: &MissionAbortCommand) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(MISSION_ABORT_COMMAND_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
///
/// Useful when the encoded frame will be the body of a larger packet
/// and the caller wants to avoid the intermediate `Vec` allocation
/// of [`encode`]. Appends [`MISSION_ABORT_COMMAND_FRAME_LEN`] bytes;
/// does not clear or truncate `buf`.
pub fn encode_into(msg: &MissionAbortCommand, buf: &mut BytesMut) {
    buf.reserve(MISSION_ABORT_COMMAND_FRAME_LEN);
    buf.put_u32(msg.vehicle_id);
    buf.put_u32(msg.mission_id);
    buf.put_u8(msg.abort_behaviour.to_byte());
    buf.put_u8(msg.priority.to_byte());
    // 2 reserved bytes.
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_f64(msg.divert_latitude_deg);
    buf.put_f64(msg.divert_longitude_deg);
    buf.put_u32(msg.timestamp_unix_ms);
}

/// Decode a mission abort command frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
/// - [`Stanag4586Error::FieldOutOfRange`] if `divert_latitude_deg` is
///   NaN or outside `[-90, 90]`.
/// - [`Stanag4586Error::FieldOutOfRange`] if `divert_longitude_deg`
///   is NaN or outside `[-180, 180]`.
///
/// Trailing bytes beyond [`MISSION_ABORT_COMMAND_FRAME_LEN`] are
/// ignored; the codec is fixed-size and a future protocol revision
/// that appends fields keeps decoding the prefix unchanged.
///
/// Unrecognised `abort_behaviour` and `priority` bytes do NOT cause
/// an error — they surface as [`AbortBehaviour::Other`] and
/// [`Priority::Other`] for forward compatibility.
pub fn decode(bytes: &[u8]) -> Result<MissionAbortCommand, Stanag4586Error> {
    if bytes.len() < MISSION_ABORT_COMMAND_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: MISSION_ABORT_COMMAND_FRAME_LEN,
        });
    }

    let mut cursor = &bytes[..MISSION_ABORT_COMMAND_FRAME_LEN];
    let vehicle_id = cursor.get_u32();
    let mission_id = cursor.get_u32();
    let abort_behaviour = AbortBehaviour::from_byte(cursor.get_u8());
    let priority = Priority::from_byte(cursor.get_u8());
    // Skip 2-byte reserved region.
    cursor.advance(2);
    let divert_latitude_deg = f64::from_bits(cursor.get_u64());
    let divert_longitude_deg = f64::from_bits(cursor.get_u64());
    let timestamp_unix_ms = cursor.get_u32();

    debug_assert!(
        cursor.is_empty(),
        "fixed-size frame should be fully consumed; bug in offset constants"
    );
    let _ = OFF_VEHICLE_ID;
    let _ = OFF_MISSION_ID;
    let _ = OFF_ABORT_BEHAVIOUR;
    let _ = OFF_PRIORITY;
    let _ = OFF_DIVERT_LATITUDE;
    let _ = OFF_DIVERT_LONGITUDE;
    let _ = OFF_TIMESTAMP;

    if divert_latitude_deg.is_nan() || !(-90.0..=90.0).contains(&divert_latitude_deg) {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "divert_latitude_deg",
            value: divert_latitude_deg.to_string(),
        });
    }
    if divert_longitude_deg.is_nan() || !(-180.0..=180.0).contains(&divert_longitude_deg) {
        return Err(Stanag4586Error::FieldOutOfRange {
            field: "divert_longitude_deg",
            value: divert_longitude_deg.to_string(),
        });
    }

    Ok(MissionAbortCommand {
        vehicle_id,
        mission_id,
        abort_behaviour,
        priority,
        divert_latitude_deg,
        divert_longitude_deg,
        timestamp_unix_ms,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Mid-range typical mission-abort fixture. Deliberately
    /// non-default values so an `assert_eq!` mismatch points at the
    /// right field.
    fn typical_abort_command() -> MissionAbortCommand {
        MissionAbortCommand {
            vehicle_id: 0xA1B2_C3D4,
            mission_id: 0x0102_0304,
            abort_behaviour: AbortBehaviour::ReturnToBase,
            priority: Priority::Urgent,
            divert_latitude_deg: 0.0,
            divert_longitude_deg: 0.0,
            timestamp_unix_ms: 0x600F_1234,
        }
    }

    /// Fixture exercising the [`AbortBehaviour::Divert`] path with
    /// non-zero divert lat/lon — used to pin that the divert
    /// coordinate fields round-trip independently of the abort
    /// behaviour.
    fn divert_abort_command() -> MissionAbortCommand {
        MissionAbortCommand {
            vehicle_id: 0xDEAD_BEEF,
            mission_id: 42,
            abort_behaviour: AbortBehaviour::Divert,
            priority: Priority::Emergency,
            divert_latitude_deg: 37.7749,
            divert_longitude_deg: -122.4194,
            timestamp_unix_ms: 0x6010_0000,
        }
    }

    // ---- Round-trip ----

    #[test]
    fn round_trip_zero_valued_fixture() {
        // All-zero is a valid frame: vehicle_id=0, mission_id=0,
        // abort_behaviour defaults to Other(0) (forward-compat
        // catch-all preserves the byte), priority defaults to
        // Other(0), zero divert lat/lon (the documented sentinel for
        // non-Divert behaviours), and zero timestamp (= unset). The
        // round-trip must hold even at this corner.
        let msg = MissionAbortCommand {
            vehicle_id: 0,
            mission_id: 0,
            abort_behaviour: AbortBehaviour::Other(0),
            priority: Priority::Other(0),
            divert_latitude_deg: 0.0,
            divert_longitude_deg: 0.0,
            timestamp_unix_ms: 0,
        };
        let bytes = encode(&msg);
        assert_eq!(bytes, vec![0u8; MISSION_ABORT_COMMAND_FRAME_LEN]);
        let decoded = decode(&bytes).expect("zero round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_typical_return_to_base_fixture() {
        let msg = typical_abort_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), MISSION_ABORT_COMMAND_FRAME_LEN);
        let decoded = decode(&bytes).expect("typical round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_divert_fixture_with_valid_lat_lon() {
        let msg = divert_abort_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), MISSION_ABORT_COMMAND_FRAME_LEN);
        let decoded = decode(&bytes).expect("divert round-trip");
        assert_eq!(decoded, msg);
    }

    // ---- Default lat/lon = 0,0 explicitly accepted ----

    #[test]
    fn decode_accepts_zero_zero_divert_position() {
        // Pin the sentinel-value contract: senders write 0.0/0.0
        // when abort_behaviour is anything other than Divert. A
        // regression that rejected `(0.0, 0.0)` as "off the WGS-84
        // origin" or required non-zero coordinates would silently
        // drop every non-Divert abort. The field is structurally
        // present on every frame so the decoder MUST accept the
        // sentinel cleanly even when paired with a non-Divert
        // behaviour.
        let msg = MissionAbortCommand {
            vehicle_id: 1,
            mission_id: 1,
            abort_behaviour: AbortBehaviour::Hold,
            priority: Priority::Normal,
            divert_latitude_deg: 0.0,
            divert_longitude_deg: 0.0,
            timestamp_unix_ms: 1,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("zero-zero divert position must decode cleanly");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.divert_latitude_deg, 0.0);
        assert_eq!(decoded.divert_longitude_deg, 0.0);
    }

    // ---- Golden-fixture decode ----

    #[test]
    fn decode_known_fixture_matches_expected_bytes() {
        // Hand-built golden fixture that pins every field at its
        // documented byte offset. The IEEE-754 big-endian byte
        // sequences for the two doubles are computed in the test
        // source so a regression that swapped to little-endian could
        // pass the round-trip + proptest checks but would still fail
        // this byte-pinning check.
        //
        // Field values:
        //   vehicle_id           = 0x1122_3344
        //   mission_id           = 0xAABB_CCDD
        //   abort_behaviour      = 0x01 (ReturnToBase)
        //   priority             = 0x02 (Urgent)
        //   divert_latitude_deg  = 37.7749
        //   divert_longitude_deg = -122.4194
        //   timestamp_unix_ms    = 0x600F_1234
        let msg = MissionAbortCommand {
            vehicle_id: 0x1122_3344,
            mission_id: 0xAABB_CCDD,
            abort_behaviour: AbortBehaviour::ReturnToBase,
            priority: Priority::Urgent,
            divert_latitude_deg: 37.7749,
            divert_longitude_deg: -122.4194,
            timestamp_unix_ms: 0x600F_1234,
        };
        let bytes = encode(&msg);
        let expected: [u8; MISSION_ABORT_COMMAND_FRAME_LEN] = [
            // vehicle_id = 0x1122_3344 (big-endian)
            0x11, 0x22, 0x33, 0x44, //
            // mission_id = 0xAABB_CCDD (big-endian)
            0xAA, 0xBB, 0xCC, 0xDD, //
            // abort_behaviour = 0x01 (ReturnToBase)
            0x01, //
            // priority = 0x02 (Urgent)
            0x02, //
            // 2 reserved zero bytes
            0x00, 0x00, //
            // divert_latitude_deg = 37.7749 → IEEE-754 big-endian
            0x40, 0x42, 0xE3, 0x2F, 0xEC, 0x56, 0xD5, 0xD0, //
            // divert_longitude_deg = -122.4194 → IEEE-754 big-endian
            0xC0, 0x5E, 0x9A, 0xD7, 0x73, 0x18, 0xFC, 0x50, //
            // timestamp_unix_ms = 0x600F_1234 (big-endian)
            0x60, 0x0F, 0x12, 0x34,
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
    fn decode_rejects_nan_divert_latitude_deg() {
        // NaN passes neither `<` nor `>` so a naive range check
        // would accept it. Pin that we explicitly reject NaN as a
        // sanity gate — a NaN coordinate is never legitimate command
        // input even if the abort behaviour does not require a
        // divert position.
        let mut wire = encode(&divert_abort_command());
        wire[12..20].copy_from_slice(&f64::NAN.to_be_bytes());
        match decode(&wire) {
            Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "divert_latitude_deg");
            }
            other => panic!("expected FieldOutOfRange/divert_latitude_deg, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_nan_divert_longitude_deg() {
        let mut wire = encode(&divert_abort_command());
        wire[20..28].copy_from_slice(&f64::NAN.to_be_bytes());
        match decode(&wire) {
            Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                assert_eq!(field, "divert_longitude_deg");
            }
            other => panic!("expected FieldOutOfRange/divert_longitude_deg, got {other:?}"),
        }
    }

    // ---- Range rejection ----

    #[test]
    fn decode_rejects_divert_latitude_out_of_range() {
        for lat in [91.0_f64, -91.0_f64] {
            let mut wire = encode(&divert_abort_command());
            wire[12..20].copy_from_slice(&lat.to_be_bytes());
            match decode(&wire) {
                Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                    assert_eq!(field, "divert_latitude_deg");
                }
                other => panic!(
                    "expected FieldOutOfRange/divert_latitude_deg for lat={lat}, got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn decode_rejects_divert_longitude_out_of_range() {
        for lon in [181.0_f64, -181.0_f64] {
            let mut wire = encode(&divert_abort_command());
            wire[20..28].copy_from_slice(&lon.to_be_bytes());
            match decode(&wire) {
                Err(Stanag4586Error::FieldOutOfRange { field, .. }) => {
                    assert_eq!(field, "divert_longitude_deg");
                }
                other => panic!(
                    "expected FieldOutOfRange/divert_longitude_deg for lon={lon}, got {other:?}"
                ),
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
                    assert_eq!(expected, MISSION_ABORT_COMMAND_FRAME_LEN);
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
        let msg = typical_abort_command();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(&[0xAA; 32]);
        assert_eq!(bytes.len(), 64);
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
    }

    // ---- AbortBehaviour enum round-trip ----

    #[test]
    fn abort_behaviour_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, AbortBehaviour)] = &[
            (0x01, AbortBehaviour::ReturnToBase),
            (0x02, AbortBehaviour::Divert),
            (0x03, AbortBehaviour::Hold),
            (0x04, AbortBehaviour::LandImmediately),
            (0x05, AbortBehaviour::Loiter),
            (0xFF, AbortBehaviour::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = AbortBehaviour::from_byte(*byte);
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
        for byte in [0x00u8, 0x06, 0x42, 0xEE] {
            let decoded = AbortBehaviour::from_byte(byte);
            assert_eq!(decoded, AbortBehaviour::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- Priority enum round-trip ----

    #[test]
    fn priority_round_trip_preserves_named_variants_and_other_byte() {
        let cases: &[(u8, Priority)] = &[
            (0x01, Priority::Normal),
            (0x02, Priority::Urgent),
            (0x03, Priority::Emergency),
            (0xFF, Priority::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = Priority::from_byte(*byte);
            assert_eq!(decoded, *expected, "from_byte mismatch for byte={byte:#x}");
            assert_eq!(
                decoded.to_byte(),
                *byte,
                "to_byte mismatch for {expected:?}"
            );
        }
        for byte in [0x00u8, 0x04, 0x42, 0xEE] {
            let decoded = Priority::from_byte(byte);
            assert_eq!(decoded, Priority::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- Convenience method parity ----

    #[test]
    fn encode_to_vec_method_matches_free_encode_function() {
        // The struct-method convenience wrapper must produce
        // byte-identical output to the free function — no surprises
        // for callers who switch between styles.
        let msg = typical_abort_command();
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
        encode_into(&typical_abort_command(), &mut buf);
        assert_eq!(buf.len(), 3 + MISSION_ABORT_COMMAND_FRAME_LEN);
        assert_eq!(&buf[0..3], &[0xAA, 0xBB, 0xCC]);
        let standalone = encode(&typical_abort_command());
        assert_eq!(&buf[3..], &standalone[..]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        // Property test: any valid struct round-trips byte-for-byte.
        // Constrain divert lat/lon to the WGS-84 range so the
        // decoder doesn't reject the property input — out-of-range
        // and NaN rejection are their own dedicated tests.
        #[test]
        fn round_trip_via_proptest(
            vehicle_id in any::<u32>(),
            mission_id in any::<u32>(),
            behaviour_byte in any::<u8>(),
            priority_byte in any::<u8>(),
            divert_latitude_deg in -90.0_f64..=90.0_f64,
            divert_longitude_deg in -180.0_f64..=180.0_f64,
            timestamp_unix_ms in any::<u32>(),
        ) {
            let original = MissionAbortCommand {
                vehicle_id,
                mission_id,
                abort_behaviour: AbortBehaviour::from_byte(behaviour_byte),
                priority: Priority::from_byte(priority_byte),
                divert_latitude_deg,
                divert_longitude_deg,
                timestamp_unix_ms,
            };
            let bytes = encode(&original);
            prop_assert_eq!(bytes.len(), MISSION_ABORT_COMMAND_FRAME_LEN);
            let decoded = decode(&bytes).expect("decode round-trip");
            prop_assert_eq!(decoded, original);
        }
    }
}
