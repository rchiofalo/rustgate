// Copyright © 2026 Roberto Chiofalo.

//! STANAG 4586 LOI 4 payload calibration command message.
//!
//! Carries the eighth **command-side** message in the
//! `rustgate-stanag4586` crate, following waypoint upload
//! ([`crate::waypoint_command`]), sensor pointing
//! ([`crate::sensor_pointing_command`]), mission abort
//! ([`crate::mission_abort_command`]), GCS handover
//! ([`crate::gcs_handover_command`]), route upload
//! ([`crate::route_upload_command`]), payload control
//! ([`crate::payload_control_command`]), and emergency status
//! request ([`crate::emergency_status_request`]). Where the prior
//! seven command-side frames each direct the platform to *do
//! something now* — fly to a waypoint, slew the optics, terminate
//! the mission, transfer authority, upload a multi-leg route,
//! start/stop a recorder, or interrupt the telemetry cadence to
//! emit a fresh snapshot — `PayloadCalibrationCommand` instructs
//! an onboard payload to perform a **sensor calibration cycle**:
//! a self-contained, time-bounded routine that brings a sensor
//! back into trim before (or in the middle of) a mission rather
//! than running it open-loop with whatever drift has accumulated
//! since the last calibration.
//!
//! # Operational model
//!
//! Sensor calibration is the operator's pre-mission and mid-mission
//! lever for keeping payload data trustworthy. Inertial gyros drift
//! once the airframe has been on the ramp for a while; a magnetometer
//! that was trimmed at the field of origin no longer reads true once
//! the platform has been ferried to a deployment site with a different
//! local magnetic declination; an EO/IR sensor's dark-frame baseline
//! shifts as the optics warm; a turret's boresight drifts after a hard
//! landing or cargo-bay handling. None of these failures will trip a
//! BIT-report fault — the sensor is operating, just operating
//! *biased*. The minimum-viable command set the operator reaches for
//! is small but distinct:
//!
//! 1. The operator notices a calibration is due — pre-mission ramp
//!    check, periodic mid-mission re-trim before crossing into a
//!    target area, post-handling re-trim after a hard maneuver. They
//!    pick a [`CalibrationKind`] selecting which routine to run
//!    ([`CalibrationKind::GyroAlignment`] for an IMU re-trim,
//!    [`CalibrationKind::MagnetometerCompensation`] for a heading
//!    sensor that has been displaced, [`CalibrationKind::DarkFrameCapture`]
//!    for an EO/IR baseline, [`CalibrationKind::BoresightAlign`] for
//!    a turret that took a knock, [`CalibrationKind::FullSelfTest`]
//!    for the "run everything you have" pre-flight check), a
//!    [`Mode`] biasing how the platform schedules the routine
//!    ([`Mode::Manual`] runs once and waits for the operator's next
//!    command, [`Mode::Automatic`] runs the routine through to
//!    completion without further interaction, [`Mode::ScheduledRecurring`]
//!    asks the platform to repeat the routine at its own internal
//!    cadence until told to stop), and the iteration / timeout
//!    bounds.
//! 2. The GCS emits a `PayloadCalibrationCommand` carrying the
//!    target `vehicle_id`, the target `payload_id` (matching the
//!    same byte value the platform used in its LOI 2-3
//!    [`crate::payload_status`] frame and the LOI 4
//!    [`crate::payload_control_command`], so the operator can
//!    calibrate the bay they are currently looking at by direct byte
//!    comparison rather than an intermediate lookup), the chosen
//!    [`CalibrationKind`] and [`Mode`], an `iteration_count`
//!    (`0` is the documented "single pass" sentinel — run the
//!    routine once and stop; non-zero values request the platform
//!    re-run the routine N additional times for averaging), an
//!    operator-supplied `timeout_secs` (`0` is the documented "no
//!    timeout" sentinel — let the calibration run as long as it
//!    needs; non-zero values let the operator put a hard ceiling
//!    on calibration duration so the platform aborts a routine that
//!    is taking too long rather than blocking on a stuck sensor),
//!    and a `timestamp_unix_ms` for the operator's clock.
//! 3. The platform applies the command: starts the calibration
//!    routine, surfaces progress through the existing LOI 2-3
//!    telemetry surfaces (a `FullSelfTest` will exercise multiple
//!    subsystems and surface their states through
//!    [`crate::sensor_status`] / [`crate::payload_status`] /
//!    [`crate::bit_report`] frames; a single-sensor routine like
//!    `MagnetometerCompensation` only touches the relevant
//!    subsystem), and either runs the routine once
//!    ([`Mode::Manual`]) or to its natural completion
//!    ([`Mode::Automatic`]) or repeats it on the platform's
//!    internal cadence until stopped ([`Mode::ScheduledRecurring`]).
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN`]
//! = 32 bytes.
//!
//! ```text
//! offset │ size │ field                │ type
//! ───────┼──────┼──────────────────────┼──────────────────────────
//!   0    │  4   │ vehicle_id           │ u32  big-endian
//!   4    │  4   │ payload_id           │ u32  big-endian
//!   8    │  1   │ calibration_kind     │ u8   enum value (see below)
//!   9    │  1   │ mode                 │ u8   enum value (see below)
//!  10    │  2   │ reserved             │ zero-padded — must be 0 on encode
//!  12    │  4   │ iteration_count      │ u32  big-endian (0 = single pass)
//!  16    │  4   │ timeout_secs         │ u32  big-endian (0 = no timeout)
//!  20    │  4   │ reserved             │ zero-padded — must be 0 on encode
//!  24    │  8   │ timestamp_unix_ms    │ u64  big-endian (Unix epoch ms)
//! ```
//!
//! The two reserved blocks are zero-filled on encode. The decoder
//! does NOT validate that they are zero on the wire so a future spec
//! revision that allocates the bytes (a calibration sequence number
//! for matching against a future response message, a per-routine
//! tolerance threshold, an optional cryptographic nonce binding the
//! command to the GCS authority that issued it) stays
//! backward-compatible at the frame-length level.
//!
//! # Field semantics
//!
//! - `vehicle_id` — the target platform identifier. Matches the
//!   `vehicle_id` carried by the LOI 2-3 telemetry frames and the
//!   LOI 4 [`crate::waypoint_command`] /
//!   [`crate::sensor_pointing_command`] /
//!   [`crate::mission_abort_command`] /
//!   [`crate::gcs_handover_command`] /
//!   [`crate::route_upload_command`] /
//!   [`crate::payload_control_command`] /
//!   [`crate::emergency_status_request`] frames so a GCS can
//!   correlate "which payload did I command on which platform"
//!   against "which platform's telemetry am I currently displaying"
//!   by direct byte comparison.
//! - `payload_id` — target payload-bay identifier. **Matches the
//!   wire byte position of
//!   [`crate::payload_status::PayloadStatus::payload_id`]** (both
//!   frames put the field at offset 4 with respect to the
//!   payload-scoped wire layout, with `PayloadStatus` having the
//!   field at the start of the frame and this command frame
//!   immediately after a 4-byte `vehicle_id`). The cross-frame
//!   correlation lets a GCS look at a `PayloadStatus` telemetry
//!   frame, copy its `payload_id` byte-for-byte into a follow-up
//!   `PayloadCalibrationCommand`, and be sure the calibration
//!   targets the same bay the telemetry described — pinned in
//!   `payload_id_field_matches_payload_status_module`.
//! - `calibration_kind` — which calibration routine to run. See
//!   [`CalibrationKind`].
//! - `mode` — how the platform should schedule the routine. See
//!   [`Mode`]. [`Mode::ScheduledRecurring`] is the load-bearing
//!   tier for periodic re-trim where the GCS does not want to
//!   pulse a fresh command on every iteration.
//! - `iteration_count` — number of additional calibration iterations
//!   the platform should run for averaging. **`0` is the documented
//!   "single pass" sentinel** — the routine runs once and stops.
//!   Non-zero values request the platform re-run the routine N
//!   additional times after the first pass and average the results
//!   (the documented use-case: long-baseline gyro alignment, where
//!   averaging over multiple samples reduces residual drift below
//!   what a single pass can achieve). A regression that rejected
//!   `0` here would silently drop every "single-pass" command — the
//!   most common case for a quick mid-mission re-trim — pinned in
//!   `decode_accepts_zero_iteration_count_as_single_pass`.
//! - `timeout_secs` — operator's maximum calibration duration before
//!   the platform aborts the routine. **`0` is the documented "no
//!   timeout" sentinel** — the operator places no time bound and
//!   the platform may run the routine to its natural completion.
//!   Non-zero values let the operator put a hard ceiling on
//!   calibration duration so a stuck sensor cannot block the
//!   platform's command loop indefinitely. A regression that
//!   rejected `0` would silently drop every "let it run" command,
//!   pinned in `decode_accepts_zero_timeout_as_no_timeout`. The
//!   codec does not validate the value otherwise — an
//!   unrealistically short timeout is the platform's
//!   calibration-scheduling layer's problem rather than a codec
//!   concern.
//! - `timestamp_unix_ms` — when the GCS issued the command,
//!   milliseconds since the Unix epoch. The platform may use it to
//!   discard a stale command that lost a race against a follow-on
//!   command, or to timestamp the calibration cycle in its own
//!   audit log for post-mission reconstruction. The codec does not
//!   validate the value (zero is legal — represents an
//!   unset/unknown timestamp).
//!
//! # What is deliberately absent
//!
//! - **The calibration response message** — the platform's "routine
//!   started, expected duration N seconds" / "routine complete,
//!   residual error E" / "routine aborted, sensor stuck" reply is
//!   surfaced through the existing LOI 2-3 read-side telemetry
//!   frames ([`crate::sensor_status`], [`crate::payload_status`],
//!   [`crate::bit_report`]) plus a dedicated calibration-result
//!   frame that is a separate follow-up read-side PR rather than a
//!   command-side concern. This module ships only the request side.
//! - **Per-sensor calibration parameter overrides** — operator-supplied
//!   gain trim values, white-balance temperature anchors, or
//!   per-axis bias deltas are deliberately not in the minimum-viable
//!   command set. The default routines the platform implements for
//!   each [`CalibrationKind`] cover the common case; one-off
//!   parameter overrides belong in a follow-up extended-command PR
//!   that allocates the existing reserved bytes for the override
//!   payload.
//! - **Other LOI 4 commands** — mode change is the remaining
//!   command-side message in the LOI 4 minimum-viable command set
//!   and ships in a follow-up PR with its own wire format and
//!   validation rules.
//! - **Response / acknowledgement messages for the request itself** —
//!   the bidirectional command-response handshake (the platform's
//!   "calibration accepted, will run at T+50ms" or "calibration
//!   rejected, sensor unavailable" reply) is a separate follow-up
//!   PR.
//! - **UDP/TCP listener wiring** — this module is pure encode/decode
//!   over `&[u8]`; the network glue is a separate change.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a payload calibration command frame.
pub const PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_PAYLOAD_ID: usize = 4;
const OFF_CALIBRATION_KIND: usize = 8;
const OFF_MODE: usize = 9;
// 10..12 reserved (2 bytes)
const OFF_ITERATION_COUNT: usize = 12;
const OFF_TIMEOUT_SECS: usize = 16;
// 20..24 reserved (4 bytes)
const OFF_TIMESTAMP: usize = 24;

/// Which calibration routine the platform should run on the targeted
/// payload.
///
/// The five named variants cover the LOI 4 payload-calibration
/// minimum-viable command vocabulary: an inertial gyro re-trim
/// ([`CalibrationKind::GyroAlignment`]) for a platform that has been
/// on the ramp long enough for the IMU bias to drift, a magnetometer
/// re-trim ([`CalibrationKind::MagnetometerCompensation`]) for a
/// heading sensor that has been displaced (a ferry to a deployment
/// site with a different local magnetic declination, a hard-iron
/// disturbance from a recent payload swap), an EO/IR dark-frame
/// baseline grab ([`CalibrationKind::DarkFrameCapture`]) once the
/// optics have warmed, a turret boresight re-align
/// ([`CalibrationKind::BoresightAlign`]) after a hard landing or
/// cargo-bay handling that may have shifted the optics relative to
/// the airframe, and a "run everything you have" pre-flight check
/// ([`CalibrationKind::FullSelfTest`]) the operator reaches for at
/// the start of a sortie when they cannot tell which subsystem is
/// most likely to be out of trim. [`CalibrationKind::Other`]
/// preserves any unrecognised wire byte so a future spec revision
/// that allocates a new routine (e.g. an `AltimeterZero` for a
/// pressure-altimeter ground reference, an `OpticsFocus` for a
/// motorised focus mechanism, a `PayloadLinkBudget` for a streamer's
/// receive-side gain-trim sweep) stays decodable on a receiver
/// running today's build — matches the same forward-compat
/// discipline used by every sibling LOI 2-3 / LOI 4 frame's enums.
///
/// # Wire byte values
///
/// | byte  | variant                      |
/// |-------|------------------------------|
/// | `0x01`| `GyroAlignment`              |
/// | `0x02`| `MagnetometerCompensation`   |
/// | `0x03`| `DarkFrameCapture`           |
/// | `0x04`| `BoresightAlign`             |
/// | `0x05`| `FullSelfTest`               |
/// | other | `Other(byte)`                |
///
/// `0x00` deliberately falls into [`CalibrationKind::Other`] rather
/// than having its own "Unknown" variant — the encode side never
/// emits `0x00` for a named routine, so observing one on decode means
/// the upstream sent something unintended and the operator should
/// be able to see the raw byte value in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationKind {
    /// Inertial gyro alignment / bias re-trim. Used after a long
    /// ramp wait or a power cycle where the IMU bias may have
    /// drifted from its last calibrated value.
    GyroAlignment,
    /// Magnetometer compensation / hard-iron re-trim. Used after a
    /// platform has been displaced to a new local magnetic
    /// declination, after a payload swap that may have introduced a
    /// new hard-iron source, or as a periodic re-trim on a long
    /// sortie.
    MagnetometerCompensation,
    /// EO/IR dark-frame baseline capture. Used once the optics have
    /// warmed to operating temperature so the dark-frame reference
    /// reflects the as-flown thermal state of the sensor.
    DarkFrameCapture,
    /// Turret boresight re-alignment. Used after a hard landing,
    /// cargo-bay handling, or any event that may have shifted the
    /// optics relative to the airframe's boresight reference.
    BoresightAlign,
    /// Full self-test — runs every calibration routine the platform
    /// supports. The "run everything you have" pre-flight check the
    /// operator reaches for at the start of a sortie when they
    /// cannot tell which subsystem is most likely to be out of
    /// trim.
    FullSelfTest,
    /// Forward-compat catch-all for calibration-kind bytes the spec
    /// may allocate in a future revision.
    Other(u8),
}

impl CalibrationKind {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::GyroAlignment,
            0x02 => Self::MagnetometerCompensation,
            0x03 => Self::DarkFrameCapture,
            0x04 => Self::BoresightAlign,
            0x05 => Self::FullSelfTest,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::GyroAlignment => 0x01,
            Self::MagnetometerCompensation => 0x02,
            Self::DarkFrameCapture => 0x03,
            Self::BoresightAlign => 0x04,
            Self::FullSelfTest => 0x05,
            Self::Other(b) => b,
        }
    }
}

/// How the platform should schedule the calibration routine against
/// its own command-execution loop.
///
/// The three named variants cover the LOI 4 payload-calibration
/// scheduling vocabulary: a one-shot routine that runs once and
/// stops ([`Mode::Manual`] — the right choice for a deliberate
/// pre-mission re-trim where the operator wants explicit control
/// over each pass), an automatic routine that runs to its natural
/// completion without further interaction
/// ([`Mode::Automatic`] — the right choice for a routine the
/// operator wants done correctly without having to babysit it), and
/// a recurring routine the platform repeats at its own internal
/// cadence until told to stop ([`Mode::ScheduledRecurring`] — the
/// right choice for periodic mid-mission re-trim where pulsing a
/// fresh command on every iteration would waste link budget).
/// [`Mode::Other`] preserves any unrecognised wire byte for
/// forward compatibility.
///
/// # Wire byte values
///
/// | byte  | variant                |
/// |-------|------------------------|
/// | `0x01`| `Manual`               |
/// | `0x02`| `Automatic`            |
/// | `0x03`| `ScheduledRecurring`   |
/// | other | `Other(byte)`          |
///
/// `0x00` deliberately falls into [`Mode::Other`] for the same
/// reason as the [`CalibrationKind`] enum above — the encode side
/// never emits `0x00` for a named mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Manual mode — run the routine once and stop. The right
    /// choice for a deliberate pre-mission re-trim where the
    /// operator wants explicit control over each pass.
    Manual,
    /// Automatic mode — run the routine to its natural completion
    /// without further interaction. The right choice for a routine
    /// the operator wants done correctly without having to babysit
    /// it.
    Automatic,
    /// Scheduled-recurring mode — repeat the routine at the
    /// platform's own internal cadence until told to stop. The
    /// right choice for periodic mid-mission re-trim where pulsing
    /// a fresh command on every iteration would waste link budget.
    ScheduledRecurring,
    /// Forward-compat catch-all for mode bytes the spec may
    /// allocate in a future revision.
    Other(u8),
}

impl Mode {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::Manual,
            0x02 => Self::Automatic,
            0x03 => Self::ScheduledRecurring,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Manual => 0x01,
            Self::Automatic => 0x02,
            Self::ScheduledRecurring => 0x03,
            Self::Other(b) => b,
        }
    }
}

/// LOI 4 payload calibration command message.
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadCalibrationCommand {
    /// Target platform identifier (matches
    /// [`crate::vehicle_position::VehiclePosition::vehicle_id`]).
    pub vehicle_id: u32,
    /// Target payload-bay identifier. Wire-byte-compatible with
    /// [`crate::payload_status::PayloadStatus::payload_id`] so a GCS
    /// can copy the field byte-for-byte from a status frame into a
    /// follow-up calibration command.
    pub payload_id: u32,
    /// Which calibration routine the platform should run on the
    /// targeted payload.
    pub calibration_kind: CalibrationKind,
    /// How the platform should schedule the routine against its own
    /// command-execution loop.
    pub mode: Mode,
    /// Number of additional calibration iterations the platform
    /// should run for averaging. `0` represents a single-pass
    /// routine; non-zero values request the platform re-run the
    /// routine N additional times after the first pass.
    pub iteration_count: u32,
    /// Operator's maximum calibration duration in seconds before
    /// the platform aborts the routine. `0` represents "no
    /// timeout" — the operator places no time bound and the
    /// platform may run the routine to its natural completion.
    pub timeout_secs: u32,
    /// When the GCS issued the command, milliseconds since the
    /// Unix epoch. `0` represents an unset / unknown timestamp.
    pub timestamp_unix_ms: u64,
}

impl PayloadCalibrationCommand {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a payload calibration command frame into a freshly
/// allocated `Vec<u8>`.
#[must_use]
pub fn encode(msg: &PayloadCalibrationCommand) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
///
/// Useful when the encoded frame will be the body of a larger packet
/// and the caller wants to avoid the intermediate `Vec` allocation
/// of [`encode`]. Appends [`PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN`]
/// bytes; does not clear or truncate `buf`.
pub fn encode_into(msg: &PayloadCalibrationCommand, buf: &mut BytesMut) {
    buf.reserve(PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN);
    buf.put_u32(msg.vehicle_id);
    buf.put_u32(msg.payload_id);
    buf.put_u8(msg.calibration_kind.to_byte());
    buf.put_u8(msg.mode.to_byte());
    // 2 reserved bytes.
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u32(msg.iteration_count);
    buf.put_u32(msg.timeout_secs);
    // 4 reserved bytes.
    buf.put_u32(0);
    buf.put_u64(msg.timestamp_unix_ms);
}

/// Decode a payload calibration command frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
///
/// Trailing bytes beyond [`PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN`]
/// are ignored; the codec is fixed-size and a future protocol
/// revision that appends fields keeps decoding the prefix unchanged.
///
/// All numeric fields accept any wire value — `vehicle_id` and
/// `payload_id` are opaque deployment-defined identifiers, the
/// timestamp is not range-checked, and `iteration_count == 0` /
/// `timeout_secs == 0` are the documented "single pass" / "no
/// timeout" sentinels (pinned by dedicated tests).
///
/// Unrecognised `calibration_kind` and `mode` bytes do NOT cause
/// an error — they surface as [`CalibrationKind::Other`] /
/// [`Mode::Other`] for forward compatibility.
pub fn decode(bytes: &[u8]) -> Result<PayloadCalibrationCommand, Stanag4586Error> {
    if bytes.len() < PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN,
        });
    }

    let mut cursor = &bytes[..PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN];
    let vehicle_id = cursor.get_u32();
    let payload_id = cursor.get_u32();
    let calibration_kind = CalibrationKind::from_byte(cursor.get_u8());
    let mode = Mode::from_byte(cursor.get_u8());
    // Skip 2-byte reserved region.
    cursor.advance(2);
    let iteration_count = cursor.get_u32();
    let timeout_secs = cursor.get_u32();
    // Skip 4-byte reserved region.
    cursor.advance(4);
    let timestamp_unix_ms = cursor.get_u64();

    debug_assert!(
        cursor.is_empty(),
        "fixed-size frame should be fully consumed; bug in offset constants"
    );
    let _ = OFF_VEHICLE_ID;
    let _ = OFF_PAYLOAD_ID;
    let _ = OFF_CALIBRATION_KIND;
    let _ = OFF_MODE;
    let _ = OFF_ITERATION_COUNT;
    let _ = OFF_TIMEOUT_SECS;
    let _ = OFF_TIMESTAMP;

    Ok(PayloadCalibrationCommand {
        vehicle_id,
        payload_id,
        calibration_kind,
        mode,
        iteration_count,
        timeout_secs,
        timestamp_unix_ms,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::payload_status::{self, PayloadKind, PayloadStatus, RecordingState, StreamingState};

    /// Zero-valued fixture — exercises every "0 is a documented
    /// sentinel" path at once: `iteration_count == 0` ("single
    /// pass"), `timeout_secs == 0` ("no timeout"),
    /// `timestamp_unix_ms == 0` (unset/unknown). The two enum bytes
    /// fall through to `Other(0)` — the encode side never emits
    /// `0x00` for a named variant, but the round-trip must hold
    /// even at this corner.
    fn zero_valued_command() -> PayloadCalibrationCommand {
        PayloadCalibrationCommand {
            vehicle_id: 0,
            payload_id: 0,
            calibration_kind: CalibrationKind::Other(0),
            mode: Mode::Other(0),
            iteration_count: 0,
            timeout_secs: 0,
            timestamp_unix_ms: 0,
        }
    }

    /// Typical pre-mission ramp re-trim: a single-pass gyro
    /// alignment under manual control with no operator-imposed
    /// timeout. Pins the `GyroAlignment` + `Manual` operational
    /// case the module-level docs call out as the default
    /// pre-flight gesture.
    fn gyro_manual_command() -> PayloadCalibrationCommand {
        PayloadCalibrationCommand {
            vehicle_id: 0xA1B2_C3D4,
            payload_id: 0x0000_0042,
            calibration_kind: CalibrationKind::GyroAlignment,
            mode: Mode::Manual,
            iteration_count: 0,
            timeout_secs: 0,
            timestamp_unix_ms: 0x0000_0001_600F_1234,
        }
    }

    /// Long-baseline averaging routine: a `FullSelfTest` driven
    /// `Automatic` with a non-zero iteration count for averaging
    /// and a 5-minute timeout ceiling. Pins the heavyweight
    /// pre-flight case the module-level docs call out.
    fn full_self_test_automatic_command() -> PayloadCalibrationCommand {
        PayloadCalibrationCommand {
            vehicle_id: 0xDEAD_BEEF,
            payload_id: 7,
            calibration_kind: CalibrationKind::FullSelfTest,
            mode: Mode::Automatic,
            iteration_count: 4,
            timeout_secs: 300,
            timestamp_unix_ms: 0x0000_0001_700A_BCDE,
        }
    }

    // ---- Round-trip ----

    #[test]
    fn round_trip_zero_valued_fixture() {
        let msg = zero_valued_command();
        let bytes = encode(&msg);
        assert_eq!(bytes, vec![0u8; PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN]);
        let decoded = decode(&bytes).expect("zero round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_gyro_manual_fixture() {
        let msg = gyro_manual_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN);
        let decoded = decode(&bytes).expect("gyro/manual round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_full_self_test_automatic_fixture() {
        let msg = full_self_test_automatic_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN);
        let decoded = decode(&bytes).expect("full-self-test/automatic round-trip");
        assert_eq!(decoded, msg);
    }

    // ---- Zero-as-sentinel acceptance ----

    #[test]
    fn decode_accepts_zero_iteration_count_as_single_pass() {
        // Pin the single-pass-sentinel contract: senders write `0`
        // for `iteration_count` to request a one-shot routine.
        // A regression that rejected `0` here would silently drop
        // every "single-pass" command — the most common case for a
        // quick mid-mission re-trim.
        let msg = PayloadCalibrationCommand {
            vehicle_id: 1,
            payload_id: 1,
            calibration_kind: CalibrationKind::MagnetometerCompensation,
            mode: Mode::Manual,
            iteration_count: 0,
            timeout_secs: 60,
            timestamp_unix_ms: 1,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("zero iteration_count must decode cleanly");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.iteration_count, 0);
    }

    #[test]
    fn decode_accepts_zero_timeout_as_no_timeout() {
        // Pin the no-timeout-sentinel contract: senders write `0`
        // for `timeout_secs` to decline to bound the calibration
        // duration. A regression that rejected `0` would silently
        // drop every "let it run" command.
        let msg = PayloadCalibrationCommand {
            vehicle_id: 1,
            payload_id: 1,
            calibration_kind: CalibrationKind::DarkFrameCapture,
            mode: Mode::Automatic,
            iteration_count: 2,
            timeout_secs: 0,
            timestamp_unix_ms: 1,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("zero timeout_secs must decode cleanly");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.timeout_secs, 0);
    }

    // ---- Golden-fixture decode ----

    #[test]
    fn decode_known_fixture_matches_expected_bytes() {
        // Hand-built golden fixture that pins every field at its
        // documented byte offset. The big-endian byte sequences for
        // the u32 / u64 fields are computed in the test source so a
        // regression that swapped to little-endian could pass
        // round-trip and proptest but would still fail this
        // byte-pinning check.
        //
        // Field values:
        //   vehicle_id        = 0x1122_3344
        //   payload_id        = 0xAABB_CCDD
        //   calibration_kind  = 0x01 (GyroAlignment)
        //   mode              = 0x02 (Automatic)
        //   iteration_count   = 0x0000_0005
        //   timeout_secs      = 0x0000_003C (60s)
        //   timestamp_unix_ms = 0xFEDC_BA98_7654_3210
        let msg = PayloadCalibrationCommand {
            vehicle_id: 0x1122_3344,
            payload_id: 0xAABB_CCDD,
            calibration_kind: CalibrationKind::GyroAlignment,
            mode: Mode::Automatic,
            iteration_count: 0x0000_0005,
            timeout_secs: 0x0000_003C,
            timestamp_unix_ms: 0xFEDC_BA98_7654_3210,
        };
        let bytes = encode(&msg);
        let expected: [u8; PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN] = [
            // vehicle_id = 0x1122_3344 (big-endian)
            0x11, 0x22, 0x33, 0x44, //
            // payload_id = 0xAABB_CCDD (big-endian)
            0xAA, 0xBB, 0xCC, 0xDD, //
            // calibration_kind = 0x01 (GyroAlignment)
            0x01, //
            // mode = 0x02 (Automatic)
            0x02, //
            // 2 reserved zero bytes
            0x00, 0x00, //
            // iteration_count = 0x0000_0005 (big-endian)
            0x00, 0x00, 0x00, 0x05, //
            // timeout_secs = 0x0000_003C (big-endian, 60s)
            0x00, 0x00, 0x00, 0x3C, //
            // 4 reserved zero bytes
            0x00, 0x00, 0x00, 0x00, //
            // timestamp_unix_ms = 0xFEDC_BA98_7654_3210 (big-endian)
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        assert_eq!(
            bytes.as_slice(),
            &expected[..],
            "encoded bytes must match the documented byte layout"
        );
        let decoded = decode(&expected).expect("golden decode");
        assert_eq!(decoded, msg);
        // Pin the named variants the bytes resolve to so a future
        // refactor that rebinds either byte accidentally trips this
        // assertion rather than silently changing operational
        // semantics.
        assert_eq!(decoded.calibration_kind, CalibrationKind::GyroAlignment);
        assert_eq!(decoded.mode, Mode::Automatic);
    }

    // ---- Truncation sweep ----

    #[test]
    fn decode_truncation_sweep_returns_frame_too_short() {
        for &len in &[0_usize, 1, 4, 8, 12, 16, 24, 31] {
            let bytes = vec![0u8; len];
            let err = decode(&bytes).expect_err("truncation must error");
            match err {
                Stanag4586Error::FrameTooShort { actual, expected } => {
                    assert_eq!(actual, len);
                    assert_eq!(expected, PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN);
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
        let msg = gyro_manual_command();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(&[0xAA; 32]);
        assert_eq!(bytes.len(), 64);
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
    }

    // ---- CalibrationKind enum round-trip ----

    #[test]
    fn calibration_kind_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, CalibrationKind)] = &[
            (0x01, CalibrationKind::GyroAlignment),
            (0x02, CalibrationKind::MagnetometerCompensation),
            (0x03, CalibrationKind::DarkFrameCapture),
            (0x04, CalibrationKind::BoresightAlign),
            (0x05, CalibrationKind::FullSelfTest),
            (0xFF, CalibrationKind::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = CalibrationKind::from_byte(*byte);
            assert_eq!(decoded, *expected, "from_byte mismatch for byte={byte:#x}");
            assert_eq!(
                decoded.to_byte(),
                *byte,
                "to_byte mismatch for {expected:?}"
            );
        }
        // Unknown bytes outside the named table also round-trip via
        // `Other`. 0x00 is in this set — the encode side never emits
        // it for a named kind, so observing it on decode means the
        // upstream sent something unintended.
        for byte in [0x00u8, 0x06, 0x42, 0xEE] {
            let decoded = CalibrationKind::from_byte(byte);
            assert_eq!(decoded, CalibrationKind::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- Mode enum round-trip ----

    #[test]
    fn mode_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, Mode)] = &[
            (0x01, Mode::Manual),
            (0x02, Mode::Automatic),
            (0x03, Mode::ScheduledRecurring),
            (0xFF, Mode::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = Mode::from_byte(*byte);
            assert_eq!(decoded, *expected, "from_byte mismatch for byte={byte:#x}");
            assert_eq!(
                decoded.to_byte(),
                *byte,
                "to_byte mismatch for {expected:?}"
            );
        }
        for byte in [0x00u8, 0x04, 0x42, 0xEE] {
            let decoded = Mode::from_byte(byte);
            assert_eq!(decoded, Mode::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- Cross-frame payload_id correlation ----

    #[test]
    fn payload_id_field_matches_payload_status_module() {
        // Pin the cross-frame correlation contract: a GCS that
        // observes a `PayloadStatus` telemetry frame for
        // payload_id=42 (#1157) and emits a follow-up
        // `PayloadCalibrationCommand` with `payload_id: 42` MUST
        // produce the same big-endian byte sequence in the wire
        // payload_id field of both frames. Without this guarantee,
        // an operator who copied the bytes verbatim from a status
        // frame into a calibration command could end up calibrating
        // a different payload — a silent footgun the codec is
        // explicitly designed to prevent.
        //
        // The two frames place `payload_id` at different absolute
        // offsets (PayloadStatus at offset 0,
        // PayloadCalibrationCommand at offset 4 — after the leading
        // vehicle_id), so the pinned property is "the four-byte
        // big-endian representation of the same logical value is
        // byte-for-byte identical between the two frames", not
        // "the absolute offset is the same".
        const PAYLOAD_ID: u32 = 42;
        const VEHICLE_ID: u32 = 0xCAFE_BABE;

        // Build a payload_status frame and locate its `payload_id`
        // bytes — the payload-status layout puts the field at
        // offset 0..4.
        let status = PayloadStatus {
            payload_id: PAYLOAD_ID,
            payload_kind: PayloadKind::Recorder,
            recording_state: RecordingState::Recording,
            streaming_state: StreamingState::Idle,
            storage_used_pct: 50.0,
            link_bandwidth_kbps: 1024.0,
            link_latency_ms: 10.0,
            timestamp_unix_ms: 1,
        };
        let status_bytes = payload_status::encode(&status);
        let status_payload_id_bytes = &status_bytes[0..4];

        // Build a payload_calibration_command frame with the same
        // logical `payload_id` — the command-side layout puts the
        // field at offset 4..8 (after the leading vehicle_id).
        let command = PayloadCalibrationCommand {
            vehicle_id: VEHICLE_ID,
            payload_id: PAYLOAD_ID,
            calibration_kind: CalibrationKind::BoresightAlign,
            mode: Mode::Manual,
            iteration_count: 0,
            timeout_secs: 0,
            timestamp_unix_ms: 1,
        };
        let command_bytes = encode(&command);
        let command_payload_id_bytes = &command_bytes[OFF_PAYLOAD_ID..OFF_PAYLOAD_ID + 4];

        // The four wire bytes representing the same logical
        // payload_id value MUST be byte-for-byte identical between
        // the two frames so the cross-frame correlation is
        // safe-by-construction.
        assert_eq!(
            status_payload_id_bytes, command_payload_id_bytes,
            "payload_id wire bytes must match across PayloadStatus and PayloadCalibrationCommand"
        );
        // Sanity-check the literal big-endian encoding of 42 so a
        // future refactor that swaps the wire format on either
        // frame still trips this test.
        assert_eq!(status_payload_id_bytes, &[0x00, 0x00, 0x00, 0x2A]);
        assert_eq!(command_payload_id_bytes, &[0x00, 0x00, 0x00, 0x2A]);
    }

    // ---- Convenience method parity ----

    #[test]
    fn encode_to_vec_method_matches_free_encode_function() {
        // The struct-method convenience wrapper must produce
        // byte-identical output to the free function — no surprises
        // for callers who switch between styles.
        let msg = gyro_manual_command();
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
        encode_into(&gyro_manual_command(), &mut buf);
        assert_eq!(buf.len(), 3 + PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN);
        assert_eq!(&buf[0..3], &[0xAA, 0xBB, 0xCC]);
        let standalone = encode(&gyro_manual_command());
        assert_eq!(&buf[3..], &standalone[..]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        // Property test: any valid struct round-trips byte-for-byte.
        // All numeric fields are unconstrained — there are no range
        // checks on the wire — and the two enum bytes cover every
        // u8 value (named variants for the recognised bytes,
        // `Other` for the rest).
        #[test]
        fn round_trip_via_proptest(
            vehicle_id in any::<u32>(),
            payload_id in any::<u32>(),
            calibration_byte in any::<u8>(),
            mode_byte in any::<u8>(),
            iteration_count in any::<u32>(),
            timeout_secs in any::<u32>(),
            timestamp_unix_ms in any::<u64>(),
        ) {
            let original = PayloadCalibrationCommand {
                vehicle_id,
                payload_id,
                calibration_kind: CalibrationKind::from_byte(calibration_byte),
                mode: Mode::from_byte(mode_byte),
                iteration_count,
                timeout_secs,
                timestamp_unix_ms,
            };
            let bytes = encode(&original);
            prop_assert_eq!(bytes.len(), PAYLOAD_CALIBRATION_COMMAND_FRAME_LEN);
            let decoded = decode(&bytes).expect("decode round-trip");
            prop_assert_eq!(decoded, original);
        }
    }
}
