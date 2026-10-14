// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! STANAG 4586 LOI 4 payload control command message.
//!
//! Carries the sixth **command-side** message in the
//! `rustgate-stanag4586` crate, following waypoint upload
//! ([`crate::waypoint_command`]), sensor pointing
//! ([`crate::sensor_pointing_command`]), mission abort
//! ([`crate::mission_abort_command`]), GCS handover
//! ([`crate::gcs_handover_command`]), and route upload
//! ([`crate::route_upload_command`]). Where waypoint upload, sensor
//! pointing, mission abort, GCS handover, and route upload each
//! direct the airframe (the flight path, the optics, the active
//! mission, the controlling station, the multi-leg route),
//! **payload control** directs an onboard payload bay — a recorder,
//! a streamer, a sensor link — telling it to start, stop, pause,
//! resume, or reconfigure its current operation. It is the
//! command-side companion to the LOI 2-3
//! [`crate::payload_status`] read-side telemetry frame: where
//! `PayloadStatus` reports "the recorder is `Recording`, storage at
//! 42%, link at 8 Mbps", `PayloadControlCommand` lets the operator
//! send the corresponding `Start`, `Stop`, `Pause`, or `Configure`
//! instruction back to that same payload.
//!
//! # Operational model
//!
//! Payload control is the second of the two command-side surfaces
//! the LOI 2-3 telemetry frames imply but do not themselves provide:
//! sensor pointing ([`crate::sensor_pointing_command`]) commands the
//! optics, payload control commands the recording/streaming bay
//! behind those optics. A typical workflow looks like:
//!
//! 1. The platform emits LOI 2-3 [`crate::payload_status`] frames at
//!    1–5 Hz reporting the bay's current `recording_state`,
//!    `streaming_state`, `storage_used_pct`, etc. The operator sees
//!    the state on the GCS UI.
//! 2. The operator decides to act — start a recording before
//!    crossing into the target area, pause an ongoing stream while
//!    the platform climbs through a known-noisy altitude band,
//!    reconfigure the streamer's bandwidth ceiling because the
//!    downlink is congested, stop a recording whose data is no
//!    longer mission-relevant.
//! 3. The GCS emits a `PayloadControlCommand` carrying the target
//!    `payload_id` (matching the same byte value that the platform
//!    used in its LOI 2-3 [`crate::payload_status`] frame, so the
//!    operator can act on the bay they are currently looking at by
//!    direct byte comparison rather than an intermediate lookup), a
//!    [`ControlAction`] selecting the action
//!    ([`ControlAction::Start`] / [`ControlAction::Stop`] /
//!    [`ControlAction::Pause`] / [`ControlAction::Resume`] /
//!    [`ControlAction::Configure`]), an optional
//!    [`QualityPreset`] biasing the encoder's quality/bitrate
//!    trade-off, and optional `bandwidth_kbps_limit` /
//!    `record_duration_secs` configuration values.
//! 4. The platform applies the command, transitions its
//!    `recording_state` / `streaming_state`, and the next
//!    [`crate::payload_status`] frame reflects the new state — the
//!    operator sees their command take effect on the same UI panel.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`PAYLOAD_CONTROL_COMMAND_FRAME_LEN`] = 32
//! bytes.
//!
//! ```text
//! offset │ size │ field                │ type
//! ───────┼──────┼──────────────────────┼──────────────────────────
//!   0    │  4   │ vehicle_id           │ u32  big-endian
//!   4    │  4   │ payload_id           │ u32  big-endian
//!   8    │  1   │ control_action       │ u8   enum value (see below)
//!   9    │  1   │ quality_preset       │ u8   enum value (see below)
//!  10    │  2   │ reserved             │ zero-padded — must be 0 on encode
//!  12    │  4   │ bandwidth_kbps_limit │ u32  big-endian (0 = no limit)
//!  16    │  4   │ record_duration_secs │ u32  big-endian (0 = unbounded)
//!  20    │  4   │ reserved             │ zero-padded — must be 0 on encode
//!  24    │  8   │ timestamp_unix_ms    │ u64  big-endian (Unix epoch ms)
//! ```
//!
//! The two reserved blocks are zero-filled on encode. The decoder
//! does NOT validate them — a future spec revision that allocates
//! the bytes (a recording-format selector, a streamer-codec hint, a
//! command sequence number for matching against the future response
//! message) stays backward-compatible at the frame-length level.
//!
//! # Field semantics
//!
//! - `vehicle_id` — the target platform identifier. Matches the
//!   `vehicle_id` carried by the LOI 2-3 telemetry frames and the
//!   LOI 4 [`crate::waypoint_command`] /
//!   [`crate::sensor_pointing_command`] /
//!   [`crate::mission_abort_command`] /
//!   [`crate::gcs_handover_command`] /
//!   [`crate::route_upload_command`] frames so a GCS can correlate
//!   "which payload did I command on which platform" against "which
//!   platform's telemetry am I currently displaying" by direct byte
//!   comparison.
//! - `payload_id` — target payload-bay identifier. **Matches the
//!   wire byte position of
//!   [`crate::payload_status::PayloadStatus::payload_id`]** (both
//!   frames put the field at offset 4 with respect to the
//!   payload-scoped wire layout, with `PayloadStatus` having the
//!   field at the start of the frame and this command frame
//!   immediately after a 4-byte `vehicle_id`). The cross-frame
//!   correlation lets a GCS look at a `PayloadStatus` telemetry
//!   frame, copy its `payload_id` byte-for-byte into a follow-up
//!   `PayloadControlCommand`, and be sure the command targets the
//!   same bay the telemetry described — pinned in
//!   `payload_id_field_matches_payload_status_module`.
//! - `control_action` — what the platform should do with the
//!   payload. See [`ControlAction`].
//! - `quality_preset` — bias for the encoder's quality / bitrate
//!   trade-off when the action is [`ControlAction::Start`] or
//!   [`ControlAction::Configure`]. See [`QualityPreset`]. Ignored by
//!   the platform for `Stop` / `Pause` / `Resume` actions; the codec
//!   carries the byte unchanged regardless.
//! - `bandwidth_kbps_limit` — operator-chosen bandwidth ceiling for
//!   streaming payloads in kilobits/sec. **`0` is the documented
//!   "no limit" sentinel** — the operator declined to constrain
//!   bandwidth and the platform should use whatever the streamer's
//!   default policy chooses. A regression that rejected `0` here
//!   would silently drop every "unconstrained" payload command (the
//!   most common operational case for a recorder, where bandwidth is
//!   irrelevant), pinned in
//!   `decode_accepts_zero_bandwidth_limit_as_no_limit_sentinel`. The
//!   codec does not validate the value otherwise — an unrealistically
//!   large limit is the platform's streamer-policy layer's problem
//!   rather than a codec concern.
//! - `record_duration_secs` — for [`ControlAction::Start`] commands
//!   on recorders, the maximum duration of the recording session in
//!   seconds. **`0` is the documented "unbounded" sentinel** — the
//!   recording continues until storage fills, the operator issues a
//!   subsequent [`ControlAction::Stop`], or the platform terminates
//!   it for some other reason. A regression that rejected `0` would
//!   silently drop every "record until told to stop" command, pinned
//!   in `decode_accepts_zero_record_duration_as_unbounded_sentinel`.
//! - `timestamp_unix_ms` — when the GCS issued the command,
//!   milliseconds since the Unix epoch. The platform may use it to
//!   discard a stale command that lost a race against a follow-on
//!   command, or to timestamp the action in its own audit log for
//!   post-mission reconstruction. The codec does not validate the
//!   value (zero is legal — represents an unset/unknown timestamp).
//!
//! # What is deliberately absent
//!
//! - **Other LOI 4 commands** — mode change is the remaining
//!   command-side message in the LOI 4 minimum-viable command set
//!   and ships in a follow-up PR with its own wire format and
//!   validation rules.
//! - **Sensor calibration commands** — gain trim, white balance,
//!   focus, sensor-internal configuration — are a separate
//!   command-side surface from this payload start/stop/pause control
//!   and out of scope for this codec.
//! - **Route-time-window updates** — re-anchoring an already-uploaded
//!   route's `start_unix_ms` / `expiry_unix_ms` without re-uploading
//!   the constituent waypoints belongs on the [`crate::route_upload_command`]
//!   surface; it is not a payload-bay operation and is out of scope
//!   here.
//! - **Response / acknowledgement messages** — the bidirectional
//!   command-response handshake (the platform's "recording started,
//!   session id N" or "configure rejected, bandwidth limit below
//!   minimum" reply) is a separate follow-up PR.
//! - **UDP/TCP listener wiring** — this module is pure encode/decode
//!   over `&[u8]`; the network glue is a separate change.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a payload control command frame.
pub const PAYLOAD_CONTROL_COMMAND_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_PAYLOAD_ID: usize = 4;
const OFF_CONTROL_ACTION: usize = 8;
const OFF_QUALITY_PRESET: usize = 9;
// 10..12 reserved (2 bytes)
const OFF_BANDWIDTH_LIMIT: usize = 12;
const OFF_RECORD_DURATION: usize = 16;
// 20..24 reserved (4 bytes)
const OFF_TIMESTAMP: usize = 24;

/// What the platform should do with the targeted payload.
///
/// The five named variants cover the LOI 4 payload-control
/// minimum-viable command vocabulary: start the payload's primary
/// operation ([`ControlAction::Start`] — begin recording, begin
/// streaming), stop it cleanly ([`ControlAction::Stop`] — finalise
/// the recording / close the stream), suspend it without releasing
/// resources ([`ControlAction::Pause`] — keep the session open,
/// stop accepting new data), resume from a paused state
/// ([`ControlAction::Resume`]), or reconfigure live operating
/// parameters ([`ControlAction::Configure`] — apply
/// `bandwidth_kbps_limit` / `record_duration_secs` to the running
/// session). [`ControlAction::Other`] preserves any unrecognised
/// wire byte so a future spec revision allocating a new action
/// (e.g. a `Snapshot` for grabbing a single-frame still while a
/// stream is running, or a `Flush` for forcing a buffered streamer
/// to drain) stays decodable on a receiver running today's build —
/// matches the same forward-compat discipline used by every
/// sibling LOI 2-3 / LOI 4 frame's enums.
///
/// # Wire byte values
///
/// | byte  | variant       |
/// |-------|---------------|
/// | `0x01`| `Start`       |
/// | `0x02`| `Stop`        |
/// | `0x03`| `Pause`       |
/// | `0x04`| `Resume`      |
/// | `0x05`| `Configure`   |
/// | other | `Other(byte)` |
///
/// `0x00` deliberately falls into [`ControlAction::Other`] rather
/// than having its own "Unknown" variant — the encode side never
/// emits `0x00` for a named action, so observing one on decode means
/// the upstream sent something unintended and the operator should
/// be able to see the raw byte value in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlAction {
    /// Begin the payload's primary operation (start recording, start
    /// streaming).
    Start,
    /// Finish the payload's current operation cleanly (close the
    /// recording, close the stream).
    Stop,
    /// Suspend the payload's current operation without releasing
    /// session resources; data accumulation pauses but the session
    /// remains open.
    Pause,
    /// Resume from a paused state — the inverse of
    /// [`ControlAction::Pause`].
    Resume,
    /// Reconfigure live operating parameters
    /// (`bandwidth_kbps_limit`, `record_duration_secs`,
    /// `quality_preset`) on a running session without stopping it.
    Configure,
    /// Forward-compat catch-all for control-action bytes the spec
    /// may allocate in a future revision.
    Other(u8),
}

impl ControlAction {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::Start,
            0x02 => Self::Stop,
            0x03 => Self::Pause,
            0x04 => Self::Resume,
            0x05 => Self::Configure,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Start => 0x01,
            Self::Stop => 0x02,
            Self::Pause => 0x03,
            Self::Resume => 0x04,
            Self::Configure => 0x05,
            Self::Other(b) => b,
        }
    }
}

/// Encoder quality / bitrate-bias preset.
///
/// The four named variants give the operator a coarse bias on the
/// quality-vs-bandwidth trade-off without the codec having to model
/// every encoder parameter individually. The semantics of each
/// preset are deployment-defined — what counts as "Medium" on an EO
/// turret may differ from "Medium" on an IR sensor — but the
/// ordinal sequence is preserved across deployments so an operator
/// who learns "High is the right bias for nominal-link target
/// prosecution" on one platform can carry that intuition to
/// another. **Operational note**: [`QualityPreset::Maximum`] is
/// tagged as a distinct variant rather than a synonym for `High` to
/// pin that the operator explicitly accepted whatever bandwidth /
/// storage cost the encoder needs at full quality — typically used
/// only for short-duration close-up captures where archival
/// fidelity outweighs link-budget considerations. A regression that
/// silently downgraded `Maximum` to `High` to "save bandwidth"
/// would defeat the operator's explicit choice.
///
/// [`QualityPreset::Other`] preserves any unrecognised wire byte
/// for forward compatibility with future spec revisions.
///
/// # Wire byte values
///
/// | byte  | variant       |
/// |-------|---------------|
/// | `0x01`| `Low`         |
/// | `0x02`| `Medium`      |
/// | `0x03`| `High`        |
/// | `0x04`| `Maximum`     |
/// | other | `Other(byte)` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityPreset {
    /// Low quality / low bitrate — the right choice when bandwidth
    /// is constrained and "we have something" outranks "we have a
    /// pristine recording".
    Low,
    /// Mid-quality / mid-bitrate balance — the typical default for
    /// nominal-link operations.
    Medium,
    /// High quality / high bitrate — biases towards fidelity at
    /// the cost of link budget; the right choice for
    /// target-prosecution captures over a healthy link.
    High,
    /// Maximum quality / encoder-defined ceiling — operator has
    /// explicitly accepted whatever bandwidth / storage cost the
    /// encoder needs. Used for short-duration close-up captures
    /// where archival fidelity outweighs link-budget concerns.
    Maximum,
    /// Forward-compat catch-all for quality-preset bytes the spec
    /// may allocate in a future revision.
    Other(u8),
}

impl QualityPreset {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::Low,
            0x02 => Self::Medium,
            0x03 => Self::High,
            0x04 => Self::Maximum,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Low => 0x01,
            Self::Medium => 0x02,
            Self::High => 0x03,
            Self::Maximum => 0x04,
            Self::Other(b) => b,
        }
    }
}

/// LOI 4 payload control command message.
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadControlCommand {
    /// Target platform identifier (matches
    /// [`crate::vehicle_position::VehiclePosition::vehicle_id`]).
    pub vehicle_id: u32,
    /// Target payload-bay identifier. Wire-byte-compatible with
    /// [`crate::payload_status::PayloadStatus::payload_id`] so a GCS
    /// can copy the field byte-for-byte from a status frame into a
    /// follow-up command.
    pub payload_id: u32,
    /// What the platform should do with the targeted payload.
    pub control_action: ControlAction,
    /// Encoder quality / bitrate bias for the action. Carried
    /// unchanged for actions that do not consume it (e.g. `Stop`,
    /// `Pause`, `Resume`).
    pub quality_preset: QualityPreset,
    /// Operator-chosen bandwidth ceiling for streaming payloads in
    /// kilobits/sec. `0` represents "no limit".
    pub bandwidth_kbps_limit: u32,
    /// For [`ControlAction::Start`] commands on recorders, the
    /// maximum duration of the recording session in seconds. `0`
    /// represents an unbounded session (until storage fills, until
    /// the operator stops, …).
    pub record_duration_secs: u32,
    /// When the GCS issued the command, milliseconds since the
    /// Unix epoch. `0` represents an unset / unknown timestamp.
    pub timestamp_unix_ms: u64,
}

impl PayloadControlCommand {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a payload control command frame into a freshly allocated
/// `Vec<u8>`.
#[must_use]
pub fn encode(msg: &PayloadControlCommand) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(PAYLOAD_CONTROL_COMMAND_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
///
/// Useful when the encoded frame will be the body of a larger packet
/// and the caller wants to avoid the intermediate `Vec` allocation
/// of [`encode`]. Appends [`PAYLOAD_CONTROL_COMMAND_FRAME_LEN`]
/// bytes; does not clear or truncate `buf`.
pub fn encode_into(msg: &PayloadControlCommand, buf: &mut BytesMut) {
    buf.reserve(PAYLOAD_CONTROL_COMMAND_FRAME_LEN);
    buf.put_u32(msg.vehicle_id);
    buf.put_u32(msg.payload_id);
    buf.put_u8(msg.control_action.to_byte());
    buf.put_u8(msg.quality_preset.to_byte());
    // 2 reserved bytes.
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u32(msg.bandwidth_kbps_limit);
    buf.put_u32(msg.record_duration_secs);
    // 4 reserved bytes.
    buf.put_u32(0);
    buf.put_u64(msg.timestamp_unix_ms);
}

/// Decode a payload control command frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
///
/// Trailing bytes beyond [`PAYLOAD_CONTROL_COMMAND_FRAME_LEN`] are
/// ignored; the codec is fixed-size and a future protocol revision
/// that appends fields keeps decoding the prefix unchanged.
///
/// All numeric fields accept any wire value — `vehicle_id` and
/// `payload_id` are opaque deployment-defined identifiers, the
/// timestamp is not range-checked, and `bandwidth_kbps_limit == 0`
/// / `record_duration_secs == 0` are the documented "no limit" /
/// "unbounded" sentinels (pinned by dedicated tests).
///
/// Unrecognised `control_action` and `quality_preset` bytes do NOT
/// cause an error — they surface as [`ControlAction::Other`] /
/// [`QualityPreset::Other`] for forward compatibility.
pub fn decode(bytes: &[u8]) -> Result<PayloadControlCommand, Stanag4586Error> {
    if bytes.len() < PAYLOAD_CONTROL_COMMAND_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: PAYLOAD_CONTROL_COMMAND_FRAME_LEN,
        });
    }

    let mut cursor = &bytes[..PAYLOAD_CONTROL_COMMAND_FRAME_LEN];
    let vehicle_id = cursor.get_u32();
    let payload_id = cursor.get_u32();
    let control_action = ControlAction::from_byte(cursor.get_u8());
    let quality_preset = QualityPreset::from_byte(cursor.get_u8());
    // Skip 2-byte reserved region.
    cursor.advance(2);
    let bandwidth_kbps_limit = cursor.get_u32();
    let record_duration_secs = cursor.get_u32();
    // Skip 4-byte reserved region.
    cursor.advance(4);
    let timestamp_unix_ms = cursor.get_u64();

    debug_assert!(
        cursor.is_empty(),
        "fixed-size frame should be fully consumed; bug in offset constants"
    );
    let _ = OFF_VEHICLE_ID;
    let _ = OFF_PAYLOAD_ID;
    let _ = OFF_CONTROL_ACTION;
    let _ = OFF_QUALITY_PRESET;
    let _ = OFF_BANDWIDTH_LIMIT;
    let _ = OFF_RECORD_DURATION;
    let _ = OFF_TIMESTAMP;

    Ok(PayloadControlCommand {
        vehicle_id,
        payload_id,
        control_action,
        quality_preset,
        bandwidth_kbps_limit,
        record_duration_secs,
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
    /// sentinel" path at once: `bandwidth_kbps_limit == 0` ("no
    /// limit"), `record_duration_secs == 0` ("unbounded"),
    /// `timestamp_unix_ms == 0` (unset/unknown). The two enum bytes
    /// fall through to `Other(0)` — the encode side never emits
    /// `0x00` for a named variant, but the round-trip must hold
    /// even at this corner.
    fn zero_valued_command() -> PayloadControlCommand {
        PayloadControlCommand {
            vehicle_id: 0,
            payload_id: 0,
            control_action: ControlAction::Other(0),
            quality_preset: QualityPreset::Other(0),
            bandwidth_kbps_limit: 0,
            record_duration_secs: 0,
            timestamp_unix_ms: 0,
        }
    }

    /// Typical operator command: start a recording at maximum
    /// quality with no bandwidth ceiling and a 30-minute cap. Pins
    /// the `Start` + `Maximum` operational case the module-level
    /// docs call out.
    fn start_maximum_quality_command() -> PayloadControlCommand {
        PayloadControlCommand {
            vehicle_id: 0xA1B2_C3D4,
            payload_id: 0x0000_0042,
            control_action: ControlAction::Start,
            quality_preset: QualityPreset::Maximum,
            bandwidth_kbps_limit: 0,
            record_duration_secs: 1800,
            timestamp_unix_ms: 0x0000_0001_600F_1234,
        }
    }

    /// `Configure` action with an explicit bandwidth limit — pins
    /// that the limit field round-trips when the action is
    /// `Configure` (the canonical use-case for changing live
    /// streaming parameters without stopping the session).
    fn configure_with_bandwidth_limit_command() -> PayloadControlCommand {
        PayloadControlCommand {
            vehicle_id: 0xDEAD_BEEF,
            payload_id: 7,
            control_action: ControlAction::Configure,
            quality_preset: QualityPreset::Medium,
            bandwidth_kbps_limit: 4096,
            record_duration_secs: 0,
            timestamp_unix_ms: 0x0000_0001_700A_BCDE,
        }
    }

    // ---- Round-trip ----

    #[test]
    fn round_trip_zero_valued_fixture() {
        let msg = zero_valued_command();
        let bytes = encode(&msg);
        assert_eq!(bytes, vec![0u8; PAYLOAD_CONTROL_COMMAND_FRAME_LEN]);
        let decoded = decode(&bytes).expect("zero round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_start_maximum_quality_fixture() {
        let msg = start_maximum_quality_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), PAYLOAD_CONTROL_COMMAND_FRAME_LEN);
        let decoded = decode(&bytes).expect("start/maximum round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_configure_with_bandwidth_limit_fixture() {
        let msg = configure_with_bandwidth_limit_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), PAYLOAD_CONTROL_COMMAND_FRAME_LEN);
        let decoded = decode(&bytes).expect("configure round-trip");
        assert_eq!(decoded, msg);
    }

    // ---- Zero-as-sentinel acceptance ----

    #[test]
    fn decode_accepts_zero_bandwidth_limit_as_no_limit_sentinel() {
        // Pin the no-limit-sentinel contract: senders write `0` for
        // `bandwidth_kbps_limit` to decline to constrain bandwidth.
        // A regression that rejected `0` here would silently drop
        // every "unconstrained" payload command — the most common
        // operational case for a recorder, where bandwidth is
        // irrelevant.
        let msg = PayloadControlCommand {
            vehicle_id: 1,
            payload_id: 1,
            control_action: ControlAction::Start,
            quality_preset: QualityPreset::High,
            bandwidth_kbps_limit: 0,
            record_duration_secs: 600,
            timestamp_unix_ms: 1,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("zero bandwidth_limit must decode cleanly");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.bandwidth_kbps_limit, 0);
    }

    #[test]
    fn decode_accepts_zero_record_duration_as_unbounded_sentinel() {
        // Pin the unbounded-recording contract: senders write `0`
        // for `record_duration_secs` to record until storage fills
        // or the operator issues a follow-up `Stop`. A regression
        // that rejected `0` would silently drop every
        // "record-until-told-to-stop" command.
        let msg = PayloadControlCommand {
            vehicle_id: 1,
            payload_id: 1,
            control_action: ControlAction::Start,
            quality_preset: QualityPreset::Medium,
            bandwidth_kbps_limit: 2048,
            record_duration_secs: 0,
            timestamp_unix_ms: 1,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("zero record_duration must decode cleanly");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.record_duration_secs, 0);
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
        //   vehicle_id           = 0x1122_3344
        //   payload_id           = 0xAABB_CCDD
        //   control_action       = 0x01 (Start)
        //   quality_preset       = 0x04 (Maximum)
        //   bandwidth_kbps_limit = 0x0010_0000 (1 Mbps)
        //   record_duration_secs = 0x0000_0E10 (3600s = 1 hour)
        //   timestamp_unix_ms    = 0xFEDC_BA98_7654_3210
        let msg = PayloadControlCommand {
            vehicle_id: 0x1122_3344,
            payload_id: 0xAABB_CCDD,
            control_action: ControlAction::Start,
            quality_preset: QualityPreset::Maximum,
            bandwidth_kbps_limit: 0x0010_0000,
            record_duration_secs: 0x0000_0E10,
            timestamp_unix_ms: 0xFEDC_BA98_7654_3210,
        };
        let bytes = encode(&msg);
        let expected: [u8; PAYLOAD_CONTROL_COMMAND_FRAME_LEN] = [
            // vehicle_id = 0x1122_3344 (big-endian)
            0x11, 0x22, 0x33, 0x44, //
            // payload_id = 0xAABB_CCDD (big-endian)
            0xAA, 0xBB, 0xCC, 0xDD, //
            // control_action = 0x01 (Start)
            0x01, //
            // quality_preset = 0x04 (Maximum)
            0x04, //
            // 2 reserved zero bytes
            0x00, 0x00, //
            // bandwidth_kbps_limit = 0x0010_0000 (big-endian)
            0x00, 0x10, 0x00, 0x00, //
            // record_duration_secs = 0x0000_0E10 (big-endian)
            0x00, 0x00, 0x0E, 0x10, //
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
                    assert_eq!(expected, PAYLOAD_CONTROL_COMMAND_FRAME_LEN);
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
        let msg = start_maximum_quality_command();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(&[0xAA; 32]);
        assert_eq!(bytes.len(), 64);
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
    }

    // ---- ControlAction enum round-trip ----

    #[test]
    fn control_action_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, ControlAction)] = &[
            (0x01, ControlAction::Start),
            (0x02, ControlAction::Stop),
            (0x03, ControlAction::Pause),
            (0x04, ControlAction::Resume),
            (0x05, ControlAction::Configure),
            (0xFF, ControlAction::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = ControlAction::from_byte(*byte);
            assert_eq!(decoded, *expected, "from_byte mismatch for byte={byte:#x}");
            assert_eq!(
                decoded.to_byte(),
                *byte,
                "to_byte mismatch for {expected:?}"
            );
        }
        // Unknown bytes outside the named table also round-trip via
        // `Other`. 0x00 is in this set — the encode side never emits
        // it for a named action, so observing it on decode means
        // the upstream sent something unintended.
        for byte in [0x00u8, 0x06, 0x42, 0xEE] {
            let decoded = ControlAction::from_byte(byte);
            assert_eq!(decoded, ControlAction::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- QualityPreset enum round-trip ----

    #[test]
    fn quality_preset_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, QualityPreset)] = &[
            (0x01, QualityPreset::Low),
            (0x02, QualityPreset::Medium),
            (0x03, QualityPreset::High),
            (0x04, QualityPreset::Maximum),
            (0xFF, QualityPreset::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = QualityPreset::from_byte(*byte);
            assert_eq!(decoded, *expected, "from_byte mismatch for byte={byte:#x}");
            assert_eq!(
                decoded.to_byte(),
                *byte,
                "to_byte mismatch for {expected:?}"
            );
        }
        for byte in [0x00u8, 0x05, 0x42, 0xEE] {
            let decoded = QualityPreset::from_byte(byte);
            assert_eq!(decoded, QualityPreset::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- Cross-frame payload_id correlation ----

    #[test]
    fn payload_id_field_matches_payload_status_module() {
        // Pin the cross-frame correlation contract: a GCS that
        // observes a `PayloadStatus` telemetry frame for
        // payload_id=42 (#1157) and emits a follow-up
        // `PayloadControlCommand` with `payload_id: 42` MUST
        // produce the same big-endian byte sequence in the wire
        // payload_id field of both frames. Without this guarantee,
        // an operator who copied the bytes verbatim from a status
        // frame into a command frame could end up commanding a
        // different payload — a silent footgun the codec is
        // explicitly designed to prevent.
        //
        // The two frames place `payload_id` at different absolute
        // offsets (PayloadStatus at offset 0, PayloadControlCommand
        // at offset 4 — after the leading vehicle_id), so the
        // pinned property is "the four-byte big-endian
        // representation of the same logical value is byte-for-byte
        // identical between the two frames", not "the absolute
        // offset is the same".
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

        // Build a payload_control_command frame with the same
        // logical `payload_id` — the command-side layout puts the
        // field at offset 4..8 (after the leading vehicle_id).
        let command = PayloadControlCommand {
            vehicle_id: VEHICLE_ID,
            payload_id: PAYLOAD_ID,
            control_action: ControlAction::Stop,
            quality_preset: QualityPreset::Medium,
            bandwidth_kbps_limit: 0,
            record_duration_secs: 0,
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
            "payload_id wire bytes must match across PayloadStatus and PayloadControlCommand"
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
        let msg = start_maximum_quality_command();
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
        encode_into(&start_maximum_quality_command(), &mut buf);
        assert_eq!(buf.len(), 3 + PAYLOAD_CONTROL_COMMAND_FRAME_LEN);
        assert_eq!(&buf[0..3], &[0xAA, 0xBB, 0xCC]);
        let standalone = encode(&start_maximum_quality_command());
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
            action_byte in any::<u8>(),
            quality_byte in any::<u8>(),
            bandwidth_kbps_limit in any::<u32>(),
            record_duration_secs in any::<u32>(),
            timestamp_unix_ms in any::<u64>(),
        ) {
            let original = PayloadControlCommand {
                vehicle_id,
                payload_id,
                control_action: ControlAction::from_byte(action_byte),
                quality_preset: QualityPreset::from_byte(quality_byte),
                bandwidth_kbps_limit,
                record_duration_secs,
                timestamp_unix_ms,
            };
            let bytes = encode(&original);
            prop_assert_eq!(bytes.len(), PAYLOAD_CONTROL_COMMAND_FRAME_LEN);
            let decoded = decode(&bytes).expect("decode round-trip");
            prop_assert_eq!(decoded, original);
        }
    }
}
