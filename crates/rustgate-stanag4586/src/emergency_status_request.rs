// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! STANAG 4586 LOI 4 emergency status request command message.
//!
//! Carries the seventh **command-side** message in the
//! `rustgate-stanag4586` crate, following waypoint upload
//! ([`crate::waypoint_command`]), sensor pointing
//! ([`crate::sensor_pointing_command`]), mission abort
//! ([`crate::mission_abort_command`]), GCS handover
//! ([`crate::gcs_handover_command`]), route upload
//! ([`crate::route_upload_command`]), and payload control
//! ([`crate::payload_control_command`]). Where the prior six
//! command-side frames each direct the platform to *act* — fly to a
//! waypoint, slew the optics, terminate the mission, transfer
//! authority, upload a route, start a recording — `EmergencyStatusRequest`
//! does not direct the platform to act on the world at all: it asks the
//! platform for an **immediate health/status snapshot** when the
//! normal-cadence telemetry feed has gone degraded, intermittent, or
//! absent altogether and the operator needs an out-of-band picture of
//! what the platform thinks its own state is.
//!
//! # Operational model
//!
//! Emergency status request is the operator's diagnostic lever — the
//! message they reach for when the LOI 2-3 telemetry stream
//! ([`crate::vehicle_position`], [`crate::system_state`],
//! [`crate::sensor_status`], [`crate::payload_status`],
//! [`crate::bit_report`]) has stopped arriving on its expected cadence,
//! is arriving with stale timestamps, or is arriving with values that
//! contradict each other (the BIT report claims green while the system
//! state shows a Major fault, the vehicle position has not advanced for
//! 30 seconds while ground speed reports 80 knots). Rather than wait
//! the next 1–5 Hz telemetry cycle and hope the picture clears, the
//! operator asks the platform to interrupt its normal cadence and emit
//! a fresh snapshot of the requested telemetry surface right now. A
//! typical workflow looks like:
//!
//! 1. The platform's LOI 2-3 telemetry stream goes degraded — the
//!    operator's GCS UI shows a stale-data indicator on the panel,
//!    the heartbeat counter has stopped advancing, or the cross-frame
//!    consistency checks raised a flag.
//! 2. The operator decides to ask out-of-band rather than wait. They
//!    pick a [`RequestKind`] selecting which telemetry surface is the
//!    most diagnostically useful to refresh first
//!    ([`RequestKind::FullStatus`] for "give me everything you have
//!    right now", [`RequestKind::FuelOnly`] when the concern is
//!    endurance margin, [`RequestKind::BatteryOnly`] for an electric
//!    platform's pack state, [`RequestKind::BitOnly`] for the platform's
//!    own self-test verdict, [`RequestKind::PositionOnly`] for the
//!    fastest-to-emit smallest-payload surface when the link is
//!    constrained), an [`UrgencyLevel`] biasing how the platform
//!    schedules the response against its own command-execution loop
//!    ([`UrgencyLevel::Routine`] queued behind ongoing work,
//!    [`UrgencyLevel::Priority`] interrupts at the next safe boundary,
//!    [`UrgencyLevel::Immediate`] interrupts at the next instruction
//!    boundary, [`UrgencyLevel::Flash`] interrupts the platform's
//!    current instruction and emits the snapshot before resuming —
//!    the load-bearing tier for "the operator believes something is
//!    wrong and cannot wait"), an operator-supplied `request_id` for
//!    correlating the response against the request once the response
//!    surfaces in a follow-up PR (`0` is the documented "unsolicited"
//!    sentinel for operators who do not need correlation), and an
//!    optional `response_deadline_ms` carrying the operator's
//!    expected response deadline (`0` is the documented "no deadline"
//!    sentinel — the operator has no time bound and the platform may
//!    queue the response behind its own scheduling policy).
//! 3. The GCS emits an `EmergencyStatusRequest` carrying the chosen
//!    `vehicle_id`, `request_id`, `request_kind`, `urgency_level`,
//!    `response_deadline_ms`, and `timestamp_unix_ms`.
//! 4. The platform applies the request: a `Flash` urgency interrupts
//!    its current instruction loop; a `Routine` urgency is queued
//!    behind whatever the platform is currently doing. The response
//!    message itself — the platform's "here is the requested status
//!    snapshot" reply — is the LOI 2-3 read-side concern from the
//!    existing telemetry frames and is out of scope for this command
//!    surface (see "What is deliberately absent" below).
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`EMERGENCY_STATUS_REQUEST_FRAME_LEN`] = 32
//! bytes.
//!
//! ```text
//! offset │ size │ field                │ type
//! ───────┼──────┼──────────────────────┼──────────────────────────
//!   0    │  4   │ vehicle_id           │ u32  big-endian
//!   4    │  4   │ request_id           │ u32  big-endian (0 = unsolicited)
//!   8    │  1   │ request_kind         │ u8   enum value (see below)
//!   9    │  1   │ urgency_level        │ u8   enum value (see below)
//!  10    │  2   │ reserved             │ zero-padded — must be 0 on encode
//!  12    │  4   │ response_deadline_ms │ u32  big-endian (0 = no deadline)
//!  16    │  8   │ reserved             │ zero-padded — must be 0 on encode
//!  24    │  8   │ timestamp_unix_ms    │ u64  big-endian (Unix epoch ms)
//! ```
//!
//! The two reserved blocks are zero-filled on encode. The decoder does
//! NOT validate that they are zero on the wire so a future spec
//! revision that allocates the bytes (a request-scope mask carrying
//! per-subsystem bits, a command sequence number for matching against
//! the future response message, an optional cryptographic nonce for
//! request authentication) stays backward-compatible at the
//! frame-length level.
//!
//! # Field semantics
//!
//! - `vehicle_id` — the target platform identifier. Matches the
//!   `vehicle_id` carried by the LOI 2-3 telemetry frames and the LOI
//!   4 [`crate::waypoint_command`] /
//!   [`crate::sensor_pointing_command`] /
//!   [`crate::mission_abort_command`] /
//!   [`crate::gcs_handover_command`] /
//!   [`crate::route_upload_command`] /
//!   [`crate::payload_control_command`] frames so a GCS can correlate
//!   "which platform did I ask for an emergency status" against
//!   "which platform's telemetry feed is degraded on my UI" by direct
//!   byte comparison without an intermediate lookup table.
//! - `request_id` — operator-supplied identifier the platform's
//!   eventual response will echo back so the GCS can match the
//!   asynchronous reply against the originating request. **`0` is the
//!   documented "unsolicited" sentinel** — the operator declined to
//!   correlate the response (a one-shot diagnostic ping where the GCS
//!   only needs the snapshot to render once and does not care which
//!   request-response cycle it belongs to). A regression that rejected
//!   `0` would silently drop every uncorrelated request, pinned in
//!   `decode_accepts_zero_request_id_as_unsolicited`. The codec does
//!   not validate uniqueness — that is the GCS's bookkeeping concern.
//! - `request_kind` — which telemetry surface the platform should
//!   refresh. See [`RequestKind`].
//! - `urgency_level` — how aggressively the platform should schedule
//!   the response against its own command-execution loop. See
//!   [`UrgencyLevel`]. [`UrgencyLevel::Flash`] is the load-bearing
//!   tier: the platform SHOULD interrupt its current instruction and
//!   emit the requested snapshot before resuming, on the operator's
//!   "something is wrong and I cannot wait" signal.
//! - `response_deadline_ms` — operator-supplied response deadline in
//!   milliseconds, measured against the platform's own clock relative
//!   to receipt. **`0` is the documented "no deadline" sentinel** —
//!   the operator has no time bound and the platform may queue the
//!   response behind its own scheduling policy. A regression that
//!   rejected `0` would silently drop every "respond when you can"
//!   request, pinned in
//!   `decode_accepts_zero_response_deadline_as_no_deadline`. The codec
//!   does not validate the value otherwise — an unrealistically short
//!   deadline is the platform's response-scheduling layer's problem
//!   rather than a codec concern.
//! - `timestamp_unix_ms` — when the GCS issued the request, milliseconds
//!   since the Unix epoch. The platform may use it to discard a stale
//!   request that lost a race against a follow-on request, or to
//!   timestamp the diagnostic event in its own audit log for
//!   post-mission reconstruction. The codec does not validate the
//!   value (zero is legal — represents an unset/unknown timestamp).
//!
//! # What is deliberately absent
//!
//! - **The response message itself** — the platform's "here is the
//!   requested status snapshot" reply is the existing LOI 2-3 read-side
//!   telemetry surface ([`crate::vehicle_position`],
//!   [`crate::system_state`], [`crate::sensor_status`],
//!   [`crate::payload_status`], [`crate::bit_report`]); the codec for
//!   those frames already exists and the response-correlation glue (a
//!   `request_id` echo field on each response frame, or a separate
//!   response-envelope frame carrying the request_id alongside one of
//!   the existing frames) is a follow-up read-side PR rather than a
//!   command-side concern. This module ships only the request side.
//! - **Other LOI 4 commands** — mode change is the remaining
//!   command-side message in the LOI 4 minimum-viable command set and
//!   ships in a follow-up PR with its own wire format and validation
//!   rules.
//! - **Response / acknowledgement messages for the request itself** —
//!   the bidirectional command-response handshake (the platform's
//!   "request accepted, snapshot will be emitted at T+50ms" or
//!   "request rejected, status surface unavailable" reply) is a
//!   separate follow-up PR.
//! - **Per-subsystem request scoping beyond the named
//!   [`RequestKind`] variants** — a future spec revision that wants
//!   to ask for "fuel + BIT but not position" can use the reserved
//!   bytes for a per-subsystem bit-mask without breaking the existing
//!   frame-length contract. The minimum-viable command vocabulary
//!   captured by [`RequestKind`] covers the single-surface cases
//!   operators reach for first.
//! - **UDP/TCP listener wiring** — this module is pure encode/decode
//!   over `&[u8]`; the network glue is a separate change.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of an emergency status request frame.
pub const EMERGENCY_STATUS_REQUEST_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_REQUEST_ID: usize = 4;
const OFF_REQUEST_KIND: usize = 8;
const OFF_URGENCY_LEVEL: usize = 9;
// 10..12 reserved (2 bytes)
const OFF_RESPONSE_DEADLINE: usize = 12;
// 16..24 reserved (8 bytes)
const OFF_TIMESTAMP: usize = 24;

/// Which telemetry surface the platform should refresh in response to
/// an [`EmergencyStatusRequest`].
///
/// The five named variants cover the LOI 4 emergency-status-request
/// minimum-viable command vocabulary: a single "give me everything you
/// have right now" snapshot covering every LOI 2-3 telemetry surface
/// the platform produces ([`RequestKind::FullStatus`]), and four
/// narrowly-scoped requests for the diagnostic surfaces operators reach
/// for first when the normal-cadence stream goes degraded — fuel state
/// for endurance-margin questions ([`RequestKind::FuelOnly`]), battery
/// state for electric-platform pack health ([`RequestKind::BatteryOnly`]),
/// the platform's self-test verdict ([`RequestKind::BitOnly`]), and
/// the smallest-payload fastest-to-emit position fix when the link is
/// constrained ([`RequestKind::PositionOnly`]).
/// [`RequestKind::Other`] preserves any unrecognised wire byte so a
/// future spec revision that allocates a new request kind (e.g. a
/// `LinkOnly` for downlink-margin diagnostics, a `PayloadOnly` for
/// recorder/streamer state, a `MissionOnly` for active-mission
/// progress) stays decodable on a receiver running today's build —
/// matches the same forward-compat discipline used by every sibling
/// LOI 2-3 / LOI 4 frame's enums.
///
/// # Wire byte values
///
/// | byte  | variant         |
/// |-------|-----------------|
/// | `0x01`| `FullStatus`    |
/// | `0x02`| `FuelOnly`      |
/// | `0x03`| `BatteryOnly`   |
/// | `0x04`| `BitOnly`       |
/// | `0x05`| `PositionOnly`  |
/// | other | `Other(byte)`   |
///
/// `0x00` deliberately falls into [`RequestKind::Other`] rather than
/// having its own "Unknown" variant — the encode side never emits
/// `0x00` for a named kind, so observing one on decode means the
/// upstream sent something unintended and the operator should be able
/// to see the raw byte value in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// Snapshot of every LOI 2-3 telemetry surface the platform
    /// produces — vehicle position, system state, sensor status,
    /// payload status, BIT report. The "give me everything you have
    /// right now" option for an operator who cannot tell which surface
    /// is most diagnostic.
    FullStatus,
    /// Fuel-only snapshot for endurance-margin questions. Used when
    /// the operator is concerned about whether the platform has the
    /// fuel to complete its current mission or reach a divert point.
    FuelOnly,
    /// Battery-only snapshot for electric-platform pack state. Used
    /// when the operator is concerned about pack health, remaining
    /// flight time, or imminent low-voltage cutoff on an electric
    /// airframe.
    BatteryOnly,
    /// Built-In-Test (BIT) verdict only — the platform's own
    /// self-test output. Used when the operator suspects a subsystem
    /// fault and wants the platform's own diagnosis before deciding
    /// whether to abort.
    BitOnly,
    /// Position-only snapshot — the smallest-payload, fastest-to-emit
    /// surface the LOI 2-3 telemetry set offers. Used when the link
    /// is bandwidth-constrained or the operator only needs to confirm
    /// the platform is still where it says it is.
    PositionOnly,
    /// Forward-compat catch-all for request-kind bytes the spec may
    /// allocate in a future revision.
    Other(u8),
}

impl RequestKind {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::FullStatus,
            0x02 => Self::FuelOnly,
            0x03 => Self::BatteryOnly,
            0x04 => Self::BitOnly,
            0x05 => Self::PositionOnly,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::FullStatus => 0x01,
            Self::FuelOnly => 0x02,
            Self::BatteryOnly => 0x03,
            Self::BitOnly => 0x04,
            Self::PositionOnly => 0x05,
            Self::Other(b) => b,
        }
    }
}

/// How aggressively the platform should schedule the response against
/// its own command-execution loop.
///
/// The four named variants cover the LOI 4 emergency-status-request
/// urgency vocabulary: a routine request that may be queued behind
/// ongoing work ([`UrgencyLevel::Routine`]), a priority request that
/// interrupts at the next safe boundary ([`UrgencyLevel::Priority`]),
/// a flash request that interrupts the platform's current instruction
/// and emits the snapshot before resuming ([`UrgencyLevel::Flash`] —
/// the load-bearing tier for "the operator believes something is
/// wrong and cannot wait"), and an immediate request that interrupts
/// at the next instruction boundary ([`UrgencyLevel::Immediate`] — a
/// step below `Flash`, between `Priority` and `Flash` in operational
/// urgency but allocated to a higher byte slot in the wire table).
/// [`UrgencyLevel::Other`] preserves any unrecognised wire byte for
/// forward compatibility.
///
/// # Wire byte values
///
/// | byte  | variant       |
/// |-------|---------------|
/// | `0x01`| `Routine`     |
/// | `0x02`| `Priority`    |
/// | `0x03`| `Flash`       |
/// | `0x04`| `Immediate`   |
/// | other | `Other(byte)` |
///
/// **Important — wire-byte ordering does NOT match precedence
/// ordering.** `Flash` is the highest-precedence tier (interrupts
/// the platform's current instruction) but sits at byte `0x03`,
/// while `Immediate` is a lower precedence (interrupts only at the
/// next instruction boundary) but sits at byte `0x04`. The byte
/// table is laid out this way deliberately: `Flash` is the most
/// operationally common emergency-tier value the codec sees on the
/// wire (it is the urgency the GCS reaches for when the LOI 2-3
/// telemetry feed has actually gone wrong), so it is allocated to a
/// low byte for fast wire-byte recognition by analyzer tools and
/// fast comparator dispatch on a platform's urgency-routing path.
/// `Immediate` sees less wire traffic in practice and is placed at
/// `0x04`. Operators reading the byte table should not infer
/// urgency ranking from the byte value — use the named variant.
///
/// `0x00` deliberately falls into [`UrgencyLevel::Other`] for the
/// same reason as the [`RequestKind`] enum above — the encode side
/// never emits `0x00` for a named tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrgencyLevel {
    /// Routine request — may be queued behind ongoing platform work.
    /// The right choice for a periodic out-of-band sanity check
    /// where the operator has no time pressure.
    Routine,
    /// Priority request — interrupts at the next safe boundary
    /// (between maneuver legs, between sensor dwells). The right
    /// choice for a "the picture looks off but I am not sure
    /// something is actually wrong" diagnostic.
    Priority,
    /// Immediate request — interrupts at the next instruction
    /// boundary. The right choice for a "the picture is contradicting
    /// itself and I need fresh data" diagnostic. Operationally a
    /// step below [`UrgencyLevel::Flash`] but allocated to a higher
    /// byte slot in the wire table; see the type-level docs for the
    /// rationale.
    Immediate,
    /// Flash request — interrupts the platform's current instruction
    /// and emits the snapshot before resuming. The load-bearing tier
    /// for "the operator believes something is wrong and cannot
    /// wait"; SHOULD trigger interrupt-style status emission.
    Flash,
    /// Forward-compat catch-all for urgency-level bytes the spec may
    /// allocate in a future revision.
    Other(u8),
}

impl UrgencyLevel {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::Routine,
            0x02 => Self::Priority,
            0x03 => Self::Flash,
            0x04 => Self::Immediate,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Routine => 0x01,
            Self::Priority => 0x02,
            Self::Flash => 0x03,
            Self::Immediate => 0x04,
            Self::Other(b) => b,
        }
    }
}

/// LOI 4 emergency status request command message.
#[derive(Debug, Clone, PartialEq)]
pub struct EmergencyStatusRequest {
    /// Target platform identifier (matches
    /// [`crate::vehicle_position::VehiclePosition::vehicle_id`]).
    pub vehicle_id: u32,
    /// Operator-supplied request identifier the platform's eventual
    /// response will echo back. `0` represents an unsolicited
    /// (uncorrelated) request.
    pub request_id: u32,
    /// Which telemetry surface the platform should refresh.
    pub request_kind: RequestKind,
    /// How aggressively the platform should schedule the response
    /// against its own command-execution loop. [`UrgencyLevel::Flash`]
    /// is the load-bearing tier and SHOULD trigger interrupt-style
    /// status emission.
    pub urgency_level: UrgencyLevel,
    /// Operator-supplied response deadline in milliseconds, measured
    /// against the platform's own clock relative to receipt. `0`
    /// represents "no deadline" — the operator has no time bound.
    pub response_deadline_ms: u32,
    /// When the GCS issued the request, milliseconds since the Unix
    /// epoch. `0` represents an unset / unknown timestamp.
    pub timestamp_unix_ms: u64,
}

impl EmergencyStatusRequest {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode an emergency status request frame into a freshly allocated
/// `Vec<u8>`.
#[must_use]
pub fn encode(msg: &EmergencyStatusRequest) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(EMERGENCY_STATUS_REQUEST_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
///
/// Useful when the encoded frame will be the body of a larger packet
/// and the caller wants to avoid the intermediate `Vec` allocation
/// of [`encode`]. Appends [`EMERGENCY_STATUS_REQUEST_FRAME_LEN`]
/// bytes; does not clear or truncate `buf`.
pub fn encode_into(msg: &EmergencyStatusRequest, buf: &mut BytesMut) {
    buf.reserve(EMERGENCY_STATUS_REQUEST_FRAME_LEN);
    buf.put_u32(msg.vehicle_id);
    buf.put_u32(msg.request_id);
    buf.put_u8(msg.request_kind.to_byte());
    buf.put_u8(msg.urgency_level.to_byte());
    // 2 reserved bytes.
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u32(msg.response_deadline_ms);
    // 8 reserved bytes.
    buf.put_u64(0);
    buf.put_u64(msg.timestamp_unix_ms);
}

/// Decode an emergency status request frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
///
/// Trailing bytes beyond [`EMERGENCY_STATUS_REQUEST_FRAME_LEN`] are
/// ignored; the codec is fixed-size and a future protocol revision
/// that appends fields keeps decoding the prefix unchanged.
///
/// All numeric fields accept any wire value — `vehicle_id` is an
/// opaque deployment-defined identifier, the timestamp is not
/// range-checked, and `request_id == 0` / `response_deadline_ms == 0`
/// are the documented "unsolicited" / "no deadline" sentinels (pinned
/// by dedicated tests).
///
/// Unrecognised `request_kind` and `urgency_level` bytes do NOT cause
/// an error — they surface as [`RequestKind::Other`] /
/// [`UrgencyLevel::Other`] for forward compatibility.
pub fn decode(bytes: &[u8]) -> Result<EmergencyStatusRequest, Stanag4586Error> {
    if bytes.len() < EMERGENCY_STATUS_REQUEST_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: EMERGENCY_STATUS_REQUEST_FRAME_LEN,
        });
    }

    let mut cursor = &bytes[..EMERGENCY_STATUS_REQUEST_FRAME_LEN];
    let vehicle_id = cursor.get_u32();
    let request_id = cursor.get_u32();
    let request_kind = RequestKind::from_byte(cursor.get_u8());
    let urgency_level = UrgencyLevel::from_byte(cursor.get_u8());
    // Skip 2-byte reserved region.
    cursor.advance(2);
    let response_deadline_ms = cursor.get_u32();
    // Skip 8-byte reserved region.
    cursor.advance(8);
    let timestamp_unix_ms = cursor.get_u64();

    debug_assert!(
        cursor.is_empty(),
        "fixed-size frame should be fully consumed; bug in offset constants"
    );
    let _ = OFF_VEHICLE_ID;
    let _ = OFF_REQUEST_ID;
    let _ = OFF_REQUEST_KIND;
    let _ = OFF_URGENCY_LEVEL;
    let _ = OFF_RESPONSE_DEADLINE;
    let _ = OFF_TIMESTAMP;

    Ok(EmergencyStatusRequest {
        vehicle_id,
        request_id,
        request_kind,
        urgency_level,
        response_deadline_ms,
        timestamp_unix_ms,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Zero-valued fixture — exercises every "0 is a documented
    /// sentinel" path at once: `request_id == 0` ("unsolicited"),
    /// `response_deadline_ms == 0` ("no deadline"),
    /// `timestamp_unix_ms == 0` (unset/unknown). The two enum bytes
    /// fall through to `Other(0)` — the encode side never emits
    /// `0x00` for a named variant, but the round-trip must hold even
    /// at this corner.
    fn zero_valued_request() -> EmergencyStatusRequest {
        EmergencyStatusRequest {
            vehicle_id: 0,
            request_id: 0,
            request_kind: RequestKind::Other(0),
            urgency_level: UrgencyLevel::Other(0),
            response_deadline_ms: 0,
            timestamp_unix_ms: 0,
        }
    }

    /// Typical operator request: a routine `FullStatus` ping with a
    /// 5-second deadline and a non-zero correlation id. Pins the
    /// `FullStatus` + `Routine` operational case the module-level
    /// docs call out as the default low-pressure diagnostic.
    fn full_status_routine_request() -> EmergencyStatusRequest {
        EmergencyStatusRequest {
            vehicle_id: 0xA1B2_C3D4,
            request_id: 0x0000_0042,
            request_kind: RequestKind::FullStatus,
            urgency_level: UrgencyLevel::Routine,
            response_deadline_ms: 5000,
            timestamp_unix_ms: 0x0000_0001_600F_1234,
        }
    }

    /// High-priority diagnostic request: a `BitOnly` snapshot at
    /// `Flash` urgency with a 100ms deadline — the operator suspects
    /// a subsystem fault and cannot wait the next telemetry cycle.
    /// Pins the load-bearing `Flash` tier round-trips through the
    /// codec without alteration.
    fn bit_only_flash_request() -> EmergencyStatusRequest {
        EmergencyStatusRequest {
            vehicle_id: 0xDEAD_BEEF,
            request_id: 7,
            request_kind: RequestKind::BitOnly,
            urgency_level: UrgencyLevel::Flash,
            response_deadline_ms: 100,
            timestamp_unix_ms: 0x0000_0001_700A_BCDE,
        }
    }

    // ---- Round-trip ----

    #[test]
    fn round_trip_zero_valued_fixture() {
        let msg = zero_valued_request();
        let bytes = encode(&msg);
        assert_eq!(bytes, vec![0u8; EMERGENCY_STATUS_REQUEST_FRAME_LEN]);
        let decoded = decode(&bytes).expect("zero round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_full_status_routine_fixture() {
        let msg = full_status_routine_request();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), EMERGENCY_STATUS_REQUEST_FRAME_LEN);
        let decoded = decode(&bytes).expect("full-status/routine round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_bit_only_flash_fixture() {
        let msg = bit_only_flash_request();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), EMERGENCY_STATUS_REQUEST_FRAME_LEN);
        let decoded = decode(&bytes).expect("bit-only/flash round-trip");
        assert_eq!(decoded, msg);
    }

    // ---- Zero-as-sentinel acceptance ----

    #[test]
    fn decode_accepts_zero_request_id_as_unsolicited() {
        // Pin the unsolicited-sentinel contract: senders write `0`
        // for `request_id` to decline to correlate the response — a
        // one-shot diagnostic ping where the GCS only needs the
        // snapshot to render once and does not care which
        // request-response cycle it belongs to. A regression that
        // rejected `0` here would silently drop every uncorrelated
        // request.
        let msg = EmergencyStatusRequest {
            vehicle_id: 1,
            request_id: 0,
            request_kind: RequestKind::FullStatus,
            urgency_level: UrgencyLevel::Routine,
            response_deadline_ms: 1000,
            timestamp_unix_ms: 1,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("zero request_id must decode cleanly");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.request_id, 0);
    }

    #[test]
    fn decode_accepts_zero_response_deadline_as_no_deadline() {
        // Pin the no-deadline contract: senders write `0` for
        // `response_deadline_ms` when the operator has no time bound
        // and the platform may queue the response behind its own
        // scheduling policy. A regression that rejected `0` would
        // silently drop every "respond when you can" request.
        let msg = EmergencyStatusRequest {
            vehicle_id: 1,
            request_id: 1,
            request_kind: RequestKind::PositionOnly,
            urgency_level: UrgencyLevel::Routine,
            response_deadline_ms: 0,
            timestamp_unix_ms: 1,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("zero response_deadline_ms must decode cleanly");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.response_deadline_ms, 0);
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
        //   request_id           = 0xAABB_CCDD
        //   request_kind         = 0x01 (FullStatus)
        //   urgency_level        = 0x03 (Flash — see UrgencyLevel
        //                                docs for why the highest
        //                                tier sits at byte 0x03 and
        //                                not 0x04)
        //   response_deadline_ms = 0x0000_07D0 (2000ms)
        //   timestamp_unix_ms    = 0xFEDC_BA98_7654_3210
        let msg = EmergencyStatusRequest {
            vehicle_id: 0x1122_3344,
            request_id: 0xAABB_CCDD,
            request_kind: RequestKind::FullStatus,
            urgency_level: UrgencyLevel::Flash,
            response_deadline_ms: 0x0000_07D0,
            timestamp_unix_ms: 0xFEDC_BA98_7654_3210,
        };
        let bytes = encode(&msg);
        let expected: [u8; EMERGENCY_STATUS_REQUEST_FRAME_LEN] = [
            // vehicle_id = 0x1122_3344 (big-endian)
            0x11, 0x22, 0x33, 0x44, //
            // request_id = 0xAABB_CCDD (big-endian)
            0xAA, 0xBB, 0xCC, 0xDD, //
            // request_kind = 0x01 (FullStatus)
            0x01, //
            // urgency_level = 0x03 (Flash per table)
            0x03, //
            // 2 reserved zero bytes
            0x00, 0x00, //
            // response_deadline_ms = 0x0000_07D0 (big-endian, 2000ms)
            0x00, 0x00, 0x07, 0xD0, //
            // 8 reserved zero bytes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
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
        // Pin the named variant the byte resolves to so a future
        // refactor that rebinds `0x03` accidentally trips this
        // assertion rather than silently changing operational
        // semantics. `Flash` is the highest-priority tier and MUST
        // resolve from wire byte `0x03`.
        assert_eq!(decoded.urgency_level, UrgencyLevel::Flash);
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
                    assert_eq!(expected, EMERGENCY_STATUS_REQUEST_FRAME_LEN);
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
        let msg = full_status_routine_request();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(&[0xAA; 32]);
        assert_eq!(bytes.len(), 64);
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
    }

    // ---- RequestKind enum round-trip ----

    #[test]
    fn request_kind_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, RequestKind)] = &[
            (0x01, RequestKind::FullStatus),
            (0x02, RequestKind::FuelOnly),
            (0x03, RequestKind::BatteryOnly),
            (0x04, RequestKind::BitOnly),
            (0x05, RequestKind::PositionOnly),
            (0xFF, RequestKind::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = RequestKind::from_byte(*byte);
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
            let decoded = RequestKind::from_byte(byte);
            assert_eq!(decoded, RequestKind::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- UrgencyLevel enum round-trip ----

    #[test]
    fn urgency_level_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, UrgencyLevel)] = &[
            (0x01, UrgencyLevel::Routine),
            (0x02, UrgencyLevel::Priority),
            (0x03, UrgencyLevel::Flash),
            (0x04, UrgencyLevel::Immediate),
            (0xFF, UrgencyLevel::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = UrgencyLevel::from_byte(*byte);
            assert_eq!(decoded, *expected, "from_byte mismatch for byte={byte:#x}");
            assert_eq!(
                decoded.to_byte(),
                *byte,
                "to_byte mismatch for {expected:?}"
            );
        }
        for byte in [0x00u8, 0x05, 0x42, 0xEE] {
            let decoded = UrgencyLevel::from_byte(byte);
            assert_eq!(decoded, UrgencyLevel::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- Convenience method parity ----

    #[test]
    fn encode_to_vec_method_matches_free_encode_function() {
        // The struct-method convenience wrapper must produce
        // byte-identical output to the free function — no surprises
        // for callers who switch between styles.
        let msg = full_status_routine_request();
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
        encode_into(&full_status_routine_request(), &mut buf);
        assert_eq!(buf.len(), 3 + EMERGENCY_STATUS_REQUEST_FRAME_LEN);
        assert_eq!(&buf[0..3], &[0xAA, 0xBB, 0xCC]);
        let standalone = encode(&full_status_routine_request());
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
            request_id in any::<u32>(),
            request_kind_byte in any::<u8>(),
            urgency_byte in any::<u8>(),
            response_deadline_ms in any::<u32>(),
            timestamp_unix_ms in any::<u64>(),
        ) {
            let original = EmergencyStatusRequest {
                vehicle_id,
                request_id,
                request_kind: RequestKind::from_byte(request_kind_byte),
                urgency_level: UrgencyLevel::from_byte(urgency_byte),
                response_deadline_ms,
                timestamp_unix_ms,
            };
            let bytes = encode(&original);
            prop_assert_eq!(bytes.len(), EMERGENCY_STATUS_REQUEST_FRAME_LEN);
            let decoded = decode(&bytes).expect("decode round-trip");
            prop_assert_eq!(decoded, original);
        }
    }
}
