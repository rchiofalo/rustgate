// Copyright © 2026 Roberto Chiofalo.

//! STANAG 4586 LOI 4 GCS handover command message.
//!
//! Carries the fourth **command-side** message in the
//! `rustgate-stanag4586` crate, following waypoint upload
//! ([`crate::waypoint_command`]), sensor pointing
//! ([`crate::sensor_pointing_command`]), and mission abort
//! ([`crate::mission_abort_command`]). Where the prior three
//! command-side frames each direct a specific subsystem aboard a single
//! platform — the airframe, a payload sensor, the active mission — GCS
//! handover does not direct the platform at all: it reassigns *which
//! Ground Control Station holds command authority over the platform*.
//! In a multi-station deployment (a forward operating base ground
//! detachment passing control to a recovery-airfield station before a
//! long-leg transit, a primary GCS handing a platform off to a
//! secondary GCS during a shift change, a training exercise where an
//! observer station temporarily monitors what an instructor station is
//! flying), one station emits a `GcsHandoverCommand` to the platform
//! and the platform changes which station it accepts subsequent
//! commands from.
//!
//! # Operational model
//!
//! Multi-station operation is the load-bearing reason this frame
//! exists: a single platform may, over the course of a single mission,
//! be in command authority of two or more distinct GCS instances. A
//! typical workflow looks like:
//!
//! 1. The platform is in command of GCS A (the launching station).
//!    GCS A's operator decides control should pass to GCS B (a
//!    recovery station, a shift-change relief operator, or a downrange
//!    forward observer who needs direct control of the sensor for the
//!    target-prosecution phase).
//! 2. GCS A emits a `GcsHandoverCommand` carrying its own ID as
//!    `current_gcs_id`, GCS B's ID as `target_gcs_id`, a
//!    [`HandoverKind`] selecting the handover semantics
//!    ([`HandoverKind::SoftHandover`] for an orderly transfer that
//!    waits for in-flight commands to complete first,
//!    [`HandoverKind::HardHandover`] for an immediate authority swap
//!    even if a command is mid-execution, [`HandoverKind::MonitorOnly`]
//!    for a non-authoritative observer that sees telemetry but cannot
//!    issue commands, [`HandoverKind::Cancel`] for revoking a
//!    previously-scheduled but not-yet-effective handover), and
//!    optionally an `effective_unix_ms` future-time timestamp scheduling
//!    the handover for later (`0` = "immediate" per documented
//!    semantics).
//! 3. The platform applies the new authority assignment at
//!    `effective_unix_ms` (or immediately if the field is `0`) and
//!    subsequent commands from the previous `current_gcs_id` are
//!    rejected at the platform's command authority gate.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`GCS_HANDOVER_COMMAND_FRAME_LEN`] = 32
//! bytes.
//!
//! ```text
//! offset │ size │ field             │ type
//! ───────┼──────┼───────────────────┼──────────────────────────
//!   0    │  4   │ vehicle_id        │ u32  big-endian
//!   4    │  4   │ current_gcs_id    │ u32  big-endian
//!   8    │  4   │ target_gcs_id     │ u32  big-endian
//!  12    │  1   │ handover_kind     │ u8   enum value (see below)
//!  13    │  3   │ reserved          │ zero-padded — must be 0 on encode
//!  16    │  8   │ effective_unix_ms │ u64  big-endian (Unix epoch ms)
//!  24    │  8   │ timestamp_unix_ms │ u64  big-endian (Unix epoch ms)
//! ```
//!
//! The reserved block is zero-filled on encode. The decoder does NOT
//! validate that it is zero on the wire so a future spec revision that
//! allocates the bytes (e.g. a handover-reason code, or a command
//! sequence number for matching against the future response message)
//! stays backward-compatible at the frame-length level.
//!
//! # Field semantics
//!
//! - `vehicle_id` — the target platform identifier. Matches the
//!   `vehicle_id` carried by the LOI 2-3 telemetry frames and the LOI
//!   4 [`crate::waypoint_command`] /
//!   [`crate::sensor_pointing_command`] /
//!   [`crate::mission_abort_command`] frames so a GCS can correlate
//!   "which platform did I hand over" against "which platform's
//!   telemetry am I currently displaying" by direct byte comparison
//!   without an intermediate lookup table.
//! - `current_gcs_id` — the GCS that currently holds command
//!   authority and is initiating the handover. Opaque to the codec —
//!   the wire byte is whatever the deployment's GCS-numbering scheme
//!   uses (a fielded number, an IP address fragment, an OPLAN-defined
//!   station identifier). The codec does not validate that the
//!   initiating sender's ID matches `current_gcs_id`; that gate lives
//!   at the platform's command authority layer.
//! - `target_gcs_id` — the GCS that should take over command
//!   authority after the handover takes effect. Opaque to the codec
//!   for the same reason as `current_gcs_id`. **Equality with
//!   `current_gcs_id` is explicitly accepted** — the operator may use
//!   it as a no-op confirmation to retransmit a stable authority
//!   assignment after a momentary loss-of-link or as a heartbeat-style
//!   "I still hold authority" signal; pinned in test
//!   `decode_accepts_same_current_and_target_gcs_id` so a regression
//!   that rejected the equality case at the codec layer is caught
//!   before it ships.
//! - `handover_kind` — which handover semantics the platform should
//!   apply. See [`HandoverKind`].
//! - `effective_unix_ms` — when the handover takes effect, milliseconds
//!   since the Unix epoch. **`0` is the documented "immediate"
//!   sentinel** — a regression that rejected `0` as "off the Unix
//!   epoch" or required a future time would silently drop every
//!   immediate handover; pinned in test
//!   `decode_accepts_zero_effective_unix_ms_as_immediate`. The codec
//!   does not validate the value otherwise — a future-dated handover
//!   for scheduled shift-change operations is legal, and a past-dated
//!   value is the platform's command-authority layer's problem rather
//!   than a codec concern.
//! - `timestamp_unix_ms` — when the GCS issued the handover command,
//!   milliseconds since the Unix epoch. The platform may use it to
//!   discard a stale command that lost a race against a follow-on
//!   handover, or to timestamp the authority change in its own audit
//!   log for post-mission reconstruction. The codec does not validate
//!   the value (zero is legal — represents an unset/unknown
//!   timestamp).
//!
//! # What is deliberately absent
//!
//! - **Other LOI 4 commands** — payload control, route upload (the
//!   multi-waypoint companion to [`crate::waypoint_command`]'s
//!   single-waypoint upload), mode change. Each is a separate
//!   follow-up PR with its own wire format and validation rules.
//! - **Response / acknowledgement messages** — the bidirectional
//!   command-response handshake (the platform's "handover accepted,
//!   authority will transfer at T+5s" or "handover rejected, target
//!   GCS not authenticated" reply) is a separate follow-up PR.
//! - **GCS-to-GCS coordination** — this codec is the platform-facing
//!   wire format only. The GCS-to-GCS coordination protocol that the
//!   two stations use to agree on the handover before either of them
//!   tells the platform is out of scope here and lives at the
//!   federation layer.
//! - **UDP/TCP listener wiring** — this module is pure encode/decode
//!   over `&[u8]`; the network glue is a separate change.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a GCS handover command frame.
pub const GCS_HANDOVER_COMMAND_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_CURRENT_GCS_ID: usize = 4;
const OFF_TARGET_GCS_ID: usize = 8;
const OFF_HANDOVER_KIND: usize = 12;
// 13..16 reserved (3 bytes)
const OFF_EFFECTIVE_UNIX_MS: usize = 16;
const OFF_TIMESTAMP: usize = 24;

/// Which handover semantics the platform should apply.
///
/// The four named variants cover the LOI 4 GCS-handover minimum-viable
/// command vocabulary: an orderly transfer that waits for in-flight
/// commands to complete first ([`HandoverKind::SoftHandover`]), an
/// immediate authority swap even if a command is mid-execution
/// ([`HandoverKind::HardHandover`]), a non-authoritative observer that
/// sees telemetry but cannot issue commands
/// ([`HandoverKind::MonitorOnly`]), and a revocation of a
/// previously-scheduled but not-yet-effective handover
/// ([`HandoverKind::Cancel`]). [`HandoverKind::Other`] preserves any
/// unrecognised wire byte so a future spec revision that allocates a
/// new handover semantics stays decodable on a receiver running
/// today's build — matches the same forward-compat discipline used by
/// every sibling LOI 2-3 / LOI 4 frame's enums.
///
/// # Wire byte values
///
/// | byte  | variant         |
/// |-------|-----------------|
/// | `0x01`| `SoftHandover`  |
/// | `0x02`| `HardHandover`  |
/// | `0x03`| `MonitorOnly`   |
/// | `0x04`| `Cancel`        |
/// | other | `Other(byte)`   |
///
/// `0x00` deliberately falls into [`HandoverKind::Other`] rather than
/// having its own "Unknown" variant — the encode side never emits
/// `0x00` for a named kind, so observing one on decode means the
/// upstream sent something unintended and the operator should be able
/// to see the raw byte value in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverKind {
    /// Orderly transfer; the platform completes any in-flight commands
    /// from the current GCS before authority moves to the target.
    SoftHandover,
    /// Immediate authority swap; the platform interrupts in-flight
    /// commands and accepts only the target GCS thereafter.
    HardHandover,
    /// Non-authoritative observer; the target GCS sees telemetry but
    /// cannot issue commands. Used for training observers and
    /// supervisory monitoring.
    MonitorOnly,
    /// Revoke a previously-scheduled but not-yet-effective handover.
    /// The current GCS retains authority.
    Cancel,
    /// Forward-compat catch-all for handover-kind bytes the spec may
    /// allocate in a future revision.
    Other(u8),
}

impl HandoverKind {
    /// Map a wire byte into the typed enum.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::SoftHandover,
            0x02 => Self::HardHandover,
            0x03 => Self::MonitorOnly,
            0x04 => Self::Cancel,
            other => Self::Other(other),
        }
    }

    /// Map the typed enum back into its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::SoftHandover => 0x01,
            Self::HardHandover => 0x02,
            Self::MonitorOnly => 0x03,
            Self::Cancel => 0x04,
            Self::Other(b) => b,
        }
    }
}

/// LOI 4 GCS handover command message.
#[derive(Debug, Clone, PartialEq)]
pub struct GcsHandoverCommand {
    /// Target platform identifier (matches
    /// [`crate::vehicle_position::VehiclePosition::vehicle_id`]).
    pub vehicle_id: u32,
    /// The GCS currently holding command authority and initiating the
    /// handover.
    pub current_gcs_id: u32,
    /// The GCS that should take command authority after the handover
    /// takes effect. Equality with `current_gcs_id` is explicitly
    /// accepted as a no-op confirmation.
    pub target_gcs_id: u32,
    /// Which handover semantics the platform should apply.
    pub handover_kind: HandoverKind,
    /// When the handover takes effect, milliseconds since the Unix
    /// epoch. `0` represents an immediate handover.
    pub effective_unix_ms: u64,
    /// When the GCS issued the command, milliseconds since the Unix
    /// epoch. `0` represents an unset / unknown timestamp.
    pub timestamp_unix_ms: u64,
}

impl GcsHandoverCommand {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a GCS handover command frame into a freshly allocated
/// `Vec<u8>`.
#[must_use]
pub fn encode(msg: &GcsHandoverCommand) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(GCS_HANDOVER_COMMAND_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
///
/// Useful when the encoded frame will be the body of a larger packet
/// and the caller wants to avoid the intermediate `Vec` allocation
/// of [`encode`]. Appends [`GCS_HANDOVER_COMMAND_FRAME_LEN`] bytes;
/// does not clear or truncate `buf`.
pub fn encode_into(msg: &GcsHandoverCommand, buf: &mut BytesMut) {
    buf.reserve(GCS_HANDOVER_COMMAND_FRAME_LEN);
    buf.put_u32(msg.vehicle_id);
    buf.put_u32(msg.current_gcs_id);
    buf.put_u32(msg.target_gcs_id);
    buf.put_u8(msg.handover_kind.to_byte());
    // 3 reserved bytes.
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u64(msg.effective_unix_ms);
    buf.put_u64(msg.timestamp_unix_ms);
}

/// Decode a GCS handover command frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
///
/// Trailing bytes beyond [`GCS_HANDOVER_COMMAND_FRAME_LEN`] are
/// ignored; the codec is fixed-size and a future protocol revision
/// that appends fields keeps decoding the prefix unchanged.
///
/// All numeric fields accept any wire value — `vehicle_id`,
/// `current_gcs_id`, and `target_gcs_id` are opaque deployment-defined
/// identifiers and the timestamps are not range-checked. Self-handover
/// (`current_gcs_id == target_gcs_id`) is accepted as a no-op
/// confirmation, and `effective_unix_ms == 0` is the documented
/// "immediate handover" sentinel — both are pinned by dedicated tests.
///
/// Unrecognised `handover_kind` bytes do NOT cause an error — they
/// surface as [`HandoverKind::Other`] for forward compatibility.
pub fn decode(bytes: &[u8]) -> Result<GcsHandoverCommand, Stanag4586Error> {
    if bytes.len() < GCS_HANDOVER_COMMAND_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: GCS_HANDOVER_COMMAND_FRAME_LEN,
        });
    }

    let mut cursor = &bytes[..GCS_HANDOVER_COMMAND_FRAME_LEN];
    let vehicle_id = cursor.get_u32();
    let current_gcs_id = cursor.get_u32();
    let target_gcs_id = cursor.get_u32();
    let handover_kind = HandoverKind::from_byte(cursor.get_u8());
    // Skip 3-byte reserved region.
    cursor.advance(3);
    let effective_unix_ms = cursor.get_u64();
    let timestamp_unix_ms = cursor.get_u64();

    debug_assert!(
        cursor.is_empty(),
        "fixed-size frame should be fully consumed; bug in offset constants"
    );
    let _ = OFF_VEHICLE_ID;
    let _ = OFF_CURRENT_GCS_ID;
    let _ = OFF_TARGET_GCS_ID;
    let _ = OFF_HANDOVER_KIND;
    let _ = OFF_EFFECTIVE_UNIX_MS;
    let _ = OFF_TIMESTAMP;

    Ok(GcsHandoverCommand {
        vehicle_id,
        current_gcs_id,
        target_gcs_id,
        handover_kind,
        effective_unix_ms,
        timestamp_unix_ms,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Mid-range typical `SoftHandover` fixture. Deliberately
    /// non-default values so an `assert_eq!` mismatch points at the
    /// right field.
    fn typical_soft_handover_command() -> GcsHandoverCommand {
        GcsHandoverCommand {
            vehicle_id: 0xA1B2_C3D4,
            current_gcs_id: 0x0000_0001,
            target_gcs_id: 0x0000_0002,
            handover_kind: HandoverKind::SoftHandover,
            effective_unix_ms: 0,
            timestamp_unix_ms: 0x0000_0001_600F_1234,
        }
    }

    /// Fixture exercising the [`HandoverKind::HardHandover`] path with
    /// a non-zero `effective_unix_ms` — used to pin that the
    /// scheduling field round-trips independently of the handover
    /// kind.
    fn hard_handover_with_effective_time() -> GcsHandoverCommand {
        GcsHandoverCommand {
            vehicle_id: 0xDEAD_BEEF,
            current_gcs_id: 42,
            target_gcs_id: 7,
            handover_kind: HandoverKind::HardHandover,
            effective_unix_ms: 0x0000_0001_700A_BCDE,
            timestamp_unix_ms: 0x0000_0001_700A_0000,
        }
    }

    // ---- Round-trip ----

    #[test]
    fn round_trip_zero_valued_fixture() {
        // All-zero is a valid frame: vehicle_id=0, current_gcs_id=0,
        // target_gcs_id=0 (which also exercises the documented
        // self-handover acceptance path), handover_kind defaults to
        // Other(0) (forward-compat catch-all preserves the byte),
        // effective_unix_ms=0 (the documented "immediate" sentinel),
        // and timestamp_unix_ms=0 (= unset). The round-trip must hold
        // even at this corner.
        let msg = GcsHandoverCommand {
            vehicle_id: 0,
            current_gcs_id: 0,
            target_gcs_id: 0,
            handover_kind: HandoverKind::Other(0),
            effective_unix_ms: 0,
            timestamp_unix_ms: 0,
        };
        let bytes = encode(&msg);
        assert_eq!(bytes, vec![0u8; GCS_HANDOVER_COMMAND_FRAME_LEN]);
        let decoded = decode(&bytes).expect("zero round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_typical_soft_handover_fixture() {
        let msg = typical_soft_handover_command();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), GCS_HANDOVER_COMMAND_FRAME_LEN);
        let decoded = decode(&bytes).expect("typical round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_hard_handover_fixture_with_effective_time() {
        let msg = hard_handover_with_effective_time();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), GCS_HANDOVER_COMMAND_FRAME_LEN);
        let decoded = decode(&bytes).expect("hard handover round-trip");
        assert_eq!(decoded, msg);
    }

    // ---- Self-handover explicitly accepted ----

    #[test]
    fn decode_accepts_same_current_and_target_gcs_id() {
        // Pin the no-op-confirmation contract: the operator may use
        // current_gcs_id == target_gcs_id to retransmit a stable
        // authority assignment after a momentary loss-of-link or as a
        // heartbeat-style "I still hold authority" signal. A
        // regression that rejected the equality case at the codec
        // layer would silently drop these confirmations and leave the
        // platform without the periodic re-affirmation it expects.
        let msg = GcsHandoverCommand {
            vehicle_id: 1,
            current_gcs_id: 0xCAFE_BABE,
            target_gcs_id: 0xCAFE_BABE,
            handover_kind: HandoverKind::SoftHandover,
            effective_unix_ms: 1,
            timestamp_unix_ms: 2,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("self-handover must decode cleanly");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.current_gcs_id, decoded.target_gcs_id);
    }

    // ---- effective_unix_ms == 0 explicitly accepted ----

    #[test]
    fn decode_accepts_zero_effective_unix_ms_as_immediate() {
        // Pin the immediate-handover sentinel: senders write `0` for
        // `effective_unix_ms` to request an immediate handover. A
        // regression that rejected `0` as "off the Unix epoch" or
        // required a non-zero (e.g. future-dated) value would silently
        // drop every immediate handover — the most common operational
        // case.
        let msg = GcsHandoverCommand {
            vehicle_id: 1,
            current_gcs_id: 1,
            target_gcs_id: 2,
            handover_kind: HandoverKind::HardHandover,
            effective_unix_ms: 0,
            timestamp_unix_ms: 1,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("zero effective_unix_ms must decode cleanly");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.effective_unix_ms, 0);
    }

    // ---- Golden-fixture decode ----

    #[test]
    fn decode_known_fixture_matches_expected_bytes() {
        // Hand-built golden fixture that pins every field at its
        // documented byte offset. The big-endian byte sequences for
        // the two u64 timestamps are computed in the test source so a
        // regression that swapped to little-endian could pass the
        // round-trip + proptest checks but would still fail this
        // byte-pinning check.
        //
        // Field values:
        //   vehicle_id        = 0x1122_3344
        //   current_gcs_id    = 0xAABB_CCDD
        //   target_gcs_id     = 0x5566_7788
        //   handover_kind     = 0x01 (SoftHandover)
        //   effective_unix_ms = 0x0123_4567_89AB_CDEF
        //   timestamp_unix_ms = 0xFEDC_BA98_7654_3210
        let msg = GcsHandoverCommand {
            vehicle_id: 0x1122_3344,
            current_gcs_id: 0xAABB_CCDD,
            target_gcs_id: 0x5566_7788,
            handover_kind: HandoverKind::SoftHandover,
            effective_unix_ms: 0x0123_4567_89AB_CDEF,
            timestamp_unix_ms: 0xFEDC_BA98_7654_3210,
        };
        let bytes = encode(&msg);
        let expected: [u8; GCS_HANDOVER_COMMAND_FRAME_LEN] = [
            // vehicle_id = 0x1122_3344 (big-endian)
            0x11, 0x22, 0x33, 0x44, //
            // current_gcs_id = 0xAABB_CCDD (big-endian)
            0xAA, 0xBB, 0xCC, 0xDD, //
            // target_gcs_id = 0x5566_7788 (big-endian)
            0x55, 0x66, 0x77, 0x88, //
            // handover_kind = 0x01 (SoftHandover)
            0x01, //
            // 3 reserved zero bytes
            0x00, 0x00, 0x00, //
            // effective_unix_ms = 0x0123_4567_89AB_CDEF (big-endian)
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, //
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
                    assert_eq!(expected, GCS_HANDOVER_COMMAND_FRAME_LEN);
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
        let msg = typical_soft_handover_command();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(&[0xAA; 32]);
        assert_eq!(bytes.len(), 64);
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
    }

    // ---- HandoverKind enum round-trip ----

    #[test]
    fn handover_kind_round_trip_preserves_named_variants_and_other_byte() {
        // Named variants table: every one MUST round-trip its
        // assigned wire byte. Plus an `Other(0xFF)` to pin the
        // forward-compat catch-all preserves the raw byte.
        let cases: &[(u8, HandoverKind)] = &[
            (0x01, HandoverKind::SoftHandover),
            (0x02, HandoverKind::HardHandover),
            (0x03, HandoverKind::MonitorOnly),
            (0x04, HandoverKind::Cancel),
            (0xFF, HandoverKind::Other(0xFF)),
        ];
        for (byte, expected) in cases {
            let decoded = HandoverKind::from_byte(*byte);
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
        for byte in [0x00u8, 0x05, 0x42, 0xEE] {
            let decoded = HandoverKind::from_byte(byte);
            assert_eq!(decoded, HandoverKind::Other(byte));
            assert_eq!(decoded.to_byte(), byte);
        }
    }

    // ---- Convenience method parity ----

    #[test]
    fn encode_to_vec_method_matches_free_encode_function() {
        // The struct-method convenience wrapper must produce
        // byte-identical output to the free function — no surprises
        // for callers who switch between styles.
        let msg = typical_soft_handover_command();
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
        encode_into(&typical_soft_handover_command(), &mut buf);
        assert_eq!(buf.len(), 3 + GCS_HANDOVER_COMMAND_FRAME_LEN);
        assert_eq!(&buf[0..3], &[0xAA, 0xBB, 0xCC]);
        let standalone = encode(&typical_soft_handover_command());
        assert_eq!(&buf[3..], &standalone[..]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        // Property test: any valid struct round-trips byte-for-byte.
        // All numeric fields are unconstrained — there are no range
        // checks on the wire, and the handover_kind byte covers every
        // u8 value (named variants 0x01–0x04, `Other` for the rest).
        #[test]
        fn round_trip_via_proptest(
            vehicle_id in any::<u32>(),
            current_gcs_id in any::<u32>(),
            target_gcs_id in any::<u32>(),
            kind_byte in any::<u8>(),
            effective_unix_ms in any::<u64>(),
            timestamp_unix_ms in any::<u64>(),
        ) {
            let original = GcsHandoverCommand {
                vehicle_id,
                current_gcs_id,
                target_gcs_id,
                handover_kind: HandoverKind::from_byte(kind_byte),
                effective_unix_ms,
                timestamp_unix_ms,
            };
            let bytes = encode(&original);
            prop_assert_eq!(bytes.len(), GCS_HANDOVER_COMMAND_FRAME_LEN);
            let decoded = decode(&bytes).expect("decode round-trip");
            prop_assert_eq!(decoded, original);
        }
    }
}
