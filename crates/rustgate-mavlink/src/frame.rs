// Copyright © 2026 Roberto Chiofalo.

//! MAVLink v1 and v2 frame parser.
//!
//! This module implements the byte-level framing state machine used by
//! every MAVLink transport in rustgate. It knows how long a frame is and
//! how to resynchronise after corruption — nothing more. CRC verification
//! and signature checking live in a separate `signing` module (future PR)
//! because those concerns also need the replay-timestamp table.
//!
//! # Wire layout
//!
//! v1 (`STX = 0xFE`):
//!
//! ```text
//! STX │ LEN │ SEQ │ SYS │ COMP │ MSGID │ PAYLOAD (0..=255) │ CRC (2)
//!  1     1     1     1     1      1           LEN               2
//! ```
//!
//! Total: `8 + LEN` bytes. Max: 263.
//!
//! v2 (`STX = 0xFD`):
//!
//! ```text
//! STX │ LEN │ INCOMPAT │ COMPAT │ SEQ │ SYS │ COMP │ MSGID (3) │ PAYLOAD │ CRC (2) │ [SIG (13)]
//!  1     1      1          1       1     1     1        3         LEN        2       0 or 13
//! ```
//!
//! Total: `12 + LEN + (13 if INCOMPAT & 0x01 else 0)`. Max: 280.
//!
//! # Resync
//!
//! If the byte at the current read position is neither `0xFE` nor `0xFD`,
//! the decoder drops one byte at a time until it finds a valid magic or
//! exhausts the buffer. A single `tracing::debug!` event summarises the
//! number of bytes discarded so a noisy link cannot flood the log stream.
//! This matches the behaviour of production MAVLink implementations like
//! `mavlink-router` and the `pymavlink` reference parser.
//!
//! # Signing policy
//!
//! The codec defaults to **v2 + signature required** — v1 frames (which
//! have no signature field) and unsigned v2 frames are both rejected
//! with a dedicated error variant so the session layer can emit the
//! matching audit record and close the link. Operators that run mixed
//! fleets opt back in via [`MavlinkFrameCodec::with_allow_v1`] and
//! [`MavlinkFrameCodec::with_require_signing`].
//!
//! Rejection advances the buffer past the offending magic byte before
//! returning so the next `decode()` call cannot re-read the same header
//! and loop forever on an attacker-supplied stream. The rest of the
//! header is deliberately left in place: if the byte after the rejected
//! magic happens to start another valid frame, resync recovers it on
//! the next call.

use std::io;

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::MavlinkError;

/// Start-of-text byte for a MAVLink v1 frame.
pub const MAVLINK_V1_MAGIC: u8 = 0xFE;

/// Start-of-text byte for a MAVLink v2 frame.
pub const MAVLINK_V2_MAGIC: u8 = 0xFD;

/// v1 header size: STX + LEN + SEQ + SYSID + COMPID + MSGID.
const MAVLINK_V1_HEADER_LEN: usize = 6;

/// v2 header size: STX + LEN + INCOMPAT + COMPAT + SEQ + SYSID + COMPID + MSGID(3).
const MAVLINK_V2_HEADER_LEN: usize = 10;

/// CRC-16/MCRF4XX trailer size, identical for v1 and v2.
const MAVLINK_CRC_LEN: usize = 2;

/// v2 signature trailer size: LINK_ID(1) + TIMESTAMP(6) + SIGNATURE(6).
const MAVLINK_SIGNATURE_LEN: usize = 13;

/// INCOMPAT_FLAGS bit marking a v2 frame as signed.
///
/// The spec reserves this bit as "incompat" because signature presence
/// changes where the CRC lives relative to the end of the frame. A
/// receiver that doesn't recognise the flag literally can't tell where
/// the frame ends, so unknown INCOMPAT bits MUST cause rejection.
const MAVLINK_IFLAG_SIGNED: u8 = 0x01;

/// Hard cap on a single MAVLink frame (v2 signed, `LEN = 255`).
///
/// 10 (header) + 255 (payload) + 2 (CRC) + 13 (signature) = 280.
pub const MAX_MAVLINK_FRAME_SIZE: usize =
    MAVLINK_V2_HEADER_LEN + u8::MAX as usize + MAVLINK_CRC_LEN + MAVLINK_SIGNATURE_LEN;

/// MAVLink message ID for `HEARTBEAT` (`0`).
///
/// Standard MAVLink dialect — every dialect inherits this ID unchanged
/// because the spec pins HEARTBEAT to message 0 specifically so cross-
/// dialect parsers can recognise presence pings without loading the
/// full message catalogue.
pub const HEARTBEAT_MSG_ID: u32 = 0;

/// Wire size of a `HEARTBEAT` payload after MAVLink's field-size-
/// descending reordering: `custom_mode` (u32) + 5 × u8 = 9 bytes.
///
/// v2 truncates trailing zero bytes on the wire, so the on-wire payload
/// can be shorter — the decoder only invokes the heartbeat callback
/// when at least the first 6 bytes (covering `custom_mode`,
/// `vehicle_type`, `autopilot`) are present.
const HEARTBEAT_PAYLOAD_MIN_LEN: usize = 6;

/// Byte offset of the `vehicle_type` field inside the HEARTBEAT payload.
///
/// MAVLink reorders fields by descending size for wire encoding, so
/// `custom_mode` (u32) lands at offset 0–3 and `type` follows at 4.
const HEARTBEAT_TYPE_OFFSET: usize = 4;

/// Byte offset of the `autopilot` field inside the HEARTBEAT payload.
const HEARTBEAT_AUTOPILOT_OFFSET: usize = 5;

rustgate_core::on_callback!(
    /// Callback invoked once per decoded MAVLink HEARTBEAT frame
    /// (`MSG_ID = 0`).
    ///
    /// Arguments are `(system_id, component_id, autopilot, vehicle_type)`
    /// — the first two come from the v1/v2 header, the latter two from the
    /// HEARTBEAT payload. The four `u8` shape mirrors the audit-event field
    /// list in `rustgate_core::audit::mavlink_heartbeat_received` so the
    /// server crate can wire a single closure that calls both.
    ///
    /// Wired by the server crate to feed the
    /// `rustgate_mavlink_heartbeats_total{system_id}` Prometheus counter
    /// and emit the `mavlink.heartbeat_received` audit event. Kept as a
    /// simple `Fn(u8, u8, u8, u8)` so the `rustgate-mavlink` crate stays
    /// metrics-agnostic and does not grow a `prometheus` dependency. The
    /// callback is fired only on frames that decode cleanly and whose
    /// HEARTBEAT payload is large enough to surface every field — a frame
    /// truncated below the spec's 6-byte minimum (covering the autopilot
    /// and vehicle_type fields after `custom_mode`) does NOT invoke the
    /// callback so a malformed sender cannot generate a fake presence
    /// signal.
    pub OnMavlinkHeartbeat,
    u8,
    u8,
    u8,
    u8
);

/// Why the MAVLink frame codec rejected a frame.
///
/// Mirrors the typed [`crate::error::MavlinkError`] variants the codec
/// surfaces on policy and validation failures, but flattened into a
/// single non-exhaustive enum so a callback consumer can branch on the
/// classification without re-matching against `io::Error::get_ref()`
/// downcasts. The variants are deliberately disjoint so a SIEM can
/// tally them independently — "fleet still has v1 senders" is a
/// different operational signal from "signing rollout incomplete" or
/// "sender uses a non-standard dialect".
///
/// Marked `#[non_exhaustive]` so a future rejection class (e.g. CRC
/// mismatch once the signing layer lands) can be added without a
/// breaking API change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// A v1 frame was rejected because the codec is configured to
    /// disallow the pre-signing wire format.
    V1NotAllowed,
    /// A v2 frame was rejected because its `INCOMPAT & SIGNED` bit was
    /// clear and the codec is configured to require signatures.
    UnsignedV2,
    /// A frame's `MSG_ID` does not appear in the CRC-EXTRA lookup
    /// table — the dialect catalogue does not know how to authenticate
    /// it. Indicates either a non-standard dialect or a hostile sender
    /// fishing for unknown IDs.
    UnknownMessageId(u32),
}

rustgate_core::on_callback!(
    /// Callback invoked once per MAVLink frame the codec rejected at the
    /// framing layer.
    ///
    /// The codec itself does not have access to the peer socket address
    /// (it operates on a `BytesMut` buffer), so the listener that drives
    /// the codec wires this callback up with whatever peer context it has
    /// — typically the dialled IP:port for a TCP link, or "unknown" for a
    /// UDP datagram whose source we deliberately do not log. The callback
    /// fires inside the decode hot path on the rejection branch only — a
    /// frame that decodes cleanly does not invoke it.
    ///
    /// Wired by the listener crate (future PR) to emit the
    /// `mavlink.unsigned_rejected`, `mavlink.v1_rejected`, and
    /// `mavlink.unknown_msg_id` audit events through
    /// `rustgate_core::audit` and increment the matching Prometheus
    /// counters. Kept as a simple `Fn(RejectionReason)` so the
    /// `rustgate-mavlink` crate stays free of `tracing`/`prometheus`
    /// dependencies on the rejection path. The closure body is responsible
    /// for shielding sensitive context (peer IP, identity) before
    /// emitting; the codec passes only the typed reason.
    pub OnMavlinkRejection,
    RejectionReason
);

/// Protocol version of a parsed MAVLink frame.
///
/// Callers that care about version (signing, message-ID parsing,
/// obligation actuators) can match on this to branch without re-reading
/// the magic byte.
///
/// Marked `#[non_exhaustive]` so a future MAVLink v3 (or a private
/// variant) can be added without a breaking API change: downstream
/// callers must use a wildcard arm when matching on this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MavlinkVersion {
    /// MAVLink v1 (`0xFE`).
    V1,
    /// MAVLink v2 (`0xFD`).
    V2,
}

impl MavlinkVersion {
    /// Classify a frame by its first byte.
    ///
    /// Returns `None` if the byte is not a recognised MAVLink magic.
    /// Primarily useful for audit logs and test assertions — the decoder
    /// itself dispatches on the raw byte.
    #[must_use]
    pub fn from_magic(byte: u8) -> Option<Self> {
        match byte {
            MAVLINK_V1_MAGIC => Some(Self::V1),
            MAVLINK_V2_MAGIC => Some(Self::V2),
            _ => None,
        }
    }
}

/// `tokio_util` [`Decoder`]/[`Encoder`] pair for MAVLink frames.
///
/// Slices complete v1 or v2 frames out of a TCP/UDP byte stream. The
/// emitted [`BytesMut`] contains the entire frame — magic byte, header,
/// payload, CRC, and (for signed v2) signature — so downstream stages
/// can verify the CRC, check the signature, or forward the bytes
/// opaquely without re-assembly.
///
/// # Signing policy
///
/// The default is **v2 + signature required** — both v1 and unsigned v2
/// are rejected at the framing layer. That default matches the threat
/// model of every deployment that runs MAVLink over anything other than
/// a fully trusted link: an attacker who can inject frames can forge
/// identities without signing. Operators running mixed fleets opt back
/// in via [`MavlinkFrameCodec::with_allow_v1`] and
/// [`MavlinkFrameCodec::with_require_signing`] — both stance-setters so
/// the choice is explicit at wiring time, not silently inherited from a
/// default.
///
/// # State
///
/// A single `Option<usize>` tracks the total length of the frame
/// currently being reassembled. When the header arrives, the length is
/// computed once and cached until the full payload has been read; this
/// avoids re-parsing the header on every poll.
pub struct MavlinkFrameCodec {
    /// Total frame length (including magic byte) once the header has
    /// been parsed. `None` until enough bytes arrive to determine the
    /// size; reset to `None` after a frame is emitted.
    pending_total_len: Option<usize>,
    /// When `true` (the default), v2 frames without the SIGNED INCOMPAT
    /// bit are rejected with [`MavlinkError::UnsignedFrameRejected`].
    require_signing: bool,
    /// When `false` (the default), v1 frames are rejected with
    /// [`MavlinkError::V1FrameRejected`].
    allow_v1: bool,
    /// Optional observer fired once per successfully-decoded HEARTBEAT
    /// frame. `None` (the default) leaves the decode hot path
    /// untouched; the server crate installs a closure that emits the
    /// `mavlink.heartbeat_received` audit event and increments the
    /// `rustgate_mavlink_heartbeats_total{system_id}` Prometheus
    /// counter under `--features metrics`.
    on_heartbeat: Option<OnMavlinkHeartbeat>,
    /// Optional observer fired once per frame the codec rejected at
    /// the framing layer (v1 disallowed, unsigned v2 with signing
    /// required, unknown MSG_ID). The listener crate wires this to
    /// emit the matching audit event through `rustgate_core::audit`
    /// and increment the rejection counter; the codec stays free of
    /// `tracing` and `prometheus` deps on the rejection path.
    on_rejection: Option<OnMavlinkRejection>,
}

impl std::fmt::Debug for MavlinkFrameCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MavlinkFrameCodec")
            .field("pending_total_len", &self.pending_total_len)
            .field("require_signing", &self.require_signing)
            .field("allow_v1", &self.allow_v1)
            .field(
                "on_heartbeat",
                &if self.on_heartbeat.is_some() {
                    "Some(<cb>)"
                } else {
                    "None"
                },
            )
            .field(
                "on_rejection",
                &if self.on_rejection.is_some() {
                    "Some(<cb>)"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

impl Default for MavlinkFrameCodec {
    fn default() -> Self {
        Self {
            pending_total_len: None,
            // Secure default: require signatures, reject v1 entirely.
            // Operators opt back in explicitly.
            require_signing: true,
            allow_v1: false,
            on_heartbeat: None,
            on_rejection: None,
        }
    }
}

impl MavlinkFrameCodec {
    /// Construct a fresh codec with no pending state.
    ///
    /// Defaults to the strict signing policy: v1 rejected,
    /// unsigned v2 rejected. See [`MavlinkFrameCodec`] struct docs.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether v2 frames without the SIGNED INCOMPAT bit are
    /// rejected.
    ///
    /// `true` (the default) rejects unsigned v2 frames with
    /// [`MavlinkError::UnsignedFrameRejected`]. `false` accepts them —
    /// use only when running on a trusted link where signing is not
    /// available end-to-end.
    #[must_use]
    pub fn with_require_signing(mut self, require: bool) -> Self {
        self.require_signing = require;
        self
    }

    /// Set whether MAVLink v1 frames are accepted.
    ///
    /// `false` (the default) rejects v1 frames with
    /// [`MavlinkError::V1FrameRejected`] — v1 has no signature field, so
    /// accepting it on a link that runs signed v2 traffic would hand an
    /// attacker a downgrade path. `true` re-enables v1 for legacy
    /// deployments; callers MUST understand that v1 traffic cannot be
    /// authenticated at the MAVLink layer.
    #[must_use]
    pub fn with_allow_v1(mut self, allow: bool) -> Self {
        self.allow_v1 = allow;
        self
    }

    /// Returns `true` if the codec rejects unsigned v2 frames.
    #[must_use]
    pub fn requires_signing(&self) -> bool {
        self.require_signing
    }

    /// Returns `true` if the codec accepts v1 frames.
    #[must_use]
    pub fn allows_v1(&self) -> bool {
        self.allow_v1
    }

    /// Install a callback fired once per successfully-decoded HEARTBEAT
    /// frame (`MSG_ID = 0`).
    ///
    /// The callback receives `(system_id, component_id, autopilot,
    /// vehicle_type)` extracted from the v1/v2 header and the HEARTBEAT
    /// payload. See [`OnMavlinkHeartbeat`] for the operational rationale.
    ///
    /// `None` (the default) leaves the decode hot path untouched and
    /// the codec performs no payload inspection beyond the framing
    /// state machine — the cost of installing the callback is paid
    /// only when an operator wires one in.
    #[must_use]
    pub fn with_on_heartbeat(mut self, cb: OnMavlinkHeartbeat) -> Self {
        self.on_heartbeat = Some(cb);
        self
    }

    /// Returns `true` if a HEARTBEAT observer is installed.
    #[must_use]
    pub fn has_heartbeat_observer(&self) -> bool {
        self.on_heartbeat.is_some()
    }

    /// Install a callback fired once per frame the codec rejected at
    /// the framing layer.
    ///
    /// See [`OnMavlinkRejection`] for the operational rationale. The
    /// listener wires this to emit the matching audit event
    /// (`mavlink.unsigned_rejected`, `mavlink.v1_rejected`,
    /// `mavlink.unknown_msg_id`) and increment a Prometheus counter
    /// labelled by reason. `None` (the default) leaves the rejection
    /// hot path untouched — the codec still produces the typed
    /// [`MavlinkError`], but no audit/metrics side-effect is
    /// generated.
    #[must_use]
    pub fn with_on_rejection(mut self, cb: OnMavlinkRejection) -> Self {
        self.on_rejection = Some(cb);
        self
    }

    /// Returns `true` if a rejection observer is installed.
    #[must_use]
    pub fn has_rejection_observer(&self) -> bool {
        self.on_rejection.is_some()
    }

    /// Internal helper: notify the rejection observer (if installed)
    /// and return the typed error variant the caller surfaces. Keeps
    /// the rejection sites in `resolve_total_len` and `decode` from
    /// repeating the `if let Some(cb) = …` boilerplate.
    fn reject(&self, reason: RejectionReason, err: MavlinkError) -> MavlinkError {
        if let Some(cb) = self.on_rejection.as_ref() {
            cb(reason);
        }
        err
    }

    /// Parse just enough of the header to know how long the frame is.
    ///
    /// Returns `Ok(Some(total_len))` when a valid magic byte plus `LEN`
    /// (and, for v2, `INCOMPAT`) byte is available. Returns `Ok(None)`
    /// when more bytes are needed. Returns `Err` when the bytes are
    /// present but parse to a malformed header (unknown INCOMPAT bits,
    /// oversized total length) or when the configured signing policy
    /// rejects the frame (v1 with `allow_v1 = false`, unsigned v2 with
    /// `require_signing = true`). On policy rejection the offending
    /// magic byte is consumed before returning so the next `decode()`
    /// call starts fresh.
    fn resolve_total_len(&self, src: &mut BytesMut) -> Result<Option<usize>, MavlinkError> {
        // Resync: drop anything that isn't a MAVLink magic byte. This is
        // deliberately eager — a single hostile client can prepend a
        // gigabyte of `0x00` to starve the parser if we limit the
        // discard window, whereas advancing per byte is O(1) on
        // `BytesMut`.
        let mut dropped = 0usize;
        while !src.is_empty() && MavlinkVersion::from_magic(src[0]).is_none() {
            src.advance(1);
            dropped += 1;
        }
        if dropped > 0 {
            // `trace` (not `debug`) — a hostile or misconfigured link
            // can produce this on every byte, and users running
            // `RUST_LOG=debug` would otherwise see the log flooded.
            tracing::trace!(bytes = dropped, "mavlink resync discarded bytes");
        }
        if src.is_empty() {
            return Ok(None);
        }

        let total = match src[0] {
            MAVLINK_V1_MAGIC => {
                // Policy check: reject v1 before buffering more bytes so
                // an attacker cannot pin memory by dripping partial v1
                // headers. Consume the magic so resync advances past it
                // on the next call and a following valid v2 frame can
                // still be picked up.
                if !self.allow_v1 {
                    src.advance(1);
                    return Err(
                        self.reject(RejectionReason::V1NotAllowed, MavlinkError::V1FrameRejected)
                    );
                }
                if src.len() < 2 {
                    return Ok(None);
                }
                let len = src[1] as usize;
                MAVLINK_V1_HEADER_LEN + len + MAVLINK_CRC_LEN
            }
            MAVLINK_V2_MAGIC => {
                if src.len() < 3 {
                    return Ok(None);
                }
                let len = src[1] as usize;
                let incompat = src[2];
                // Per MAVLink spec: any INCOMPAT bit the receiver does
                // not understand MUST cause the packet to be rejected.
                // Signature presence (bit 0) is the only flag this
                // implementation knows; anything else changes wire
                // parsing we can't perform.
                if incompat & !MAVLINK_IFLAG_SIGNED != 0 {
                    // Advance past the bad magic byte so the next decode
                    // call cannot re-read the same header and loop
                    // forever on an attacker-supplied stream. Dropping
                    // only the magic (not the whole header) preserves
                    // the chance that the following byte happens to
                    // start a real frame.
                    src.advance(1);
                    return Err(MavlinkError::InvalidIncompatFlags { flags: incompat });
                }
                let signed = incompat & MAVLINK_IFLAG_SIGNED != 0;
                // Policy check: reject unsigned v2 frames when signing
                // is required. Consume only the magic byte, matching the
                // recovery behaviour of the INCOMPAT rejection above.
                if self.require_signing && !signed {
                    src.advance(1);
                    return Err(self.reject(
                        RejectionReason::UnsignedV2,
                        MavlinkError::UnsignedFrameRejected,
                    ));
                }
                let sig_len = if signed { MAVLINK_SIGNATURE_LEN } else { 0 };
                MAVLINK_V2_HEADER_LEN + len + MAVLINK_CRC_LEN + sig_len
            }
            // Defense-in-depth: the resync loop above should guarantee
            // only magic bytes reach here, but return an error instead
            // of panicking.
            _ => {
                let byte = src[0];
                src.advance(1);
                return Err(MavlinkError::InvalidMagic { byte });
            }
        };

        if total > MAX_MAVLINK_FRAME_SIZE {
            return Err(MavlinkError::FrameTooLarge {
                size: total,
                max: MAX_MAVLINK_FRAME_SIZE,
            });
        }

        Ok(Some(total))
    }
}

impl Decoder for MavlinkFrameCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let total = match self.pending_total_len {
            Some(n) => n,
            None => match self.resolve_total_len(src)? {
                Some(n) => {
                    self.pending_total_len = Some(n);
                    n
                }
                None => return Ok(None),
            },
        };

        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }

        // Clear pending_total_len BEFORE splitting so that a panic
        // between these two lines (e.g., OOM) cannot leave the codec in
        // a state where it thinks it is mid-frame on a buffer that no
        // longer contains one.
        self.pending_total_len = None;
        let frame = src.split_to(total);

        // CRC-EXTRA gate (F-73): the dialect catalogue's `crc_extra`
        // byte is required to authenticate the frame's CRC trailer. A
        // frame whose `MSG_ID` is not in the lookup table cannot be
        // verified — accepting it would either bypass the CRC check
        // silently or panic via `unwrap()` on the table lookup. The
        // lookup uses `Option`-returning `crc_extra::crc_extra` so an
        // attacker who streams frames with random `MSG_ID`s drives
        // neither a panic nor a per-frame allocation; the rejection
        // surfaces as `MavlinkError::UnknownMessageId` and consumes
        // the frame's bytes (already split out of `src` above) so a
        // recovery loop can immediately try the next frame.
        let msg_id = match parse_msg_id(&frame) {
            Some(id) => id,
            None => {
                // Defense-in-depth: a frame that survived the framing
                // state machine should always have a parseable header.
                // Treat the unparseable case as the same hostile-input
                // class — surface a typed error and fire the rejection
                // observer so a SIEM can correlate the spike.
                return Err(self
                    .reject(
                        RejectionReason::UnknownMessageId(0),
                        MavlinkError::UnknownMessageId { id: 0 },
                    )
                    .into());
            }
        };
        if crate::crc_extra::crc_extra(msg_id).is_none() {
            return Err(self
                .reject(
                    RejectionReason::UnknownMessageId(msg_id),
                    MavlinkError::UnknownMessageId { id: msg_id },
                )
                .into());
        }

        // HEARTBEAT inspection runs only when an observer is wired —
        // gating on `is_some()` keeps the no-observer path identical
        // to the pre-#909 hot path (no field extraction, no callback
        // dispatch). The header walk reads at most 7 bytes, so the
        // observer-on path adds a handful of L1-resident loads per
        // frame; the cost only materialises on links that wired in
        // a Prometheus counter or audit listener.
        if self.on_heartbeat.is_some()
            && let Some((sys, comp, autopilot, veh)) = parse_heartbeat_fields(&frame)
        {
            // `is_some()` was just verified — the `if let` cannot fail
            // here even though clippy can't prove it, but the explicit
            // `if let` keeps the call site readable without a
            // `.expect()` that adds noise on the success path.
            if let Some(cb) = self.on_heartbeat.as_ref() {
                cb(sys, comp, autopilot, veh);
            }
        }

        Ok(Some(frame))
    }
}

/// Extract the `MSG_ID` field from a fully-decoded MAVLink frame.
///
/// Returns `None` for any frame whose magic byte is not recognised or
/// whose buffer is shorter than the v1/v2 header — defense-in-depth
/// against a future refactor that loosens the framer's guarantees.
/// Read-only by construction; the caller owns the buffer.
fn parse_msg_id(frame: &[u8]) -> Option<u32> {
    let first = *frame.first()?;
    let version = MavlinkVersion::from_magic(first)?;
    match version {
        // v1: STX(0) LEN(1) SEQ(2) SYS(3) COMP(4) MSGID(5)
        MavlinkVersion::V1 => Some(*frame.get(5)? as u32),
        // v2: STX(0) LEN(1) INCOMPAT(2) COMPAT(3) SEQ(4) SYS(5) COMP(6)
        //     MSGID_LO(7) MSGID_MID(8) MSGID_HI(9)
        MavlinkVersion::V2 => {
            let lo = *frame.get(7)? as u32;
            let mid = *frame.get(8)? as u32;
            let hi = *frame.get(9)? as u32;
            Some(lo | (mid << 8) | (hi << 16))
        }
    }
}

/// Extract `(system_id, component_id, autopilot, vehicle_type)` from a
/// fully-decoded MAVLink frame whose `MSG_ID` is `HEARTBEAT` (`0`).
///
/// Returns `None` for any non-HEARTBEAT frame, for any frame whose
/// magic byte is not recognised (defense-in-depth — the framer
/// guarantees a recognised magic but a future refactor could regress),
/// and for HEARTBEAT frames whose **wire-declared** payload length
/// (the `LEN` byte at offset 1) is below the 6-byte minimum that
/// covers `custom_mode` (4 bytes) + `vehicle_type` + `autopilot`. The
/// minimum-length check uses `LEN`, not the trailing-slice length,
/// because v2 truncates trailing zero bytes on the wire — a sender
/// that legitimately omits `base_mode`, `system_status`, and
/// `mavlink_version` (the spec allows it) would still expose the
/// fields the audit/metrics signal cares about.
///
/// Read-only by construction: takes `&[u8]` and never mutates the
/// frame. The caller (the `Decoder::decode` impl) owns the buffer and
/// hands it back to the framework after this returns.
fn parse_heartbeat_fields(frame: &[u8]) -> Option<(u8, u8, u8, u8)> {
    let first = *frame.first()?;
    let version = MavlinkVersion::from_magic(first)?;

    let (sys_off, comp_off, msgid_off, payload_off) = match version {
        // v1: STX(0) LEN(1) SEQ(2) SYS(3) COMP(4) MSGID(5) PAYLOAD(6+)
        MavlinkVersion::V1 => (3, 4, 5, MAVLINK_V1_HEADER_LEN),
        // v2: STX(0) LEN(1) INCOMPAT(2) COMPAT(3) SEQ(4) SYS(5) COMP(6)
        //     MSGID_LO(7) MSGID_MID(8) MSGID_HI(9) PAYLOAD(10+)
        MavlinkVersion::V2 => (5, 6, 7, MAVLINK_V2_HEADER_LEN),
    };

    // Wire-declared payload length. For v2 a sender can legally
    // truncate trailing zero bytes — the SIEM signal must trust LEN,
    // not the trailing-slice length, because the slice also includes
    // CRC and (for signed v2) the signature trailer.
    let wire_payload_len = *frame.get(1)? as usize;
    if wire_payload_len < HEARTBEAT_PAYLOAD_MIN_LEN {
        return None;
    }

    let msgid = match version {
        MavlinkVersion::V1 => *frame.get(msgid_off)? as u32,
        MavlinkVersion::V2 => {
            let lo = *frame.get(msgid_off)? as u32;
            let mid = *frame.get(msgid_off + 1)? as u32;
            let hi = *frame.get(msgid_off + 2)? as u32;
            lo | (mid << 8) | (hi << 16)
        }
    };
    if msgid != HEARTBEAT_MSG_ID {
        return None;
    }

    // Defense-in-depth: the framer guarantees `frame.len() >= header +
    // wire_payload_len + crc(+sig)`, so these accesses are within
    // bounds. The `?` operators keep the function panic-free even if a
    // future refactor breaks that invariant.
    let payload = frame.get(payload_off..)?;
    let vehicle_type = *payload.get(HEARTBEAT_TYPE_OFFSET)?;
    let autopilot = *payload.get(HEARTBEAT_AUTOPILOT_OFFSET)?;
    let system_id = *frame.get(sys_off)?;
    let component_id = *frame.get(comp_off)?;

    Some((system_id, component_id, autopilot, vehicle_type))
}

/// Encode a prepared MAVLink frame into the outbound buffer.
///
/// The encoder validates only the wire-level framing invariants it can
/// check cheaply: non-empty, recognised magic byte, under the 280-byte
/// cap. Internal field consistency — the `LEN` byte matches the real
/// payload length, the CRC covers the correct slice, the signature is
/// well-formed — is the caller's responsibility. MAVLink frames that
/// originate on the wire are already validated upstream; frames built
/// by application code must use a MAVLink message library.
impl Encoder<BytesMut> for MavlinkFrameCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot encode an empty MAVLink frame",
            ));
        }
        if MavlinkVersion::from_magic(item[0]).is_none() {
            return Err(MavlinkError::InvalidMagic { byte: item[0] }.into());
        }
        if item.len() > MAX_MAVLINK_FRAME_SIZE {
            return Err(MavlinkError::FrameTooLarge {
                size: item.len(),
                max: MAX_MAVLINK_FRAME_SIZE,
            }
            .into());
        }
        dst.reserve(item.len());
        dst.extend_from_slice(&item);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::sync::Arc;

    use bytes::BufMut;

    use super::*;

    /// Permissive codec for state-machine tests that exercise the
    /// framing logic without caring about signing policy. Using this
    /// helper keeps the test bodies readable — tests that DO care about
    /// policy construct the codec inline with the relevant builders.
    fn permissive_codec() -> MavlinkFrameCodec {
        MavlinkFrameCodec::new()
            .with_allow_v1(true)
            .with_require_signing(false)
    }

    /// Build a valid v1 frame with a `LEN`-byte payload filled with a
    /// single repeating byte. CRC bytes are zeroed — the framer does not
    /// verify them.
    fn v1_frame(len: u8, payload_byte: u8) -> BytesMut {
        let mut buf =
            BytesMut::with_capacity(MAVLINK_V1_HEADER_LEN + len as usize + MAVLINK_CRC_LEN);
        buf.put_u8(MAVLINK_V1_MAGIC);
        buf.put_u8(len);
        buf.put_u8(0); // seq
        buf.put_u8(1); // sysid
        buf.put_u8(2); // compid
        buf.put_u8(0); // msgid
        for _ in 0..len {
            buf.put_u8(payload_byte);
        }
        buf.put_u16_le(0); // crc (not verified here)
        buf
    }

    /// Build a valid v2 frame (signed if `signed` is true) with a
    /// `LEN`-byte payload of `payload_byte` repeated.
    fn v2_frame(len: u8, signed: bool, payload_byte: u8) -> BytesMut {
        let sig_len = if signed { MAVLINK_SIGNATURE_LEN } else { 0 };
        let total = MAVLINK_V2_HEADER_LEN + len as usize + MAVLINK_CRC_LEN + sig_len;
        let mut buf = BytesMut::with_capacity(total);
        buf.put_u8(MAVLINK_V2_MAGIC);
        buf.put_u8(len);
        buf.put_u8(if signed { MAVLINK_IFLAG_SIGNED } else { 0 }); // incompat
        buf.put_u8(0); // compat
        buf.put_u8(0); // seq
        buf.put_u8(1); // sysid
        buf.put_u8(2); // compid
        buf.put_u8(0); // msgid lo
        buf.put_u8(0); // msgid mid
        buf.put_u8(0); // msgid hi
        for _ in 0..len {
            buf.put_u8(payload_byte);
        }
        buf.put_u16_le(0); // crc
        if signed {
            for _ in 0..MAVLINK_SIGNATURE_LEN {
                buf.put_u8(0);
            }
        }
        buf
    }

    #[test]
    fn version_from_magic() {
        assert_eq!(MavlinkVersion::from_magic(0xFE), Some(MavlinkVersion::V1));
        assert_eq!(MavlinkVersion::from_magic(0xFD), Some(MavlinkVersion::V2));
        assert_eq!(MavlinkVersion::from_magic(0x00), None);
        assert_eq!(MavlinkVersion::from_magic(0xBF), None); // TAK protobuf magic
    }

    #[test]
    fn decode_v1_frame_round_trip() {
        let mut codec = permissive_codec();
        let frame = v1_frame(10, 0xAB);
        let mut buf = frame.clone();
        let decoded = codec.decode(&mut buf).unwrap().expect("frame");
        assert_eq!(decoded, frame);
        assert_eq!(decoded.len(), MAVLINK_V1_HEADER_LEN + 10 + MAVLINK_CRC_LEN);
        assert_eq!(decoded[0], MAVLINK_V1_MAGIC);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_v2_unsigned_frame_round_trip() {
        let mut codec = MavlinkFrameCodec::new().with_require_signing(false);
        let frame = v2_frame(20, false, 0xCD);
        let mut buf = frame.clone();
        let decoded = codec.decode(&mut buf).unwrap().expect("frame");
        assert_eq!(decoded, frame);
        assert_eq!(decoded.len(), MAVLINK_V2_HEADER_LEN + 20 + MAVLINK_CRC_LEN);
    }

    #[test]
    fn decode_v2_signed_frame_includes_signature() {
        let mut codec = MavlinkFrameCodec::new();
        let frame = v2_frame(5, true, 0xEF);
        let mut buf = frame.clone();
        let decoded = codec.decode(&mut buf).unwrap().expect("frame");
        assert_eq!(
            decoded.len(),
            MAVLINK_V2_HEADER_LEN + 5 + MAVLINK_CRC_LEN + MAVLINK_SIGNATURE_LEN
        );
        assert_eq!(decoded[0], MAVLINK_V2_MAGIC);
        // Last 13 bytes are the signature section (zeroed in this
        // synthetic frame); just confirm the framer included them.
        let sig_start = decoded.len() - MAVLINK_SIGNATURE_LEN;
        assert!(decoded[sig_start..].iter().all(|&b| b == 0));
    }

    #[test]
    fn decode_max_size_v2_signed_frame() {
        // 10 + 255 + 2 + 13 = 280 — the hard cap.
        let mut codec = MavlinkFrameCodec::new();
        let frame = v2_frame(u8::MAX, true, 0x42);
        assert_eq!(frame.len(), MAX_MAVLINK_FRAME_SIZE);
        let mut buf = frame.clone();
        let decoded = codec.decode(&mut buf).unwrap().expect("frame");
        assert_eq!(decoded.len(), MAX_MAVLINK_FRAME_SIZE);
    }

    #[test]
    fn decode_partial_header_returns_none() {
        // `permissive_codec` here because strict defaults reject v1 at
        // the magic byte before even looking at LEN — we want to cover
        // the "need more bytes" branch, not the policy branch.
        let mut codec = permissive_codec();
        // Magic byte only — no LEN yet.
        let mut buf = BytesMut::from(&[MAVLINK_V1_MAGIC][..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_partial_v2_header_returns_none_waiting_for_incompat() {
        // Signing policy cannot be evaluated until the INCOMPAT byte
        // arrives, so the decoder must wait rather than reject
        // optimistically. Even with the strict default (signing
        // required), a partial v2 header must return `None`, not an
        // error.
        let mut codec = MavlinkFrameCodec::new();
        // Magic + LEN but no INCOMPAT byte — we can't determine signed vs unsigned.
        let mut buf = BytesMut::from(&[MAVLINK_V2_MAGIC, 10][..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_partial_payload_returns_none_then_completes() {
        let mut codec = permissive_codec();
        let frame = v1_frame(16, 0xBB);

        // Feed the first half, expect None.
        let half = frame.len() / 2;
        let mut buf = BytesMut::from(&frame[..half]);
        assert!(codec.decode(&mut buf).unwrap().is_none());

        // Feed the rest, expect the full frame.
        buf.extend_from_slice(&frame[half..]);
        let decoded = codec.decode(&mut buf).unwrap().expect("frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn decode_resyncs_past_garbage_bytes() {
        let mut codec = permissive_codec();
        let frame = v1_frame(4, 0xFF);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]); // garbage prefix
        buf.extend_from_slice(&frame);
        let decoded = codec.decode(&mut buf).unwrap().expect("frame");
        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_resyncs_between_v1_and_v2_frames() {
        // Deliver two frames with junk between them; both should be
        // recovered on consecutive decode() calls.
        let mut codec = permissive_codec();
        let f1 = v1_frame(3, 0x11);
        let f2 = v2_frame(7, false, 0x22);

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // junk between frames
        buf.extend_from_slice(&f2);

        let d1 = codec.decode(&mut buf).unwrap().expect("frame 1");
        assert_eq!(d1, f1);

        let d2 = codec.decode(&mut buf).unwrap().expect("frame 2");
        assert_eq!(d2, f2);

        assert!(buf.is_empty());
    }

    #[test]
    fn decode_rejects_unknown_incompat_flags() {
        let mut codec = MavlinkFrameCodec::new();
        // INCOMPAT = 0x02 — no flag assigned to this bit today.
        let mut buf = BytesMut::from(&[MAVLINK_V2_MAGIC, 0, 0x02][..]);
        let err = codec.decode(&mut buf).expect_err("should reject");
        assert!(err.to_string().contains("INCOMPAT"), "got: {err}");
    }

    #[test]
    fn decode_recovers_after_invalid_incompat_flags() {
        // Regression guard: an earlier revision returned the INCOMPAT
        // error WITHOUT consuming the bad magic byte, so the very next
        // decode() would re-read the same header and loop forever on an
        // attacker-supplied stream. After the fix, the bad magic byte
        // must be consumed and a following valid frame must decode.
        // Uses the permissive codec so the follow-on v1 frame is
        // accepted — the invariant under test is the state-machine
        // recovery, not signing policy.
        let mut codec = permissive_codec();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[MAVLINK_V2_MAGIC, 0, 0x02]); // bad INCOMPAT
        let follow = v1_frame(3, 0x55);
        buf.extend_from_slice(&follow);

        let err = codec.decode(&mut buf).expect_err("first decode rejects");
        assert!(err.to_string().contains("INCOMPAT"), "got: {err}");
        // No buffered header remains: the next decode starts fresh.
        assert!(codec.pending_total_len.is_none());

        let decoded = codec
            .decode(&mut buf)
            .unwrap()
            .expect("follow-on frame decodes");
        assert_eq!(decoded, follow);
        assert!(buf.is_empty());
    }

    #[test]
    fn max_frame_size_matches_spec() {
        // Invariant guard: MAVLink v2 hard cap is 280 bytes (10 header
        // + 255 payload + 2 CRC + 13 signature). If this test breaks,
        // either the MAVLink spec changed or one of the layout
        // constants was edited incorrectly — both cases require
        // deliberate review of every consumer of MAX_MAVLINK_FRAME_SIZE.
        assert_eq!(MAX_MAVLINK_FRAME_SIZE, 280);
    }

    #[test]
    fn decode_preserves_frame_order_across_multiple_reads() {
        // Three frames arrive in one buffer; consecutive decode() calls
        // must return them in order without losing or duplicating any.
        let mut codec = permissive_codec();
        let frames = [
            v1_frame(2, 0x01),
            v2_frame(4, false, 0x02),
            v2_frame(8, true, 0x03),
        ];

        let mut buf = BytesMut::new();
        for f in &frames {
            buf.extend_from_slice(f);
        }

        for (i, expected) in frames.iter().enumerate() {
            let got = codec
                .decode(&mut buf)
                .unwrap()
                .unwrap_or_else(|| panic!("frame {i} missing"));
            assert_eq!(&got, expected, "frame {i} mismatch");
        }

        assert!(buf.is_empty());
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn encode_passthrough_preserves_bytes() {
        let mut codec = MavlinkFrameCodec::new();
        let frame = v2_frame(5, true, 0x77);
        let mut dst = BytesMut::new();
        codec.encode(frame.clone(), &mut dst).unwrap();
        assert_eq!(dst, frame);
    }

    #[test]
    fn encode_rejects_empty_frame() {
        let mut codec = MavlinkFrameCodec::new();
        let mut dst = BytesMut::new();
        let err = codec.encode(BytesMut::new(), &mut dst).expect_err("empty");
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn encode_rejects_bad_magic() {
        let mut codec = MavlinkFrameCodec::new();
        let mut dst = BytesMut::new();
        let bad = BytesMut::from(&[0x00, 0x01, 0x02][..]);
        let err = codec.encode(bad, &mut dst).expect_err("bad magic");
        assert!(err.to_string().contains("magic"), "got: {err}");
    }

    #[test]
    fn codec_state_resets_after_each_frame() {
        let mut codec = permissive_codec();
        let frame = v1_frame(3, 0xDE);

        // Decode once — pending_total_len should reset.
        let mut buf = frame.clone();
        let _ = codec.decode(&mut buf).unwrap().expect("frame");
        assert!(codec.pending_total_len.is_none());

        // Decode again — should parse a fresh frame cleanly.
        let mut buf2 = frame.clone();
        let decoded = codec.decode(&mut buf2).unwrap().expect("frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn decode_empty_buffer_returns_none() {
        let mut codec = MavlinkFrameCodec::new();
        let mut buf = BytesMut::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_all_garbage_drains_buffer_and_returns_none() {
        // No magic bytes at all — the resync loop should drain the
        // buffer without producing a frame or an error.
        let mut codec = MavlinkFrameCodec::new();
        let mut buf = BytesMut::from(&[0x00, 0x01, 0x02, 0x03, 0x04][..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert!(buf.is_empty());
    }

    // ─── Signing policy ──────────────────────────────────────────────

    #[test]
    fn default_codec_requires_signing_and_rejects_v1() {
        let codec = MavlinkFrameCodec::new();
        assert!(codec.requires_signing(), "secure default: require signing");
        assert!(!codec.allows_v1(), "secure default: reject v1");
    }

    #[test]
    fn strict_codec_rejects_v1_frame() {
        // Default (strict) codec: v1 frame with valid magic must be
        // rejected before payload is buffered.
        let mut codec = MavlinkFrameCodec::new();
        let frame = v1_frame(4, 0xAA);
        let mut buf = frame.clone();
        let err = codec.decode(&mut buf).expect_err("v1 must reject");
        assert!(
            err.to_string().contains("v1 frame rejected"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn strict_codec_rejects_v1_and_recovers_on_following_v2_signed_frame() {
        // A v1 frame arriving first must be rejected, but a following
        // signed v2 frame (the only wire form the strict codec accepts)
        // must decode cleanly afterward. This protects against an
        // attacker forcing the session layer to close by prepending a
        // single v1 header — rejection consumes only the offending
        // magic byte, not the payload bytes that follow.
        let mut codec = MavlinkFrameCodec::new();
        let mut buf = BytesMut::new();
        // Start with a plausible v1 magic byte.
        buf.extend_from_slice(&[MAVLINK_V1_MAGIC]);
        // Append a fully signed v2 frame right after.
        let signed = v2_frame(3, true, 0xBB);
        buf.extend_from_slice(&signed);

        let err = codec.decode(&mut buf).expect_err("v1 rejected");
        assert!(err.to_string().contains("v1 frame rejected"), "got: {err}");
        assert!(codec.pending_total_len.is_none());

        let decoded = codec.decode(&mut buf).unwrap().expect("v2 signed decodes");
        assert_eq!(decoded, signed);
        assert!(buf.is_empty());
    }

    #[test]
    fn strict_codec_rejects_unsigned_v2_frame() {
        // `require_signing = true` (the default) must reject an
        // unsigned v2 frame once the INCOMPAT byte confirms the missing
        // signature bit.
        let mut codec = MavlinkFrameCodec::new();
        let frame = v2_frame(10, false, 0xCC);
        let mut buf = frame.clone();
        let err = codec.decode(&mut buf).expect_err("unsigned must reject");
        assert!(
            err.to_string().contains("unsigned frame rejected"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn strict_codec_accepts_signed_v2_frame() {
        // The strict default must still accept the only wire form it
        // considers authentic: v2 with the SIGNED INCOMPAT bit set.
        let mut codec = MavlinkFrameCodec::new();
        let frame = v2_frame(5, true, 0xEE);
        let mut buf = frame.clone();
        let decoded = codec.decode(&mut buf).unwrap().expect("signed v2 decodes");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn unsigned_v2_rejection_consumes_magic_and_recovers_on_next_frame() {
        // Mirror of `decode_recovers_after_invalid_incompat_flags` but
        // for the signing policy: rejecting an unsigned v2 frame must
        // consume only the magic byte so a following valid signed v2
        // frame still decodes. Protects against an attacker stalling
        // the codec by dribbling unsigned-v2 headers.
        let mut codec = MavlinkFrameCodec::new();
        let mut buf = BytesMut::new();
        // Build an unsigned v2 header prefix: magic, LEN=0, INCOMPAT=0.
        buf.extend_from_slice(&[MAVLINK_V2_MAGIC, 0, 0]);
        let signed = v2_frame(3, true, 0x42);
        buf.extend_from_slice(&signed);

        let err = codec.decode(&mut buf).expect_err("unsigned rejected");
        assert!(
            err.to_string().contains("unsigned frame rejected"),
            "got: {err}"
        );
        assert!(codec.pending_total_len.is_none());

        let decoded = codec.decode(&mut buf).unwrap().expect("follow-on");
        assert_eq!(decoded, signed);
        assert!(buf.is_empty());
    }

    #[test]
    fn permissive_builder_accepts_unsigned_v2() {
        // Opt-out path: an operator that explicitly sets
        // `with_require_signing(false)` must be able to receive
        // unsigned v2 frames. Guards against a refactor that
        // accidentally hardcodes the strict check.
        let mut codec = MavlinkFrameCodec::new().with_require_signing(false);
        let frame = v2_frame(2, false, 0x11);
        let mut buf = frame.clone();
        let decoded = codec
            .decode(&mut buf)
            .unwrap()
            .expect("unsigned v2 permitted");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn permissive_builder_accepts_v1() {
        // Opt-out path for v1: explicit allow_v1(true) must re-enable
        // the wire format.
        let mut codec = MavlinkFrameCodec::new().with_allow_v1(true);
        let frame = v1_frame(2, 0x22);
        let mut buf = frame.clone();
        let decoded = codec.decode(&mut buf).unwrap().expect("v1 permitted");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn require_signing_does_not_reject_unrelated_incompat_bits_first() {
        // If INCOMPAT has an unknown bit AND is unsigned, the spec
        // requires the unknown-bit rejection to win: returning
        // UnsignedFrameRejected instead would mislead an operator into
        // thinking a sender just forgot to sign, when in fact the
        // frame's wire format is fundamentally un-parsable. Regression
        // guard that the policy check runs AFTER the mandatory spec
        // check.
        let mut codec = MavlinkFrameCodec::new();
        // INCOMPAT = 0x02 (unknown bit, not SIGNED) — must surface as
        // InvalidIncompatFlags, not UnsignedFrameRejected, even though
        // the strict policy would otherwise reject unsigned v2.
        let mut buf = BytesMut::from(&[MAVLINK_V2_MAGIC, 0, 0x02][..]);
        let err = codec.decode(&mut buf).expect_err("incompat wins");
        assert!(err.to_string().contains("INCOMPAT"), "got: {err}");
    }

    // ─── HEARTBEAT observer ──────────────────────────────────────────

    use std::sync::Mutex;

    /// Captured heartbeat-callback invocations for use in observer
    /// tests. Each tuple is `(system_id, component_id, autopilot,
    /// vehicle_type)` exactly as the observer received it.
    type HeartbeatLog = Arc<Mutex<Vec<(u8, u8, u8, u8)>>>;

    /// Build a valid v1 HEARTBEAT frame with caller-controlled header
    /// and payload fields. CRC bytes are zeroed (the framer does not
    /// verify them). Layout matches `v1_frame` but exposes every byte
    /// the heartbeat-callback test wants to assert on.
    fn v1_heartbeat_frame(
        sys: u8,
        comp: u8,
        msgid: u8,
        autopilot: u8,
        vehicle_type: u8,
        payload_len: u8,
    ) -> BytesMut {
        let mut buf =
            BytesMut::with_capacity(MAVLINK_V1_HEADER_LEN + payload_len as usize + MAVLINK_CRC_LEN);
        buf.put_u8(MAVLINK_V1_MAGIC);
        buf.put_u8(payload_len);
        buf.put_u8(0); // seq
        buf.put_u8(sys);
        buf.put_u8(comp);
        buf.put_u8(msgid);
        // HEARTBEAT payload (after MAVLink size-descending field reorder):
        //   [0..4] custom_mode (u32, zeroed in tests)
        //   [4]    type / vehicle_type
        //   [5]    autopilot
        //   [6]    base_mode (zeroed in tests)
        //   [7]    system_status (zeroed in tests)
        //   [8]    mavlink_version (zeroed in tests)
        for i in 0..payload_len {
            buf.put_u8(match i as usize {
                HEARTBEAT_TYPE_OFFSET => vehicle_type,
                HEARTBEAT_AUTOPILOT_OFFSET => autopilot,
                _ => 0,
            });
        }
        buf.put_u16_le(0); // crc
        buf
    }

    /// Build a valid v2 HEARTBEAT frame with caller-controlled header
    /// + payload fields.
    fn v2_heartbeat_frame(
        sys: u8,
        comp: u8,
        msgid: u32,
        signed: bool,
        autopilot: u8,
        vehicle_type: u8,
        payload_len: u8,
    ) -> BytesMut {
        let sig_len = if signed { MAVLINK_SIGNATURE_LEN } else { 0 };
        let total = MAVLINK_V2_HEADER_LEN + payload_len as usize + MAVLINK_CRC_LEN + sig_len;
        let mut buf = BytesMut::with_capacity(total);
        buf.put_u8(MAVLINK_V2_MAGIC);
        buf.put_u8(payload_len);
        buf.put_u8(if signed { MAVLINK_IFLAG_SIGNED } else { 0 }); // incompat
        buf.put_u8(0); // compat
        buf.put_u8(0); // seq
        buf.put_u8(sys);
        buf.put_u8(comp);
        buf.put_u8((msgid & 0xFF) as u8); // msgid lo
        buf.put_u8(((msgid >> 8) & 0xFF) as u8); // msgid mid
        buf.put_u8(((msgid >> 16) & 0xFF) as u8); // msgid hi
        for i in 0..payload_len {
            buf.put_u8(match i as usize {
                HEARTBEAT_TYPE_OFFSET => vehicle_type,
                HEARTBEAT_AUTOPILOT_OFFSET => autopilot,
                _ => 0,
            });
        }
        buf.put_u16_le(0); // crc
        if signed {
            for _ in 0..MAVLINK_SIGNATURE_LEN {
                buf.put_u8(0);
            }
        }
        buf
    }

    /// Capture handle for tests that drive the HEARTBEAT observer —
    /// keeps the boilerplate of building an `Arc<Mutex<Vec<...>>>`
    /// plus observer closure off every test body.
    fn capture_observer() -> (OnMavlinkHeartbeat, HeartbeatLog) {
        let log: HeartbeatLog = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);
        let cb: OnMavlinkHeartbeat = Arc::new(move |sys, comp, ap, vt| {
            log_clone
                .lock()
                .expect("observer mutex must not poison")
                .push((sys, comp, ap, vt));
        });
        (cb, log)
    }

    #[test]
    fn default_codec_has_no_heartbeat_observer() {
        let codec = MavlinkFrameCodec::new();
        assert!(
            !codec.has_heartbeat_observer(),
            "secure default must not install a callback"
        );
    }

    #[test]
    fn with_on_heartbeat_installs_observer() {
        // Pin the builder semantics — `with_on_heartbeat(cb)` must
        // toggle the observer flag without changing other policy
        // defaults (signing required, v1 rejected).
        let (cb, _log) = capture_observer();
        let codec = MavlinkFrameCodec::new().with_on_heartbeat(cb);
        assert!(codec.has_heartbeat_observer());
        assert!(codec.requires_signing(), "policy defaults preserved");
        assert!(!codec.allows_v1(), "policy defaults preserved");
    }

    #[test]
    fn heartbeat_msg_id_zero_invokes_callback() {
        // Feed a synthetic v2 signed HEARTBEAT and assert the observer
        // sees the four expected u8 fields. system_id=42 (typical
        // tactical drone), component_id=1 (MAV_COMP_ID_AUTOPILOT1),
        // autopilot=12 (MAV_AUTOPILOT_ARDUPILOTMEGA), vehicle_type=2
        // (MAV_TYPE_QUADROTOR) — the values the audit-log test in
        // `rustgate-core` mirrors.
        let (cb, log) = capture_observer();
        let mut codec = MavlinkFrameCodec::new().with_on_heartbeat(cb);
        let frame = v2_heartbeat_frame(42, 1, HEARTBEAT_MSG_ID, true, 12, 2, 9);
        let mut buf = frame.clone();
        let decoded = codec.decode(&mut buf).unwrap().expect("frame decoded");
        assert_eq!(decoded, frame, "callback must not corrupt the frame");
        let captured = log.lock().unwrap().clone();
        assert_eq!(captured, vec![(42, 1, 12, 2)]);
    }

    #[test]
    fn heartbeat_v1_invokes_callback_with_header_fields() {
        // v1's header layout differs from v2 (sysid offset 3 vs 5) —
        // exercise both so a future refactor that conflates the two
        // versions fails here. Use the permissive codec since the
        // strict default rejects v1 outright.
        let (cb, log) = capture_observer();
        let mut codec = MavlinkFrameCodec::new()
            .with_allow_v1(true)
            .with_require_signing(false)
            .with_on_heartbeat(cb);
        let frame = v1_heartbeat_frame(7, 200, 0, 3, 10, 9);
        let mut buf = frame.clone();
        let _ = codec.decode(&mut buf).unwrap().expect("frame");
        let captured = log.lock().unwrap().clone();
        assert_eq!(captured, vec![(7, 200, 3, 10)]);
    }

    #[test]
    fn non_heartbeat_msg_id_does_not_invoke_callback() {
        // STATUSTEXT (MSG_ID 253) is the canonical "operator log line"
        // message — it shares the same wire frame shape but carries no
        // presence semantics, so the observer must NOT fire on it. The
        // counter is per-aircraft; treating non-HEARTBEAT frames as
        // heartbeats would over-count presence and corrupt fleet
        // dashboards.
        let (cb, log) = capture_observer();
        let mut codec = MavlinkFrameCodec::new().with_on_heartbeat(cb);
        // Use a non-HEARTBEAT MSG_ID — STATUSTEXT (253) is the
        // canonical example, but any non-zero value exercises the
        // negative branch.
        let frame = v2_heartbeat_frame(42, 1, 253, true, 12, 2, 9);
        let mut buf = frame.clone();
        let _ = codec.decode(&mut buf).unwrap().expect("frame decoded");
        assert!(
            log.lock().unwrap().is_empty(),
            "non-HEARTBEAT must not invoke the observer"
        );
    }

    #[test]
    fn malformed_heartbeat_payload_does_not_invoke_callback() {
        // A v2 sender that legally truncates the HEARTBEAT payload
        // below the 6-byte minimum (covering custom_mode + vehicle_type
        // + autopilot) cannot be classified as a presence ping —
        // invoking the callback with synthesised zero values would
        // generate a fake `system_id=0, autopilot=0, type=0` audit
        // event indistinguishable from a bench-test airframe.
        let (cb, log) = capture_observer();
        let mut codec = MavlinkFrameCodec::new().with_on_heartbeat(cb);
        // Truncated payload: LEN = 4 (custom_mode only — no
        // vehicle_type, no autopilot).
        let frame = v2_heartbeat_frame(42, 1, HEARTBEAT_MSG_ID, true, 12, 2, 4);
        let mut buf = frame.clone();
        let _ = codec.decode(&mut buf).unwrap().expect("frame decoded");
        assert!(
            log.lock().unwrap().is_empty(),
            "truncated HEARTBEAT must not invoke the observer"
        );
    }

    #[test]
    fn heartbeat_observer_not_invoked_when_unset() {
        // No observer installed — decode must complete successfully
        // and produce no callback invocations. Pins the cost-free
        // contract: the `Option<...>::is_some()` gate keeps the no-
        // observer path identical to the pre-#909 hot path.
        let mut codec = MavlinkFrameCodec::new();
        let frame = v2_heartbeat_frame(42, 1, HEARTBEAT_MSG_ID, true, 12, 2, 9);
        let mut buf = frame.clone();
        let decoded = codec.decode(&mut buf).unwrap().expect("frame decoded");
        assert_eq!(decoded, frame);
        // No log to assert against — the test exercises the no-
        // observer hot path by virtue of completing without panicking.
    }

    #[test]
    fn heartbeat_observer_invoked_per_frame_in_burst() {
        // Three HEARTBEATs back-to-back must produce three observer
        // invocations in the order they arrived. Defends against a
        // refactor that batches frames internally and only fires the
        // observer for the first or last in the batch.
        let (cb, log) = capture_observer();
        let mut codec = MavlinkFrameCodec::new().with_on_heartbeat(cb);

        let f1 = v2_heartbeat_frame(1, 1, HEARTBEAT_MSG_ID, true, 12, 2, 9);
        let f2 = v2_heartbeat_frame(2, 1, HEARTBEAT_MSG_ID, true, 3, 10, 9);
        let f3 = v2_heartbeat_frame(3, 1, HEARTBEAT_MSG_ID, true, 8, 14, 9);

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&f2);
        buf.extend_from_slice(&f3);

        for _ in 0..3 {
            let _ = codec.decode(&mut buf).unwrap().expect("frame");
        }

        let captured = log.lock().unwrap().clone();
        assert_eq!(captured, vec![(1, 1, 12, 2), (2, 1, 3, 10), (3, 1, 8, 14),]);
    }

    #[test]
    fn parse_heartbeat_fields_returns_none_for_short_frame() {
        // Direct unit test on the helper — `frame.first()` returning
        // None must short-circuit cleanly. Defends against a refactor
        // that indexes `frame[0]` without bounds-checking.
        assert!(parse_heartbeat_fields(&[]).is_none());
        assert!(parse_heartbeat_fields(&[0xFE]).is_none());
    }

    #[test]
    fn parse_heartbeat_fields_returns_none_for_unknown_magic() {
        // Defense-in-depth: even though the framer guarantees a
        // recognised magic byte, the helper must not panic on a frame
        // whose magic byte is neither 0xFE nor 0xFD.
        let mut buf = BytesMut::from(&[0xAB, 9, 0, 0, 0, 0, 0, 0, 0, 0][..]);
        // Pad out to a plausible length so the test isn't actually
        // hitting the short-frame branch.
        for _ in 0..10 {
            buf.put_u8(0);
        }
        assert!(parse_heartbeat_fields(&buf).is_none());
    }

    // ─── F-72 / F-73 spec mirror tests ───────────────────────────────
    //
    // These tests mirror the exact names called out in the issue #752
    // implementation plan so a reviewer scanning the spec can locate
    // each one with one grep. They overlap intentionally with the
    // earlier "strict_codec_*" tests above (which name the *behaviour*)
    // — the spec mirrors name the *requirement* and serve as the
    // canonical regression set going forward.

    #[test]
    fn v1_frame_rejected_by_default() {
        // F-72: the default codec rejects v1 outright.
        let mut codec = MavlinkFrameCodec::new();
        let frame = v1_frame(4, 0xAA);
        let mut buf = frame.clone();
        let err = codec.decode(&mut buf).expect_err("v1 must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let mav = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<MavlinkError>())
            .expect("typed MavlinkError preserved");
        assert!(matches!(mav, MavlinkError::V1FrameRejected));
    }

    #[test]
    fn v1_frame_accepted_with_allow_v1_opt_in() {
        // F-72: explicit operator opt-in re-enables v1.
        let mut codec = MavlinkFrameCodec::new()
            .with_allow_v1(true)
            .with_require_signing(false);
        let frame = v1_frame(4, 0xBB);
        let mut buf = frame.clone();
        let decoded = codec
            .decode(&mut buf)
            .expect("opt-in path is panic-free")
            .expect("frame decodes");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn v2_unsigned_frame_rejected_by_default() {
        // F-72: the default codec rejects unsigned v2.
        let mut codec = MavlinkFrameCodec::new();
        let frame = v2_frame(8, false, 0xCC);
        let mut buf = frame.clone();
        let err = codec.decode(&mut buf).expect_err("unsigned v2 rejected");
        let mav = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<MavlinkError>())
            .expect("typed MavlinkError preserved");
        assert!(matches!(mav, MavlinkError::UnsignedFrameRejected));
    }

    #[test]
    fn v2_unsigned_frame_accepted_with_require_signing_false() {
        // F-72: operator opt-out for legacy (signed-not-available) deployments.
        let mut codec = MavlinkFrameCodec::new().with_require_signing(false);
        let frame = v2_frame(8, false, 0xDD);
        let mut buf = frame.clone();
        let decoded = codec
            .decode(&mut buf)
            .expect("opt-out is panic-free")
            .expect("frame decodes");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn unknown_msg_id_rejected_without_panic() {
        // F-73: an attacker-supplied MSG_ID that is not in the
        // CRC-EXTRA lookup table must surface as a typed
        // `UnknownMessageId` error WITHOUT panicking and WITHOUT
        // allocating per frame. We use a deliberately-far MSG_ID
        // (1_000_000) outside any common dialect catalogue. The frame
        // is a valid signed v2 in every other respect — only the
        // MSG_ID is non-standard — so we test that the CRC-EXTRA gate
        // fires AFTER the framing/policy gates.
        let mut codec = MavlinkFrameCodec::new();
        let frame = v2_heartbeat_frame(42, 1, 1_000_000, true, 12, 2, 9);
        let mut buf = frame.clone();
        let err = codec
            .decode(&mut buf)
            .expect_err("unknown MSG_ID must surface");
        let mav = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<MavlinkError>())
            .expect("typed MavlinkError preserved");
        match mav {
            MavlinkError::UnknownMessageId { id } => {
                assert_eq!(
                    *id, 1_000_000,
                    "id field must echo back the offending value"
                )
            }
            other => panic!("expected UnknownMessageId, got {other:?}"),
        }
        // Buffer was fully consumed: rejection here happens AFTER the
        // frame is split out of `src` so the next decode is a clean
        // start, not a stuck mid-frame state.
        assert!(buf.is_empty());
        assert!(codec.pending_total_len.is_none());
    }

    #[test]
    fn unknown_msg_id_rejection_burst_does_not_panic_on_release() {
        // F-73 stress test: streaming many frames with random unknown
        // MSG_IDs must not drive a panic on any iteration. Pins the
        // "no per-frame allocation, no panic" contract under sustained
        // attacker input.
        let mut codec = MavlinkFrameCodec::new();
        for id in [99_999u32, 1_234_567, 0x00FF_FFFE, 0x00BA_DBAD] {
            let frame = v2_heartbeat_frame(1, 1, id, true, 0, 0, 9);
            let mut buf = frame.clone();
            let err = codec.decode(&mut buf).expect_err("unknown MSG_ID rejected");
            let mav = err
                .get_ref()
                .and_then(|e| e.downcast_ref::<MavlinkError>())
                .expect("typed MavlinkError preserved");
            assert!(matches!(mav, MavlinkError::UnknownMessageId { .. }));
        }
    }

    #[test]
    fn mavlink_unsigned_rejected_audit_event_fires_on_v1() {
        // F-72 wiring: a v1 frame on the strict codec must invoke the
        // rejection observer with `RejectionReason::V1NotAllowed`. The
        // listener wires this observer to call
        // `rustgate_core::audit::mavlink_v1_rejected` (and would
        // similarly call `mavlink_unsigned_rejected` on a
        // `RejectionReason::UnsignedV2`); here we observe via a shared
        // `Arc<Mutex<Vec<...>>>` to pin the wiring contract without
        // needing the listener crate to exist yet.
        let log: Arc<Mutex<Vec<RejectionReason>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);
        let cb: OnMavlinkRejection = Arc::new(move |reason| {
            log_clone
                .lock()
                .expect("rejection observer mutex must not poison")
                .push(reason);
        });
        let mut codec = MavlinkFrameCodec::new().with_on_rejection(cb);
        let frame = v1_frame(4, 0xAA);
        let mut buf = frame.clone();
        let _ = codec.decode(&mut buf).expect_err("v1 rejected");
        assert_eq!(
            log.lock().unwrap().clone(),
            vec![RejectionReason::V1NotAllowed]
        );
    }

    #[test]
    fn rejection_observer_fires_for_unsigned_v2() {
        // F-72 wiring (other half of the F-72/F-73 pair): a v2
        // unsigned frame on the strict codec invokes the observer with
        // `RejectionReason::UnsignedV2`. Without this test, a refactor
        // that wired only the V1 reason and forgot the unsigned-v2
        // reason would silently make the audit signal incomplete.
        let log: Arc<Mutex<Vec<RejectionReason>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);
        let cb: OnMavlinkRejection = Arc::new(move |reason| {
            log_clone.lock().unwrap().push(reason);
        });
        let mut codec = MavlinkFrameCodec::new().with_on_rejection(cb);
        let frame = v2_frame(4, false, 0xEE);
        let mut buf = frame.clone();
        let _ = codec.decode(&mut buf).expect_err("unsigned v2 rejected");
        assert_eq!(
            log.lock().unwrap().clone(),
            vec![RejectionReason::UnsignedV2]
        );
    }

    #[test]
    fn rejection_observer_fires_for_unknown_msg_id() {
        // F-73 wiring: unknown MSG_ID rejection must invoke the
        // observer with `RejectionReason::UnknownMessageId(id)`
        // carrying the offending ID so a SIEM can detect dialect
        // mismatch attempts (operational signal: "is the upstream
        // sending random IDs to fish for the panic gadget?").
        let log: Arc<Mutex<Vec<RejectionReason>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);
        let cb: OnMavlinkRejection = Arc::new(move |reason| {
            log_clone.lock().unwrap().push(reason);
        });
        let mut codec = MavlinkFrameCodec::new().with_on_rejection(cb);
        let frame = v2_heartbeat_frame(1, 1, 99_999, true, 0, 0, 9);
        let mut buf = frame.clone();
        let _ = codec.decode(&mut buf).expect_err("unknown MSG_ID rejected");
        assert_eq!(
            log.lock().unwrap().clone(),
            vec![RejectionReason::UnknownMessageId(99_999)]
        );
    }

    #[test]
    fn rejection_observer_quiet_on_clean_decode() {
        // Negative pin: a frame that decodes cleanly does NOT invoke
        // the rejection observer. Without this test, a refactor that
        // accidentally fired the observer on every frame would silently
        // flood a SIEM with false-positive rejection events.
        let log: Arc<Mutex<Vec<RejectionReason>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);
        let cb: OnMavlinkRejection = Arc::new(move |reason| {
            log_clone.lock().unwrap().push(reason);
        });
        let mut codec = MavlinkFrameCodec::new().with_on_rejection(cb);
        // Signed v2 HEARTBEAT — passes every gate.
        let frame = v2_heartbeat_frame(42, 1, HEARTBEAT_MSG_ID, true, 12, 2, 9);
        let mut buf = frame.clone();
        let _ = codec.decode(&mut buf).unwrap().expect("clean decode");
        assert!(
            log.lock().unwrap().is_empty(),
            "clean decode must NOT invoke the rejection observer"
        );
    }

    #[test]
    fn parse_msg_id_handles_unknown_magic() {
        // Defense-in-depth: the framer should never hand `parse_msg_id`
        // a non-MAVLink magic, but a future refactor might. Pin the
        // return-`None` contract.
        assert_eq!(parse_msg_id(&[]), None);
        assert_eq!(parse_msg_id(&[0xAB, 0, 0, 0, 0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn parse_msg_id_v1_extracts_byte_5() {
        // v1 layout: STX(0) LEN(1) SEQ(2) SYS(3) COMP(4) MSGID(5)
        // MSGID lives at offset 5 — pinning prevents an off-by-one
        // refactor from silently corrupting the CRC-EXTRA lookup key.
        let frame = [MAVLINK_V1_MAGIC, 1, 0, 0, 0, 76, 0, 0, 0]; // msgid=76
        assert_eq!(parse_msg_id(&frame), Some(76));
    }

    #[test]
    fn parse_msg_id_v2_extracts_24_bit_little_endian() {
        // v2 layout: STX(0) LEN(1) INCOMPAT(2) COMPAT(3) SEQ(4) SYS(5)
        //            COMP(6) MSGID_LO(7) MSGID_MID(8) MSGID_HI(9)
        // 0x123456 little-endian = [0x56, 0x34, 0x12].
        let frame = [MAVLINK_V2_MAGIC, 1, 0, 0, 0, 0, 0, 0x56, 0x34, 0x12, 0];
        assert_eq!(parse_msg_id(&frame), Some(0x123456));
    }
}
