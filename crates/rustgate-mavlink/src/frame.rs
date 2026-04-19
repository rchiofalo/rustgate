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
#[derive(Debug)]
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
}

impl Default for MavlinkFrameCodec {
    fn default() -> Self {
        Self {
            pending_total_len: None,
            // Secure default: require signatures, reject v1 entirely.
            // Operators opt back in explicitly.
            require_signing: true,
            allow_v1: false,
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
                    return Err(MavlinkError::V1FrameRejected);
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
                    return Err(MavlinkError::UnsignedFrameRejected);
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
        Ok(Some(src.split_to(total)))
    }
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
}
