// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-deployment stream framing for STANAG 4586 (feature `stream`).
//!
//! STANAG 4586 frames are message-type-dependent in size and carry no
//! universally-agreed, self-describing length prefix at a fixed offset —
//! the Edition 2 message wrapper that would let a generic parser find the
//! body length is defined in the **NATO-restricted** specification, which
//! is not distributable and is not present in this repository. A generic
//! stream delimiter therefore cannot be shipped by guessing the wire
//! layout: a wrong guess on an unauthenticated, unencrypted TCP port is
//! the parser-differential class of defect that ADR 0023 D2/D3 forbid,
//! and it is exactly the length-collision the tracking issue (#1492)
//! reports — a shorter message body whose leading bytes alias a longer
//! frame.
//!
//! This module resolves that fork the honest way, per
//! [`docs/design/stanag4586-stream-framing.md`](../../../../docs/design/stanag4586-stream-framing.md):
//! frame delimitation is driven by a per-deployment [`StreamProfile`] the
//! operator supplies from their own controlled Interface Control Document
//! (ICD), **not** guessed from the wire. Without a profile the decoder
//! fails closed with [`Stanag4586StreamError::ProfileRequired`] — it
//! consumes no bytes and attempts no parse.
//!
//! # What this is and is not
//!
//! - It **is** a fail-closed delimiter that reproduces the *exact bounded
//!   semantics* of the already-hardened
//!   `rustgate_transport::HeaderLengthCodec` (bound the body length against
//!   `MAX_FRAME_SIZE` *before* reserving any buffer, per ADR 0023 D5;
//!   require the length field to fit inside the header; split header +
//!   body) — reproduced rather than depended-on so a leaf codec crate does
//!   not pull in `rustgate-transport`, and extended only by a `big_endian`
//!   flag because that codec is big-endian only. Each delimited frame is
//!   handed to the crate's existing per-message decode path
//!   ([`Stanag4586EntityCodec`]) — the *same* codec the router uses, so
//!   there is no parser differential (ADR 0023 D2).
//! - It **is not** server wiring. Nothing here binds a socket or reaches
//!   `tactical_ingress.rs`; there is no `start_stanag4586_tcp`. The whole
//!   module is gated behind the `stream` cargo feature and is inert until
//!   an operator supplies and validates a profile against a real device.
//!   Stream STANAG 4586 is *not* "done" — see the design note.

use bytes::BytesMut;
use rustgate_core::constants::MAX_FRAME_SIZE;
use rustgate_core::entity::{Entity, EntityCodec};

use crate::entity::{Stanag4586EntityCodec, Stanag4586EntityError};

/// Width of the embedded length field within the framing header.
///
/// A separate, self-describing enum (rather than reusing
/// [`rustgate_core::protocol::HeaderSize`] directly on the public surface)
/// so a `StreamProfile` an operator writes reads as configuration
/// (`One`/`Two`/`Four` bytes) without pulling the transport crate's
/// framing vocabulary into a STANAG-specific config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthFieldSize {
    /// 1-byte length field (body up to 255 bytes).
    One,
    /// 2-byte length field (body up to 65 535 bytes).
    Two,
    /// 4-byte length field (body up to `u32::MAX`, still clamped by
    /// [`StreamProfile::max_frame_size`]).
    Four,
}

impl LengthFieldSize {
    /// Number of bytes the length field occupies within the header.
    #[must_use]
    pub const fn byte_count(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}

/// Per-deployment framing parameters for a STANAG 4586 TCP stream.
///
/// An operator supplies these from their controlled ICD; the crate never
/// guesses them. The four delimitation parameters mirror exactly what
/// [`rustgate_transport::HeaderLengthCodec`] consumes — the profile is the
/// config surface for that delimiter, not a second framing implementation.
///
/// Construct with [`StreamProfile::new`] (the delimitation parameters) and
/// tighten the frame cap with [`StreamProfile::with_max_frame_size`]. The
/// constructor is intentionally infallible; a self-inconsistent profile (a
/// length field that does not fit inside the header) is surfaced as a typed
/// [`Stanag4586StreamError::InvalidProfile`] on first use rather than
/// panicking, mirroring how `HeaderLengthCodec` reports a misconfigured
/// offset as `InvalidData` at decode time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamProfile {
    /// Total header bytes preceding the frame body.
    header_len: usize,
    /// Byte offset of the length field within the header.
    length_field_offset: usize,
    /// Width of the length field.
    length_field_size: LengthFieldSize,
    /// Whether the length field is big-endian (NATO's standard byte order)
    /// or little-endian (some vendor ICDs).
    big_endian: bool,
    /// Upper bound on a decoded frame body, clamped to [`MAX_FRAME_SIZE`].
    max_frame_size: usize,
}

impl StreamProfile {
    /// Build a profile from the ICD-supplied delimitation parameters.
    ///
    /// `header_len` is the total header size in bytes; `length_field_offset`
    /// is the byte offset of the length field within that header;
    /// `length_field_size` is its width; `big_endian` selects the length
    /// field's byte order. The frame cap defaults to [`MAX_FRAME_SIZE`];
    /// tighten it with [`StreamProfile::with_max_frame_size`].
    #[must_use]
    pub const fn new(
        header_len: usize,
        length_field_offset: usize,
        length_field_size: LengthFieldSize,
        big_endian: bool,
    ) -> Self {
        Self {
            header_len,
            length_field_offset,
            length_field_size,
            big_endian,
            max_frame_size: MAX_FRAME_SIZE,
        }
    }

    /// Tighten the per-frame body cap below [`MAX_FRAME_SIZE`]. A value
    /// above the global cap is clamped down to it — the global cap is a
    /// hard ceiling no profile can raise.
    #[must_use]
    pub const fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        // `min` is not const-stable on `usize` for the edition/toolchain
        // pinned here, so branch explicitly to keep the builder `const`.
        self.max_frame_size = if max_frame_size < MAX_FRAME_SIZE {
            max_frame_size
        } else {
            MAX_FRAME_SIZE
        };
        self
    }

    /// The effective per-frame body cap (post-clamp).
    #[must_use]
    pub const fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Validate that the length field lies fully inside the header. Returns
    /// the end offset of the length field on success. Mirrors the bounds
    /// check `HeaderLengthCodec::decode` performs, hoisted so the
    /// fail-closed decoder can reject a self-inconsistent profile before it
    /// ever touches bytes.
    fn validate(&self) -> Result<usize, Stanag4586StreamError> {
        let width = self.length_field_size.byte_count();
        let (end, overflowed) = self.length_field_offset.overflowing_add(width);
        if overflowed || end > self.header_len {
            return Err(Stanag4586StreamError::InvalidProfile {
                header_len: self.header_len,
                length_field_offset: self.length_field_offset,
                length_field_size: width,
            });
        }
        Ok(end)
    }
}

/// Errors surfaced by [`Stanag4586StreamDecoder`].
///
/// A **separate** enum from [`crate::error::Stanag4586Error`] and
/// [`Stanag4586EntityError`] on purpose: the stream-framing failure modes
/// belong to a distinct operational class (a missing deployment profile is
/// an operator-config problem, not a wire-format reject), and keeping them
/// separate means adding [`ProfileRequired`](Self::ProfileRequired) here
/// cannot break an exhaustive match on either existing error surface.
#[derive(Debug, thiserror::Error)]
pub enum Stanag4586StreamError {
    /// No [`StreamProfile`] was configured, so the decoder cannot delimit
    /// the stream. This is the **fail-closed** default: rather than guess a
    /// wire layout that is NATO-restricted and unknowable at compile time,
    /// the decoder consumes no bytes and returns this variant. The operator
    /// must supply a profile from their controlled ICD.
    #[error(
        "STANAG 4586 stream framing requires a per-deployment StreamProfile (spec is NATO-restricted; no layout is guessed)"
    )]
    ProfileRequired,

    /// The configured [`StreamProfile`] is self-inconsistent: the length
    /// field does not fit inside the header. Reported before any byte is
    /// consumed so a misconfiguration fails loudly at startup rather than
    /// silently mis-framing traffic.
    #[error(
        "invalid StreamProfile: length field at offset {length_field_offset} (+{length_field_size} bytes) does not fit in {header_len}-byte header"
    )]
    InvalidProfile {
        /// Total header length from the profile.
        header_len: usize,
        /// Length-field offset from the profile.
        length_field_offset: usize,
        /// Length-field width in bytes.
        length_field_size: usize,
    },

    /// The delimited body length exceeds the profile's frame cap (which is
    /// itself clamped to [`MAX_FRAME_SIZE`]). Rejected **before** any buffer
    /// is reserved so a hostile length field cannot drive an unbounded
    /// allocation (ADR 0023 D5).
    #[error("STANAG 4586 stream frame body too large: {body_len} bytes exceeds limit of {limit}")]
    FrameTooLarge {
        /// Body length read from the framing header.
        body_len: usize,
        /// Effective cap (`min(profile cap, MAX_FRAME_SIZE)`).
        limit: usize,
    },

    /// A delimited frame did not decode to a well-formed [`Entity`] via the
    /// crate's existing per-message codec. The inner variant carries the
    /// [`Stanag4586EntityError`] context (e.g. `UnsupportedMessage` for the
    /// length-collision case) so the ingress audit trail records exactly
    /// what was rejected without re-parsing a display string.
    #[error("STANAG 4586 stream frame decode failed: {0}")]
    Decode(#[from] Stanag4586EntityError),
}

/// Result of a single [`Stanag4586StreamDecoder::decode`] call.
#[derive(Debug)]
pub enum StreamFrame {
    /// A full frame was delimited and decoded to an [`Entity`]. The framing
    /// header and body have been consumed from the input buffer.
    Decoded(Box<Entity>),
    /// Not enough bytes are buffered yet for a full frame. No bytes were
    /// consumed; the caller should read more and retry.
    Incomplete,
}

/// Fail-closed, profile-driven stream delimiter for STANAG 4586.
///
/// Without a [`StreamProfile`] every [`decode`](Self::decode) call returns
/// [`Stanag4586StreamError::ProfileRequired`] and consumes no bytes. With a
/// profile, it delimits one frame at a time (bounding the body against the
/// profile cap before allocating) and hands each frame to
/// [`Stanag4586EntityCodec`].
///
/// Stateless apart from the profile — the delimiter reads only from the
/// caller-owned [`BytesMut`], so one decoder is safe to reuse across a
/// connection's read loop.
#[derive(Debug, Default)]
pub struct Stanag4586StreamDecoder {
    profile: Option<StreamProfile>,
    codec: Stanag4586EntityCodec,
}

impl Stanag4586StreamDecoder {
    /// A decoder with **no** profile. Every [`decode`](Self::decode) call
    /// fails closed with [`Stanag4586StreamError::ProfileRequired`] until a
    /// profile is supplied via [`with_profile`](Self::with_profile). This is
    /// the deliberate default: no profile means no guessed framing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach an operator-supplied [`StreamProfile`], enabling delimitation.
    #[must_use]
    pub fn with_profile(mut self, profile: StreamProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Whether a profile is configured. `false` means every decode fails
    /// closed — useful for a startup readiness check before binding a port.
    #[must_use]
    pub fn has_profile(&self) -> bool {
        self.profile.is_some()
    }

    /// Attempt to delimit and decode exactly one frame from `src`.
    ///
    /// On success the framing header and body are removed from `src` and the
    /// decoded [`Entity`] is returned as [`StreamFrame::Decoded`]. When
    /// fewer than a full frame's bytes are buffered, returns
    /// [`StreamFrame::Incomplete`] without consuming anything. With no
    /// profile configured, returns [`Stanag4586StreamError::ProfileRequired`]
    /// and consumes nothing.
    pub fn decode(&self, src: &mut BytesMut) -> Result<StreamFrame, Stanag4586StreamError> {
        let profile = self.profile.ok_or(Stanag4586StreamError::ProfileRequired)?;
        let _length_field_end = profile.validate()?;

        // Need the whole header before the embedded length field is readable.
        if src.len() < profile.header_len {
            return Ok(StreamFrame::Incomplete);
        }

        let body_len = read_body_length(&src[..profile.header_len], &profile);

        // Bound BEFORE reserving — no attacker-driven allocation (ADR 0023
        // D5). Matches `HeaderLengthCodec`'s own ordering.
        if body_len > profile.max_frame_size {
            return Err(Stanag4586StreamError::FrameTooLarge {
                body_len,
                limit: profile.max_frame_size,
            });
        }

        let total = profile.header_len.saturating_add(body_len);
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(StreamFrame::Incomplete);
        }

        // Split off the full frame (header + body), then decode the body
        // through the crate's existing per-message codec — the *same* codec
        // the router uses, so there is no parser differential (ADR 0023 D2).
        let frame = src.split_to(total);
        let body = &frame[profile.header_len..];
        let entity = self.codec.to_entity(body)?;
        Ok(StreamFrame::Decoded(Box::new(entity)))
    }
}

/// Read the big- or little-endian body length from the framing header.
///
/// The caller has already validated (via [`StreamProfile::validate`]) that
/// the length field lies fully inside `header`, so the fixed-width reads
/// below are in-bounds. The big-endian path is byte-for-byte identical to
/// [`rustgate_transport::HeaderLengthCodec`]; the little-endian path exists
/// only because some vendor ICDs deviate from NATO's standard byte order,
/// and it is expressed as the mirror of the same read.
fn read_body_length(header: &[u8], profile: &StreamProfile) -> usize {
    let o = profile.length_field_offset;
    match (profile.length_field_size, profile.big_endian) {
        (LengthFieldSize::One, _) => header[o] as usize,
        (LengthFieldSize::Two, true) => u16::from_be_bytes([header[o], header[o + 1]]) as usize,
        (LengthFieldSize::Two, false) => u16::from_le_bytes([header[o], header[o + 1]]) as usize,
        (LengthFieldSize::Four, true) => {
            u32::from_be_bytes([header[o], header[o + 1], header[o + 2], header[o + 3]]) as usize
        }
        (LengthFieldSize::Four, false) => {
            u32::from_le_bytes([header[o], header[o + 1], header[o + 2], header[o + 3]]) as usize
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use bytes::BufMut;
    use rustgate_core::entity::EntityKind;

    use super::*;
    use crate::vehicle_position::{self, FlightState, VEHICLE_POSITION_FRAME_LEN, VehiclePosition};

    /// A minimal ICD-style profile: a 4-byte header carrying a 2-byte
    /// big-endian body length at offset 0. `header_len` = 4 so the length
    /// field (offset 0, width 2) fits with room to spare.
    fn sample_profile() -> StreamProfile {
        StreamProfile::new(4, 0, LengthFieldSize::Two, true)
    }

    /// Build a single wire frame: `[u16 body_len BE][2 reserved][body]`.
    fn wrap_frame(profile: &StreamProfile, body: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        // header: length field at offset 0, then pad to header_len.
        buf.put_u16(body.len() as u16);
        while buf.len() < profile.header_len {
            buf.put_u8(0);
        }
        buf.extend_from_slice(body);
        buf
    }

    fn sample_vehicle_position_body() -> Vec<u8> {
        vehicle_position::encode(&VehiclePosition {
            vehicle_id: 42,
            flight_state: FlightState::Transit,
            latitude_deg: 42.0,
            longitude_deg: -71.0,
            altitude_msl_m: 100.0,
            ground_speed_mps: 10.0,
            heading_deg: 90.0,
            timestamp_unix_ms: 1_700_000_000_123,
        })
    }

    #[test]
    fn no_profile_fails_closed_and_consumes_nothing() {
        let decoder = Stanag4586StreamDecoder::new();
        assert!(!decoder.has_profile());
        let mut buf = BytesMut::from(&[1u8, 2, 3, 4, 5, 6][..]);
        let before = buf.len();
        let err = decoder.decode(&mut buf).expect_err("must fail closed");
        assert!(matches!(err, Stanag4586StreamError::ProfileRequired));
        // Fail-closed means no bytes consumed — the caller can retry once a
        // profile is supplied without losing stream position.
        assert_eq!(buf.len(), before);
    }

    #[test]
    fn two_full_frames_delimit_and_partial_trailing_is_buffered() {
        let profile = sample_profile();
        let decoder = Stanag4586StreamDecoder::new().with_profile(profile);
        let body = sample_vehicle_position_body();

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&wrap_frame(&profile, &body));
        buf.extend_from_slice(&wrap_frame(&profile, &body));
        // A partial trailing frame: header claiming a body, but only part of
        // the header present.
        buf.extend_from_slice(&[0u8, 48]);

        // First frame.
        match decoder.decode(&mut buf).expect("frame 1") {
            StreamFrame::Decoded(entity) => assert_eq!(entity.uid, "stanag4586-42"),
            StreamFrame::Incomplete => panic!("expected frame 1"),
        }
        // Second frame.
        match decoder.decode(&mut buf).expect("frame 2") {
            StreamFrame::Decoded(entity) => assert_eq!(entity.uid, "stanag4586-42"),
            StreamFrame::Incomplete => panic!("expected frame 2"),
        }
        // Third decode: the trailing 2 bytes are less than the 4-byte
        // header, so the frame is incomplete and left buffered intact.
        let remaining = buf.len();
        match decoder.decode(&mut buf).expect("frame 3 incomplete") {
            StreamFrame::Incomplete => {}
            StreamFrame::Decoded(_) => panic!("expected incomplete"),
        }
        assert_eq!(buf.len(), remaining, "incomplete frame must stay buffered");
    }

    #[test]
    fn oversize_length_rejected_before_allocation() {
        // A 2-byte BE length field can encode up to 65 535, so cap the
        // profile below that and present a length that exceeds the cap.
        let profile = sample_profile().with_max_frame_size(64);
        let decoder = Stanag4586StreamDecoder::new().with_profile(profile);

        let mut buf = BytesMut::new();
        buf.put_u16(1024); // body_len = 1024 > cap 64
        buf.put_u16(0); // pad to header_len = 4
        // Deliberately do NOT supply 1024 bytes — the reject must happen on
        // the length field alone, before any body is buffered or reserved.

        let err = decoder.decode(&mut buf).expect_err("must reject oversize");
        match err {
            Stanag4586StreamError::FrameTooLarge { body_len, limit } => {
                assert_eq!(body_len, 1024);
                assert_eq!(limit, 64);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn vehicle_position_frame_round_trips_and_colliding_length_surfaces_unsupported() {
        let profile = sample_profile();
        let decoder = Stanag4586StreamDecoder::new().with_profile(profile);

        // A delimited 48-byte vehicle-position frame decodes to an Entity.
        let body = sample_vehicle_position_body();
        assert_eq!(body.len(), VEHICLE_POSITION_FRAME_LEN);
        let mut buf = wrap_frame(&profile, &body);
        match decoder.decode(&mut buf).expect("vehicle position") {
            StreamFrame::Decoded(entity) => {
                assert_eq!(entity.uid, "stanag4586-42");
                assert_eq!(entity.kind, EntityKind::Aircraft);
            }
            StreamFrame::Incomplete => panic!("expected decoded frame"),
        }

        // A colliding 32-byte message body: the profile delimits it cleanly
        // (proving the length collision the issue describes is resolved by
        // the operator-supplied framing), and the per-message codec surfaces
        // UnsupportedMessage rather than mis-parsing it as a 48-byte frame.
        let short_body = vec![0u8; 32];
        let mut buf = wrap_frame(&profile, &short_body);
        let err = decoder
            .decode(&mut buf)
            .expect_err("32-byte must be unsupported");
        match err {
            Stanag4586StreamError::Decode(Stanag4586EntityError::UnsupportedMessage(_)) => {}
            other => panic!("expected Decode(UnsupportedMessage), got {other:?}"),
        }
        // The colliding frame was fully consumed — the stream stays framed.
        assert!(buf.is_empty());
    }

    #[test]
    fn invalid_profile_length_field_outside_header_rejected() {
        // header_len = 2 but a 4-byte length field at offset 0 spills past
        // the header — a self-inconsistent profile must fail loudly rather
        // than index out of bounds.
        let profile = StreamProfile::new(2, 0, LengthFieldSize::Four, true);
        let decoder = Stanag4586StreamDecoder::new().with_profile(profile);
        let mut buf = BytesMut::from(&[0u8; 8][..]);
        let err = decoder.decode(&mut buf).expect_err("invalid profile");
        assert!(matches!(err, Stanag4586StreamError::InvalidProfile { .. }));
    }

    #[test]
    fn little_endian_length_field_is_honoured() {
        // Same frame, little-endian length field — a vendor ICD deviation.
        let profile = StreamProfile::new(4, 0, LengthFieldSize::Two, false);
        let decoder = Stanag4586StreamDecoder::new().with_profile(profile);
        let body = sample_vehicle_position_body();

        let mut buf = BytesMut::new();
        buf.put_u16_le(body.len() as u16);
        buf.put_u16(0); // pad to header_len = 4
        buf.extend_from_slice(&body);

        match decoder.decode(&mut buf).expect("le frame") {
            StreamFrame::Decoded(entity) => assert_eq!(entity.uid, "stanag4586-42"),
            StreamFrame::Incomplete => panic!("expected decoded le frame"),
        }
    }

    #[test]
    fn max_frame_size_clamped_to_global_cap() {
        // A profile asking for more than the global cap is clamped down.
        let profile = sample_profile().with_max_frame_size(usize::MAX);
        assert_eq!(profile.max_frame_size(), MAX_FRAME_SIZE);
    }
}
