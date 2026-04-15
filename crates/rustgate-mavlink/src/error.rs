// Copyright © 2026 Roberto Chiofalo.

//! Errors produced by the MAVLink frame parser.
//!
//! The codec distinguishes three failure modes so that callers can
//! choose different recovery strategies:
//!
//! - [`MavlinkError::InvalidMagic`] — byte at the current read position
//!   is neither `0xFE` nor `0xFD`. The decoder treats this as recoverable
//!   (resynchronise by discarding one byte and retrying) and does not
//!   surface the error to the caller. It is exposed on the enum so tests
//!   can assert on the internal state machine.
//! - [`MavlinkError::FrameTooLarge`] — a `LEN` field claims a payload
//!   size that would exceed the protocol maximum. Fatal for the current
//!   frame; the decoder reports it so the session layer can close the
//!   link.
//! - [`MavlinkError::InvalidIncompatFlags`] — a v2 frame sets
//!   `INCOMPAT_FLAGS` bits this implementation does not understand.
//!   Per the MAVLink spec unknown INCOMPAT bits MUST cause the frame to
//!   be rejected — compat bits may be ignored, but incompat bits by
//!   definition change wire-level parsing.

use std::io;

/// Errors surfaced by [`crate::frame::MavlinkFrameCodec`].
#[derive(Debug, thiserror::Error)]
pub enum MavlinkError {
    /// The leading byte is not a recognised MAVLink magic (`0xFE` or `0xFD`).
    ///
    /// Recoverable: the decoder handles this internally by dropping one
    /// byte and retrying. Exposed on the enum for test assertions.
    #[error("invalid MAVLink magic byte 0x{byte:02X}")]
    InvalidMagic { byte: u8 },

    /// A `LEN` field claims a frame size that would exceed the protocol
    /// maximum (v1: 263 bytes; v2 unsigned: 267 bytes; v2 signed: 280
    /// bytes).
    ///
    /// This cannot actually happen with the one-byte `LEN` field today
    /// (255 is the max, and 255 + overhead stays under the hard cap),
    /// but surfacing a dedicated error lets the signing layer reuse the
    /// same enum when it introduces its own oversize checks.
    #[error("MAVLink frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },

    /// A v2 frame sets INCOMPAT_FLAGS bits this implementation does not
    /// recognise. Per-spec this MUST cause the frame to be rejected.
    #[error("unsupported MAVLink v2 INCOMPAT_FLAGS 0x{flags:02X}")]
    InvalidIncompatFlags { flags: u8 },
}

impl From<MavlinkError> for io::Error {
    fn from(err: MavlinkError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }
}
