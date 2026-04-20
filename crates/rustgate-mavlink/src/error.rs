// Copyright © 2026 Roberto Chiofalo.

//! Errors produced by the MAVLink frame parser.
//!
//! The codec distinguishes five failure modes so that callers can
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
//! - [`MavlinkError::V1FrameRejected`] — a v1 frame arrived on a codec
//!   configured to reject MAVLink v1. Defaults to rejection so that a
//!   compliance deployment cannot silently accept the pre-signing wire
//!   format. Operators opt back into v1 via
//!   [`crate::frame::MavlinkFrameCodec::with_allow_v1`].
//! - [`MavlinkError::UnsignedFrameRejected`] — a v2 frame whose
//!   `INCOMPAT & SIGNED` bit is clear arrived on a codec configured to
//!   require signatures. Defaults to rejection so that the operator must
//!   explicitly permit unsigned traffic via
//!   [`crate::frame::MavlinkFrameCodec::with_require_signing`].

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

    /// A v1 frame (`STX = 0xFE`) arrived on a codec configured to reject
    /// v1 traffic.
    ///
    /// Rustgate defaults to rejecting v1 because the v1 wire format has
    /// no signature field — accepting it silently would hand an attacker a
    /// downgrade path that bypasses v2 signing. Operators that run mixed
    /// fleets opt back in via
    /// [`crate::frame::MavlinkFrameCodec::with_allow_v1`].
    #[error("MAVLink v1 frame rejected by signing policy (v1 not allowed)")]
    V1FrameRejected,

    /// A v2 frame arrived with `INCOMPAT & SIGNED = 0` on a codec
    /// configured to require signatures.
    ///
    /// The signature policy is set independently of v1 acceptance so
    /// operators can opt in to "signed v2 only" without also having to
    /// choose a stance on v1.
    #[error("MAVLink v2 unsigned frame rejected by signing policy")]
    UnsignedFrameRejected,
}

impl From<MavlinkError> for io::Error {
    fn from(err: MavlinkError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::error::Error as _;

    use super::*;

    // ---- Display ----

    #[test]
    fn invalid_magic_display_uses_uppercase_hex_with_0x_prefix() {
        // The byte is rendered via `{byte:02X}` — operator eyeballing logs
        // needs the 0x prefix and fixed-width, so pin the exact shape.
        assert_eq!(
            MavlinkError::InvalidMagic { byte: 0x00 }.to_string(),
            "invalid MAVLink magic byte 0x00"
        );
        assert_eq!(
            MavlinkError::InvalidMagic { byte: 0xAB }.to_string(),
            "invalid MAVLink magic byte 0xAB"
        );
        assert_eq!(
            MavlinkError::InvalidMagic { byte: 0xFF }.to_string(),
            "invalid MAVLink magic byte 0xFF"
        );
    }

    #[test]
    fn invalid_magic_display_pads_single_digit_bytes() {
        // `{:02X}` zero-pads — a 0x05 byte must render as "0x05", not "0x5".
        // Regression target: dropping the `02` width would break log greps.
        let msg = MavlinkError::InvalidMagic { byte: 0x05 }.to_string();
        assert!(msg.ends_with("0x05"), "padding lost: {msg}");
    }

    #[test]
    fn frame_too_large_display_includes_both_sizes() {
        let err = MavlinkError::FrameTooLarge {
            size: 500,
            max: 280,
        };
        assert_eq!(
            err.to_string(),
            "MAVLink frame too large: 500 bytes (max 280)"
        );
    }

    #[test]
    fn frame_too_large_display_handles_zero_values() {
        // Pin that the formatter doesn't special-case zero (no "0 bytes" is
        // suppressed, no singular "1 byte" branch exists). Callers may pass
        // sentinel zeros when plumbing errors through unknown sizes.
        assert_eq!(
            MavlinkError::FrameTooLarge { size: 0, max: 0 }.to_string(),
            "MAVLink frame too large: 0 bytes (max 0)"
        );
    }

    #[test]
    fn invalid_incompat_flags_display_uses_uppercase_hex() {
        assert_eq!(
            MavlinkError::InvalidIncompatFlags { flags: 0x01 }.to_string(),
            "unsupported MAVLink v2 INCOMPAT_FLAGS 0x01"
        );
        assert_eq!(
            MavlinkError::InvalidIncompatFlags { flags: 0xFE }.to_string(),
            "unsupported MAVLink v2 INCOMPAT_FLAGS 0xFE"
        );
    }

    #[test]
    fn v1_frame_rejected_display_is_static() {
        // No interpolated fields — pin the exact operator-facing text so a
        // rename doesn't break audit-log greps.
        assert_eq!(
            MavlinkError::V1FrameRejected.to_string(),
            "MAVLink v1 frame rejected by signing policy (v1 not allowed)"
        );
    }

    #[test]
    fn unsigned_frame_rejected_display_is_static() {
        assert_eq!(
            MavlinkError::UnsignedFrameRejected.to_string(),
            "MAVLink v2 unsigned frame rejected by signing policy"
        );
    }

    // ---- std::error::Error::source ----

    #[test]
    fn every_variant_has_no_source() {
        // None of the variants wrap an `#[source]` field, so Error::source()
        // must be None across the board. A future refactor that added a
        // `#[source]` field without updating callers would fail here.
        assert!(MavlinkError::InvalidMagic { byte: 0 }.source().is_none());
        assert!(
            MavlinkError::FrameTooLarge { size: 0, max: 0 }
                .source()
                .is_none()
        );
        assert!(
            MavlinkError::InvalidIncompatFlags { flags: 0 }
                .source()
                .is_none()
        );
        assert!(MavlinkError::V1FrameRejected.source().is_none());
        assert!(MavlinkError::UnsignedFrameRejected.source().is_none());
    }

    // ---- Debug renders variant name ----

    #[test]
    fn debug_contains_variant_name() {
        // Pin the derived Debug so logs using `?` render the variant name,
        // which is the only way to disambiguate V1FrameRejected from
        // UnsignedFrameRejected at a glance when Display strings are filtered.
        assert!(format!("{:?}", MavlinkError::V1FrameRejected).contains("V1FrameRejected"));
        assert!(
            format!("{:?}", MavlinkError::UnsignedFrameRejected).contains("UnsignedFrameRejected")
        );
        assert!(
            format!("{:?}", MavlinkError::InvalidMagic { byte: 0xFE }).contains("InvalidMagic")
        );
    }

    // ---- From<MavlinkError> for io::Error ----

    #[test]
    fn from_invalid_magic_into_io_error_sets_invalid_data_kind() {
        // The io::Error bridge must classify every MavlinkError as
        // InvalidData so the session-layer read loop can route them
        // uniformly to the "drop session + audit" path.
        let err: io::Error = MavlinkError::InvalidMagic { byte: 0xAB }.into();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn from_frame_too_large_into_io_error_preserves_display() {
        // The conversion stores the MavlinkError as the io::Error's inner,
        // which means Display must round-trip verbatim through io::Error.
        let err: io::Error = MavlinkError::FrameTooLarge {
            size: 1024,
            max: 280,
        }
        .into();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            "MAVLink frame too large: 1024 bytes (max 280)"
        );
    }

    #[test]
    fn from_invalid_incompat_flags_into_io_error_is_invalid_data() {
        let err: io::Error = MavlinkError::InvalidIncompatFlags { flags: 0x04 }.into();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("0x04"));
    }

    #[test]
    fn from_v1_frame_rejected_into_io_error_is_invalid_data() {
        let err: io::Error = MavlinkError::V1FrameRejected.into();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("v1 frame rejected"));
    }

    #[test]
    fn from_unsigned_frame_rejected_into_io_error_is_invalid_data() {
        let err: io::Error = MavlinkError::UnsignedFrameRejected.into();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("unsigned frame rejected"));
    }

    #[test]
    fn io_error_exposes_mavlink_error_via_get_ref_downcast() {
        // `io::Error::new(kind, source)` stores `source` behind an Arc that
        // can be retrieved via `get_ref()` + downcast. Pin this contract so
        // callers wanting the typed MavlinkError back (e.g. metrics
        // classifying by variant) don't have to re-parse Display.
        let inner = MavlinkError::InvalidMagic { byte: 0x7E };
        let io_err: io::Error = inner.into();
        let dyn_ref = io_err.get_ref().expect("inner error should be present");
        let mav_ref = dyn_ref
            .downcast_ref::<MavlinkError>()
            .expect("inner should downcast to MavlinkError");
        match mav_ref {
            MavlinkError::InvalidMagic { byte } => assert_eq!(*byte, 0x7E),
            other => panic!("expected InvalidMagic, got {other:?}"),
        }
    }

    #[test]
    fn io_error_preserves_mavlink_display_at_top_level() {
        // `io::Error::source()` forwards to the inner's source() (not returns
        // the inner), similar to `#[error(transparent)]`. Since no MavlinkError
        // variant carries an `#[source]`, the chain bottoms out at None — but
        // the io::Error's OWN Display still contains the original MavlinkError
        // text because the conversion stores it as the inner. Pin this
        // combined shape: top Display is the MAVLink message, source() is None.
        let io_err: io::Error = MavlinkError::InvalidIncompatFlags { flags: 0x40 }.into();
        assert_eq!(
            io_err.to_string(),
            "unsupported MAVLink v2 INCOMPAT_FLAGS 0x40"
        );
        assert!(
            io_err.source().is_none(),
            "io::Error::source() should forward to MavlinkError::source(), \
             which is None for all variants"
        );
    }

    #[test]
    fn from_conversion_works_through_question_mark() {
        // Pin that `?` propagates MavlinkError → io::Error at a function
        // boundary, which is the whole point of the From impl: the codec's
        // tokio AsyncRead/AsyncWrite glue expects to `?` these.
        fn returns_mavlink() -> std::result::Result<(), MavlinkError> {
            Err(MavlinkError::UnsignedFrameRejected)
        }
        fn bridges() -> io::Result<()> {
            returns_mavlink()?;
            Ok(())
        }
        let e = bridges().expect_err("MavlinkError should convert via ?");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }
}
