// Copyright © 2026 Roberto Chiofalo.

//! Typed failure surface for the Link 16 / JREAP-C codec.
//!
//! Distinct from the [`crate::codec::Link16EntityError`] surfaced by
//! the [`rustgate_core::entity::EntityCodec`] implementation: this
//! module's [`Link16Error`] covers wire-format-layer truncation /
//! framing decisions, while `Link16EntityError` covers the additional
//! class of "this Entity cannot be represented as a JREAP-C frame".

/// Errors surfaced by the wire-format decode / encode entry points
/// (`JreapFrame::decode`, `J2_2AirTrack::decode`, …).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Link16Error {
    /// Buffer truncated before a required field.
    #[error("JREAP-C truncated: needed {needed} bytes for {field}, had {available}")]
    Truncated {
        /// Field name that the decoder was attempting to read when the
        /// underlying buffer ran out.
        field: &'static str,
        /// Number of bytes the field requires per STANAG 5518.
        needed: usize,
        /// Number of bytes still available in the buffer at the point
        /// of truncation.
        available: usize,
    },

    /// The JREAP-C header's `body_length` field disagrees with the
    /// supplied buffer length. JREAP-C encodes the body length in the
    /// header so the receiver can frame a back-to-back stream of
    /// frames on a single TCP connection without re-parsing every
    /// J-series message body.
    #[error(
        "JREAP-C body length mismatch: header declared {declared} bytes, buffer carries {actual}"
    )]
    BodyLengthMismatch {
        /// `JreapFrame.body_length` value as decoded from the wire.
        declared: usize,
        /// Actual byte count of the body slice.
        actual: usize,
    },

    /// Header version byte does not match a supported JREAP variant.
    /// JREAP-C is `0x03`; the codec rejects other version bytes
    /// (JREAP-A, JREAP-B, future revisions) rather than guessing the
    /// frame layout.
    #[error("unsupported JREAP version: got {got:#04x}, expected {expected:#04x} (JREAP-C)")]
    UnsupportedVersion {
        /// Version byte found in the header.
        got: u8,
        /// Version byte the decoder was expecting.
        expected: u8,
    },

    /// Caller asked the decoder to parse a specific message type but
    /// the frame body carried a different one. Surfaced by
    /// `J2_2AirTrack::decode` when the caller hands it a non-J2.2
    /// payload.
    #[error("expected J-series message {expected:#04x}, got {got:#04x}")]
    UnexpectedMessageType {
        /// Wire byte the decoder was expecting.
        expected: u8,
        /// Wire byte found in the body.
        got: u8,
    },

    /// A field carried a value outside the codec's accepted envelope.
    /// Used for latitude / longitude range checks, NaN / infinity
    /// rejection on encode, and out-of-range track-number values.
    #[error("JREAP-C invalid value for {field}: {reason}")]
    InvalidValue {
        /// Field name where the invalid value was observed.
        field: &'static str,
        /// Human-readable reason for rejection (range-check failure,
        /// non-finite float, invalid character class).
        reason: &'static str,
    },
}
