// Copyright © 2026 Roberto Chiofalo.

//! Typed failure surface for the DIS codec.
//!
//! Distinct from the [`crate::codec::DisEntityError`] surfaced by the
//! [`rustgate_core::entity::EntityCodec`] implementation: this module's
//! [`DisError`] covers wire-format-layer truncation / framing decisions,
//! while `DisEntityError` covers the additional class of "this Entity
//! cannot be represented as a DIS Entity State PDU" (no position, UID
//! does not match the canonical `dis-<site>-<app>-<entity>` shape, …).

/// Errors surfaced by the wire-format decode / encode entry points
/// (`PduHeader::decode`, `EntityStatePdu::decode`, …).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DisError {
    /// Buffer truncated before a required field.
    #[error("DIS PDU truncated: needed {needed} bytes for {field}, had {available}")]
    Truncated {
        /// Field name that the decoder was attempting to read when the
        /// underlying buffer ran out.
        field: &'static str,
        /// Number of bytes the field requires per IEEE 1278.1.
        needed: usize,
        /// Number of bytes still available in the buffer at the point
        /// of truncation.
        available: usize,
    },

    /// The PDU header's `length` field disagrees with the supplied
    /// buffer length. DIS encodes the total PDU length (header + body)
    /// in a u16 so the receiver can frame multi-PDU UDP datagrams
    /// without re-parsing body shapes.
    #[error("DIS PDU length mismatch: header declared {declared} bytes, buffer carries {actual}")]
    LengthMismatch {
        /// `PduHeader::length` value as decoded from the wire.
        declared: usize,
        /// Actual byte count of the supplied buffer.
        actual: usize,
    },

    /// PDU type byte does not match the type the caller asked the
    /// decoder to parse. Surfaced by `EntityStatePdu::decode` when the
    /// caller hands it a non-Entity-State PDU.
    #[error("expected PDU type {expected}, got {got}")]
    UnexpectedPduType {
        /// PDU type byte the decoder was expecting (1 for Entity State).
        expected: u8,
        /// PDU type byte found in the header.
        got: u8,
    },

    /// Marking string carried characters outside the codec's accepted
    /// envelope. IEEE 1278.1 § 5.3.3.1 specifies the marking field as
    /// 1 charset byte + 11 marking bytes, but in practice operators
    /// expect ASCII-printable data; non-ASCII bytes surface this error
    /// rather than silently lossy-decoding.
    #[error("DIS entity marking is not valid ASCII at byte {byte_index}")]
    InvalidMarking {
        /// Zero-based offset within the 11-byte marking field where
        /// the non-ASCII byte was found.
        byte_index: usize,
    },

    /// Reserved-field padding bytes were non-zero. IEEE 1278.1 reserves
    /// two bytes after the `length` field; an interoperability-strict
    /// receiver may want to reject non-zero padding (potential sender
    /// bug). The decoder accepts non-zero padding but exposes this
    /// error to callers that opt into strict mode (not yet wired).
    #[error("DIS PDU padding is non-zero: {got:#06x}")]
    NonZeroPadding {
        /// Padding word as observed on the wire.
        got: u16,
    },
}
