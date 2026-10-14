// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Errors produced by the VMF codec.
//!
//! The codec distinguishes a small set of failure modes so callers can
//! pick the right recovery strategy. Bit-level parsing has two distinct
//! classes of failure that each map to a different operational class:
//!
//! - [`VmfError::Truncated`] — the bit stream ran out before the field
//!   the parser was reading completed. Always recoverable at the
//!   session boundary by waiting for more bytes (UDP datagrams are
//!   atomic but a stream-mode TCP transport may need more data).
//! - [`VmfError::InvalidValue`] — a decoded scalar lies outside the
//!   envelope MIL-STD-6017 documents (lat/lon out of range, message
//!   type out of the K-series space, classification value undefined).
//!   Hostile or corrupt traffic — the session layer typically drops
//!   the datagram and continues.
//! - [`VmfError::Unsupported`] — the wire format is well-formed and
//!   carries a value the parser understands as legitimate, but this
//!   MVP shipping under issue #868 only models K05.1 Position Reports.
//!   Other K-series messages decode the header but the body is left
//!   as opaque bytes (see [`crate::VmfMessage::Unknown`]); this error
//!   variant exists for the encode direction, where there is no
//!   meaningful "opaque round-trip" path.
//! - [`VmfError::EncodeOverflow`] — a value supplied to the encoder
//!   does not fit the bit-width MIL-STD-6017 reserves for it (e.g. a
//!   URN above the 24-bit envelope, latitude outside `[-90, 90]`).

/// Errors surfaced by [`crate::VmfCodec`] and the lower-level
/// [`crate::header`] / [`crate::k05_1`] modules.
#[derive(Debug, thiserror::Error)]
pub enum VmfError {
    /// The bit stream ended before the field the parser was reading
    /// completed. Carries the field name and how many bits were
    /// requested so a session-layer log line can pinpoint which UAP
    /// bit truncated the frame.
    #[error("VMF bit stream truncated reading {field}: needed {needed_bits} bits")]
    Truncated {
        /// Symbolic field name (e.g. `"urn"`, `"k05_1.latitude"`).
        field: &'static str,
        /// How many bits the decoder asked for at the truncation
        /// point.
        needed_bits: u32,
    },

    /// A decoded value is outside the envelope MIL-STD-6017 defines
    /// for it. The string captures the field and the offending raw
    /// value for the audit trail.
    #[error("VMF invalid value for {field}: {detail}")]
    InvalidValue {
        /// Symbolic field name (e.g. `"latitude"`).
        field: &'static str,
        /// Human-readable detail (e.g. `"raw 0x123456 outside [-90, 90]"`).
        detail: String,
    },

    /// The frame is well-formed and decodes, but encoding the matching
    /// message back to the wire is not implemented in this MVP. Today
    /// only K05.1 Position Reports round-trip; every other K-series
    /// message decodes its header and surfaces its body as
    /// [`crate::VmfMessage::Unknown`], which has no encode direction.
    #[error("VMF encode for message type {message_type} is not supported in this build")]
    Unsupported {
        /// Numeric K-series message type (FAD/MSG-NUM combined).
        message_type: u16,
    },

    /// The encoder cannot represent the supplied value at the bit
    /// width MIL-STD-6017 reserves for it. The string captures the
    /// field and the offending value for the audit trail.
    #[error("VMF encode overflow for {field}: {detail}")]
    EncodeOverflow {
        /// Symbolic field name (e.g. `"urn"`).
        field: &'static str,
        /// Human-readable detail (e.g. `"value 0x10000000 exceeds 24-bit envelope"`).
        detail: String,
    },
}
