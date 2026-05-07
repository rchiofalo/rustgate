// Copyright © 2026 Roberto Chiofalo.

//! Typed error variants surfaced by the Meshtastic codec.
//!
//! Every failure path in this crate maps to one of these variants —
//! the parser never panics and the encoder never silently drops
//! data. The enum is non-exhaustive so future variants can land
//! without a breaking change at the consumer boundary.

/// Failure modes for [`crate::codec::MeshtasticCodec`] and the
/// underlying wire-format primitives.
///
/// Distinct from the canonical workspace `RustgateError` because
/// the boundary aggregator (used in the `rustgate-core` /
/// `rustgate-transport` slice) is not automatically constructed
/// from per-codec errors — binary callers propagate `?` and map
/// at the orchestration layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MeshtasticError {
    /// The encoded TAKPacket exceeds the [`crate::MAX_PAYLOAD_BYTES`]
    /// LoRa transport cap. Surface this on encode (the encoder
    /// declines to emit) and on decode (a mesh frame whose payload
    /// length itself exceeds the cap is malformed).
    #[error(
        "Meshtastic TAKPacket payload {bytes} bytes exceeds {} byte cap",
        crate::MAX_PAYLOAD_BYTES
    )]
    PayloadTooLarge {
        /// Size of the offending payload in bytes.
        bytes: usize,
    },

    /// A length-delimited field declared a length that exceeds the
    /// transport cap (or `usize::MAX`). The wire bytes are rejected
    /// before any allocation occurs so a malicious sender cannot
    /// trigger an out-of-memory condition.
    #[error("length-delimited field length {bytes} exceeds {cap}-byte cap")]
    LengthExceeded {
        /// Declared length in bytes.
        bytes: usize,
        /// Maximum acceptable length in bytes.
        cap: usize,
    },

    /// The wire bytes ended mid-record. The caller likely received
    /// a partial mesh frame and should resync rather than retry the
    /// same buffer.
    #[error("Meshtastic TAKPacket wire bytes are truncated")]
    Truncated,

    /// A varint declared a continuation byte without a follow-up
    /// byte. Symptom of a torn / partial frame or upstream corruption.
    #[error("varint truncated mid-byte")]
    TruncatedVarint,

    /// A varint declared more than 10 bytes (the protobuf cap for a
    /// 64-bit varint). The wire bytes are malformed; reject rather
    /// than spin or wrap.
    #[error("varint exceeds 10-byte protobuf maximum")]
    VarintOverflow,

    /// A protobuf wire type the parser does not implement. Wire
    /// types 0, 1, 2, and 5 are the four standard types; 3 and 4
    /// are deprecated; anything else is a forward-compatibility
    /// hole that surfaces here rather than corrupting the cursor.
    #[error("unknown protobuf wire type {wire_type}")]
    UnknownWireType {
        /// The offending three-bit wire type (0-7 range).
        wire_type: u8,
    },

    /// A length-delimited string field carried bytes that do not
    /// parse as UTF-8. Typical cause is an upstream firmware bug
    /// or a frame routed through a transport that munged the bytes.
    #[error("UTF-8 validation failed at byte {position}")]
    InvalidUtf8 {
        /// Number of valid UTF-8 bytes before the offending byte.
        position: usize,
    },

    /// Encode path: the supplied [`rustgate_core::entity::Entity`]
    /// has no shape that fits the Meshtastic wire form (typically
    /// an event with no position and no chat body). Cross-protocol
    /// fan-out callers see this for entities that simply do not
    /// belong on a position-and-chat oriented mesh transport.
    #[error("entity cannot be mapped to Meshtastic TAKPacket: {0}")]
    UnsupportedEntity(String),
}
