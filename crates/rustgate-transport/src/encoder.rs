//! Outbound message encoding for protocol translation.
//!
//! # Security Model
//!
//! Encoders transform authenticated [`RoutableMessage`]s into wire format.
//! The message's `source` identity is derived from mTLS certificate validation,
//! not from payload content—encoders never trust message claims for auth.
//!
//! Encoding is the final step before framing and transmission. Encoders:
//! - Receive messages with verified source identity (from TLS handshake)
//! - Transform payload bytes to the destination protocol format
//! - Never modify authentication metadata or routing decisions
//!
//! This separation ensures protocol translation cannot bypass access control.

use std::io;

use bytes::Bytes;
use rustgate_core::message::RoutableMessage;

/// Transforms a [`RoutableMessage`] into wire-format bytes for a specific protocol.
///
/// Implementations must be `Send + Sync` for concurrent session handling.
pub trait MessageEncoder: Send + Sync {
    /// Encode the message payload for transmission.
    ///
    /// # Errors
    ///
    /// Returns an error if the message cannot be encoded for the target protocol.
    #[must_use = "encoding errors must be handled to prevent silent data loss"]
    fn encode(&self, msg: &RoutableMessage) -> io::Result<Bytes>;
}

/// Passthrough encoder that preserves the original payload bytes.
#[derive(Debug, Default)]
pub struct RawEncoder;

impl MessageEncoder for RawEncoder {
    fn encode(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        Ok(msg.payload.clone())
    }
}

/// Encoder for Cursor on Target (CoT) XML protocol.
///
/// Passes through payloads that originated as CoT XML. Non-CoT payloads
/// are currently passed through raw; future versions may wrap them in
/// CoT XML envelopes using message metadata.
#[derive(Debug, Default)]
pub struct CotEncoder;

impl MessageEncoder for CotEncoder {
    fn encode(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        if msg.metadata.source_protocol == "cot" {
            return Ok(msg.payload.clone());
        }
        Ok(msg.payload.clone())
    }
}
