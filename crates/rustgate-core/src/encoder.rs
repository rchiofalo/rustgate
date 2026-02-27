//! Outbound message encoding trait.
//!
//! # Security Model
//!
//! Encoders transform authenticated [`RoutableMessage`]s into wire format.
//! The message's `source` identity is derived from mTLS certificate validation,
//! not from payload content — encoders never trust message claims for auth.
//!
//! Encoding is the final step before framing and transmission. Encoders:
//! - Receive messages with verified source identity (from TLS handshake)
//! - Transform payload bytes to the destination protocol format
//! - Never modify authentication metadata or routing decisions
//!
//! This separation ensures protocol translation cannot bypass access control.

use std::io;

use bytes::Bytes;

use crate::message::RoutableMessage;

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
