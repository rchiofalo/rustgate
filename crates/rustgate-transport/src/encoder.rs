//! Outbound message encoders.
//!
//! Re-exports the [`MessageEncoder`] trait from `rustgate-core` and provides
//! built-in encoder implementations.

use std::io;

use bytes::Bytes;
// Re-export the trait from core so downstream crates that depend on
// rustgate-transport continue to find it at the same path.
pub use rustgate_core::encoder::MessageEncoder;
use rustgate_core::message::RoutableMessage;

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
