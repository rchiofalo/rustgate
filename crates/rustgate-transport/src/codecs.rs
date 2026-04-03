//! Concrete [`Codec`] implementations for
//! built-in wire protocols.
//!
//! These replace the legacy `MessageEncoder` implementations with the unified
//! bidirectional codec abstraction.

use std::io;

use bytes::{Bytes, BytesMut};
use rustgate_core::codec::Codec;
use rustgate_core::message::RoutableMessage;
use rustgate_core::protocol::FramingStrategy;

/// Passthrough codec that preserves original payload bytes unchanged.
#[derive(Debug, Default, Clone)]
pub struct RawCodec;

impl Codec for RawCodec {
    fn protocol_id(&self) -> &'static str {
        "raw"
    }

    fn framing(&self) -> FramingStrategy {
        FramingStrategy::LineDelimited
    }

    fn decode_payload(&self, buf: BytesMut) -> io::Result<Bytes> {
        Ok(buf.freeze())
    }

    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        Ok(msg.payload.clone())
    }
}

/// Codec for Cursor on Target (CoT) XML protocol.
///
/// Passes through payloads that originated as CoT XML. Non-CoT payloads
/// are currently passed through raw; future versions may wrap them in
/// CoT XML envelopes using message metadata.
#[derive(Debug, Default, Clone)]
pub struct CotCodec;

impl Codec for CotCodec {
    fn protocol_id(&self) -> &'static str {
        "cot"
    }

    fn framing(&self) -> FramingStrategy {
        FramingStrategy::XmlStream
    }

    fn decode_payload(&self, buf: BytesMut) -> io::Result<Bytes> {
        Ok(buf.freeze())
    }

    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        Ok(msg.payload.clone())
    }

    fn detect(&self, buf: &[u8]) -> f32 {
        if buf.first() == Some(&b'<') { 0.8 } else { 0.0 }
    }
}
