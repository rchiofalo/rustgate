//! Unified codec trait for message encoding and decoding.
//!
//! The [`Codec`] trait provides a single abstraction for protocol-specific
//! message transformation, replacing the older `MessageEncoder` trait.
//! Implementations handle both inbound (decode) and outbound (encode)
//! payload conversion while remaining agnostic to framing and transport.

use std::io;

use bytes::{Bytes, BytesMut};

use crate::message::RoutableMessage;
use crate::protocol::FramingStrategy;

/// Unified codec for bidirectional message transformation.
///
/// Each implementation handles a specific wire protocol (raw passthrough,
/// CoT XML, TAK protobuf, etc.). The codec is responsible only for payload
/// encoding/decoding; framing is handled separately by the transport layer.
///
/// Implementations must be `Send + Sync` for use across async tasks.
pub trait Codec: Send + Sync + std::fmt::Debug {
    /// Short identifier for this codec (e.g., `"raw"`, `"cot"`, `"tak-proto"`).
    fn protocol_id(&self) -> &'static str;

    /// Suggested framing strategy for this codec.
    ///
    /// Transports that manage their own framing (e.g., WebSocket) may ignore
    /// this value.
    fn framing(&self) -> FramingStrategy;

    /// Decode an inbound payload from wire format to the canonical internal
    /// representation (XML for CoT-based protocols).
    ///
    /// # Errors
    ///
    /// Returns an error if the payload cannot be decoded.
    fn decode_payload(&self, buf: BytesMut) -> io::Result<Bytes>;

    /// Encode an outbound [`RoutableMessage`] into wire-format bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the message cannot be encoded for the target protocol.
    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes>;

    /// Confidence score (0.0 to 1.0) that the given bytes belong to this codec.
    ///
    /// Used for protocol auto-detection. Returns 0.0 when detection is not
    /// supported or not applicable (e.g., WebSocket codecs where framing is
    /// handled externally).
    fn detect(&self, _buf: &[u8]) -> f32 {
        0.0
    }
}
