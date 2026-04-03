//! Pluggable codec implementation for TAK protobuf wire format.
//!
//! Combines the 0xBF+varint framing with bidirectional protobuf ↔ XML
//! payload conversion. This unifies what was previously split across
//! `TakFrameCodec`, `TakProtobufEncoder`, and inline `proto_to_xml` calls
//! in the session layer.

use std::io;

use bytes::Bytes;
use rustgate_core::codec::Codec;
use rustgate_core::message::RoutableMessage;
use rustgate_core::protocol::FramingStrategy;

/// Codec for TAK protobuf wire format (0xBF + varint + protobuf payload).
///
/// On decode, converts protobuf frames to canonical XML for internal routing.
/// On encode, converts XML payloads to protobuf for wire transmission.
#[derive(Debug, Default, Clone)]
pub struct TakProtobufCodec;

impl Codec for TakProtobufCodec {
    fn protocol_id(&self) -> &str {
        "tak-protobuf"
    }

    fn framing(&self) -> FramingStrategy {
        FramingStrategy::TakProtobuf
    }

    fn decode_payload(&self, frame: &[u8]) -> io::Result<Bytes> {
        let xml_bytes = crate::convert::proto_to_xml(frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Bytes::from(xml_bytes))
    }

    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        let proto_bytes = crate::convert::xml_to_proto(&msg.payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Bytes::from(proto_bytes))
    }

    fn detect(&self, prefix: &[u8]) -> f32 {
        if prefix.first() == Some(&0xBF) {
            0.95
        } else {
            0.0
        }
    }
}
