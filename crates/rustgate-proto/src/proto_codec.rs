//! Unified codec for TAK protobuf sessions.
//!
//! Converts between XML (the canonical internal format) and TAK protobuf
//! wire format at session edges.

use std::io;

use bytes::{Bytes, BytesMut};
use rustgate_core::codec::Codec;
use rustgate_core::message::RoutableMessage;
use rustgate_core::protocol::FramingStrategy;

/// Codec that translates between XML and TAK protobuf wire format.
///
/// - Inbound: protobuf -> XML (before routing)
/// - Outbound: XML -> protobuf (after routing)
#[derive(Debug, Default, Clone)]
pub struct TakProtobufCodec;

impl Codec for TakProtobufCodec {
    fn protocol_id(&self) -> &'static str {
        "tak-proto"
    }

    fn framing(&self) -> FramingStrategy {
        FramingStrategy::TakProtobuf
    }

    fn decode_payload(&self, buf: BytesMut) -> io::Result<Bytes> {
        let xml_bytes = crate::convert::proto_to_xml(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Bytes::from(xml_bytes))
    }

    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        let proto_bytes = crate::convert::xml_to_proto(&msg.payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Bytes::from(proto_bytes))
    }

    fn detect(&self, buf: &[u8]) -> f32 {
        if buf.first() == Some(&0xBF) { 0.9 } else { 0.0 }
    }
}
