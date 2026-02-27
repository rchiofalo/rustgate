//! Outbound encoder for TAK protobuf sessions.
//!
//! # Security Model
//!
//! Same as other encoders: transforms authenticated RoutableMessages
//! into wire format. Never modifies authentication metadata.

use std::io;

use bytes::Bytes;
use rustgate_core::encoder::MessageEncoder;
use rustgate_core::message::RoutableMessage;

/// Encoder that converts XML RoutableMessage payloads to TAK protobuf.
///
/// The canonical payload in RoutableMessage is always XML. This encoder
/// translates XML -> protobuf for sessions using the TAK protobuf wire format.
#[derive(Debug, Default)]
pub struct TakProtobufEncoder;

impl MessageEncoder for TakProtobufEncoder {
    fn encode(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        let proto_bytes = crate::convert::xml_to_proto(&msg.payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Bytes::from(proto_bytes))
    }
}
