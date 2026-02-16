//! Outbound message encoding for protocol translation.

use std::io;

use bytes::Bytes;
use rustgate_core::message::RoutableMessage;

pub trait MessageEncoder: Send + Sync {
    fn encode(&self, msg: &RoutableMessage) -> io::Result<Bytes>;
}

#[derive(Debug, Default)]
pub struct RawEncoder;

impl MessageEncoder for RawEncoder {
    fn encode(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        Ok(msg.payload.clone())
    }
}

#[derive(Debug, Default)]
pub struct CotEncoder;

impl MessageEncoder for CotEncoder {
    fn encode(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        if msg.metadata.source_protocol == "cot" {
            // Already CoT XML, pass through
            return Ok(msg.payload.clone());
        }

        // Non-CoT payload - for now, pass through raw
        // Future: construct CoT XML wrapper from metadata
        Ok(msg.payload.clone())
    }
}
