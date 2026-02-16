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
        // TODO: serialize RoutableMessage to CoT XML
        Ok(msg.payload.clone())
    }
}
