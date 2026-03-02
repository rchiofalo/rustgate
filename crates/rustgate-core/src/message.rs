use bytes::Bytes;
use std::time::{Duration, SystemTime};

use crate::identity::{GroupId, Identity};

/// Source protocol identifier for messages originating from federation peers.
pub const SOURCE_FEDERATION: &str = "federation";

/// Every message flowing through rustgate becomes this.
#[derive(Debug, Clone)]
pub struct RoutableMessage {
    pub source: Identity,
    pub destination: Destination,
    pub payload: Bytes,
    pub metadata: Metadata,
}

#[derive(Debug, Clone)]
pub struct Metadata {
    pub received_at: SystemTime,
    pub source_protocol: String,
    pub message_type: MessageType,
    pub ttl: Option<Duration>,
}

#[derive(Debug, Clone)]
pub enum Destination {
    Group(GroupId),
    Direct(Identity),
    Broadcast,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageType {
    Position,
    Chat,
    Alert,
    Status,
    File,
    Other(String),
}
