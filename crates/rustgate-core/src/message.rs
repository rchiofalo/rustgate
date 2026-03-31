use std::time::{Duration, SystemTime};

use bytes::Bytes;

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

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Position => f.write_str("position"),
            Self::Chat => f.write_str("chat"),
            Self::Alert => f.write_str("alert"),
            Self::Status => f.write_str("status"),
            Self::File => f.write_str("file"),
            Self::Other(s) => write!(f, "other:{s}"),
        }
    }
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Broadcast => f.write_str("broadcast"),
            Self::Group(g) => write!(f, "group:{g}"),
            Self::Direct(id) => write!(f, "direct:{}", id.cn),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn message_type_display() {
        assert_eq!(MessageType::Position.to_string(), "position");
        assert_eq!(MessageType::Chat.to_string(), "chat");
        assert_eq!(MessageType::Alert.to_string(), "alert");
        assert_eq!(MessageType::Status.to_string(), "status");
        assert_eq!(MessageType::File.to_string(), "file");
        assert_eq!(
            MessageType::Other("custom".to_string()).to_string(),
            "other:custom"
        );
    }

    #[test]
    fn destination_display() {
        assert_eq!(Destination::Broadcast.to_string(), "broadcast");
        assert_eq!(
            Destination::Group("team-alpha".to_string()).to_string(),
            "group:team-alpha"
        );

        let id = Identity {
            cn: "alice".to_string(),
            fingerprint: "abc123".to_string(),
            groups: std::collections::BTreeSet::new(),
        };
        assert_eq!(Destination::Direct(id).to_string(), "direct:alice");
    }
}
