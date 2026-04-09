//! Core message types used throughout the routing engine.
//!
//! Every message entering rustgate — whether from a TLS client, WebSocket,
//! federation peer, or NATS subscription — is normalized into a
//! [`RoutableMessage`] before being handed to the router.

use std::time::{Duration, SystemTime};

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use bytes::Bytes;

use crate::identity::{GroupId, Identity};

/// Source protocol identifier for messages originating from federation peers.
pub const SOURCE_FEDERATION: &str = "federation";

/// The internal message envelope for all routed messages.
///
/// Every inbound message is wrapped in this type before entering the router.
/// The router inspects [`destination`](Self::destination) to determine delivery
/// targets and uses [`source`](Self::source) for group membership checks.
#[derive(Debug, Clone)]
pub struct RoutableMessage {
    /// Identity of the sender, extracted from their client certificate.
    pub source: Identity,
    /// Where this message should be delivered.
    pub destination: Destination,
    /// Raw message bytes (typically CoT XML or protobuf).
    pub payload: Bytes,
    /// Contextual information about message origin and lifecycle.
    pub metadata: Metadata,
}

/// Contextual metadata attached to every routed message.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// When the message was received by this server.
    pub received_at: SystemTime,
    /// Transport that originated this message (e.g., `"tcp"`, `"nats"`, `"federation"`).
    pub source_protocol: String,
    /// Classified message type, used for routing decisions (e.g., caching positions).
    pub message_type: MessageType,
    /// Optional time-to-live; expired messages are evicted from the position cache.
    pub ttl: Option<Duration>,
}

impl Metadata {
    /// Returns `true` when this message has a TTL and `received_at + ttl`
    /// is in the past.
    ///
    /// Messages without a TTL never expire. A message whose `received_at`
    /// timestamp is in the future (clock skew) is treated as not expired.
    pub fn is_expired(&self) -> bool {
        let Some(ttl) = self.ttl else {
            return false;
        };
        match self.received_at.elapsed() {
            Ok(elapsed) => elapsed > ttl,
            Err(_) => false,
        }
    }
}

/// Routing destination for a message.
#[derive(Debug, Clone)]
pub enum Destination {
    /// Deliver to all sessions whose certificate OU includes this group.
    Group(GroupId),
    /// Deliver to the session whose certificate CN matches this identity.
    Direct(Identity),
    /// Deliver to all connected sessions (except the sender).
    Broadcast,
}

/// Classified message type.
///
/// The router uses this to make routing decisions — for example, only
/// [`Position`](Self::Position) messages are stored in the position cache
/// for replay to newly connected sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageType {
    /// Situational awareness position report (cached for replay).
    Position,
    /// Chat / instant message.
    Chat,
    /// Emergency or alert event.
    Alert,
    /// Device status update.
    Status,
    /// File transfer metadata.
    File,
    /// Any other CoT event type not classified above.
    Other(String),
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for MessageType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=5)? {
            0 => Ok(Self::Position),
            1 => Ok(Self::Chat),
            2 => Ok(Self::Alert),
            3 => Ok(Self::Status),
            4 => Ok(Self::File),
            _ => {
                let len = u.int_in_range(1..=32)?;
                let s: String = (0..len)
                    .map(|_| u.int_in_range(b'a'..=b'z').map(|b| b as char))
                    .collect::<arbitrary::Result<_>>()?;
                Ok(Self::Other(s))
            }
        }
    }
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for Destination {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(Self::Broadcast),
            1 => {
                let len = u.int_in_range(1..=16)?;
                let group: String = (0..len)
                    .map(|_| u.int_in_range(b'a'..=b'z').map(|b| b as char))
                    .collect::<arbitrary::Result<_>>()?;
                Ok(Self::Group(group))
            }
            _ => Ok(Self::Direct(u.arbitrary()?)),
        }
    }
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for Metadata {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let protocols = ["tcp", "udp", "websocket", "federation", "nats"];
        let idx = u.int_in_range(0..=4)?;
        let source_protocol = protocols[idx].to_string();

        let ttl_secs: Option<u64> = u.arbitrary()?;
        let ttl = ttl_secs.map(|s| Duration::from_secs(s % 86400));

        Ok(Self {
            received_at: SystemTime::now(),
            source_protocol,
            message_type: u.arbitrary()?,
            ttl,
        })
    }
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for RoutableMessage {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let payload_len = u.int_in_range(0..=1024)?;
        let payload_bytes: Vec<u8> = (0..payload_len)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<_>>()?;

        Ok(Self {
            source: u.arbitrary()?,
            destination: u.arbitrary()?,
            payload: Bytes::from(payload_bytes),
            metadata: u.arbitrary()?,
        })
    }
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
            spiffe_id: None,
            attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
        };
        assert_eq!(Destination::Direct(id).to_string(), "direct:alice");
    }
}
