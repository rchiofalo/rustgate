// Copyright © 2026 Roberto Chiofalo.

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

/// Source protocol identifier for messages ingested from a MAVLink transport.
///
/// Used by the router to tag messages that arrived over MAVLink UDP/TCP so
/// downstream consumers (audit logs, echo-prevention filters) can
/// distinguish MAVLink traffic from CoT/XML traffic without re-parsing the
/// payload.
pub const SOURCE_MAVLINK: &str = "mavlink";

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
    /// Deliver to multiple groups simultaneously.
    ///
    /// Used by SA multicast routing to fan a single message out to
    /// several groups in one routing pass.
    Multicast(Vec<GroupId>),
}

impl Destination {
    /// Short ASCII tag naming the destination variant.
    ///
    /// Stable across releases — used as a label value in Prometheus
    /// metrics (where low cardinality matters) and as a field value in
    /// audit/structured-log records (where SIEM rules grep for the
    /// exact string). Returns one of:
    ///
    /// - `"group"` — unicast to one group
    /// - `"direct"` — unicast to one CN
    /// - `"broadcast"` — fan-out to all sessions
    /// - `"multicast"` — fan-out to multiple groups
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Group(_) => "group",
            Self::Direct(_) => "direct",
            Self::Broadcast => "broadcast",
            Self::Multicast(_) => "multicast",
        }
    }
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
    /// MAVLink frame (autonomous vehicle telemetry / command).
    ///
    /// Routed opaquely — the payload is a complete MAVLink v1 or v2 frame
    /// including magic, header, payload, CRC, and (for v2) optional
    /// signature. The router does not interpret MAVLink message IDs; that
    /// is the responsibility of obligation actuators and per-link signing
    /// verifiers in the `rustgate-mavlink` crate.
    Mavlink,
    /// Any other CoT event type not classified above.
    Other(String),
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for MessageType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=6)? {
            0 => Ok(Self::Position),
            1 => Ok(Self::Chat),
            2 => Ok(Self::Alert),
            3 => Ok(Self::Status),
            4 => Ok(Self::File),
            5 => Ok(Self::Mavlink),
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
        match u.int_in_range(0..=3)? {
            0 => Ok(Self::Broadcast),
            1 => {
                let len = u.int_in_range(1..=16)?;
                let group: String = (0..len)
                    .map(|_| u.int_in_range(b'a'..=b'z').map(|b| b as char))
                    .collect::<arbitrary::Result<_>>()?;
                Ok(Self::Group(group))
            }
            2 => Ok(Self::Direct(u.arbitrary()?)),
            _ => {
                let count = u.int_in_range(0..=4)?;
                let groups: Vec<String> = (0..count)
                    .map(|_| {
                        let len = u.int_in_range(1..=16)?;
                        (0..len)
                            .map(|_| u.int_in_range(b'a'..=b'z').map(|b| b as char))
                            .collect::<arbitrary::Result<String>>()
                    })
                    .collect::<arbitrary::Result<_>>()?;
                Ok(Self::Multicast(groups))
            }
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
            Self::Mavlink => f.write_str("mavlink"),
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
            Self::Multicast(groups) => write!(f, "multicast:[{}]", groups.join(",")),
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
        assert_eq!(MessageType::Mavlink.to_string(), "mavlink");
        assert_eq!(
            MessageType::Other("custom".to_string()).to_string(),
            "other:custom"
        );
    }

    #[test]
    fn source_mavlink_constant() {
        // Pin the on-the-wire source-protocol tag for MAVLink traffic.
        // Other crates (audit, echo-prevention filters) key off this
        // string; changing it is a breaking change for operators who
        // grep their logs.
        assert_eq!(SOURCE_MAVLINK, "mavlink");
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
            tenant: None,
            spiffe_id: None,
            attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
        };
        assert_eq!(Destination::Direct(id).to_string(), "direct:alice");
    }

    #[test]
    fn destination_display_multicast_joins_groups_with_commas() {
        // Pins the human-readable Multicast rendering used in audit log
        // entries — the brackets + comma-separated list let operators grep
        // for any referenced group with a simple literal substring.
        let d = Destination::Multicast(vec!["alpha".into(), "bravo".into(), "charlie".into()]);
        assert_eq!(d.to_string(), "multicast:[alpha,bravo,charlie]");
    }

    #[test]
    fn destination_display_multicast_empty_list() {
        // Empty Multicast still has stable shape: "multicast:[]".
        let d = Destination::Multicast(Vec::new());
        assert_eq!(d.to_string(), "multicast:[]");
    }

    #[test]
    fn destination_kind_str_is_low_cardinality_label() {
        // These strings are Prometheus label values and SIEM-grep tokens —
        // they must stay short, ASCII, and stable across releases.
        assert_eq!(
            Destination::Group("g".into()).kind_str(),
            "group",
            "metrics label must be 'group' for Destination::Group"
        );
        assert_eq!(
            Destination::Broadcast.kind_str(),
            "broadcast",
            "metrics label must be 'broadcast' for Destination::Broadcast"
        );
        assert_eq!(
            Destination::Multicast(vec!["a".into(), "b".into()]).kind_str(),
            "multicast",
            "metrics label must be 'multicast' for Destination::Multicast"
        );
        let id = Identity {
            cn: "carol".into(),
            fingerprint: "fp".into(),
            groups: std::collections::BTreeSet::new(),
            tenant: None,
            spiffe_id: None,
            attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
        };
        assert_eq!(
            Destination::Direct(id).kind_str(),
            "direct",
            "metrics label must be 'direct' for Destination::Direct"
        );
    }

    #[test]
    fn destination_kind_str_returns_static_str() {
        // Pins the fact that kind_str yields a compile-time &'static str
        // suitable for direct use as a Prometheus label without allocation.
        let _static_check: &'static str = Destination::Broadcast.kind_str();
    }

    #[test]
    fn source_federation_constant_is_stable() {
        // Documented in CLAUDE.md as the tag used to mark federated
        // messages; downstream loop-prevention filters key off this
        // exact string. Parallel to SOURCE_MAVLINK.
        assert_eq!(SOURCE_FEDERATION, "federation");
    }

    #[test]
    fn metadata_is_expired_none_ttl_never_expires() {
        // Messages with no TTL are immortal — required so federated
        // control traffic (which never sets a TTL) doesn't silently
        // drop from the position cache.
        let meta = Metadata {
            received_at: SystemTime::UNIX_EPOCH,
            source_protocol: "tcp".into(),
            message_type: MessageType::Chat,
            ttl: None,
        };
        assert!(
            !meta.is_expired(),
            "Metadata::is_expired must return false when ttl is None"
        );
    }

    #[test]
    fn metadata_is_expired_past_ttl_is_true() {
        // received_at long in the past, ttl only 1ms -> expired.
        let meta = Metadata {
            received_at: SystemTime::now()
                .checked_sub(Duration::from_secs(60))
                .expect("clock arithmetic"),
            source_protocol: "tcp".into(),
            message_type: MessageType::Position,
            ttl: Some(Duration::from_millis(1)),
        };
        assert!(
            meta.is_expired(),
            "Metadata::is_expired must return true when now > received_at + ttl"
        );
    }

    #[test]
    fn metadata_is_expired_within_ttl_is_false() {
        // received_at ~now, generous ttl -> not expired.
        let meta = Metadata {
            received_at: SystemTime::now(),
            source_protocol: "tcp".into(),
            message_type: MessageType::Position,
            ttl: Some(Duration::from_secs(3600)),
        };
        assert!(
            !meta.is_expired(),
            "Metadata::is_expired must return false when now < received_at + ttl"
        );
    }

    #[test]
    fn metadata_is_expired_future_received_at_treated_as_fresh() {
        // Clock skew defense: if received_at is in the future (another
        // node's clock ran ahead), elapsed() returns Err; the contract
        // is to treat that as "not expired" so we do not silently drop
        // legitimate messages. Pin this to prevent accidental strictness.
        let meta = Metadata {
            received_at: SystemTime::now()
                .checked_add(Duration::from_secs(3600))
                .expect("clock arithmetic"),
            source_protocol: "federation".into(),
            message_type: MessageType::Alert,
            ttl: Some(Duration::from_secs(1)),
        };
        assert!(
            !meta.is_expired(),
            "future received_at must not count as expired (clock-skew tolerance)"
        );
    }

    #[test]
    fn message_type_display_other_preserves_payload() {
        // Edge case: the inner label for Other is forwarded verbatim.
        assert_eq!(MessageType::Other(String::new()).to_string(), "other:");
        assert_eq!(
            MessageType::Other("a-b_c.d/e".into()).to_string(),
            "other:a-b_c.d/e"
        );
    }

    #[test]
    fn message_type_equality_includes_inner_string() {
        // Two Other variants are equal iff their payloads match — pins
        // the derived PartialEq/Eq semantics used by routing decisions.
        assert_eq!(
            MessageType::Other("x".into()),
            MessageType::Other("x".into())
        );
        assert_ne!(
            MessageType::Other("x".into()),
            MessageType::Other("y".into())
        );
        assert_ne!(MessageType::Position, MessageType::Chat);
    }
}
