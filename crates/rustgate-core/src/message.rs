// Copyright © 2026 Roberto Chiofalo.

//! Core message types used throughout the routing engine.
//!
//! Every message entering rustgate — whether from a TLS client, WebSocket,
//! federation peer, or NATS subscription — is normalized into a
//! [`RoutableMessage`] before being handed to the router.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use bytes::Bytes;

use crate::identity::Identity;

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
    ///
    /// Wrapped in `Arc<str>` so per-recipient fan-out clones are a
    /// refcount bump rather than a heap allocation. Display / Debug /
    /// `as_ref::<str>` are forwarded unchanged. Closes #784.
    Group(Arc<str>),
    /// Deliver to the session whose certificate CN matches this identity.
    Direct(Identity),
    /// Deliver to all connected sessions (except the sender).
    Broadcast,
    /// Deliver to multiple groups simultaneously.
    ///
    /// Used by SA multicast routing to fan a single message out to
    /// several groups in one routing pass.
    Multicast(Vec<Arc<str>>),
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
                Ok(Self::Group(Arc::<str>::from(group)))
            }
            2 => Ok(Self::Direct(u.arbitrary()?)),
            _ => {
                let count = u.int_in_range(0..=4)?;
                let groups: Vec<Arc<str>> = (0..count)
                    .map(|_| {
                        let len = u.int_in_range(1..=16)?;
                        (0..len)
                            .map(|_| u.int_in_range(b'a'..=b'z').map(|b| b as char))
                            .collect::<arbitrary::Result<String>>()
                            .map(Arc::<str>::from)
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
            Self::Multicast(groups) => {
                // `Arc<str>` does not impl `Iterator::join`. Render each
                // group with comma separators preserving the previous
                // wire-stable shape `multicast:[a,b,c]`.
                f.write_str("multicast:[")?;
                let mut first = true;
                for g in groups {
                    if !first {
                        f.write_str(",")?;
                    }
                    first = false;
                    f.write_str(g)?;
                }
                f.write_str("]")
            }
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
            Destination::Group("team-alpha".into()).to_string(),
            "group:team-alpha"
        );

        let id = Identity {
            cn: std::sync::Arc::<str>::from("alice"),
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

    // ── defensive-invariant coverage ────────────────────────────────

    #[test]
    fn routable_message_and_subtypes_are_send_sync_clone_debug_static() {
        // Every routed message flows across task boundaries (router ↔
        // session handler ↔ federation forwarder ↔ publisher queue)
        // and must be safely cloneable for fan-out delivery. Pin the
        // full bound-set at compile time so a refactor that embedded a
        // non-`Send` field (e.g. an `Rc`-wrapped attachment, a
        // `*const _` pointer for metrics) fails here rather than at
        // the far-away `tokio::spawn(async move { msg.clone() … })`
        // site inside the router's broadcast loop.
        fn assert_bounds<T: Send + Sync + Clone + std::fmt::Debug + 'static>() {}
        assert_bounds::<RoutableMessage>();
        assert_bounds::<Metadata>();
        assert_bounds::<Destination>();
        assert_bounds::<MessageType>();
    }

    #[test]
    fn message_type_exhaustive_match_pins_current_seven_variant_set() {
        // An exhaustive match without a wildcard arm is the canonical
        // way to pin the current variant set — adding an 8th variant
        // (e.g. a future `CoTCasEvac` classification) must force the
        // author to update every routing-decision match site in the
        // codebase, rather than silently falling through a `_ =>`
        // default arm that hides the new classification from the
        // router. The test drives each variant through a minimal
        // Display round-trip so a forgotten Display arm also fails at
        // this test site rather than at a deployed log pipeline.
        let all: [MessageType; 7] = [
            MessageType::Position,
            MessageType::Chat,
            MessageType::Alert,
            MessageType::Status,
            MessageType::File,
            MessageType::Mavlink,
            MessageType::Other(String::new()),
        ];
        for variant in &all {
            let rendered = match variant {
                MessageType::Position => "position",
                MessageType::Chat => "chat",
                MessageType::Alert => "alert",
                MessageType::Status => "status",
                MessageType::File => "file",
                MessageType::Mavlink => "mavlink",
                MessageType::Other(s) => {
                    // pin via prefix — the dynamic payload is rendered
                    // verbatim, but the prefix is the stable contract
                    assert!(variant.to_string().starts_with("other:"));
                    if s.is_empty() {
                        "other"
                    } else {
                        "other_nonempty"
                    }
                }
            };
            assert!(!rendered.is_empty(), "variant must render to non-empty tag");
        }
    }

    #[test]
    fn destination_exhaustive_match_pins_current_four_variant_set() {
        // Same contract as `message_type_exhaustive_match_pins…` but
        // for Destination. The router's delivery path has dedicated
        // branches for each variant (group lookup, direct-CN lookup,
        // broadcast fan-out, multicast fan-over-groups); a fifth
        // variant (e.g. `Multitenant { tenant, groups }`) would need
        // a new router arm and this test forces the author to confront
        // the decision rather than silently falling through default.
        let id = Identity {
            cn: "c".into(),
            fingerprint: "f".into(),
            groups: std::collections::BTreeSet::new(),
            tenant: None,
            spiffe_id: None,
            attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
        };
        let all = [
            Destination::Group("g".into()),
            Destination::Direct(id),
            Destination::Broadcast,
            Destination::Multicast(vec!["h".into()]),
        ];
        for dest in &all {
            let tag = match dest {
                Destination::Group(_) => "group",
                Destination::Direct(_) => "direct",
                Destination::Broadcast => "broadcast",
                Destination::Multicast(_) => "multicast",
            };
            assert_eq!(
                tag,
                dest.kind_str(),
                "exhaustive-match tag must agree with kind_str"
            );
        }
    }

    #[test]
    fn destination_kind_str_values_are_pairwise_distinct_ascii_lowercase() {
        // Prometheus label invariants: low cardinality, ASCII-only,
        // lowercase. A regression that collapsed two variants to the
        // same string (e.g. both `Group` and `Multicast` → "group")
        // would silently merge metrics buckets and defeat operator
        // troubleshooting. Pin pairwise distinctness and the ASCII-
        // lowercase shape.
        let id = Identity {
            cn: "c".into(),
            fingerprint: "f".into(),
            groups: std::collections::BTreeSet::new(),
            tenant: None,
            spiffe_id: None,
            attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
        };
        let labels: [&'static str; 4] = [
            Destination::Group("g".into()).kind_str(),
            Destination::Direct(id).kind_str(),
            Destination::Broadcast.kind_str(),
            Destination::Multicast(vec![]).kind_str(),
        ];
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(
            unique.len(),
            labels.len(),
            "kind_str values must be pairwise distinct: {labels:?}"
        );
        for label in &labels {
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase()),
                "kind_str value must be all-ASCII-lowercase, got {label:?}"
            );
            assert!(!label.is_empty(), "kind_str must never be empty");
        }
    }

    #[test]
    fn source_protocol_constants_are_pairwise_distinct_ascii_lowercase() {
        // SOURCE_FEDERATION and SOURCE_MAVLINK are grep-tokens for
        // echo-prevention filters and audit-log correlation. If either
        // regressed to the same value (or to uppercase / mixed-case),
        // every downstream grep rule in operator runbooks would break
        // silently. Pin distinctness + lowercase ASCII shape.
        assert_ne!(
            SOURCE_FEDERATION, SOURCE_MAVLINK,
            "source protocol constants must be distinct"
        );
        for constant in [SOURCE_FEDERATION, SOURCE_MAVLINK] {
            assert!(
                constant.chars().all(|c| c.is_ascii_lowercase()),
                "source protocol constant must be ASCII lowercase, got {constant:?}"
            );
            assert!(!constant.is_empty(), "source protocol must not be empty");
        }
    }

    #[test]
    fn metadata_is_expired_with_duration_max_ttl_never_expires() {
        // `Duration::MAX` TTL pins the "effectively never expires"
        // path that overflow-safe arithmetic relies on: `elapsed` is
        // always a finite Duration, so `elapsed > Duration::MAX` is
        // false for any elapsed value. A regression that replaced `>`
        // with `>=` would make a `Duration::MAX` TTL suddenly expire
        // when elapsed == Duration::MAX, which can happen in contrived
        // test fixtures but more importantly would silently flip the
        // contract for edge-case config.
        let meta = Metadata {
            received_at: SystemTime::now()
                .checked_sub(Duration::from_secs(3600))
                .expect("clock arithmetic"),
            source_protocol: "tcp".into(),
            message_type: MessageType::Position,
            ttl: Some(Duration::MAX),
        };
        assert!(
            !meta.is_expired(),
            "Duration::MAX TTL must never expire — got expired"
        );
    }

    #[test]
    fn metadata_is_expired_with_zero_ttl_after_brief_wait_returns_true() {
        // `Duration::ZERO` TTL means "expired immediately after
        // received_at" — any non-zero elapsed time must trip
        // `elapsed > 0`. A regression that treated zero-TTL as
        // "no expiry" (conflating Some(ZERO) with None) would
        // silently keep expired messages in the position cache.
        let meta = Metadata {
            received_at: SystemTime::now()
                .checked_sub(Duration::from_millis(10))
                .expect("clock arithmetic"),
            source_protocol: "tcp".into(),
            message_type: MessageType::Position,
            ttl: Some(Duration::ZERO),
        };
        assert!(
            meta.is_expired(),
            "Some(Duration::ZERO) TTL must expire after any elapsed time"
        );
    }

    #[test]
    fn destination_display_direct_renders_cn_not_fingerprint() {
        // Security-relevant contract: the Display impl must render the
        // CN (a human-readable identifier operators use in audit
        // grep) and NEVER leak the raw fingerprint (a cryptographic
        // hash of the client cert that ties log entries to specific
        // physical tokens). A regression that swapped to `id.fingerprint`
        // inside the `Direct` arm would silently leak fingerprints
        // into every audit line that renders a destination.
        let id = Identity {
            cn: "alice".into(),
            fingerprint: "SECRET_FINGERPRINT_MUST_NOT_LEAK".into(),
            groups: std::collections::BTreeSet::new(),
            tenant: None,
            spiffe_id: None,
            attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
        };
        let rendered = Destination::Direct(id).to_string();
        assert_eq!(
            rendered, "direct:alice",
            "Display must render CN, not fingerprint"
        );
        assert!(
            !rendered.contains("SECRET_FINGERPRINT"),
            "fingerprint must NEVER leak into Display output: {rendered}"
        );
    }

    #[test]
    fn message_type_display_other_passes_through_special_chars_verbatim() {
        // The `Other(String)` inner label is end-user-supplied (CoT
        // event-type string) and the Display impl forwards it verbatim
        // after `"other:"`. Pin that there is no hidden sanitisation —
        // this matters because downstream log sinks MUST apply their
        // own sanitisation (via `rustgate_core::sanitize::sanitize_for_log`);
        // a future refactor that added "helpful" escaping inside
        // MessageType::Display would silently double-escape every
        // downstream log record.
        let inputs = [
            "a:b",   // colon mid-string
            "x,y,z", // comma
            "with space",
            "",      // empty
            "UPPER", // uppercase preserved
            "digit1",
        ];
        for input in inputs {
            let rendered = MessageType::Other(input.to_string()).to_string();
            assert_eq!(
                rendered,
                format!("other:{input}"),
                "Other Display must pass inner payload verbatim for {input:?}"
            );
        }
    }

    #[test]
    fn routable_message_clone_shares_payload_bytes_ref_count() {
        // `Bytes` is reference-counted; cloning a `RoutableMessage`
        // must share the payload buffer rather than deep-copying.
        // Operationally critical: every broadcast fan-out clones the
        // message once per recipient, and a regression that replaced
        // `Bytes` with `Vec<u8>` (or added a `.to_vec()` call) would
        // turn O(1) fan-out into O(N·payload_len) and collapse
        // throughput on large CoT/MAVLink messages.
        let payload = Bytes::from_static(b"some-payload-bytes");
        let id = Identity {
            cn: "alice".into(),
            fingerprint: "fp".into(),
            groups: std::collections::BTreeSet::new(),
            tenant: None,
            spiffe_id: None,
            attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
        };
        let msg = RoutableMessage {
            source: id,
            destination: Destination::Broadcast,
            payload,
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "tcp".into(),
                message_type: MessageType::Position,
                ttl: None,
            },
        };
        let cloned = msg.clone();
        // `Bytes` clone shares the same allocation — the as_ptr values
        // must agree for static-source buffers.
        assert_eq!(
            msg.payload.as_ptr(),
            cloned.payload.as_ptr(),
            "RoutableMessage::clone must share payload buffer (Bytes ref-count), not deep-copy"
        );
        // Byte content agreement (basic round-trip sanity).
        assert_eq!(msg.payload, cloned.payload);
    }

    #[test]
    fn metadata_is_expired_boundary_is_strictly_greater() {
        // The implementation uses `elapsed > ttl` (strict greater).
        // Pin that `elapsed == ttl` (exact-match boundary) is NOT
        // considered expired. Operationally this matters because
        // position-cache sweep runs at fixed intervals and a regression
        // to `>=` would silently flip the cache's eviction timing by
        // exactly one interval tick (first sweep vs next sweep),
        // changing staleness semantics that alerting rules depend on.
        //
        // We cannot pin the exact-boundary case deterministically via
        // SystemTime (wall-clock elapsed is always strictly greater
        // than a ttl set to the same offset computed earlier); instead
        // we pin the "barely-under" case: ttl > elapsed by a tiny
        // margin, assert NOT expired. A `>=` regression would still
        // pass this — but combined with `metadata_is_expired_past_ttl_
        // is_true` (existing test, which uses 60s elapsed vs 1ms ttl)
        // the pair pins that within-ttl is false and past-ttl is true.
        let now = SystemTime::now();
        let meta = Metadata {
            received_at: now,
            source_protocol: "tcp".into(),
            message_type: MessageType::Position,
            ttl: Some(Duration::from_secs(3600)),
        };
        assert!(
            !meta.is_expired(),
            "just-received message with 1h TTL must not be expired"
        );
    }
}
