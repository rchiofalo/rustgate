// Copyright © 2026 Roberto Chiofalo.

//! Core message types used throughout the routing engine.
//!
//! Every message entering rustgate — whether from a TLS client, WebSocket,
//! federation peer, or NATS subscription — is normalized into a
//! [`RoutableMessage`] before being handed to the router.
//!
//! # Builder pattern for [`Metadata`]
//!
//! [`Metadata`] is marked `#[non_exhaustive]` and is constructed via the
//! [`Metadata::new`] constructor plus chainable `with_*` builder methods.
//! The constructor takes only the always-required fields
//! (`received_at`, `source_protocol`, `message_type`); every optional
//! field is set with a dedicated builder method (`with_ttl`, etc.) and
//! defaults to `None` when not specified.
//!
//! ```
//! use std::time::{Duration, SystemTime};
//! use rustgate_core::message::{Metadata, MessageType};
//!
//! let meta = Metadata::new(SystemTime::now(), "tcp".to_string(), MessageType::Position)
//!     .with_ttl(Duration::from_secs(60));
//! ```
//!
//! Future fields land as additive `with_*` methods so that adding a new
//! optional field never breaks an existing construction site.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

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
///
/// # Optional attached entity
///
/// [`entity`](Self::entity) carries an optional parsed
/// [`crate::entity::Entity`] alongside the raw [`payload`](Self::payload).
/// It is `None` at every ingress today; codecs that have already decoded
/// the payload into a canonical entity may attach it via
/// [`RoutableMessage::with_entity`] so downstream consumers (Foundry
/// projection, inference back-annotation) can skip a redundant re-decode.
/// The field is wrapped in `Arc` so the frequently-cloned envelope stays
/// cheap on the broadcast fan-out hot path — a clone is a refcount bump,
/// not a deep copy of the entity. See ADR 0035.
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
    /// Optional parsed entity attached alongside [`payload`](Self::payload).
    ///
    /// `None` at every construction site today — this is a purely
    /// additive field. When a codec has already produced a canonical
    /// [`crate::entity::Entity`], attaching it here via
    /// [`RoutableMessage::with_entity`] lets the Foundry outbound and
    /// inference back-annotation seams consume it directly instead of
    /// re-decoding [`payload`](Self::payload). Wrapped in `Arc` so
    /// cloning the envelope for per-recipient fan-out stays O(1). Refs
    /// #1540, ADR 0035.
    pub entity: Option<Arc<crate::entity::Entity>>,
}

impl RoutableMessage {
    /// Builder-style setter for [`RoutableMessage::entity`]. Returns
    /// `self` for chaining, mirroring the `Metadata::with_*` builders.
    ///
    /// Attach a parsed entity when the ingress codec has already decoded
    /// the payload, so the Foundry outbound and inference seams can use
    /// it directly rather than re-decoding [`RoutableMessage::payload`].
    /// The entity is wrapped in `Arc` internally to keep envelope clones
    /// cheap. Refs #1540, ADR 0035.
    #[must_use]
    pub fn with_entity(mut self, entity: crate::entity::Entity) -> Self {
        self.entity = Some(Arc::new(entity));
        self
    }
}

/// Contextual metadata attached to every routed message.
///
/// Marked `#[non_exhaustive]` so that adding a new optional field is an
/// additive change for downstream crates: external consumers must construct
/// values via [`Metadata::new`] (plus `with_*` builder methods) rather than
/// struct literals. Inside the workspace `cargo` still permits literal
/// construction, but the [`Metadata::new`] constructor is the canonical
/// path and the only one used by the routing crates.
///
/// # Builder
///
/// Use [`Metadata::new`] for the three required fields, then chain
/// `with_*` methods to set optional fields. Each future optional field
/// becomes its own `with_<name>` method so construction-site churn stays
/// near zero when the schema grows.
//
// Future field additions: append the new optional field below the
// existing ones with `#[serde(default, skip_serializing_if = "…")]` so the
// wire format stays stable, then add a `Metadata::with_<name>` builder
// method below. Existing call sites continue to compile because every
// optional field defaults to its empty value inside `Metadata::new`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// When the message was received by this server.
    pub received_at: SystemTime,
    /// Transport that originated this message (e.g., `"tcp"`, `"nats"`, `"federation"`).
    pub source_protocol: String,
    /// Classified message type, used for routing decisions (e.g., caching positions).
    pub message_type: MessageType,
    /// Optional time-to-live; expired messages are evicted from the position cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<Duration>,
    /// Optional W3C Trace Context attached at ingress and propagated end-to-end
    /// across local routing and federation hops (closes #852, PR-C).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<crate::traceparent::TraceContext>,
    /// Optional CAPCO classification marking attached to the message
    /// envelope. `None` for legacy traffic; the per-recipient authz
    /// path forwards `Some(_)` into the `classification` context so
    /// policies can deny release to recipients whose clearance does
    /// not dominate the marking (closes #849 items 3 + 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<crate::classification::ClassificationMarking>,
    /// Optional tenant identifier associated with the originating
    /// session. Populated at the router accept path from
    /// [`crate::identity::Identity::tenant`] (which is itself derived
    /// from the certificate Organization (`O=`) field) so downstream
    /// surfaces — archive directories, store-and-forward keying, NATS
    /// subject prefix, per-tenant metrics — can partition data at
    /// rest without re-deriving the tenant from the source identity.
    /// `None` for legacy traffic and unauthenticated/plaintext
    /// sessions; consumers fall back to
    /// [`crate::constants::DEFAULT_TENANT_ARCHIVE_KEY`] when a key is
    /// required (closes #859).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    // Future optional fields land here. Each must:
    //   1. Be `Option<T>` (or another type with a sensible default).
    //   2. Carry `#[serde(default, skip_serializing_if = "…")]` so absent
    //      fields round-trip identically across versions.
    //   3. Default to its empty value inside `Metadata::new` below.
    //   4. Have a matching `Metadata::with_<name>` builder method.
}

impl Metadata {
    /// Construct a [`Metadata`] with the three always-required fields.
    ///
    /// All optional fields (currently `ttl`) default to `None`. Set them
    /// via the chainable `with_*` builder methods (e.g.
    /// [`Metadata::with_ttl`]).
    ///
    /// `source_protocol` is owned (`String`) to keep call-site type
    /// inference simple — pass either a literal-built `String` (`"tcp".to_string()`)
    /// or one of the [`SOURCE_FEDERATION`] / [`SOURCE_MAVLINK`] constants
    /// converted with `.to_string()`.
    pub fn new(
        received_at: SystemTime,
        source_protocol: String,
        message_type: MessageType,
    ) -> Self {
        Self {
            received_at,
            source_protocol,
            message_type,
            ttl: None,
            trace_context: None,
            classification: None,
            tenant_id: None,
        }
    }

    /// Builder-style setter for [`Metadata::ttl`]. Returns `self` for chaining.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Builder-style setter for [`Metadata::trace_context`]. Returns `self`
    /// for chaining. Closes #852.
    #[must_use]
    pub fn with_trace_context(mut self, ctx: crate::traceparent::TraceContext) -> Self {
        self.trace_context = Some(ctx);
        self
    }

    /// Builder-style setter for [`Metadata::classification`]. Returns
    /// `self` for chaining. Refs #849.
    #[must_use]
    pub fn with_classification(
        mut self,
        marking: crate::classification::ClassificationMarking,
    ) -> Self {
        self.classification = Some(marking);
        self
    }

    /// Builder-style setter for [`Metadata::tenant_id`]. Returns `self`
    /// for chaining. Closes #859.
    ///
    /// Tenant identifiers are arbitrary operator-supplied strings drawn
    /// from the cert Organization (`O=`) field. Consumers that key
    /// per-tenant data structures should treat `None` and the empty
    /// string equivalently and fall back to
    /// [`crate::constants::DEFAULT_TENANT_ARCHIVE_KEY`].
    #[must_use]
    pub fn with_tenant_id(mut self, tenant: impl Into<String>) -> Self {
        let s: String = tenant.into();
        self.tenant_id = if s.is_empty() { None } else { Some(s) };
        self
    }

    /// Borrow the tenant identifier on this metadata, if any.
    ///
    /// Returns `Some(&str)` when [`Metadata::with_tenant_id`] was called
    /// with a non-empty value, `None` otherwise. Callers that key data at
    /// rest by tenant should pair this with
    /// [`crate::constants::DEFAULT_TENANT_ARCHIVE_KEY`] to materialise a
    /// concrete bucket name for legacy / unauthenticated traffic.
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

        let mut meta = Self::new(SystemTime::now(), source_protocol, u.arbitrary()?);
        if let Some(t) = ttl {
            meta = meta.with_ttl(t);
        }
        if let Ok(tag) = u.int_in_range::<u8>(0..=2) {
            // 0/1 → keep tenant absent (legacy shape); 2 → fabricate a
            // small tenant id so the fuzzer also exercises the
            // populated-tenant code path on archive / SF / NATS.
            if tag == 2 {
                let len = u.int_in_range(1..=8)?;
                let tenant: String = (0..len)
                    .map(|_| u.int_in_range(b'a'..=b'z').map(|b| b as char))
                    .collect::<arbitrary::Result<_>>()?;
                meta = meta.with_tenant_id(tenant);
            }
        }
        Ok(meta)
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
            // Additive #1540 field: the fuzzer exercises the envelope
            // shape with no attached entity — the attach fast path has
            // dedicated unit coverage, and keeping this `None` preserves
            // the pre-#1540 corpus shape.
            entity: None,
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
        let meta = Metadata::new(SystemTime::UNIX_EPOCH, "tcp".into(), MessageType::Chat);
        assert!(
            !meta.is_expired(),
            "Metadata::is_expired must return false when ttl is None"
        );
    }

    #[test]
    fn metadata_is_expired_past_ttl_is_true() {
        // received_at long in the past, ttl only 1ms -> expired.
        let meta = Metadata::new(
            SystemTime::now()
                .checked_sub(Duration::from_secs(60))
                .expect("clock arithmetic"),
            "tcp".into(),
            MessageType::Position,
        )
        .with_ttl(Duration::from_millis(1));
        assert!(
            meta.is_expired(),
            "Metadata::is_expired must return true when now > received_at + ttl"
        );
    }

    #[test]
    fn metadata_is_expired_within_ttl_is_false() {
        // received_at ~now, generous ttl -> not expired.
        let meta = Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position)
            .with_ttl(Duration::from_secs(3600));
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
        let meta = Metadata::new(
            SystemTime::now()
                .checked_add(Duration::from_secs(3600))
                .expect("clock arithmetic"),
            "federation".into(),
            MessageType::Alert,
        )
        .with_ttl(Duration::from_secs(1));
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
        let meta = Metadata::new(
            SystemTime::now()
                .checked_sub(Duration::from_secs(3600))
                .expect("clock arithmetic"),
            "tcp".into(),
            MessageType::Position,
        )
        .with_ttl(Duration::MAX);
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
        let meta = Metadata::new(
            SystemTime::now()
                .checked_sub(Duration::from_millis(10))
                .expect("clock arithmetic"),
            "tcp".into(),
            MessageType::Position,
        )
        .with_ttl(Duration::ZERO);
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
            metadata: Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position),
            entity: None,
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
        let meta = Metadata::new(now, "tcp".into(), MessageType::Position)
            .with_ttl(Duration::from_secs(3600));
        assert!(
            !meta.is_expired(),
            "just-received message with 1h TTL must not be expired"
        );
    }

    // ── builder-pattern coverage (closes #1298) ─────────────────────

    #[test]
    fn metadata_new_initializes_optional_fields_to_none() {
        // The constructor takes only the required fields and must zero
        // every optional field to `None`. Future field additions must
        // preserve this invariant — adding an optional field that
        // defaults to a non-None value is a silent semantic change for
        // every existing call site.
        let now = SystemTime::now();
        let meta = Metadata::new(now, "tcp".into(), MessageType::Position);
        assert_eq!(meta.received_at, now);
        assert_eq!(meta.source_protocol, "tcp");
        assert_eq!(meta.message_type, MessageType::Position);
        assert!(meta.ttl.is_none(), "ttl must default to None");
    }

    #[test]
    fn metadata_with_ttl_sets_ttl_field() {
        // `with_ttl` is a builder-style chain: it must return `self`
        // with the field updated and leave every other field
        // untouched. Pin both that the field is set and that nothing
        // else is mutated.
        let now = SystemTime::now();
        let ttl = Duration::from_secs(60);
        let meta = Metadata::new(now, "nats".into(), MessageType::Chat).with_ttl(ttl);
        assert_eq!(meta.ttl, Some(ttl));
        assert_eq!(meta.received_at, now);
        assert_eq!(meta.source_protocol, "nats");
        assert_eq!(meta.message_type, MessageType::Chat);
    }

    #[test]
    fn metadata_with_ttl_overwrites_previous_value() {
        // Builder methods must be idempotent under chained re-application:
        // calling `with_ttl` twice replaces (not stacks) the value, so a
        // future re-config flow that recomputes the TTL after extra
        // policy lookup behaves predictably.
        let meta = Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position)
            .with_ttl(Duration::from_secs(10))
            .with_ttl(Duration::from_secs(99));
        assert_eq!(meta.ttl, Some(Duration::from_secs(99)));
    }

    #[test]
    fn metadata_serde_round_trip_preserves_wire_format_for_default_ttl() {
        // Serialize-then-deserialize must reconstruct the original
        // value exactly. Pin this so the `#[non_exhaustive]` attribute
        // (which can subtly affect derived serde behavior on some
        // future compiler versions) does not silently change the wire
        // shape for a stock-built `Metadata::new(...)`.
        let original = Metadata::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            "tcp".into(),
            MessageType::Position,
        );
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: Metadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
        assert!(parsed.ttl.is_none(), "default ttl must round-trip as None");
    }

    #[test]
    fn metadata_serde_round_trip_preserves_wire_format_for_some_ttl() {
        // Same round-trip pin as above, but for the `Some(ttl)` branch:
        // the `#[serde(skip_serializing_if = "Option::is_none")]`
        // attribute must NOT skip a present `Some` value.
        let original = Metadata::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            "federation".into(),
            MessageType::Alert,
        )
        .with_ttl(Duration::from_secs(60));
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(
            json.contains("\"ttl\""),
            "wire format must include `ttl` field when Some, got {json}"
        );
        let parsed: Metadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
        assert_eq!(parsed.ttl, Some(Duration::from_secs(60)));
    }

    #[test]
    fn metadata_serde_existing_wire_format_still_deserializes() {
        // Pre-PR serializers (e.g. a future federation peer that built
        // its own JSON shape mirroring the struct fields) emit either
        // `"ttl": null` or omit the field entirely. Both shapes must
        // continue to deserialize cleanly so on-disk store-and-forward
        // queues written before this PR can be replayed by a binary
        // built after this PR. Pin both shapes.
        let with_explicit_null = "{\"received_at\":{\"secs_since_epoch\":1700000000,\"nanos_since_epoch\":0},\"source_protocol\":\"tcp\",\"message_type\":\"Position\",\"ttl\":null}";
        let parsed: Metadata = serde_json::from_str(with_explicit_null).expect("explicit null");
        assert!(parsed.ttl.is_none());

        let with_omitted_field = "{\"received_at\":{\"secs_since_epoch\":1700000000,\"nanos_since_epoch\":0},\"source_protocol\":\"tcp\",\"message_type\":\"Position\"}";
        let parsed: Metadata = serde_json::from_str(with_omitted_field).expect("omitted ttl");
        assert!(parsed.ttl.is_none());
    }

    #[test]
    fn metadata_struct_is_non_exhaustive_for_external_crates() {
        // Documentation pin: the struct is `#[non_exhaustive]`. External
        // crates cannot construct a `Metadata` via struct literal; they
        // must go through `Metadata::new(...)`. We cannot drive a
        // compile-fail test from here without `trybuild`, but we do pin
        // that the constructor + `with_ttl` builder produce a value
        // equal to the equivalent inline-built value, which is what
        // external code MUST rely on. A regression that changed the
        // builder default for `ttl` would be caught by the `is_none`
        // assertion in `metadata_new_initializes_optional_fields_to_none`.
        // This test exists to make the `#[non_exhaustive]` contract
        // discoverable to future maintainers via test name alone.
        let via_builder =
            Metadata::new(SystemTime::UNIX_EPOCH, "tcp".into(), MessageType::Position)
                .with_ttl(Duration::from_secs(10));
        assert_eq!(via_builder.ttl, Some(Duration::from_secs(10)));
    }

    // ── trace context coverage (closes #852, PR-C) ──────────────────

    /// Build a fixed-content [`crate::traceparent::TraceContext`] for
    /// trace-context unit-test fixtures. The trace_id / span_id values
    /// are the canonical W3C examples used by every other unit test in
    /// the workspace; pinning them here gives the audit-correlation
    /// assertions a stable hex tail to grep for.
    fn sample_trace_context() -> crate::traceparent::TraceContext {
        crate::traceparent::TraceContext::new(
            [
                0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
                0x47, 0x36,
            ],
            [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7],
            0x01,
        )
        .expect("valid trace context")
    }

    #[test]
    fn metadata_new_initializes_trace_context_to_none() {
        // Per PR-C of #852: `trace_context` is the latest optional field
        // and MUST default to `None` so existing call sites that did not
        // request a trace context behave identically to the pre-PR
        // baseline. A regression that forgot to zero this field inside
        // `Metadata::new` would be caught here at construction time
        // rather than at the federation forwarder where the misset
        // value would silently override the active OTel span.
        let meta = Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position);
        assert!(
            meta.trace_context.is_none(),
            "trace_context must default to None, got {:?}",
            meta.trace_context
        );
    }

    // ── classification field coverage (refs #849) ───────────────────

    #[test]
    fn metadata_new_initializes_classification_to_none() {
        // Constructor invariant: every optional field defaults to
        // `None` so existing call sites observe identical behaviour
        // before and after the additive #849 field landed. A regression
        // that defaulted to `Some(...)` would silently mark every
        // legacy message and tip the egress enforcement open.
        let meta = Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position);
        assert!(
            meta.classification.is_none(),
            "Metadata::new must default classification to None"
        );
    }

    #[test]
    fn metadata_with_trace_context_sets_field() {
        // Builder-style chain on `trace_context`: same contract as
        // `with_ttl` — the field is set, no other field is mutated, and
        // the call returns `Self` so it can chain after `with_ttl` /
        // `Metadata::new`.
        let ctx = sample_trace_context();
        let now = SystemTime::now();
        let meta = Metadata::new(now, "federation".into(), MessageType::Alert)
            .with_trace_context(ctx.clone());
        assert_eq!(meta.trace_context.as_ref(), Some(&ctx));
        assert_eq!(meta.received_at, now);
        assert_eq!(meta.source_protocol, "federation");
        assert_eq!(meta.message_type, MessageType::Alert);
        assert!(
            meta.ttl.is_none(),
            "ttl must remain untouched by with_trace_context"
        );
    }

    #[test]
    fn metadata_with_classification_sets_field() {
        // Builder pin: `with_classification` takes ownership of a
        // marking and returns the metadata with the field populated.
        // Pin both the field set and that the other fields are
        // untouched so a future refactor to the builder shape is
        // caught here rather than at every call site.
        use crate::classification::{Classification, ClassificationMarking};

        let now = SystemTime::now();
        let marking = ClassificationMarking::new(Classification::Secret);
        let meta = Metadata::new(now, "tcp".into(), MessageType::Position)
            .with_classification(marking.clone());
        assert_eq!(meta.classification, Some(marking));
        assert_eq!(meta.received_at, now);
        assert_eq!(meta.source_protocol, "tcp");
        assert_eq!(meta.message_type, MessageType::Position);
        assert!(
            meta.ttl.is_none(),
            "ttl must remain None after classification"
        );
    }

    #[test]
    fn metadata_serde_round_trip_preserves_trace_context_some() {
        // Round-trip a `Some(trace_context)` through serde_json and
        // assert (1) the wire format includes the `trace_context` key
        // and (2) the deserialized value compares equal to the original.
        // The `#[serde(into = "String", try_from = "String")]` delegation
        // on `TraceContext` means the JSON representation is the W3C
        // banner string, not a struct dump — pin that shape here so a
        // future serde-derive change cannot silently flip the wire form.
        let original = Metadata::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            "federation".into(),
            MessageType::Position,
        )
        .with_trace_context(sample_trace_context());
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(
            json.contains("\"trace_context\""),
            "wire format must include trace_context when Some, got {json}"
        );
        // Banner string is the canonical traceparent for the sample
        // context; confirms the `into = String` delegation fires.
        assert!(
            json.contains("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            "wire format must include the W3C banner string, got {json}"
        );
        let parsed: Metadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
        assert_eq!(parsed.trace_context.as_ref(), Some(&sample_trace_context()));
    }

    #[test]
    fn metadata_serde_round_trip_preserves_trace_context_none() {
        // Default `None` MUST round-trip cleanly without emitting a
        // `trace_context` field in the wire output — pin via the
        // `skip_serializing_if = "Option::is_none"` attribute. A
        // regression that emitted `"trace_context":null` would still
        // deserialize correctly but would inflate every routed message
        // on the wire by a non-trivial constant.
        let original = Metadata::new(SystemTime::UNIX_EPOCH, "tcp".into(), MessageType::Chat);
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(
            !json.contains("\"trace_context\""),
            "wire format must omit trace_context when None, got {json}"
        );
        let parsed: Metadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
        assert!(parsed.trace_context.is_none());
    }

    #[test]
    fn metadata_serde_old_wire_format_without_trace_context_field_still_deserializes() {
        // Wire-format compatibility: pre-PR-C peers (or on-disk store-
        // and-forward queues) emit metadata records without the
        // `trace_context` field. The `#[serde(default)]` attribute MUST
        // accept the absent field as `None` so a binary built with this
        // PR can replay queues written before #852 / #1293 / this PR.
        // The same shape with explicit `null` is also pinned for
        // belt-and-braces coverage.
        let with_omitted_field = "{\"received_at\":{\"secs_since_epoch\":1700000000,\"nanos_since_epoch\":0},\"source_protocol\":\"tcp\",\"message_type\":\"Position\"}";
        let parsed: Metadata =
            serde_json::from_str(with_omitted_field).expect("omitted trace_context");
        assert!(parsed.trace_context.is_none());
        assert!(parsed.ttl.is_none());

        let with_explicit_null = "{\"received_at\":{\"secs_since_epoch\":1700000000,\"nanos_since_epoch\":0},\"source_protocol\":\"tcp\",\"message_type\":\"Position\",\"trace_context\":null}";
        let parsed: Metadata =
            serde_json::from_str(with_explicit_null).expect("null trace_context");
        assert!(parsed.trace_context.is_none());
    }

    #[test]
    fn metadata_with_trace_context_overwrites_previous_value() {
        // Builder methods are idempotent under chained re-application —
        // calling `with_trace_context` twice replaces (not stacks) the
        // value. Mirrors the `with_ttl` invariant pinned above so the
        // contract is consistent across builder methods.
        let first = sample_trace_context();
        let second = crate::traceparent::TraceContext::new(
            [
                0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00,
            ],
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            0x00,
        )
        .expect("valid replacement context");
        let meta = Metadata::new(
            SystemTime::now(),
            "federation".into(),
            MessageType::Position,
        )
        .with_trace_context(first)
        .with_trace_context(second.clone());
        assert_eq!(meta.trace_context.as_ref(), Some(&second));
    }

    #[test]
    fn metadata_serde_round_trip_preserves_classification() {
        // Pin that a marking on the wire deserializes to an equivalent
        // marking — including the canonical CAPCO banner-string form
        // produced by `Display`. Pre-#849 federation peers do not emit
        // this field; post-#849 peers must round-trip cleanly.
        use crate::classification::ClassificationMarking;

        let marking: ClassificationMarking =
            "//SECRET//NOFORN".parse().expect("test fixture must parse");
        let original = Metadata::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            "tcp".into(),
            MessageType::Position,
        )
        .with_classification(marking.clone());
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(
            json.contains("\"classification\""),
            "wire format must include `classification` field when Some, got {json}"
        );
        assert!(
            json.contains("//SECRET//NOFORN"),
            "wire format must carry canonical banner string, got {json}"
        );
        let parsed: Metadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
        assert_eq!(parsed.classification, Some(marking));
    }

    // ── tenant_id builder coverage (closes #859) ────────────────────

    #[test]
    fn metadata_new_initializes_tenant_id_to_none() {
        // Constructor invariant for the additive #859 field: zero the
        // tenant slot so callers that did not opt-in observe identical
        // pre-PR behaviour. A regression that defaulted to a placeholder
        // tenant would silently route every message into one tenant
        // bucket on disk.
        let meta = Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position);
        assert!(
            meta.tenant_id.is_none(),
            "Metadata::new must default tenant_id to None"
        );
        assert!(meta.tenant_id().is_none());
    }

    #[test]
    fn metadata_with_tenant_id_sets_field_and_accessor_agrees() {
        // Builder-pin: `with_tenant_id` populates the field, returns
        // `Self` for chaining, and the accessor mirrors the value
        // verbatim. Pin both so a future refactor that diverged the
        // field and the accessor (e.g. lower-cased only one of them)
        // surfaces here, not at the archive directory layout test.
        let meta = Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position)
            .with_tenant_id("acme");
        assert_eq!(meta.tenant_id.as_deref(), Some("acme"));
        assert_eq!(meta.tenant_id(), Some("acme"));
    }

    #[test]
    fn metadata_with_tenant_id_empty_string_collapses_to_none() {
        // Empty-string tenant is treated as absent so cert Organization
        // == "" matches the same code path as legacy traffic. A
        // regression that stored `Some("")` would create an archive
        // subdirectory with an empty path component (`<dir>//cot-…`)
        // and break the rotation sweep.
        let meta = Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position)
            .with_tenant_id("");
        assert!(meta.tenant_id.is_none());
        assert!(meta.tenant_id().is_none());
    }

    #[test]
    fn metadata_with_tenant_id_overwrites_previous_value() {
        // Mirrors the with_ttl / with_trace_context idempotency pin.
        let meta = Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position)
            .with_tenant_id("acme")
            .with_tenant_id("globex");
        assert_eq!(meta.tenant_id.as_deref(), Some("globex"));
    }

    #[test]
    fn metadata_serde_round_trip_preserves_tenant_id() {
        // Pin that a `Some(tenant)` round-trips through the wire form
        // unchanged and the JSON includes the explicit field.
        let original = Metadata::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            "tcp".into(),
            MessageType::Position,
        )
        .with_tenant_id("coalition-a");
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(
            json.contains("\"tenant_id\""),
            "wire format must include tenant_id when Some, got {json}"
        );
        assert!(json.contains("coalition-a"));
        let parsed: Metadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
        assert_eq!(parsed.tenant_id.as_deref(), Some("coalition-a"));
    }

    #[test]
    fn metadata_serde_old_wire_format_without_tenant_id_still_deserializes() {
        // Backward compat: pre-#859 federation peers and on-disk
        // store-and-forward queues do not include the `tenant_id` key.
        // Both omitted-field and explicit-null shapes must continue to
        // deserialize cleanly so a binary built with this PR can replay
        // older queues without a one-shot migration.
        let with_omitted = "{\"received_at\":{\"secs_since_epoch\":1700000000,\"nanos_since_epoch\":0},\"source_protocol\":\"tcp\",\"message_type\":\"Position\"}";
        let parsed: Metadata = serde_json::from_str(with_omitted).expect("omitted tenant");
        assert!(parsed.tenant_id.is_none());

        let with_null = "{\"received_at\":{\"secs_since_epoch\":1700000000,\"nanos_since_epoch\":0},\"source_protocol\":\"tcp\",\"message_type\":\"Position\",\"tenant_id\":null}";
        let parsed: Metadata = serde_json::from_str(with_null).expect("null tenant");
        assert!(parsed.tenant_id.is_none());
    }

    #[test]
    fn metadata_serde_omits_tenant_id_when_none() {
        // Wire-size invariant: skip-serializing on `None` keeps the
        // legacy bytes-on-the-wire shape, so a federation peer that has
        // not opted in pays no size penalty for the new field.
        let original = Metadata::new(SystemTime::UNIX_EPOCH, "tcp".into(), MessageType::Chat);
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(
            !json.contains("\"tenant_id\""),
            "wire format must omit tenant_id when None, got {json}"
        );
    }

    #[test]
    fn metadata_serde_old_wire_format_without_classification_still_deserializes() {
        // Backward-compatibility pin (#849): pre-#849 peers serialise
        // `Metadata` without the `classification` key. Their wire form
        // — both `"classification": null` and the omitted-field shape
        // — must continue to deserialise cleanly so on-disk
        // store-and-forward queues written before this PR can replay
        // post-PR. A regression that removed the
        // `#[serde(default, skip_serializing_if = "Option::is_none")]`
        // attribute would surface here.
        let with_explicit_null = "{\
            \"received_at\":{\"secs_since_epoch\":1700000000,\"nanos_since_epoch\":0},\
            \"source_protocol\":\"tcp\",\
            \"message_type\":\"Position\",\
            \"classification\":null}";
        let parsed: Metadata = serde_json::from_str(with_explicit_null).expect("explicit null");
        assert!(parsed.classification.is_none());

        let with_omitted_field = "{\
            \"received_at\":{\"secs_since_epoch\":1700000000,\"nanos_since_epoch\":0},\
            \"source_protocol\":\"tcp\",\
            \"message_type\":\"Position\"}";
        let parsed: Metadata = serde_json::from_str(with_omitted_field).expect("omitted field");
        assert!(parsed.classification.is_none());

        // And a present marking deserializes to Some.
        let with_marking = "{\
            \"received_at\":{\"secs_since_epoch\":1700000000,\"nanos_since_epoch\":0},\
            \"source_protocol\":\"tcp\",\
            \"message_type\":\"Position\",\
            \"classification\":\"//UNCLASSIFIED//\"}";
        let parsed: Metadata = serde_json::from_str(with_marking).expect("with marking");
        assert!(parsed.classification.is_some());
    }

    // ── attached-entity builder coverage (refs #1540, ADR 0035) ──────

    fn sample_message() -> RoutableMessage {
        RoutableMessage {
            source: Identity {
                cn: "alice".into(),
                fingerprint: "fp".into(),
                groups: std::collections::BTreeSet::new(),
                tenant: None,
                spiffe_id: None,
                attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
            },
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event/>"),
            metadata: Metadata::new(SystemTime::now(), "cot".into(), MessageType::Position),
            entity: None,
        }
    }

    fn sample_entity() -> crate::entity::Entity {
        crate::entity::Entity {
            uid: "track-1".into(),
            kind: crate::entity::EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: std::collections::BTreeMap::new(),
            taskings: Vec::new(),
            files: Vec::new(),
        }
    }

    #[test]
    fn routable_message_defaults_entity_to_none() {
        // The additive #1540 field must default to `None` at every
        // construction site so the attach is purely opt-in — a
        // regression that materialised a placeholder entity would
        // change the Foundry/inference fast-path selection for every
        // legacy message.
        let msg = sample_message();
        assert!(
            msg.entity.is_none(),
            "a plain RoutableMessage must carry no attached entity"
        );
    }

    #[test]
    fn routable_message_with_entity_attaches_and_wraps_in_arc() {
        // `with_entity` populates the slot, returns `Self` for chaining,
        // and leaves every other field untouched. Pin that the attached
        // entity round-trips by value so the Foundry/inference seams see
        // exactly what was attached.
        let entity = sample_entity();
        let msg = sample_message().with_entity(entity.clone());
        let attached = msg.entity.as_ref().expect("entity must be attached");
        assert_eq!(**attached, entity);
        // Other fields are unchanged by the builder.
        assert_eq!(msg.metadata.source_protocol, "cot");
        assert!(matches!(msg.destination, Destination::Broadcast));
    }

    #[test]
    fn routable_message_with_entity_clone_shares_entity_arc() {
        // The attach is `Arc`-wrapped so cloning the envelope for
        // per-recipient fan-out is a refcount bump, not a deep copy of
        // the entity. Pin the pointer-sharing contract so a regression
        // to a bare `Entity` (which would deep-copy on every fan-out
        // clone) fails here.
        let msg = sample_message().with_entity(sample_entity());
        let cloned = msg.clone();
        let a = msg.entity.as_ref().expect("orig entity");
        let b = cloned.entity.as_ref().expect("cloned entity");
        assert!(
            Arc::ptr_eq(a, b),
            "clone must share the attached-entity Arc, not deep-copy it"
        );
    }
}
