// Copyright © 2026 Roberto Chiofalo.

//! Configuration for the MQTT server.

use std::sync::Arc;

use rustgate_core::egress::{OnFederationForward, OnHttpForward, OnNatsPublish};
use rustgate_transport::Router;
use tokio::sync::{Notify, Semaphore};

use crate::listener::MqttListener;
use crate::topic::WildcardPolicy;

/// Callback invoked once per mTLS-authenticated MQTT session immediately
/// after the permit is acquired and before the session task is spawned.
///
/// Wired by the server crate to feed the `rustgate_mqtt_connections_total`
/// Prometheus counter. Kept as a simple `Fn()` so the `rustgate-mqtt`
/// crate stays metrics-agnostic and does not grow a `prometheus`
/// dependency.
pub type OnMqttAccept = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked when a TLS-authenticated MQTT connection is rejected
/// because the shared cross-transport connection-limit semaphore is
/// saturated.
///
/// Wired by the server crate to feed the
/// `rustgate_mqtt_connections_rejected_total` Prometheus counter. Fires
/// *after* the listener-layer rejections (TLS failure, cert validation,
/// per-IP rate limit) because those paths return `Ok(None)` from
/// [`MqttListener::accept`](crate::MqttListener::accept) and never reach
/// the permit gate.
pub type OnMqttReject = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked once per MQTT PUBLISH that is authorised and handed
/// to the router for delivery.
///
/// Wired by the server crate to feed the `rustgate_mqtt_publishes_total`
/// Prometheus counter. Fires exactly once per successful PUBLISH — after
/// topic validation, prefix mapping, and group-membership authorisation
/// pass, and immediately before the router forwards the envelope.
pub type OnMqttPublish = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked once per MQTT PUBLISH that is rejected by the
/// session handler (QoS2 unsupported, invalid topic, or not authorised
/// for the resolved group).
///
/// Wired by the server crate to feed the
/// `rustgate_mqtt_publishes_rejected_total` Prometheus counter. Fires
/// exactly once per rejected PUBLISH regardless of which validation
/// branch triggered the refusal, so operators get a single admission-
/// failure signal without per-reason cardinality.
pub type OnMqttPublishReject = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked once per SUBSCRIBE topic filter that is successfully
/// bound to an authorised group.
///
/// Wired by the server crate to feed the `rustgate_mqtt_subscribes_total`
/// Prometheus counter. Fires *per filter*, not per SUBSCRIBE packet — a
/// single MQTT SUBSCRIBE with three wildcard filters may produce up to
/// three increments — so the counter tracks actual group bindings rather
/// than packet counts.
pub type OnMqttSubscribe = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked once per SUBSCRIBE topic filter that is rejected by
/// the session handler (QoS2 unsupported, filter invalid under the
/// active wildcard policy, or not authorised for any resolved group).
///
/// Wired by the server crate to feed the
/// `rustgate_mqtt_subscribes_rejected_total` Prometheus counter. Fires
/// *per filter*, mirroring [`OnMqttSubscribe`] — a SUBSCRIBE with three
/// filters where two are denied produces two increments on this counter
/// and one on [`OnMqttSubscribe`].
pub type OnMqttSubscribeReject = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked once per PUBLISH whose `retain=1` flag and non-empty
/// payload caused the broker's `RetainStore` to insert or overwrite the
/// last-known-value entry for the published topic.
///
/// Wired by the server crate to feed the
/// `rustgate_mqtt_retain_stored_total` Prometheus counter. Fires AFTER
/// authorisation succeeds and AFTER the store is updated, so the
/// counter always reflects entries actually persisted in the cache.
pub type OnMqttRetainStored = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked once per PUBLISH whose `retain=1` flag combined
/// with a zero-byte payload caused the broker's `RetainStore` to
/// remove the entry for the published topic, per MQTT 5.0 §3.3.1.3.
///
/// Wired by the server crate to feed the
/// `rustgate_mqtt_retain_cleared_total` Prometheus counter. Fires
/// regardless of whether an entry was actually present in the store
/// (the spec mandates the clear semantics; the counter measures
/// operator-issued clears, not just cache-state transitions). Pairs
/// with [`OnMqttRetainStored`] for a complete picture of retain
/// store mutations.
pub type OnMqttRetainCleared = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked once per retained `PUBLISH` packet replayed to a
/// fresh subscriber on a successful `SUBSCRIBE`. Fires *per delivered
/// retained message*, not per SUBSCRIBE packet — a single SUBSCRIBE
/// whose filter matches three retained topics produces three
/// increments.
///
/// Wired by the server crate to feed the
/// `rustgate_mqtt_retain_replayed_total` Prometheus counter. The
/// authorisation re-check runs before the callback fires, so the
/// counter only ever counts replays the subscriber was actually
/// allowed to receive — a metric used to detect retain-fan-out
/// patterns (e.g. a wildcard subscribe expanding to thousands of
/// retained topics) ahead of throughput-related operational issues.
pub type OnMqttRetainReplayed = Arc<dyn Fn() + Send + Sync>;
/// Callback invoked exactly once per will message published on a
/// client's behalf when the connection ended ungracefully (TLS error,
/// keep-alive timeout, write-loop early exit, abrupt TCP close — any
/// path that is NOT a clean DISCONNECT). Fires AFTER the will payload
/// has been routed via `Router::route_for_egress`, regardless of
/// whether the router accepted or dropped the message — the callback
/// records the broker's decision to fire the will, not the eventual
/// delivery outcome.
///
/// Wired by the server crate to feed the
/// `rustgate_mqtt_will_published_total` Prometheus counter. A spike on
/// this counter typically correlates with a partition or a fleet of
/// clients hitting their keep-alive timeout — the operational signal
/// is "presence-loss is happening at scale, look at the network".
pub type OnMqttWillPublished = Arc<dyn Fn() + Send + Sync>;

/// Bundle of session-level observer callbacks (publish accept/reject,
/// subscribe accept/reject) passed through to every spawned MQTT
/// session.
///
/// Packaged as a single struct so that threading the four callbacks
/// through the already-large `handle_mqtt_session` call does not push
/// the argument count above the documented `#[allow(clippy::too_many_
/// arguments)]` justification. The four fields are fired independently
/// at the publish and subscribe hot paths; a `None` field leaves the
/// corresponding hot path untouched.
#[derive(Default, Clone)]
pub struct MqttSessionHooks {
    /// Fires after a PUBLISH is handed to the router. See
    /// [`OnMqttPublish`].
    pub on_publish: Option<OnMqttPublish>,

    /// Fires when a PUBLISH is rejected. See [`OnMqttPublishReject`].
    pub on_publish_reject: Option<OnMqttPublishReject>,

    /// Fires per accepted SUBSCRIBE filter. See [`OnMqttSubscribe`].
    pub on_subscribe: Option<OnMqttSubscribe>,

    /// Fires per rejected SUBSCRIBE filter. See
    /// [`OnMqttSubscribeReject`].
    pub on_subscribe_reject: Option<OnMqttSubscribeReject>,

    /// Fires per PUBLISH that stored a retained message. See
    /// [`OnMqttRetainStored`].
    pub on_retain_stored: Option<OnMqttRetainStored>,

    /// Fires per PUBLISH that cleared a retained entry via the
    /// MQTT 5.0 §3.3.1.3 zero-byte clear semantic. See
    /// [`OnMqttRetainCleared`].
    pub on_retain_cleared: Option<OnMqttRetainCleared>,

    /// Fires per retained PUBLISH delivered to a fresh subscriber. See
    /// [`OnMqttRetainReplayed`].
    pub on_retain_replayed: Option<OnMqttRetainReplayed>,
    /// Fires once per will message published on ungraceful disconnect.
    /// See [`OnMqttWillPublished`].
    pub on_will_published: Option<OnMqttWillPublished>,
}

impl std::fmt::Debug for MqttSessionHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fmt_cb = |cb: &Option<Arc<dyn Fn() + Send + Sync>>| {
            if cb.is_some() { "Some(<cb>)" } else { "None" }
        };
        f.debug_struct("MqttSessionHooks")
            .field("on_publish", &fmt_cb(&self.on_publish))
            .field("on_publish_reject", &fmt_cb(&self.on_publish_reject))
            .field("on_subscribe", &fmt_cb(&self.on_subscribe))
            .field("on_subscribe_reject", &fmt_cb(&self.on_subscribe_reject))
            .field("on_retain_stored", &fmt_cb(&self.on_retain_stored))
            .field("on_retain_cleared", &fmt_cb(&self.on_retain_cleared))
            .field("on_retain_replayed", &fmt_cb(&self.on_retain_replayed))
            .field("on_will_published", &fmt_cb(&self.on_will_published))
            .finish()
    }
}

/// Bundle of post-route egress forwarding callbacks fired by the MQTT
/// session on the PUBLISH hot path.
///
/// Mirrors the three sinks already wired on the WebSocket transport
/// (NATS bridge, federation forwarder, HTTP egress) so that MQTT
/// PUBLISHes participate in horizontal scale-out, server-to-server
/// mesh delivery, and webhook fan-out with the same post-Send-PEP
/// payload the router produces. Each field is an independent optional
/// sink — `None` skips the corresponding fan-out at no runtime cost.
///
/// Packaged as a single struct so threading the three callbacks
/// through the already-large `handle_mqtt_session` call (which carries
/// a narrow `#[allow(clippy::too_many_arguments)]` justification) does
/// not push the argument count further. The alias types live in
/// `rustgate_core::egress` so the same shapes are shared workspace-
/// wide.
#[derive(Default, Clone)]
pub struct MqttForwardingHooks {
    /// Fires after a successful local route to hand the message off to
    /// the NATS publisher. See
    /// [`OnNatsPublish`](rustgate_core::egress::OnNatsPublish).
    pub nats_publish: Option<OnNatsPublish>,

    /// Fires after a successful local route to hand the payload off to
    /// the federation forwarder. See
    /// [`OnFederationForward`](rustgate_core::egress::OnFederationForward).
    pub federation_forward: Option<OnFederationForward>,

    /// Fires after a successful local route to hand the message off to
    /// the HTTP egress publisher. See
    /// [`OnHttpForward`](rustgate_core::egress::OnHttpForward).
    pub http_forward: Option<OnHttpForward>,
}

impl std::fmt::Debug for MqttForwardingHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fmt_cb = |present: bool| if present { "Some(<cb>)" } else { "None" };
        f.debug_struct("MqttForwardingHooks")
            .field("nats_publish", &fmt_cb(self.nats_publish.is_some()))
            .field(
                "federation_forward",
                &fmt_cb(self.federation_forward.is_some()),
            )
            .field("http_forward", &fmt_cb(self.http_forward.is_some()))
            .finish()
    }
}

/// Configuration for [`MqttServer::run`](crate::MqttServer::run).
pub struct MqttServerConfig {
    /// The bound MQTT TLS listener.
    pub listener: MqttListener,

    /// Shared router for message delivery.
    pub router: Arc<Router>,

    /// Connection-limit semaphore shared across all transports.
    pub connection_limit: Arc<Semaphore>,

    /// Shutdown signal.
    pub shutdown: Arc<Notify>,

    /// Optional prefix to strip from MQTT topics before mapping to groups.
    ///
    /// For example, with `topic_prefix = Some("rustgate/".into())`, the MQTT
    /// topic `rustgate/alpha` maps to group `alpha`. Topics that do not start
    /// with the prefix are rejected.
    pub topic_prefix: Option<String>,

    /// Maximum MQTT packet size in bytes (default: 16 MiB).
    pub max_packet_size: usize,

    /// Maximum number of QoS 1 / QoS 2 PUBLISHes a client may have
    /// in-flight to the broker without intervening acks (default: 32).
    ///
    /// Advertised in CONNACK as MQTT 5.0 §3.2.2.3.3 `Receive Maximum`
    /// so a compliant client self-limits and the broker has a known
    /// concurrency cap to plan against. The wire field is a `u16` so
    /// the operator cannot configure a value above 65535 (the spec's
    /// implicit default when the property is absent — i.e. "no limit
    /// beyond the wire field's range"). The default of 32 is a
    /// conservative starting point; a deployment with high-throughput
    /// QoS 1 traffic can raise it but must accept the additional
    /// session-state memory cost (each in-flight PUBLISH consumes its
    /// payload size in the read buffer until ack-and-route completes).
    pub receive_max: u16,

    /// Maximum MQTT 5.0 `Topic Alias` value the broker will accept on
    /// inbound PUBLISHes from this client (default: 0 = topic aliases
    /// disabled).
    ///
    /// Advertised in CONNACK as MQTT 5.0 §3.2.2.3.8 `Topic Alias
    /// Maximum`. A non-zero value enables a per-connection alias
    /// table where the client can establish `topic="foo/bar" + alias=N`
    /// in one PUBLISH and then send subsequent PUBLISHes with empty
    /// topic + alias=N — useful when the topic name is long and the
    /// PUBLISHes are frequent. Per §3.3.2.3.4, an alias outside
    /// `[1, advertised_max]` is a Protocol Error and the broker MUST
    /// respond with DISCONNECT reason code 0x94 (TopicAliasInvalid).
    /// Default `0` disables the feature; any inbound PUBLISH carrying
    /// a Topic Alias triggers DISCONNECT.
    ///
    /// Memory cost: O(advertised_max) per connection for the alias
    /// table. The default of 0 is conservative; tactical deployments
    /// with high-frequency publishers on a small set of long topics
    /// benefit from a modest cap (8-32).
    pub topic_alias_max: u16,

    /// Maximum MQTT 5.0 `Session Expiry Interval` (in seconds) the broker
    /// will honor for retained sessions (default: 0 = retention disabled).
    ///
    /// When `0`, the broker advertises Session Expiry Interval = 0 in
    /// CONNACK (regardless of what the client requested) and continues
    /// to reject `clean_start = 0` outright — preserving the v1.0
    /// behaviour from #1162. Set to `> 0` to enable session retention
    /// per MQTT 5.0 §3.1.2.11.2; the negotiated expiry returned in
    /// CONNACK is `min(client_request, max_session_expiry_secs)`.
    /// Special value `u32::MAX` means "no operator cap" — honor the
    /// client's request verbatim, including the spec's "never expires"
    /// sentinel.
    ///
    /// Sessions consume O(subscriptions) memory per retained client
    /// for the duration of their expiry window; pair this with
    /// [`max_retained_sessions`](Self::max_retained_sessions) to bound
    /// total memory footprint.
    pub max_session_expiry_secs: u32,

    /// Hard cap on the number of simultaneously-retained MQTT
    /// sessions (default: 1024). Only meaningful when
    /// [`max_session_expiry_secs`](Self::max_session_expiry_secs) > 0.
    /// When the store is full, the oldest entry by disconnect time
    /// is evicted to make room — the assumption being that recent
    /// disconnects are more likely to reconnect than stale ones.
    /// A new session for a client_id already in the store overwrites
    /// the existing entry per MQTT 5.0 §3.1.4 server-takeover
    /// semantics, regardless of the cap.
    pub max_retained_sessions: usize,

    /// Minimum keep-alive interval in seconds. Clients requesting 0
    /// (disabled) or a value below this floor get this value imposed.
    pub min_keep_alive_secs: u16,

    /// MQTT 5.0 `Server Keep Alive` override advertised in CONNACK
    /// (default: `0` = no override; broker honors the client's
    /// CONNECT-time keep-alive request).
    ///
    /// Per MQTT 5.0 §3.2.2.3.14: "If the Server returns a Server Keep
    /// Alive on the CONNACK packet, the Client MUST use this value
    /// instead of the Keep Alive value the Client sent on CONNECT."
    /// When configured to a non-zero value, the broker:
    /// 1. Sets `properties.server_keep_alive = Some(server_keep_alive_secs)`
    ///    on every v5 CONNACK so a compliant client switches to the
    ///    overridden interval.
    /// 2. Enforces the overridden interval on the read-loop keep-alive
    ///    timer instead of the client's request, so a non-compliant
    ///    client that ignores the property still gets disconnected on
    ///    the operator's chosen schedule rather than the client's.
    ///
    /// When `0` (default), the broker leaves the property unset and
    /// honors the client's CONNECT-time keep-alive verbatim — preserving
    /// the pre-this-knob behaviour for deployments that don't need the
    /// override channel.
    ///
    /// v3.1.1 has no Server Keep Alive feature; the v4 path is unaffected
    /// regardless of this setting.
    pub server_keep_alive_secs: u16,

    /// Channel capacity for response packets flowing from read loop to
    /// write loop (per session).
    pub response_channel_capacity: usize,

    /// Wildcard policy applied to SUBSCRIBE topic filters.
    ///
    /// Default is [`WildcardPolicy::SingleLevelOnly`], which accepts `+`
    /// (single-level) filters such as `fleet/+/position` but rejects `#`
    /// (multi-level). Set to [`WildcardPolicy::Full`] on listeners where
    /// authorised clients legitimately need full-subtree subscriptions;
    /// set to [`WildcardPolicy::Reject`] to match pre-wildcard behaviour.
    pub wildcard_policy: WildcardPolicy,

    /// Optional observer called once per mTLS-authenticated MQTT session
    /// accepted by the server. `None` leaves the accept path untouched;
    /// the server crate installs a closure that increments
    /// `rustgate_mqtt_connections_total`. See [`OnMqttAccept`].
    pub on_accept: Option<OnMqttAccept>,

    /// Optional observer called once per connection-limit rejection.
    /// `None` leaves the reject path untouched; the server crate installs
    /// a closure that increments `rustgate_mqtt_connections_rejected_total`.
    /// See [`OnMqttReject`].
    pub on_reject: Option<OnMqttReject>,

    /// Optional per-session observer callbacks for PUBLISH / SUBSCRIBE
    /// admission outcomes. `None` leaves every hot path untouched; the
    /// server crate installs closures that increment the
    /// `rustgate_mqtt_{publishes,subscribes}{_rejected,}_total` Prometheus
    /// counters. See [`MqttSessionHooks`].
    pub session_hooks: Option<MqttSessionHooks>,

    /// Optional post-route egress forwarding callbacks (NATS bridge,
    /// federation forwarder, HTTP egress). `None` disables every fan-
    /// out at no runtime cost. The server crate wires these under
    /// `#[cfg(feature = "nats|federation|http")]` blocks so MQTT
    /// PUBLISHes participate in the same scale-out / mesh / webhook
    /// paths already used by the WebSocket transport. See
    /// [`MqttForwardingHooks`].
    pub forwarding_hooks: Option<MqttForwardingHooks>,
}

impl MqttServerConfig {
    /// Default maximum packet size: 16 MiB (matches websocket frame cap).
    pub const DEFAULT_MAX_PACKET_SIZE: usize = 16 * 1024 * 1024;

    /// Default maximum `Session Expiry Interval` (0 — retention OFF).
    ///
    /// Disabled by default to preserve the v1.0 broker contract: a
    /// fresh deployment that doesn't opt in via
    /// [`max_session_expiry_secs`](Self::max_session_expiry_secs) keeps
    /// the existing "clean_start=1 only, sessions never persist"
    /// behaviour from before #1163. Operators turn this on
    /// deliberately, accepting the additional memory cost +
    /// reconnection-resumption semantics that come with it.
    pub const DEFAULT_MAX_SESSION_EXPIRY_SECS: u32 = 0;

    /// Default cap on retained sessions (1024).
    pub const DEFAULT_MAX_RETAINED_SESSIONS: usize = 1024;

    /// Default `Receive Maximum` advertised in CONNACK (32).
    ///
    /// Sized to match the default `response_channel_capacity` (64) at
    /// roughly half — the inflight cap should be smaller than the
    /// session's outbound channel cap so a client maxing out its
    /// allowed pipelining cannot also fill the response channel and
    /// block the write loop. Operators can raise this for a
    /// throughput-sensitive deployment but should raise the response
    /// channel cap proportionally.
    pub const DEFAULT_RECEIVE_MAX: u16 = 32;

    /// Default `Topic Alias Maximum` advertised in CONNACK (0 — disabled).
    ///
    /// Disabled by default: the feature is a bandwidth optimization
    /// for repeated long-topic PUBLISHes, not a correctness requirement,
    /// and most fleets don't need it. Operators turn it on by setting
    /// a non-zero cap when their workload profile (long topics +
    /// high frequency) justifies the per-connection memory overhead.
    pub const DEFAULT_TOPIC_ALIAS_MAX: u16 = 0;

    /// Default `Server Keep Alive` override advertised in CONNACK
    /// (0 — no override; honor the client's request).
    ///
    /// Disabled by default: the spec leaves keep-alive negotiation as
    /// "client proposes, broker may override," and most deployments
    /// trust the client's choice. Operators turn it on when fleet-wide
    /// presence-loss detection needs a uniform cadence (e.g. to align
    /// dashboards or rate-limit ungraceful-disconnect storms) rather
    /// than each client's idiosyncratic value.
    pub const DEFAULT_SERVER_KEEP_ALIVE_SECS: u16 = 0;

    /// Default minimum keep-alive in seconds.
    pub const DEFAULT_MIN_KEEP_ALIVE_SECS: u16 = 30;

    /// Default response channel capacity per session.
    pub const DEFAULT_RESPONSE_CHANNEL_CAPACITY: usize = 64;
}

impl std::fmt::Debug for MqttServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MqttServerConfig")
            .field("listener", &self.listener)
            .field("router", &"<Router>")
            .field("connection_limit", &"<Semaphore>")
            .field("shutdown", &"<Notify>")
            .field("topic_prefix", &self.topic_prefix)
            .field("max_packet_size", &self.max_packet_size)
            .field("receive_max", &self.receive_max)
            .field("topic_alias_max", &self.topic_alias_max)
            .field("max_session_expiry_secs", &self.max_session_expiry_secs)
            .field("max_retained_sessions", &self.max_retained_sessions)
            .field("min_keep_alive_secs", &self.min_keep_alive_secs)
            .field("server_keep_alive_secs", &self.server_keep_alive_secs)
            .field("response_channel_capacity", &self.response_channel_capacity)
            .field("wildcard_policy", &self.wildcard_policy)
            .field(
                "on_accept",
                &if self.on_accept.is_some() {
                    "Some(<cb>)"
                } else {
                    "None"
                },
            )
            .field(
                "on_reject",
                &if self.on_reject.is_some() {
                    "Some(<cb>)"
                } else {
                    "None"
                },
            )
            .field("session_hooks", &self.session_hooks)
            .field("forwarding_hooks", &self.forwarding_hooks)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use rustgate_core::constants::MAX_FRAME_SIZE;

    use super::*;

    // ------------------------------------------------------------------
    // Default constants — pin the wire / operator-visible numbers.
    // Changing any of these affects CONNACK negotiation, keep-alive
    // floors, and session memory footprint, so a silent drift in the
    // constant is exactly the sort of thing this test catches.
    // ------------------------------------------------------------------

    #[test]
    fn default_max_packet_size_is_sixteen_mib() {
        // 16 MiB keeps MQTT in lockstep with the websocket frame cap
        // and with `rustgate_core::constants::MAX_FRAME_SIZE`.
        assert_eq!(MqttServerConfig::DEFAULT_MAX_PACKET_SIZE, 16 * 1024 * 1024,);
        assert_eq!(MqttServerConfig::DEFAULT_MAX_PACKET_SIZE, 16_777_216);
    }

    #[test]
    fn default_max_packet_size_matches_shared_frame_cap() {
        // Cross-check that the MQTT default does not drift away from
        // the workspace-wide shared frame cap used by the length-
        // prefixed and protobuf codecs.
        assert_eq!(MqttServerConfig::DEFAULT_MAX_PACKET_SIZE, MAX_FRAME_SIZE,);
    }

    #[test]
    fn default_min_keep_alive_is_thirty_seconds() {
        // Clients requesting 0 (disabled) or a smaller value have this
        // value forced upon them — changing it alters CONNACK behaviour.
        assert_eq!(MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS, 30);
    }

    #[test]
    fn default_server_keep_alive_is_zero_meaning_no_override() {
        // The default 0 preserves the pre-this-knob behaviour: the
        // broker honors the client's CONNECT-time keep-alive request
        // verbatim. A regression that flipped this default to a
        // non-zero value would force every connecting client onto a
        // broker-imposed cadence and would surface immediately in the
        // CONNACK property assertions in the integration suite.
        assert_eq!(MqttServerConfig::DEFAULT_SERVER_KEEP_ALIVE_SECS, 0);
    }

    #[test]
    fn default_response_channel_capacity_is_sixty_four() {
        // Per-session backpressure boundary between the read loop and
        // the write loop. Changing this affects memory accounting in
        // tests that assert queue depth.
        assert_eq!(MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY, 64);
    }

    // ------------------------------------------------------------------
    // Trait bounds — pin compile-time invariants cheaply, without
    // spinning up a Router / TLS stack just to test `Debug`.
    // ------------------------------------------------------------------

    #[test]
    fn config_type_is_debug() {
        // The `#[derive(Debug)]` must remain — tracing expansions such
        // as `tracing::info!(?config, ...)` would fail to compile if a
        // future refactor accidentally dropped the derive.
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<MqttServerConfig>();
    }

    // ------------------------------------------------------------------
    // Observer callback plumbing — the `on_accept` / `on_reject` fields
    // are the mechanism by which the server crate feeds
    // `rustgate_mqtt_connections_total` and `rustgate_mqtt_connections_
    // rejected_total` without `rustgate-mqtt` growing a `prometheus`
    // dependency. These tests pin the type aliases, the `None` default
    // equivalent, and the manual `Debug` impl rendering, so a refactor
    // that narrows the callback signature or swaps the `Option<Arc<…>>`
    // holder would fail here before the server crate's wiring breaks.
    // ------------------------------------------------------------------

    #[test]
    fn on_accept_type_is_send_sync_arc_fn() {
        // Pins the callback bound end-to-end so the server crate can
        // share the closure across task boundaries. A change to the
        // `+ Send + Sync` requirement would force a different spelling
        // at every call site and land as a compile error here first.
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnMqttAccept = Arc::new(|| {});
        assert_bounds(&cb);
    }

    #[test]
    fn on_reject_type_is_send_sync_arc_fn() {
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnMqttReject = Arc::new(|| {});
        assert_bounds(&cb);
    }

    #[tokio::test]
    async fn debug_none_observers_render_as_none() {
        // The manual `Debug` impl must keep the `on_accept: "None"` /
        // `on_reject: "None"` sentinels so operator log greps see the
        // wiring state. A regression that accidentally printed the raw
        // Option (which would try to render the non-Debug `Arc<dyn Fn>`
        // and fail) is caught here.
        let ca = rustgate_test_utils::certs::TestCa::new("debug-none-test");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let tls = rustgate_transport::TlsConfig::from_pem(
            &server.cert_pem,
            &server.key_pem,
            &ca.cert_pem,
        )
        .expect("TlsConfig from fresh test certs");
        let listener = MqttListener::bind("127.0.0.1:0".parse().unwrap(), &tls).expect("bind");
        let config = MqttServerConfig {
            listener,
            router: Arc::new(Router::default()),
            connection_limit: Arc::new(Semaphore::new(1)),
            shutdown: Arc::new(Notify::new()),
            topic_prefix: None,
            max_packet_size: 1024,
            receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
            topic_alias_max: MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX,
            max_session_expiry_secs: MqttServerConfig::DEFAULT_MAX_SESSION_EXPIRY_SECS,
            max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
            min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
            server_keep_alive_secs: MqttServerConfig::DEFAULT_SERVER_KEEP_ALIVE_SECS,
            response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
            wildcard_policy: WildcardPolicy::default(),
            on_accept: None,
            on_reject: None,
            session_hooks: None,
            forwarding_hooks: None,
        };
        let rendered = format!("{config:?}");
        assert!(
            rendered.contains("on_accept: \"None\""),
            "Debug output must contain `on_accept: \"None\"` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("on_reject: \"None\""),
            "Debug output must contain `on_reject: \"None\"` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("forwarding_hooks: None"),
            "Debug output must contain `forwarding_hooks: None` sentinel, got: {rendered}",
        );
    }

    #[tokio::test]
    async fn debug_some_observers_render_as_cb_sentinel() {
        // Mirror of `debug_none_observers_render_as_none` but installs
        // both callbacks so the `Some(<cb>)` branch is exercised. This
        // is the more operationally-relevant render (production always
        // installs callbacks under `--features metrics`), so a silent
        // regression to the `None` branch would leave the operator
        // unable to tell whether observers are wired at all.
        let ca = rustgate_test_utils::certs::TestCa::new("debug-some-test");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let tls = rustgate_transport::TlsConfig::from_pem(
            &server.cert_pem,
            &server.key_pem,
            &ca.cert_pem,
        )
        .expect("TlsConfig from fresh test certs");
        let listener = MqttListener::bind("127.0.0.1:0".parse().unwrap(), &tls).expect("bind");
        let config = MqttServerConfig {
            listener,
            router: Arc::new(Router::default()),
            connection_limit: Arc::new(Semaphore::new(1)),
            shutdown: Arc::new(Notify::new()),
            topic_prefix: None,
            max_packet_size: 1024,
            receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
            topic_alias_max: MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX,
            max_session_expiry_secs: MqttServerConfig::DEFAULT_MAX_SESSION_EXPIRY_SECS,
            max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
            min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
            server_keep_alive_secs: MqttServerConfig::DEFAULT_SERVER_KEEP_ALIVE_SECS,
            response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
            wildcard_policy: WildcardPolicy::default(),
            on_accept: Some(Arc::new(|| {})),
            on_reject: Some(Arc::new(|| {})),
            session_hooks: Some(MqttSessionHooks::default()),
            forwarding_hooks: Some(MqttForwardingHooks::default()),
        };
        let rendered = format!("{config:?}");
        assert!(
            rendered.contains("on_accept: \"Some(<cb>)\""),
            "expected `on_accept: \"Some(<cb>)\"` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("on_reject: \"Some(<cb>)\""),
            "expected `on_reject: \"Some(<cb>)\"` sentinel, got: {rendered}",
        );
    }

    // ------------------------------------------------------------------
    // Session-level hooks (`MqttSessionHooks`) — publish/subscribe
    // admission observers. Follow the same pattern as `OnMqttAccept` /
    // `OnMqttReject`: pin the `Send + Sync` bounds on each type alias
    // and pin the manual `Debug` impl's `Some(<cb>)` / `None` sentinels
    // so a refactor that silently dropped a bound or broke the debug
    // rendering cannot land without failing a test here first.
    // ------------------------------------------------------------------

    #[test]
    fn on_publish_type_is_send_sync_arc_fn() {
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnMqttPublish = Arc::new(|| {});
        assert_bounds(&cb);
    }

    #[test]
    fn on_publish_reject_type_is_send_sync_arc_fn() {
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnMqttPublishReject = Arc::new(|| {});
        assert_bounds(&cb);
    }

    #[test]
    fn on_subscribe_type_is_send_sync_arc_fn() {
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnMqttSubscribe = Arc::new(|| {});
        assert_bounds(&cb);
    }

    #[test]
    fn on_subscribe_reject_type_is_send_sync_arc_fn() {
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnMqttSubscribeReject = Arc::new(|| {});
        assert_bounds(&cb);
    }

    #[test]
    fn session_hooks_default_has_no_callbacks_installed() {
        // `MqttSessionHooks::default()` is the wiring seed for
        // metrics-off builds — every field must be `None` so that the
        // session's hot path does not pay a closure-dispatch cost for
        // callbacks that will never fire.
        let hooks = MqttSessionHooks::default();
        assert!(hooks.on_publish.is_none());
        assert!(hooks.on_publish_reject.is_none());
        assert!(hooks.on_subscribe.is_none());
        assert!(hooks.on_subscribe_reject.is_none());
    }

    #[test]
    fn session_hooks_debug_none_renders_all_fields_as_none_sentinel() {
        let rendered = format!("{:?}", MqttSessionHooks::default());
        assert!(
            rendered.contains("on_publish: \"None\""),
            "expected `on_publish: \"None\"` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("on_publish_reject: \"None\""),
            "expected `on_publish_reject: \"None\"` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("on_subscribe: \"None\""),
            "expected `on_subscribe: \"None\"` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("on_subscribe_reject: \"None\""),
            "expected `on_subscribe_reject: \"None\"` sentinel, got: {rendered}",
        );
    }

    #[test]
    fn session_hooks_debug_some_renders_cb_sentinel_for_each_installed_field() {
        // Install each callback independently so a regression that
        // wired up the wrong field (copy-paste bug in the server crate)
        // is caught by a test that exercises each field's rendering
        // in isolation rather than all-or-nothing.
        let hooks = MqttSessionHooks {
            on_publish: Some(Arc::new(|| {})),
            on_publish_reject: Some(Arc::new(|| {})),
            on_subscribe: Some(Arc::new(|| {})),
            on_subscribe_reject: Some(Arc::new(|| {})),
            on_retain_stored: Some(Arc::new(|| {})),
            on_retain_cleared: Some(Arc::new(|| {})),
            on_retain_replayed: Some(Arc::new(|| {})),
            on_will_published: Some(Arc::new(|| {})),
        };
        let rendered = format!("{hooks:?}");
        assert!(rendered.contains("on_publish: \"Some(<cb>)\""));
        assert!(rendered.contains("on_publish_reject: \"Some(<cb>)\""));
        assert!(rendered.contains("on_subscribe: \"Some(<cb>)\""));
        assert!(rendered.contains("on_subscribe_reject: \"Some(<cb>)\""));
        assert!(rendered.contains("on_retain_stored: \"Some(<cb>)\""));
        assert!(rendered.contains("on_retain_cleared: \"Some(<cb>)\""));
        assert!(rendered.contains("on_retain_replayed: \"Some(<cb>)\""));
        assert!(rendered.contains("on_will_published: \"Some(<cb>)\""));
    }

    #[test]
    fn session_hooks_clone_duplicates_arc_without_wrapping() {
        // `MqttSessionHooks` derives `Clone` so the server crate can
        // hand it by value into every session spawn without bumping
        // `Arc`-of-`Arc` indirection. Verify that cloning preserves
        // strong_count sharing rather than creating a new arc.
        let inner: OnMqttPublish = Arc::new(|| {});
        let hooks = MqttSessionHooks {
            on_publish: Some(Arc::clone(&inner)),
            ..MqttSessionHooks::default()
        };
        let initial_count = Arc::strong_count(&inner);
        let cloned = hooks.clone();
        let after_clone = Arc::strong_count(&inner);
        assert_eq!(
            after_clone,
            initial_count + 1,
            "cloning hooks must bump the inner Arc's strong count, not wrap in a new Arc",
        );
        drop(cloned);
        assert_eq!(
            Arc::strong_count(&inner),
            initial_count,
            "dropping the clone must restore the original strong count",
        );
    }

    // ------------------------------------------------------------------
    // Forwarding hooks (`MqttForwardingHooks`) — post-route egress fan
    // out bundle. Follows the same contract as `MqttSessionHooks` so
    // the server crate can install each field independently under its
    // own feature gate (`nats`, `federation`, `http`). The callback
    // aliases themselves live in `rustgate_core::egress` and are
    // verified workspace-wide there; these tests pin the MQTT-side
    // wiring: that the struct derives `Default + Clone`, that the
    // manual `Debug` renders the `Some(<cb>)` / `None` sentinels, and
    // that cloning preserves `Arc` strong-count sharing so the server
    // crate does not accidentally stack `Arc`-of-`Arc` on every
    // session spawn.
    // ------------------------------------------------------------------

    #[test]
    fn forwarding_hooks_default_has_no_callbacks_installed() {
        // `MqttForwardingHooks::default()` is the wiring seed for
        // builds that opt out of every egress sink — every field must
        // be `None` so the session's hot path does not pay a closure-
        // dispatch cost for fan-outs that will never fire.
        let hooks = MqttForwardingHooks::default();
        assert!(hooks.nats_publish.is_none());
        assert!(hooks.federation_forward.is_none());
        assert!(hooks.http_forward.is_none());
    }

    #[test]
    fn forwarding_hooks_debug_none_renders_all_fields_as_none_sentinel() {
        // The manual `Debug` impl mirrors the `MqttSessionHooks`
        // sentinel shape so operator log greps see the wiring state
        // uniformly across both hook bundles.
        let rendered = format!("{:?}", MqttForwardingHooks::default());
        assert!(
            rendered.contains("nats_publish: \"None\""),
            "expected `nats_publish: \"None\"` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("federation_forward: \"None\""),
            "expected `federation_forward: \"None\"` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("http_forward: \"None\""),
            "expected `http_forward: \"None\"` sentinel, got: {rendered}",
        );
    }

    #[test]
    fn forwarding_hooks_debug_some_renders_cb_sentinel_for_each_installed_field() {
        // Install each callback independently so a regression that
        // wired the wrong field (copy-paste bug in the server crate's
        // `start_mqtt` fan-out) is caught by a test that exercises
        // each field's rendering in isolation rather than all-or-
        // nothing.
        let hooks = MqttForwardingHooks {
            nats_publish: Some(Arc::new(|_msg| {})),
            federation_forward: Some(Arc::new(|_payload, _groups, _meta| {})),
            http_forward: Some(Arc::new(|_msg| {})),
        };
        let rendered = format!("{hooks:?}");
        assert!(
            rendered.contains("nats_publish: \"Some(<cb>)\""),
            "expected `nats_publish: \"Some(<cb>)\"` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("federation_forward: \"Some(<cb>)\""),
            "expected `federation_forward: \"Some(<cb>)\"` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("http_forward: \"Some(<cb>)\""),
            "expected `http_forward: \"Some(<cb>)\"` sentinel, got: {rendered}",
        );
    }

    #[test]
    fn forwarding_hooks_clone_duplicates_arc_without_wrapping() {
        // Same `Arc` strong-count-sharing contract as
        // `session_hooks_clone_duplicates_arc_without_wrapping`, but
        // exercised through the `nats_publish` slot because the egress
        // bundle is cloned into the per-session spawn exactly the way
        // `MqttSessionHooks` is.
        let inner: OnNatsPublish = Arc::new(|_msg| {});
        let hooks = MqttForwardingHooks {
            nats_publish: Some(Arc::clone(&inner)),
            ..MqttForwardingHooks::default()
        };
        let initial_count = Arc::strong_count(&inner);
        let cloned = hooks.clone();
        let after_clone = Arc::strong_count(&inner);
        assert_eq!(
            after_clone,
            initial_count + 1,
            "cloning forwarding hooks must bump the inner Arc's strong count, not wrap in a new Arc",
        );
        drop(cloned);
        assert_eq!(
            Arc::strong_count(&inner),
            initial_count,
            "dropping the clone must restore the original strong count",
        );
    }
}
