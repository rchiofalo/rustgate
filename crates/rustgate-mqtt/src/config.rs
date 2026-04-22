// Copyright © 2026 Roberto Chiofalo.

//! Configuration for the MQTT server.

use std::sync::Arc;

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

    /// Minimum keep-alive interval in seconds. Clients requesting 0
    /// (disabled) or a value below this floor get this value imposed.
    pub min_keep_alive_secs: u16,

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
}

impl MqttServerConfig {
    /// Default maximum packet size: 16 MiB (matches websocket frame cap).
    pub const DEFAULT_MAX_PACKET_SIZE: usize = 16 * 1024 * 1024;

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
            .field("min_keep_alive_secs", &self.min_keep_alive_secs)
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
            min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
            response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
            wildcard_policy: WildcardPolicy::default(),
            on_accept: None,
            on_reject: None,
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
            min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
            response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
            wildcard_policy: WildcardPolicy::default(),
            on_accept: Some(Arc::new(|| {})),
            on_reject: Some(Arc::new(|| {})),
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
}
