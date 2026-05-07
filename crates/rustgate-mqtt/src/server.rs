// Copyright © 2026 Roberto Chiofalo.

//! MQTT server — accept loop, session spawning, and graceful shutdown.
//!
//! [`MqttServer::run`] is the main entry point. It accepts connections from
//! the [`MqttListener`](crate::MqttListener), enforces the connection limit,
//! spawns a session task per connection, and shuts down cleanly when the
//! shutdown signal fires.

use std::sync::Arc;

use rustgate_core::tasks::spawn_background;
use tracing::{info, warn};

use crate::TRANSPORT_LABEL;
use crate::config::MqttServerConfig;
use crate::retain::RetainStore;
use crate::session::{ClientIdRegistry, handle_mqtt_session};

/// The MQTT server that manages the accept loop and session lifecycle.
#[derive(Debug)]
pub struct MqttServer;

impl MqttServer {
    /// Run the MQTT server until the shutdown signal fires.
    ///
    /// Accepts mTLS-authenticated connections, enforces the shared
    /// connection limit, and spawns a session handler per connection.
    pub async fn run(config: MqttServerConfig) {
        let MqttServerConfig {
            listener,
            router,
            connection_limit,
            shutdown,
            topic_prefix,
            max_packet_size,
            receive_max,
            topic_alias_max,
            max_session_expiry_secs,
            max_retained_sessions,
            min_keep_alive_secs,
            server_keep_alive_secs,
            response_channel_capacity,
            wildcard_policy,
            on_accept,
            on_reject,
            session_hooks,
            forwarding_hooks,
        } = config;

        let client_id_registry = ClientIdRegistry::new();
        // One retain store per server, shared across every accepted
        // session for the lifetime of the listener. Mirrors the
        // ClientIdRegistry pattern — process-local, no operator-facing
        // config because retain semantics are mandated by the MQTT
        // spec rather than something a deployment turns on/off.
        let retain_store = RetainStore::new();

        // One session-retention store per server (refs #880 +
        // follow-up to #1162). When `max_session_expiry_secs == 0`
        // this is a cheap no-op surface — `is_enabled()` returns
        // false and every save/take short-circuits — so deployments
        // that don't enable retention pay near-zero cost. When
        // enabled, a background reaper task sweeps expired entries
        // every 30 s so the store doesn't grow without bound between
        // disconnects and reconnects beyond the configured TTL.
        let session_store =
            crate::session_store::SessionStore::new(if max_session_expiry_secs > 0 {
                max_retained_sessions
            } else {
                0
            });
        if session_store.is_enabled() {
            let store_for_reaper = Arc::clone(&session_store);
            let shutdown_for_reaper = Arc::clone(&shutdown);
            spawn_background("mqtt-session-reaper", async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = tick.tick() => {
                            let dropped = store_for_reaper.reap_expired();
                            if dropped > 0 {
                                info!(
                                    transport = TRANSPORT_LABEL,
                                    dropped,
                                    remaining = store_for_reaper.len(),
                                    "MQTT session retention reaper sweep",
                                );
                            }
                        }
                        () = shutdown_for_reaper.notified() => {
                            break;
                        }
                    }
                }
            });
        }

        info!(
            transport = TRANSPORT_LABEL,
            addr = ?listener.local_addr().ok(),
            session_retention_enabled = session_store.is_enabled(),
            "MQTT server started",
        );

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok(Some(pre_session)) => {
                            let peer_addr = pre_session.peer_addr;
                            let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!(
                                        transport = TRANSPORT_LABEL,
                                        peer = %peer_addr,
                                        "connection limit reached, rejecting MQTT client",
                                    );
                                    rustgate_core::audit::connection_rejected(
                                        peer_addr,
                                        "MQTT connection limit reached",
                                    );
                                    if let Some(ref cb) = on_reject {
                                        cb();
                                    }
                                    continue;
                                }
                            };

                            if let Some(ref cb) = on_accept {
                                cb();
                            }

                            let router = Arc::clone(&router);
                            let prefix = topic_prefix.clone();
                            let registry = Arc::clone(&client_id_registry);
                            let retain = Arc::clone(&retain_store);
                            let sessions = Arc::clone(&session_store);
                            let hooks = session_hooks.clone();
                            let forwarding = forwarding_hooks.clone();
                            spawn_background(
                                "mqtt-session",
                                handle_mqtt_session(
                                    pre_session,
                                    router,
                                    prefix,
                                    max_packet_size,
                                    receive_max,
                                    topic_alias_max,
                                    max_session_expiry_secs,
                                    min_keep_alive_secs,
                                    server_keep_alive_secs,
                                    response_channel_capacity,
                                    wildcard_policy,
                                    registry,
                                    retain,
                                    sessions,
                                    permit,
                                    hooks,
                                    forwarding,
                                ),
                            );
                        }
                        Ok(None) => {
                            // TLS handshake failed or cert invalid — already logged by listener.
                        }
                        Err(e) => {
                            warn!(transport = TRANSPORT_LABEL, error = %e, "MQTT accept error");
                        }
                    }
                }
                () = shutdown.notified() => {
                    info!(transport = TRANSPORT_LABEL, "MQTT server shutting down");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use rustgate_test_utils::certs::TestCa;
    use rustgate_tls::TlsConfig;
    use rustgate_transport::Router;
    use tokio::sync::{Notify, Semaphore};

    use super::*;
    use crate::config::{MqttServerConfig, MqttSessionHooks};
    use crate::listener::MqttListener;
    use crate::topic::WildcardPolicy;

    // ------------------------------------------------------------------
    // These tests exercise the accept-loop orchestration of
    // `MqttServer::run` without driving real TLS handshakes — the
    // integration suite under `tests/mqtt_integration.rs` already covers
    // the full handshake + CONNECT + PUBLISH + SUBSCRIBE path end-to-end.
    // Here we pin the lifecycle invariants (Debug trait bound, shutdown
    // responsiveness, on-accept / on-reject plumbing presence) that the
    // accept loop itself owns and that a refactor could silently break
    // without tripping a wire-level test.
    // ------------------------------------------------------------------

    /// Build a server-side `TlsConfig` using a throw-away test CA.
    fn test_tls_config(label: &str) -> TlsConfig {
        let ca = TestCa::new(label);
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
            .expect("build TlsConfig from freshly issued test certs")
    }

    fn loopback_zero() -> SocketAddr {
        "127.0.0.1:0"
            .parse()
            .expect("static loopback address must parse")
    }

    /// Assemble an `MqttServerConfig` bound to a fresh loopback port.
    ///
    /// The listener has no clients, so the only path the accept loop can
    /// take is the shutdown branch. This keeps each test focused on
    /// lifecycle semantics rather than handshake mechanics.
    fn build_config(shutdown: Arc<Notify>, label: &str) -> MqttServerConfig {
        let tls = test_tls_config(label);
        let listener = MqttListener::bind(loopback_zero(), &tls).expect("bind MQTT listener");
        MqttServerConfig {
            listener,
            router: Arc::new(Router::default()),
            connection_limit: Arc::new(Semaphore::new(1)),
            shutdown,
            topic_prefix: None,
            max_packet_size: MqttServerConfig::DEFAULT_MAX_PACKET_SIZE,
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
        }
    }

    // ------------------------------------------------------------------
    // Trait bounds — pin the `Debug` derive cheaply so a future refactor
    // that accidentally drops it (e.g. because an added field is not
    // `Debug`) lands as a compile error here, not inside a tracing macro
    // expansion at an unrelated call site.
    // ------------------------------------------------------------------

    #[test]
    fn server_type_is_debug() {
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<MqttServer>();
    }

    #[test]
    fn server_debug_renders_struct_name() {
        let rendered = format!("{:?}", MqttServer);
        assert_eq!(rendered, "MqttServer");
    }

    // ------------------------------------------------------------------
    // Shutdown responsiveness — the accept loop `tokio::select!`s on
    // `listener.accept()` and `shutdown.notified()`. These tests verify
    // that the `shutdown` branch wins deterministically when no client is
    // connecting, so an operator-initiated SIGTERM translates into a
    // clean drain rather than a hang waiting for an accept that will
    // never arrive.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn run_returns_immediately_when_shutdown_pre_notified() {
        // Notify *before* spawning `run` — tokio's Notify stores one
        // permit, so the first `notified()` poll inside the select
        // completes without ever parking.
        let shutdown = Arc::new(Notify::new());
        shutdown.notify_one();
        let config = build_config(Arc::clone(&shutdown), "mqtt-server-pre-notified");

        // Bound the test with a generous virtual-time timeout so a
        // regression that stops honouring the shutdown notify manifests
        // as a test failure rather than hanging CI.
        tokio::time::timeout(Duration::from_secs(5), MqttServer::run(config))
            .await
            .expect("MqttServer::run must return when shutdown was notified before spawn");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_returns_when_shutdown_fires_after_spawn() {
        // The more realistic path: operator sends SIGTERM while the
        // server is idling in `listener.accept()`. Spawn `run`, yield
        // once so it reaches the select, then notify.
        let shutdown = Arc::new(Notify::new());
        let config = build_config(Arc::clone(&shutdown), "mqtt-server-post-notified");

        let handle = tokio::spawn(MqttServer::run(config));
        // One yield is enough under current_thread flavour to let the
        // spawned task advance past the setup and park on the select.
        tokio::task::yield_now().await;
        shutdown.notify_one();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("MqttServer::run must exit within timeout after shutdown is notified")
            .expect("MqttServer::run task must not panic during shutdown");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_ignores_extra_shutdown_notifications() {
        // `Notify::notify_one` coalesces — a second notify after the
        // loop has already exited must be a silent no-op rather than
        // re-arming the notify and stranding the next run invocation.
        let shutdown = Arc::new(Notify::new());
        let config = build_config(Arc::clone(&shutdown), "mqtt-server-double-notify");

        let handle = tokio::spawn(MqttServer::run(config));
        tokio::task::yield_now().await;
        shutdown.notify_one();
        // Second notify after the loop has already broken out.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.notify_one();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run must still terminate cleanly when extra notifies arrive")
            .expect("run task must not panic on duplicate shutdown notify");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_notify_is_observed_by_concurrent_readers() {
        // Pin the contract that the `Arc<Notify>` handed in to
        // `MqttServerConfig` is the *same* handle the run loop awaits.
        // If a refactor ever clones or swaps the notify during config
        // destructure, external holders (e.g. the server crate's
        // `stop_subsystem` helper) would be unable to trigger shutdown
        // — this test would catch that before it reached integration.
        let shutdown = Arc::new(Notify::new());
        let external = Arc::clone(&shutdown);
        let config = build_config(shutdown, "mqtt-server-shared-notify");

        let handle = tokio::spawn(MqttServer::run(config));
        tokio::task::yield_now().await;
        external.notify_one();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("external Arc<Notify> must still be able to shut down the loop")
            .expect("run task must not panic when notified via cloned Arc");
    }

    // ------------------------------------------------------------------
    // Observer wiring — the accept loop fires `on_accept` only on the
    // success path and `on_reject` only on the connection-limit-exceeded
    // path. Neither fires on a clean shutdown with no inbound clients,
    // so the invariant we can cheaply verify here is that installing the
    // callbacks does not itself perturb the shutdown path (e.g. through
    // a panicking destructor during config destructure).
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn run_exits_cleanly_with_observers_installed() {
        let shutdown = Arc::new(Notify::new());
        let tls = test_tls_config("mqtt-server-observers");
        let listener = MqttListener::bind(loopback_zero(), &tls).expect("bind");
        let config = MqttServerConfig {
            listener,
            router: Arc::new(Router::default()),
            connection_limit: Arc::new(Semaphore::new(1)),
            shutdown: Arc::clone(&shutdown),
            topic_prefix: None,
            max_packet_size: MqttServerConfig::DEFAULT_MAX_PACKET_SIZE,
            receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
            topic_alias_max: MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX,
            max_session_expiry_secs: MqttServerConfig::DEFAULT_MAX_SESSION_EXPIRY_SECS,
            max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
            min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
            server_keep_alive_secs: MqttServerConfig::DEFAULT_SERVER_KEEP_ALIVE_SECS,
            response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
            wildcard_policy: WildcardPolicy::default(),
            on_accept: Some(Arc::new(|| {
                panic!("on_accept must not fire on clean shutdown with no clients")
            })),
            on_reject: Some(Arc::new(|| {
                panic!("on_reject must not fire on clean shutdown with no clients")
            })),
            session_hooks: Some(MqttSessionHooks::default()),
            forwarding_hooks: None,
        };

        let handle = tokio::spawn(MqttServer::run(config));
        tokio::task::yield_now().await;
        shutdown.notify_one();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run must terminate with observers installed")
            .expect("run task must not panic on shutdown with no accept / reject events");
    }
}
