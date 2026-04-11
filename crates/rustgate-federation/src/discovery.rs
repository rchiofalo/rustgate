// Copyright © 2026 Roberto Chiofalo.

//! Dynamic federation peer discovery (issue #571).
//!
//! This module exposes a pluggable [`PeerDiscovery`] trait together with a
//! background [`reconciler`] task that ticks on a fixed interval, calls
//! [`PeerDiscovery::discover`] to resolve the current peer set, and feeds the
//! result into `FederationManager::swap_peers`. It's the dynamic counterpart
//! to the static `--federation-peers-file` workflow: operators point rustgate
//! at a discovery backend (mDNS on the LAN, a Consul cluster, or an etcd key
//! prefix) and new peers are picked up automatically without editing a
//! JSON file.
//!
//! Three backends ship in-tree behind sub-features:
//!
//! | Feature | Backend | Notes |
//! |---|---|---|
//! | `peer-discovery-dns-sd` | `dns_sd::DnsSdDiscovery` | mDNS / zeroconf, no daemon required |
//! | `peer-discovery-consul` | `consul::ConsulDiscovery` | Consul catalog HTTP API (`/v1/catalog/service/<name>`) |
//! | `peer-discovery-etcd` | `etcd::EtcdDiscovery` | etcd v3 key-prefix scan |
//!
//! Enabling the umbrella `peer-discovery` feature pulls in all three. The
//! trait itself is available whenever any one backend is enabled — external
//! callers can also implement it to plug in a custom source (e.g. a
//! Kubernetes API client), which is what the tests do via `MockDiscovery`.
//!
//! Every backend is expected to return a fresh `Vec<PeerConfig>` from
//! `discover`: the reconciler is stateless between ticks and relies on
//! `swap_peers` to compute the diff.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::PeerConfig;
use crate::manager::FederationManager;

#[cfg(feature = "peer-discovery-consul")]
pub mod consul;
#[cfg(feature = "peer-discovery-dns-sd")]
pub mod dns_sd;
#[cfg(feature = "peer-discovery-etcd")]
pub mod etcd;

/// Pluggable source of federation peers.
///
/// Implementations resolve the current peer set on demand. The reconciler
/// invokes [`Self::discover`] on every tick and pipes the result into
/// `FederationManager::swap_peers`, so implementations should return the
/// **full** peer list (not a delta). Errors propagated from `discover` are
/// logged and the reconciler retries on the next tick — implementations must
/// therefore be safe to call repeatedly and should not hold a lock across
/// failures.
#[async_trait]
pub trait PeerDiscovery: Send + Sync + 'static {
    /// Resolve the current peer set from the backend.
    ///
    /// Called on a fixed interval by [`reconciler`]. Returns the full list of
    /// peers that should currently be configured; the reconciler diffs it
    /// against the manager's active peers and applies adds/removes via
    /// `swap_peers`.
    async fn discover(&self) -> anyhow::Result<Vec<PeerConfig>>;

    /// Human-readable name of this backend, used for logging.
    ///
    /// Default implementation returns `"peer-discovery"`; backends should
    /// override this to return something like `"dns-sd"` or `"consul"` so
    /// audit logs distinguish reconcile events across multiple sources.
    fn backend_name(&self) -> &'static str {
        "peer-discovery"
    }
}

/// Spawn the background discovery reconciler task.
///
/// The returned `JoinHandle` owns the task; dropping the handle detaches the
/// task (it will then be cancelled when its shutdown receiver fires). The
/// task ticks on `interval`, resolves the peer set from `source`, and calls
/// `manager.swap_peers(...)` under the shared `RwLock`. Errors from
/// `discover()` are logged with `target="audit", event_type="config.reload",
/// component="federation_peer_discovery", result="failure"` and swallowed —
/// the task never panics or exits on error, so a transient backend outage
/// does not permanently disable discovery.
///
/// `shutdown` is a `tokio::sync::watch::Receiver<bool>` channel; when the
/// corresponding sender flips to `true`, the task logs a shutdown message
/// and exits cleanly. This mirrors the shutdown pattern used by the other
/// long-running federation tasks (see `v1::client` and `store::kv`).
pub fn reconciler(
    manager: Arc<RwLock<FederationManager>>,
    source: Arc<dyn PeerDiscovery>,
    interval: Duration,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { reconciler_loop(manager, source, interval, shutdown).await })
}

/// Inner loop extracted so tests can drive it without a `JoinHandle`.
async fn reconciler_loop(
    manager: Arc<RwLock<FederationManager>>,
    source: Arc<dyn PeerDiscovery>,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let backend = source.backend_name();
    let mut ticker = tokio::time::interval(interval);
    // Skip the first immediate tick — the reconciler should wait one interval
    // before its first discovery call so the manager has time to finish its
    // initial start() routine.
    let _ = ticker.tick().await;
    info!(
        backend = backend,
        interval_secs = interval.as_secs(),
        "federation peer discovery reconciler started"
    );

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                run_once(&manager, source.as_ref(), backend).await;
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!(backend = backend, "federation peer discovery reconciler shutting down");
                    return;
                }
            }
        }
    }
}

/// Execute one reconcile cycle.
///
/// Separated from `reconciler_loop` so the mock-backend unit test can invoke
/// a single tick deterministically without having to juggle timers.
async fn run_once(
    manager: &Arc<RwLock<FederationManager>>,
    source: &dyn PeerDiscovery,
    backend: &'static str,
) {
    match source.discover().await {
        Ok(peers) => {
            let peer_count = peers.len();
            let diff = {
                let mut mgr = manager.write().await;
                mgr.swap_peers(peers).await
            };
            for (peer_id, err) in &diff.failed {
                warn!(
                    backend = backend,
                    peer_id = %peer_id,
                    error = %err,
                    "failed to add federation peer from discovery"
                );
            }
            info!(
                target: "audit",
                event_type = "config.reload",
                component = "federation_peer_discovery",
                result = "success",
                backend = backend,
                discovered = peer_count,
                added = diff.added.len(),
                removed = diff.removed.len(),
                unchanged = diff.unchanged.len(),
                failed = diff.failed.len(),
                "federation peer set reconciled from discovery backend"
            );
        }
        Err(e) => {
            warn!(
                target: "audit",
                event_type = "config.reload",
                component = "federation_peer_discovery",
                result = "failure",
                backend = backend,
                error = %e,
                "federation peer discovery cycle failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;

    use super::*;
    use crate::config::{FederationConfig, PeerConfig, RoutingMode};

    fn test_config() -> FederationConfig {
        FederationConfig {
            federate_id: "test-discovery".into(),
            v1_enabled: false,
            v1_listen_addr: "127.0.0.1:0".parse().unwrap(),
            v2_enabled: false,
            v2_listen_addr: "127.0.0.1:0".parse().unwrap(),
            peers: vec![],
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
            health_check_interval: Duration::from_secs(5),
            client_timeout: Duration::from_secs(15),
            max_message_size: 10 * 1024 * 1024,
            reconnect_delay: Duration::from_secs(30),
            max_reconnects: -1,
            max_hops: 10,
            default_group: "__ANON__".into(),
            store_path: None,
            skip_hostname_verify: false,
            trust_store_dir: None,
            cert_file: PathBuf::from("/nonexistent/cert.pem"),
            key_file: PathBuf::from("/nonexistent/key.pem"),
            ca_file: PathBuf::from("/nonexistent/ca.pem"),
            jwt_secret: None,
            jwt_expiry_secs: 3600,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout: Duration::from_secs(60),
            replay_buffer_capacity: 1000,
            replay_buffer_dir: None,
            replay_max_bytes: crate::replay_persist::DEFAULT_REPLAY_MAX_BYTES,
            pod_id: None,
            ha_nats_url: None,
            local_region: None,
        }
    }

    fn peer(id: &str, addr: &str) -> PeerConfig {
        PeerConfig {
            id: id.into(),
            address: addr.into(),
            groups: vec!["default".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: false,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        }
    }

    /// Test double for [`PeerDiscovery`]: returns a caller-controlled list
    /// and counts how many times `discover` was invoked.
    struct MockDiscovery {
        peers: StdMutex<Vec<PeerConfig>>,
        calls: StdMutex<usize>,
        fail: StdMutex<bool>,
    }

    impl MockDiscovery {
        fn new(peers: Vec<PeerConfig>) -> Self {
            Self {
                peers: StdMutex::new(peers),
                calls: StdMutex::new(0),
                fail: StdMutex::new(false),
            }
        }

        fn set_peers(&self, peers: Vec<PeerConfig>) {
            *self.peers.lock().unwrap() = peers;
        }

        fn call_count(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl PeerDiscovery for MockDiscovery {
        async fn discover(&self) -> anyhow::Result<Vec<PeerConfig>> {
            *self.calls.lock().unwrap() += 1;
            if *self.fail.lock().unwrap() {
                anyhow::bail!("simulated discovery failure");
            }
            Ok(self.peers.lock().unwrap().clone())
        }

        fn backend_name(&self) -> &'static str {
            "mock"
        }
    }

    #[tokio::test]
    async fn reconcile_adds_newly_discovered_peers() {
        let mgr = Arc::new(RwLock::new(FederationManager::new(test_config())));
        let mock = Arc::new(MockDiscovery::new(vec![peer("alpha", "127.0.0.1:9100")]));

        run_once(&mgr, mock.as_ref(), "mock").await;

        assert_eq!(mock.call_count(), 1);
        let guard = mgr.read().await;
        assert_eq!(guard.config().peers.len(), 1);
        assert_eq!(guard.config().peers[0].id.as_str(), "alpha");
    }

    #[tokio::test]
    async fn reconcile_removes_vanished_peers() {
        let mgr = Arc::new(RwLock::new(FederationManager::new(test_config())));
        let mock = Arc::new(MockDiscovery::new(vec![
            peer("alpha", "127.0.0.1:9100"),
            peer("beta", "127.0.0.1:9101"),
        ]));
        run_once(&mgr, mock.as_ref(), "mock").await;
        assert_eq!(mgr.read().await.config().peers.len(), 2);

        // Second cycle: backend drops beta.
        mock.set_peers(vec![peer("alpha", "127.0.0.1:9100")]);
        run_once(&mgr, mock.as_ref(), "mock").await;

        let guard = mgr.read().await;
        assert_eq!(guard.config().peers.len(), 1);
        assert_eq!(guard.config().peers[0].id.as_str(), "alpha");
    }

    #[tokio::test]
    async fn reconcile_swallows_discovery_errors() {
        let mgr = Arc::new(RwLock::new(FederationManager::new(test_config())));
        let mock = Arc::new(MockDiscovery::new(vec![peer("alpha", "127.0.0.1:9100")]));
        *mock.fail.lock().unwrap() = true;

        // Should not panic — errors are logged and the manager is untouched.
        run_once(&mgr, mock.as_ref(), "mock").await;
        assert_eq!(mgr.read().await.config().peers.len(), 0);
    }

    #[tokio::test]
    async fn reconciler_loop_exits_on_shutdown() {
        let mgr = Arc::new(RwLock::new(FederationManager::new(test_config())));
        let mock = Arc::new(MockDiscovery::new(vec![]));
        let (tx, rx) = tokio::sync::watch::channel(false);

        let handle = reconciler(
            Arc::clone(&mgr),
            mock.clone() as Arc<dyn PeerDiscovery>,
            Duration::from_millis(50),
            rx,
        );

        // Let the loop spin for a few ticks.
        tokio::time::sleep(Duration::from_millis(200)).await;
        tx.send(true).unwrap();

        // The join handle should resolve quickly once the shutdown flag flips.
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("reconciler did not shut down")
            .expect("reconciler panicked");
    }
}
