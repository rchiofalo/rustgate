//! Federation peer file hot-reload via SIGHUP and periodic polling.
//!
//! [`FederationPeerReloader`] watches the on-disk federation peers JSON file
//! for changes (via SHA-256 digest comparison) and atomically reconciles the
//! [`FederationManager`](rustgate_federation::manager::FederationManager)'s
//! configured peer set when the file content differs. Peers added to the file
//! are connected, peers removed are gracefully disconnected, and peers whose
//! configuration changed are reconnected with the new settings. Peers that
//! are unchanged are left alone — existing connections are preserved.
//!
//! Mirrors the polling pattern used by [`crate::acl_reloader::AclReloader`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustgate_federation::manager::FederationManager;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Watches a federation peers JSON file and reconciles the manager's peer set
/// on change.
pub(crate) struct FederationPeerReloader {
    peers_path: PathBuf,
    manager: Arc<RwLock<FederationManager>>,
    last_hash: std::sync::Mutex<[u8; 32]>,
}

impl FederationPeerReloader {
    /// Create a new reloader for the given peers file and federation manager.
    pub(crate) fn new(
        peers_path: impl Into<PathBuf>,
        manager: Arc<RwLock<FederationManager>>,
        initial_hash: [u8; 32],
    ) -> Arc<Self> {
        Arc::new(Self {
            peers_path: peers_path.into(),
            manager,
            last_hash: std::sync::Mutex::new(initial_hash),
        })
    }

    /// SHA-256 digest of the file bytes.
    pub(crate) fn compute_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Re-read the peers file and reconcile the manager's peer set if the
    /// content has changed.
    ///
    /// Returns `Ok(true)` if a swap was performed, `Ok(false)` if the file
    /// was unchanged.
    pub(crate) async fn reload(&self) -> anyhow::Result<bool> {
        let data = tokio::fs::read_to_string(&self.peers_path)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to read federation peers file {}: {e}",
                    self.peers_path.display()
                )
            })?;

        let new_hash = Self::compute_hash(data.as_bytes());

        {
            let guard = self
                .last_hash
                .lock()
                .map_err(|_| anyhow::anyhow!("federation reloader hash lock poisoned"))?;
            if *guard == new_hash {
                debug!(
                    path = %self.peers_path.display(),
                    "federation peers file unchanged"
                );
                return Ok(false);
            }
        }

        let new_peers: Vec<rustgate_federation::config::PeerConfig> = serde_json::from_str(&data)
            .map_err(|e| {
            anyhow::anyhow!(
                "failed to parse federation peers file {}: {e}",
                self.peers_path.display()
            )
        })?;

        let diff = {
            let mut mgr = self.manager.write().await;
            mgr.swap_peers(new_peers).await
        };

        {
            let mut guard = self
                .last_hash
                .lock()
                .map_err(|_| anyhow::anyhow!("federation reloader hash lock poisoned"))?;
            *guard = new_hash;
        }

        info!(
            target: "audit",
            event_type = "config.reload",
            component = "federation_peers",
            result = "success",
            added = diff.added.len(),
            removed = diff.removed.len(),
            unchanged = diff.unchanged.len(),
            failed = diff.failed.len(),
            path = %self.peers_path.display(),
            "federation peer set reloaded"
        );

        Ok(true)
    }

    /// Spawn a background task that polls the peers file at the given interval
    /// and reloads when changes are detected.
    pub(crate) fn spawn_watcher(self: &Arc<Self>, interval: Duration) {
        let reloader = Arc::clone(self);
        drop(tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            // Skip the first immediate tick — peers were just loaded.
            let _ = tick.tick().await;

            loop {
                let _ = tick.tick().await;
                if let Err(e) = reloader.reload().await {
                    warn!(
                        target: "audit",
                        event_type = "config.reload",
                        component = "federation_peers",
                        result = "failure",
                        path = %reloader.peers_path.display(),
                        error = %e,
                        "federation peer reload failed"
                    );
                }
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use rustgate_federation::config::{FederationConfig, PeerConfig};

    use super::*;

    fn write_peers(dir: &std::path::Path, content: &str) {
        std::fs::write(dir.join("peers.json"), content).unwrap();
    }

    fn manager(peers: Vec<PeerConfig>) -> Arc<RwLock<FederationManager>> {
        Arc::new(RwLock::new(FederationManager::new(FederationConfig {
            federate_id: "test-fed".into(),
            peers,
            ..Default::default()
        })))
    }

    const PEER_ALPHA: &str = r#"{
        "id": "alpha",
        "address": "127.0.0.1:9100",
        "groups": ["g1"],
        "enabled": true,
        "is_outbound": false,
        "trust_cert_cn": null
    }"#;

    const PEER_BETA: &str = r#"{
        "id": "beta",
        "address": "127.0.0.1:9101",
        "groups": ["g2"],
        "enabled": true,
        "is_outbound": false,
        "trust_cert_cn": null
    }"#;

    #[test]
    fn compute_hash_deterministic() {
        let h1 = FederationPeerReloader::compute_hash(b"x");
        let h2 = FederationPeerReloader::compute_hash(b"x");
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_hash_differs() {
        let h1 = FederationPeerReloader::compute_hash(b"a");
        let h2 = FederationPeerReloader::compute_hash(b"b");
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn reload_unchanged_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let initial = format!("[{PEER_ALPHA}]");
        write_peers(dir.path(), &initial);
        let mgr = manager(serde_json::from_str(&initial).unwrap());
        let r = FederationPeerReloader::new(
            dir.path().join("peers.json"),
            mgr,
            FederationPeerReloader::compute_hash(initial.as_bytes()),
        );
        assert!(!r.reload().await.unwrap());
    }

    #[tokio::test]
    async fn reload_adds_new_peer_to_config() {
        let dir = tempfile::tempdir().unwrap();
        let initial = format!("[{PEER_ALPHA}]");
        write_peers(dir.path(), &initial);
        let mgr = manager(serde_json::from_str(&initial).unwrap());
        let r = FederationPeerReloader::new(
            dir.path().join("peers.json"),
            Arc::clone(&mgr),
            FederationPeerReloader::compute_hash(initial.as_bytes()),
        );

        let updated = format!("[{PEER_ALPHA},{PEER_BETA}]");
        write_peers(dir.path(), &updated);

        assert!(r.reload().await.unwrap());
        let m = mgr.read().await;
        assert_eq!(m.config().peers.len(), 2);
        assert!(m.config().peers.iter().any(|p| p.id.as_str() == "beta"));
    }

    #[tokio::test]
    async fn reload_removes_peer_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let initial = format!("[{PEER_ALPHA},{PEER_BETA}]");
        write_peers(dir.path(), &initial);
        let mgr = manager(serde_json::from_str(&initial).unwrap());
        let r = FederationPeerReloader::new(
            dir.path().join("peers.json"),
            Arc::clone(&mgr),
            FederationPeerReloader::compute_hash(initial.as_bytes()),
        );

        let updated = format!("[{PEER_BETA}]");
        write_peers(dir.path(), &updated);

        assert!(r.reload().await.unwrap());
        let m = mgr.read().await;
        assert_eq!(m.config().peers.len(), 1);
        assert_eq!(m.config().peers[0].id.as_str(), "beta");
    }

    #[tokio::test]
    async fn reload_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        write_peers(dir.path(), "[]");
        let mgr = manager(vec![]);
        let r = FederationPeerReloader::new(
            dir.path().join("peers.json"),
            mgr,
            FederationPeerReloader::compute_hash(b"[]"),
        );
        write_peers(dir.path(), "{not json");
        assert!(r.reload().await.is_err());
    }
}
