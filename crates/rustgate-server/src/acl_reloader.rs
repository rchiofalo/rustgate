//! ACL file hot-reload via polling.
//!
//! [`AclReloader`] periodically checks the on-disk group ACL JSON file for
//! changes (via SHA-256 digest comparison) and atomically swaps the router's
//! ACL policy when the file content differs. This enables zero-downtime ACL
//! updates without restarting the server.
//!
//! Follows the same polling pattern as
//! [`CertReloader`](rustgate_transport::CertReloader): compute a hash of the
//! file contents, compare against the previously stored hash, and swap only
//! when the hash changes.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustgate_transport::Router;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// Watches a group ACL JSON file and hot-reloads the router's policy on change.
///
/// Construct with [`AclReloader::new`], then call
/// [`spawn_watcher`](Self::spawn_watcher) to start the background polling task.
pub(crate) struct AclReloader {
    acl_path: PathBuf,
    router: Arc<Router>,
    /// SHA-256 digest of the last successfully loaded file contents.
    last_hash: std::sync::Mutex<[u8; 32]>,
}

impl AclReloader {
    /// Create a new ACL reloader for the given file and router.
    ///
    /// The file must already exist and be valid JSON; the initial ACL should
    /// have been loaded before constructing this reloader.
    pub(crate) fn new(
        acl_path: impl Into<PathBuf>,
        router: Arc<Router>,
        initial_hash: [u8; 32],
    ) -> Arc<Self> {
        Arc::new(Self {
            acl_path: acl_path.into(),
            router,
            last_hash: std::sync::Mutex::new(initial_hash),
        })
    }

    /// Re-read the ACL file, parse it, and swap the router's policy if the
    /// file content has changed.
    ///
    /// Returns `Ok(true)` if the policy was swapped, `Ok(false)` if unchanged.
    pub(crate) fn reload(&self) -> anyhow::Result<bool> {
        let data = std::fs::read_to_string(&self.acl_path).map_err(|e| {
            anyhow::anyhow!("failed to read ACL file {}: {e}", self.acl_path.display())
        })?;

        let new_hash = Self::compute_hash(data.as_bytes());

        // Compare against stored hash -- skip parse if unchanged.
        {
            let guard = self
                .last_hash
                .lock()
                .map_err(|_| anyhow::anyhow!("ACL reloader hash lock poisoned"))?;
            if *guard == new_hash {
                debug!(
                    path = %self.acl_path.display(),
                    "ACL file unchanged"
                );
                return Ok(false);
            }
        }

        // File changed -- parse and swap.
        let config: crate::acl_config::GroupAclFile = serde_json::from_str(&data).map_err(|e| {
            anyhow::anyhow!("failed to parse ACL file {}: {e}", self.acl_path.display())
        })?;

        let mut groups = std::collections::HashMap::new();
        for (group_id, entry) in config.groups {
            let _ = groups.insert(
                group_id,
                rustgate_transport::GroupAcl::with_deny(
                    entry
                        .send
                        .into_iter()
                        .map(|s| s.to_ascii_lowercase())
                        .collect(),
                    entry
                        .receive
                        .into_iter()
                        .map(|s| s.to_ascii_lowercase())
                        .collect(),
                    entry
                        .deny_send
                        .into_iter()
                        .map(|s| s.to_ascii_lowercase())
                        .collect(),
                    entry
                        .deny_receive
                        .into_iter()
                        .map(|s| s.to_ascii_lowercase())
                        .collect(),
                ),
            );
        }

        let policy = rustgate_transport::GroupAclPolicy::new(groups);
        let group_count = policy.len();

        let new_acl = if policy.is_empty() {
            None
        } else {
            Some(policy)
        };

        self.router.swap_acl(new_acl);

        // Update stored hash after successful swap.
        {
            let mut guard = self
                .last_hash
                .lock()
                .map_err(|_| anyhow::anyhow!("ACL reloader hash lock poisoned"))?;
            *guard = new_hash;
        }

        info!(
            target: "audit",
            event_type = "acl.reload_success",
            path = %self.acl_path.display(),
            groups = group_count,
            "group ACL policy reloaded"
        );

        Ok(true)
    }

    /// Spawn a background task that polls the ACL file at the given interval
    /// and reloads when changes are detected.
    ///
    /// File I/O is offloaded to a blocking thread via
    /// [`tokio::task::spawn_blocking`] to avoid stalling the async runtime.
    pub(crate) fn spawn_watcher(self: &Arc<Self>, interval: Duration) {
        let reloader = Arc::clone(self);
        drop(tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            // Skip the first immediate tick -- the ACL was just loaded.
            let _ = tick.tick().await;

            loop {
                let _ = tick.tick().await;

                let r = Arc::clone(&reloader);
                let result = tokio::task::spawn_blocking(move || r.reload()).await;

                let reload_result = match result {
                    Ok(inner) => inner,
                    Err(e) => {
                        warn!(
                            target: "audit",
                            event_type = "acl.reload_failed",
                            path = %reloader.acl_path.display(),
                            error = %e,
                            "ACL reload task panicked"
                        );
                        continue;
                    }
                };

                if let Err(e) = reload_result {
                    warn!(
                        target: "audit",
                        event_type = "acl.reload_failed",
                        path = %reloader.acl_path.display(),
                        error = %e,
                        "ACL reload failed"
                    );
                }
            }
        }));
    }

    /// Overwrite the reloader's stored hash.
    ///
    /// Called by the REST API after it has persisted a mutation so the
    /// next poll does not re-detect the same change as a pending reload.
    #[cfg(feature = "metrics")]
    pub(crate) fn set_hash(&self, hash: [u8; 32]) {
        if let Ok(mut guard) = self.last_hash.lock() {
            *guard = hash;
        }
    }

    /// SHA-256 digest of the file bytes.
    pub(crate) fn compute_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn write_acl_file(dir: &std::path::Path, content: &str) {
        std::fs::write(dir.join("acl.json"), content).unwrap();
    }

    const INITIAL_ACL: &str = r#"{
        "groups": {
            "alpha": {
                "send": ["alice"],
                "receive": ["alice", "bob"]
            }
        }
    }"#;

    const UPDATED_ACL: &str = r#"{
        "groups": {
            "alpha": {
                "send": ["alice", "bob"],
                "receive": ["alice", "bob"]
            }
        }
    }"#;

    #[test]
    fn reload_detects_changed_file() {
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(dir.path(), INITIAL_ACL);

        let initial_hash = AclReloader::compute_hash(INITIAL_ACL.as_bytes());
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(dir.path().join("acl.json"), router, initial_hash);

        // Same content -- should return false
        assert!(!reloader.reload().unwrap());

        // Change the file
        write_acl_file(dir.path(), UPDATED_ACL);

        // Changed content -- should return true
        assert!(reloader.reload().unwrap());

        // Same again -- should return false
        assert!(!reloader.reload().unwrap());
    }

    #[tokio::test]
    async fn reload_swaps_router_acl() {
        use std::collections::BTreeSet;

        let dir = tempfile::tempdir().unwrap();
        write_acl_file(dir.path(), INITIAL_ACL);

        let initial_hash = AclReloader::compute_hash(INITIAL_ACL.as_bytes());
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(
            dir.path().join("acl.json"),
            Arc::clone(&router),
            initial_hash,
        );

        // Register alice and bob in group alpha
        let alice_id = Arc::new(
            rustgate_core::identity::Identity::new(
                "alice".to_string(),
                "alice-fp".to_string(),
                BTreeSet::from(["alpha".to_string()]),
            )
            .unwrap(),
        );
        let bob_id = Arc::new(
            rustgate_core::identity::Identity::new(
                "bob".to_string(),
                "bob-fp".to_string(),
                BTreeSet::from(["alpha".to_string()]),
            )
            .unwrap(),
        );

        let (ptx_a, _ntx_a) = tokio::sync::mpsc::channel(16);
        let (ptx_a2, ntx_a2) = tokio::sync::mpsc::channel(16);
        let mut nrx_a = ntx_a2;
        let (ptx_b, _ntx_b) = tokio::sync::mpsc::channel(16);
        let (ptx_b2, _ntx_b2) = tokio::sync::mpsc::channel(16);

        let _ = router
            .register(rustgate_transport::SessionHandle::new(
                alice_id.clone(),
                ptx_a,
                ptx_a2,
            ))
            .await;
        let _ = router
            .register(rustgate_transport::SessionHandle::new(
                bob_id.clone(),
                ptx_b,
                ptx_b2,
            ))
            .await;

        // Initially no ACL: bob can send
        let msg = rustgate_core::message::RoutableMessage {
            source: (*bob_id).clone(),
            destination: rustgate_core::message::Destination::Group("alpha".to_string()),
            payload: bytes::Bytes::from_static(b"<msg/>"),
            metadata: rustgate_core::message::Metadata {
                received_at: std::time::SystemTime::now(),
                source_protocol: "test".to_string(),
                message_type: rustgate_core::message::MessageType::Chat,
                ttl: None,
            },
        };
        router.route(msg).await;
        assert!(nrx_a.try_recv().is_ok(), "alice must receive in open mode");

        // Reload with UPDATED_ACL: adds bob to senders
        write_acl_file(dir.path(), UPDATED_ACL);
        assert!(reloader.reload().unwrap());

        // Now bob IS authorized (UPDATED_ACL adds bob to senders)
        let msg = rustgate_core::message::RoutableMessage {
            source: (*bob_id).clone(),
            destination: rustgate_core::message::Destination::Group("alpha".to_string()),
            payload: bytes::Bytes::from_static(b"<msg2/>"),
            metadata: rustgate_core::message::Metadata {
                received_at: std::time::SystemTime::now(),
                source_protocol: "test".to_string(),
                message_type: rustgate_core::message::MessageType::Chat,
                ttl: None,
            },
        };
        router.route(msg).await;
        assert!(
            nrx_a.try_recv().is_ok(),
            "alice must receive: bob is authorized after ACL reload"
        );
    }

    #[test]
    fn reload_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(dir.path(), INITIAL_ACL);

        let initial_hash = AclReloader::compute_hash(INITIAL_ACL.as_bytes());
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(dir.path().join("acl.json"), router, initial_hash);

        // Corrupt the file
        write_acl_file(dir.path(), "not valid json");

        let result = reloader.reload();
        assert!(result.is_err(), "invalid JSON should return an error");
    }

    #[test]
    fn reload_fails_on_missing_file() {
        let router = Arc::new(Router::new());
        let initial_hash = AclReloader::compute_hash(b"");
        let reloader = AclReloader::new("/nonexistent/acl.json", router, initial_hash);

        let result = reloader.reload();
        assert!(result.is_err(), "missing file should return an error");
    }

    #[test]
    fn compute_hash_deterministic() {
        let h1 = AclReloader::compute_hash(b"test-data");
        let h2 = AclReloader::compute_hash(b"test-data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_hash_differs_for_different_input() {
        let h1 = AclReloader::compute_hash(b"data-a");
        let h2 = AclReloader::compute_hash(b"data-b");
        assert_ne!(h1, h2);
    }
}
