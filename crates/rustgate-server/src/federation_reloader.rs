// Copyright © 2026 Roberto Chiofalo.

//! Federation peer file hot-reload via SIGHUP and periodic polling.
//!
//! [`FederationPeerReloader`] watches the on-disk federation peers JSON file
//! for changes (via SHA-256 digest comparison) and atomically reconciles the
//! [`rustgate_federation::manager::FederationManager`]'s
//! configured peer set when the file content differs. Peers added to the file
//! are connected, peers removed are gracefully disconnected, and peers whose
//! configuration changed are reconnected with the new settings. Peers that
//! are unchanged are left alone — existing connections are preserved.
//!
//! Mirrors the polling pattern used by [`crate::acl_reloader::AclReloader`].
//!
//! The watcher is intended to be **single-instance** per server process: a
//! single `FederationPeerReloader` is constructed at startup and shared
//! between the periodic poller and the SIGHUP handler. To guarantee that the
//! hash check, file parse, and `swap_peers` call execute as one atomic unit
//! (and to avoid a TOCTOU between two reload triggers firing concurrently),
//! [`FederationPeerReloader::reload`] takes an internal `tokio::sync::Mutex`
//! for the duration of the reconcile.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustgate_federation::manager::FederationManager;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// Watches a federation peers JSON file and reconciles the manager's peer set
/// on change.
///
/// Designed to be instantiated **once** per server process. Concurrent calls
/// to [`Self::reload`] are serialized through `reload_lock` so that the hash
/// compare, parse, and swap form a single critical section.
pub(crate) struct FederationPeerReloader {
    peers_path: PathBuf,
    manager: Arc<RwLock<FederationManager>>,
    last_hash: std::sync::Mutex<[u8; 32]>,
    /// Serializes the entire reload pipeline (hash check + parse + swap) so
    /// that two reload triggers (e.g. SIGHUP racing the periodic poller) can
    /// never both observe an unchanged hash and then both call `swap_peers`.
    reload_lock: Mutex<()>,
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
            reload_lock: Mutex::new(()),
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
        // Hold this lock for the entire reconcile so the hash check and the
        // subsequent swap_peers cannot interleave with another reload trigger.
        let _reload_guard = self.reload_lock.lock().await;

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

        // Surface per-peer error reasons so operators pushing a bad entry can
        // see why immediately, instead of only seeing a `failed=N` count in
        // the audit summary.
        for (peer_id, err) in &diff.failed {
            warn!(
                peer_id = %peer_id,
                error = %err,
                "failed to add federation peer"
            );
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

    /// `compute_hash` must yield exactly 32 bytes of output — the
    /// `[u8; 32]` return type pins it at the type system, but a future
    /// refactor that changed the signature to `Vec<u8>` (e.g. to feed a
    /// length-prefixed hasher) would pass type-check while silently
    /// changing the digest size operators see in `tracing::debug!` lines.
    /// Length-pin the digest as a defensive smoke assertion.
    #[test]
    fn compute_hash_output_length_is_sha256_32_bytes() {
        let h = FederationPeerReloader::compute_hash(b"peers");
        assert_eq!(
            h.len(),
            32,
            "SHA-256 digest must be exactly 32 bytes; a different size implies the algorithm was silently swapped"
        );
    }

    /// Pin the SHA-256 of the empty byte slice against the RFC 6234 /
    /// NIST FIPS 180-4 reference vector. This is the cheapest possible
    /// cross-build determinism check — a regression where the hasher was
    /// accidentally re-keyed (e.g. via `Sha256::new_with_prefix(b"...")`
    /// added for "domain separation"), truncated, or swapped for a
    /// different algorithm with a similar API surface (SHA-256/224,
    /// SHA-512/256) would trip here rather than silently breaking every
    /// operator's `last_hash` after a rolling deploy.
    #[test]
    fn compute_hash_empty_input_matches_rfc_sha256_empty_vector() {
        const SHA256_EMPTY: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(
            FederationPeerReloader::compute_hash(b""),
            SHA256_EMPTY,
            "compute_hash(b\"\") must match the RFC 6234 SHA-256 empty vector; any drift means the hash function is not what the module docs advertise"
        );
    }

    /// The `spawn_watcher` task loops forever and calls `reload()` on every
    /// tick; if the peers file is temporarily missing (e.g. a ConfigMap
    /// remount window under Kubernetes), the reload must surface an error
    /// — silent success with an empty peer set would disconnect every live
    /// federation peer mid-operation. Pin that (a) the error propagates,
    /// and (b) the error message names both the fact that it's the
    /// federation peers file (so operators grepping audit logs for the
    /// reload failure can find it) and the actual path (so they can see
    /// which deployment this is).
    #[tokio::test]
    async fn reload_with_missing_peers_file_returns_error_including_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-peers.json");
        let mgr = manager(vec![]);
        let r = FederationPeerReloader::new(&missing, mgr, [0u8; 32]);

        let err = r
            .reload()
            .await
            .expect_err("missing file must surface as Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("federation peers file"),
            "error must name the file category for operator grep: {msg}"
        );
        assert!(
            msg.contains(missing.display().to_string().as_str()),
            "error must echo the actual path so multi-deploy operators can disambiguate: {msg}"
        );
    }

    /// State-integrity invariant: a reload that fails at the JSON parse
    /// stage must **not** advance `last_hash`. The design intent — load
    /// bytes → hash → compare → parse → swap → update hash — is that only
    /// a fully-successful swap commits the new hash, so that a subsequent
    /// recovery (operator rolls the bad config back to a prior good one)
    /// is detected as "back to previous known-good" rather than "drift".
    /// A regression that hoisted the `last_hash = new_hash` assignment
    /// above the parse step would silently pass the existing
    /// `reload_rejects_invalid_json` test (which only checks `is_err()`)
    /// but break this one: after a bad reload, writing the original good
    /// content should look like a no-op (`Ok(false)`), not a change.
    #[tokio::test]
    async fn reload_err_on_invalid_json_preserves_last_hash_so_recovery_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let initial = format!("[{PEER_ALPHA}]");
        write_peers(dir.path(), &initial);
        let mgr = manager(serde_json::from_str(&initial).unwrap());
        let r = FederationPeerReloader::new(
            dir.path().join("peers.json"),
            mgr,
            FederationPeerReloader::compute_hash(initial.as_bytes()),
        );

        // Corrupt the file; reload must fail.
        write_peers(dir.path(), "{not json");
        assert!(
            r.reload().await.is_err(),
            "invalid JSON must fail the reload"
        );

        // Restore the original good content; reload must report unchanged
        // (because last_hash was preserved across the bad reload).
        write_peers(dir.path(), &initial);
        assert!(
            !r.reload().await.unwrap(),
            "after rolling bad config back to the known-good original, reload must see last_hash unchanged (== hash of original) and return false; if it returns true, last_hash was corrupted by the bad reload"
        );
    }

    /// Symmetric positive-path invariant to the state-integrity test
    /// above: a **successful** reload must advance `last_hash` so that an
    /// immediate second reload on the same file returns `Ok(false)`. The
    /// existing `reload_adds_new_peer_to_config` test only asserts the
    /// first reload returns `true` and the manager saw the swap — it does
    /// not pin that the hash is committed, so a refactor that dropped
    /// the post-swap `*guard = new_hash` would silently make every
    /// reload a full swap (hammering `FederationManager::swap_peers` on
    /// every poller tick) without tripping the existing suite.
    #[tokio::test]
    async fn reload_after_successful_swap_advances_last_hash_so_second_reload_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let initial = format!("[{PEER_ALPHA}]");
        write_peers(dir.path(), &initial);
        let mgr = manager(serde_json::from_str(&initial).unwrap());
        let r = FederationPeerReloader::new(
            dir.path().join("peers.json"),
            Arc::clone(&mgr),
            FederationPeerReloader::compute_hash(initial.as_bytes()),
        );

        // Change the file and drive one successful reload.
        let updated = format!("[{PEER_ALPHA},{PEER_BETA}]");
        write_peers(dir.path(), &updated);
        assert!(
            r.reload().await.unwrap(),
            "first reload on a changed file must perform a swap"
        );

        // Immediately drive a second reload against the *same* updated
        // file. last_hash should now match the updated hash, so the
        // reload must short-circuit before the parse step.
        assert!(
            !r.reload().await.unwrap(),
            "second reload on unchanged file must return false; a true return means last_hash was not advanced on the preceding successful swap"
        );
    }

    /// Parse-error messages must carry the file path so an operator
    /// looking at the `config.reload component=federation_peers
    /// result=failure` audit line can correlate it to the actual file on
    /// disk (important under Kubernetes/multi-tenant deployments where
    /// several servers share a log aggregator but write to different
    /// ConfigMaps). The existing `reload_rejects_invalid_json` test only
    /// checks `is_err()` so a refactor that dropped `self.peers_path` from
    /// the error context (e.g. to "simplify" with `?` on a raw serde
    /// error) would silently lose this diagnostic.
    #[tokio::test]
    async fn reload_parse_error_message_includes_path_for_operator_grep() {
        let dir = tempfile::tempdir().unwrap();
        write_peers(dir.path(), "[]");
        let mgr = manager(vec![]);
        let path = dir.path().join("peers.json");
        let r =
            FederationPeerReloader::new(&path, mgr, FederationPeerReloader::compute_hash(b"[]"));
        write_peers(dir.path(), "{not json");

        let err = r
            .reload()
            .await
            .expect_err("invalid JSON must surface as Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("parse federation peers file"),
            "parse error must name that it is a parse failure of the peers file: {msg}"
        );
        assert!(
            msg.contains(path.display().to_string().as_str()),
            "parse error must echo the file path so operators can disambiguate deployments: {msg}"
        );
    }
}
