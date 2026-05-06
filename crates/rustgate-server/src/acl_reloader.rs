// Copyright © 2026 Roberto Chiofalo.

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

use rustgate_core::tasks::spawn_background;
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

        // Reject reserved-sentinel group ids (`__*__`) on reload, same
        // guardrail the startup loader applies. A bad reload must fail
        // closed — the stored hash is NOT updated here, so the next
        // reload tick re-parses the file and re-reports the same error
        // instead of silently treating the bad state as "already loaded".
        if let Err(msg) = config.validate_operator_policy() {
            return Err(anyhow::anyhow!(
                "refusing to reload ACL file {}: {msg}",
                self.acl_path.display()
            ));
        }

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
        spawn_background("acl-reloader", async move {
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
        });
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
            destination: rustgate_core::message::Destination::Group("alpha".into()),
            payload: bytes::Bytes::from_static(b"<msg/>"),
            metadata: rustgate_core::message::Metadata::new(
                std::time::SystemTime::now(),
                "test".to_string(),
                rustgate_core::message::MessageType::Chat,
            ),
        };
        router.route(msg).await;
        assert!(nrx_a.try_recv().is_ok(), "alice must receive in open mode");

        // Reload with UPDATED_ACL: adds bob to senders
        write_acl_file(dir.path(), UPDATED_ACL);
        assert!(reloader.reload().unwrap());

        // Now bob IS authorized (UPDATED_ACL adds bob to senders)
        let msg = rustgate_core::message::RoutableMessage {
            source: (*bob_id).clone(),
            destination: rustgate_core::message::Destination::Group("alpha".into()),
            payload: bytes::Bytes::from_static(b"<msg2/>"),
            metadata: rustgate_core::message::Metadata::new(
                std::time::SystemTime::now(),
                "test".to_string(),
                rustgate_core::message::MessageType::Chat,
            ),
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

    /// A reload that would swap in a policy keyed by a reserved
    /// sentinel (e.g. `__plaintext__`) must fail closed: the reload
    /// returns an error, the router continues to serve the previous
    /// policy, and the stored hash stays on the previous value so the
    /// next poll re-reports the same error instead of silently
    /// treating the bad file as "already loaded".
    ///
    /// Regression for issue #749 — the scenario where an operator
    /// hot-edits the ACL JSON to reference the synthetic plaintext
    /// group and the reloader would otherwise happily swap that into
    /// the dispatch path.
    #[test]
    fn reload_rejects_reserved_sentinel_group() {
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(dir.path(), INITIAL_ACL);

        let initial_hash = AclReloader::compute_hash(INITIAL_ACL.as_bytes());
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(
            dir.path().join("acl.json"),
            Arc::clone(&router),
            initial_hash,
        );

        // Overwrite with a file whose only group is the reserved
        // plaintext sentinel.
        write_acl_file(
            dir.path(),
            r#"{
                "groups": {
                    "__plaintext__": {"send": ["alice"]}
                }
            }"#,
        );

        let err = reloader
            .reload()
            .expect_err("sentinel-keyed policy must be rejected on reload");
        let msg = err.to_string();
        assert!(
            msg.contains("__plaintext__"),
            "error must name the offending key: {msg}"
        );
        assert!(msg.contains("reserved"), "error must explain why: {msg}");

        // Router policy is untouched — no ACL was ever installed by
        // the initial call path, so snapshot stays None.
        let snap = router.acl_snapshot();
        assert!(snap.as_ref().is_none(), "router must keep prior state");

        // Prove the stored hash was NOT advanced to the bad-file hash:
        // overwrite with a *different* good policy (`UPDATED_ACL`
        // — differs from `INITIAL_ACL` — so the hash comparison
        // genuinely detects a change) and assert the reload swaps. If
        // the reloader had mistakenly stored the sentinel file's hash,
        // the next reload path would skip the parse entirely.
        write_acl_file(dir.path(), UPDATED_ACL);
        assert!(
            reloader.reload().unwrap(),
            "after writing a different valid file, next reload must swap"
        );
    }

    // ── Contract-shape coverage ─────────────────────────────────────
    //
    // The tests above drive the sunny path and a handful of failure
    // branches.  The ones below pin contract-shape surface — Send+Sync
    // bounds (so the `spawn_watcher` task compiles at every call site),
    // the empty-input boundary on the hash helper, the "bad reload
    // must not advance the stored hash" fail-closed invariant, the
    // empty-policy-swaps-to-None optimisation, the case-insensitive
    // CN normalisation at reload time, the deny-list branches in the
    // policy builder, and the operator-triage error-message format.
    // A refactor that quietly drops any of those still passes every
    // sunny-path test in this module but breaks operator workflows.
    //
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn arc_acl_reloader_is_send_and_sync_for_background_task() {
        // `spawn_watcher` moves `Arc<Self>` into `tokio::spawn`; an
        // accidental `Rc<…>` or a `!Sync` field (e.g. a `Cell`) would
        // fail to compile at the spawn site, not here. Pin the bound
        // local to the module so the offending refactor lights up the
        // nearest test binary first.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Arc<AclReloader>>();
    }

    #[test]
    fn compute_hash_empty_input_matches_known_sha256_boundary() {
        // Pin the SHA-256 of the empty byte slice so a refactor that
        // silently swapped to a different digest algorithm (e.g.
        // SHA3-256) fails here rather than at the first real reload.
        // The literal is the canonical all-zero-length SHA-256.
        let expected =
            hex_literal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(AclReloader::compute_hash(b""), expected);
    }

    #[test]
    fn compute_hash_output_length_is_thirty_two_bytes() {
        // `[u8; 32]` is part of the public-ish return signature —
        // `set_hash` and `new` both accept exactly 32 bytes, and the
        // background poll writes `new_hash` back into the `[u8; 32]`
        // Mutex cell. A regression that widened the return to `Vec<u8>`
        // or narrowed to `[u8; 16]` would fail here at test-compile
        // time rather than propagating silently through the call graph.
        let h = AclReloader::compute_hash(b"x");
        let _compile_pin: [u8; 32] = h;
    }

    #[test]
    fn reload_does_not_advance_stored_hash_on_parse_failure() {
        // The fail-closed invariant: if a reload tick reads a bad file
        // (invalid JSON), the stored hash must NOT be updated. The
        // next poll must therefore re-read and re-report the same
        // error rather than silently treating the bad file as
        // "already loaded" and skipping it forever. A regression that
        // moved the `*guard = new_hash` line above the parse/validate
        // step would break this — an operator who accidentally shipped
        // a malformed ACL would see one warn line and then silent
        // amnesia thereafter.
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(dir.path(), INITIAL_ACL);
        let initial_hash = AclReloader::compute_hash(INITIAL_ACL.as_bytes());
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(dir.path().join("acl.json"), router, initial_hash);

        // Corrupt the file: first reload MUST error.
        write_acl_file(dir.path(), "not valid json");
        let first = reloader.reload();
        assert!(first.is_err(), "corrupt file must error on first reload");

        // Second reload of the SAME bad file MUST also error — a
        // regression that advanced the stored hash to the bad-file
        // hash would silently return `Ok(false)` here.
        let second = reloader.reload();
        assert!(
            second.is_err(),
            "stored hash must not advance on parse failure; next reload must re-report the error"
        );
    }

    #[test]
    fn reload_does_not_advance_stored_hash_on_missing_file() {
        // Same fail-closed invariant on the file-read failure branch
        // (the earlier `read_to_string` error). A transient permission
        // glitch or a disappeared mount point must leave the stored
        // hash on the previous value so recovery lands cleanly on the
        // next poll tick.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acl.json");
        write_acl_file(dir.path(), INITIAL_ACL);
        let initial_hash = AclReloader::compute_hash(INITIAL_ACL.as_bytes());
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(&path, router, initial_hash);

        // Remove the file: first reload MUST error.
        std::fs::remove_file(&path).unwrap();
        assert!(
            reloader.reload().is_err(),
            "missing file must error on first reload"
        );
        // Still missing: second reload MUST also error.
        assert!(
            reloader.reload().is_err(),
            "stored hash must not advance on read failure"
        );

        // Restore a good file: next reload MUST swap (proves the
        // stored hash is still the INITIAL hash, not the empty-file
        // hash from the missing state).
        write_acl_file(dir.path(), UPDATED_ACL);
        assert!(
            reloader.reload().unwrap(),
            "recovery must swap once the file is valid again"
        );
    }

    #[tokio::test]
    async fn reload_swaps_to_none_when_policy_becomes_empty() {
        // An empty `groups: {}` file is a legitimate operator action —
        // "there's no ACL policy any more, fall back to unrestricted".
        // The reloader distinguishes this from `Some(empty policy)` by
        // installing `None` into the router's `ArcSwap`. A regression
        // that installed `Some(policy)` with `policy.is_empty() ==
        // true` would flip every group's default from "no policy =
        // allow" to "policy exists but no allow-list = deny-all".
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(dir.path(), INITIAL_ACL);
        let initial_hash = AclReloader::compute_hash(INITIAL_ACL.as_bytes());
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(
            dir.path().join("acl.json"),
            Arc::clone(&router),
            initial_hash,
        );

        // First reload: install the initial policy (non-empty).
        // Overwrite with an empty-groups file so the next reload
        // genuinely differs.
        write_acl_file(dir.path(), r#"{"groups": {}}"#);
        assert!(reloader.reload().unwrap(), "empty-groups reload must swap");

        let snap = router.acl_snapshot();
        assert!(
            snap.as_ref().is_none(),
            "empty policy must install as None, not Some(empty policy)"
        );
    }

    #[tokio::test]
    async fn reload_normalises_acl_cns_to_ascii_lowercase() {
        // Defence-in-depth: ACL entries are compared case-insensitively
        // in the router, but the reloader additionally lowercases at
        // install time so every downstream reader sees a single
        // canonical form regardless of how the operator wrote the JSON.
        // A regression that dropped the `.map(|s| s.to_ascii_lowercase())`
        // on any of the four lists would silently break every case-
        // varying ACL file (and there's no lint to catch it).
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(
            dir.path(),
            r#"{
                "groups": {
                    "alpha": {
                        "send": ["ALICE"],
                        "receive": ["BOB"],
                        "deny_send": ["CHARLIE"],
                        "deny_receive": ["DAVE"]
                    }
                }
            }"#,
        );
        let initial_hash = AclReloader::compute_hash(b""); // forces change detection
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(
            dir.path().join("acl.json"),
            Arc::clone(&router),
            initial_hash,
        );
        assert!(reloader.reload().unwrap(), "first reload must swap");

        let snap = router.acl_snapshot();
        let policy = snap
            .as_ref()
            .as_ref()
            .expect("policy must be installed after reload");
        let alpha = policy
            .groups()
            .get("alpha")
            .expect("group alpha must be present");
        assert!(
            alpha.senders().contains("alice"),
            "send CNs must be lowercased on reload"
        );
        assert!(
            alpha.receivers().contains("bob"),
            "receive CNs must be lowercased on reload"
        );
        assert!(
            alpha.deny_senders().contains("charlie"),
            "deny_send CNs must be lowercased on reload"
        );
        assert!(
            alpha.deny_receivers().contains("dave"),
            "deny_receive CNs must be lowercased on reload"
        );
        // Negative: the upper-case form must NOT be present — a
        // regression that only lowercased *some* of the four lists
        // would slip past the positive checks by duplicating data.
        assert!(!alpha.senders().contains("ALICE"));
        assert!(!alpha.receivers().contains("BOB"));
        assert!(!alpha.deny_senders().contains("CHARLIE"));
        assert!(!alpha.deny_receivers().contains("DAVE"));
    }

    #[tokio::test]
    async fn reload_installs_multiple_groups_independently() {
        // Multi-group parsing smoke: a two-group file must produce a
        // `GroupAclPolicy` where both groups are independently keyed
        // (a regression that used a single shared `HashMap` insert
        // slot would clobber one). Also pins the group_count field
        // that the audit log line emits.
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(
            dir.path(),
            r#"{
                "groups": {
                    "alpha": {"send": ["alice"], "receive": ["alice"]},
                    "beta":  {"send": ["bob"],   "receive": ["bob"]}
                }
            }"#,
        );
        let initial_hash = AclReloader::compute_hash(b"");
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(
            dir.path().join("acl.json"),
            Arc::clone(&router),
            initial_hash,
        );
        assert!(reloader.reload().unwrap(), "first reload must swap");

        let snap = router.acl_snapshot();
        let policy = snap.as_ref().as_ref().expect("policy installed");
        assert_eq!(policy.len(), 2, "both groups must be installed");
        assert!(policy.groups().contains_key("alpha"));
        assert!(policy.groups().contains_key("beta"));
    }

    #[tokio::test]
    async fn reload_carries_deny_send_and_deny_receive_through_to_router() {
        // Pins the full `GroupAcl::with_deny(send, receive, deny_send,
        // deny_receive)` argument plumbing. A regression that passed
        // the same list twice (e.g. `deny_send` in both positions)
        // would still compile and still pass every sunny-path test,
        // but would break the deny-first precedence the router
        // documents for `is_send_authorized` / `is_receive_authorized`.
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(
            dir.path(),
            r#"{
                "groups": {
                    "alpha": {
                        "send": ["alice", "mallory"],
                        "receive": ["alice", "eve"],
                        "deny_send": ["mallory"],
                        "deny_receive": ["eve"]
                    }
                }
            }"#,
        );
        let initial_hash = AclReloader::compute_hash(b"");
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(
            dir.path().join("acl.json"),
            Arc::clone(&router),
            initial_hash,
        );
        assert!(reloader.reload().unwrap(), "reload must swap");
        let snap = router.acl_snapshot();
        let policy = snap.as_ref().as_ref().expect("policy installed");

        // Deny-first precedence is documented on
        // `GroupAclPolicy::is_send_authorized` — mallory is on both
        // lists and must be denied.
        assert!(policy.is_send_authorized("alpha", "alice"));
        assert!(!policy.is_send_authorized("alpha", "mallory"));
        assert!(policy.is_receive_authorized("alpha", "alice"));
        assert!(!policy.is_receive_authorized("alpha", "eve"));
    }

    #[test]
    fn reload_error_on_parse_failure_names_file_path_for_operator_triage() {
        // The `anyhow::anyhow!("failed to parse ACL file {}: {e}", …)`
        // format is the operator's only trace breadcrumb when the
        // reload audit line fires. A refactor that dropped the path
        // interpolation (e.g. replaced `{}` with a generic "ACL file")
        // would make multi-ACL deployments impossible to debug from
        // logs alone. Pin the path token in the error string.
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(dir.path(), INITIAL_ACL);
        let initial_hash = AclReloader::compute_hash(INITIAL_ACL.as_bytes());
        let router = Arc::new(Router::new());
        let path = dir.path().join("acl.json");
        let reloader = AclReloader::new(&path, router, initial_hash);

        write_acl_file(dir.path(), "not valid json");
        let err = reloader.reload().expect_err("invalid JSON must error");
        let msg = err.to_string();
        assert!(
            msg.contains(&path.display().to_string()),
            "error must name the offending file path: {msg}"
        );
        assert!(
            msg.contains("parse"),
            "error must explain the failure mode: {msg}"
        );
    }

    #[test]
    fn reload_error_on_missing_file_names_file_path_for_operator_triage() {
        // Same contract on the read-failure branch. The
        // `anyhow::anyhow!("failed to read ACL file {}: {e}", …)`
        // wrap is the only signal an operator has to distinguish "I
        // forgot to create the file" from "JSON syntax error".
        let path = std::path::PathBuf::from("/nonexistent/deliberately-missing/acl.json");
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(&path, router, AclReloader::compute_hash(b""));
        let err = reloader.reload().expect_err("missing file must error");
        let msg = err.to_string();
        assert!(
            msg.contains(&path.display().to_string()),
            "error must name the missing path: {msg}"
        );
        assert!(
            msg.contains("read"),
            "error must distinguish the read-failure branch: {msg}"
        );
    }

    #[tokio::test]
    async fn spawn_watcher_returns_immediately_without_panicking() {
        // The `spawn_watcher` signature takes `self: &Arc<Self>` so
        // the caller can keep a reference for later `set_hash` calls.
        // The watcher runs forever in a detached task; the sanity
        // pin is that constructing and calling the method does not
        // panic synchronously (e.g. the `drop(tokio::spawn(…))`
        // pattern swallows nothing it should propagate). Drive with
        // a tiny interval to force at least one tick under the test
        // before the test ends; rely on tempdir drop + tokio runtime
        // shutdown to cut the detached task short.
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(dir.path(), INITIAL_ACL);
        let initial_hash = AclReloader::compute_hash(INITIAL_ACL.as_bytes());
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(dir.path().join("acl.json"), router, initial_hash);
        // Must be callable on `&Arc<Self>` — a regression that
        // narrowed to `self` (owned) would break every real caller,
        // which keeps an Arc for mutation via `set_hash`.
        reloader.spawn_watcher(Duration::from_millis(10));
        // Let the task tick at least once so the loop body executes
        // (proves `reload` is actually called through the blocking
        // offload path). Bounded sleep so CI stays fast.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn set_hash_updates_stored_hash_observable_via_subsequent_reload() {
        // The `set_hash` metrics-feature hook is called by the REST
        // API after a mutation so the next poll does not re-detect
        // the same change as a pending reload. Pin the contract: if
        // `set_hash` is called with the on-disk file's hash, the
        // next `reload` call must return `Ok(false)` (unchanged) even
        // though the in-memory last_hash was previously stale.
        let dir = tempfile::tempdir().unwrap();
        write_acl_file(dir.path(), INITIAL_ACL);
        // Start with a DELIBERATELY WRONG initial hash so the first
        // reload would normally detect change.
        let wrong_hash = AclReloader::compute_hash(b"");
        let router = Arc::new(Router::new());
        let reloader = AclReloader::new(dir.path().join("acl.json"), router, wrong_hash);
        // Advance the stored hash to match the on-disk file out-of-
        // band (the API-mutation path).
        reloader.set_hash(AclReloader::compute_hash(INITIAL_ACL.as_bytes()));
        // Next reload must see "unchanged" and return false.
        assert!(
            !reloader.reload().unwrap(),
            "reload after set_hash to on-disk hash must observe no change"
        );
    }

    /// Decode a 64-character lower-hex string to `[u8; 32]`.  Kept
    /// local so this module does not take a dev-dep on the `hex`
    /// crate for a single compile-time constant.
    fn hex_literal(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "hex literal must be 64 chars for 32 bytes");
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(chunk[0]);
            let lo = hex_digit(chunk[1]);
            out[i] = (hi << 4) | lo;
        }
        out
    }

    fn hex_digit(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => 10 + b - b'a',
            b'A'..=b'F' => 10 + b - b'A',
            _ => panic!("invalid hex digit: {b}"),
        }
    }
}
