// Copyright © 2026 Roberto Chiofalo.

//! Authz policy file hot-reload via polling.
//!
//! Mirrors [`crate::acl_reloader::AclReloader`]: compute a SHA-256 digest
//! of the on-disk JSON policy file, compare against the last successfully
//! loaded digest, and when the file content changes parse + compile the
//! new policy **before** swapping it onto the router. Parse or compile
//! failures leave the previous engine in place so a bad edit never
//! interrupts enforcement.
//!
//! Every reload outcome — success, read error, parse error, or compile
//! error — emits a structured audit event via
//! [`rustgate_core::audit`] and updates the authz reload metrics when
//! the `metrics` feature is enabled.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustgate_authz::{NativeEngine, PolicyEngine, parser};
use rustgate_core::audit;
use rustgate_transport::Router;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// Maximum policy-file size the reloader will read from disk.
///
/// Authz policies are hand-authored JSON and realistic rule counts hover
/// in the low hundreds; even an expansive production policy with
/// thousands of rules comfortably fits inside a megabyte. We cap the
/// read at 4 MiB so that a malformed, runaway, or adversarial file
/// cannot exhaust server memory via [`std::fs::read`], which slurps the
/// entire file into a contiguous buffer before parse+compile ever
/// runs. Exceeding the cap fails the load with a `read`-stage audit
/// event so operators see the same structured error they would see
/// for a missing file.
pub(crate) const MAX_POLICY_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Read the policy file at `path`, rejecting files larger than
/// [`MAX_POLICY_FILE_BYTES`].
///
/// We check the file length via [`std::fs::metadata`] before the read
/// so that an adversarial multi-gigabyte file never lands in memory.
/// A partial-read race (file grew between `metadata` and `read`) would
/// still produce a bounded buffer because `std::fs::read` caps the
/// allocation at what was available at open time, but we layer a
/// defensive post-read length check as well: any read that somehow
/// returns more than the cap is rejected before parse.
///
/// Returns the raw bytes on success, or a [`std::io::Error`] with the
/// kind preserved so callers can differentiate "file missing" from
/// "file too large" in their audit emission.
fn read_policy_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    // Stat first so an oversize file never allocates.
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_POLICY_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "authz policy file size {} bytes exceeds cap of {} bytes",
                meta.len(),
                MAX_POLICY_FILE_BYTES
            ),
        ));
    }
    let data = std::fs::read(path)?;
    // Defence-in-depth: the file could have grown between `metadata`
    // and `read`. Reject rather than quietly accept a buffer larger
    // than the advertised cap.
    if data.len() as u64 > MAX_POLICY_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "authz policy file grew past cap during read: {} bytes > {}",
                data.len(),
                MAX_POLICY_FILE_BYTES
            ),
        ));
    }
    Ok(data)
}

/// Result of a single synchronous policy load.
#[derive(Debug)]
pub(crate) struct LoadedPolicy {
    pub(crate) engine: NativeEngine,
    pub(crate) rule_count: usize,
    pub(crate) hash: [u8; 32],
}

/// Read, parse, and compile the policy at `path`.
///
/// On failure, emits an `authz.reload_failed` audit event identifying the
/// stage that failed (`"read"`, `"parse"`, or `"compile"`) and returns
/// the error so the caller can decide whether to abort startup or continue
/// in fail-open mode.
pub(crate) fn load_once(path: &Path) -> anyhow::Result<LoadedPolicy> {
    let path_display = path.display().to_string();

    let data = match read_policy_bounded(path) {
        Ok(d) => d,
        Err(e) => {
            audit::authz_reload_failed(&path_display, "read", &e.to_string());
            return Err(anyhow::anyhow!(
                "failed to read authz policy file {path_display}: {e}"
            ));
        }
    };

    let rule_set = match parser::parse_json(&data) {
        Ok(rs) => rs,
        Err(e) => {
            audit::authz_reload_failed(&path_display, "parse", &e.to_string());
            return Err(anyhow::anyhow!(
                "failed to parse authz policy file {path_display}: {e}"
            ));
        }
    };

    let rule_count = rule_set.rules.len();

    let engine = match NativeEngine::new(rule_set) {
        Ok(eng) => eng,
        Err(e) => {
            audit::authz_reload_failed(&path_display, "compile", &e.to_string());
            return Err(anyhow::anyhow!(
                "failed to compile authz policy file {path_display}: {e}"
            ));
        }
    };

    let hash = compute_hash(&data);
    Ok(LoadedPolicy {
        engine,
        rule_count,
        hash,
    })
}

/// Watches an authz policy file and hot-reloads the router's engine on
/// change. The initial load is the caller's responsibility (see
/// [`load_once`]) so startup can fail fast on a malformed policy.
pub(crate) struct AuthzReloader {
    path: PathBuf,
    router: Arc<Router>,
    last_hash: std::sync::Mutex<[u8; 32]>,
}

impl AuthzReloader {
    pub(crate) fn new(
        path: impl Into<PathBuf>,
        router: Arc<Router>,
        initial_hash: [u8; 32],
    ) -> Arc<Self> {
        Arc::new(Self {
            path: path.into(),
            router,
            last_hash: std::sync::Mutex::new(initial_hash),
        })
    }

    /// Re-read the policy file and swap if changed. Returns `Ok(true)`
    /// when the engine was swapped, `Ok(false)` when the file was
    /// unchanged. Errors are already audited by [`load_once`].
    pub(crate) fn reload(&self) -> anyhow::Result<bool> {
        // Quick digest check before any parse work. `read_policy_bounded`
        // caps the read at MAX_POLICY_FILE_BYTES so an oversized file
        // cannot exhaust memory on a poll cycle.
        let data = match read_policy_bounded(&self.path) {
            Ok(d) => d,
            Err(e) => {
                audit::authz_reload_failed(
                    &self.path.display().to_string(),
                    "read",
                    &e.to_string(),
                );
                return Err(anyhow::anyhow!(
                    "failed to read authz policy file {}: {e}",
                    self.path.display()
                ));
            }
        };
        let new_hash = compute_hash(&data);
        {
            let guard = self
                .last_hash
                .lock()
                .map_err(|_| anyhow::anyhow!("authz reloader hash lock poisoned"))?;
            if *guard == new_hash {
                debug!(path = %self.path.display(), "authz policy file unchanged");
                return Ok(false);
            }
        }

        // Validate (parse + compile) before swapping. `load_once` would
        // re-read the file; inline the remaining steps here so we only
        // read once per poll cycle.
        let path_display = self.path.display().to_string();
        let rule_set = match parser::parse_json(&data) {
            Ok(rs) => rs,
            Err(e) => {
                audit::authz_reload_failed(&path_display, "parse", &e.to_string());
                return Err(anyhow::anyhow!(
                    "failed to parse authz policy file {path_display}: {e}"
                ));
            }
        };
        let rule_count = rule_set.rules.len();
        let engine = match NativeEngine::new(rule_set) {
            Ok(eng) => eng,
            Err(e) => {
                audit::authz_reload_failed(&path_display, "compile", &e.to_string());
                return Err(anyhow::anyhow!(
                    "failed to compile authz policy file {path_display}: {e}"
                ));
            }
        };

        let policy_id = engine.policy_id().to_string();
        let arc_engine: Arc<dyn PolicyEngine> = Arc::new(engine);
        self.router.swap_authz(arc_engine);

        {
            let mut guard = self
                .last_hash
                .lock()
                .map_err(|_| anyhow::anyhow!("authz reloader hash lock poisoned"))?;
            *guard = new_hash;
        }

        audit::authz_reload_success(&path_display, &policy_id, rule_count);
        #[cfg(feature = "metrics")]
        crate::metrics::record_authz_reload(true, Some(rule_count));

        info!(
            path = %self.path.display(),
            policy_id = %policy_id,
            rule_count,
            "authz policy reloaded"
        );
        Ok(true)
    }

    /// Spawn a background polling task. File I/O runs on a blocking
    /// thread so the async runtime is never stalled.
    pub(crate) fn spawn_watcher(self: &Arc<Self>, interval: Duration) {
        let reloader = Arc::clone(self);
        drop(tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            let _ = tick.tick().await; // skip immediate first tick
            loop {
                let _ = tick.tick().await;
                let r = Arc::clone(&reloader);
                let result = tokio::task::spawn_blocking(move || r.reload()).await;
                match result {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        warn!(
                            path = %reloader.path.display(),
                            error = %e,
                            "authz reload failed"
                        );
                        #[cfg(feature = "metrics")]
                        crate::metrics::record_authz_reload(false, None);
                    }
                    Err(e) => {
                        warn!(
                            path = %reloader.path.display(),
                            error = %e,
                            "authz reload task panicked"
                        );
                        #[cfg(feature = "metrics")]
                        crate::metrics::record_authz_reload(false, None);
                    }
                }
            }
        }));
    }
}

/// Spawn a watcher task. Convenience wrapper used from `main.rs`.
pub(crate) fn spawn_authz_reloader(
    router: Arc<Router>,
    path: PathBuf,
    initial_hash: [u8; 32],
    interval: Duration,
) -> Arc<AuthzReloader> {
    let reloader = AuthzReloader::new(path, router, initial_hash);
    reloader.spawn_watcher(interval);
    reloader
}

pub(crate) fn compute_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    const ALLOW_ALL: &str = r#"{
        "version": 1,
        "default_effect": "deny",
        "rules": [
            {
                "id": "allow-all-send",
                "effect": "allow",
                "action": "send",
                "subject": {},
                "resource": { "kind": "any" }
            }
        ]
    }"#;

    const DENY_ALL: &str = r#"{
        "version": 1,
        "default_effect": "deny",
        "rules": []
    }"#;

    #[test]
    fn load_once_rejects_missing_file() {
        let result = load_once(Path::new("/nonexistent/authz.json"));
        assert!(result.is_err());
    }

    #[test]
    fn load_once_rejects_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        std::fs::write(&path, "not valid json").unwrap();
        let result = load_once(&path);
        assert!(result.is_err());
    }

    #[test]
    fn load_once_accepts_valid_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        std::fs::write(&path, ALLOW_ALL).unwrap();
        let loaded = load_once(&path).unwrap();
        assert_eq!(loaded.rule_count, 1);
    }

    #[test]
    fn reload_detects_change_and_swaps_engine() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        std::fs::write(&path, ALLOW_ALL).unwrap();
        let initial = load_once(&path).unwrap();
        let router = Arc::new(Router::new().with_authz(Arc::new(initial.engine)));
        let first_id = router.authz_snapshot().unwrap().policy_id().to_string();

        let reloader = AuthzReloader::new(&path, Arc::clone(&router), initial.hash);
        assert!(!reloader.reload().unwrap(), "unchanged file must not swap");

        std::fs::write(&path, DENY_ALL).unwrap();
        assert!(reloader.reload().unwrap(), "changed file must swap");
        let second_id = router.authz_snapshot().unwrap().policy_id().to_string();
        assert_ne!(first_id, second_id, "policy id should change after reload");
    }

    #[test]
    fn reload_keeps_last_good_on_malformed_update() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        std::fs::write(&path, ALLOW_ALL).unwrap();
        let initial = load_once(&path).unwrap();
        let router = Arc::new(Router::new().with_authz(Arc::new(initial.engine)));
        let good_id = router.authz_snapshot().unwrap().policy_id().to_string();

        let reloader = AuthzReloader::new(&path, Arc::clone(&router), initial.hash);
        std::fs::write(&path, "not valid json").unwrap();
        assert!(reloader.reload().is_err());
        let after_id = router.authz_snapshot().unwrap().policy_id().to_string();
        assert_eq!(good_id, after_id, "bad reload must not swap engine");
    }

    #[test]
    fn load_once_rejects_oversize_file() {
        // Exceeding MAX_POLICY_FILE_BYTES must fail at the read stage
        // before parse+compile ever runs, so a hostile multi-gigabyte
        // policy cannot exhaust memory. We write cap+1 bytes of valid
        // JSON filler (a huge `rules` padding array would also work
        // but a raw-bytes buffer is cheaper and still exercises the
        // metadata check).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.json");
        let oversize = vec![b'x'; (MAX_POLICY_FILE_BYTES + 1) as usize];
        std::fs::write(&path, oversize).unwrap();
        let result = load_once(&path);
        assert!(
            result.is_err(),
            "policy file larger than cap must fail to load"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("exceeds cap"),
            "error must identify the size cap, got: {msg}"
        );
    }

    #[test]
    fn reload_rejects_oversize_file_on_update() {
        // Start with a legitimate small policy, then grow the file
        // past the cap to simulate an attacker or a broken deploy
        // pipeline that replaces the file with a huge payload. The
        // previous engine must stay installed and the error must
        // name the cap.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        std::fs::write(&path, ALLOW_ALL).unwrap();
        let initial = load_once(&path).unwrap();
        let router = Arc::new(Router::new().with_authz(Arc::new(initial.engine)));
        let good_id = router.authz_snapshot().unwrap().policy_id().to_string();

        let reloader = AuthzReloader::new(&path, Arc::clone(&router), initial.hash);
        let oversize = vec![b'x'; (MAX_POLICY_FILE_BYTES + 1) as usize];
        std::fs::write(&path, oversize).unwrap();
        let result = reloader.reload();
        assert!(result.is_err());
        let after_id = router.authz_snapshot().unwrap().policy_id().to_string();
        assert_eq!(
            good_id, after_id,
            "oversize reload must not swap the engine"
        );
    }

    #[tokio::test]
    async fn watcher_hot_reloads_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        std::fs::write(&path, ALLOW_ALL).unwrap();
        let initial = load_once(&path).unwrap();
        let router = Arc::new(Router::new().with_authz(Arc::new(initial.engine)));
        let first_id = router.authz_snapshot().unwrap().policy_id().to_string();

        let reloader = AuthzReloader::new(&path, Arc::clone(&router), initial.hash);
        reloader.spawn_watcher(Duration::from_millis(150));

        std::fs::write(&path, DENY_ALL).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        let second_id = router.authz_snapshot().unwrap().policy_id().to_string();
        assert_ne!(first_id, second_id, "watcher should have swapped engine");
    }
}
