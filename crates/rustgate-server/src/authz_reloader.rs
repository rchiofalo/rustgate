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

    let data = match std::fs::read(path) {
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
        // Quick digest check before any parse work.
        let data = match std::fs::read(&self.path) {
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
