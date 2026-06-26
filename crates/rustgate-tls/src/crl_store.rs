// Copyright © 2026 Roberto Chiofalo.

//! Hot-swappable, generation-counted certificate-revocation-list store.
//!
//! Client-cert revocation used to be frozen at boot: the CRL list was baked
//! into a static [`rustls::server::WebPkiClientVerifier`] and nothing swapped a
//! freshly-published CRL into the live listener — an operator had to restart the
//! server for a `/api/revoke` to take effect (issue #1496, ADR 0025).
//!
//! [`CrlStore`] fixes that. It holds the parsed CRL list behind an [`RwLock`]
//! with a monotonic **generation counter**, mirrors the
//! [`crate::cert_reloader::CertReloader`] SHA-256 change-detection pattern, and
//! exposes a cheap [`CrlStore::snapshot`] that the [`crate::DynamicCertVerifier`]
//! pulls on its rebuild path. A background [`CrlStore::spawn_watcher`] task — or
//! SIGHUP / the management API — drives [`CrlStore::reload`], bumping the
//! generation only when the file's bytes actually change, so the live verifier
//! observes new revocations on the next handshake with no `ServerConfig`
//! rebuild and no restart.
//!
//! CRLs are public artifacts, so the file is read with a plain `std::fs::read`
//! (no `Zeroizing`); only the bytes-changed hash and the parsed list are kept.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use rustls::pki_types::CertificateRevocationListDer;
use rustls::pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use x509_parser::prelude::parse_x509_crl;

use rustgate_core::error::{ConfigError, Result, RustgateError};
use rustgate_core::tasks::spawn_background;

/// Freshness summary of the currently-loaded CRL set, recomputed on every
/// successful [`CrlStore::reload`]. Drives the (opt-in) fail-closed staleness
/// gate in a later piece and the management-API revocation status.
#[derive(Debug, Clone, Default)]
pub struct CrlHealth {
    /// Number of CRLs that parsed and carry a `nextUpdate` field.
    pub parsed_count: usize,
    /// `true` when **every** parsed CRL with a `nextUpdate` is in the past.
    /// Deliberately all-stale (not any-stale): a single fresh sibling CRL keeps
    /// the set usable. A set with zero parsed CRLs is **not** all-stale — an
    /// empty-but-valid CRL (no revocations) is a healthy state, not a failure.
    pub all_stale: bool,
}

/// Internal swap unit — the parsed list, its generation, and the change-detect
/// hash, replaced atomically under the write lock.
#[derive(Debug)]
struct CrlState {
    crls: Arc<Vec<CertificateRevocationListDer<'static>>>,
    generation: u64,
    hash: [u8; 32],
    health: CrlHealth,
}

/// A file-backed CRL set that can be reloaded at runtime without a restart.
#[derive(Debug)]
pub struct CrlStore {
    path: PathBuf,
    state: RwLock<CrlState>,
}

impl CrlStore {
    /// Load the CRL file at `path` and build the initial store (generation 1).
    ///
    /// Returns an error if the file cannot be read or contains no valid CRL —
    /// the same strictness as boot-time [`crate::TlsConfig::with_crls`], so a
    /// misconfigured `--crl` fails fast rather than starting with an empty set.
    pub fn from_path(path: &Path) -> Result<Arc<Self>> {
        let bytes = read_crl_file(path)?;
        let (crls, hash, health) = parse_and_summarize(&bytes, path)?;
        info!(
            path = %path.display(),
            count = crls.len(),
            all_stale = health.all_stale,
            "loaded certificate revocation lists",
        );
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            state: RwLock::new(CrlState {
                crls: Arc::new(crls),
                generation: 1,
                hash,
                health,
            }),
        }))
    }

    /// Re-read the CRL file and swap it in if the bytes changed.
    ///
    /// Returns `Ok(true)` when a new generation was installed, `Ok(false)` when
    /// the file was byte-identical to the loaded set (no generation bump). A
    /// parse failure on a *changed* file is an error and the previous generation
    /// is retained — a corrupt republish never silently empties the live set.
    pub fn reload(&self) -> Result<bool> {
        let bytes = read_crl_file(&self.path)?;
        let new_hash: [u8; 32] = Sha256::digest(&bytes).into();

        {
            let guard = self
                .state
                .read()
                .map_err(|_| ConfigError::Other("CRL store lock poisoned".to_string()))?;
            if guard.hash == new_hash {
                debug!(path = %self.path.display(), "CRL file unchanged");
                return Ok(false);
            }
        }

        let (crls, hash, health) = parse_and_summarize(&bytes, &self.path)?;
        let count = crls.len();
        {
            let mut guard = self
                .state
                .write()
                .map_err(|_| ConfigError::Other("CRL store lock poisoned".to_string()))?;
            guard.crls = Arc::new(crls);
            guard.generation = guard.generation.wrapping_add(1);
            guard.hash = hash;
            guard.health = health.clone();
        }
        info!(
            path = %self.path.display(),
            count,
            all_stale = health.all_stale,
            "certificate revocation lists reloaded",
        );
        rustgate_core::audit::crl_reload_success(count, "file");
        Ok(true)
    }

    /// Cheap snapshot for the verifier's rebuild path: the current generation
    /// and a refcount-bumped handle to the immutable CRL list. Hot-path safe —
    /// a read-lock + two `Arc` clones, no parsing or allocation of CRL bytes.
    pub fn snapshot(&self) -> (u64, Arc<Vec<CertificateRevocationListDer<'static>>>) {
        match self.state.read() {
            Ok(guard) => (guard.generation, Arc::clone(&guard.crls)),
            // A poisoned lock should never happen (no panics under the lock);
            // fail safe by reporting generation 0 + an empty list so the
            // verifier rebuilds into a no-CRL state rather than panicking on the
            // handshake thread.
            Err(_) => (0, Arc::new(Vec::new())),
        }
    }

    /// Current freshness summary (cloned).
    pub fn health(&self) -> CrlHealth {
        self.state
            .read()
            .map(|g| g.health.clone())
            .unwrap_or_default()
    }

    /// Current generation counter (test/diagnostic accessor).
    pub fn generation(&self) -> u64 {
        self.state.read().map(|g| g.generation).unwrap_or(0)
    }

    /// Spawn a background task that re-reads the CRL file every `interval`.
    ///
    /// Fire-and-forget (matches [`crate::cert_reloader::CertReloader::spawn_watcher`]);
    /// the file read runs on a blocking thread so it never stalls the runtime.
    /// A zero interval is a no-op — the caller gates on `--crl-refresh-interval`.
    pub fn spawn_watcher(self: &Arc<Self>, interval: Duration) {
        if interval.is_zero() {
            debug!("CRL watcher skipped: refresh interval is 0");
            return;
        }
        let store = Arc::clone(self);
        spawn_background("crl-reloader", async move {
            let mut tick = tokio::time::interval(interval);
            // Skip the immediate first tick — the initial load already happened
            // in `from_path`; poll only after one full interval.
            let _ = tick.tick().await;
            loop {
                let _ = tick.tick().await;
                let s = Arc::clone(&store);
                let path = store.path.display().to_string();
                match tokio::task::spawn_blocking(move || s.reload()).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        warn!(path = %path, error = %e, "CRL reload failed");
                        rustgate_core::audit::crl_reload_failed(&path, &e.to_string());
                    }
                    Err(e) => {
                        warn!(path = %path, error = %e, "CRL reload task panicked");
                    }
                }
            }
        });
    }
}

/// Read the CRL file. CRLs are public — a plain read, no secret-file handling.
fn read_crl_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        RustgateError::from(ConfigError::Other(format!(
            "failed to read CRL file {}: {e}",
            path.display()
        )))
    })
}

/// Parse a PEM CRL bundle into DER, reject an empty set, and summarize freshness.
fn parse_and_summarize(
    bytes: &[u8],
    path: &Path,
) -> Result<(
    Vec<CertificateRevocationListDer<'static>>,
    [u8; 32],
    CrlHealth,
)> {
    let crls: Vec<CertificateRevocationListDer<'static>> =
        CertificateRevocationListDer::pem_slice_iter(bytes)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                RustgateError::from(ConfigError::PemParse {
                    kind: "CRL".to_string(),
                    reason: e.to_string(),
                })
            })?;
    if crls.is_empty() {
        return Err(ConfigError::EmptyPem {
            kind: "CRLs".to_string(),
        }
        .into());
    }
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    let health = summarize_health(&crls, path);
    Ok((crls, hash, health))
}

/// Compute the all-stale freshness summary by parsing each CRL's `nextUpdate`.
fn summarize_health(crls: &[CertificateRevocationListDer<'static>], path: &Path) -> CrlHealth {
    let now = x509_parser::time::ASN1Time::now();
    let mut parsed_count = 0usize;
    let mut any_fresh = false;
    for (i, der) in crls.iter().enumerate() {
        match parse_x509_crl(der.as_ref()) {
            Ok((_, crl)) => {
                if let Some(next_update) = crl.next_update() {
                    parsed_count += 1;
                    if next_update >= now {
                        any_fresh = true;
                    } else {
                        warn!(
                            path = %path.display(),
                            crl_index = i,
                            next_update = %next_update,
                            "CRL is stale — nextUpdate is in the past",
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    crl_index = i,
                    error = %e,
                    "failed to parse CRL for freshness check — skipping",
                );
            }
        }
    }
    // all_stale only when there is at least one CRL carrying a nextUpdate and
    // none of them are fresh. Zero parsed (no nextUpdate anywhere) is treated as
    // not-all-stale: an absent nextUpdate or a no-revocations CRL is healthy.
    CrlHealth {
        parsed_count,
        all_stale: parsed_count > 0 && !any_fresh,
    }
}
