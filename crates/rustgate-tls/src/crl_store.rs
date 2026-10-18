// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustgate_core::error::{ConfigError, Result, RustgateError};
use rustgate_core::revocation::RevokedSet;
use rustgate_core::tasks::spawn_background;
use rustls::pki_types::CertificateRevocationListDer;
use rustls::pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use x509_parser::prelude::parse_x509_crl;

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
    /// `(issuer, serial)` pairs revoked by this generation, for the
    /// mid-session revocation sweep (ADR 0025, piece 3).
    revoked: Arc<RevokedSet>,
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
        let revoked = Arc::new(revoked_set(&crls, path));
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
                revoked,
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
        let revoked = Arc::new(revoked_set(&crls, &self.path));
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
            guard.revoked = revoked;
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

    /// The revoked `(issuer, serial)` set of the current generation. Cheap — a
    /// read-lock and an `Arc` clone; the set is built once per reload.
    pub fn revoked_set(&self) -> Arc<RevokedSet> {
        match self.state.read() {
            Ok(guard) => Arc::clone(&guard.revoked),
            // Fail safe (no panics under the lock): an empty set evicts nothing.
            Err(_) => Arc::new(RevokedSet::new()),
        }
    }

    /// Current freshness summary (cloned).
    pub fn health(&self) -> CrlHealth {
        self.state
            .read()
            .map(|g| g.health.clone())
            .unwrap_or_default()
    }

    /// Re-evaluate freshness of the *currently loaded* CRL set against the wall
    /// clock and refresh the cached [`CrlHealth`], returning it.
    ///
    /// Freshness is time-relative: a CRL that was fresh at the last reload can
    /// age past its `nextUpdate` with no change to the file bytes.
    /// [`CrlStore::reload`] short-circuits on byte-identical files
    /// (`Ok(false)`) and therefore does
    /// **not** re-check staleness, so the fail-closed watcher must call this on
    /// every tick to observe a set that has silently gone stale (#1496,
    /// ADR-0025 Piece 2). Cheap — a read-lock to snapshot the `Arc<Vec<..>>`,
    /// then re-parse `nextUpdate` outside the lock, then a short write-lock to
    /// store the recomputed summary.
    pub fn reevaluate_health(&self) -> CrlHealth {
        let crls = match self.state.read() {
            Ok(guard) => Arc::clone(&guard.crls),
            Err(_) => return CrlHealth::default(),
        };
        let health = summarize_health(&crls, &self.path);
        if let Ok(mut guard) = self.state.write() {
            guard.health = health.clone();
        }
        health
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
        self.spawn_watcher_with_observer(interval, None);
    }

    /// Like [`spawn_watcher`](Self::spawn_watcher), but invokes `observer` with
    /// the current [`CrlHealth`] on **every** tick — after a reload attempt and
    /// *including* ticks where the file bytes were unchanged.
    ///
    /// This is the hook that drives the opt-in fail-closed staleness gate
    /// ([`crate::FailClosedGate`]): freshness is time-relative, so the observer
    /// must run each tick to catch a set that has aged past its `nextUpdate`
    /// with no change to the file bytes. When the file *did* change and reloads
    /// to a healthy set, the observer sees `all_stale == false` and can release
    /// the gate synchronously — recovery does not wait for inbound traffic
    /// (#1496, ADR-0025 Piece 2). `None` reproduces the plain watcher.
    pub fn spawn_watcher_with_observer(
        self: &Arc<Self>,
        interval: Duration,
        observer: Option<CrlHealthObserver>,
    ) {
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
                // Re-evaluate freshness every tick (even on an unchanged file:
                // `reload` short-circuits byte-identical bytes and never
                // re-checks staleness). Feed the result to the fail-closed
                // observer so a set that aged into staleness still engages the
                // gate, and a fresh set releases it.
                if let Some(observe) = &observer {
                    let s = Arc::clone(&store);
                    match tokio::task::spawn_blocking(move || s.reevaluate_health()).await {
                        Ok(health) => observe(&health),
                        Err(e) => {
                            warn!(error = %e, "CRL freshness re-evaluation task panicked");
                        }
                    }
                }
            }
        });
    }
}

/// Observer invoked with the current [`CrlHealth`] on every watcher tick.
///
/// Drives the opt-in fail-closed staleness gate; see
/// [`CrlStore::spawn_watcher_with_observer`].
pub type CrlHealthObserver = Arc<dyn Fn(&CrlHealth) + Send + Sync>;

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

/// Collect every revoked `(issuer CN, serial)` pair across `crls`.
///
/// Serials come from x509-parser's `BigUint::to_bytes_be`, the same form the
/// session identity's `cert_serial` uses, so a high-bit serial (DER-padded
/// with `0x00` on the wire) matches on both sides. A CRL that does not parse,
/// or whose issuer has no CN, contributes nothing: webpki still enforces it at
/// the handshake, and a session can only be issuer-matched by CN.
fn revoked_set(crls: &[CertificateRevocationListDer<'static>], path: &Path) -> RevokedSet {
    let mut set = RevokedSet::new();
    for (i, der) in crls.iter().enumerate() {
        let crl = match parse_x509_crl(der.as_ref()) {
            Ok((_, crl)) => crl,
            Err(e) => {
                warn!(path = %path.display(), crl_index = i, error = %e,
                    "CRL could not be parsed for the revocation sweep");
                continue;
            }
        };
        let Some(issuer_cn) = crl
            .issuer()
            .iter_common_name()
            .find_map(|cn| cn.as_str().ok())
        else {
            warn!(path = %path.display(), crl_index = i,
                "CRL issuer has no CN; its entries are not used by the revocation sweep");
            continue;
        };
        for revoked in crl.iter_revoked_certificates() {
            set.insert(issuer_cn, &revoked.user_certificate.to_bytes_be());
        }
    }
    set
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use rustgate_test_utils::certs::TestCa;

    use super::*;

    fn now_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    fn write_temp(pem: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rustgate-crlstore-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("crl.pem");
        std::fs::write(&p, pem).unwrap();
        p
    }

    fn identity_of(pem: &str) -> rustgate_core::identity::Identity {
        let der = rustgate_test_utils::tls::parse_certs(pem).remove(0);
        crate::extract::extract_identity(&der).unwrap()
    }

    #[test]
    fn revoked_set_matches_a_high_bit_serial_on_both_sides() {
        // ADR 0025 revision 3: a serial with its high bit set is DER-encoded
        // with a leading 0x00 in both the certificate and the CRL. The session
        // identity and the CRL entry must still produce the same key.
        let ca = TestCa::new("Sweep CA");
        let revoked = ca.issue_client_cert_with_serial("alice", &[0x80, 0x01, 0x02]);
        let kept = ca.issue_client_cert_with_serial("bob", &[0x80, 0x01, 0x03]);
        // Prove the fixture really carries the DER sign pad on the wire.
        let der = rustgate_test_utils::tls::parse_certs(&revoked.cert_pem).remove(0);
        let (_, parsed) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        assert_eq!(parsed.raw_serial(), &[0x00, 0x80, 0x01, 0x02]);
        let alice = identity_of(&revoked.cert_pem);
        assert_eq!(
            alice.attributes.get("cert_serial"),
            Some(&rustgate_core::identity::AttrValue::Str("800102".into()))
        );

        let store =
            CrlStore::from_path(&write_temp(&ca.generate_crl(&[&revoked.cert_pem]))).unwrap();
        let set = store.revoked_set();
        assert_eq!(set.len(), 1);
        assert!(set.is_revoked(&alice));
        assert!(!set.is_revoked(&identity_of(&kept.cert_pem)));
    }

    #[test]
    fn revoked_set_is_issuer_scoped_and_follows_reloads() {
        let ca = TestCa::new("Sweep CA");
        let other = TestCa::new("Other CA");
        let a = ca.issue_client_cert_with_serial("alice", &[0x11]);
        // Same serial, different issuer: must never match CA's CRL.
        let b = other.issue_client_cert_with_serial("bob", &[0x11]);

        let path = write_temp(&ca.generate_crl(&[]));
        let store = CrlStore::from_path(&path).unwrap();
        // Empty-but-fresh CRL: nothing revoked and healthy.
        assert!(store.revoked_set().is_empty());
        assert!(!store.health().all_stale);

        std::fs::write(&path, ca.generate_crl(&[&a.cert_pem])).unwrap();
        assert!(store.reload().unwrap());
        let set = store.revoked_set();
        assert!(set.is_revoked(&identity_of(&a.cert_pem)));
        assert!(!set.is_revoked(&identity_of(&b.cert_pem)));
    }

    #[test]
    fn from_path_loads_at_generation_1() {
        let ca = TestCa::new("crl-store-ca");
        let p = write_temp(&ca.generate_crl(&[]));
        let store = CrlStore::from_path(&p).unwrap();
        assert_eq!(store.generation(), 1);
        let (generation, crls) = store.snapshot();
        assert_eq!(generation, 1);
        assert!(!crls.is_empty());
    }

    #[test]
    fn reload_is_false_on_identical_bytes() {
        let ca = TestCa::new("crl-store-ca");
        let p = write_temp(&ca.generate_crl(&[]));
        let store = CrlStore::from_path(&p).unwrap();
        assert!(
            !store.reload().unwrap(),
            "byte-identical file must not bump the generation"
        );
        assert_eq!(store.generation(), 1);
    }

    #[test]
    fn reload_bumps_generation_when_file_changes() {
        let ca = TestCa::new("crl-store-ca");
        let p = write_temp(&ca.generate_crl(&[]));
        let store = CrlStore::from_path(&p).unwrap();
        let (gen0, list0) = store.snapshot();
        // Successive CRLs from the same CA get distinct serial numbers, so the
        // bytes differ and reload installs a new generation.
        std::fs::write(&p, ca.generate_crl(&[])).unwrap();
        assert!(
            store.reload().unwrap(),
            "changed bytes must install a new generation"
        );
        assert_eq!(store.generation(), gen0 + 1);
        let (gen1, list1) = store.snapshot();
        assert_eq!(gen1, 2);
        // The snapshot returns the new list (a distinct Arc).
        assert!(!Arc::ptr_eq(&list0, &list1));
    }

    #[test]
    fn fresh_crl_is_not_all_stale_but_expired_is() {
        let ca = TestCa::new("crl-store-ca");
        let fresh = write_temp(&ca.generate_crl(&[]));
        assert!(
            !CrlStore::from_path(&fresh).unwrap().health().all_stale,
            "a CRL with a future nextUpdate must not be all-stale"
        );

        let expired = write_temp(&ca.generate_expired_crl(&[]));
        assert!(
            CrlStore::from_path(&expired).unwrap().health().all_stale,
            "a CRL with a past nextUpdate must be all-stale"
        );
    }

    #[test]
    fn empty_but_fresh_crl_is_healthy_not_all_stale() {
        // ADR-0025 revision 3 regression: an empty-but-fresh CRL — a legal
        // published "nothing is revoked, I am current" list with zero revoked
        // serials and a future nextUpdate — must be HEALTHY (all_stale=false)
        // so the opt-in fail-closed gate never engages on it (#1496).
        let ca = TestCa::new("crl-store-ca");
        let p = write_temp(&ca.generate_crl(&[]));
        let store = CrlStore::from_path(&p).unwrap();
        let health = store.health();
        assert!(
            health.parsed_count > 0,
            "a CRL carrying a nextUpdate must be counted as parsed"
        );
        assert!(
            !health.all_stale,
            "an empty-but-fresh CRL must not be all-stale"
        );
    }

    #[test]
    fn reevaluate_health_recomputes_from_loaded_set() {
        // `reload` short-circuits byte-identical files and never re-checks
        // freshness, so the fail-closed watcher relies on `reevaluate_health`
        // to observe the current staleness of the loaded set. A fresh CRL
        // re-evaluates to not-all-stale; an expired one to all-stale.
        let ca = TestCa::new("crl-store-ca");
        let fresh = write_temp(&ca.generate_crl(&[]));
        let store = CrlStore::from_path(&fresh).unwrap();
        assert!(!store.reevaluate_health().all_stale);

        let expired = write_temp(&ca.generate_expired_crl(&[]));
        let store = CrlStore::from_path(&expired).unwrap();
        assert!(store.reevaluate_health().all_stale);
    }

    #[test]
    fn from_path_rejects_missing_file() {
        assert!(CrlStore::from_path(Path::new("/nonexistent/dir/crl.pem")).is_err());
    }

    #[test]
    fn from_path_rejects_non_crl_bytes() {
        let p = write_temp("definitely not a PEM CRL");
        assert!(CrlStore::from_path(&p).is_err());
    }
}
