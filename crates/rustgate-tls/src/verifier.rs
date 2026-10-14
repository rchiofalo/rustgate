// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Dynamic client certificate verifier for runtime trust store changes.
//!
//! [`DynamicCertVerifier`] implements the rustls [`ClientCertVerifier`] trait
//! and rebuilds its inner [`WebPkiClientVerifier`] when the trust store
//! generation changes. This allows adding or removing CA certificates at
//! runtime without restarting the TLS listener — changes take effect on
//! the next TLS handshake.
//!
//! The verifier is generic over its root store source: callers provide a
//! closure that returns `(generation, RootCertStore)`. This avoids a
//! direct dependency on the federation crate's `TrustStore` type.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme};
use tracing::{debug, info, warn};

/// Monotonic clock source for the fail-closed grace timer.
///
/// Abstracted behind a trait so tests can drive the grace deadline
/// deterministically without sleeping. Production uses [`SystemClock`]
/// ([`Instant::now`]); tests inject a controllable fake.
pub trait GraceClock: Send + Sync {
    /// Current monotonic instant.
    fn now(&self) -> Instant;
}

/// Real monotonic clock backed by [`Instant::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl GraceClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Opt-in fail-closed staleness gate for the live CRL verifier (ADR-0025
/// Piece 2, M-10).
///
/// When enabled, the gate observes CRL freshness on every watcher tick and,
/// once **every** parsed CRL has been stale continuously for longer than the
/// configured grace window, engages `deny_all`: the [`DynamicCertVerifier`]
/// then rejects *all* client-certificate handshakes at the top of
/// [`DynamicCertVerifier::verify_client_cert`], before delegating to the inner
/// `WebPkiClientVerifier`. A fresh, non-stale CRL clears the gate synchronously
/// on the reload path so recovery does not wait for inbound traffic.
///
/// The gate is `deny_all` + a grace deadline behind a small mutex touched only
/// on watcher ticks and reloads — never on the handshake hot path, which reads
/// `deny_all` with a single relaxed atomic load.
pub struct FailClosedGate {
    /// Hot-path flag: `true` rejects every client-cert handshake. Read with a
    /// relaxed atomic load in `verify_client_cert`; written only from
    /// [`FailClosedGate::observe`] / [`FailClosedGate::clear`].
    deny_all: AtomicBool,
    /// Grace window: how long the CRL set must remain continuously stale
    /// before the gate engages. Zero engages immediately on the first
    /// observed all-stale tick.
    grace: Duration,
    /// Deadline bookkeeping, guarded because the watcher-tick observation is
    /// off the hot path. `None` means "not currently in a staleness window".
    stale_since: Mutex<Option<Instant>>,
    clock: Arc<dyn GraceClock>,
}

impl fmt::Debug for FailClosedGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FailClosedGate")
            .field("deny_all", &self.deny_all.load(Ordering::Relaxed))
            .field("grace_secs", &self.grace.as_secs())
            .finish_non_exhaustive()
    }
}

impl FailClosedGate {
    /// Build a gate with the given grace window using the real system clock.
    pub fn new(grace: Duration) -> Arc<Self> {
        Self::with_clock(grace, Arc::new(SystemClock))
    }

    /// Build a gate with an injected clock (test seam).
    pub fn with_clock(grace: Duration, clock: Arc<dyn GraceClock>) -> Arc<Self> {
        Arc::new(Self {
            deny_all: AtomicBool::new(false),
            grace,
            stale_since: Mutex::new(None),
            clock,
        })
    }

    /// Hot-path read: is the gate currently rejecting all handshakes?
    pub fn is_engaged(&self) -> bool {
        self.deny_all.load(Ordering::Relaxed)
    }

    /// Observe the latest CRL freshness. Call on every watcher tick and on
    /// every reload — including ticks where the file bytes were unchanged, so
    /// a set that ages into staleness still engages the gate.
    ///
    /// * `all_stale == false` → healthy: clear any staleness window and
    ///   release `deny_all` synchronously (ADR revision 2 — recovery must not
    ///   wait for inbound traffic).
    /// * `all_stale == true` → start (or continue) the grace timer; engage
    ///   `deny_all` only once `grace` has elapsed since the window opened.
    pub fn observe(&self, all_stale: bool) {
        if !all_stale {
            self.clear();
            return;
        }
        let now = self.clock.now();
        let mut stale_since = self.stale_since.lock();
        let opened = *stale_since.get_or_insert(now);
        let elapsed = now.saturating_duration_since(opened);
        if elapsed >= self.grace && !self.deny_all.swap(true, Ordering::Relaxed) {
            drop(stale_since);
            warn!(
                grace_secs = self.grace.as_secs(),
                "CRL fail-closed engaged: all CRLs stale past grace window, \
                 rejecting all client-cert handshakes until a fresh CRL is published"
            );
            rustgate_core::audit::crl_fail_closed_engaged(self.grace.as_secs());
        }
    }

    /// Release the gate and reset the staleness window. Idempotent — only logs
    /// and emits an audit event on an actual engaged→clear transition.
    pub fn clear(&self) {
        let mut stale_since = self.stale_since.lock();
        *stale_since = None;
        if self.deny_all.swap(false, Ordering::Relaxed) {
            drop(stale_since);
            info!("CRL fail-closed cleared: fresh CRL observed, resuming client-cert handshakes");
            rustgate_core::audit::crl_fail_closed_cleared();
        }
    }
}

/// Provides a fresh root certificate store and its generation number.
///
/// The generation is a monotonically increasing counter that changes
/// whenever the set of trusted certificates is modified. The verifier
/// compares it against its cached value to decide whether to rebuild.
pub type RootStoreProvider = Box<dyn Fn() -> (u64, RootCertStore) + Send + Sync>;

/// Provides the current CRL list and its generation number.
///
/// Symmetric to [`RootStoreProvider`]: a monotonically increasing counter that
/// changes whenever the revocation set is reloaded, letting the verifier rebuild
/// when a freshly-published CRL lands — without a `ServerConfig` rebuild or a
/// restart (#1496). Like the root-store provider it is invoked on the rustls
/// handshake thread, so the closure body must stay cheap (an `Arc` clone over a
/// hot-reloadable store, e.g. [`crate::CrlStore::snapshot`]).
pub type CrlProvider =
    Box<dyn Fn() -> (u64, Arc<Vec<CertificateRevocationListDer<'static>>>) + Send + Sync>;

/// Cached inner verifier state.
struct CachedVerifier {
    generation: u64,
    crl_generation: u64,
    verifier: Arc<dyn ClientCertVerifier>,
}

/// A [`ClientCertVerifier`] that dynamically rebuilds when the trust
/// store changes, allowing zero-downtime CA rotation.
///
/// On each `verify_client_cert` call, the verifier checks whether the
/// trust store generation has changed. If so, it rebuilds the inner
/// [`WebPkiClientVerifier`] with the fresh root store **and** refreshes
/// the `root_hint_subjects` list so the TLS `CertificateRequest`
/// advertises every currently-trusted CA. Signature verification
/// methods delegate to the crypto provider and do not depend on the
/// root store.
///
/// # Root hint freshness (F-50)
///
/// `root_hint_subjects` is served from an atomic [`ArcSwap`] of a
/// `&'static [DistinguishedName]` slice that is replaced alongside the
/// inner [`WebPkiClientVerifier`] on generation advance. Each rebuild
/// leaks a small heap buffer (~`sizeof(DN) × N` bytes per rotation) via
/// [`Vec::leak`] so the returned reference has a stable lifetime for
/// the rustls trait contract — rotations are rare and the leak is
/// bounded by rotation rate. Clients whose issuing CA is added after
/// startup will now see it advertised in the handshake immediately.
pub struct DynamicCertVerifier {
    provider: RootStoreProvider,
    crl_provider: CrlProvider,
    /// Opt-in fail-closed staleness gate. When present and engaged, every
    /// `verify_client_cert` call is rejected before the inner verifier runs.
    /// `None` (the default) preserves the original fail-open behavior.
    fail_closed: Option<Arc<FailClosedGate>>,
    cached: Mutex<CachedVerifier>,
    /// Current root-hint subjects. Replaced atomically on every trust
    /// store generation advance so handshakes always see the live
    /// advertised CA list. Backed by a `&'static` slice produced via
    /// `Vec::leak`, so the returned reference from `root_hint_subjects`
    /// can outlive any `&self` borrow (required by the rustls trait
    /// contract). Using a static-lifetime payload avoids the
    /// `arc_swap::Guard` lifetime-escape problem.
    current_subjects: ArcSwap<&'static [DistinguishedName]>,
}

impl DynamicCertVerifier {
    /// Create a new dynamic verifier.
    ///
    /// The `provider` closure is called to obtain a fresh `RootCertStore`
    /// and its generation counter whenever a change is detected. It is
    /// also called once at construction to build the initial verifier.
    ///
    /// `crls` are included in every rebuilt `WebPkiClientVerifier`.
    ///
    /// # Runtime requirement
    ///
    /// This constructor is **synchronous** — no tokio runtime context is
    /// required. It does **not** spawn tasks, perform network I/O, or
    /// touch the filesystem directly: all I/O is the responsibility of
    /// the caller-supplied `provider` closure (which may, for example,
    /// snapshot a `TrustStore` populated earlier from disk).
    ///
    /// The `provider` closure is invoked **once** during construction
    /// to build the initial verifier, and **once per**
    /// [`verify_client_cert`](Self::verify_client_cert) **call** thereafter.
    /// If the closure performs blocking I/O it will block the rustls
    /// handshake worker thread, so the closure body should be fast and
    /// non-blocking — typically a `RwLock::read` over an in-memory store.
    ///
    /// Each generation advance leaks a small `Vec<DistinguishedName>`
    /// via [`Vec::leak`] — see the type-level docs on root-hint freshness.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use rustls::RootCertStore;
    /// use rustgate_tls::DynamicCertVerifier;
    ///
    /// // The provider closure is invoked lock-free on every TLS handshake;
    /// // keep it cheap. A typical implementation snapshots an in-memory
    /// // trust store and returns a (generation, RootCertStore) pair.
    /// let provider = Box::new(|| (0u64, RootCertStore::empty()));
    /// let _verifier = DynamicCertVerifier::new(provider, Vec::new())
    ///     .expect("build verifier");
    /// ```
    pub fn new(
        provider: RootStoreProvider,
        crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<Arc<Self>, Error> {
        // Static CRL set — fixed for this verifier's lifetime. A constant
        // generation means the CRL side never triggers a rebuild, preserving the
        // original behaviour for callers (e.g. federation inbound) that do not
        // hot-reload CRLs.
        let crls = Arc::new(crls);
        let crl_provider: CrlProvider = Box::new(move || (0, Arc::clone(&crls)));
        Self::with_crl_provider(provider, crl_provider)
    }

    /// Like [`new`](Self::new), but the CRL set is pulled from a
    /// generation-counted [`CrlProvider`] (e.g. a hot-reloadable
    /// [`crate::CrlStore`]) instead of being frozen at construction. The live
    /// verifier rebuilds — and so observes a freshly-published CRL at the next
    /// handshake — whenever **either** the root-store generation **or** the CRL
    /// generation advances, with no restart (#1496).
    ///
    /// Both provider closures run on the rustls handshake worker thread and must
    /// be cheap and non-blocking (a `RwLock::read` + `Arc` clone).
    pub fn with_crl_provider(
        provider: RootStoreProvider,
        crl_provider: CrlProvider,
    ) -> Result<Arc<Self>, Error> {
        Self::with_crl_provider_and_gate(provider, crl_provider, None)
    }

    /// Like [`with_crl_provider`](Self::with_crl_provider), but also attaches an
    /// opt-in [`FailClosedGate`]. When `fail_closed` is `Some` and the gate is
    /// engaged, [`verify_client_cert`](Self::verify_client_cert) rejects every
    /// handshake before delegating to the inner verifier. Passing `None`
    /// preserves the original fail-open behavior (#1496, ADR-0025 Piece 2).
    pub fn with_crl_provider_and_gate(
        provider: RootStoreProvider,
        crl_provider: CrlProvider,
        fail_closed: Option<Arc<FailClosedGate>>,
    ) -> Result<Arc<Self>, Error> {
        let (generation, root_store) = provider();
        let (crl_generation, crls) = crl_provider();
        let initial_subjects: &'static [DistinguishedName] = Vec::leak(root_store.subjects());
        let crls_ref: &[CertificateRevocationListDer<'static>] = &crls;
        let verifier = Self::build_verifier(Arc::new(root_store), crls_ref)?;

        Ok(Arc::new(Self {
            provider,
            crl_provider,
            fail_closed,
            cached: Mutex::new(CachedVerifier {
                generation,
                crl_generation,
                verifier,
            }),
            current_subjects: ArcSwap::from_pointee(initial_subjects),
        }))
    }

    /// The attached fail-closed gate, if any. Callers (e.g. the CRL watcher in
    /// `rustgate-server::setup`) drive [`FailClosedGate::observe`] through this
    /// handle on every refresh tick.
    pub fn fail_closed_gate(&self) -> Option<&Arc<FailClosedGate>> {
        self.fail_closed.as_ref()
    }

    /// Build a `WebPkiClientVerifier` from the given root store and CRLs.
    fn build_verifier(
        root_store: Arc<RootCertStore>,
        crls: &[CertificateRevocationListDer<'static>],
    ) -> Result<Arc<dyn ClientCertVerifier>, Error> {
        let mut builder = WebPkiClientVerifier::builder(root_store);
        if !crls.is_empty() {
            builder = builder.with_crls(crls.to_vec());
        }
        builder
            .build()
            .map(|v| v as Arc<dyn ClientCertVerifier>)
            .map_err(|e| Error::General(format!("verifier build error: {e}")))
    }

    /// Get the current inner verifier, rebuilding if the root-store **or** the
    /// CRL generation changed since the last build.
    fn current_verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, Error> {
        let (current_gen, root_store) = (self.provider)();
        let (current_crl_gen, crls) = (self.crl_provider)();

        let mut cached = self.cached.lock();

        if cached.generation == current_gen && cached.crl_generation == current_crl_gen {
            return Ok(Arc::clone(&cached.verifier));
        }

        // Either generation changed — rebuild from the store + CRLs we just
        // fetched. Share the store via `Arc::clone` so we can still read its
        // subjects after handing one reference to `build_verifier`; we leak the
        // fresh subject slice only on a ROOT change (a CRL-only refresh leaves
        // the advertised CA list identical, so re-leaking it would waste heap).
        let root_changed = cached.generation != current_gen;
        debug!(
            old_generation = cached.generation,
            new_generation = current_gen,
            old_crl_generation = cached.crl_generation,
            new_crl_generation = current_crl_gen,
            "trust store or CRL changed, rebuilding client cert verifier"
        );
        let root_store = Arc::new(root_store);
        let crls_ref: &[CertificateRevocationListDer<'static>] = &crls;

        match Self::build_verifier(Arc::clone(&root_store), crls_ref) {
            Ok(verifier) => {
                cached.generation = current_gen;
                cached.crl_generation = current_crl_gen;
                cached.verifier = Arc::clone(&verifier);
                if root_changed {
                    // Swap in the fresh subject slice only after the rebuild
                    // succeeds — on error we keep the old hints aligned with the
                    // still-active cached verifier so handshakes don't advertise
                    // CAs we can't validate.
                    let fresh_subjects: &'static [DistinguishedName] =
                        Vec::leak(root_store.subjects());
                    self.current_subjects.store(Arc::new(fresh_subjects));
                }
                Ok(verifier)
            }
            Err(e) => {
                rustgate_core::audit::verifier_rebuild_failed(&e.to_string());
                warn!(
                    error = %e,
                    "failed to rebuild verifier after trust store or CRL change, using cached"
                );
                Ok(Arc::clone(&cached.verifier))
            }
        }
    }
}

impl fmt::Debug for DynamicCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (generation, crl_generation) = {
            let cached = self.cached.lock();
            (cached.generation, cached.crl_generation)
        };
        let (_, crls) = (self.crl_provider)();
        f.debug_struct("DynamicCertVerifier")
            .field("generation", &generation)
            .field("crl_generation", &crl_generation)
            .field("crls", &crls.len())
            .finish()
    }
}

impl ClientCertVerifier for DynamicCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Double-deref: the Guard derefs to `Arc<&'static [DN]>`, which
        // derefs to `&'static [DN]`. The static lifetime trivially
        // outlives any `&self` borrow, satisfying the rustls trait
        // contract without leaking the Arc.
        **self.current_subjects.load()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        // Fail-closed staleness gate (opt-in). Consulted BEFORE building or
        // delegating to the inner verifier so a "good" OCSP verdict from an
        // outer wrapper (which delegates to this method first) cannot override
        // it. A single relaxed atomic load on the hot path.
        if let Some(gate) = &self.fail_closed
            && gate.is_engaged()
        {
            return Err(Error::General(
                "client cert rejected: CRL stale, fail-closed engaged".to_string(),
            ));
        }
        let verifier = self.current_verifier()?;
        verifier.verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| Error::General("no crypto provider installed".to_string()))?;
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| Error::General("no crypto provider installed".to_string()))?;
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    fn test_root_store() -> RootCertStore {
        let ca = rustgate_test_utils::certs::TestCa::new("Dynamic Test CA");
        let mut store = RootCertStore::empty();
        let certs: Vec<CertificateDer<'static>> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(ca.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        for cert in certs {
            store.add(cert).unwrap();
        }
        store
    }

    #[test]
    fn new_builds_initial_verifier() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(Box::new(move || (0, store.clone())), Vec::new())
            .expect("build verifier");
        assert!(!verifier.root_hint_subjects().is_empty());
    }

    #[test]
    fn generation_change_triggers_rebuild() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let generation = Arc::new(AtomicU64::new(0));
        let store = test_root_store();

        let gen_clone = Arc::clone(&generation);
        let verifier = DynamicCertVerifier::new(
            Box::new(move || (gen_clone.load(Ordering::Acquire), store.clone())),
            Vec::new(),
        )
        .expect("build verifier");

        // First call — should use cached
        let v1 = verifier.current_verifier().unwrap();

        // Same generation — still cached
        let v2 = verifier.current_verifier().unwrap();
        assert!(Arc::ptr_eq(&v1, &v2));

        // Bump generation — should rebuild
        generation.store(1, Ordering::Release);
        let v3 = verifier.current_verifier().unwrap();
        assert!(!Arc::ptr_eq(&v1, &v3));
    }

    #[test]
    fn root_hint_subjects_refreshes_after_ca_rotation() {
        // F-50 regression: before the fix, `root_hint_subjects` returned
        // a static slice snapshotted at construction — adding a new CA
        // at runtime left the TLS `CertificateRequest` advertising the
        // stale list. After the fix, each generation advance atomically
        // swaps in the fresh subject set.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca1 = rustgate_test_utils::certs::TestCa::new("Dynamic Test CA One");
        let ca2 = rustgate_test_utils::certs::TestCa::new("Dynamic Test CA Two");

        let mut store1 = RootCertStore::empty();
        for cert in rustls_pki_types::pem::PemObject::pem_slice_iter(ca1.cert_pem.as_bytes())
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .unwrap()
        {
            store1.add(cert).unwrap();
        }

        let mut store2 = store1.clone();
        for cert in rustls_pki_types::pem::PemObject::pem_slice_iter(ca2.cert_pem.as_bytes())
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .unwrap()
        {
            store2.add(cert).unwrap();
        }

        let generation = Arc::new(AtomicU64::new(0));
        let gen_clone = Arc::clone(&generation);
        let s1 = store1.clone();
        let s2 = store2.clone();
        let verifier = DynamicCertVerifier::new(
            Box::new(move || {
                let g = gen_clone.load(Ordering::Acquire);
                let store = if g == 0 { s1.clone() } else { s2.clone() };
                (g, store)
            }),
            Vec::new(),
        )
        .expect("build verifier");

        let subjects_before = verifier.root_hint_subjects().len();
        assert_eq!(subjects_before, 1, "initial hints must advertise one CA");

        // Advance generation AND trigger a verifier refresh — the latter
        // is how `current_verifier` observes the change in production.
        generation.store(1, Ordering::Release);
        let _ = verifier.current_verifier().unwrap();

        let subjects_after = verifier.root_hint_subjects().len();
        assert_eq!(
            subjects_after, 2,
            "after CA rotation the hint list must include the new CA"
        );
    }

    #[test]
    fn root_hint_subjects_keeps_old_list_on_rebuild_error() {
        // When a rebuild fails, the cached verifier stays in place; the
        // hint list must also stay in lockstep so we never advertise CAs
        // whose keys we cannot actually verify against.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca = rustgate_test_utils::certs::TestCa::new("Dynamic Test CA");
        let mut good = RootCertStore::empty();
        for cert in rustls_pki_types::pem::PemObject::pem_slice_iter(ca.cert_pem.as_bytes())
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .unwrap()
        {
            good.add(cert).unwrap();
        }

        let generation = Arc::new(AtomicU64::new(0));
        let gen_clone = Arc::clone(&generation);
        let good_clone = good.clone();
        let verifier = DynamicCertVerifier::new(
            Box::new(move || {
                let g = gen_clone.load(Ordering::Acquire);
                // Generation 1 returns an empty store which fails to
                // build a WebPkiClientVerifier (needs at least one root).
                let store = if g == 0 {
                    good_clone.clone()
                } else {
                    RootCertStore::empty()
                };
                (g, store)
            }),
            Vec::new(),
        )
        .expect("build verifier");

        let before = verifier.root_hint_subjects().len();
        assert_eq!(before, 1);

        generation.store(1, Ordering::Release);
        // Force a rebuild attempt (it fails internally but returns the cached verifier).
        let _ = verifier.current_verifier().unwrap();

        let after = verifier.root_hint_subjects().len();
        assert_eq!(
            after, 1,
            "rebuild failure must keep hints aligned with the live cached verifier"
        );
    }

    #[test]
    fn debug_format() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(Box::new(move || (42, store.clone())), Vec::new())
            .expect("build verifier");
        let debug = format!("{verifier:?}");
        assert!(debug.contains("DynamicCertVerifier"));
        assert!(debug.contains("42"));
    }

    #[test]
    fn supported_verify_schemes_not_empty() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(Box::new(move || (0, store.clone())), Vec::new())
            .expect("build verifier");
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    #[test]
    fn survives_panic_in_lock_scope() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(Box::new(move || (0, store.clone())), Vec::new())
            .expect("build verifier");

        // Simulate a panic while holding the verifier lock.
        let v = Arc::clone(&verifier);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = v.cached.lock();
            panic!("simulated panic while holding verifier lock");
        }));
        assert!(result.is_err());

        // With parking_lot::Mutex, the lock is not poisoned — subsequent
        // calls succeed rather than permanently failing all TLS handshakes.
        let inner = verifier
            .current_verifier()
            .expect("verifier must not be poisoned");
        assert!(!inner.root_hint_subjects().is_empty());
    }

    #[test]
    fn root_store_provider_and_verifier_are_send_sync() {
        // Structural bounds check: `DynamicCertVerifier` is stored inside
        // `Arc<dyn ClientCertVerifier>` in every TLS listener across the
        // workspace, which demands `Send + Sync`. The `RootStoreProvider`
        // type alias embeds `Box<dyn Fn(...) + Send + Sync>` so that a
        // closure capturing an `Arc<RwLock<TrustStore>>` remains sharable
        // across the handshake worker pool. A regression that dropped
        // either bound would only manifest at a transitive call site in
        // `rustgate-server::setup`; pin it here so the compile failure
        // surfaces in the module that owns the types.
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<DynamicCertVerifier>();
        assert_send_sync::<RootStoreProvider>();
    }

    #[test]
    fn debug_format_reports_crl_count_not_crl_contents() {
        // The Debug impl intentionally projects `self.crls.len()` into a
        // `crls` field rather than formatting the CRL DER bytes (which
        // would spam logs with hex-DER blobs and potentially leak
        // operational signal about the revocation-list shape to anyone
        // with log access). Pin both the numeric count AND the absence
        // of the underlying `CertificateRevocationListDer` type name in
        // the rendered output.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(Box::new(move || (7, store.clone())), Vec::new())
            .expect("build verifier");
        let dbg = format!("{verifier:?}");
        assert!(dbg.contains("DynamicCertVerifier"));
        assert!(
            dbg.contains("generation: 7"),
            "generation must be visible, got: {dbg}"
        );
        assert!(
            dbg.contains("crls: 0"),
            "crl count must be visible as len (0 here), got: {dbg}"
        );
        assert!(
            !dbg.contains("CertificateRevocationListDer"),
            "CRL DER type must not leak into Debug output"
        );
        assert!(
            !dbg.contains("provider"),
            "the RootStoreProvider closure must not leak into Debug output: {dbg}"
        );
    }

    #[test]
    fn debug_reflects_current_generation_after_rebuild() {
        // The Debug impl reads `cached.generation` under the parking_lot
        // lock — after a rebuild advances the counter, Debug must
        // surface the new value so `tracing::debug!(?verifier, …)` on
        // the post-rotation path carries the advertised generation,
        // not the construction-time snapshot.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let generation = Arc::new(AtomicU64::new(0));
        let gen_clone = Arc::clone(&generation);
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(
            Box::new(move || (gen_clone.load(Ordering::Acquire), store.clone())),
            Vec::new(),
        )
        .expect("build verifier");

        assert!(format!("{verifier:?}").contains("generation: 0"));

        generation.store(99, Ordering::Release);
        let _ = verifier.current_verifier().expect("rebuild");

        let dbg = format!("{verifier:?}");
        assert!(
            dbg.contains("generation: 99"),
            "Debug must reflect post-rebuild generation, got: {dbg}"
        );
    }

    #[test]
    fn same_generation_does_not_rebuild_verifier() {
        // The cached verifier identity is preserved across repeated
        // current_verifier() calls when the provider reports the same
        // generation — pin via Arc::ptr_eq on five consecutive calls so
        // a regression that accidentally rebuilt on every call (losing
        // the `cached.generation == current_gen` fast path) would cost
        // a fresh WebPkiClientVerifier allocation per handshake and
        // re-leak subject hints, fails here.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(Box::new(move || (42, store.clone())), Vec::new())
            .expect("build verifier");

        let v0 = verifier.current_verifier().expect("v0");
        for _ in 0..5 {
            let v = verifier.current_verifier().expect("current");
            assert!(
                Arc::ptr_eq(&v0, &v),
                "same-generation calls must return the cached Arc"
            );
        }
    }

    #[test]
    fn generation_decrease_triggers_rebuild_not_just_increase() {
        // The cache check is `cached.generation == current_gen` — any
        // inequality rebuilds, including a *decrease*. Pin this so a
        // refactor to `current_gen > cached.generation` (which would
        // seem like a "monotonic counter" optimization) fails here: in
        // production a rotation rollback is rare but not unreachable,
        // and the verifier MUST reflect whatever the trust-store source
        // reports, not its idea of linear time.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let generation = Arc::new(AtomicU64::new(5));
        let gen_clone = Arc::clone(&generation);
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(
            Box::new(move || (gen_clone.load(Ordering::Acquire), store.clone())),
            Vec::new(),
        )
        .expect("build verifier");

        let v_at_5 = verifier.current_verifier().expect("gen=5");

        // Decrease generation.
        generation.store(2, Ordering::Release);
        let v_at_2 = verifier.current_verifier().expect("gen=2");

        assert!(
            !Arc::ptr_eq(&v_at_5, &v_at_2),
            "generation decrease (5→2) must rebuild, not be silently ignored"
        );
    }

    #[test]
    fn provider_is_called_once_per_current_verifier_invocation() {
        // Observability invariant: every call to `current_verifier`
        // must ask the provider for the current state exactly once.
        // If a future refactor cached the provider output itself (e.g.
        // under a time-based TTL) the verifier would stop reacting to
        // out-of-band trust-store updates between TTL ticks — pin the
        // current contract by counting provider invocations across
        // three reads with a static generation.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let call_count = Arc::new(AtomicU64::new(0));
        let call_count_cb = Arc::clone(&call_count);
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(
            Box::new(move || {
                let _ = call_count_cb.fetch_add(1, Ordering::Relaxed);
                (0, store.clone())
            }),
            Vec::new(),
        )
        .expect("build verifier");

        // One call during construction.
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        // Three more calls should increment the counter by three.
        let _ = verifier.current_verifier().expect("v1");
        let _ = verifier.current_verifier().expect("v2");
        let _ = verifier.current_verifier().expect("v3");
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            4,
            "each current_verifier call must consult the provider exactly once"
        );
    }

    #[test]
    fn initial_hint_subject_count_matches_root_store_cert_count() {
        // Pin that the DN-list leaked by `Vec::leak(root_store.subjects())`
        // has the same cardinality as the number of certs installed
        // during construction — a regression that dropped duplicates or
        // silently truncated would change what the handshake
        // CertificateRequest advertises and surface as "mystery client
        // cert rejections" rather than a loud failure.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca1 = rustgate_test_utils::certs::TestCa::new("DT CA One");
        let ca2 = rustgate_test_utils::certs::TestCa::new("DT CA Two");
        let ca3 = rustgate_test_utils::certs::TestCa::new("DT CA Three");

        let mut store = RootCertStore::empty();
        for ca in [&ca1, &ca2, &ca3] {
            for cert in rustls_pki_types::pem::PemObject::pem_slice_iter(ca.cert_pem.as_bytes())
                .collect::<Result<Vec<CertificateDer<'static>>, _>>()
                .expect("parse cert")
            {
                store.add(cert).expect("add cert");
            }
        }
        assert_eq!(store.len(), 3, "sanity: three CAs installed");

        let verifier = DynamicCertVerifier::new(Box::new(move || (0, store.clone())), Vec::new())
            .expect("build verifier");
        assert_eq!(
            verifier.root_hint_subjects().len(),
            3,
            "hint list must include one DN per installed CA"
        );
    }

    #[test]
    fn new_with_non_empty_crls_constructs_successfully() {
        // The `if !crls.is_empty() { builder.with_crls(...) }` branch in
        // build_verifier is otherwise unexercised by the existing suite;
        // pin it by constructing a verifier with a real CRL and
        // asserting both construction success AND that a subsequent
        // rebuild-through-generation-change preserves the CRL list
        // (`self.crls.to_vec()` is passed through `build_verifier`
        // every rebuild, so a regression that dropped it on the second
        // path would silently disable revocation checking after the
        // first CA rotation).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca = rustgate_test_utils::certs::TestCa::new("CRL Test CA");
        let mut store = RootCertStore::empty();
        for cert in rustls_pki_types::pem::PemObject::pem_slice_iter(ca.cert_pem.as_bytes())
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .expect("parse")
        {
            store.add(cert).expect("add");
        }

        // Issue a real CRL revoking no serials (empty list is a legal
        // published CRL — "I am current and nothing is revoked") so
        // webpki's parser accepts it. `generate_crl` returns PEM which
        // we decode into DER for the rustls verifier API.
        let crl_pem = ca.generate_crl(&[]);
        let crl_ders: Vec<CertificateRevocationListDer<'static>> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(crl_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("decode CRL PEM");
        assert_eq!(crl_ders.len(), 1, "one CRL expected");
        let crls = crl_ders;

        let generation = Arc::new(AtomicU64::new(0));
        let gen_clone = Arc::clone(&generation);
        let store_c = store.clone();
        let verifier = DynamicCertVerifier::new(
            Box::new(move || (gen_clone.load(Ordering::Acquire), store_c.clone())),
            crls,
        )
        .expect("build verifier with non-empty CRL");

        // Debug reports the CRL count (1) — pins the full Vec survived construction.
        assert!(
            format!("{verifier:?}").contains("crls: 1"),
            "constructor must retain the CRL vector"
        );

        // Trigger rebuild; the CRL list is cloned and re-applied on
        // every rebuild. Absence of panic/error here is the pin.
        generation.store(1, Ordering::Release);
        let _ = verifier.current_verifier().expect("rebuild preserves CRLs");

        // CRL count must survive the rebuild.
        assert!(
            format!("{verifier:?}").contains("crls: 1"),
            "rebuild must not drop the CRL vector"
        );
    }

    #[test]
    fn root_hint_subjects_does_not_acquire_cached_mutex() {
        // `root_hint_subjects` is on the TLS handshake hot path and is
        // called every time the server assembles a `CertificateRequest`.
        // The `ArcSwap` backing it exists specifically so reads do not
        // block on the rebuild mutex — pin this by holding the mutex
        // in the current thread and concurrently calling
        // `root_hint_subjects` in a second thread within a bounded
        // timeout. A regression that added a `self.cached.lock()` call
        // to the hint accessor would cause the spawned thread to
        // deadlock past the timeout and the test would fail.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(Box::new(move || (0, store.clone())), Vec::new())
            .expect("build verifier");

        let v_for_thread = Arc::clone(&verifier);
        let _guard = verifier.cached.lock();

        let (tx, rx) = std::sync::mpsc::channel();
        let _thread = std::thread::spawn(move || {
            let count = v_for_thread.root_hint_subjects().len();
            let _ = tx.send(count);
        });

        let count = rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("root_hint_subjects must not block on cached mutex");
        assert!(
            count > 0,
            "non-empty hint list expected from lock-free read"
        );
        drop(_guard);
    }

    #[test]
    fn verifier_usable_as_dyn_client_cert_verifier_via_arc() {
        // rustls consumes the verifier as `Arc<dyn ClientCertVerifier>`.
        // Pin that `Arc<DynamicCertVerifier>` up-casts to that trait
        // object cleanly (both the unsize coercion and the
        // `Send + Sync` auto-traits on the `dyn` projection). A future
        // refactor that narrowed any of the inner fields to a
        // non-Send/Sync type would fail here rather than at the call
        // site in `rustgate-server::setup`.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(Box::new(move || (0, store.clone())), Vec::new())
            .expect("build verifier");

        let as_trait: Arc<dyn ClientCertVerifier> = verifier;
        assert!(!as_trait.root_hint_subjects().is_empty());
        assert!(!as_trait.supported_verify_schemes().is_empty());
    }

    // ---- Fail-closed staleness gate (ADR-0025 Piece 2, M-10) ----

    use std::sync::Mutex as StdMutex;

    /// Controllable clock for deterministic grace-window tests.
    struct FakeClock {
        now: StdMutex<Instant>,
    }

    impl FakeClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                now: StdMutex::new(Instant::now()),
            })
        }

        fn advance(&self, by: Duration) {
            let mut g = self.now.lock().unwrap();
            *g += by;
        }
    }

    impl GraceClock for FakeClock {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
    }

    /// Build a dynamic verifier whose inner `WebPkiClientVerifier` is valid,
    /// wired to a fail-closed gate, so we can prove the gate short-circuits
    /// `verify_client_cert` before the inner verifier ever runs.
    fn verifier_with_gate(gate: Arc<FailClosedGate>) -> Arc<DynamicCertVerifier> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = test_root_store();
        DynamicCertVerifier::with_crl_provider_and_gate(
            Box::new(move || (0, store.clone())),
            {
                let empty: Arc<Vec<CertificateRevocationListDer<'static>>> = Arc::new(Vec::new());
                Box::new(move || (0, Arc::clone(&empty)))
            },
            Some(gate),
        )
        .expect("build verifier with gate")
    }

    #[test]
    fn gate_engaged_rejects_before_delegating_to_inner() {
        let clock = FakeClock::new();
        let gate = FailClosedGate::with_clock(Duration::from_secs(0), clock);
        let verifier = verifier_with_gate(Arc::clone(&gate));

        // Engage the gate via an all-stale observation (grace 0 => immediate).
        gate.observe(true);
        assert!(gate.is_engaged());

        // A bogus end-entity would be rejected by the inner verifier anyway,
        // but the gate must short-circuit with its OWN error string, proving
        // the inner verifier was never consulted.
        let bogus = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
        let err = verifier
            .verify_client_cert(&bogus, &[], UnixTime::now())
            .expect_err("engaged gate must reject");
        match err {
            Error::General(msg) => assert!(
                msg.contains("fail-closed engaged"),
                "expected fail-closed error, got: {msg}"
            ),
            other => panic!("expected General fail-closed error, got: {other:?}"),
        }
    }

    #[test]
    fn grace_zero_engages_immediately_on_all_stale() {
        let clock = FakeClock::new();
        let gate = FailClosedGate::with_clock(Duration::from_secs(0), Arc::clone(&clock) as _);
        assert!(!gate.is_engaged());
        gate.observe(true);
        assert!(gate.is_engaged(), "grace 0 must engage on first all-stale");
    }

    #[test]
    fn grace_window_defers_engagement_until_deadline() {
        let clock = FakeClock::new();
        let gate = FailClosedGate::with_clock(Duration::from_secs(30), Arc::clone(&clock) as _);

        // Window opens but grace not yet elapsed.
        gate.observe(true);
        assert!(!gate.is_engaged(), "must not engage before grace elapses");

        // Still short of the deadline.
        clock.advance(Duration::from_secs(29));
        gate.observe(true);
        assert!(!gate.is_engaged(), "still within grace window");

        // Cross the deadline.
        clock.advance(Duration::from_secs(2));
        gate.observe(true);
        assert!(gate.is_engaged(), "must engage once grace elapses");
    }

    #[test]
    fn fresh_generation_clears_gate_synchronously() {
        let clock = FakeClock::new();
        let gate = FailClosedGate::with_clock(Duration::from_secs(0), Arc::clone(&clock) as _);

        gate.observe(true);
        assert!(gate.is_engaged());

        // A healthy (not all-stale) observation must clear the gate right away,
        // without any handshake — recovery does not wait for inbound traffic.
        gate.observe(false);
        assert!(
            !gate.is_engaged(),
            "fresh CRL must clear the gate synchronously"
        );
    }

    #[test]
    fn stale_window_resets_after_recovery() {
        let clock = FakeClock::new();
        let gate = FailClosedGate::with_clock(Duration::from_secs(30), Arc::clone(&clock) as _);

        // Open a window, then recover before the deadline — the window resets.
        gate.observe(true);
        clock.advance(Duration::from_secs(20));
        gate.observe(false);
        assert!(!gate.is_engaged());

        // A new stale window must count from zero again, not from the old open.
        gate.observe(true);
        clock.advance(Duration::from_secs(20));
        gate.observe(true);
        assert!(
            !gate.is_engaged(),
            "recovery must reset the staleness clock, not accumulate"
        );
        clock.advance(Duration::from_secs(11));
        gate.observe(true);
        assert!(gate.is_engaged());
    }

    #[test]
    fn healthy_observation_never_engages_gate() {
        // ADR revision 3 posture: a healthy (`all_stale == false`) observation
        // — e.g. an empty-but-fresh CRL with a future nextUpdate and zero
        // revoked serials — must never engage the gate, even with grace 0.
        let clock = FakeClock::new();
        let gate = FailClosedGate::with_clock(Duration::from_secs(0), clock);
        for _ in 0..5 {
            gate.observe(false);
            assert!(!gate.is_engaged(), "healthy CRL must not engage the gate");
        }
    }

    #[test]
    fn no_gate_stays_fail_open() {
        // Without a gate the verifier preserves the original behavior: a valid
        // inner verifier is always consulted; there is no deny-all path.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = test_root_store();
        let verifier = DynamicCertVerifier::new(Box::new(move || (0, store.clone())), Vec::new())
            .expect("build verifier");
        assert!(verifier.fail_closed_gate().is_none());
    }

    #[test]
    fn gate_debug_redacts_via_non_exhaustive() {
        let gate = FailClosedGate::new(Duration::from_secs(5));
        let dbg = format!("{gate:?}");
        assert!(dbg.contains("FailClosedGate"));
        assert!(dbg.contains("grace_secs"));
    }
}
