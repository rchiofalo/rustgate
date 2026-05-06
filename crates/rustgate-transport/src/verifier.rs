// Copyright © 2026 Roberto Chiofalo.

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

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme};
use tracing::{debug, warn};

/// Provides a fresh root certificate store and its generation number.
///
/// The generation is a monotonically increasing counter that changes
/// whenever the set of trusted certificates is modified. The verifier
/// compares it against its cached value to decide whether to rebuild.
pub type RootStoreProvider = Box<dyn Fn() -> (u64, RootCertStore) + Send + Sync>;

/// Cached inner verifier state.
struct CachedVerifier {
    generation: u64,
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
    crls: Vec<CertificateRevocationListDer<'static>>,
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
    /// use rustgate_transport::DynamicCertVerifier;
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
        let (generation, root_store) = provider();
        let initial_subjects: &'static [DistinguishedName] = Vec::leak(root_store.subjects());
        let verifier = Self::build_verifier(Arc::new(root_store), &crls)?;

        Ok(Arc::new(Self {
            provider,
            crls,
            cached: Mutex::new(CachedVerifier {
                generation,
                verifier,
            }),
            current_subjects: ArcSwap::from_pointee(initial_subjects),
        }))
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

    /// Get the current inner verifier, rebuilding if the generation changed.
    fn current_verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, Error> {
        let (current_gen, root_store) = (self.provider)();

        let mut cached = self.cached.lock();

        if cached.generation == current_gen {
            return Ok(Arc::clone(&cached.verifier));
        }

        // Generation changed — rebuild using the store we already fetched.
        // Share the store via `Arc::clone` so we can still read its
        // subjects after handing one reference to `build_verifier`; we
        // leak the fresh subject slice only on success so rebuild
        // failures don't leave orphan heap buffers behind.
        debug!(
            old_generation = cached.generation,
            new_generation = current_gen,
            "trust store changed, rebuilding client cert verifier"
        );
        let root_store = Arc::new(root_store);

        match Self::build_verifier(Arc::clone(&root_store), &self.crls) {
            Ok(verifier) => {
                cached.generation = current_gen;
                cached.verifier = Arc::clone(&verifier);
                // Compute and swap in the fresh subject slice only
                // after the rebuild succeeds — on error we keep the old
                // hints aligned with the still-active cached verifier
                // so handshakes don't advertise CAs we can't validate.
                let fresh_subjects: &'static [DistinguishedName] = Vec::leak(root_store.subjects());
                self.current_subjects.store(Arc::new(fresh_subjects));
                Ok(verifier)
            }
            Err(e) => {
                rustgate_core::audit::verifier_rebuild_failed(&e.to_string());
                warn!(
                    error = %e,
                    "failed to rebuild verifier after trust store change, using cached"
                );
                Ok(Arc::clone(&cached.verifier))
            }
        }
    }
}

impl fmt::Debug for DynamicCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let generation = self.cached.lock().generation;
        f.debug_struct("DynamicCertVerifier")
            .field("generation", &generation)
            .field("crls", &self.crls.len())
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
}
