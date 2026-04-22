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
}
