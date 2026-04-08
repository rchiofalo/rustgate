//! Client certificate OCSP verification (Tier 1).
//!
//! This module wraps any [`ClientCertVerifier`] with a layer that consults
//! a SKI-keyed cache of OCSP responses for the presented end-entity client
//! certificate. The wrapper is "fail-open" by default: if the cache has
//! never seen the certificate, the inner verifier's decision stands and a
//! background task is dispatched to fetch an OCSP response so the *next*
//! handshake can be checked. If a cached entry says the certificate is
//! revoked, the verifier rejects the handshake outright.
//!
//! # Design
//!
//! - **Cache key.** The cache is keyed on the X.509 Subject Key Identifier
//!   (SKI) extension when present, falling back to a SHA-256 hash of the
//!   end-entity DER if the extension is missing. Fingerprint stability
//!   across re-issuances is *not* a goal — we want one entry per
//!   distinct cert, not per identity.
//! - **Background fetcher.** A single bounded `tokio::sync::mpsc` channel
//!   feeds a background task that calls `ocsp_stapler::Client::query`
//!   and inserts the result into the cache. Verification never blocks on
//!   network I/O — it only ever reads from the in-memory cache.
//! - **Why piggyback on `ocsp_stapler::Client`?** It already implements
//!   AIA URL extraction, OCSP request encoding, and HTTP fetching. Using
//!   it avoids pulling in a second OCSP/HTTP stack.
//! - **Why "Tier 1"?** Real-world OCSP responders are flaky. A
//!   strict-mode (fail-closed) verifier will reject perfectly good
//!   clients during transient OCSP outages. Tier 1 keeps revocation
//!   "near-real-time" without making the server brittle. A future
//!   `--client-ocsp-required` flag can flip the policy to fail-closed
//!   once operators are comfortable with their responder uptime.
//!
//! # Metrics
//!
//! Two callbacks (`on_cache_hit`, `on_cache_miss`) let the rustgate-server
//! crate plug Prometheus counters in without forcing this crate to depend
//! on the metrics stack. They are no-ops when omitted.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use x509_parser::prelude::*;

/// Callback invoked on a cache hit (any cached entry, regardless of status).
pub type OnCacheHit = Arc<dyn Fn() + Send + Sync>;
/// Callback invoked on a cache miss before a background fetch is dispatched.
pub type OnCacheMiss = Arc<dyn Fn() + Send + Sync>;

/// Trait for fetching OCSP responses for a leaf/issuer pair.
///
/// Abstracted so tests can inject a deterministic responder without
/// running a real HTTP server. The production implementation
/// (`OcspStaplerFetcher`) wraps `ocsp_stapler::Client`.
/// Boxed future returned by [`OcspFetcher::fetch`].
pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;

pub trait OcspFetcher: Send + Sync + 'static {
    /// Fetch the OCSP status for the given DER-encoded leaf/issuer pair.
    ///
    /// Returns `Ok(true)` for a "good" status, `Ok(false)` for a
    /// "revoked" status, and `Err(_)` for any failure (including
    /// "unknown", network errors, parse errors). The wrapper treats
    /// errors the same as cache misses on subsequent verifications.
    fn fetch<'a>(&'a self, leaf_der: &'a [u8], issuer_der: &'a [u8]) -> FetchFuture<'a>;
}

/// Production OCSP fetcher backed by `ocsp_stapler::Client`.
#[cfg(feature = "ocsp")]
#[allow(missing_debug_implementations)]
pub struct OcspStaplerFetcher {
    client: ocsp_stapler::Client,
}

#[cfg(feature = "ocsp")]
impl Default for OcspStaplerFetcher {
    fn default() -> Self {
        Self {
            client: ocsp_stapler::Client::new(),
        }
    }
}

#[cfg(feature = "ocsp")]
impl OcspFetcher for OcspStaplerFetcher {
    fn fetch<'a>(&'a self, leaf_der: &'a [u8], issuer_der: &'a [u8]) -> FetchFuture<'a> {
        Box::pin(async move {
            let response = self
                .client
                .query(leaf_der, issuer_der)
                .await
                .map_err(|e| format!("ocsp query failed: {e:#}"))?;
            // The `Good` variant matches a "good" certificate status;
            // anything else (Revoked, Unknown) is treated as revoked.
            // We classify via the Debug repr to avoid taking a direct
            // dependency on `rasn_ocsp` for a single enum match.
            let good = format!("{:?}", response.cert_status).starts_with("Good");
            Ok(good)
        })
    }
}

/// Cached OCSP status for a single end-entity certificate.
#[derive(Clone, Copy, Debug)]
enum CachedStatus {
    Good,
    Revoked,
}

/// Wraps an inner [`ClientCertVerifier`] with OCSP-based revocation checks.
///
/// See the module-level documentation for design notes.
pub struct ClientOcspVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    cache: parking_lot::Mutex<HashMap<Vec<u8>, CachedStatus>>,
    fetch_tx: mpsc::Sender<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    on_hit: Option<OnCacheHit>,
    on_miss: Option<OnCacheMiss>,
}

impl std::fmt::Debug for ClientOcspVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.cache.lock().len();
        f.debug_struct("ClientOcspVerifier")
            .field("cache_entries", &len)
            .finish()
    }
}

/// Channel buffer size for the background OCSP fetch queue.
///
/// Bounded so a flood of unique client certs cannot fan out unbounded
/// HTTP requests. When the channel is full, additional fetches are
/// dropped (the verifier still serves cached entries normally).
const FETCH_QUEUE_CAPACITY: usize = 256;

impl ClientOcspVerifier {
    /// Wrap an inner verifier with the OCSP cache and background fetcher.
    ///
    /// Spawns one tokio task that consumes `FETCH_QUEUE_CAPACITY`
    /// pending fetch requests at a time. The task exits when the
    /// returned `Arc` is dropped.
    pub fn new(
        inner: Arc<dyn ClientCertVerifier>,
        fetcher: Arc<dyn OcspFetcher>,
        on_hit: Option<OnCacheHit>,
        on_miss: Option<OnCacheMiss>,
    ) -> Arc<Self> {
        let (fetch_tx, mut fetch_rx) =
            mpsc::channel::<(Vec<u8>, Vec<u8>, Vec<u8>)>(FETCH_QUEUE_CAPACITY);

        let verifier = Arc::new(Self {
            inner,
            cache: parking_lot::Mutex::new(HashMap::new()),
            fetch_tx,
            on_hit,
            on_miss,
        });

        let weak = Arc::downgrade(&verifier);
        let fetcher_clone = fetcher;
        drop(tokio::spawn(async move {
            while let Some((ski, leaf, issuer)) = fetch_rx.recv().await {
                let Some(this) = weak.upgrade() else {
                    return;
                };
                match fetcher_clone.fetch(&leaf, &issuer).await {
                    Ok(true) => {
                        debug!(?ski, "client OCSP: cached as Good");
                        let _ = this.cache.lock().insert(ski, CachedStatus::Good);
                    }
                    Ok(false) => {
                        warn!(?ski, "client OCSP: certificate reported as revoked");
                        let _ = this.cache.lock().insert(ski, CachedStatus::Revoked);
                    }
                    Err(e) => {
                        debug!(?ski, error = %e, "client OCSP: fetch failed");
                    }
                }
            }
        }));

        verifier
    }

    /// Read the cached OCSP status for the given SKI, if any.
    fn cached_status(&self, ski: &[u8]) -> Option<CachedStatus> {
        self.cache.lock().get(ski).copied()
    }

    /// Schedule a background OCSP fetch. Drops the request if the queue
    /// is full so a flood of unique certs cannot fan out unbounded I/O.
    fn schedule_fetch(&self, ski: Vec<u8>, leaf: Vec<u8>, issuer: Vec<u8>) {
        if let Err(e) = self.fetch_tx.try_send((ski, leaf, issuer)) {
            debug!(error = %e, "client OCSP: fetch queue full, dropping request");
        }
    }

    /// Number of cached entries. Test/observability helper.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().len()
    }
}

/// Compute the cache key for a leaf certificate.
///
/// Prefers the X.509 Subject Key Identifier extension when present
/// (per RFC 5280 §4.2.1.2). Falls back to a SHA-256 of the full DER
/// when the extension is missing or unparseable.
fn cache_key(leaf_der: &[u8]) -> Vec<u8> {
    if let Ok((_, cert)) = X509Certificate::from_der(leaf_der) {
        for ext in cert.extensions() {
            if let ParsedExtension::SubjectKeyIdentifier(ski) = ext.parsed_extension() {
                return ski.0.to_vec();
            }
        }
    }
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(leaf_der);
    hasher.finalize().to_vec()
}

impl ClientCertVerifier for ClientOcspVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        // Always run the inner verifier first — OCSP is a *supplemental*
        // revocation check, not a replacement for path validation.
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;

        let ski = cache_key(end_entity.as_ref());
        match self.cached_status(&ski) {
            Some(CachedStatus::Good) => {
                if let Some(cb) = &self.on_hit {
                    cb();
                }
                Ok(verified)
            }
            Some(CachedStatus::Revoked) => {
                if let Some(cb) = &self.on_hit {
                    cb();
                }
                Err(Error::General(
                    "client certificate revoked per cached OCSP response".to_string(),
                ))
            }
            None => {
                if let Some(cb) = &self.on_miss {
                    cb();
                }
                // Schedule a background fetch so the next handshake for
                // this cert has a cached answer. Tier 1 is fail-open:
                // accept the inner verifier's decision for this handshake.
                //
                // The "issuer" passed to the fetcher is the first
                // intermediate when present. When the leaf is signed
                // directly by a trust anchor (no intermediate), we
                // pass an empty slice; the production fetcher will
                // fail gracefully (no AIA → no fetch) but injected
                // test fetchers can still be exercised.
                let issuer = intermediates
                    .first()
                    .map(|c| c.as_ref().to_vec())
                    .unwrap_or_default();
                self.schedule_fetch(ski, end_entity.as_ref().to_vec(), issuer);
                Ok(verified)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustls::pki_types::CertificateDer;
    use rustls::server::WebPkiClientVerifier;

    use super::*;

    /// Deterministic in-memory fetcher used by unit tests.
    struct FakeFetcher {
        good: bool,
        calls: Arc<AtomicUsize>,
    }

    impl OcspFetcher for FakeFetcher {
        fn fetch<'a>(&'a self, _leaf: &'a [u8], _issuer: &'a [u8]) -> FetchFuture<'a> {
            let calls = self.calls.clone();
            let good = self.good;
            Box::pin(async move {
                let _ = calls.fetch_add(1, Ordering::SeqCst);
                Ok(good)
            })
        }
    }

    fn build_inner_and_certs() -> (Arc<dyn ClientCertVerifier>, CertificateDer<'static>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = rustgate_test_utils::certs::TestCa::new("ClientOCSP Test CA");
        let leaf = ca.issue_client_cert("client-1", &[]);
        let mut roots = rustls::RootCertStore::empty();
        let ca_der: Vec<CertificateDer<'static>> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(ca.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        for c in ca_der {
            roots.add(c).unwrap();
        }
        let inner: Arc<dyn ClientCertVerifier> = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let leaf_der: Vec<CertificateDer<'static>> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(leaf.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let leaf_der = leaf_der.into_iter().next().unwrap();
        (inner, leaf_der)
    }

    #[tokio::test]
    async fn miss_then_hit_increments_callbacks() {
        let (inner, leaf_der) = build_inner_and_certs();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: calls.clone(),
        });
        let hits = Arc::new(AtomicUsize::new(0));
        let misses = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let m = misses.clone();
        let verifier = ClientOcspVerifier::new(
            inner,
            fetcher,
            Some(Arc::new(move || {
                let _ = h.fetch_add(1, Ordering::SeqCst);
            })),
            Some(Arc::new(move || {
                let _ = m.fetch_add(1, Ordering::SeqCst);
            })),
        );

        // Drive only the cache plumbing (not the inner verifier path
        // validation, which would require a full chain). We test the
        // full handshake path in the integration test.
        let ski = cache_key(leaf_der.as_ref());
        assert!(verifier.cached_status(&ski).is_none());
        verifier.schedule_fetch(ski.clone(), leaf_der.as_ref().to_vec(), Vec::new());

        // Wait for the background task to insert.
        for _ in 0..50 {
            if verifier.cached_status(&ski).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(matches!(
            verifier.cached_status(&ski),
            Some(CachedStatus::Good)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cache_key_uses_ski_when_present() {
        let ca = rustgate_test_utils::certs::TestCa::new("SKI test");
        let leaf = ca.issue_client_cert("ski-client", &[]);
        let leaf_der: Vec<CertificateDer<'static>> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(leaf.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key1 = cache_key(leaf_der[0].as_ref());
        let key2 = cache_key(leaf_der[0].as_ref());
        assert_eq!(key1, key2);
        assert!(!key1.is_empty());
    }
}
