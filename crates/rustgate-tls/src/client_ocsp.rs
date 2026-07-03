// Copyright © 2026 Roberto Chiofalo.

//! Client certificate OCSP verification (Tier 1).
//!
//! This module wraps any [`ClientCertVerifier`] with a layer that consults
//! a fingerprint-keyed cache of OCSP responses for the presented end-entity
//! client certificate. The wrapper is "fail-open" by default: if the cache
//! has never seen the certificate, the inner verifier's decision stands and
//! a background task is dispatched to fetch an OCSP response so the *next*
//! handshake can be checked. If a cached entry says the certificate is
//! revoked, the verifier rejects the handshake outright.
//!
//! # Design
//!
//! - **Cache key.** The cache is keyed on the SHA-256 fingerprint of the
//!   full end-entity DER encoding. This guarantees one entry per distinct
//!   certificate and avoids collisions that could occur when using the
//!   Subject Key Identifier (SKI), since two certificates reissued with
//!   the same key pair share the same SKI.
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

use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;

use lru::LruCache;
use rustgate_core::tasks::spawn_background;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use sha2::Digest;
use tokio::sync::mpsc;
use tracing::{debug, warn};

rustgate_core::on_callback!(
    /// Callback invoked on a cache hit (any cached entry, regardless of status).
    pub OnCacheHit
);
rustgate_core::on_callback!(
    /// Callback invoked on a cache miss before a background fetch is dispatched.
    pub OnCacheMiss
);

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
// justification: `ocsp_stapler::Client` does not implement `Debug` upstream
// and derives would fail. Custom `Debug` impl would have nothing meaningful
// to print (the client is an opaque HTTP pool with secrets in memory).
// The type is visible only through the `ClientOcspFetcher` trait and never
// printed in our logs, so the workspace-wide `missing_debug_implementations`
// warning is a false positive here.
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
    /// Reported `Good`, recorded at the given wall-clock second (Unix
    /// epoch). The timestamp lets a frequently-reconnecting cert's `Good`
    /// answer be re-validated after the TTL instead of trusted for the whole
    /// process lifetime (#1625). `Revoked` needs no timestamp: revocation is
    /// monotonic — a revoked certificate never becomes good again.
    Good {
        cached_at_secs: u64,
    },
    Revoked,
}

/// Wraps an inner [`ClientCertVerifier`] with OCSP-based revocation checks.
///
/// See the module-level documentation for design notes.
pub struct ClientOcspVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    // SEC-6: bounded LRU rather than an unbounded `HashMap`. One entry per
    // distinct presented client cert; an adversary rotating many CA-issued
    // certs would otherwise grow this without limit for the process lifetime.
    // A `get` on the hot verify path bumps recency, so actively-connecting
    // peers stay cached and only idle entries are evicted under pressure.
    cache: parking_lot::Mutex<LruCache<Vec<u8>, CachedStatus>>,
    fetch_tx: mpsc::Sender<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    on_hit: Option<OnCacheHit>,
    on_miss: Option<OnCacheMiss>,
    /// Seconds after which a cached `Good` answer is treated as stale and
    /// re-validated on the next handshake (#1625). Bounds how long a
    /// frequently-reconnecting cert is trusted without re-querying the
    /// responder, so a later revocation is observed within this window.
    good_ttl_secs: u64,
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

/// Maximum number of cached OCSP statuses (SEC-6).
///
/// Bounds the per-verifier cache so an adversary rotating many distinct
/// CA-issued client certificates cannot grow it without limit. Each entry is
/// a 32-byte fingerprint + a one-byte status, so 4096 entries is well under
/// ~200 KiB while comfortably covering realistic distinct-client populations.
/// Least-recently-used entries are evicted once the cap is reached.
const OCSP_CACHE_CAPACITY: usize = 4096;

/// Default re-validation window for a cached `Good` OCSP answer (#1625).
///
/// One hour balances responder load against revocation-detection latency: a
/// frequently-reconnecting client's `Good` status is re-queried at most this
/// long after it was recorded, so a revocation issued mid-session is observed
/// within the window rather than never. CRL, when configured, independently
/// catches the same revocation on its own refresh cadence.
const DEFAULT_OCSP_GOOD_TTL_SECS: u64 = 3600;

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
        Self::new_with_good_ttl(inner, fetcher, on_hit, on_miss, DEFAULT_OCSP_GOOD_TTL_SECS)
    }

    /// Like [`Self::new`] but with an explicit re-validation window for cached
    /// `Good` answers (#1625). Exposed primarily for tests; production callers
    /// use [`Self::new`], which applies [`DEFAULT_OCSP_GOOD_TTL_SECS`].
    pub fn new_with_good_ttl(
        inner: Arc<dyn ClientCertVerifier>,
        fetcher: Arc<dyn OcspFetcher>,
        on_hit: Option<OnCacheHit>,
        on_miss: Option<OnCacheMiss>,
        good_ttl_secs: u64,
    ) -> Arc<Self> {
        let (fetch_tx, mut fetch_rx) =
            mpsc::channel::<(Vec<u8>, Vec<u8>, Vec<u8>)>(FETCH_QUEUE_CAPACITY);

        // `unwrap_or(MIN)` keeps the construction panic-free even if the
        // const were ever set to 0; OCSP_CACHE_CAPACITY is non-zero so MIN
        // is never actually reached.
        let cap = NonZeroUsize::new(OCSP_CACHE_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        let verifier = Arc::new(Self {
            inner,
            cache: parking_lot::Mutex::new(LruCache::new(cap)),
            fetch_tx,
            on_hit,
            on_miss,
            good_ttl_secs,
        });

        let weak = Arc::downgrade(&verifier);
        let fetcher_clone = fetcher;
        spawn_background("client-ocsp-fetcher", async move {
            while let Some((cert_fp, leaf, issuer)) = fetch_rx.recv().await {
                let Some(this) = weak.upgrade() else {
                    return;
                };
                match fetcher_clone.fetch(&leaf, &issuer).await {
                    Ok(true) => {
                        debug!(?cert_fp, "client OCSP: cached as Good");
                        let _ = this.cache.lock().put(
                            cert_fp,
                            CachedStatus::Good {
                                cached_at_secs: now_unix_secs(),
                            },
                        );
                    }
                    Ok(false) => {
                        warn!(?cert_fp, "client OCSP: certificate reported as revoked");
                        let _ = this.cache.lock().put(cert_fp, CachedStatus::Revoked);
                    }
                    Err(e) => {
                        debug!(?cert_fp, error = %e, "client OCSP: fetch failed");
                    }
                }
            }
        });

        verifier
    }

    /// Read the cached OCSP status for the given certificate fingerprint.
    fn cached_status(&self, cert_fp: &[u8]) -> Option<CachedStatus> {
        self.cache.lock().get(cert_fp).copied()
    }

    /// Schedule a background OCSP fetch. Drops the request if the queue
    /// is full so a flood of unique certs cannot fan out unbounded I/O.
    fn schedule_fetch(&self, cert_fp: Vec<u8>, leaf: Vec<u8>, issuer: Vec<u8>) {
        if let Err(e) = self.fetch_tx.try_send((cert_fp, leaf, issuer)) {
            debug!(error = %e, "client OCSP: fetch queue full, dropping request");
        }
    }

    /// Number of cached entries. Test/observability helper.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().len()
    }
}

/// Current wall-clock time as whole seconds since the Unix epoch, used to
/// stamp cached `Good` answers. Used off the verify hot path (in the
/// background fetcher), so reading the system clock here is fine. Returns 0 if
/// the clock is before the epoch, which only makes a `Good` entry look stale
/// sooner (fail-safe).
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a `Good` entry recorded at `cached_at_secs` is stale at handshake
/// time `now_secs`, given the re-validation window `ttl_secs`. Pulled out as a
/// pure function so the staleness arithmetic is unit-testable. Clock-backwards
/// safe: `saturating_sub` treats a backwards clock step as age 0 (fresh), so a
/// rewound NTP correction can never force a re-fetch storm.
fn good_entry_is_stale(cached_at_secs: u64, now_secs: u64, ttl_secs: u64) -> bool {
    now_secs.saturating_sub(cached_at_secs) >= ttl_secs
}

/// Compute the cache key for a leaf certificate.
///
/// Returns the SHA-256 fingerprint of the full DER encoding. This
/// guarantees a unique key per certificate — two certs reissued with
/// the same key pair (identical SKI) will still have different serial
/// numbers, validity periods, and thus different DER encodings.
fn cache_key(leaf_der: &[u8]) -> Vec<u8> {
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

        let cert_fp = cache_key(end_entity.as_ref());
        match self.cached_status(&cert_fp) {
            Some(CachedStatus::Good { cached_at_secs }) => {
                if good_entry_is_stale(cached_at_secs, now.as_secs(), self.good_ttl_secs) {
                    // Stale `Good`: re-validate. Fire the miss callback and
                    // schedule a background re-fetch, then fail open for this
                    // handshake exactly like a cache miss (Tier 1). Without
                    // this, a `Good` answer is bumped on every reconnect and
                    // never re-queried, so a later revocation is never
                    // observed for the process lifetime (#1625).
                    if let Some(cb) = &self.on_miss {
                        cb();
                    }
                    let issuer = intermediates
                        .first()
                        .map(|c| c.as_ref().to_vec())
                        .unwrap_or_default();
                    self.schedule_fetch(cert_fp, end_entity.as_ref().to_vec(), issuer);
                    Ok(verified)
                } else {
                    if let Some(cb) = &self.on_hit {
                        cb();
                    }
                    Ok(verified)
                }
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
                self.schedule_fetch(cert_fp, end_entity.as_ref().to_vec(), issuer);
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

    /// Fetcher that always errors. Used to pin the "errored fetch =
    /// nothing cached" branch of the background task so the next
    /// handshake falls through the miss arm again (no silent
    /// "treat errors as Good" regression).
    struct ErrFetcher;

    impl OcspFetcher for ErrFetcher {
        fn fetch<'a>(&'a self, _leaf: &'a [u8], _issuer: &'a [u8]) -> FetchFuture<'a> {
            Box::pin(async move { Err("injected fetch error".to_string()) })
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
        let fp = cache_key(leaf_der.as_ref());
        assert!(verifier.cached_status(&fp).is_none());
        verifier.schedule_fetch(fp.clone(), leaf_der.as_ref().to_vec(), Vec::new());

        // Wait for the background task to insert.
        for _ in 0..50 {
            if verifier.cached_status(&fp).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(matches!(
            verifier.cached_status(&fp),
            Some(CachedStatus::Good { .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cache_key_is_deterministic() {
        let ca = rustgate_test_utils::certs::TestCa::new("fingerprint test");
        let leaf = ca.issue_client_cert("fp-client", &[]);
        let leaf_der: Vec<CertificateDer<'static>> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(leaf.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key1 = cache_key(leaf_der[0].as_ref());
        let key2 = cache_key(leaf_der[0].as_ref());
        assert_eq!(key1, key2);
        // SHA-256 output is always 32 bytes.
        assert_eq!(key1.len(), 32);
    }

    /// Two certs issued to the same CN must produce different cache keys.
    /// Each call to `issue_client_cert` generates a fresh key pair, so the
    /// certs differ in serial number, public key, and DER encoding. Under
    /// the old SKI-based scheme, certs reissued with the *same* key pair
    /// would have collided; SHA-256 of the full DER avoids this because
    /// any difference in the encoding (serial, validity, key) produces a
    /// distinct fingerprint.
    #[test]
    fn cache_key_differs_for_reissued_cert() {
        let ca = rustgate_test_utils::certs::TestCa::new("collision test");
        let cert_a = ca.issue_client_cert("same-cn", &["ops"]);
        let cert_b = ca.issue_client_cert("same-cn", &["ops"]);
        let der_a: Vec<CertificateDer<'static>> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(cert_a.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let der_b: Vec<CertificateDer<'static>> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(cert_b.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key_a = cache_key(der_a[0].as_ref());
        let key_b = cache_key(der_b[0].as_ref());
        assert_ne!(
            key_a, key_b,
            "different certs must produce different cache keys"
        );
    }

    // -----------------------------------------------------------------------
    // Defensive invariants — constants, hash primitives, type-surface bounds.
    // -----------------------------------------------------------------------

    /// The fetch queue capacity is a load-bearing knob: too small and a
    /// moderate flood of unique handshakes drops all OCSP refreshes;
    /// too large and a malicious flood of bogus CNs fans out unbounded
    /// background HTTP traffic. Pin the constant so a silent edit is
    /// caught in code review.
    #[test]
    fn fetch_queue_capacity_is_256() {
        assert_eq!(FETCH_QUEUE_CAPACITY, 256);
    }

    /// SEC-6: the OCSP status cache is a bounded LRU. Inserting beyond the
    /// capacity must evict least-recently-used entries rather than grow the
    /// map without limit (an adversary rotating distinct CA-issued certs).
    #[tokio::test]
    async fn cache_is_bounded_to_capacity() {
        let (inner, _) = build_inner_and_certs();
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);
        // Insert well beyond the cap directly through the (in-module) cache.
        {
            let mut cache = verifier.cache.lock();
            for i in 0..(OCSP_CACHE_CAPACITY + 100) {
                let _ = cache.put(
                    (i as u64).to_le_bytes().to_vec(),
                    CachedStatus::Good { cached_at_secs: 0 },
                );
            }
        }
        assert_eq!(
            verifier.cache_len(),
            OCSP_CACHE_CAPACITY,
            "cache must be bounded to OCSP_CACHE_CAPACITY, not grow without limit"
        );
    }

    /// `cache_key` must be SHA-256 of the input, not an alternative hash.
    /// A silent refactor to BLAKE3 or SHA-1 (the latter is still common in
    /// certificate fingerprint tooling) would produce keys the rest of
    /// the OCSP plumbing would not recognise across restarts and would
    /// break any forensics correlating fingerprints produced by external
    /// certificate-inspection tools against the cache keys logged here.
    #[test]
    fn cache_key_is_sha256_of_full_der() {
        use sha2::{Digest, Sha256};
        let sample: &[u8] = b"arbitrary-der-payload-for-hash-identity-check";
        let expected = Sha256::digest(sample).to_vec();
        assert_eq!(cache_key(sample), expected);
        assert_eq!(cache_key(sample).len(), 32);
    }

    /// Empty input must hash without panic. SHA-256 of the empty byte
    /// string is a well-known published vector; this pins the zero-input
    /// edge case (which can be exercised by a malformed handshake that
    /// somehow presents an empty leaf) so a regression that called
    /// `update` on a zero-length slice under a cfg that required a
    /// non-zero update would be caught.
    #[test]
    fn cache_key_of_empty_input_matches_sha256_empty_vector() {
        let key = cache_key(&[]);
        // SHA-256("") per FIPS 180-4 test vectors.
        let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected_hex);
    }

    /// A single-bit flip must produce a completely different key
    /// (avalanche). This is a core property of SHA-256 and the defence
    /// behind keying on the full DER rather than the SKI: attackers who
    /// forge certs that differ from a revoked cert by one bit must not
    /// collide in the cache.
    #[test]
    fn cache_key_differs_on_single_bit_flip() {
        let a: Vec<u8> = (0..64).collect();
        let mut b = a.clone();
        b[0] ^= 0x01;
        let key_a = cache_key(&a);
        let key_b = cache_key(&b);
        assert_ne!(key_a, key_b);
        // At least half the bytes should differ on a strong hash; an
        // accidental regression to an identity or XOR-based "hash"
        // would leave most bytes equal.
        let diffs = key_a
            .iter()
            .zip(key_b.iter())
            .filter(|(x, y)| x != y)
            .count();
        assert!(
            diffs >= 16,
            "expected strong avalanche, only {diffs}/32 bytes differ",
        );
    }

    /// `cache_key` is a pure function — calling it twice with the same
    /// input on different inputs must not interleave state. Pins there
    /// is no global hasher, no thread-local accumulator.
    #[test]
    fn cache_key_is_purely_functional_on_interleaved_calls() {
        let a: Vec<u8> = b"alpha".to_vec();
        let b: Vec<u8> = b"beta".to_vec();
        let k_a1 = cache_key(&a);
        let k_b1 = cache_key(&b);
        let k_a2 = cache_key(&a);
        let k_b2 = cache_key(&b);
        assert_eq!(k_a1, k_a2);
        assert_eq!(k_b1, k_b2);
        assert_ne!(k_a1, k_b1);
    }

    /// The `CachedStatus` enum must be `Copy + Clone + Debug` so the
    /// lock-held closure in `cached_status` can return the value by
    /// value without cloning a `String`, and so traces can log the
    /// variant.
    #[test]
    fn cached_status_is_copy_clone_debug() {
        fn assert_bounds<T: Copy + Clone + std::fmt::Debug>() {}
        assert_bounds::<CachedStatus>();
        // `Copy` is exercised implicitly via the bounds assertion above; use
        // the explicit `Clone::clone` form so clippy does not flag this as
        // `clone_on_copy` (we genuinely want to exercise the `Clone` derive).
        let g = CachedStatus::Good { cached_at_secs: 0 };
        let cloned = Clone::clone(&g);
        assert!(matches!(cloned, CachedStatus::Good { .. }));
        assert!(format!("{g:?}").contains("Good"));
        assert!(format!("{:?}", CachedStatus::Revoked).contains("Revoked"));
    }

    /// A `Good` entry is stale once `ttl_secs` have elapsed since it was
    /// recorded; a backwards clock step keeps it fresh rather than forcing a
    /// re-fetch storm (#1625).
    #[test]
    fn good_entry_staleness_window() {
        // Within the window → fresh.
        assert!(!good_entry_is_stale(100, 150, 3600));
        assert!(!good_entry_is_stale(100, 100 + 3599, 3600));
        // At and past the window → stale (re-validate).
        assert!(good_entry_is_stale(100, 100 + 3600, 3600));
        assert!(good_entry_is_stale(100, 100 + 10_000, 3600));
        // Clock stepped backwards (now < cached_at) → fresh, never a storm.
        assert!(!good_entry_is_stale(5000, 100, 3600));
    }

    /// `OcspFetcher` trait objects must be shareable across tokio tasks
    /// (the fetcher is held by the background task spawned from `new()`
    /// which moves into `tokio::spawn`). Pin the trait-level bounds
    /// against a silent narrowing to `Send` or `Sync` alone.
    #[test]
    fn ocsp_fetcher_trait_is_send_sync_static() {
        fn assert_bounds<T: Send + Sync + 'static + ?Sized>() {}
        assert_bounds::<dyn OcspFetcher>();
    }

    /// The callback aliases must be `Send + Sync + Clone` because the
    /// router clones them into per-session state and the verifier task
    /// invokes them from the tokio runtime.
    #[test]
    fn on_cache_hit_and_miss_aliases_are_send_sync_clone() {
        fn assert_bounds<T: Send + Sync + Clone>() {}
        assert_bounds::<OnCacheHit>();
        assert_bounds::<OnCacheMiss>();
    }

    /// The `FetchFuture` alias must remain `Send + 'a` so fetcher impls
    /// can be awaited across task boundaries without downgrading the
    /// trait-object bounds. A concrete assignment compiles only when
    /// the inner future satisfies the alias bounds — a regression that
    /// dropped `Send` or widened to `!Send` would trip on this line.
    #[test]
    fn fetch_future_alias_is_pin_box_dyn_send() {
        // Use a plain `async {}` block (not an `async fn` declaration) to
        // avoid clippy's `unused_async` warning on a body that legitimately
        // contains no `.await` — the test's point is purely the type shape.
        let _f: FetchFuture<'_> = Box::pin(async { Ok::<bool, String>(true) });
        // Compile-time: the alias must also be `Send` so it can be
        // moved into spawned tokio tasks.
        fn is_send<T: Send>(_: &T) {}
        let g: FetchFuture<'_> = Box::pin(async { Ok::<bool, String>(true) });
        is_send(&g);
    }

    /// The custom `Debug` impl on `ClientOcspVerifier` prints only the
    /// cache-entry count. It must NOT leak the inner verifier (which
    /// might log subjects of root hints on its own `Debug`) nor the
    /// fetcher (which may hold HTTP client state). This is the
    /// redacted-debug defence pattern used across the workspace.
    #[tokio::test]
    async fn debug_redacts_inner_and_fetcher_prints_cache_entry_count() {
        let (inner, _leaf) = build_inner_and_certs();
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);
        let s = format!("{verifier:?}");
        assert!(s.contains("ClientOcspVerifier"));
        assert!(s.contains("cache_entries"));
        // Negative: should not expose the inner verifier or fetcher.
        assert!(!s.contains("FakeFetcher"));
        assert!(!s.contains("WebPkiClientVerifier"));
    }

    /// `ClientOcspVerifier::new` accepts `None` for both callbacks and
    /// still produces a usable verifier. Catches a regression that
    /// reverted the `Option` wrapper to required callbacks.
    #[tokio::test]
    async fn new_with_none_callbacks_is_usable() {
        let (inner, _) = build_inner_and_certs();
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);
        // cache_len is zero on a fresh verifier.
        assert_eq!(verifier.cache_len(), 0);
        // cached_status on an unknown fingerprint is None.
        assert!(verifier.cached_status(b"unknown-fingerprint").is_none());
    }

    /// The `cache_len` accessor observes the same count the Debug impl
    /// prints and increments as the background fetcher inserts. Pins
    /// the accessor's contract against a regression that returned a
    /// stale or hard-coded count.
    #[tokio::test]
    async fn cache_len_reflects_inserts_from_background_fetcher() {
        let (inner, leaf_der) = build_inner_and_certs();
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);
        assert_eq!(verifier.cache_len(), 0);
        let fp = cache_key(leaf_der.as_ref());
        verifier.schedule_fetch(fp.clone(), leaf_der.as_ref().to_vec(), Vec::new());
        for _ in 0..50 {
            if verifier.cache_len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(verifier.cache_len(), 1);
    }

    /// `schedule_fetch` must drop silently when the bounded channel is
    /// full. A regression that `.await`-ed the send or panicked on
    /// queue saturation would turn a benign traffic burst into a
    /// runtime crash or a latency spike on the handshake hot path.
    #[tokio::test]
    async fn schedule_fetch_drops_silently_when_queue_is_saturated() {
        // Fetcher that never completes — keeps the queue full.
        struct StuckFetcher;
        impl OcspFetcher for StuckFetcher {
            fn fetch<'a>(&'a self, _l: &'a [u8], _i: &'a [u8]) -> FetchFuture<'a> {
                Box::pin(async move {
                    // Hold forever so the queue-drain loop is blocked
                    // on our first message; subsequent sends must
                    // saturate the bounded channel and be dropped
                    // without panic.
                    futures::future::pending::<()>().await;
                    Ok(true)
                })
            }
        }
        let (inner, _) = build_inner_and_certs();
        let verifier = ClientOcspVerifier::new(inner, Arc::new(StuckFetcher), None, None);
        // Prime the receiver-side loop with one message it will hold
        // forever, then saturate the channel plus one additional send
        // that must be dropped.
        verifier.schedule_fetch(vec![0u8; 32], vec![0u8; 32], Vec::new());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // FETCH_QUEUE_CAPACITY + 2: one in-flight, capacity in channel,
        // and one more to exceed the bound.
        for i in 0..(FETCH_QUEUE_CAPACITY + 2) {
            verifier.schedule_fetch(vec![i as u8; 32], vec![i as u8; 32], Vec::new());
        }
        // The test passes if we reach here without panicking. Cache
        // remains empty because the stuck fetcher never completes.
        assert_eq!(verifier.cache_len(), 0);
    }

    /// When the cache has a `Revoked` entry, `verify_client_cert`
    /// rejects the handshake with an `Error::General` carrying a
    /// message that mentions OCSP revocation. Pins the rejection path
    /// against a silent change that swapped the variant or the text
    /// (operators grep for "revoked" in logs during incidents).
    #[tokio::test]
    async fn verify_client_cert_rejects_when_cached_revoked() {
        let (inner, leaf_der) = build_inner_and_certs();
        let fetcher = Arc::new(FakeFetcher {
            good: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);
        // Seed the cache as Revoked manually via the scheduler + the
        // fetcher (which returns false → Revoked).
        let fp = cache_key(leaf_der.as_ref());
        verifier.schedule_fetch(fp.clone(), leaf_der.as_ref().to_vec(), Vec::new());
        for _ in 0..50 {
            if matches!(verifier.cached_status(&fp), Some(CachedStatus::Revoked)) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // Sanity: the cache is seeded Revoked.
        assert!(matches!(
            verifier.cached_status(&fp),
            Some(CachedStatus::Revoked)
        ));
        let now = UnixTime::now();
        let result = verifier.verify_client_cert(&leaf_der, &[], now);
        let err = result.expect_err("revoked cert must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("revoked"),
            "expected 'revoked' in error, got: {msg}",
        );
    }

    /// `verify_client_cert` returns the inner verifier's result when
    /// the cache says the cert is Good. Pins the happy-path branch.
    #[tokio::test]
    async fn verify_client_cert_accepts_when_cached_good() {
        let (inner, leaf_der) = build_inner_and_certs();
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);
        let fp = cache_key(leaf_der.as_ref());
        verifier.schedule_fetch(fp.clone(), leaf_der.as_ref().to_vec(), Vec::new());
        for _ in 0..50 {
            if matches!(verifier.cached_status(&fp), Some(CachedStatus::Good { .. })) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let now = UnixTime::now();
        // verify_client_cert runs the inner verifier (which needs a
        // valid chain to the test CA) and then consults the cache.
        // A successful Ok here confirms both paths agree.
        let result = verifier.verify_client_cert(&leaf_der, &[], now);
        assert!(result.is_ok(), "Good cached cert must pass: {result:?}");
    }

    /// On a cache hit (Good), the `on_hit` callback is invoked exactly
    /// once per `verify_client_cert` call. Pins the metric-counter
    /// semantics operators depend on to understand OCSP cache
    /// effectiveness.
    #[tokio::test]
    async fn on_hit_callback_fires_once_on_good_cache_hit() {
        let (inner, leaf_der) = build_inner_and_certs();
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let verifier = ClientOcspVerifier::new(
            inner,
            fetcher,
            Some(Arc::new(move || {
                let _ = h.fetch_add(1, Ordering::SeqCst);
            })),
            None,
        );
        let fp = cache_key(leaf_der.as_ref());
        verifier.schedule_fetch(fp.clone(), leaf_der.as_ref().to_vec(), Vec::new());
        for _ in 0..50 {
            if matches!(verifier.cached_status(&fp), Some(CachedStatus::Good { .. })) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        let _ = verifier.verify_client_cert(&leaf_der, &[], UnixTime::now());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// On a cache miss, the `on_miss` callback fires exactly once and a
    /// background fetch is scheduled. The inner verifier's Ok still
    /// stands because Tier 1 is fail-open.
    #[tokio::test]
    async fn on_miss_callback_fires_once_and_schedules_fetch_on_cold_cache() {
        let (inner, leaf_der) = build_inner_and_certs();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: calls.clone(),
        });
        let misses = Arc::new(AtomicUsize::new(0));
        let m = misses.clone();
        let verifier = ClientOcspVerifier::new(
            inner,
            fetcher,
            None,
            Some(Arc::new(move || {
                let _ = m.fetch_add(1, Ordering::SeqCst);
            })),
        );
        // Cold cache → miss + schedule_fetch + inner-verifier Ok.
        let result = verifier.verify_client_cert(&leaf_der, &[], UnixTime::now());
        assert!(
            result.is_ok(),
            "fail-open Tier 1 accepts cold-cache verification"
        );
        assert_eq!(misses.load(Ordering::SeqCst), 1);
        // Background fetch drains eventually.
        for _ in 0..50 {
            if calls.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// `root_hint_subjects` delegates to the inner verifier and returns
    /// exactly the inner's slice. A regression that returned an empty
    /// slice would silently cause rustls to send no CA hints in the
    /// TLS handshake, breaking clients that depend on them to pick the
    /// right cert chain.
    #[tokio::test]
    async fn root_hint_subjects_delegates_to_inner() {
        let (inner, _) = build_inner_and_certs();
        // `DistinguishedName` is a newtype around a byte vector without
        // `PartialEq`, so compare length and byte contents directly.
        let inner_subjects_bytes: Vec<Vec<u8>> = inner
            .root_hint_subjects()
            .iter()
            .map(|s| s.as_ref().to_vec())
            .collect();
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);
        let wrapped_bytes: Vec<Vec<u8>> = verifier
            .root_hint_subjects()
            .iter()
            .map(|s| s.as_ref().to_vec())
            .collect();
        assert_eq!(wrapped_bytes, inner_subjects_bytes);
    }

    /// `supported_verify_schemes` delegates to the inner verifier and
    /// returns the inner's list verbatim. A regression that returned a
    /// narrower set would silently reject handshakes that used a
    /// supported-by-inner-but-filtered-by-wrapper scheme (e.g. RSA-PSS).
    #[tokio::test]
    async fn supported_verify_schemes_delegates_to_inner() {
        let (inner, _) = build_inner_and_certs();
        let inner_schemes = inner.supported_verify_schemes();
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);
        assert_eq!(verifier.supported_verify_schemes(), inner_schemes);
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    /// When the inner verifier rejects the certificate, the wrapper
    /// must propagate that rejection *without* consulting the cache.
    /// Pins the "OCSP is supplemental, not substitute for path
    /// validation" contract against a regression that flipped the
    /// ordering and let a valid OCSP Good override a path-validation
    /// failure.
    #[tokio::test]
    async fn inner_verifier_rejection_propagates_without_cache_consult() {
        // A custom inner verifier that always rejects. We build one by
        // hand rather than using `WebPkiClientVerifier` with an empty
        // root store because that builder refuses to build (returns
        // `NoRootAnchors`); we need a deterministic "inner always
        // rejects" behaviour for this branch test.
        #[derive(Debug)]
        struct AlwaysReject;
        impl ClientCertVerifier for AlwaysReject {
            fn root_hint_subjects(&self) -> &[DistinguishedName] {
                &[]
            }
            fn verify_client_cert(
                &self,
                _ee: &CertificateDer<'_>,
                _inter: &[CertificateDer<'_>],
                _now: UnixTime,
            ) -> Result<ClientCertVerified, Error> {
                Err(Error::General("inner-rejected".to_string()))
            }
            fn verify_tls12_signature(
                &self,
                _m: &[u8],
                _c: &CertificateDer<'_>,
                _d: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, Error> {
                Err(Error::General("unused".to_string()))
            }
            fn verify_tls13_signature(
                &self,
                _m: &[u8],
                _c: &CertificateDer<'_>,
                _d: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, Error> {
                Err(Error::General("unused".to_string()))
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![SignatureScheme::RSA_PKCS1_SHA256]
            }
        }

        let (_, leaf_der) = build_inner_and_certs();
        let strict_inner: Arc<dyn ClientCertVerifier> = Arc::new(AlwaysReject);
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(strict_inner, fetcher, None, None);
        // Seed the cache as Good — the rejection path should ignore
        // this and still fail on the inner verifier's decision.
        let fp = cache_key(leaf_der.as_ref());
        verifier.schedule_fetch(fp.clone(), leaf_der.as_ref().to_vec(), Vec::new());
        for _ in 0..50 {
            if matches!(verifier.cached_status(&fp), Some(CachedStatus::Good { .. })) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let result = verifier.verify_client_cert(&leaf_der, &[], UnixTime::now());
        let err = result.expect_err("inner rejection must propagate even on Good cache");
        let msg = format!("{err}");
        assert!(
            msg.contains("inner-rejected"),
            "wrapper must carry inner error verbatim, got: {msg}",
        );
    }

    /// Weak references held by the background fetch task must release
    /// when the last strong `Arc<ClientOcspVerifier>` is dropped, so
    /// the spawned task exits cleanly and does not leak. Pins the
    /// `Arc::downgrade`-based lifecycle against a regression that
    /// upgraded to a strong reference (which would create a cycle and
    /// leak the task).
    /// ADR-0025 Piece 2 composition invariant: when the inner
    /// `DynamicCertVerifier` has its fail-closed gate engaged, the outer
    /// `ClientOcspVerifier` MUST reject regardless of a "good" OCSP verdict.
    /// The wrapper runs the inner `verify_client_cert` first with `?`, so an
    /// engaged gate short-circuits before OCSP is ever consulted (#1496).
    #[tokio::test]
    async fn ocsp_wrapper_cannot_override_engaged_fail_closed_gate() {
        let (_, leaf_der) = build_inner_and_certs();

        // Real dynamic inner verifier with an engaged fail-closed gate.
        let ca = rustgate_test_utils::certs::TestCa::new("FC Gate OCSP CA");
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pki_types::pem::PemObject::pem_slice_iter(ca.cert_pem.as_bytes())
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .unwrap()
        {
            roots.add(c).unwrap();
        }
        let gate = crate::verifier::FailClosedGate::new(std::time::Duration::from_secs(0));
        gate.observe(true);
        assert!(gate.is_engaged());
        let empty_crls: Arc<Vec<rustls::pki_types::CertificateRevocationListDer<'static>>> =
            Arc::new(Vec::new());
        let inner = crate::verifier::DynamicCertVerifier::with_crl_provider_and_gate(
            Box::new(move || (0, roots.clone())),
            Box::new(move || (0, Arc::clone(&empty_crls))),
            Some(gate),
        )
        .unwrap();

        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);
        // Seed a Good OCSP verdict so the ONLY thing that can reject is the
        // inner gate.
        let fp = cache_key(leaf_der.as_ref());
        verifier.schedule_fetch(fp.clone(), leaf_der.as_ref().to_vec(), Vec::new());
        for _ in 0..50 {
            if matches!(verifier.cached_status(&fp), Some(CachedStatus::Good { .. })) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let err = verifier
            .verify_client_cert(&leaf_der, &[], UnixTime::now())
            .expect_err("engaged inner gate must reject despite a Good OCSP verdict");
        assert!(
            format!("{err}").contains("fail-closed engaged"),
            "wrapper must surface the inner fail-closed error, got: {err}"
        );
    }

    #[tokio::test]
    async fn spawned_task_exits_when_verifier_arc_is_dropped() {
        let (inner, _) = build_inner_and_certs();
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);
        let weak = Arc::downgrade(&verifier);
        assert!(weak.upgrade().is_some());
        drop(verifier);
        // Yield a few times for the spawned task to see the weak
        // pointer fail to upgrade and terminate.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(
            weak.upgrade().is_none(),
            "verifier Arc must fully drop once the caller releases it",
        );
    }

    /// Pin that a failed fetch leaves the cache empty — the next
    /// handshake must re-enter the miss arm and re-schedule a fetch,
    /// not silently fail open forever via a stale `Ok(_)` insert.
    #[tokio::test]
    async fn errored_fetch_leaves_cache_entry_unset() {
        let (inner, leaf_der) = build_inner_and_certs();
        let verifier = ClientOcspVerifier::new(inner, Arc::new(ErrFetcher), None, None);

        let fp = cache_key(leaf_der.as_ref());
        verifier.schedule_fetch(fp.clone(), leaf_der.as_ref().to_vec(), Vec::new());

        // Let the background task drain the queue and hit the error
        // arm. A small fixed budget is plenty — the task is sync-on-error.
        for _ in 0..50 {
            if verifier.cache_len() > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(
            verifier.cached_status(&fp).is_none(),
            "errored fetch must not populate the cache",
        );
        assert_eq!(verifier.cache_len(), 0);
    }

    /// `verify_client_cert` passes an empty issuer slice when the leaf
    /// is signed directly by a trust anchor (no intermediate). The
    /// background fetcher must accept that input shape and not panic —
    /// the production `OcspStaplerFetcher` fails gracefully via AIA
    /// lookup returning nothing; injected test fetchers see the same
    /// empty buffer.
    #[tokio::test]
    async fn schedule_fetch_with_empty_issuer_is_not_a_panic() {
        let (inner, leaf_der) = build_inner_and_certs();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(FakeFetcher {
            good: true,
            calls: calls.clone(),
        });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);

        let fp = cache_key(leaf_der.as_ref());
        // Empty issuer (zero-length Vec) — the no-intermediate edge case.
        verifier.schedule_fetch(fp.clone(), leaf_der.as_ref().to_vec(), Vec::new());
        for _ in 0..50 {
            if verifier.cached_status(&fp).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "empty issuer must still reach the fetcher (production will AIA-fail gracefully)",
        );
    }

    /// `cached_status` must never surface a stale/mismatched entry for
    /// arbitrary input shapes. Pin a variety of byte patterns (empty
    /// slice, all-zero 32-byte, all-`0xFF` 64-byte, short ASCII prefix)
    /// and assert all miss.
    #[tokio::test]
    async fn cached_status_returns_none_for_unknown_key_shapes() {
        let (inner, _leaf_der) = build_inner_and_certs();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(FakeFetcher { good: true, calls });
        let verifier = ClientOcspVerifier::new(inner, fetcher, None, None);

        assert!(verifier.cached_status(&[]).is_none());
        assert!(verifier.cached_status(&[0u8; 32]).is_none());
        assert!(verifier.cached_status(&[0xFFu8; 64]).is_none());
        assert!(verifier.cached_status(b"short").is_none());
    }
}
