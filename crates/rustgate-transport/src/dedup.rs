// Copyright © 2026 Roberto Chiofalo.

//! Cross-path message deduplication cache.
//!
//! When the same logical message arrives via multiple ingress paths
//! (for example, a direct client connection and a federation peer that
//! forwarded it), subscribers should only receive it once. This module
//! provides a bounded LRU cache, keyed by
//! `SHA-256(tenant || 0x00 || uid || 0x00 || time_le || 0x00 || payload)`,
//! that the router consults on the dispatch hot path.
//!
//! For CoT XML payloads the `uid` and `time` attributes are extracted
//! and folded into the key alongside the payload hash. For non-CoT
//! payloads (protobuf, raw binary, anything the XML attribute scanner
//! cannot parse) the cache falls back to a pure content-hash key, with
//! `uid` empty and `time` set to zero. Either way, two byte-identical
//! payloads within the window are suppressed; two different payloads
//! sharing a `(uid, time)` pair pass through independently.
//!
//! # Tenant isolation
//!
//! By default, the cache folds each sender's tenant (derived from the
//! X.509 Organization field on the client certificate) into the key so
//! a message sent by tenant `A` cannot suppress a byte-identical
//! message sent by tenant `B`. Without this, a malicious tenant could
//! probe for the existence of messages in another tenant by submitting
//! candidate `(uid, time, payload)` triples and observing whether
//! delivery succeeds (= the other tenant did not send this) or is
//! silently deduplicated (= the other tenant sent exactly this). See
//! issue #722.
//!
//! Single-tenant deployments, or multi-tenant deployments where
//! cross-tenant duplicate suppression is explicitly desired, can opt
//! back into the pre-#722 behaviour with
//! [`DedupCache::with_cross_tenant(true)`][DedupCache::with_cross_tenant]
//! — equivalent to forcing the tenant slot in the key preimage to
//! empty for every caller. The flag is a stance-setter, not a runtime
//! toggle: it is fixed at construction time and documented loudly.
//!
//! Disabled by default; the server enables it via the
//! `--dedup-window-secs` CLI flag (a value of `0` keeps it off).

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

/// Default maximum number of cached entries when no override is given.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Optional callback invoked once per suppressed duplicate so the server
/// crate can update its Prometheus counter without `rustgate-transport`
/// taking a direct dependency on the metrics layer.
pub type OnDuplicate = Arc<dyn Fn() + Send + Sync>;

/// Optional callback invoked after a fresh entry is inserted into the
/// cache. The server crate uses this to publish the current cache size
/// as a Prometheus gauge without pulling a metrics dependency into
/// `rustgate-transport`.
pub type OnInsert = Arc<dyn Fn(usize) + Send + Sync>;

/// Cache key: a 32-byte SHA-256 digest.
type Key = [u8; 32];

/// Bounded, time-windowed deduplication cache.
///
/// The cache uses an LRU policy for size eviction and lazy TTL eviction
/// for age: an entry whose age exceeds the configured window is treated
/// as absent on the next lookup and replaced.
pub struct DedupCache {
    inner: Mutex<LruCache<Key, Instant>>,
    window: Duration,
    hits: AtomicU64,
    on_duplicate: Option<OnDuplicate>,
    on_insert: Option<OnInsert>,
    /// When `true`, the tenant slot in the key preimage is forced to
    /// empty for every lookup/insert so byte-identical messages from
    /// different tenants collide — the pre-#722 behaviour. Defaults to
    /// `false` (tenant-isolated).
    cross_tenant: bool,
}

impl std::fmt::Debug for DedupCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedupCache")
            .field("window", &self.window)
            .field("hits", &self.hits.load(Ordering::Relaxed))
            .field("cross_tenant", &self.cross_tenant)
            .finish()
    }
}

impl DedupCache {
    /// Create a new dedup cache with the given dedup window and capacity.
    ///
    /// `max_entries` of zero is normalized to `1` since the underlying
    /// LRU implementation requires a non-zero capacity. Tenant
    /// isolation is on by default — use
    /// [`with_cross_tenant`][Self::with_cross_tenant] to disable it.
    pub fn new(window: Duration, max_entries: usize) -> Self {
        let cap = NonZeroUsize::new(max_entries.max(1)).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            window,
            hits: AtomicU64::new(0),
            on_duplicate: None,
            on_insert: None,
            cross_tenant: false,
        }
    }

    /// Construct from a window in seconds. Returns `None` when `secs == 0`
    /// so callers can use the result directly as the on/off switch.
    pub fn from_secs(secs: u64, max_entries: usize) -> Option<Self> {
        if secs == 0 {
            return None;
        }
        Some(Self::new(Duration::from_secs(secs), max_entries))
    }

    /// Opt into cross-tenant deduplication.
    ///
    /// When `true`, the tenant slot in the cache key preimage is forced
    /// to empty so a message sent by tenant `A` suppresses a
    /// byte-identical message from tenant `B`. **This is unsafe in any
    /// deployment where tenants do not fully trust each other** — it
    /// opens a cross-tenant timing side-channel (issue #722) because a
    /// malicious tenant can probe for the existence of specific
    /// messages in another tenant by observing whether candidate
    /// payloads are silently suppressed. Single-tenant deployments, or
    /// deployments where cross-tenant duplicate suppression is
    /// explicitly desired, can opt in with eyes open.
    ///
    /// Defaults to `false` (tenant-isolated).
    pub fn with_cross_tenant(mut self, cross_tenant: bool) -> Self {
        self.cross_tenant = cross_tenant;
        self
    }

    /// Whether this cache folds the tenant into the key (`false`) or
    /// forces it to empty (`true`). Exposed for diagnostics and tests.
    pub fn is_cross_tenant(&self) -> bool {
        self.cross_tenant
    }

    /// Install a callback fired once per suppressed duplicate.
    pub fn set_on_duplicate(&mut self, cb: OnDuplicate) {
        self.on_duplicate = Some(cb);
    }

    /// Install a callback fired after each fresh insert, receiving the
    /// current cache size.
    pub fn set_on_insert(&mut self, cb: OnInsert) {
        self.on_insert = Some(cb);
    }

    /// Total number of duplicates suppressed since startup.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Number of currently tracked entries.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Whether the cache currently has no tracked entries.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Configured deduplication window.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Check whether
    /// `SHA-256(tenant || 0x00 || uid || 0x00 || 0_i64_le || 0x00 || payload)`
    /// was already seen within the configured window. Returns `true` on
    /// duplicate; otherwise inserts and returns `false`.
    ///
    /// The `time` parameter has been removed from the public API; the
    /// payload hash alone subsumes it.
    ///
    /// `tenant` should be the sender's tenant key (typically the X.509
    /// Organization field on the client certificate; an empty string is
    /// used for clients with no tenant attribute). When this cache was
    /// built with [`with_cross_tenant(true)`][Self::with_cross_tenant]
    /// the supplied `tenant` is ignored and the tenant slot is forced
    /// empty — see the type-level docs for the security implications.
    pub fn check_and_insert(&self, tenant: &str, uid: &str, payload: &[u8]) -> bool {
        let effective_tenant = if self.cross_tenant { "" } else { tenant };
        let key = build_key(effective_tenant, uid, payload);
        let now = Instant::now();
        let window = self.window;

        let mut cache = self.inner.lock();
        if let Some(stamp) = cache.get(&key) {
            if now.duration_since(*stamp) < window {
                drop(cache);
                let _ = self.hits.fetch_add(1, Ordering::Relaxed);
                if let Some(cb) = &self.on_duplicate {
                    cb();
                }
                return true;
            }
            // Entry expired — refresh and treat as new.
            let _ = cache.put(key, now);
            let len = cache.len();
            drop(cache);
            if let Some(cb) = &self.on_insert {
                cb(len);
            }
            return false;
        }
        let _ = cache.put(key, now);
        let len = cache.len();
        drop(cache);
        if let Some(cb) = &self.on_insert {
            cb(len);
        }
        false
    }

    /// Convenience wrapper for callers that have only the raw payload
    /// and the sender's tenant.
    ///
    /// For CoT XML payloads the `uid` attribute is extracted and folded
    /// into the key. For non-CoT payloads (protobuf, raw binary) the
    /// cache falls back to a pure content-hash key with an empty `uid`,
    /// so byte-identical payloads are still deduped.
    ///
    /// `tenant` should come from `Identity.tenant.as_deref().unwrap_or("")`
    /// on the dispatch path. See
    /// [`check_and_insert`][Self::check_and_insert] for the full
    /// semantics and the cross-tenant-mode caveat.
    pub fn check_payload(&self, tenant: &str, payload: &[u8]) -> bool {
        let uid = crate::replay::extract_xml_attr(payload, b"uid=")
            .and_then(|u| std::str::from_utf8(u).ok())
            .unwrap_or("");
        self.check_and_insert(tenant, uid, payload)
    }
}

/// Build the 32-byte cache key.
///
/// The format is
/// `SHA-256(tenant || 0x00 || uid || 0x00 || 0_i64_le || 0x00 || payload)`.
/// The `time` slot is fixed at zero (little-endian i64) and retained in
/// the hash preimage for stability with any external tooling that may
/// hash the same shape; since the full payload is also hashed, the time
/// slot is informational and cannot cause collisions.
///
/// Folding `tenant` into the preimage prevents a malicious tenant from
/// probing for the existence of messages in another tenant by observing
/// whether candidate payloads are silently suppressed (issue #722).
fn build_key(tenant: &str, uid: &str, payload: &[u8]) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(tenant.as_bytes());
    hasher.update([0u8]);
    hasher.update(uid.as_bytes());
    hasher.update([0u8]);
    hasher.update(0i64.to_le_bytes());
    hasher.update([0u8]);
    hasher.update(payload);
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cache(secs: u64, cap: usize) -> DedupCache {
        DedupCache::new(Duration::from_secs(secs), cap)
    }

    #[test]
    fn duplicate_is_detected() {
        let c = cache(60, 16);
        assert!(!c.check_and_insert("", "UID-1", b"hello"));
        assert!(c.check_and_insert("", "UID-1", b"hello"));
        assert_eq!(c.hits(), 1);
    }

    #[test]
    fn different_payload_same_uid_passes() {
        let c = cache(60, 16);
        assert!(!c.check_and_insert("", "UID-1", b"hello"));
        assert!(!c.check_and_insert("", "UID-1", b"world"));
        assert_eq!(c.hits(), 0);
    }

    #[test]
    fn expired_entry_is_not_duplicate() {
        // Use a real 10ms window and sleep past it to exercise the TTL
        // expiry branch (not the zero-window short-circuit).
        let c = DedupCache::new(Duration::from_millis(10), 16);
        assert!(!c.check_and_insert("", "UID-1", b"hello"));
        std::thread::sleep(Duration::from_millis(20));
        assert!(!c.check_and_insert("", "UID-1", b"hello"));
        assert_eq!(c.hits(), 0);
    }

    #[test]
    fn lru_eviction_drops_oldest() {
        let c = cache(3600, 2);
        assert!(!c.check_and_insert("", "U1", b"a"));
        assert!(!c.check_and_insert("", "U2", b"b"));
        assert!(!c.check_and_insert("", "U3", b"c")); // evicts U1
        assert_eq!(c.len(), 2);
        // U1 was evicted — re-insertion is not a duplicate.
        assert!(!c.check_and_insert("", "U1", b"a"));
    }

    #[test]
    fn from_secs_zero_returns_none() {
        assert!(DedupCache::from_secs(0, 100).is_none());
        assert!(DedupCache::from_secs(60, 100).is_some());
    }

    #[test]
    fn callback_fires_on_duplicate() {
        let counter = Arc::new(AtomicU64::new(0));
        let mut c = cache(60, 16);
        let cc = Arc::clone(&counter);
        c.set_on_duplicate(Arc::new(move || {
            let _ = cc.fetch_add(1, Ordering::Relaxed);
        }));
        assert!(!c.check_and_insert("", "U", b"x"));
        assert!(c.check_and_insert("", "U", b"x"));
        assert!(c.check_and_insert("", "U", b"x"));
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn on_insert_callback_receives_len() {
        let last_len = Arc::new(AtomicU64::new(0));
        let mut c = cache(60, 16);
        let ll = Arc::clone(&last_len);
        c.set_on_insert(Arc::new(move |len| {
            ll.store(len as u64, Ordering::Relaxed);
        }));
        assert!(!c.check_and_insert("", "U1", b"x"));
        assert_eq!(last_len.load(Ordering::Relaxed), 1);
        assert!(!c.check_and_insert("", "U2", b"y"));
        assert_eq!(last_len.load(Ordering::Relaxed), 2);
        // Duplicate should NOT fire on_insert.
        assert!(c.check_and_insert("", "U1", b"x"));
        assert_eq!(last_len.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn check_payload_extracts_cot_attrs() {
        let c = cache(60, 16);
        let xml = br#"<event uid="ALPHA" time="2024-01-01T00:00:00Z" type="a-f-G"/>"#;
        assert!(!c.check_payload("", xml));
        assert!(c.check_payload("", xml));
    }

    #[test]
    fn check_payload_dedupes_protobuf_binary() {
        // Non-CoT binary (protobuf-style) payload: no uid/time attrs.
        // With content-hash fallback, the second arrival is suppressed.
        let c = cache(60, 16);
        let payload: &[u8] = &[
            0x0a, 0x05, b'h', b'e', b'l', b'l', b'o', 0x10, 0x2a, 0x18, 0xff, 0x01,
        ];
        assert!(!c.check_payload("", payload));
        assert!(c.check_payload("", payload));
        assert_eq!(c.hits(), 1);
    }

    #[test]
    fn check_payload_distinct_binary_passes_through() {
        let c = cache(60, 16);
        let a: &[u8] = &[0x0a, 0x01, 0x41];
        let b: &[u8] = &[0x0a, 0x01, 0x42];
        assert!(!c.check_payload("", a));
        assert!(!c.check_payload("", b));
        assert_eq!(c.hits(), 0);
    }

    // ----- Tenant isolation regression tests (#722) -------------------

    #[test]
    fn different_tenants_same_payload_pass_independently() {
        // The attack model: tenant B sends a byte-identical message to
        // one tenant A just sent. With isolation (default), B's send
        // MUST be admitted — otherwise B has confirmed A sent exactly
        // this payload.
        let c = cache(60, 16);
        assert!(!c.check_and_insert("tenant-a", "UID-1", b"hello"));
        assert!(!c.check_and_insert("tenant-b", "UID-1", b"hello"));
        assert_eq!(c.hits(), 0);
    }

    #[test]
    fn same_tenant_same_payload_still_deduped() {
        // Intra-tenant dedup MUST still work — that is the whole point.
        let c = cache(60, 16);
        assert!(!c.check_and_insert("tenant-a", "UID-1", b"hello"));
        assert!(c.check_and_insert("tenant-a", "UID-1", b"hello"));
        assert_eq!(c.hits(), 1);
    }

    #[test]
    fn cross_tenant_mode_suppresses_across_tenants() {
        // With the explicit opt-in, pre-#722 behaviour is preserved:
        // tenant B's byte-identical resend after tenant A is suppressed.
        let c = DedupCache::new(Duration::from_secs(60), 16).with_cross_tenant(true);
        assert!(c.is_cross_tenant());
        assert!(!c.check_and_insert("tenant-a", "UID-1", b"hello"));
        assert!(c.check_and_insert("tenant-b", "UID-1", b"hello"));
        assert_eq!(c.hits(), 1);
    }

    #[test]
    fn missing_tenant_treated_as_empty() {
        // Clients without an Organization field pass "" on the hot
        // path. Two "" senders of the same payload collide, which is
        // the pre-tenant behaviour and the correct fallback.
        let c = cache(60, 16);
        assert!(!c.check_and_insert("", "UID-1", b"hello"));
        assert!(c.check_and_insert("", "UID-1", b"hello"));
        assert_eq!(c.hits(), 1);
    }

    #[test]
    fn tenant_affects_check_payload_too() {
        // The convenience wrapper honours the tenant boundary for CoT.
        let c = cache(60, 16);
        let xml = br#"<event uid="ALPHA" time="2024-01-01T00:00:00Z" type="a-f-G"/>"#;
        assert!(!c.check_payload("tenant-a", xml));
        assert!(!c.check_payload("tenant-b", xml));
        assert!(c.check_payload("tenant-a", xml));
        assert_eq!(c.hits(), 1);
    }
}
