//! Cross-path message deduplication cache.
//!
//! When the same logical message arrives via multiple ingress paths
//! (for example, a direct client connection and a federation peer that
//! forwarded it), subscribers should only receive it once. This module
//! provides a bounded LRU cache, keyed by `(uid, time, sha256(payload))`,
//! that the router consults on the dispatch hot path.
//!
//! The content hash defends against UID/time collisions: two messages
//! that share a `(uid, time)` pair but have different payloads are
//! treated as distinct and both delivered.
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

/// Cache key combining `uid`, `time`, and a SHA-256 digest of the payload.
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
}

impl std::fmt::Debug for DedupCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedupCache")
            .field("window", &self.window)
            .field("hits", &self.hits.load(Ordering::Relaxed))
            .finish()
    }
}

impl DedupCache {
    /// Create a new dedup cache with the given dedup window and capacity.
    ///
    /// `max_entries` of zero is normalized to `1` since the underlying
    /// LRU implementation requires a non-zero capacity.
    pub fn new(window: Duration, max_entries: usize) -> Self {
        let cap = NonZeroUsize::new(max_entries.max(1)).unwrap_or(
            // Safe: 1 is always non-zero.
            #[allow(clippy::unwrap_used)]
            NonZeroUsize::new(1).expect("1 is non-zero"),
        );
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            window,
            hits: AtomicU64::new(0),
            on_duplicate: None,
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

    /// Install a callback fired once per suppressed duplicate.
    pub fn set_on_duplicate(&mut self, cb: OnDuplicate) {
        self.on_duplicate = Some(cb);
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

    /// Check whether `(uid, time, sha256(payload))` was already seen
    /// within the configured window. Returns `true` if it is a duplicate
    /// (and the caller should drop the message); otherwise inserts the
    /// key and returns `false`.
    pub fn check_and_insert(&self, uid: &str, time: i64, payload: &[u8]) -> bool {
        let key = build_key(uid, time, payload);
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
            return false;
        }
        let _ = cache.put(key, now);
        false
    }

    /// Convenience wrapper for callers that have only the raw payload.
    ///
    /// Extracts the CoT `uid` and `time` attributes from the payload and
    /// runs `check_and_insert`. Non-CoT payloads (where the attributes
    /// cannot be extracted) bypass dedup and return `false`.
    pub fn check_payload(&self, payload: &[u8]) -> bool {
        let (Some(uid), Some(time)) = (
            crate::replay::extract_xml_attr_pub(payload, b"uid="),
            crate::replay::extract_xml_attr_pub(payload, b"time="),
        ) else {
            return false;
        };
        let uid_s = match std::str::from_utf8(uid) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // We hash the time bytes alongside the digest, so the numeric
        // value passed in is informational only — use a stable hash of
        // the raw bytes via i64::from_ne_bytes when possible, otherwise 0.
        let time_key = stable_time_key(time);
        self.check_and_insert(uid_s, time_key, payload)
    }
}

/// Derive a stable i64 from the raw bytes of the `time` attribute.
///
/// CoT timestamps are typically ISO-8601 strings; we collapse them to a
/// 64-bit value via FNV-1a so the public API can stay numeric while still
/// being collision-resistant in combination with the SHA-256 of the
/// payload.
fn stable_time_key(time: &[u8]) -> i64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in time {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash as i64
}

fn build_key(uid: &str, time: i64, payload: &[u8]) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(uid.as_bytes());
    hasher.update([0u8]);
    hasher.update(time.to_le_bytes());
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
        assert!(!c.check_and_insert("UID-1", 100, b"hello"));
        assert!(c.check_and_insert("UID-1", 100, b"hello"));
        assert_eq!(c.hits(), 1);
    }

    #[test]
    fn different_payload_same_uid_time_passes() {
        let c = cache(60, 16);
        assert!(!c.check_and_insert("UID-1", 100, b"hello"));
        assert!(!c.check_and_insert("UID-1", 100, b"world"));
        assert_eq!(c.hits(), 0);
    }

    #[test]
    fn expired_entry_is_not_duplicate() {
        let c = DedupCache::new(Duration::from_millis(0), 16);
        assert!(!c.check_and_insert("UID-1", 100, b"hello"));
        // Zero-window means the previous entry is immediately stale.
        assert!(!c.check_and_insert("UID-1", 100, b"hello"));
    }

    #[test]
    fn lru_eviction_drops_oldest() {
        let c = cache(3600, 2);
        assert!(!c.check_and_insert("U1", 1, b"a"));
        assert!(!c.check_and_insert("U2", 2, b"b"));
        assert!(!c.check_and_insert("U3", 3, b"c")); // evicts U1
        assert_eq!(c.len(), 2);
        // U1 was evicted — re-insertion is not a duplicate.
        assert!(!c.check_and_insert("U1", 1, b"a"));
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
        assert!(!c.check_and_insert("U", 1, b"x"));
        assert!(c.check_and_insert("U", 1, b"x"));
        assert!(c.check_and_insert("U", 1, b"x"));
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn check_payload_extracts_cot_attrs() {
        let c = cache(60, 16);
        let xml = br#"<event uid="ALPHA" time="2024-01-01T00:00:00Z" type="a-f-G"/>"#;
        assert!(!c.check_payload(xml));
        assert!(c.check_payload(xml));
    }

    #[test]
    fn check_payload_bypasses_non_cot() {
        let c = cache(60, 16);
        assert!(!c.check_payload(b"not xml"));
        assert!(!c.check_payload(b"not xml"));
    }
}
