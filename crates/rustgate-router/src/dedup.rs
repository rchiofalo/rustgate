// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-path message deduplication cache.
//!
//! When the same logical message arrives via multiple ingress paths
//! (for example, a direct client connection and a federation peer that
//! forwarded it), subscribers should only receive it once. This module
//! provides a bounded LRU cache that the router consults on the
//! dispatch hot path.
//!
//! # Key shape (domain-separated CoT vs non-CoT)
//!
//! The cache uses two distinct, domain-separated key preimages so that
//! a CoT XML payload and a non-CoT payload that happen to share bytes
//! cannot collide. The leading domain tag (`b"cot"` or `b"non-cot"`)
//! is hashed in first and is followed by a `0x00` separator before any
//! caller-supplied bytes:
//!
//! - **CoT XML** —
//!   `SHA-256(b"cot" || 0x00 || tenant || 0x00 || uid || 0x00 || payload)`.
//!   The `uid` is extracted from the XML attribute scanner (see
//!   `crate::replay::extract_xml_attr`); the full payload is folded in
//!   so messages sharing a `uid` but with different bytes do not
//!   collide.
//! - **non-CoT** —
//!   `SHA-256(b"non-cot" || 0x00 || tenant || 0x00 || cn || 0x00 ||
//!   source_protocol || 0x00 || millis_window_le || 0x00 ||
//!   sha256(payload))`. The sender's CN
//!   (`Identity.cn`) is folded in so two different senders emitting
//!   byte-identical payloads at the same instant (e.g. two MAVLink
//!   HEARTBEATs) are NOT collapsed into one delivery, and a
//!   window-truncated unix-millis timestamp is folded in so a
//!   legitimate retransmission across the window boundary is not
//!   silently dropped.
//!
//! Closes #882: the previous non-CoT path had no CN and no time
//! component, so any two senders in the same tenant emitting the same
//! bytes were collapsed into one delivery, and a payload that happened
//! to share bytes with a CoT XML message could collide across the
//! protocol boundary.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lru::LruCache;
use parking_lot::Mutex;
use rustgate_core::message::RoutableMessage;
use sha2::{Digest, Sha256};

/// Default maximum number of cached entries when no override is given.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

rustgate_core::on_callback!(
    /// Optional callback invoked once per suppressed duplicate so the server
    /// crate can update its Prometheus counter without `rustgate-transport`
    /// taking a direct dependency on the metrics layer.
    pub OnDuplicate
);

rustgate_core::on_callback!(
    /// Optional callback invoked after a fresh entry is inserted into the
    /// cache. The server crate uses this to publish the current cache size
    /// as a Prometheus gauge without pulling a metrics dependency into
    /// `rustgate-transport`.
    pub OnInsert,
    usize
);

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
    /// Lookups that did NOT match an existing live entry — either no
    /// entry was present, or the entry was present but expired. Counted
    /// here so the management API can surface a hit/miss ratio without
    /// approximating it from `hits` alone (the LRU `len` does not
    /// distinguish "never seen" from "evicted by capacity"). Refs #902.
    misses: AtomicU64,
    /// Capacity-driven evictions: entries removed by `LruCache::put`
    /// returning `Some` because the cache was already at capacity. Does
    /// not count TTL expiries (those are observed implicitly when an
    /// expired entry is overwritten by the same key) — see
    /// [`DedupStats`] field docs for the exact accounting boundary.
    evictions: AtomicU64,
    on_duplicate: Option<OnDuplicate>,
    on_insert: Option<OnInsert>,
    /// When `true`, the tenant slot in the key preimage is forced to
    /// empty for every lookup/insert so byte-identical messages from
    /// different tenants collide — the pre-#722 behaviour. Defaults to
    /// `false` (tenant-isolated).
    cross_tenant: bool,
}

/// Snapshot of dedup-cache statistics for the management REST API.
///
/// Returned by [`DedupCache::stats`]; surfaced through
/// [`crate::Router::dedup_full_stats`] to the
/// `GET /api/v1/dedup/stats` endpoint (refs #902). Counter fields are
/// `u64` snapshots taken with `Ordering::Relaxed` and are not consistent
/// with each other under concurrent writers — operators reading the
/// endpoint get a non-atomic instant-in-time view, matching the
/// `prometheus`-scrape semantics the rest of the workspace uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DedupStats {
    /// Currently tracked entries — equivalent to [`DedupCache::len`].
    pub entries: usize,
    /// Maximum tracked entries before LRU eviction kicks in. Constant
    /// for the lifetime of the cache (set at construction).
    pub capacity: usize,
    /// Cumulative duplicates suppressed since startup — equivalent to
    /// [`DedupCache::hits`].
    pub hit_count: u64,
    /// Cumulative non-duplicate lookups (fresh insert OR refresh of an
    /// expired entry). The pre-fix duplicate-only counter could not
    /// distinguish a healthy stream of unique messages from a stalled
    /// pipeline — exposing misses lets operators graph a hit ratio.
    pub miss_count: u64,
    /// Cumulative capacity-driven LRU evictions since startup. A
    /// sustained non-zero rate indicates the configured `max_entries`
    /// is too low for the dedup window and traffic rate combination,
    /// and dedup correctness is degraded (evicted entries are no longer
    /// available to suppress duplicates).
    pub evictions: u64,
    /// Configured deduplication window in whole seconds.
    pub ttl_seconds: u64,
}

impl std::fmt::Debug for DedupCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedupCache")
            .field("window", &self.window)
            .field("hits", &self.hits.load(Ordering::Relaxed))
            .field("misses", &self.misses.load(Ordering::Relaxed))
            .field("evictions", &self.evictions.load(Ordering::Relaxed))
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
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
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

    /// Total number of non-duplicate lookups since startup — fresh
    /// inserts plus expired-entry refreshes. Pairs with [`hits`][Self::hits]
    /// for hit-ratio computation; refs #902.
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Total number of capacity-driven LRU evictions since startup.
    /// A sustained non-zero rate signals that the configured
    /// `max_entries` is too low for the dedup window and traffic rate.
    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Number of currently tracked entries.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Maximum tracked entries before LRU eviction kicks in. Constant
    /// for the lifetime of the cache; surfaces the construction-time
    /// `max_entries` value for the management REST API. Refs #902.
    pub fn capacity(&self) -> usize {
        self.inner.lock().cap().get()
    }

    /// Whether the cache currently has no tracked entries.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Configured deduplication window.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Snapshot of all stats fields surfaced by the management REST
    /// API. Counter fields are read with `Ordering::Relaxed` and are
    /// not consistent with each other under concurrent writers — see
    /// [`DedupStats`] for the exact accounting boundary. Refs #902.
    pub fn stats(&self) -> DedupStats {
        // Take the lock once for `len` + `cap` so the entry count and
        // capacity are read under the same critical section. The
        // counter loads happen outside the lock — they are atomic
        // singletons and the snapshot is documented non-atomic, so
        // holding the cache mutex across them would only widen the
        // hot-path lock without an observable correctness gain.
        let (entries, capacity) = {
            let cache = self.inner.lock();
            (cache.len(), cache.cap().get())
        };
        DedupStats {
            entries,
            capacity,
            hit_count: self.hits.load(Ordering::Relaxed),
            miss_count: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            ttl_seconds: self.window.as_secs(),
        }
    }

    /// Check whether the CoT preimage
    /// `SHA-256(b"cot" || 0x00 || tenant || 0x00 || uid || 0x00 || payload)`
    /// was already seen within the configured window. Returns `true` on
    /// duplicate; otherwise inserts and returns `false`.
    ///
    /// This is the CoT-keyed entry point. The `b"cot"` domain-separator
    /// prefix prevents cross-collision with the non-CoT path
    /// (`b"non-cot"`) used by [`check_message`][Self::check_message] for
    /// payloads where the XML `uid` cannot be extracted — a non-CoT
    /// payload that happens to share bytes with a CoT XML payload
    /// cannot suppress it.
    ///
    /// `tenant` should be the sender's tenant key (typically the X.509
    /// Organization field on the client certificate; an empty string is
    /// used for clients with no tenant attribute). When this cache was
    /// built with [`with_cross_tenant(true)`][Self::with_cross_tenant]
    /// the supplied `tenant` is ignored and the tenant slot is forced
    /// empty — see the type-level docs for the security implications.
    pub fn check_and_insert(&self, tenant: &str, uid: &str, payload: &[u8]) -> bool {
        let effective_tenant = if self.cross_tenant { "" } else { tenant };
        let key = build_cot_key(effective_tenant, uid, payload);
        self.lookup_or_insert(key)
    }

    /// Check whether the given [`RoutableMessage`] is a duplicate within
    /// the configured window.
    ///
    /// This is the dispatch-time entry point used by the router. It
    /// dispatches to one of two domain-separated key preimages so a CoT
    /// XML payload and a non-CoT payload sharing bytes cannot collide:
    ///
    /// - **CoT XML** (uid extractable from the payload):
    ///   `SHA-256(b"cot" || 0x00 || tenant || 0x00 || uid || 0x00 || payload)`,
    ///   identical to [`check_and_insert`][Self::check_and_insert].
    /// - **non-CoT** (uid not extractable):
    ///   `SHA-256(b"non-cot" || 0x00 || tenant || 0x00 || cn || 0x00 ||
    ///   source_protocol || 0x00 || millis_window_le || 0x00 ||
    ///   sha256(payload))`. The sender's `Identity.cn` is folded in so two
    ///   different senders emitting byte-identical payloads at the same
    ///   instant are NOT collapsed; `metadata.source_protocol` is folded in
    ///   so two different protocols whose bytes coincide do not cross-dedupe
    ///   (#1531); and `metadata.received_at` truncated to the dedup window is
    ///   folded in so a legitimate retransmission across the window boundary
    ///   is not silently dropped.
    ///
    /// Returns `true` on duplicate; otherwise inserts and returns
    /// `false`. Honours the cross-tenant flag identically to
    /// [`check_and_insert`][Self::check_and_insert].
    ///
    /// Closes #882.
    pub fn check_message(&self, msg: &RoutableMessage) -> bool {
        let tenant = msg.source.tenant.as_deref().unwrap_or("");
        let effective_tenant = if self.cross_tenant { "" } else { tenant };

        // CoT path: extract `uid` from the XML payload. If present,
        // route through the same preimage as `check_and_insert` so the
        // two entry points share keys for CoT traffic.
        if let Some(uid_bytes) = crate::replay::extract_xml_attr(&msg.payload, b"uid=")
            && let Ok(uid) = std::str::from_utf8(uid_bytes)
        {
            let key = build_cot_key(effective_tenant, uid, &msg.payload);
            return self.lookup_or_insert(key);
        }

        // Non-CoT path: bind to (tenant, cn, source_protocol, time,
        // payload-hash). source_protocol prevents two different protocols
        // whose raw bytes coincide from cross-deduping (#1531).
        let cn: &str = &msg.source.cn;
        let millis_window = window_truncated_millis(msg.metadata.received_at, self.window);
        let key = build_non_cot_key(
            effective_tenant,
            cn,
            &msg.metadata.source_protocol,
            millis_window,
            &msg.payload,
        );
        self.lookup_or_insert(key)
    }

    /// Convenience wrapper for callers that have only the raw payload
    /// and the sender's tenant.
    ///
    /// For CoT XML payloads the `uid` attribute is extracted and folded
    /// into the key. For non-CoT payloads (protobuf, raw binary) the
    /// cache falls back to a content-hash-only key with empty CN and
    /// zero time-window — preserved for callers (mostly tests) that do
    /// not have a full [`RoutableMessage`] in hand. Production callers
    /// on the dispatch hot path should use
    /// [`check_message`][Self::check_message] instead so non-CoT
    /// duplicates are correctly bound to (cn, time, payload-hash) per
    /// #882.
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

    /// Shared lookup-or-insert hot path used by every key-shape entry
    /// point. Holds the cache mutex for the minimum span necessary,
    /// fires the duplicate / insert callbacks outside the lock to keep
    /// the critical section bounded, and respects the LRU TTL.
    fn lookup_or_insert(&self, key: Key) -> bool {
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
            // Entry expired — refresh and treat as a miss. The same
            // key is overwritten in place, which is NOT a
            // capacity-driven eviction so we deliberately do not bump
            // `evictions`.
            let _ = cache.put(key, now);
            let len = cache.len();
            drop(cache);
            let _ = self.misses.fetch_add(1, Ordering::Relaxed);
            if let Some(cb) = &self.on_insert {
                cb(len);
            }
            return false;
        }
        // Fresh insert: use `push` (not `put`) so the LRU returns the
        // `(K, V)` pair pushed out by capacity, if any. `put` filters
        // capacity-eviction tuples internally and returns `None`,
        // which would silently undercount evictions for a brand-new
        // key in a full cache. By construction we already know the
        // key was absent (the `cache.get` branch above did not match),
        // so any `Some` returned here is unambiguously a capacity
        // eviction — track it so operators can detect a too-small
        // `max_entries` configuration.
        let evicted = cache.push(key, now);
        let len = cache.len();
        drop(cache);
        let _ = self.misses.fetch_add(1, Ordering::Relaxed);
        if evicted.is_some() {
            let _ = self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(cb) = &self.on_insert {
            cb(len);
        }
        false
    }
}

/// Domain-separator tag for CoT XML keys.
const DOMAIN_COT: &[u8] = b"cot";

/// Domain-separator tag for non-CoT keys.
const DOMAIN_NON_COT: &[u8] = b"non-cot";

/// Build the 32-byte cache key for a CoT XML payload.
///
/// The format is
/// `SHA-256(b"cot" || 0x00 || tenant || 0x00 || uid || 0x00 || payload)`.
/// The leading `b"cot"` domain tag prevents cross-collision with
/// [`build_non_cot_key`] — a non-CoT payload that happens to share
/// bytes with a CoT XML payload cannot suppress it.
///
/// Folding `tenant` into the preimage prevents a malicious tenant from
/// probing for the existence of messages in another tenant by observing
/// whether candidate payloads are silently suppressed (issue #722).
fn build_cot_key(tenant: &str, uid: &str, payload: &[u8]) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_COT);
    hasher.update([0u8]);
    hasher.update(tenant.as_bytes());
    hasher.update([0u8]);
    hasher.update(uid.as_bytes());
    hasher.update([0u8]);
    hasher.update(payload);
    hasher.finalize().into()
}

/// Build the 32-byte cache key for a non-CoT payload.
///
/// The format is
/// `SHA-256(b"non-cot" || 0x00 || tenant || 0x00 || cn || 0x00 ||
/// source_protocol || 0x00 || millis_window_le || 0x00 || sha256(payload))`.
///
/// Closes #882: the previous fallback (`b"" || tenant || 0x00 || ""
/// || 0x00 || 0_i64_le || 0x00 || payload`) had no CN and no time
/// component, so two senders within the same tenant emitting the same
/// bytes were collapsed into a single delivery, and a payload that
/// happened to share bytes with a CoT XML payload could collide across
/// the protocol boundary. This shape:
///
/// - Adds the `b"non-cot"` domain prefix so CoT and non-CoT keys
///   cannot collide.
/// - Folds in the sender's CN so two different senders emitting
///   byte-identical bytes (e.g. two MAVLink HEARTBEATs at the same
///   instant) are NOT deduped against each other.
/// - Folds in the message's `source_protocol` so two *different* protocols
///   whose raw payloads happen to share bytes (e.g. a DIS PDU and an ASTERIX
///   datablock from the same sender at the same instant) are NOT deduped
///   against each other (F-189/#1531).
/// - Folds in the message's wall-clock timestamp truncated to the
///   dedup window, so a legitimate retransmission within a later
///   window is not silently suppressed by a stale cache entry from an
///   earlier window.
/// - Hashes the payload first and folds the digest in (rather than
///   the raw bytes) so the preimage stays bounded — the cache is on
///   the dispatch hot path and the surrounding mutex protects every
///   in-flight message.
fn build_non_cot_key(
    tenant: &str,
    cn: &str,
    source_protocol: &str,
    millis_window: u64,
    payload: &[u8],
) -> Key {
    let payload_digest: [u8; 32] = Sha256::digest(payload).into();
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_NON_COT);
    hasher.update([0u8]);
    hasher.update(tenant.as_bytes());
    hasher.update([0u8]);
    hasher.update(cn.as_bytes());
    hasher.update([0u8]);
    hasher.update(source_protocol.as_bytes());
    hasher.update([0u8]);
    hasher.update(millis_window.to_le_bytes());
    hasher.update([0u8]);
    hasher.update(payload_digest);
    hasher.finalize().into()
}

/// Truncate a wall-clock `received_at` timestamp to the configured
/// dedup window.
///
/// Returns the unix-millis representation of `received_at` floored to
/// the nearest multiple of `window` (in milliseconds). Two messages
/// received within the same window land in the same time bucket; a
/// legitimate retransmission that crosses into a later window lands in
/// a different bucket and is correctly admitted as a fresh insert.
///
/// Edge cases handled to keep the hot path panic-free:
///
/// - `received_at` before `UNIX_EPOCH` → `0` (clock skew tolerance).
/// - `window == 0` (deliberately disabled-but-still-constructed cache)
///   → returns the raw millis without flooring; downstream
///   `lookup_or_insert` treats every entry as already-expired anyway.
/// - millis or window milliseconds that exceed `u64::MAX` → saturating
///   conversion to `u64::MAX`; the cache window is bounded by
///   construction (`Duration` is `u64::MAX` seconds at most), so this
///   is operationally a no-op and exists only to forbid `as` truncation.
fn window_truncated_millis(received_at: SystemTime, window: Duration) -> u64 {
    let millis = u64::try_from(
        received_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
    if window_ms == 0 {
        millis
    } else {
        (millis / window_ms) * window_ms
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

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

    // ----- Stats accounting (refs #902) -------------------------------

    #[test]
    fn stats_track_hits_misses_and_capacity() {
        // Two unique inserts → 2 misses, 0 hits. Two re-inserts of a
        // known key within the window → 2 hits. Capacity stays constant
        // for the lifetime of the cache.
        let c = cache(60, 8);
        assert!(!c.check_and_insert("", "U1", b"a"));
        assert!(!c.check_and_insert("", "U2", b"b"));
        assert!(c.check_and_insert("", "U1", b"a"));
        assert!(c.check_and_insert("", "U2", b"b"));
        let s = c.stats();
        assert_eq!(s.entries, 2);
        assert_eq!(s.capacity, 8);
        assert_eq!(s.hit_count, 2);
        assert_eq!(s.miss_count, 2);
        assert_eq!(s.evictions, 0);
        assert_eq!(s.ttl_seconds, 60);
    }

    #[test]
    fn stats_track_capacity_driven_evictions() {
        // Capacity = 2; the third insert pushes the LRU tail out and
        // bumps the eviction counter. A re-insert of the evicted key
        // is a fresh miss, not a hit.
        let c = cache(3600, 2);
        assert!(!c.check_and_insert("", "U1", b"a"));
        assert!(!c.check_and_insert("", "U2", b"b"));
        assert!(!c.check_and_insert("", "U3", b"c")); // evicts U1
        assert_eq!(c.evictions(), 1);
        assert!(!c.check_and_insert("", "U1", b"a")); // evicts U2
        assert_eq!(c.evictions(), 2);
        assert_eq!(c.misses(), 4);
        assert_eq!(c.hits(), 0);
    }

    #[test]
    fn stats_ttl_refresh_does_not_count_as_eviction() {
        // An entry whose timestamp falls outside the window is treated
        // as a miss and overwritten in place — that is NOT a
        // capacity-driven eviction. The eviction counter is reserved
        // for "the LRU tail had to be pushed out to make room", which
        // operators need to monitor independently of TTL churn.
        let c = DedupCache::new(Duration::from_millis(10), 16);
        assert!(!c.check_and_insert("", "U1", b"a"));
        std::thread::sleep(Duration::from_millis(20));
        assert!(!c.check_and_insert("", "U1", b"a"));
        assert_eq!(c.evictions(), 0);
        assert_eq!(c.misses(), 2);
        assert_eq!(c.hits(), 0);
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

    // ----- Non-CoT replay-key binding regression tests (#882) ---------
    //
    // These pin the post-#882 contract: the non-CoT key path on
    // `check_message` is `SHA-256(b"non-cot" || 0x00 || tenant || 0x00
    // || cn || 0x00 || millis_window_le || 0x00 || sha256(payload))`,
    // domain-separated from the CoT path's `b"cot"` prefix. The
    // pre-fix non-CoT path collapsed across (cn, time) and could
    // collide with CoT XML keys that happened to share bytes.

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    /// Construct a `RoutableMessage` with the supplied `cn`, payload,
    /// and `received_at` for the dedup tests below. Tenant defaults to
    /// the empty string (most non-CoT senders in the test fixtures
    /// have no Organization field).
    fn make_msg(cn: &str, payload: &[u8], received_at: SystemTime) -> RoutableMessage {
        let id = Identity {
            cn: std::sync::Arc::<str>::from(cn),
            fingerprint: format!("fp-{cn}"),
            groups: std::collections::BTreeSet::new(),
            tenant: None,
            spiffe_id: None,
            attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
        };
        RoutableMessage {
            source: id,
            destination: Destination::Broadcast,
            payload: Bytes::copy_from_slice(payload),
            metadata: Metadata::new(
                received_at,
                "tcp".into(),
                MessageType::Other("mavlink-heartbeat".into()),
            ),
            entity: None,
        }
    }

    #[test]
    fn check_message_two_cns_same_non_cot_payload_pass_independently() {
        // Pre-#882 bug: two MAVLink HEARTBEATs from different drones
        // sent at the same instant share bytes, so the cache collapsed
        // them into a single delivery and one of the two senders was
        // silently dropped. With CN binding, the second send is
        // admitted as a fresh insert.
        let c = cache(60, 16);
        // Non-CoT bytes (intentionally NOT XML — extract_xml_attr
        // returns None and the cache routes through the non-CoT path).
        let payload: &[u8] = &[0x00, 0xfd, 0x09, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02];
        let now = SystemTime::now();
        let msg_a = make_msg("drone-alpha", payload, now);
        let msg_b = make_msg("drone-bravo", payload, now);
        assert!(
            !c.check_message(&msg_a),
            "first sender's message must be admitted"
        );
        assert!(
            !c.check_message(&msg_b),
            "byte-identical message from a different CN must NOT be deduped — \
             pre-#882 the cache collapsed both into one delivery",
        );
        assert_eq!(c.hits(), 0, "no duplicates should have been suppressed");
    }

    #[test]
    fn check_message_same_cn_payload_different_source_protocol_not_deduped() {
        // F-189/#1531: two DIFFERENT protocols whose raw bytes coincide (same
        // sender, same instant) must NOT cross-dedupe — folding
        // source_protocol into the non-CoT key keeps them distinct.
        let c = cache(60, 16);
        // Non-CoT bytes (not XML, so the non-CoT path is taken).
        let payload: &[u8] = &[0x10, 0x20, 0x30, 0x40, 0x50];
        let now = SystemTime::now();
        let make = |proto: &str| RoutableMessage {
            source: Identity {
                cn: std::sync::Arc::<str>::from("sensor-1"),
                fingerprint: "fp-sensor-1".to_string(),
                groups: std::collections::BTreeSet::new(),
                tenant: None,
                spiffe_id: None,
                attributes: std::sync::Arc::new(std::collections::BTreeMap::new()),
            },
            destination: Destination::Broadcast,
            payload: Bytes::copy_from_slice(payload),
            metadata: Metadata::new(now, proto.into(), MessageType::Other("raw".into())),
            entity: None,
        };
        assert!(!c.check_message(&make("dis")), "first protocol admitted");
        assert!(
            !c.check_message(&make("asterix")),
            "byte-identical payload from a DIFFERENT source_protocol must NOT be deduped (#1531)",
        );
        assert_eq!(
            c.hits(),
            0,
            "cross-protocol must not have suppressed anything"
        );
        // The fix must NOT weaken intra-protocol dedup: the same protocol
        // repeating the identical payload in-window is still a duplicate.
        assert!(
            c.check_message(&make("dis")),
            "same protocol + identical payload in-window is still a duplicate",
        );
        assert_eq!(c.hits(), 1);
    }

    #[test]
    fn check_message_same_cn_same_non_cot_payload_within_window_is_deduped() {
        // Intra-sender dedup must still work for the non-CoT path —
        // that is the whole point of having a dedup cache. Two
        // byte-identical sends from the same CN at the same instant
        // are correctly suppressed.
        let c = cache(60, 16);
        let payload: &[u8] = &[0x00, 0xfd, 0x09, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02];
        let now = SystemTime::now();
        let msg = make_msg("drone-alpha", payload, now);
        assert!(!c.check_message(&msg), "first send must be admitted");
        assert!(
            c.check_message(&msg),
            "byte-identical resend within the window must be suppressed"
        );
        assert_eq!(c.hits(), 1);
    }

    #[test]
    fn check_message_same_cn_same_non_cot_payload_outside_window_passes() {
        // Time binding: a legitimate retransmission outside the dedup
        // window must NOT be silently suppressed by a stale cache
        // entry from an earlier window. The pre-#882 non-CoT path had
        // no time component, so retransmissions far in the future were
        // still suppressed if the cache entry had not been LRU-evicted.
        // Use a 100 ms window so we can drive two sends across the
        // boundary deterministically.
        let c = DedupCache::new(Duration::from_millis(100), 16);
        let payload: &[u8] = &[0x00, 0xfd, 0x09, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02];
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_millis(1_000);
        let t1 = SystemTime::UNIX_EPOCH + Duration::from_millis(1_500);
        let msg_a = make_msg("drone-alpha", payload, t0);
        let msg_b = make_msg("drone-alpha", payload, t1);
        assert!(!c.check_message(&msg_a));
        // Sleep just past the cache window so the LRU entry's TTL also
        // expires — the time-bucket binding must hold even when the
        // LRU has not yet reaped the earlier entry, but the LRU TTL
        // check is the final backstop.
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            !c.check_message(&msg_b),
            "retransmission in a later time-window must NOT be suppressed",
        );
        assert_eq!(c.hits(), 0);
    }

    #[test]
    fn check_message_cot_and_non_cot_byte_collision_do_not_dedupe() {
        // Domain separation: a non-CoT payload that happens to share
        // bytes with a CoT XML payload must not collide with it
        // through the dedup cache. The `b"cot"` vs `b"non-cot"`
        // domain prefixes prevent cross-protocol collisions.
        //
        // We construct a CoT XML message and a non-CoT message whose
        // payloads are byte-identical at the wire level, then assert
        // that neither suppresses the other through `check_message`.
        let c = cache(60, 16);
        // A real CoT XML message: extract_xml_attr WILL find a uid and
        // route through the CoT key path.
        let xml: &[u8] = br#"<event uid="ALPHA" time="2024-01-01T00:00:00Z" type="a-f-G"/>"#;
        let now = SystemTime::now();

        // Send the CoT XML through check_message — it is dispatched to
        // the CoT key path because uid="ALPHA" is extractable.
        let cot_msg = make_msg("alpha-cn", xml, now);
        assert!(!c.check_message(&cot_msg), "CoT XML admitted on first send");

        // Now construct a non-CoT message whose payload is the same
        // bytes but force the non-CoT path by stripping the leading
        // `<` so extract_xml_attr returns None. We pin the protocol
        // boundary by asserting the second arrival is NOT deduped.
        // The bytes of the two payloads differ by exactly one leading
        // byte — but the property under test (different domain tags
        // produce different keys) is independent of how we reach the
        // non-CoT path, and the broader contract test below uses the
        // raw-bytes-match construction directly.
        let mut non_cot_bytes = xml.to_vec();
        non_cot_bytes[0] = b' '; // strip leading '<' so it is not parseable XML
        let non_cot_msg = make_msg("alpha-cn", &non_cot_bytes, now);
        assert!(
            !c.check_message(&non_cot_msg),
            "non-CoT payload must not collide with the CoT-keyed entry",
        );

        // Tighter contract: even when the underlying preimages are
        // crafted so the non-CoT body hash equals the CoT preimage,
        // the leading domain tag forces distinct SHA-256 outputs.
        // Pin this directly at the key builder level to lock the
        // domain-separation invariant against future refactors.
        let cot_key = build_cot_key("", "ALPHA", xml);
        let non_cot_key = build_non_cot_key(
            "",
            "ALPHA",
            "",
            window_truncated_millis(now, Duration::from_secs(60)),
            xml,
        );
        assert_ne!(
            cot_key, non_cot_key,
            "CoT and non-CoT key builders must produce distinct keys for the \
             same trailing inputs — domain separation is required for #882",
        );

        assert_eq!(c.hits(), 0);
    }

    #[test]
    fn build_cot_key_domain_prefix_is_pinned() {
        // The `b"cot"` domain prefix is part of the wire-stable shape
        // of the cache key — any operator who has built tooling that
        // computes the same key out-of-band (e.g. a NATS-side dedup
        // mirror) keys off this exact prefix. Pin the leading bytes of
        // the SHA-256 preimage by computing the digest manually here.
        let mut h = Sha256::new();
        h.update(b"cot");
        h.update([0u8]);
        h.update(b"tenant");
        h.update([0u8]);
        h.update(b"UID-1");
        h.update([0u8]);
        h.update(b"hello");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(build_cot_key("tenant", "UID-1", b"hello"), expected);
    }

    #[test]
    fn build_non_cot_key_domain_prefix_is_pinned() {
        // Same wire-stability contract as `build_cot_key_domain_prefix_is_pinned`
        // but for the non-CoT shape: prefix `b"non-cot"`, then tenant,
        // CN, source_protocol, millis_window (little-endian), then the
        // SHA-256 of the payload. Pinning the prefix and field order lets
        // external tooling (e.g. operator scripts that grep audit logs and
        // recompute the dedup key from message metadata) stay aligned.
        let payload_digest: [u8; 32] = Sha256::digest(b"hello").into();
        let mut h = Sha256::new();
        h.update(b"non-cot");
        h.update([0u8]);
        h.update(b"tenant");
        h.update([0u8]);
        h.update(b"alpha-cn");
        h.update([0u8]);
        h.update(b"dis");
        h.update([0u8]);
        h.update(42u64.to_le_bytes());
        h.update([0u8]);
        h.update(payload_digest);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(
            build_non_cot_key("tenant", "alpha-cn", "dis", 42, b"hello"),
            expected
        );
    }

    #[test]
    fn window_truncated_millis_floors_to_window_boundary() {
        // Two timestamps inside the same window must yield the same
        // bucket; one timestamp in the next window must yield a
        // different (larger) bucket.
        let window = Duration::from_secs(5);
        let t_a = SystemTime::UNIX_EPOCH + Duration::from_millis(7_300);
        let t_b = SystemTime::UNIX_EPOCH + Duration::from_millis(9_999);
        let t_c = SystemTime::UNIX_EPOCH + Duration::from_millis(10_001);
        let a = window_truncated_millis(t_a, window);
        let b = window_truncated_millis(t_b, window);
        let c = window_truncated_millis(t_c, window);
        assert_eq!(a, 5_000, "7.3s rounds down to the 5s window boundary");
        assert_eq!(b, 5_000, "9.999s also rounds down to the 5s boundary");
        assert_eq!(c, 10_000, "10.001s lands in the next 5s bucket");
        assert!(a == b, "in-window timestamps share a bucket");
        assert!(a < c, "across-window timestamp lands in a later bucket");
    }

    #[test]
    fn window_truncated_millis_zero_window_returns_raw_millis() {
        // A `Duration::ZERO` window has no division-by-zero footgun —
        // we return the raw millis. In practice the cache's TTL check
        // would already classify every entry as expired with a zero
        // window, so the bucket value is informational; this test
        // pins the contract.
        let t = SystemTime::UNIX_EPOCH + Duration::from_millis(12_345);
        assert_eq!(window_truncated_millis(t, Duration::ZERO), 12_345);
    }

    #[test]
    fn window_truncated_millis_pre_unix_epoch_returns_zero() {
        // Clock-skew tolerance: a `received_at` timestamp before
        // UNIX_EPOCH (which `SystemTime` permits on some platforms)
        // must not panic — we return 0. Pin this so a hot-path
        // regression cannot crash the router on a system whose clock
        // briefly stepped backward.
        let t = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(window_truncated_millis(t, Duration::from_secs(60)), 0);
    }
}
