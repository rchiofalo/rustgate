// Copyright © 2026 Roberto Chiofalo.

//! Latest-state cache for position reports.
//!
//! Clients expect to receive the current situational awareness (SA) picture
//! on connect. This cache stores the most recent position event per CN and
//! replays them to newly connected sessions.
//!
//! ## TTL Semantics
//!
//! Each cached position may carry an optional TTL in its metadata:
//!
//! - **`ttl: None`** — the entry never expires by time. It is only evicted
//!   when the client disconnects ([`PositionCache::remove`]), a newer
//!   position replaces it, or the cache reaches capacity and the oldest
//!   entry is evicted.
//! - **`ttl: Some(duration)`** — the entry expires when
//!   `received_at + duration < now`. A `Duration::ZERO` TTL means the entry
//!   expires on the next check (any elapsed time > 0).
//! - Clock-backwards edge cases (e.g., NTP corrections) are treated as
//!   not-expired to avoid spurious eviction.
//!
//! ## Sweep Task
//!
//! [`PositionCache::start_sweep_task`] spawns a background `tokio` task that calls
//! [`PositionCache::sweep`] at a fixed interval (default: **15 seconds**).
//! The sweep removes all entries whose TTL has elapsed. Entries without a
//! TTL are never removed by the sweep — they persist until explicitly
//! removed or replaced.
//!
//! The sweep interval is independent of individual entry TTLs. An entry
//! with a 5-second TTL will not be removed until the next 15-second sweep runs,
//! but it will be excluded from [`PositionCache::get_all`] results
//! immediately (the `is_expired` check runs on read).
//!
//! ## Security Invariant — Pre-Obligation Storage
//!
//! Entries in this cache are the **pre-obligation** form of each
//! position event. The router stores positions *before* applying
//! data-plane authz obligations (`MaskPoint`, `MaskPayload`) so that
//! replay to newly connected sessions can re-evaluate the Send PEP
//! against the current policy and apply whatever masking rules are in
//! force at replay time. See `route_inner`'s cache-store ordering
//! comment in `router.rs` and the re-evaluation loop in
//! [`Router::replay_positions`].
//!
//! This design keeps the replay path responsive to post-ingest policy
//! tightening, but it means cached entries may contain classified
//! coordinates even when policy mandates they be masked on the wire.
//! Callers MUST:
//!
//! - Never serialize [`PositionCache`] contents to disk, forward them
//!   to federation / NATS / HTTP egress, or dump them via any
//!   diagnostic interface. Only [`Router::replay_positions`] is an
//!   authorized reader; it re-evaluates both Send and Receive PEPs and
//!   applies current-policy obligations before delivery.
//! - Treat the in-memory footprint as equivalent to the classification
//!   of the highest-classified traffic the process handles.
//!
//! [`Router::replay_positions`]: crate::Router::replay_positions

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use rustgate_core::masking::hash_cn;
use rustgate_core::message::RoutableMessage;

/// Default sweep interval for removing expired position entries.
const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Default maximum number of entries in the position cache.
const DEFAULT_MAX_ENTRIES: usize = 100_000;

rustgate_core::on_callback!(
    /// Callback invoked whenever the cache's entry count changes.
    ///
    /// The argument is the post-mutation size. Fires on [`PositionCache::store`]
    /// (including capacity-driven eviction), [`PositionCache::remove`], and
    /// [`PositionCache::sweep`]. Used by the server crate to feed the
    /// `rustgate_position_cache_size` Prometheus gauge; kept transport-agnostic
    /// so this crate does not leak a `prometheus` dependency.
    pub OnCacheSize,
    usize
);

/// A cached position plus the monotonic sequence number assigned when it was
/// (last) stored. Capacity eviction ranks by `seq`, not the message's
/// wall-clock `received_at`, so an NTP step-back cannot make a freshly-stored
/// entry look "oldest" and get it evicted on arrival (#1542).
struct PositionEntry {
    msg: RoutableMessage,
    seq: u64,
}

/// Stores the most recent position report per client CN.
///
/// # Concurrency
///
/// Backed by a sharded [`DashMap`] rather than a single
/// `RwLock<HashMap>`. Under the multi-worker ingest contention modelled
/// by `benches/dedup_contention.rs`, a single mutex around the map
/// collapses from ~10 Melem/s to ~6 Melem/s as worker count climbs from
/// 4 to 16, while the sharded map holds ~51–58 Melem/s (roughly 8x
/// faster at 16 workers, and flat under contention). The position cache
/// is the one clean map to migrate: it has no LRU/eviction-accounting
/// coupling, so a raw sharded map is a drop-in replacement (#1524).
///
/// The public API is synchronous: DashMap's per-shard locks are held
/// only for the duration of each map operation and never span an
/// `.await`, so this is not the `std::sync::Mutex`-across-await footgun.
///
/// One semantic difference from the old single-lock design: `sweep`,
/// `get_all`, and the capacity-eviction scan take per-shard locks rather
/// than one map-wide lock, so they no longer observe a single consistent
/// snapshot. For a best-effort latest-state cache this is acceptable —
/// TTL expiry and capacity eviction are already approximate (interval
/// sweep, monotonic-seq ranking), and no invariant depends on a
/// whole-map atomic view.
pub struct PositionCache {
    /// Keyed by `Arc<str>` so insert/remove on the SA-replay hot path
    /// reuse the sender's existing CN allocation (refcount bump) rather
    /// than copying the bytes into a fresh `String`. Closes #784.
    entries: DashMap<Arc<str>, PositionEntry>,
    /// Monotonic counter handed out on every `store`. Strictly increasing and
    /// independent of the wall clock, so it gives a stable least-recently-
    /// stored ordering for capacity eviction.
    next_seq: AtomicU64,
    /// Maximum number of entries before oldest-entry eviction kicks in.
    max_entries: usize,
    /// Lock-free hot-swappable size-change observer. `None` when unset;
    /// wired by `rustgate_server::setup` after construction so the transport
    /// crate stays metrics-agnostic.
    on_size: ArcSwap<Option<OnCacheSize>>,
}

impl std::fmt::Debug for PositionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PositionCache")
            .field("max_entries", &self.max_entries)
            .field(
                "on_size",
                &if self.on_size.load().is_some() {
                    "Some(<cb>)"
                } else {
                    "None"
                },
            )
            .finish_non_exhaustive()
    }
}

/// Check if a message has expired based on its TTL.
///
/// A message is expired when `received_at + ttl < now`. Messages without
/// a TTL never expire (they are only evicted on disconnect or replacement).
pub(crate) fn is_expired(msg: &RoutableMessage) -> bool {
    let Some(ttl) = msg.metadata.ttl else {
        return false;
    };
    match msg.metadata.received_at.elapsed() {
        Ok(elapsed) => elapsed > ttl,
        // Clock went backwards — treat as not expired to avoid data loss.
        Err(_) => false,
    }
}

impl Default for PositionCache {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
            next_seq: AtomicU64::new(0),
            max_entries: DEFAULT_MAX_ENTRIES,
            on_size: ArcSwap::new(Arc::new(None)),
        }
    }
}

impl PositionCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a position cache with a custom maximum entry count.
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            next_seq: AtomicU64::new(0),
            max_entries,
            on_size: ArcSwap::new(Arc::new(None)),
        }
    }

    /// Install (or replace) a callback that fires whenever the entry count
    /// changes. Called with the post-mutation size. Wired by the server
    /// crate to update `rustgate_position_cache_size`.
    pub fn set_on_size(&self, cb: OnCacheSize) {
        self.on_size.store(Arc::new(Some(cb)));
    }

    fn notify_size(&self, size: usize) {
        let guard = self.on_size.load();
        let cb_ref: &Option<OnCacheSize> = &guard;
        if let Some(cb) = cb_ref {
            cb(size);
        }
    }

    /// Store a position report, replacing any previous entry for this CN.
    ///
    /// If the cache is at capacity and this is a new CN, the
    /// least-recently-stored entry is evicted first (ranked by a monotonic
    /// sequence number, not the wall clock).
    pub fn store(&self, msg: RoutableMessage) {
        let cn = msg.source.cn.clone();

        // If this CN already exists, replacing it won't grow the cache.
        if !self.entries.contains_key(&cn) && self.entries.len() >= self.max_entries {
            // Evict the least-recently-stored entry by monotonic seq —
            // NOT the wall-clock received_at. An NTP step-back can give a
            // freshly-stored entry an earlier received_at than entries
            // already cached; ranking by received_at would then evict the
            // brand-new entry on arrival (#1542).
            //
            // The `iter()` scan takes per-shard locks, so this is an
            // approximate min under concurrent inserts — acceptable for a
            // best-effort capacity bound. The iterator guard is dropped
            // before `remove` so no two shard locks are held at once.
            let oldest_cn = self
                .entries
                .iter()
                .min_by_key(|e| e.value().seq)
                .map(|e| e.key().clone());
            if let Some(oldest_cn) = oldest_cn {
                tracing::warn!(
                    evicted_cn = %hash_cn(&oldest_cn),
                    size = self.entries.len(),
                    max = self.max_entries,
                    "position cache at capacity, evicting least-recently-stored entry",
                );
                let _ = self.entries.remove(&oldest_cn);
            }
        }
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let _ = self.entries.insert(cn, PositionEntry { msg, seq });
        let size = self.entries.len();
        self.notify_size(size);
    }

    /// Get all cached position reports for replay to a new session.
    ///
    /// Expired entries (past their TTL) are excluded from the result
    /// but not removed — the sweep task handles cleanup.
    pub fn get_all(&self) -> Vec<RoutableMessage> {
        self.entries
            .iter()
            .filter(|e| !is_expired(&e.value().msg))
            .map(|e| e.value().msg.clone())
            .collect()
    }

    /// Remove the cached position for a CN (e.g., on disconnect).
    pub fn remove(&self, cn: &str) {
        let _ = self.entries.remove(cn);
        let size = self.entries.len();
        self.notify_size(size);
    }

    /// Remove all expired entries from the cache.
    ///
    /// Returns the number of entries removed. `retain` locks one shard at
    /// a time, so the sweep is no longer a single-snapshot pass over the
    /// whole map — entries inserted into an already-visited shard survive
    /// until the next sweep. This is acceptable: the sweep is only a
    /// cleanup pass (`get_all` already filters expired entries on read),
    /// and no correctness invariant depends on it being atomic.
    pub fn sweep(&self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| !is_expired(&e.msg));
        let after = self.entries.len();
        let removed = before.saturating_sub(after);
        if removed > 0 {
            self.notify_size(after);
        }
        removed
    }

    /// Number of cached positions (including expired entries not yet swept).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Spawn a background task that periodically sweeps expired entries.
    ///
    /// The task runs until the provided `shutdown` signal is notified.
    /// Uses the default sweep interval of 15 seconds.
    pub fn start_sweep_task(
        self: &std::sync::Arc<Self>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        self.start_sweep_task_with_interval(shutdown, DEFAULT_SWEEP_INTERVAL)
    }

    /// Spawn a background task with a custom sweep interval.
    pub fn start_sweep_task_with_interval(
        self: &std::sync::Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let cache = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // First tick fires immediately — skip it so the first sweep
            // happens after one full interval.
            let _ = ticker.tick().await;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let removed = cache.sweep();
                        if removed > 0 {
                            tracing::debug!(removed, "position cache sweep");
                        }
                    }
                    _ = shutdown.changed() => {
                        break;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    use super::*;

    fn make_identity(cn: &str) -> Identity {
        Identity::new(cn.to_string(), format!("{cn}-fp"), BTreeSet::new()).expect("valid identity")
    }

    fn make_position_with_ttl(cn: &str, ttl: Option<Duration>) -> RoutableMessage {
        let mut metadata =
            Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Position);
        if let Some(t) = ttl {
            metadata = metadata.with_ttl(t);
        }
        RoutableMessage {
            source: make_identity(cn),
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event/>"),
            metadata,
            entity: None,
        }
    }

    fn make_position_at(cn: &str, received_at: SystemTime) -> RoutableMessage {
        RoutableMessage {
            source: make_identity(cn),
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event/>"),
            metadata: Metadata::new(received_at, "cot".to_string(), MessageType::Position),
            entity: None,
        }
    }

    fn make_expired_position(cn: &str) -> RoutableMessage {
        // received 10 seconds ago with a 1-second TTL → expired
        let metadata = Metadata::new(
            SystemTime::now() - Duration::from_secs(10),
            "cot".to_string(),
            MessageType::Position,
        )
        .with_ttl(Duration::from_secs(1));
        RoutableMessage {
            source: make_identity(cn),
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event/>"),
            metadata,
            entity: None,
        }
    }

    #[tokio::test]
    async fn store_and_retrieve() {
        let cache = PositionCache::new();
        let msg = make_position_with_ttl("alice", None);
        cache.store(msg);

        let all = cache.get_all();
        assert_eq!(all.len(), 1);
        assert_eq!(&*all[0].source.cn, "alice");
    }

    #[tokio::test]
    async fn get_all_excludes_expired() {
        let cache = PositionCache::new();

        // Fresh position
        cache.store(make_position_with_ttl("alice", None));
        // Expired position
        cache.store(make_expired_position("bob"));

        let all = cache.get_all();
        assert_eq!(all.len(), 1, "expired entry should be excluded");
        assert_eq!(&*all[0].source.cn, "alice");
    }

    #[tokio::test]
    async fn get_all_includes_non_expired_ttl() {
        let cache = PositionCache::new();

        // Position with TTL that hasn't expired yet (5 minutes)
        cache.store(make_position_with_ttl(
            "alice",
            Some(Duration::from_secs(300)),
        ));

        let all = cache.get_all();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn sweep_removes_expired() {
        let cache = PositionCache::new();

        cache.store(make_position_with_ttl("alice", None));
        cache.store(make_expired_position("bob"));
        cache.store(make_expired_position("charlie"));
        assert_eq!(cache.len(), 3);

        let removed = cache.sweep();
        assert_eq!(removed, 2, "two expired entries should be swept");
        assert_eq!(cache.len(), 1);

        let remaining = cache.get_all();
        assert_eq!(&*remaining[0].source.cn, "alice");
    }

    #[tokio::test]
    async fn sweep_no_expired_returns_zero() {
        let cache = PositionCache::new();
        cache.store(make_position_with_ttl("alice", None));

        let removed = cache.sweep();
        assert_eq!(removed, 0);
    }

    #[tokio::test]
    async fn sweep_task_runs_and_cleans() {
        let cache = Arc::new(PositionCache::new());

        // Store an already-expired entry
        cache.store(make_expired_position("stale-user"));
        assert_eq!(cache.len(), 1);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Start sweep with a short interval for testing
        let handle = cache.start_sweep_task_with_interval(shutdown_rx, Duration::from_millis(50));

        // Wait for at least one sweep cycle
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(cache.len(), 0, "expired entry should have been swept");

        // Signal shutdown
        let _ = shutdown_tx.send(true);
        handle.await.expect("sweep task should complete cleanly");
    }

    #[tokio::test]
    async fn is_expired_no_ttl_never_expires() {
        let msg = make_position_with_ttl("alice", None);
        assert!(!is_expired(&msg));
    }

    #[tokio::test]
    async fn is_expired_future_ttl_not_expired() {
        let msg = make_position_with_ttl("alice", Some(Duration::from_secs(3600)));
        assert!(!is_expired(&msg));
    }

    #[tokio::test]
    async fn is_expired_past_ttl_expired() {
        let msg = make_expired_position("alice");
        assert!(is_expired(&msg));
    }

    #[tokio::test]
    async fn remove_still_works() {
        let cache = PositionCache::new();
        cache.store(make_position_with_ttl("alice", None));
        cache.store(make_position_with_ttl("bob", None));

        cache.remove("alice");
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn store_replaces_previous_entry() {
        let cache = PositionCache::new();
        cache.store(make_position_with_ttl("alice", None));
        cache.store(make_position_with_ttl(
            "alice",
            Some(Duration::from_secs(60)),
        ));

        assert_eq!(cache.len(), 1);
        let all = cache.get_all();
        assert!(all[0].metadata.ttl.is_some(), "should have the newer entry");
    }

    #[tokio::test]
    async fn evicts_oldest_when_at_capacity() {
        let cache = PositionCache::with_max_entries(2);

        // Insert two entries — cache is now full.
        cache.store(make_position_with_ttl("alice", None));
        // Small delay so received_at times differ.
        tokio::time::sleep(Duration::from_millis(10)).await;
        cache.store(make_position_with_ttl("bob", None));
        assert_eq!(cache.len(), 2);

        // Third entry should evict alice (oldest received_at).
        tokio::time::sleep(Duration::from_millis(10)).await;
        cache.store(make_position_with_ttl("charlie", None));
        assert_eq!(cache.len(), 2, "should not exceed capacity");

        let all = cache.get_all();
        let cns: Vec<&str> = all.iter().map(|m| &*m.source.cn).collect();
        assert!(!cns.contains(&"alice"), "alice should have been evicted");
        assert!(cns.contains(&"bob"));
        assert!(cns.contains(&"charlie"));
    }

    #[tokio::test]
    async fn capacity_eviction_uses_insertion_order_not_wall_clock() {
        // NTP step-back: a freshly-stored entry can carry an EARLIER
        // received_at than entries already cached. Eviction must rank by the
        // monotonic store sequence, so the genuinely-oldest entry is evicted
        // and the fresh insert survives — not the reverse (#1542).
        let cache = PositionCache::with_max_entries(2);
        let base = SystemTime::now();
        cache.store(make_position_at("alice", base));
        cache.store(make_position_at("bob", base + Duration::from_secs(1)));
        // carol is stored LAST (newest), but the clock stepped back so her
        // received_at is the EARLIEST of the three — pre-fix she'd be evicted
        // on arrival.
        cache.store(make_position_at("carol", base - Duration::from_secs(60)));
        assert_eq!(cache.len(), 2, "should not exceed capacity");

        let cns: BTreeSet<String> = cache
            .get_all()
            .into_iter()
            .map(|m| m.source.cn.to_string())
            .collect();
        assert!(
            cns.contains("carol"),
            "the freshly-stored entry must NOT be evicted despite an older wall-clock timestamp",
        );
        assert!(cns.contains("bob"));
        assert!(
            !cns.contains("alice"),
            "the first-stored entry (lowest seq) should be the eviction victim",
        );
    }

    #[tokio::test]
    async fn replace_same_cn_does_not_evict() {
        let cache = PositionCache::with_max_entries(2);

        cache.store(make_position_with_ttl("alice", None));
        cache.store(make_position_with_ttl("bob", None));
        assert_eq!(cache.len(), 2);

        // Replacing alice shouldn't trigger eviction since it's an existing key.
        cache.store(make_position_with_ttl(
            "alice",
            Some(Duration::from_secs(60)),
        ));
        assert_eq!(cache.len(), 2);

        let all = cache.get_all();
        let cns: Vec<&str> = all.iter().map(|m| &*m.source.cn).collect();
        assert!(cns.contains(&"alice"));
        assert!(cns.contains(&"bob"));
    }

    mod on_size {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use super::*;

        #[tokio::test]
        async fn store_fires_callback_with_post_mutation_size() {
            let cache = PositionCache::new();
            let seen = Arc::new(AtomicUsize::new(0));
            let seen_cb = Arc::clone(&seen);
            cache.set_on_size(Arc::new(move |size| {
                seen_cb.store(size, Ordering::SeqCst);
            }));

            cache.store(make_position_with_ttl("alice", None));
            assert_eq!(seen.load(Ordering::SeqCst), 1);

            cache.store(make_position_with_ttl("bob", None));
            assert_eq!(seen.load(Ordering::SeqCst), 2);
        }

        #[tokio::test]
        async fn remove_fires_callback_with_post_mutation_size() {
            let cache = PositionCache::new();
            cache.store(make_position_with_ttl("alice", None));
            cache.store(make_position_with_ttl("bob", None));

            let seen = Arc::new(AtomicUsize::new(usize::MAX));
            let seen_cb = Arc::clone(&seen);
            cache.set_on_size(Arc::new(move |size| {
                seen_cb.store(size, Ordering::SeqCst);
            }));

            cache.remove("alice");
            assert_eq!(seen.load(Ordering::SeqCst), 1);

            cache.remove("bob");
            assert_eq!(seen.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn sweep_fires_callback_only_when_entries_removed() {
            let cache = PositionCache::new();
            cache.store(make_position_with_ttl("alice", None)); // non-expiring
            cache.store(make_expired_position("bob"));

            let fires = Arc::new(AtomicUsize::new(0));
            let seen_size = Arc::new(AtomicUsize::new(usize::MAX));
            let fires_cb = Arc::clone(&fires);
            let seen_cb = Arc::clone(&seen_size);
            cache.set_on_size(Arc::new(move |size| {
                let _ = fires_cb.fetch_add(1, Ordering::SeqCst);
                seen_cb.store(size, Ordering::SeqCst);
            }));

            let removed = cache.sweep();
            assert_eq!(removed, 1);
            assert_eq!(fires.load(Ordering::SeqCst), 1);
            assert_eq!(seen_size.load(Ordering::SeqCst), 1);

            // Second sweep removes nothing → callback must not fire again.
            let removed2 = cache.sweep();
            assert_eq!(removed2, 0);
            assert_eq!(
                fires.load(Ordering::SeqCst),
                1,
                "no callback on no-op sweep"
            );
        }

        #[tokio::test]
        async fn capacity_eviction_reports_post_insert_size() {
            let cache = PositionCache::with_max_entries(2);
            cache.store(make_position_with_ttl("alice", None));
            tokio::time::sleep(Duration::from_millis(5)).await;
            cache.store(make_position_with_ttl("bob", None));

            let seen = Arc::new(AtomicUsize::new(usize::MAX));
            let seen_cb = Arc::clone(&seen);
            cache.set_on_size(Arc::new(move |size| {
                seen_cb.store(size, Ordering::SeqCst);
            }));

            // Third insert triggers oldest-eviction; net size stays at 2.
            tokio::time::sleep(Duration::from_millis(5)).await;
            cache.store(make_position_with_ttl("charlie", None));
            assert_eq!(seen.load(Ordering::SeqCst), 2);
        }

        #[tokio::test]
        async fn replacing_callback_uses_latest() {
            let cache = PositionCache::new();
            let first = Arc::new(AtomicUsize::new(0));
            let second = Arc::new(AtomicUsize::new(0));
            let first_cb = Arc::clone(&first);
            let second_cb = Arc::clone(&second);

            cache.set_on_size(Arc::new(move |_| {
                let _ = first_cb.fetch_add(1, Ordering::SeqCst);
            }));
            cache.store(make_position_with_ttl("alice", None));
            assert_eq!(first.load(Ordering::SeqCst), 1);

            cache.set_on_size(Arc::new(move |_| {
                let _ = second_cb.fetch_add(1, Ordering::SeqCst);
            }));
            cache.store(make_position_with_ttl("bob", None));
            assert_eq!(first.load(Ordering::SeqCst), 1, "old cb must not fire");
            assert_eq!(second.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn no_callback_installed_is_silent_noop() {
            let cache = PositionCache::new();
            cache.store(make_position_with_ttl("alice", None));
            cache.remove("alice");
            // Nothing panics or deadlocks when no observer is wired.
            assert_eq!(cache.len(), 0);
        }
    }
}
