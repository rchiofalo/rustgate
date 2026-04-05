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
//! [`start_sweep_task`] spawns a background `tokio` task that calls
//! [`PositionCache::sweep`] at a fixed interval (default: **15 seconds**).
//! The sweep removes all entries whose TTL has elapsed. Entries without a
//! TTL are never removed by the sweep — they persist until explicitly
//! removed or replaced.
//!
//! The sweep interval is independent of individual entry TTLs. An entry
//! with a 5-second TTL will not be removed until the next 15-second sweep runs,
//! but it will be excluded from [`PositionCache::get_all`] results
//! immediately (the `is_expired` check runs on read).

use std::collections::HashMap;
use std::time::Duration;

use rustgate_core::message::RoutableMessage;
use tokio::sync::RwLock;

/// Default sweep interval for removing expired position entries.
const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Default maximum number of entries in the position cache.
const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Stores the most recent position report per client CN.
#[derive(Debug)]
pub struct PositionCache {
    entries: RwLock<HashMap<String, RoutableMessage>>,
    /// Maximum number of entries before oldest-entry eviction kicks in.
    max_entries: usize,
}

/// Check if a position message has expired based on its TTL.
///
/// A message is expired when `received_at + ttl < now`. Messages without
/// a TTL never expire (they are only evicted on disconnect or replacement).
fn is_expired(msg: &RoutableMessage) -> bool {
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
            entries: RwLock::new(HashMap::new()),
            max_entries: DEFAULT_MAX_ENTRIES,
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
            entries: RwLock::new(HashMap::new()),
            max_entries,
        }
    }

    /// Store a position report, replacing any previous entry for this CN.
    ///
    /// If the cache is at capacity and this is a new CN, the oldest entry
    /// (by `received_at` time) is evicted first.
    pub async fn store(&self, msg: RoutableMessage) {
        let cn = msg.source.cn.clone();
        let mut entries = self.entries.write().await;

        // If this CN already exists, replacing it won't grow the cache.
        if !entries.contains_key(&cn) && entries.len() >= self.max_entries {
            // Evict the oldest entry by received_at time.
            if let Some(oldest_cn) = entries
                .iter()
                .min_by_key(|(_, m)| m.metadata.received_at)
                .map(|(cn, _)| cn.clone())
            {
                tracing::warn!(
                    evicted_cn = %oldest_cn,
                    size = entries.len(),
                    max = self.max_entries,
                    "position cache at capacity, evicting oldest entry",
                );
                let _ = entries.remove(&oldest_cn);
            }
        }
        let _ = entries.insert(cn, msg);
    }

    /// Get all cached position reports for replay to a new session.
    ///
    /// Expired entries (past their TTL) are excluded from the result
    /// but not removed — the sweep task handles cleanup.
    pub async fn get_all(&self) -> Vec<RoutableMessage> {
        let entries = self.entries.read().await;
        entries
            .values()
            .filter(|msg| !is_expired(msg))
            .cloned()
            .collect()
    }

    /// Remove the cached position for a CN (e.g., on disconnect).
    pub async fn remove(&self, cn: &str) {
        let mut entries = self.entries.write().await;
        let _ = entries.remove(cn);
    }

    /// Remove all expired entries from the cache.
    ///
    /// Returns the number of entries removed.
    pub async fn sweep(&self) -> usize {
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|_, msg| !is_expired(msg));
        before - entries.len()
    }

    /// Number of cached positions (including expired entries not yet swept).
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Check if cache is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
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
                        let removed = cache.sweep().await;
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
        RoutableMessage {
            source: make_identity(cn),
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event/>"),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "cot".to_string(),
                message_type: MessageType::Position,
                ttl,
            },
        }
    }

    fn make_expired_position(cn: &str) -> RoutableMessage {
        RoutableMessage {
            source: make_identity(cn),
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event/>"),
            metadata: Metadata {
                // received 10 seconds ago with a 1-second TTL → expired
                received_at: SystemTime::now() - Duration::from_secs(10),
                source_protocol: "cot".to_string(),
                message_type: MessageType::Position,
                ttl: Some(Duration::from_secs(1)),
            },
        }
    }

    #[tokio::test]
    async fn store_and_retrieve() {
        let cache = PositionCache::new();
        let msg = make_position_with_ttl("alice", None);
        cache.store(msg).await;

        let all = cache.get_all().await;
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].source.cn, "alice");
    }

    #[tokio::test]
    async fn get_all_excludes_expired() {
        let cache = PositionCache::new();

        // Fresh position
        cache.store(make_position_with_ttl("alice", None)).await;
        // Expired position
        cache.store(make_expired_position("bob")).await;

        let all = cache.get_all().await;
        assert_eq!(all.len(), 1, "expired entry should be excluded");
        assert_eq!(all[0].source.cn, "alice");
    }

    #[tokio::test]
    async fn get_all_includes_non_expired_ttl() {
        let cache = PositionCache::new();

        // Position with TTL that hasn't expired yet (5 minutes)
        cache
            .store(make_position_with_ttl(
                "alice",
                Some(Duration::from_secs(300)),
            ))
            .await;

        let all = cache.get_all().await;
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn sweep_removes_expired() {
        let cache = PositionCache::new();

        cache.store(make_position_with_ttl("alice", None)).await;
        cache.store(make_expired_position("bob")).await;
        cache.store(make_expired_position("charlie")).await;
        assert_eq!(cache.len().await, 3);

        let removed = cache.sweep().await;
        assert_eq!(removed, 2, "two expired entries should be swept");
        assert_eq!(cache.len().await, 1);

        let remaining = cache.get_all().await;
        assert_eq!(remaining[0].source.cn, "alice");
    }

    #[tokio::test]
    async fn sweep_no_expired_returns_zero() {
        let cache = PositionCache::new();
        cache.store(make_position_with_ttl("alice", None)).await;

        let removed = cache.sweep().await;
        assert_eq!(removed, 0);
    }

    #[tokio::test]
    async fn sweep_task_runs_and_cleans() {
        let cache = Arc::new(PositionCache::new());

        // Store an already-expired entry
        cache.store(make_expired_position("stale-user")).await;
        assert_eq!(cache.len().await, 1);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Start sweep with a short interval for testing
        let handle = cache.start_sweep_task_with_interval(shutdown_rx, Duration::from_millis(50));

        // Wait for at least one sweep cycle
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(cache.len().await, 0, "expired entry should have been swept");

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
        cache.store(make_position_with_ttl("alice", None)).await;
        cache.store(make_position_with_ttl("bob", None)).await;

        cache.remove("alice").await;
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn store_replaces_previous_entry() {
        let cache = PositionCache::new();
        cache.store(make_position_with_ttl("alice", None)).await;
        cache
            .store(make_position_with_ttl(
                "alice",
                Some(Duration::from_secs(60)),
            ))
            .await;

        assert_eq!(cache.len().await, 1);
        let all = cache.get_all().await;
        assert!(all[0].metadata.ttl.is_some(), "should have the newer entry");
    }

    #[tokio::test]
    async fn evicts_oldest_when_at_capacity() {
        let cache = PositionCache::with_max_entries(2);

        // Insert two entries — cache is now full.
        cache.store(make_position_with_ttl("alice", None)).await;
        // Small delay so received_at times differ.
        tokio::time::sleep(Duration::from_millis(10)).await;
        cache.store(make_position_with_ttl("bob", None)).await;
        assert_eq!(cache.len().await, 2);

        // Third entry should evict alice (oldest received_at).
        tokio::time::sleep(Duration::from_millis(10)).await;
        cache.store(make_position_with_ttl("charlie", None)).await;
        assert_eq!(cache.len().await, 2, "should not exceed capacity");

        let all = cache.get_all().await;
        let cns: Vec<&str> = all.iter().map(|m| m.source.cn.as_str()).collect();
        assert!(!cns.contains(&"alice"), "alice should have been evicted");
        assert!(cns.contains(&"bob"));
        assert!(cns.contains(&"charlie"));
    }

    #[tokio::test]
    async fn replace_same_cn_does_not_evict() {
        let cache = PositionCache::with_max_entries(2);

        cache.store(make_position_with_ttl("alice", None)).await;
        cache.store(make_position_with_ttl("bob", None)).await;
        assert_eq!(cache.len().await, 2);

        // Replacing alice shouldn't trigger eviction since it's an existing key.
        cache
            .store(make_position_with_ttl(
                "alice",
                Some(Duration::from_secs(60)),
            ))
            .await;
        assert_eq!(cache.len().await, 2);

        let all = cache.get_all().await;
        let cns: Vec<&str> = all.iter().map(|m| m.source.cn.as_str()).collect();
        assert!(cns.contains(&"alice"));
        assert!(cns.contains(&"bob"));
    }
}
