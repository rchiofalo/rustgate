// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! NATS JetStream KV-backed federate store.
//!
//! Provides a distributed federate store that synchronizes across multiple
//! pods via NATS KV watch. Reads are served from a local in-memory cache
//! for performance, while writes are committed to KV immediately
//! (write-through). Message statistics are batched and flushed periodically
//! to reduce KV write pressure.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use rustgate_core::tasks::spawn_background;
use rustgate_resilience::reconnect::backoff_delay;
use tracing::{debug, info, warn};

use crate::config::RoutingMode;
use crate::error::{FederationError, Result};
use crate::store::{FederateInfo, FederateStore, FederateUpdate};

const KV_BUCKET: &str = "federation-peers";
const STATS_FLUSH_INTERVAL_SECS: u64 = 5;

/// SEC-4: bounded retry for write-through KV mutations. The in-memory cache
/// is updated optimistically (read-your-writes), so a silently-dropped KV
/// write would diverge local and KV state until restart. Retrying recovers
/// the common transient-NATS case; a permanent give-up is surfaced via the
/// `kv_write_failures` metric so operators can alert and reconcile.
const KV_WRITE_MAX_ATTEMPTS: u32 = 4;
const KV_WRITE_RETRY_BASE: Duration = Duration::from_millis(100);

/// Pending statistics update for a federate.
#[derive(Debug, Default, Clone)]
struct PendingStats {
    sent: u64,
    recv: u64,
}

/// NATS JetStream KV-backed federate store.
///
/// Maintains a local in-memory cache that is kept in sync with the
/// distributed KV store via a watch loop. Mutations are written through
/// to KV immediately, while statistics are batched.
pub struct KvStore {
    kv: async_nats::jetstream::kv::Store,
    federates: Arc<RwLock<HashMap<String, FederateInfo>>>,
    pending_stats: Arc<std::sync::Mutex<HashMap<String, PendingStats>>>,
    watch_handle: Option<tokio::task::JoinHandle<()>>,
    stats_handle: Option<tokio::task::JoinHandle<()>>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl std::fmt::Debug for KvStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.federates.read().map(|f| f.len()).unwrap_or(0);
        f.debug_struct("KvStore")
            .field("bucket", &KV_BUCKET)
            .field("count", &count)
            .finish()
    }
}

impl KvStore {
    /// Create a new KV store and initialize the NATS KV bucket.
    ///
    /// Does NOT load data or start background tasks — call [`FederateStore::load`]
    /// after construction to perform the initial sync and start watchers.
    pub async fn new(jetstream: async_nats::jetstream::Context) -> Result<Self> {
        let kv = jetstream
            .create_key_value(async_nats::jetstream::kv::Config {
                bucket: KV_BUCKET.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| {
                FederationError::storage(format!(
                    "failed to create federation-peers KV bucket: {e}"
                ))
            })?;

        Ok(Self {
            kv,
            federates: Arc::new(RwLock::new(HashMap::new())),
            pending_stats: Arc::new(std::sync::Mutex::new(HashMap::new())),
            watch_handle: None,
            stats_handle: None,
            shutdown_tx: None,
        })
    }

    /// Perform the initial load from KV and start background tasks.
    ///
    /// This is an async operation separate from `new()` because the
    /// [`FederateStore`] trait's `load()` is synchronous. Call this
    /// method before using the store.
    pub async fn init(&mut self) -> Result<()> {
        // Initial load from KV
        self.load_from_kv().await?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        // Start watch loop
        let kv = self.kv.clone();
        let federates = self.federates.clone();
        let mut watch_shutdown = shutdown_rx.clone();
        self.watch_handle = Some(tokio::spawn(async move {
            if let Err(e) = watch_loop(&kv, &federates, &mut watch_shutdown).await {
                warn!(error = %e, "KV watch loop failed");
            }
        }));

        // Start stats flush loop
        let kv = self.kv.clone();
        let federates = self.federates.clone();
        let pending_stats = self.pending_stats.clone();
        let mut stats_shutdown = shutdown_rx;
        self.stats_handle = Some(tokio::spawn(async move {
            stats_flush_loop(&kv, &federates, &pending_stats, &mut stats_shutdown).await;
        }));

        info!("KV federate store initialized");
        Ok(())
    }

    /// Load all entries from the KV bucket into the local cache.
    async fn load_from_kv(&self) -> Result<()> {
        let mut keys = Vec::new();
        {
            use futures::StreamExt;
            let mut key_stream =
                self.kv.keys().await.map_err(|e| {
                    FederationError::storage(format!("failed to list KV keys: {e}"))
                })?;
            while let Some(result) = key_stream.next().await {
                if let Ok(key) = result {
                    keys.push(key);
                }
            }
        }

        let mut loaded = HashMap::new();
        for key in keys {
            if let Ok(Some(entry)) = self.kv.entry(&key).await {
                match serde_json::from_slice::<FederateInfo>(&entry.value) {
                    Ok(info) => {
                        let _ = loaded.insert(info.id.clone(), info);
                    }
                    Err(e) => {
                        warn!(key = %key, error = %e, "failed to deserialize federate from KV");
                    }
                }
            }
        }

        let count = loaded.len();
        let mut federates = self
            .federates
            .write()
            .map_err(|e| FederationError::lock("lock poisoned", e))?;
        *federates = loaded;

        info!(count, "loaded federates from KV store");
        Ok(())
    }

    /// Write a federate to the KV bucket (SEC-4: retried, failure-surfaced).
    ///
    /// The async write is retried with bounded backoff so a transient NATS
    /// failure doesn't silently diverge the optimistically-updated local
    /// cache from the KV store. A permanent give-up increments the
    /// `kv_write_failures` metric (and logs loudly) so operators can alert;
    /// the watch loop + load-on-restart reconcile the cache from KV.
    fn put_kv(&self, info: &FederateInfo) -> Result<()> {
        let data = serde_json::to_vec(info)
            .map_err(|e| FederationError::serde("failed to serialize federate", e))?;
        let kv = self.kv.clone();
        let key = info.id.clone();
        let value = bytes::Bytes::from(data);
        spawn_background("fed-kv-put", async move {
            let ok = write_with_retry(KV_WRITE_MAX_ATTEMPTS, KV_WRITE_RETRY_BASE, || {
                let kv = kv.clone();
                let key = key.clone();
                let value = value.clone();
                async move { kv.put(&key, value).await.map(|_| ()) }
            })
            .await;
            if !ok {
                warn!(
                    key = %key,
                    attempts = KV_WRITE_MAX_ATTEMPTS,
                    "federate KV write permanently failed — local cache and KV store have \
                     diverged; reconcile on watch reconnect / restart"
                );
                #[cfg(feature = "api")]
                crate::metrics::kv_write_failures().inc();
            }
        });
        Ok(())
    }

    /// Delete a federate from the KV bucket (SEC-4: retried, failure-surfaced).
    fn delete_kv(&self, id: &str) {
        let kv = self.kv.clone();
        let key = id.to_string();
        spawn_background("fed-kv-delete", async move {
            let ok = write_with_retry(KV_WRITE_MAX_ATTEMPTS, KV_WRITE_RETRY_BASE, || {
                let kv = kv.clone();
                let key = key.clone();
                async move { kv.delete(&key).await.map(|_| ()) }
            })
            .await;
            if !ok {
                warn!(
                    key = %key,
                    attempts = KV_WRITE_MAX_ATTEMPTS,
                    "federate KV delete permanently failed — local cache and KV store have \
                     diverged; reconcile on watch reconnect / restart"
                );
                #[cfg(feature = "api")]
                crate::metrics::kv_write_failures().inc();
            }
        });
    }

    /// Stop background tasks.
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(h) = self.watch_handle.take() {
            h.abort();
        }
        if let Some(h) = self.stats_handle.take() {
            h.abort();
        }
        info!("KV federate store stopped");
    }
}

impl FederateStore for KvStore {
    fn load(&mut self) -> Result<()> {
        // Initial load happens in init(). This is a no-op for the sync trait.
        // Users should call init() before using the store.
        Ok(())
    }

    fn save(&self) -> Result<()> {
        // KV store is write-through, no explicit save needed.
        Ok(())
    }

    fn add(&mut self, info: FederateInfo) {
        if let Err(e) = self.put_kv(&info) {
            warn!(error = %e, id = %info.id, "federation KV write failed");
        }
        let mut federates = match self.federates.write() {
            Ok(f) => f,
            Err(_) => return,
        };
        let _ = federates.insert(info.id.clone(), info);
    }

    fn get(&self, id: &str) -> Option<FederateInfo> {
        let federates = match self.federates.read() {
            Ok(f) => f,
            Err(_) => return None,
        };
        federates.get(id).cloned()
    }

    fn list(&self) -> Vec<FederateInfo> {
        let federates = match self.federates.read() {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        federates.values().cloned().collect()
    }

    fn list_enabled(&self) -> Vec<FederateInfo> {
        let federates = match self.federates.read() {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        federates.values().filter(|f| f.enabled).cloned().collect()
    }

    fn list_outbound(&self) -> Vec<FederateInfo> {
        let federates = match self.federates.read() {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        federates
            .values()
            .filter(|f| f.enabled && f.is_outbound)
            .cloned()
            .collect()
    }

    fn remove(&mut self, id: &str) -> bool {
        let mut federates = match self.federates.write() {
            Ok(f) => f,
            Err(_) => return false,
        };
        let existed = federates.remove(id).is_some();
        if existed {
            drop(federates);
            self.delete_kv(id);
        }
        existed
    }

    fn update(&mut self, id: &str, update: FederateUpdate) -> Result<Option<String>> {
        let mut federates = self
            .federates
            .write()
            .map_err(|e| FederationError::lock("lock poisoned", e))?;

        let info = federates
            .get_mut(id)
            .ok_or_else(|| FederationError::PeerNotFound(id.to_string()))?;

        let old_address = if let Some(addr) = update.address {
            let old = info.address.clone();
            info.address = addr;
            Some(old)
        } else {
            None
        };

        if let Some(groups) = update.groups {
            info.groups = groups;
        }
        if let Some(is_outbound) = update.is_outbound {
            info.is_outbound = is_outbound;
        }
        if let Some(trust_cert_cn) = update.trust_cert_cn {
            info.trust_cert_cn = trust_cert_cn;
        }

        let info_clone = info.clone();
        drop(federates);
        if let Err(e) = self.put_kv(&info_clone) {
            warn!(error = %e, id = %info_clone.id, "federation KV write failed");
        }

        Ok(old_address)
    }

    fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<()> {
        let mut federates = self
            .federates
            .write()
            .map_err(|e| FederationError::lock("lock poisoned", e))?;

        let info = federates
            .get_mut(id)
            .ok_or_else(|| FederationError::PeerNotFound(id.to_string()))?;

        info.enabled = enabled;
        let info_clone = info.clone();
        drop(federates);
        if let Err(e) = self.put_kv(&info_clone) {
            warn!(error = %e, id = %info_clone.id, "federation KV write failed");
        }

        Ok(())
    }

    fn set_routing_mode(&mut self, id: &str, mode: RoutingMode) -> Result<()> {
        let mut federates = self
            .federates
            .write()
            .map_err(|e| FederationError::lock("lock poisoned", e))?;

        let info = federates
            .get_mut(id)
            .ok_or_else(|| FederationError::PeerNotFound(id.to_string()))?;

        info.routing_mode = mode;
        let info_clone = info.clone();
        drop(federates);
        if let Err(e) = self.put_kv(&info_clone) {
            warn!(error = %e, id = %info_clone.id, "federation KV write failed");
        }

        Ok(())
    }

    fn update_last_seen(&mut self, id: &str) {
        let mut federates = match self.federates.write() {
            Ok(f) => f,
            Err(_) => return,
        };
        if let Some(info) = federates.get_mut(id) {
            info.last_seen = Some(SystemTime::now());
            // Don't write-through for last_seen updates (too frequent)
        }
    }

    fn update_stats(&mut self, id: &str, sent: u64, recv: u64) {
        // Update local cache immediately
        let mut federates = match self.federates.write() {
            Ok(f) => f,
            Err(_) => return,
        };
        if let Some(info) = federates.get_mut(id) {
            info.messages_sent += sent;
            info.messages_recv += recv;
        }
        drop(federates);

        // Batch for periodic flush
        let mut pending = match self.pending_stats.lock() {
            Ok(p) => p,
            Err(_) => return,
        };
        let entry = pending.entry(id.to_string()).or_default();
        entry.sent += sent;
        entry.recv += recv;
    }

    fn count(&self) -> usize {
        self.federates.read().map(|f| f.len()).unwrap_or(0)
    }
}

/// Retry an async KV write up to `max_attempts` times with exponential
/// backoff between attempts. Returns `true` on the first success, `false`
/// if every attempt failed (SEC-4).
///
/// Generic over the write closure so it is unit-testable without a live
/// NATS server: the closure is re-invoked per attempt and must produce a
/// fresh future each time. Bounds how long the optimistically-updated local
/// cache can diverge from the KV store on a transient failure; a permanent
/// give-up (`false`) is surfaced by the caller via the failure metric.
async fn write_with_retry<F, Fut, E>(max_attempts: u32, base: Duration, mut attempt_fn: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<(), E>>,
    E: std::fmt::Display,
{
    let max_attempts = max_attempts.max(1);
    for attempt in 0..max_attempts {
        match attempt_fn().await {
            Ok(()) => return true,
            Err(e) => {
                warn!(
                    attempt = attempt + 1,
                    max_attempts,
                    error = %e,
                    "KV write attempt failed"
                );
                if attempt + 1 < max_attempts {
                    tokio::time::sleep(backoff_delay(base, attempt)).await;
                }
            }
        }
    }
    false
}

/// Watch loop: receives KV mutations and updates the local cache.
async fn watch_loop(
    kv: &async_nats::jetstream::kv::Store,
    federates: &RwLock<HashMap<String, FederateInfo>>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    use futures::StreamExt;

    let mut watcher = kv
        .watch_all()
        .await
        .map_err(|e| FederationError::storage(format!("failed to start KV watch: {e}")))?;

    loop {
        tokio::select! {
            entry = watcher.next() => {
                let Some(entry) = entry else {
                    debug!("KV watch stream ended");
                    return Ok(());
                };

                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(error = %e, "error reading KV watch entry");
                        continue;
                    }
                };

                let mut cache = match federates.write() {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                if entry.operation == async_nats::jetstream::kv::Operation::Delete
                    || entry.operation == async_nats::jetstream::kv::Operation::Purge
                {
                    let _ = cache.remove(&entry.key);
                    debug!(key = %entry.key, "removed federate from cache (KV delete)");
                } else {
                    match serde_json::from_slice::<FederateInfo>(&entry.value) {
                        Ok(info) => {
                            debug!(id = %info.id, "updated federate in cache from KV");
                            let _ = cache.insert(info.id.clone(), info);
                        }
                        Err(e) => {
                            warn!(key = %entry.key, error = %e, "failed to deserialize KV entry");
                        }
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                debug!("KV watch loop shutting down");
                return Ok(());
            }
        }
    }
}

/// Periodically flush batched statistics to the KV store.
async fn stats_flush_loop(
    kv: &async_nats::jetstream::kv::Store,
    federates: &RwLock<HashMap<String, FederateInfo>>,
    pending_stats: &std::sync::Mutex<HashMap<String, PendingStats>>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(STATS_FLUSH_INTERVAL_SECS));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                flush_stats(kv, federates, pending_stats);
            }
            _ = shutdown_rx.changed() => {
                // Final flush before shutdown
                flush_stats(kv, federates, pending_stats);
                debug!("stats flush loop shutting down");
                return;
            }
        }
    }
}

/// Flush pending statistics to KV.
fn flush_stats(
    kv: &async_nats::jetstream::kv::Store,
    federates: &RwLock<HashMap<String, FederateInfo>>,
    pending_stats: &std::sync::Mutex<HashMap<String, PendingStats>>,
) {
    // Swap out the pending stats
    let pending = {
        let mut stats = match pending_stats.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        if stats.is_empty() {
            return;
        }
        let pending = stats.clone();
        stats.clear();
        pending
    };

    // Write each updated federate to KV
    let federates_read = match federates.read() {
        Ok(f) => f,
        Err(_) => return,
    };

    for id in pending.keys() {
        if let Some(info) = federates_read.get(id)
            && let Ok(data) = serde_json::to_vec(info)
        {
            let kv = kv.clone();
            let key = id.clone();
            spawn_background("fed-kv-stats-flush", async move {
                if let Err(e) = kv.put(&key, data.into()).await {
                    warn!(key = %key, error = %e, "failed to flush stats to KV");
                }
            });
        }
    }
}

#[cfg(test)]
#[allow(unused_results)]
mod tests {
    use super::*;

    #[test]
    fn kv_bucket_name() {
        assert_eq!(KV_BUCKET, "federation-peers");
    }

    #[test]
    fn stats_flush_interval() {
        assert_eq!(STATS_FLUSH_INTERVAL_SECS, 5);
    }

    #[test]
    fn pending_stats_default() {
        let stats = PendingStats::default();
        assert_eq!(stats.sent, 0);
        assert_eq!(stats.recv, 0);
    }

    #[test]
    fn pending_stats_accumulation() {
        let pending: Arc<std::sync::Mutex<HashMap<String, PendingStats>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Simulate multiple stat updates
        {
            let mut stats = pending.lock().expect("lock");
            let entry = stats.entry("peer-1".into()).or_default();
            entry.sent += 10;
            entry.recv += 5;
        }

        {
            let mut stats = pending.lock().expect("lock");
            let entry = stats.entry("peer-1".into()).or_default();
            entry.sent += 3;
            entry.recv += 2;
        }

        let stats = pending.lock().expect("lock");
        let entry = stats.get("peer-1").expect("exists");
        assert_eq!(entry.sent, 13);
        assert_eq!(entry.recv, 7);
    }

    #[test]
    fn pending_stats_multiple_peers() {
        let pending: Arc<std::sync::Mutex<HashMap<String, PendingStats>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        {
            let mut stats = pending.lock().expect("lock");
            stats.entry("peer-1".into()).or_default().sent += 5;
            stats.entry("peer-2".into()).or_default().sent += 3;
            stats.entry("peer-1".into()).or_default().recv += 2;
        }

        let stats = pending.lock().expect("lock");
        assert_eq!(stats.len(), 2);
        assert_eq!(stats.get("peer-1").expect("exists").sent, 5);
        assert_eq!(stats.get("peer-1").expect("exists").recv, 2);
        assert_eq!(stats.get("peer-2").expect("exists").sent, 3);
    }

    #[test]
    fn pending_stats_swap_and_clear() {
        let pending: Arc<std::sync::Mutex<HashMap<String, PendingStats>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        {
            let mut stats = pending.lock().expect("lock");
            stats.entry("peer-1".into()).or_default().sent += 10;
        }

        // Swap out pending (simulating flush)
        let swapped = {
            let mut stats = pending.lock().expect("lock");
            let s = stats.clone();
            stats.clear();
            s
        };

        assert_eq!(swapped.len(), 1);
        assert_eq!(swapped.get("peer-1").expect("exists").sent, 10);

        // Original should be empty
        let stats = pending.lock().expect("lock");
        assert!(stats.is_empty());
    }

    // ── SEC-4: bounded write retry ─────────────────────────────────────

    #[tokio::test]
    async fn write_with_retry_succeeds_on_first_attempt() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        let ok = write_with_retry(4, Duration::from_millis(1), || {
            let c = Arc::clone(&c);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok::<(), String>(())
            }
        })
        .await;
        assert!(ok);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no retry needed on success"
        );
    }

    #[tokio::test]
    async fn write_with_retry_recovers_after_transient_failures() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        // Fail the first two attempts, succeed on the third.
        let ok = write_with_retry(4, Duration::from_millis(1), || {
            let c = Arc::clone(&c);
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err("transient NATS error".to_string())
                } else {
                    Ok::<(), String>(())
                }
            }
        })
        .await;
        assert!(ok, "should recover once a retry succeeds");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn write_with_retry_gives_up_after_max_attempts() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        let ok = write_with_retry(4, Duration::from_millis(1), || {
            let c = Arc::clone(&c);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err::<(), String>("permanent failure".into())
            }
        })
        .await;
        assert!(!ok, "should give up after exhausting attempts");
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn write_with_retry_floors_attempts_at_one() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        // max_attempts = 0 must still attempt once (floored at 1).
        let ok = write_with_retry(0, Duration::from_millis(1), || {
            let c = Arc::clone(&c);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err::<(), String>("fail".into())
            }
        })
        .await;
        assert!(!ok);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
