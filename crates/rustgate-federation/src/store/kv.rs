// Copyright © 2026 Roberto Chiofalo.

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

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::config::RoutingMode;
use crate::store::{FederateInfo, FederateStore, FederateUpdate};

const KV_BUCKET: &str = "federation-peers";
const STATS_FLUSH_INTERVAL_SECS: u64 = 5;

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
            .context("failed to create federation-peers KV bucket")?;

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
            let mut key_stream = self.kv.keys().await.context("failed to list KV keys")?;
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
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
        *federates = loaded;

        info!(count, "loaded federates from KV store");
        Ok(())
    }

    /// Write a federate to the KV bucket.
    fn put_kv(&self, info: &FederateInfo) -> Result<()> {
        let data = serde_json::to_vec(info).context("failed to serialize federate")?;
        let kv = self.kv.clone();
        let key = info.id.clone();
        // Fire-and-forget async write
        drop(tokio::spawn(async move {
            if let Err(e) = kv.put(&key, data.into()).await {
                warn!(key = %key, error = %e, "failed to write federate to KV");
            }
        }));
        Ok(())
    }

    /// Delete a federate from the KV bucket.
    fn delete_kv(&self, id: &str) {
        let kv = self.kv.clone();
        let key = id.to_string();
        drop(tokio::spawn(async move {
            if let Err(e) = kv.delete(&key).await {
                warn!(key = %key, error = %e, "failed to delete federate from KV");
            }
        }));
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
        let _ = self.put_kv(&info);
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
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        let info = federates
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("federate not found: {id}"))?;

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
        let _ = self.put_kv(&info_clone);

        Ok(old_address)
    }

    fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<()> {
        let mut federates = self
            .federates
            .write()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        let info = federates
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("federate not found: {id}"))?;

        info.enabled = enabled;
        let info_clone = info.clone();
        drop(federates);
        let _ = self.put_kv(&info_clone);

        Ok(())
    }

    fn set_routing_mode(&mut self, id: &str, mode: RoutingMode) -> Result<()> {
        let mut federates = self
            .federates
            .write()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        let info = federates
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("federate not found: {id}"))?;

        info.routing_mode = mode;
        let info_clone = info.clone();
        drop(federates);
        let _ = self.put_kv(&info_clone);

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

/// Watch loop: receives KV mutations and updates the local cache.
async fn watch_loop(
    kv: &async_nats::jetstream::kv::Store,
    federates: &RwLock<HashMap<String, FederateInfo>>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    use futures::StreamExt;

    let mut watcher = kv.watch_all().await.context("failed to start KV watch")?;

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
            drop(tokio::spawn(async move {
                if let Err(e) = kv.put(&key, data.into()).await {
                    warn!(key = %key, error = %e, "failed to flush stats to KV");
                }
            }));
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
}
