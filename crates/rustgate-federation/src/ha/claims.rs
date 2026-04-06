//! Distributed peer ownership via NATS KV claims.
//!
//! Ensures exactly one pod manages each outbound peer connection
//! in multi-pod (Kubernetes) deployments. Uses NATS JetStream KV
//! with TTL-based expiry for automatic failover.
//!
//! ## Lifecycle
//!
//! 1. Pod starts and calls [`ClaimManager::try_claim`] for each outbound peer
//! 2. Atomic KV `create` ensures only one pod wins each claim
//! 3. Background refresh loop re-puts claims every 10s to keep the 30s TTL alive
//! 4. If a pod dies, its claims expire after 30s
//! 5. Watch loop detects expired claims and fires `on_peer_available` callback
//! 6. Surviving pods race to adopt with randomized jitter

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, watch};
use tracing::{debug, info, warn};

use super::{ADOPT_DELAY_SECS, CLAIM_TTL_SECS, MAX_ADOPT_JITTER_MS, REFRESH_INTERVAL_SECS};

const CLAIM_BUCKET: &str = "federation-claims";

/// Callback invoked when a peer becomes available for adoption
/// (its claim expired due to pod death).
pub type OnPeerAvailable = Arc<dyn Fn(String) + Send + Sync>;

/// Callback invoked when a claim is lost to another pod.
///
/// Arguments: `(peer_id, stale_fencing_token)`. The fencing token is the
/// NATS KV revision that this pod held before the claim was lost.
pub type OnClaimLost = Arc<dyn Fn(String, u64) + Send + Sync>;

/// Manages distributed peer ownership using NATS JetStream KV.
///
/// Each outbound peer connection is "claimed" by exactly one pod.
/// Claims are maintained via KV entries with TTL. If a pod dies,
/// its claims expire and other pods can adopt the orphaned peers.
pub struct ClaimManager {
    kv: async_nats::jetstream::kv::Store,
    pod_id: String,
    claims: Mutex<HashMap<String, u64>>, // peer_id → revision
    on_peer_available: Option<OnPeerAvailable>,
    on_claim_lost: Option<OnClaimLost>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    task_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for ClaimManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimManager")
            .field("pod_id", &self.pod_id)
            .finish()
    }
}

impl ClaimManager {
    /// Create a new claim manager.
    ///
    /// Initializes the NATS KV bucket with the configured TTL.
    pub async fn new(jetstream: async_nats::jetstream::Context, pod_id: String) -> Result<Self> {
        let kv = jetstream
            .create_key_value(async_nats::jetstream::kv::Config {
                bucket: CLAIM_BUCKET.into(),
                max_age: Duration::from_secs(CLAIM_TTL_SECS),
                ..Default::default()
            })
            .await
            .context("failed to create federation-claims KV bucket")?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(Self {
            kv,
            pod_id,
            claims: Mutex::new(HashMap::new()),
            on_peer_available: None,
            on_claim_lost: None,
            shutdown_tx,
            shutdown_rx,
            task_handles: Mutex::new(Vec::new()),
        })
    }

    /// Set callbacks for peer availability and claim loss events.
    pub fn set_callbacks(
        &mut self,
        on_peer_available: OnPeerAvailable,
        on_claim_lost: OnClaimLost,
    ) {
        self.on_peer_available = Some(on_peer_available);
        self.on_claim_lost = Some(on_claim_lost);
    }

    /// Start background refresh and watch loops.
    pub async fn start(&self) {
        let mut handles = self.task_handles.lock().await;

        // Refresh loop: re-put all claims every REFRESH_INTERVAL_SECS
        let kv = self.kv.clone();
        let pod_id = self.pod_id.clone();
        let claims = self.claims.lock().await;
        let claims_snapshot: HashMap<String, u64> = claims.clone();
        drop(claims);

        let claims_ref = Arc::new(Mutex::new(claims_snapshot));
        let claims_for_refresh = claims_ref.clone();
        let on_claim_lost = self.on_claim_lost.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();

        let refresh_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(REFRESH_INTERVAL_SECS));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        refresh_claims(
                            &kv,
                            &pod_id,
                            &claims_for_refresh,
                            on_claim_lost.as_ref(),
                        ).await;
                    }
                    _ = shutdown_rx.changed() => {
                        debug!("claim refresh loop shutting down");
                        return;
                    }
                }
            }
        });
        handles.push(refresh_handle);

        // Watch loop: detect expired claims and fire on_peer_available
        let kv = self.kv.clone();
        let pod_id = self.pod_id.clone();
        let claims_for_watch = claims_ref;
        let on_peer_available = self.on_peer_available.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();

        let watch_handle = tokio::spawn(async move {
            if let Err(e) = watch_expired_claims(
                &kv,
                &pod_id,
                &claims_for_watch,
                on_peer_available.as_ref(),
                &mut shutdown_rx,
            )
            .await
            {
                warn!(error = %e, "claim watch loop failed");
            }
        });
        handles.push(watch_handle);

        info!(pod_id = %self.pod_id, "claim manager started");
    }

    /// Attempt to claim a peer.
    ///
    /// Uses atomic KV `create` which only succeeds if the key does not exist.
    /// Returns the fencing token (NATS KV revision) on success, or `None` if
    /// the peer is already claimed by another pod. The fencing token is a
    /// monotonically increasing integer that prevents split-brain: a pod must
    /// hold a current token to operate on a peer.
    pub async fn try_claim(&self, peer_id: &str) -> Option<u64> {
        let value = bytes::Bytes::from(self.pod_id.clone());

        match self.kv.create(peer_id, value.clone()).await {
            Ok(revision) => {
                let mut claims = self.claims.lock().await;
                let _ = claims.insert(peer_id.to_string(), revision);
                info!(peer_id = %peer_id, pod_id = %self.pod_id, fence = revision, "claimed peer");
                Some(revision)
            }
            Err(_) => {
                // Key exists — check if we already own it (e.g., from a previous run)
                match self.kv.entry(peer_id).await {
                    Ok(Some(entry)) if entry.value == self.pod_id.as_bytes() => {
                        let mut claims = self.claims.lock().await;
                        let _ = claims.insert(peer_id.to_string(), entry.revision);
                        debug!(peer_id = %peer_id, fence = entry.revision, "reclaimed own peer");
                        Some(entry.revision)
                    }
                    _ => {
                        debug!(peer_id = %peer_id, "peer already claimed by another pod");
                        None
                    }
                }
            }
        }
    }

    /// Return the fencing token (NATS KV revision) for a claimed peer.
    ///
    /// Returns `None` if this pod does not own the claim.
    pub async fn fencing_token(&self, peer_id: &str) -> Option<u64> {
        let claims = self.claims.lock().await;
        claims.get(peer_id).copied()
    }

    /// Check whether the given fencing token is still the current claim revision.
    ///
    /// Returns `true` if this pod still holds the claim with the given token
    /// (or a newer one). Returns `false` if the claim has been lost.
    pub async fn is_token_valid(&self, peer_id: &str, token: u64) -> bool {
        let claims = self.claims.lock().await;
        match claims.get(peer_id) {
            Some(&current) => current >= token,
            None => false,
        }
    }

    /// Release a claim, allowing other pods to adopt the peer.
    pub async fn release(&self, peer_id: &str) -> Result<()> {
        let mut claims = self.claims.lock().await;
        let _ = claims.remove(peer_id);
        drop(claims);

        self.kv
            .delete(peer_id)
            .await
            .context("failed to delete claim from KV")?;

        info!(peer_id = %peer_id, pod_id = %self.pod_id, "released peer claim");
        Ok(())
    }

    /// Check if this pod owns the claim for a peer.
    pub async fn is_owner(&self, peer_id: &str) -> bool {
        let claims = self.claims.lock().await;
        claims.contains_key(peer_id)
    }

    /// List all peers claimed by this pod.
    pub async fn claimed_peers(&self) -> Vec<String> {
        let claims = self.claims.lock().await;
        claims.keys().cloned().collect()
    }

    /// Gracefully stop the claim manager, releasing all claims.
    pub async fn stop(&self) {
        // Signal background tasks to stop
        let _ = self.shutdown_tx.send(true);

        // Release all claims so other pods can adopt immediately
        let claims = self.claims.lock().await;
        let peer_ids: Vec<String> = claims.keys().cloned().collect();
        drop(claims);

        for peer_id in &peer_ids {
            if let Err(e) = self.kv.delete(peer_id).await {
                warn!(peer_id = %peer_id, error = %e, "failed to release claim on shutdown");
            }
        }

        // Clear local state
        let mut claims = self.claims.lock().await;
        claims.clear();

        // Wait for background tasks
        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle.abort();
        }

        info!(
            pod_id = %self.pod_id,
            released = peer_ids.len(),
            "claim manager stopped"
        );
    }

    /// Return the adoption delay duration.
    ///
    /// After claiming an orphaned peer, the manager should wait this long
    /// before connecting, giving the remote TAK Server time to clean up.
    pub fn adopt_delay() -> Duration {
        Duration::from_secs(ADOPT_DELAY_SECS)
    }

    /// Compute a jitter delay for adoption (prevents thundering herd).
    pub fn adoption_jitter() -> Duration {
        // Use subsecond nanos from current time as simple entropy source
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let jitter_ms = (nanos as u64) % MAX_ADOPT_JITTER_MS;
        Duration::from_millis(jitter_ms)
    }
}

/// Refresh all active claims by re-putting them to reset TTL.
async fn refresh_claims(
    kv: &async_nats::jetstream::kv::Store,
    pod_id: &str,
    claims: &Mutex<HashMap<String, u64>>,
    on_claim_lost: Option<&OnClaimLost>,
) {
    let snapshot = {
        let claims = claims.lock().await;
        claims.clone()
    };

    if snapshot.is_empty() {
        return;
    }

    let value = bytes::Bytes::from(pod_id.to_string());

    for (peer_id, revision) in &snapshot {
        match kv.update(peer_id, value.clone(), *revision).await {
            Ok(new_rev) => {
                let mut claims = claims.lock().await;
                if let Some(rev) = claims.get_mut(peer_id) {
                    debug!(
                        peer_id = %peer_id,
                        old_fence = %rev,
                        new_fence = %new_rev,
                        "refreshed claim"
                    );
                    *rev = new_rev;
                }
            }
            Err(e) => {
                // Check if another pod took the claim
                match kv.entry(peer_id).await {
                    Ok(Some(entry)) if entry.value != pod_id.as_bytes() => {
                        warn!(
                            peer_id = %peer_id,
                            new_owner = %String::from_utf8_lossy(&entry.value),
                            stale_fence = %revision,
                            "lost claim to another pod"
                        );
                        let mut claims_guard = claims.lock().await;
                        let _ = claims_guard.remove(peer_id);
                        drop(claims_guard);

                        if let Some(callback) = on_claim_lost {
                            callback(peer_id.clone(), *revision);
                        }
                    }
                    Ok(None) => {
                        // Key expired, try to reclaim
                        debug!(peer_id = %peer_id, "claim expired during refresh, attempting reclaim");
                        match kv.create(peer_id, value.clone()).await {
                            Ok(new_rev) => {
                                let mut claims_guard = claims.lock().await;
                                let _ = claims_guard.insert(peer_id.clone(), new_rev);
                                debug!(peer_id = %peer_id, "reclaimed expired peer");
                            }
                            Err(_) => {
                                let mut claims_guard = claims.lock().await;
                                let _ = claims_guard.remove(peer_id);
                                warn!(peer_id = %peer_id, "failed to reclaim expired peer");
                            }
                        }
                    }
                    _ => {
                        warn!(peer_id = %peer_id, error = %e, "failed to refresh claim");
                    }
                }
            }
        }
    }
}

/// Watch for expired/deleted claims and fire adoption callbacks.
async fn watch_expired_claims(
    kv: &async_nats::jetstream::kv::Store,
    pod_id: &str,
    claims: &Mutex<HashMap<String, u64>>,
    on_peer_available: Option<&OnPeerAvailable>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    use futures::StreamExt;

    let mut watcher = kv.watch_all().await.context("failed to start KV watch")?;

    loop {
        tokio::select! {
            entry = watcher.next() => {
                let Some(entry) = entry else {
                    debug!("claim watch stream ended");
                    return Ok(());
                };

                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(error = %e, "error reading claim watch entry");
                        continue;
                    }
                };

                // Only interested in deletions (claim expiry or explicit release)
                if entry.operation != async_nats::jetstream::kv::Operation::Delete
                    && entry.operation != async_nats::jetstream::kv::Operation::Purge
                {
                    continue;
                }

                let peer_id = entry.key.clone();

                // Don't try to adopt our own releases
                let we_owned_it = {
                    let local_claims = claims.lock().await;
                    local_claims.contains_key(&peer_id)
                };

                if we_owned_it {
                    continue;
                }

                debug!(
                    peer_id = %peer_id,
                    pod_id = %pod_id,
                    "detected expired claim, peer available for adoption"
                );

                if let Some(callback) = on_peer_available {
                    // Fire callback with jitter delay to prevent thundering herd
                    let callback = callback.clone();
                    let peer_id_owned = peer_id;
                    let jitter = ClaimManager::adoption_jitter();
                    drop(tokio::spawn(async move {
                        tokio::time::sleep(jitter).await;
                        callback(peer_id_owned);
                    }));
                }
            }
            _ = shutdown_rx.changed() => {
                debug!("claim watch loop shutting down");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
#[allow(unused_results)]
mod tests {
    use super::*;

    #[test]
    fn adopt_delay_is_30s() {
        assert_eq!(ClaimManager::adopt_delay(), Duration::from_secs(30));
    }

    #[test]
    fn adoption_jitter_is_bounded() {
        let jitter = ClaimManager::adoption_jitter();
        assert!(jitter < Duration::from_millis(MAX_ADOPT_JITTER_MS));
    }

    #[test]
    fn claim_bucket_name() {
        assert_eq!(CLAIM_BUCKET, "federation-claims");
    }

    #[test]
    fn constants_are_reasonable() {
        let ttl = CLAIM_TTL_SECS;
        let refresh = REFRESH_INTERVAL_SECS;
        let jitter = MAX_ADOPT_JITTER_MS;
        let adopt = ADOPT_DELAY_SECS;
        assert!(ttl > refresh, "TTL must exceed refresh interval");
        assert!(
            jitter < adopt * 1000,
            "jitter must be less than adopt delay"
        );
    }

    #[test]
    fn on_claim_lost_type_includes_fencing_token() {
        // Verify the OnClaimLost callback accepts (peer_id, stale_token)
        let called = Arc::new(std::sync::Mutex::new(None));
        let called_clone = called.clone();

        let callback: OnClaimLost = Arc::new(move |peer_id: String, token: u64| {
            *called_clone.lock().expect("lock") = Some((peer_id, token));
        });

        callback("peer-1".to_string(), 42);

        let result = called.lock().expect("lock").take();
        assert_eq!(result, Some(("peer-1".to_string(), 42)));
    }
}
