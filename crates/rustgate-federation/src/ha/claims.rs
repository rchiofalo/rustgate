// Copyright © 2026 Roberto Chiofalo.

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

use rustgate_core::PeerId;
use rustgate_core::masking::hash_cn;
use rustgate_core::tasks::spawn_background;
use tokio::sync::{Mutex, watch};
use tracing::{debug, info, warn};

use super::{ADOPT_DELAY_SECS, CLAIM_TTL_SECS, MAX_ADOPT_JITTER_MS, REFRESH_INTERVAL_SECS};
use crate::error::{FederationError, Result};

const CLAIM_BUCKET: &str = "federation-claims";

rustgate_core::on_callback!(
    /// Callback invoked when a peer becomes available for adoption
    /// (its claim expired due to pod death).
    ///
    /// F-113: receives a typed [`PeerId`] so downstream consumers (the HA
    /// adoption channel in `FederationManager`) cannot accidentally mix
    /// peer ids with other free-form strings (pod ids, server names).
    pub OnPeerAvailable,
    PeerId
);

rustgate_core::on_callback!(
    /// Callback invoked when a claim is lost to another pod.
    ///
    /// Arguments: `(peer_id, stale_fencing_token)`. The fencing token is the
    /// NATS KV revision that this pod held before the claim was lost.
    ///
    /// F-113: receives a typed [`PeerId`] for the same reason as
    /// [`OnPeerAvailable`].
    pub OnClaimLost,
    PeerId,
    u64
);

/// Manages distributed peer ownership using NATS JetStream KV.
///
/// Each outbound peer connection is "claimed" by exactly one pod.
/// Claims are maintained via KV entries with TTL. If a pod dies,
/// its claims expire and other pods can adopt the orphaned peers.
pub struct ClaimManager {
    kv: async_nats::jetstream::kv::Store,
    pod_id: String,
    // Single source of truth for claim state, shared with the background
    // refresh/watch tasks via `Arc` clone. Claims added after `start()` via
    // `try_claim` are visible to those tasks because both sides lock the
    // same `Arc<Mutex<..>>` — see issue #1494.
    claims: Arc<Mutex<HashMap<String, u64>>>, // peer_id → revision
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
            .map_err(|e| {
                FederationError::storage(format!(
                    "failed to create federation-claims KV bucket: {e}"
                ))
            })?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(Self {
            kv,
            pod_id,
            claims: Arc::new(Mutex::new(HashMap::new())),
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

        // Refresh loop: re-put all claims every REFRESH_INTERVAL_SECS.
        // Share the SAME `Arc<Mutex<..>>` as `self.claims` so claims added
        // after `start()` via `try_claim` are refreshed (issue #1494). A
        // cloned snapshot would freeze the refresh set at start time and let
        // later claims' TTL expire → split-brain.
        let kv = self.kv.clone();
        let pod_id = self.pod_id.clone();
        let claims_for_refresh = self.claims.clone();
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
        let claims_for_watch = self.claims.clone();
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
    ///
    /// F-113: takes a typed [`PeerId`] reference. The KV bucket key (a bare
    /// string) is derived via `peer_id.as_str()` so the wire format is
    /// unchanged.
    pub async fn try_claim(&self, peer_id: &PeerId) -> Option<u64> {
        let key = peer_id.as_str();
        let value = bytes::Bytes::from(self.pod_id.clone());

        match self.kv.create(key, value.clone()).await {
            Ok(revision) => {
                let mut claims = self.claims.lock().await;
                let _ = claims.insert(key.to_string(), revision);
                info!(peer_id = %hash_cn(key), pod_id = %self.pod_id, fence = revision, "claimed peer");
                Some(revision)
            }
            Err(_) => {
                // Key exists — check if we already own it (e.g., from a previous run)
                match self.kv.entry(key).await {
                    Ok(Some(entry)) if entry.value == self.pod_id.as_bytes() => {
                        let mut claims = self.claims.lock().await;
                        let _ = claims.insert(key.to_string(), entry.revision);
                        debug!(peer_id = %hash_cn(key), fence = entry.revision, "reclaimed own peer");
                        Some(entry.revision)
                    }
                    _ => {
                        debug!(peer_id = %hash_cn(key), "peer already claimed by another pod");
                        None
                    }
                }
            }
        }
    }

    /// Return the fencing token (NATS KV revision) for a claimed peer.
    ///
    /// Returns `None` if this pod does not own the claim.
    pub async fn fencing_token(&self, peer_id: &PeerId) -> Option<u64> {
        let claims = self.claims.lock().await;
        claims.get(peer_id.as_str()).copied()
    }

    /// Check whether the given fencing token is still the current claim revision.
    ///
    /// Returns `true` if this pod still holds the claim with the given token
    /// (or a newer one). Returns `false` if the claim has been lost.
    pub async fn is_token_valid(&self, peer_id: &PeerId, token: u64) -> bool {
        let claims = self.claims.lock().await;
        match claims.get(peer_id.as_str()) {
            Some(&current) => current >= token,
            None => false,
        }
    }

    /// Release a claim, allowing other pods to adopt the peer.
    pub async fn release(&self, peer_id: &PeerId) -> Result<()> {
        let key = peer_id.as_str();
        let mut claims = self.claims.lock().await;
        let _ = claims.remove(key);
        drop(claims);

        self.kv.delete(key).await.map_err(|e| {
            FederationError::storage(format!("failed to delete claim from KV: {e}"))
        })?;

        info!(peer_id = %hash_cn(key), pod_id = %self.pod_id, "released peer claim");
        Ok(())
    }

    /// Check if this pod owns the claim for a peer.
    pub async fn is_owner(&self, peer_id: &PeerId) -> bool {
        let claims = self.claims.lock().await;
        claims.contains_key(peer_id.as_str())
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
                        peer_id = %hash_cn(peer_id),
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
                            // Convert to typed `PeerId` at the callback boundary;
                            // local-cache keys remain `String` for HashMap lookup.
                            callback(PeerId::new(peer_id.as_str()), *revision);
                        }
                    }
                    Ok(None) => {
                        // Key expired, try to reclaim
                        debug!(peer_id = %hash_cn(peer_id), "claim expired during refresh, attempting reclaim");
                        match kv.create(peer_id, value.clone()).await {
                            Ok(new_rev) => {
                                let mut claims_guard = claims.lock().await;
                                let _ = claims_guard.insert(peer_id.clone(), new_rev);
                                debug!(peer_id = %hash_cn(peer_id), "reclaimed expired peer");
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

    let mut watcher = kv
        .watch_all()
        .await
        .map_err(|e| FederationError::storage(format!("failed to start KV watch: {e}")))?;

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
                    peer_id = %hash_cn(&peer_id),
                    pod_id = %pod_id,
                    "detected expired claim, peer available for adoption"
                );

                if let Some(callback) = on_peer_available {
                    // Fire callback with jitter delay to prevent thundering herd
                    let callback = callback.clone();
                    let peer_id_owned: PeerId = PeerId::new(peer_id);
                    let jitter = ClaimManager::adoption_jitter();
                    spawn_background("fed-claim-adoption", async move {
                        tokio::time::sleep(jitter).await;
                        callback(peer_id_owned);
                    });
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
        // Verify the OnClaimLost callback accepts (peer_id, stale_token).
        // F-113: receiver expects a typed `PeerId`, not a free `String`.
        let called = Arc::new(std::sync::Mutex::new(None));
        let called_clone = called.clone();

        let callback: OnClaimLost = Arc::new(move |peer_id: PeerId, token: u64| {
            *called_clone.lock().expect("lock") = Some((peer_id, token));
        });

        callback(PeerId::new("peer-1"), 42);

        let result = called.lock().expect("lock").take();
        assert_eq!(result, Some((PeerId::new("peer-1"), 42)));
    }

    // ── OnPeerAvailable contract pins ──────────────────────────────────
    //
    // The existing suite only exercises `OnClaimLost`; the sibling alias
    // `OnPeerAvailable` (fired when a foreign pod's claim expires and the
    // peer becomes adoptable) had no functional test. A regression that
    // narrowed the signature to `Fn(&str)` — cheap to type, catastrophic
    // to wire — would not compile at call sites but would pass every
    // existing test in this module silently.

    #[test]
    fn on_peer_available_callback_fires_with_owned_peer_id() {
        // F-113: `OnPeerAvailable` carries a typed `PeerId`. Pin both the
        // signature (compile-time, via the explicit `PeerId` annotation in
        // the closure) and the round-trip identity at the callback boundary.
        let seen = Arc::new(std::sync::Mutex::new(None));
        let seen_clone = seen.clone();

        let callback: OnPeerAvailable = Arc::new(move |peer_id: PeerId| {
            *seen_clone.lock().expect("lock") = Some(peer_id);
        });

        callback(PeerId::new("orphaned-peer"));

        let result = seen.lock().expect("lock").take();
        assert_eq!(result, Some(PeerId::new("orphaned-peer")));
    }

    // ── Callback-bound compile-time pins ───────────────────────────────
    //
    // Both callback aliases flow across task boundaries: `OnPeerAvailable`
    // is moved into a `tokio::spawn` block after a jittered sleep inside
    // `watch_expired_claims`, and `OnClaimLost` is called from inside the
    // refresh loop's `tokio::select!`. A regression that dropped `Send`
    // or `Sync` or narrowed the lifetime away from `'static` would only
    // surface at those call sites — pinning the bounds at the module's
    // own test harness fails the offending edit at the first-level build
    // rather than after a `spawn` somewhere else in the crate refuses to
    // compile.

    #[test]
    fn on_peer_available_type_satisfies_send_sync_static_bound() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<OnPeerAvailable>();
    }

    #[test]
    fn on_claim_lost_type_satisfies_send_sync_static_bound() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<OnClaimLost>();
    }

    // ── Callback Arc-cloneability ──────────────────────────────────────
    //
    // `OnPeerAvailable = Arc<dyn Fn(String) + Send + Sync>` and its sibling
    // are cloned into per-claim spawn blocks inside `watch_expired_claims`
    // (the closure is moved into a `tokio::spawn` after being cloned once
    // per expiry event). A regression that changed the alias to a bare
    // `Box<dyn Fn ...>` would still satisfy the functional signature tests
    // above but would fail at that clone site. Pin the Arc-shared-closure
    // contract by holding two handles, firing each, and asserting both
    // routes observe the same inner state.

    #[test]
    fn callback_arcs_can_be_cloned_independently_and_fire_shared_closure() {
        let counter = Arc::new(std::sync::Mutex::new(0u32));
        let counter_for_closure = counter.clone();

        let original: OnPeerAvailable = Arc::new(move |_peer_id: PeerId| {
            let mut guard = counter_for_closure.lock().expect("lock");
            *guard += 1;
        });
        let cloned = original.clone();

        // Both handles point at the same underlying closure.
        assert_eq!(
            Arc::strong_count(&original),
            2,
            "clone must bump the strong count, not wrap in an outer Arc"
        );

        original(PeerId::new("peer-A"));
        cloned(PeerId::new("peer-B"));

        let final_count = *counter.lock().expect("lock");
        assert_eq!(
            final_count, 2,
            "both Arc handles must route through the same captured mutex"
        );
    }

    // ── adoption_jitter distribution pins ──────────────────────────────
    //
    // The existing suite calls `adoption_jitter()` exactly once and asserts
    // the sample is below `MAX_ADOPT_JITTER_MS`. That catches only the
    // pathological "always returns a huge duration" regression. Two
    // defensive-invariant gaps remain: (a) the helper could regress to a
    // fixed constant (e.g. an editor accidentally deleting the modulo and
    // leaving `Duration::from_millis(0)`), silently defeating the
    // thundering-herd mitigation the documentation advertises; and (b) a
    // refactor that changed the modulus to a type-narrow `u32` or flipped
    // the operand order could push a single call beyond the bound on a
    // subsec_nanos value close to `u32::MAX`. Many-sample tests close both
    // gaps — a single degenerate run cannot satisfy both "distinct values
    // observed" and "no sample exceeds the bound" simultaneously unless
    // the formula is healthy.

    #[test]
    fn adoption_jitter_stays_strictly_below_max_across_many_samples() {
        // 2048 samples at ~1µs each exercises a ~2ms span of subsec_nanos
        // values — enough for the modulo to cycle through the full output
        // range several times. Every single one must still honour the
        // bound.
        let max = Duration::from_millis(MAX_ADOPT_JITTER_MS);
        for _ in 0..2048 {
            let jitter = ClaimManager::adoption_jitter();
            assert!(
                jitter < max,
                "adoption_jitter returned {jitter:?}, must be < {max:?}"
            );
        }
    }

    #[test]
    fn adoption_jitter_samples_span_more_than_one_distinct_value() {
        // If the helper ever regressed to a constant (deleted modulo, hard
        // coded zero, or the `subsec_nanos` source was accidentally
        // replaced with a field that returns the same value every call),
        // the distinct-value count across a modest sample would collapse
        // to one and fail here. The assertion is probabilistic in the
        // formal sense — subsec_nanos can in principle repeat — but the
        // ~512µs span covered by 512 sequential calls at microsecond
        // resolution makes a degenerate collapse astronomically unlikely
        // on any platform whose `SystemTime::now()` resolves at even
        // millisecond granularity.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..512 {
            let _ = seen.insert(ClaimManager::adoption_jitter());
        }
        assert!(
            seen.len() > 1,
            "adoption_jitter produced only {} distinct value(s) across 512 samples \
             — the thundering-herd mitigation has regressed to a constant",
            seen.len()
        );
    }

    // ── Constant cross-coherence pins ──────────────────────────────────
    //
    // The existing `constants_are_reasonable` pins `TTL > refresh` and
    // `jitter < adopt * 1000`. Two stronger invariants the module docs
    // imply but no test enforces: (a) the claim lifecycle doc advertises
    // "re-puts every 10s to keep the 30s TTL alive" — operationally this
    // requires the TTL to survive at least *one* missed refresh (e.g. a
    // brief NATS hiccup), so `CLAIM_TTL_SECS >= 2 * REFRESH_INTERVAL_SECS`
    // is the design-motivated invariant; (b) every duration constant in
    // this module is meant as a positive interval — a zero-sentinel
    // regression on any of them silently breaks the module (zero refresh
    // spins hot, zero TTL expires instantly, zero jitter defeats the
    // herd-mitigation contract, zero adopt delay skips the documented
    // remote-cleanup window).

    #[test]
    fn claim_ttl_permits_at_least_two_full_refresh_windows_before_expiry() {
        // Stronger than `TTL > refresh` (the existing invariant). The
        // lifecycle contract requires surviving at least one missed
        // refresh without losing the claim — so TTL must be at least
        // *two* refresh intervals. At 30s TTL / 10s refresh the margin
        // is three refreshes; the assertion is the lower bound.
        //
        // Wrapped in `const { … }` so the assertion fires at
        // compile time (every operand is a `const u64`) rather than
        // at test-binary startup.
        const {
            assert!(
                CLAIM_TTL_SECS >= 2 * REFRESH_INTERVAL_SECS,
                "CLAIM_TTL_SECS must be >= 2 * REFRESH_INTERVAL_SECS so one missed refresh does not expire the claim"
            );
        }
    }

    #[test]
    fn ha_duration_constants_are_all_strictly_positive() {
        // Every operand is a `const u64`, so the assertions are const-
        // evaluated and fire at compile time in the `const { … }`
        // block. The failure messages still surface to the operator
        // via the rustc diagnostic when a regression lands.
        const {
            assert!(CLAIM_TTL_SECS > 0, "CLAIM_TTL_SECS must be > 0");
        }
        const {
            assert!(
                REFRESH_INTERVAL_SECS > 0,
                "REFRESH_INTERVAL_SECS must be > 0 (zero would busy-loop the refresh task)"
            );
        }
        const {
            assert!(
                MAX_ADOPT_JITTER_MS > 0,
                "MAX_ADOPT_JITTER_MS must be > 0 (zero defeats the thundering-herd mitigation)"
            );
        }
        const {
            assert!(
                ADOPT_DELAY_SECS > 0,
                "ADOPT_DELAY_SECS must be > 0 (zero skips the documented remote-cleanup window)"
            );
        }
    }
}
