// Copyright © 2026 Roberto Chiofalo.

//! Per-tenant resource quota tracking and enforcement.
//!
//! Tracks active connections per tenant (identified by the certificate
//! Organization field) and enforces configurable limits. Quota
//! configuration is loaded from a JSON file and can be hot-reloaded
//! via `ArcSwap` on the router.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use dashmap::DashMap;
use parking_lot::RwLock;
use rustgate_resilience::token_bucket::{TokenBucket, TokenBucketRejection};
use serde::Deserialize;

/// Sentinel tenant key used when a connection has no explicit tenant
/// (i.e. `Identity.tenant` is `None`). Mapped to `default_quota` if
/// one is configured.
pub const DEFAULT_TENANT_KEY: &str = "__default__";

/// Resource limits for a single tenant.
///
/// Uses `deny_unknown_fields` to reject quota entries containing
/// unexpected properties — a typo like `"max_connectons"` produces a
/// clear deserialization error instead of being silently ignored,
/// which is critical for a security-relevant cap (#815, F-136).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantQuota {
    /// Maximum concurrent connections. 0 = unlimited.
    #[serde(default)]
    pub max_connections: u32,
    /// Reserved for future per-tenant message rate limiting. Not yet enforced.
    #[serde(default)]
    pub max_message_rate: u32,
    /// Maximum bytes that may be queued at any instant across all egress
    /// paths (router broadcast, HTTP publisher, NATS bridge, federation
    /// outbound) for this tenant. 0 = unlimited. Used by
    /// [`TenantQuotaTracker::try_reserve_bytes`] to prevent a single noisy
    /// tenant from exhausting the global [`crate::backpressure::BackpressureGate`].
    #[serde(default)]
    pub max_queued_bytes: u64,
    /// Per-tenant aggregate-throughput cap, in bytes per second
    /// (issue #883 sub-item 4). Sums payload bytes across every active
    /// session for the tenant. `0` (the default) disables the
    /// per-tenant throughput limiter for this entry — callers fall
    /// through to whatever per-session bucket the listener already
    /// applies. When set, a message is admitted only if the bucket
    /// has at least `payload.len()` tokens at evaluation time.
    #[serde(default)]
    pub max_throughput_bps: u64,
    /// Bucket refill rate, in bytes per second (issue #883 sub-item
    /// 4). `0` (the default) is "no refill" — the bucket starts full
    /// at `max_throughput_bps` and stays drained until the operator
    /// hot-reloads the config, which is the correct semantic for a
    /// hard ceiling. Set greater than zero for steady-state
    /// throughput: every second the bucket reclaims `refill_throughput_bps`
    /// tokens up to the cap, so a tenant gets sustained throughput
    /// at that rate plus a burst capacity equal to
    /// `max_throughput_bps`.
    #[serde(default)]
    pub refill_throughput_bps: u64,
}

/// Quota configuration loaded from file.
///
/// Uses `deny_unknown_fields` to reject quota files containing
/// unexpected top-level keys — a typo like `"tenats"` would otherwise
/// silently parse as an empty map and leave every tenant unlimited
/// (#815, F-136).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaConfig {
    /// Per-tenant quotas keyed by tenant name (cert Organization).
    #[serde(default)]
    pub tenants: HashMap<String, TenantQuota>,
    /// Default quota applied when tenant has no specific entry.
    pub default_quota: Option<TenantQuota>,
}

/// Per-tenant counters for live tracking.
#[derive(Debug, Default)]
struct TenantCounters {
    active_connections: AtomicU32,
    /// Bytes currently reserved on egress queues for this tenant. Parallel
    /// to `active_connections` but governed by `max_queued_bytes`.
    queued_bytes: AtomicUsize,
}

/// Callback fired once per per-tenant throughput-bucket rejection
/// (issue #883 sub-item 4). The single argument is the tenant key.
/// Wired by the server binary to feed the
/// `rustgate_tenant_throughput_rejections_total{tenant}` Prometheus
/// counter; left unset, the rejection still emits the
/// [`rustgate_core::audit::tenant_throughput_exceeded`] event but no
/// metric increment.
///
/// Hot-reloadable via `ArcSwap` on the tracker so the server can
/// install it once at startup without holding a lock on the routing
/// hot path.
pub type OnTenantThroughputRejection = Arc<dyn Fn(&str) + Send + Sync>;

/// Callback fired after each per-tenant throughput acquire (admit OR
/// reject) with the post-decision token level in bytes (issue #883
/// sub-item 4). The first argument is the tenant key, the second is
/// the bucket's current available tokens. Wired by the server binary
/// to feed the `rustgate_tenant_throughput_bps{tenant}` gauge so an
/// operator can visualize headroom in real time.
pub type OnTenantThroughputConsumed = Arc<dyn Fn(&str, f64) + Send + Sync>;

/// Tracks and enforces per-tenant resource quotas.
///
/// Designed to be wrapped in `Arc` and shared across the router and
/// session lifecycle. Connection tracking is lock-free on the hot path
/// (atomic increment/decrement); the `RwLock` only guards the counter
/// map when a new tenant is first seen.
///
/// The aggregate-throughput bucket map (issue #883 sub-item 4) uses
/// [`DashMap`] for lock-free per-tenant access on the message-send hot
/// path — a single `parking_lot::RwLock<HashMap<…>>` would serialize
/// every tenant's send through the same shard, defeating the whole
/// point of *per*-tenant isolation when one tenant happens to be at
/// its cap and is continuously triggering the slow path.
pub struct TenantQuotaTracker {
    config: QuotaConfig,
    counters: RwLock<HashMap<String, Arc<TenantCounters>>>,
    /// Per-tenant aggregate-throughput buckets (issue #883 sub-item 4).
    /// Created lazily on first send for each tenant; entries persist
    /// until [`TenantQuotaTracker`] drops. The map is bounded by
    /// distinct tenant identifiers (cert Organization), which a
    /// CN-churning attacker cannot inflate.
    throughput_buckets: DashMap<Arc<str>, Arc<TokenBucket>>,
    on_throughput_rejection: arc_swap::ArcSwap<Option<OnTenantThroughputRejection>>,
    on_throughput_consumed: arc_swap::ArcSwap<Option<OnTenantThroughputConsumed>>,
}

impl std::fmt::Debug for TenantQuotaTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom Debug to skip the callback ArcSwap (no useful Debug)
        // and to surface the throughput bucket map size for diagnostics
        // without enumerating every entry.
        f.debug_struct("TenantQuotaTracker")
            .field("config", &self.config)
            .field("counter_tenants", &self.counters.read().len())
            .field("throughput_tenants", &self.throughput_buckets.len())
            .finish_non_exhaustive()
    }
}

impl TenantQuotaTracker {
    /// Create a new tracker with the given configuration.
    pub fn new(config: QuotaConfig) -> Self {
        Self {
            config,
            counters: RwLock::new(HashMap::new()),
            throughput_buckets: DashMap::new(),
            on_throughput_rejection: arc_swap::ArcSwap::from_pointee(None),
            on_throughput_consumed: arc_swap::ArcSwap::from_pointee(None),
        }
    }

    /// Install (or replace) the per-tenant throughput-rejection
    /// metrics callback (issue #883 sub-item 4). Hot-reloadable via
    /// `ArcSwap`. Pass `None` to clear.
    pub fn set_on_throughput_rejection(&self, cb: Option<OnTenantThroughputRejection>) {
        self.on_throughput_rejection.store(Arc::new(cb));
    }

    /// Install (or replace) the per-tenant throughput-consumed
    /// metrics callback (issue #883 sub-item 4). Hot-reloadable via
    /// `ArcSwap`. Pass `None` to clear.
    pub fn set_on_throughput_consumed(&self, cb: Option<OnTenantThroughputConsumed>) {
        self.on_throughput_consumed.store(Arc::new(cb));
    }

    /// Look up the quota for a tenant, falling back to the default.
    pub fn quota_for(&self, tenant: &str) -> Option<&TenantQuota> {
        self.config
            .tenants
            .get(tenant)
            .or(self.config.default_quota.as_ref())
    }

    /// Atomically check whether a new connection is within quota AND
    /// increment the counter if so. Uses a compare-and-swap loop to
    /// prevent the TOCTOU race between separate check + record calls.
    ///
    /// Returns `true` if the connection was admitted, `false` if the
    /// tenant is at or above its `max_connections` limit.
    pub fn check_and_record_connection(&self, tenant: &str) -> bool {
        let quota = match self.quota_for(tenant) {
            Some(q) => q,
            // No quota configured for this tenant and no default: allow.
            None => return true,
        };

        // 0 means unlimited -- still record the connection for tracking.
        let max = quota.max_connections;
        if max == 0 {
            self.record_connect_inner(tenant);
            return true;
        }

        // Fast path: counter already exists -- CAS loop.
        {
            let counters = self.counters.read();
            if let Some(c) = counters.get(tenant) {
                return Self::cas_increment(&c.active_connections, max);
            }
        }
        // Slow path: create counter entry then CAS.
        let mut counters = self.counters.write();
        let entry = counters
            .entry(tenant.to_owned())
            .or_insert_with(|| Arc::new(TenantCounters::default()));
        Self::cas_increment(&entry.active_connections, max)
    }

    /// CAS loop: atomically increment if below `max`.
    fn cas_increment(counter: &AtomicU32, max: u32) -> bool {
        loop {
            let current = counter.load(Ordering::Relaxed);
            if current >= max {
                return false;
            }
            if counter
                .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Record a new connection for `tenant`. Increments the active
    /// connection counter unconditionally (used only for unlimited quotas).
    fn record_connect_inner(&self, tenant: &str) {
        // Fast path: counter already exists.
        {
            let counters = self.counters.read();
            if let Some(c) = counters.get(tenant) {
                let _ = c.active_connections.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Slow path: create a new counter entry.
        let mut counters = self.counters.write();
        let entry = counters
            .entry(tenant.to_owned())
            .or_insert_with(|| Arc::new(TenantCounters::default()));
        let _ = entry.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a disconnection for `tenant`. Decrements the active
    /// connection counter with saturating subtract to prevent underflow.
    pub fn record_disconnect(&self, tenant: &str) {
        let counters = self.counters.read();
        if let Some(c) = counters.get(tenant) {
            let _ = c
                .active_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                });
        }
    }

    /// Current active connection count for a tenant.
    pub fn active_connections(&self, tenant: &str) -> u32 {
        let counters = self.counters.read();
        counters
            .get(tenant)
            .map(|c| c.active_connections.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Attempt to reserve `bytes` worth of egress queue capacity for
    /// `tenant`. Returns a [`TenantBytePermit`] on success; the permit
    /// releases the reservation automatically when dropped.
    ///
    /// Returns `None` if the tenant's `max_queued_bytes` would be exceeded,
    /// OR if the tenant has no quota configured (no entry in `tenants` and
    /// no `default_quota`). Callers that want to fall through to the global
    /// gate in the no-config case should treat `None` as "no per-tenant
    /// accounting applies", not as a rejection.
    ///
    /// A `max_queued_bytes` value of `0` is treated as unlimited, matching
    /// the semantics of `max_connections`. In that case the reservation
    /// is still tracked so operators can observe real-time byte usage.
    pub fn try_reserve_bytes(
        self: &Arc<Self>,
        tenant: &str,
        bytes: usize,
    ) -> Option<TenantBytePermit> {
        let quota = self.quota_for(tenant)?;
        let max = quota.max_queued_bytes;

        // Fast path: counter already exists.
        {
            let counters = self.counters.read();
            if let Some(c) = counters.get(tenant)
                && Self::try_add_bytes(&c.queued_bytes, bytes, max)
            {
                return Some(TenantBytePermit::new(
                    Arc::clone(self),
                    tenant.to_owned(),
                    bytes,
                ));
            }
            if counters.get(tenant).is_some() {
                // Counter exists but was at/above the cap.
                return None;
            }
        }

        // Slow path: create counter entry then CAS.
        let mut counters = self.counters.write();
        let entry = counters
            .entry(tenant.to_owned())
            .or_insert_with(|| Arc::new(TenantCounters::default()));
        if Self::try_add_bytes(&entry.queued_bytes, bytes, max) {
            Some(TenantBytePermit::new(
                Arc::clone(self),
                tenant.to_owned(),
                bytes,
            ))
        } else {
            None
        }
    }

    /// CAS loop: atomically add `n` to `counter` if the result would stay
    /// at or below `max` (treating `max == 0` as unlimited). Saturates at
    /// `usize::MAX` on overflow to avoid wraparound.
    fn try_add_bytes(counter: &AtomicUsize, n: usize, max: u64) -> bool {
        loop {
            let current = counter.load(Ordering::Relaxed);
            let new = current.saturating_add(n);
            if max > 0 && (new as u64) > max {
                return false;
            }
            if counter
                .compare_exchange_weak(current, new, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Release `bytes` of previously reserved egress queue capacity for
    /// `tenant`. Saturates at zero to prevent underflow on over-release.
    fn release_bytes(&self, tenant: &str, bytes: usize) {
        let counters = self.counters.read();
        if let Some(c) = counters.get(tenant) {
            let _ = c
                .queued_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(bytes))
                });
        }
    }

    /// Current queued-byte reservation for a tenant.
    pub fn queued_bytes(&self, tenant: &str) -> usize {
        let counters = self.counters.read();
        counters
            .get(tenant)
            .map(|c| c.queued_bytes.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Load a `QuotaConfig` from a JSON file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_config(
        path: &std::path::Path,
    ) -> std::result::Result<QuotaConfig, Box<dyn std::error::Error + Send + Sync>> {
        let data = std::fs::read_to_string(path)?;
        let config: QuotaConfig = serde_json::from_str(&data)?;
        Ok(config)
    }

    /// Lazily fetch (or create) the per-tenant aggregate-throughput
    /// bucket (issue #883 sub-item 4). Returns `None` when the tenant
    /// has no quota at all (no entry, no default) OR when its
    /// `max_throughput_bps` is `0` — both cases mean "no per-tenant
    /// throughput cap applies", and the caller should fall through to
    /// whatever per-session bucket the listener already owns.
    ///
    /// Uses [`DashMap::entry`] so the lookup-then-insert runs under a
    /// single shard lock, not a global mutex — the same pattern the
    /// router's per-CN replay-bucket map uses (router.rs,
    /// issue #836). The `or_insert_with` closure builds the
    /// [`TokenBucket`] lazily so the common-path return-existing case
    /// pays only the `DashMap::get` cost.
    fn throughput_bucket_for(&self, tenant: &str) -> Option<Arc<TokenBucket>> {
        let quota = self.quota_for(tenant)?;
        let cap = quota.max_throughput_bps;
        if cap == 0 {
            return None;
        }
        // `refill == 0` is the documented "no refill" semantic — the
        // bucket starts full at `cap` and stays drained until the
        // operator reloads the config. This is the correct default
        // for a hard ceiling: the only way to get more than `cap`
        // bytes per (config-reload-window) is to explicitly set a
        // non-zero refill rate.
        let refill = quota.refill_throughput_bps as f64;
        if let Some(existing) = self.throughput_buckets.get(tenant) {
            return Some(Arc::clone(existing.value()));
        }
        let entry = self
            .throughput_buckets
            .entry(Arc::<str>::from(tenant))
            .or_insert_with(|| Arc::new(TokenBucket::new(refill, Some(cap as f64))));
        Some(Arc::clone(entry.value()))
    }

    /// Attempt to charge `tokens` (bytes) against the per-tenant
    /// aggregate-throughput bucket (issue #883 sub-item 4).
    ///
    /// Returns `Ok(())` when the bucket admitted the request. Returns
    /// `Err(TenantThroughputRejection { tenant, requested, available })`
    /// when the bucket had fewer than `tokens` available; the caller
    /// is expected to drop the message and emit
    /// [`rustgate_core::audit::tenant_throughput_exceeded`].
    ///
    /// When the tenant has no quota configured (no entry and no
    /// default) OR the configured `max_throughput_bps` is `0`, this
    /// method admits the request with `Ok(())` — the per-tenant
    /// limiter is a *layer on top of* the per-session limiter, not a
    /// replacement, and a tenant with no quota entry must not be
    /// rate-limited at all by this layer.
    ///
    /// The implementation captures the bucket's `available` count
    /// from the rejection result rather than re-reading via
    /// [`TokenBucket::current_tokens`] so the audit attribution is
    /// race-free against concurrent acquires.
    ///
    /// # Errors
    ///
    /// Returns [`TenantThroughputRejection`] when the bucket holds
    /// fewer than `tokens` after lazy refill.
    pub fn try_acquire_tenant_tokens(
        &self,
        tenant: &str,
        tokens: u64,
    ) -> Result<(), TenantThroughputRejection> {
        let Some(bucket) = self.throughput_bucket_for(tenant) else {
            // No per-tenant cap configured: admit so the caller falls
            // through to the per-session bucket only. Issue #883 explicitly
            // calls this out as the "wire-format compat" path for
            // existing deployments without the new TOML keys.
            return Ok(());
        };
        let result = bucket.try_acquire_n(tokens as f64);
        match result {
            Ok(()) => {
                let consumed_guard = self.on_throughput_consumed.load();
                if let Some(cb) = (**consumed_guard).as_ref() {
                    cb(tenant, bucket.current_tokens());
                }
                Ok(())
            }
            Err(TokenBucketRejection { available }) => {
                let rej_guard = self.on_throughput_rejection.load();
                if let Some(cb) = (**rej_guard).as_ref() {
                    cb(tenant);
                }
                let consumed_guard = self.on_throughput_consumed.load();
                if let Some(cb) = (**consumed_guard).as_ref() {
                    cb(tenant, available);
                }
                // Cast back to u64 for the audit-event field — the
                // bucket only ever holds non-negative whole-byte
                // counts so the precision loss is the rounding of a
                // sub-byte fractional remainder, which is operationally
                // irrelevant.
                Err(TenantThroughputRejection {
                    tenant: tenant.to_owned(),
                    requested: tokens,
                    available: available as u64,
                })
            }
        }
    }

    /// Number of tenants currently holding a throughput bucket.
    /// Test-only observation.
    #[cfg(test)]
    fn throughput_bucket_count(&self) -> usize {
        self.throughput_buckets.len()
    }

    /// Snapshot the current per-tenant aggregate throughput-bucket
    /// level (in bytes). Returns `None` if the tenant has no
    /// throughput cap configured. Used by metrics gauge code paths
    /// that want to publish "current bucket headroom" rather than
    /// only reacting to per-message callbacks.
    pub fn tenant_throughput_available(&self, tenant: &str) -> Option<f64> {
        self.throughput_bucket_for(tenant)
            .map(|b| b.current_tokens())
    }
}

/// Rejection returned by
/// [`TenantQuotaTracker::try_acquire_tenant_tokens`] when the
/// per-tenant aggregate-throughput bucket cannot fund the request.
///
/// `requested` and `available` are both in bytes; emit them on the
/// [`rustgate_core::audit::tenant_throughput_exceeded`] event so the
/// SIEM trail records both sides of the budget at decision time.
#[derive(Debug, Clone)]
pub struct TenantThroughputRejection {
    /// Tenant key the request was charged against.
    pub tenant: String,
    /// Bytes the message asked for.
    pub requested: u64,
    /// Bytes the bucket held when the rejection was decided (after
    /// lazy refill, before any decrement).
    pub available: u64,
}

impl std::fmt::Display for TenantThroughputRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tenant `{}` throughput exceeded: requested={}B, available={}B",
            self.tenant, self.requested, self.available
        )
    }
}

impl std::error::Error for TenantThroughputRejection {}

/// RAII guard that releases a tenant byte reservation on drop.
///
/// Acquired via [`TenantQuotaTracker::try_reserve_bytes`]. Designed to be
/// attached to in-flight egress envelopes (HTTP publisher queue entries,
/// NATS publish tasks, federation outbound messages) so that droppedor
/// completed messages release their reservation automatically —
/// including panics inside the egress pipeline.
///
/// # Design
///
/// The permit holds a reference back to the tracker via `Arc` so that
/// `Drop` never panics even if callers lose their tracker reference
/// first. It is sized-on-acquire (the reservation count is captured at
/// construction time), so mutating `bytes` after acquisition is not
/// supported — acquire a new permit instead.
#[must_use = "dropping the permit immediately releases the reservation"]
pub struct TenantBytePermit {
    tracker: Arc<TenantQuotaTracker>,
    tenant: String,
    bytes: usize,
}

impl TenantBytePermit {
    fn new(tracker: Arc<TenantQuotaTracker>, tenant: String, bytes: usize) -> Self {
        Self {
            tracker,
            tenant,
            bytes,
        }
    }

    /// Number of bytes reserved by this permit.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Tenant key this permit belongs to.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
}

impl std::fmt::Debug for TenantBytePermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantBytePermit")
            .field("tenant", &self.tenant)
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Drop for TenantBytePermit {
    fn drop(&mut self) {
        self.tracker.release_bytes(&self.tenant, self.bytes);
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn config_with_tenant(tenant: &str, max_conn: u32) -> QuotaConfig {
        let mut tenants = HashMap::new();
        let _ = tenants.insert(
            tenant.to_string(),
            TenantQuota {
                max_connections: max_conn,
                max_message_rate: 0,
                max_queued_bytes: 0,
                max_throughput_bps: 0,
                refill_throughput_bps: 0,
            },
        );
        QuotaConfig {
            tenants,
            default_quota: None,
        }
    }

    fn config_with_byte_quota(tenant: &str, max_queued_bytes: u64) -> QuotaConfig {
        let mut tenants = HashMap::new();
        let _ = tenants.insert(
            tenant.to_string(),
            TenantQuota {
                max_connections: 0,
                max_message_rate: 0,
                max_queued_bytes,
                max_throughput_bps: 0,
                refill_throughput_bps: 0,
            },
        );
        QuotaConfig {
            tenants,
            default_quota: None,
        }
    }

    fn config_with_throughput(tenant: &str, cap_bps: u64, refill_bps: u64) -> QuotaConfig {
        let mut tenants = HashMap::new();
        let _ = tenants.insert(
            tenant.to_string(),
            TenantQuota {
                max_connections: 0,
                max_message_rate: 0,
                max_queued_bytes: 0,
                max_throughput_bps: cap_bps,
                refill_throughput_bps: refill_bps,
            },
        );
        QuotaConfig {
            tenants,
            default_quota: None,
        }
    }

    #[test]
    fn check_and_record_allows_under_limit() {
        let tracker = TenantQuotaTracker::new(config_with_tenant("acme", 3));
        assert!(tracker.check_and_record_connection("acme"));
        assert!(tracker.check_and_record_connection("acme"));
        assert!(tracker.check_and_record_connection("acme"));
        assert_eq!(tracker.active_connections("acme"), 3);
        // At limit -- next should fail.
        assert!(!tracker.check_and_record_connection("acme"));
    }

    #[test]
    fn check_and_record_rejects_at_limit() {
        let tracker = TenantQuotaTracker::new(config_with_tenant("acme", 2));
        assert!(tracker.check_and_record_connection("acme"));
        assert!(tracker.check_and_record_connection("acme"));
        assert!(!tracker.check_and_record_connection("acme"));
    }

    #[test]
    fn disconnect_frees_slot() {
        let tracker = TenantQuotaTracker::new(config_with_tenant("acme", 1));
        assert!(tracker.check_and_record_connection("acme"));
        assert!(!tracker.check_and_record_connection("acme"));
        tracker.record_disconnect("acme");
        assert!(tracker.check_and_record_connection("acme"));
    }

    #[test]
    fn disconnect_saturates_at_zero() {
        let tracker = TenantQuotaTracker::new(config_with_tenant("acme", 10));
        // Disconnect without any prior connect -- should not underflow.
        tracker.record_disconnect("acme");
        // If it wrapped to u32::MAX the next check would fail.
        assert!(tracker.check_and_record_connection("acme"));
        assert_eq!(tracker.active_connections("acme"), 1);
    }

    #[test]
    fn unknown_tenant_no_default_allows() {
        let tracker = TenantQuotaTracker::new(QuotaConfig {
            tenants: HashMap::new(),
            default_quota: None,
        });
        assert!(tracker.check_and_record_connection("unknown-org"));
    }

    #[test]
    fn default_quota_applies_to_unknown() {
        let config = QuotaConfig {
            tenants: HashMap::new(),
            default_quota: Some(TenantQuota {
                max_connections: 1,
                max_message_rate: 0,
                max_queued_bytes: 0,
                max_throughput_bps: 0,
                refill_throughput_bps: 0,
            }),
        };
        let tracker = TenantQuotaTracker::new(config);
        assert!(tracker.check_and_record_connection("unknown"));
        assert!(!tracker.check_and_record_connection("unknown"));
    }

    #[test]
    fn default_tenant_key_applies_default_quota() {
        let config = QuotaConfig {
            tenants: HashMap::new(),
            default_quota: Some(TenantQuota {
                max_connections: 2,
                max_message_rate: 0,
                max_queued_bytes: 0,
                max_throughput_bps: 0,
                refill_throughput_bps: 0,
            }),
        };
        let tracker = TenantQuotaTracker::new(config);
        assert!(tracker.check_and_record_connection(DEFAULT_TENANT_KEY));
        assert!(tracker.check_and_record_connection(DEFAULT_TENANT_KEY));
        assert!(!tracker.check_and_record_connection(DEFAULT_TENANT_KEY));
    }

    #[test]
    fn zero_max_means_unlimited() {
        let tracker = TenantQuotaTracker::new(config_with_tenant("acme", 0));
        for _ in 0..100 {
            assert!(tracker.check_and_record_connection("acme"));
        }
        assert!(tracker.check_and_record_connection("acme"));
    }

    #[test]
    fn active_connections_tracks_correctly() {
        let tracker = TenantQuotaTracker::new(config_with_tenant("acme", 10));
        assert_eq!(tracker.active_connections("acme"), 0);
        assert!(tracker.check_and_record_connection("acme"));
        assert!(tracker.check_and_record_connection("acme"));
        assert_eq!(tracker.active_connections("acme"), 2);
        tracker.record_disconnect("acme");
        assert_eq!(tracker.active_connections("acme"), 1);
    }

    #[test]
    fn try_reserve_bytes_admits_under_limit() {
        let tracker = Arc::new(TenantQuotaTracker::new(config_with_byte_quota(
            "acme", 1_000,
        )));
        let p1 = tracker.try_reserve_bytes("acme", 400).unwrap();
        let p2 = tracker.try_reserve_bytes("acme", 400).unwrap();
        assert_eq!(tracker.queued_bytes("acme"), 800);
        assert_eq!(p1.bytes(), 400);
        assert_eq!(p2.tenant(), "acme");
    }

    #[test]
    fn try_reserve_bytes_rejects_over_limit() {
        let tracker = Arc::new(TenantQuotaTracker::new(config_with_byte_quota(
            "acme", 1_000,
        )));
        let _p1 = tracker.try_reserve_bytes("acme", 900).unwrap();
        // 900 + 200 would exceed 1000.
        assert!(tracker.try_reserve_bytes("acme", 200).is_none());
        // Exact fit at boundary succeeds.
        let _p2 = tracker
            .try_reserve_bytes("acme", 100)
            .expect("reservation at the exact cap boundary must succeed");
        // Over boundary fails.
        assert!(tracker.try_reserve_bytes("acme", 1).is_none());
    }

    #[test]
    fn permit_drop_releases_reservation() {
        let tracker = Arc::new(TenantQuotaTracker::new(config_with_byte_quota(
            "acme", 1_000,
        )));
        {
            let _permit = tracker.try_reserve_bytes("acme", 800).unwrap();
            assert_eq!(tracker.queued_bytes("acme"), 800);
        }
        assert_eq!(tracker.queued_bytes("acme"), 0);
        // After release, a full new reservation must succeed.
        let _permit = tracker.try_reserve_bytes("acme", 1_000).unwrap();
    }

    #[test]
    fn zero_max_queued_bytes_means_unlimited() {
        let tracker = Arc::new(TenantQuotaTracker::new(config_with_byte_quota("acme", 0)));
        let _p1 = tracker.try_reserve_bytes("acme", 1_000_000).unwrap();
        let _p2 = tracker.try_reserve_bytes("acme", 1_000_000).unwrap();
        // Even with unlimited cap, bytes are tracked for observability.
        assert_eq!(tracker.queued_bytes("acme"), 2_000_000);
    }

    #[test]
    fn unknown_tenant_no_default_yields_no_permit() {
        let tracker = Arc::new(TenantQuotaTracker::new(QuotaConfig {
            tenants: HashMap::new(),
            default_quota: None,
        }));
        // No quota configured — caller should fall back to global gate
        // only, so we return None instead of a dummy permit.
        assert!(tracker.try_reserve_bytes("unknown", 1_000).is_none());
    }

    #[test]
    fn default_quota_applies_byte_limit_to_unknown() {
        let config = QuotaConfig {
            tenants: HashMap::new(),
            default_quota: Some(TenantQuota {
                max_connections: 0,
                max_message_rate: 0,
                max_queued_bytes: 500,
                max_throughput_bps: 0,
                refill_throughput_bps: 0,
            }),
        };
        let tracker = Arc::new(TenantQuotaTracker::new(config));
        let _p = tracker.try_reserve_bytes("stranger", 500).unwrap();
        // Over cap rejected.
        assert!(tracker.try_reserve_bytes("stranger", 1).is_none());
    }

    #[test]
    fn release_bytes_saturates_at_zero() {
        let tracker = Arc::new(TenantQuotaTracker::new(config_with_byte_quota(
            "acme", 1_000,
        )));
        // Prime the counter map.
        {
            let _permit = tracker.try_reserve_bytes("acme", 100).unwrap();
        }
        // Explicit over-release path — would underflow if not saturating.
        tracker.release_bytes("acme", 1_000_000);
        assert_eq!(tracker.queued_bytes("acme"), 0);
        // Counter still usable after over-release.
        let _p = tracker.try_reserve_bytes("acme", 1_000).unwrap();
    }

    #[test]
    fn byte_and_connection_counters_are_independent() {
        // Tenant with both limits.
        let mut tenants = HashMap::new();
        let _ = tenants.insert(
            "acme".to_string(),
            TenantQuota {
                max_connections: 2,
                max_message_rate: 0,
                max_queued_bytes: 1_000,
                max_throughput_bps: 0,
                refill_throughput_bps: 0,
            },
        );
        let tracker = Arc::new(TenantQuotaTracker::new(QuotaConfig {
            tenants,
            default_quota: None,
        }));
        // Connection limit independent of byte limit.
        assert!(tracker.check_and_record_connection("acme"));
        assert!(tracker.check_and_record_connection("acme"));
        assert!(!tracker.check_and_record_connection("acme"));
        // Bytes still have their full quota.
        let _p = tracker.try_reserve_bytes("acme", 1_000).unwrap();
        assert!(tracker.try_reserve_bytes("acme", 1).is_none());
    }

    #[test]
    fn permit_debug_redacts_nothing_sensitive() {
        let tracker = Arc::new(TenantQuotaTracker::new(config_with_byte_quota(
            "acme", 1_000,
        )));
        let permit = tracker.try_reserve_bytes("acme", 256).unwrap();
        let debug = format!("{permit:?}");
        assert!(debug.contains("TenantBytePermit"));
        assert!(debug.contains("acme"));
        assert!(debug.contains("256"));
    }

    /// Pin that `QuotaConfig::deserialize` rejects unknown top-level keys.
    /// A typo like `"tenats"` (missing `n`) would otherwise parse as an
    /// empty `tenants` map, silently leaving every tenant unlimited; the
    /// `deny_unknown_fields` discipline (#815, F-136) is what catches it
    /// at config load.
    #[test]
    fn quota_config_rejects_unknown_top_level_field() {
        let json = r#"{"tenants":{},"bogus":42}"#;
        let result: Result<QuotaConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "unknown top-level field must be rejected by deny_unknown_fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("bogus"),
            "error should name the offending field: {err}"
        );
    }

    /// Pin that `TenantQuota::deserialize` rejects unknown nested keys
    /// — a typo like `"max_connectons"` is silently ignored without
    /// `deny_unknown_fields`, leaving the tenant unlimited (the
    /// security-relevant default for an unset `max_connections`).
    #[test]
    fn tenant_quota_rejects_unknown_nested_field() {
        let json = r#"{"tenants":{"acme":{"max_connections":3,"max_connectons":99}},"default_quota":null}"#;
        let result: Result<QuotaConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "typo'd `max_connectons` must be rejected by deny_unknown_fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("max_connectons"),
            "error should name the offending field: {err}"
        );
    }

    // ── Per-tenant token bucket coverage (issue #883 sub-item 4) ──

    #[test]
    fn try_acquire_tenant_tokens_admits_under_cap() {
        // 1 000-byte cap, 1 000-byte refill: both fields = `cap` so the
        // bucket starts full and admits a single full-cap drain.
        let tracker = TenantQuotaTracker::new(config_with_throughput("acme", 1_000, 1_000));
        assert!(tracker.try_acquire_tenant_tokens("acme", 800).is_ok());
        assert!(tracker.try_acquire_tenant_tokens("acme", 200).is_ok());
    }

    #[test]
    fn try_acquire_tenant_tokens_rejects_over_cap_with_attribution() {
        let tracker = TenantQuotaTracker::new(config_with_throughput("acme", 1_000, 0));
        assert!(tracker.try_acquire_tenant_tokens("acme", 800).is_ok());
        let err = tracker
            .try_acquire_tenant_tokens("acme", 300)
            .expect_err("over-cap request must reject");
        assert_eq!(err.tenant, "acme");
        assert_eq!(err.requested, 300);
        // ~200 bytes remained when we tried to charge 300.
        assert!(
            err.available <= 200 && err.available > 150,
            "available must reflect post-refill headroom; got {}",
            err.available
        );
    }

    #[test]
    fn try_acquire_tenant_tokens_unknown_tenant_admits_when_no_default() {
        let tracker = TenantQuotaTracker::new(QuotaConfig {
            tenants: HashMap::new(),
            default_quota: None,
        });
        // No quota at all → admit (caller falls through to per-session).
        assert!(
            tracker
                .try_acquire_tenant_tokens("nobody", 1_000_000)
                .is_ok()
        );
    }

    #[test]
    fn try_acquire_tenant_tokens_zero_cap_admits_unconditionally() {
        // Tenant entry exists but `max_throughput_bps == 0` means
        // "this layer does not apply" — admit so the caller falls
        // through to whatever per-session limiter the listener applies.
        let tracker = TenantQuotaTracker::new(config_with_tenant("acme", 0));
        assert!(tracker.try_acquire_tenant_tokens("acme", 1_000_000).is_ok());
        assert_eq!(tracker.throughput_bucket_count(), 0);
    }

    #[test]
    fn try_acquire_tenant_tokens_default_quota_applies_to_unknown() {
        let config = QuotaConfig {
            tenants: HashMap::new(),
            default_quota: Some(TenantQuota {
                max_connections: 0,
                max_message_rate: 0,
                max_queued_bytes: 0,
                max_throughput_bps: 500,
                refill_throughput_bps: 0,
            }),
        };
        let tracker = TenantQuotaTracker::new(config);
        // Unknown tenant gets the default 500-byte cap.
        assert!(tracker.try_acquire_tenant_tokens("stranger", 500).is_ok());
        let err = tracker
            .try_acquire_tenant_tokens("stranger", 1)
            .expect_err("default-cap drain must reject the next byte");
        assert_eq!(err.tenant, "stranger");
    }

    #[test]
    fn try_acquire_tenant_tokens_isolates_per_tenant() {
        let mut tenants = HashMap::new();
        let _ = tenants.insert(
            "acme".to_string(),
            TenantQuota {
                max_connections: 0,
                max_message_rate: 0,
                max_queued_bytes: 0,
                max_throughput_bps: 1_000,
                refill_throughput_bps: 0,
            },
        );
        let _ = tenants.insert(
            "globex".to_string(),
            TenantQuota {
                max_connections: 0,
                max_message_rate: 0,
                max_queued_bytes: 0,
                max_throughput_bps: 1_000,
                refill_throughput_bps: 0,
            },
        );
        let tracker = TenantQuotaTracker::new(QuotaConfig {
            tenants,
            default_quota: None,
        });
        // Saturate acme.
        assert!(tracker.try_acquire_tenant_tokens("acme", 1_000).is_ok());
        assert!(tracker.try_acquire_tenant_tokens("acme", 1).is_err());
        // Globex still has its full cap.
        assert!(tracker.try_acquire_tenant_tokens("globex", 1_000).is_ok());
        assert!(tracker.try_acquire_tenant_tokens("globex", 1).is_err());
    }

    #[test]
    fn try_acquire_tenant_tokens_metrics_callbacks_fire() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let tracker = Arc::new(TenantQuotaTracker::new(config_with_throughput(
            "acme", 1_000, 0,
        )));
        let rejections = Arc::new(AtomicU64::new(0));
        let consumed = Arc::new(AtomicU64::new(0));
        let r = Arc::clone(&rejections);
        tracker.set_on_throughput_rejection(Some(Arc::new(move |_t: &str| {
            let _ = r.fetch_add(1, Ordering::Relaxed);
        })));
        let c = Arc::clone(&consumed);
        tracker.set_on_throughput_consumed(Some(Arc::new(move |_t: &str, _level: f64| {
            let _ = c.fetch_add(1, Ordering::Relaxed);
        })));

        assert!(tracker.try_acquire_tenant_tokens("acme", 1_000).is_ok());
        assert!(tracker.try_acquire_tenant_tokens("acme", 1).is_err());
        // Two acquires → two `consumed` callbacks (admit and reject
        // both report the post-decision level so the gauge stays
        // accurate).
        assert_eq!(consumed.load(Ordering::Relaxed), 2);
        assert_eq!(rejections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn tenant_throughput_available_returns_none_for_uncapped_tenant() {
        let tracker = TenantQuotaTracker::new(config_with_tenant("acme", 0));
        assert!(tracker.tenant_throughput_available("acme").is_none());
    }

    #[test]
    fn tenant_throughput_available_reflects_drain_state() {
        let tracker = TenantQuotaTracker::new(config_with_throughput("acme", 1_000, 0));
        // First call lazily creates the bucket and reports full cap.
        let initial = tracker
            .tenant_throughput_available("acme")
            .expect("capped tenant must report a level");
        assert!((initial - 1_000.0).abs() < 1.0);
        assert!(tracker.try_acquire_tenant_tokens("acme", 600).is_ok());
        let after = tracker.tenant_throughput_available("acme").unwrap();
        assert!(
            (after - 400.0).abs() < 1.0,
            "level after 600-byte charge must be ~400, got {after}"
        );
    }

    /// Pin that the `OnTenantThroughputRejection` callback is wired
    /// before any `consumed` callback observes the post-rejection
    /// state — operators need both events for the same drop event so
    /// the rejection counter and the headroom gauge stay coherent in
    /// the same scrape interval.
    #[test]
    fn rejection_and_consumed_callbacks_coalesce_on_drop() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let tracker = Arc::new(TenantQuotaTracker::new(config_with_throughput(
            "acme", 100, 0,
        )));
        let rej_count = Arc::new(AtomicU64::new(0));
        let consumed_calls = Arc::new(AtomicU64::new(0));
        let r = Arc::clone(&rej_count);
        tracker.set_on_throughput_rejection(Some(Arc::new(move |_| {
            let _ = r.fetch_add(1, Ordering::Relaxed);
        })));
        let c = Arc::clone(&consumed_calls);
        tracker.set_on_throughput_consumed(Some(Arc::new(move |_, _| {
            let _ = c.fetch_add(1, Ordering::Relaxed);
        })));

        // One immediate over-cap drain.
        assert!(tracker.try_acquire_tenant_tokens("acme", 1_000).is_err());
        assert_eq!(rej_count.load(Ordering::Relaxed), 1);
        assert_eq!(consumed_calls.load(Ordering::Relaxed), 1);
    }

    /// Pin that the new `max_throughput_bps` / `refill_throughput_bps`
    /// fields default to 0 when omitted — preserving the wire-format
    /// compat the issue calls out (existing deployments without the
    /// new TOML keys must continue to work).
    #[test]
    fn tenant_quota_throughput_fields_default_to_zero_when_absent() {
        let json = r#"{"tenants":{"acme":{"max_connections":3}},"default_quota":null}"#;
        let cfg: QuotaConfig =
            serde_json::from_str(json).expect("legacy 3-field tenant entry must still parse");
        let tenant = &cfg.tenants["acme"];
        assert_eq!(tenant.max_throughput_bps, 0);
        assert_eq!(tenant.refill_throughput_bps, 0);
    }

    /// Pin that an unknown nested key is rejected even with the new
    /// throughput fields added — the `deny_unknown_fields` discipline
    /// (#815, F-136) must still catch a typo'd
    /// `max_throuhgput_bps` (transposed letters).
    #[test]
    fn tenant_quota_rejects_unknown_throughput_typo() {
        let json = r#"{"tenants":{"acme":{"max_throughput_bps":1000,"max_throuhgput_bps":99}},"default_quota":null}"#;
        let result: Result<QuotaConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "typo'd throughput field must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("max_throuhgput_bps"),
            "error should name the offending field: {err}"
        );
    }
}
