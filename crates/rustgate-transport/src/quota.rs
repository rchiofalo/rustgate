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

use parking_lot::RwLock;
use serde::Deserialize;

/// Sentinel tenant key used when a connection has no explicit tenant
/// (i.e. `Identity.tenant` is `None`). Mapped to `default_quota` if
/// one is configured.
pub const DEFAULT_TENANT_KEY: &str = "__default__";

/// Resource limits for a single tenant.
#[derive(Debug, Clone, Deserialize)]
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
}

/// Quota configuration loaded from file.
#[derive(Debug, Clone, Deserialize)]
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

/// Tracks and enforces per-tenant resource quotas.
///
/// Designed to be wrapped in `Arc` and shared across the router and
/// session lifecycle. Connection tracking is lock-free on the hot path
/// (atomic increment/decrement); the `RwLock` only guards the counter
/// map when a new tenant is first seen.
#[derive(Debug)]
pub struct TenantQuotaTracker {
    config: QuotaConfig,
    counters: RwLock<HashMap<String, Arc<TenantCounters>>>,
}

impl TenantQuotaTracker {
    /// Create a new tracker with the given configuration.
    pub fn new(config: QuotaConfig) -> Self {
        Self {
            config,
            counters: RwLock::new(HashMap::new()),
        }
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
}

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
}
