// Copyright © 2026 Roberto Chiofalo.

//! Per-tenant resource quota tracking and enforcement.
//!
//! Tracks active connections per tenant (identified by the certificate
//! Organization field) and enforces configurable limits. Quota
//! configuration is loaded from a JSON file and can be hot-reloaded
//! via `ArcSwap` on the router.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

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
}
