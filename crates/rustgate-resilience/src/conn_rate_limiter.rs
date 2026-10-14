// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-IP connection rate limiting shared across transport listeners.
//!
//! [`ConnRateLimiter`] is preserved as a thin compatibility wrapper over
//! [`crate::sliding_window::SlidingWindowLimiter`] so existing call
//! sites (MQTT/WebSocket listeners, UDP transport, plaintext listener)
//! keep compiling without source changes during the deprecation cycle.
//! New code should construct `SlidingWindowLimiter` directly.
//!
//! **NAT/proxy caveat:** rate limiting uses the raw TCP peer address. Behind
//! NAT or a load balancer, all clients sharing one egress IP are rate-limited
//! together, and an attacker with multiple IPs bypasses the limit entirely.
//! See the threat model (D8) for deployment guidance.

use std::net::IpAddr;
use std::time::Duration;

use crate::sliding_window::{
    DEFAULT_MAX_TRACKED_KEYS, DEFAULT_SWEEP_INTERVAL, SlidingWindowLimiter,
};

/// Default number of tracked IPs that triggers an inline sweep of stale
/// entries. Re-exported for source compatibility with pre-#798 callers.
pub const DEFAULT_SWEEP_THRESHOLD: usize = DEFAULT_SWEEP_INTERVAL;

/// Hard cap on distinct IP keys the limiter will track concurrently.
/// Re-exported for source compatibility with pre-#798 callers.
pub const DEFAULT_MAX_TRACKED_IPS: usize = DEFAULT_MAX_TRACKED_KEYS;

/// Per-IP sliding-window connection rate limiter.
///
/// Tracks connection timestamps per IP address and rejects IPs that have
/// reached `max_connections` within the configured `window`. Stale entries
/// are pruned lazily — no background task is needed.
///
/// IPv6 addresses are bucketed by their `/64` prefix so that an attacker
/// cycling through a network prefix cannot evade rate limiting by
/// incrementing the host portion. IPv4 addresses are tracked individually.
///
/// # Deprecation
///
/// This type is now a thin shim over [`SlidingWindowLimiter`] with the
/// `category = "connection"` audit tag, `collapse_ipv6_to_64 = true`,
/// and the default tracked-key cap. New code should construct the
/// generic limiter directly so the SIEM category labels stay
/// distinguishable; this wrapper is kept for one PR cycle so existing
/// callers keep compiling without churn.
#[deprecated(
    since = "0.1.0",
    note = "use rustgate_resilience::sliding_window::SlidingWindowLimiter::new(max, window, \"connection\").with_ipv6_64_collapse(true) directly; this shim is kept for one PR cycle"
)]
pub struct ConnRateLimiter {
    inner: SlidingWindowLimiter,
}

// justification: the deprecation lives on the type alias users see, but the
// crate's own impl block referencing the type would otherwise trigger
// `deprecated` on every method call. The shim is removed in the next PR
// cycle, at which point this allow goes away with the type.
#[allow(deprecated)]
impl ConnRateLimiter {
    /// Create a rate limiter that allows `max_connections` per IP within `window`.
    pub fn new(max_connections: usize, window: Duration) -> Self {
        Self {
            inner: SlidingWindowLimiter::new(max_connections, window, "connection")
                .with_ipv6_64_collapse(true),
        }
    }

    /// Override the tracked-IP map cap. Primarily useful for tests that
    /// want to exercise eviction paths without allocating 64k entries.
    #[must_use]
    pub fn with_max_tracked_ips(mut self, max_tracked_ips: usize) -> Self {
        self.inner = self.inner.with_max_tracked_keys(max_tracked_ips);
        self
    }

    /// Returns `true` if the IP should be rejected (rate-limited).
    ///
    /// When the IP is under the limit, records the current timestamp and
    /// returns `false`. When at or above the limit, returns `true` without
    /// recording a new timestamp.
    pub fn is_limited(&self, ip: IpAddr) -> bool {
        self.inner.is_limited(ip)
    }
}

// justification: same as the impl block — deprecation is on the type the
// SDK consumer sees, the crate's own Debug impl is mechanical and cannot
// avoid naming the deprecated type.
#[allow(deprecated)]
impl std::fmt::Debug for ConnRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnRateLimiter")
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, deprecated)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_limit() {
        let limiter = ConnRateLimiter::new(10, Duration::from_secs(10));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..9 {
            assert!(
                !limiter.is_limited(ip),
                "should allow connections under limit"
            );
        }
    }

    #[test]
    fn blocks_at_limit() {
        let limiter = ConnRateLimiter::new(10, Duration::from_secs(10));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..10 {
            assert!(!limiter.is_limited(ip));
        }
        assert!(limiter.is_limited(ip), "should block at limit");
    }

    #[test]
    fn isolates_ips() {
        let limiter = ConnRateLimiter::new(10, Duration::from_secs(10));
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..10 {
            assert!(!limiter.is_limited(ip_a));
        }
        assert!(limiter.is_limited(ip_a), "ip_a should be blocked");
        assert!(!limiter.is_limited(ip_b), "ip_b should have its own limit");
    }

    #[test]
    fn ipv6_addresses_in_same_64_share_bucket() {
        let limiter = ConnRateLimiter::new(2, Duration::from_secs(10));
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::ffff:ffff:ffff:ffff".parse().unwrap();
        assert!(!limiter.is_limited(a));
        assert!(!limiter.is_limited(b));
        let c: IpAddr = "2001:db8::dead:beef".parse().unwrap();
        assert!(
            limiter.is_limited(c),
            "IPv6 hosts in the same /64 must share a single bucket"
        );
    }

    #[test]
    fn ipv6_different_64_prefixes_are_isolated() {
        let limiter = ConnRateLimiter::new(1, Duration::from_secs(10));
        let prefix_a: IpAddr = "2001:db8:1::1".parse().unwrap();
        let prefix_b: IpAddr = "2001:db8:2::1".parse().unwrap();
        assert!(!limiter.is_limited(prefix_a));
        assert!(
            !limiter.is_limited(prefix_b),
            "distinct /64 prefixes must have independent buckets"
        );
    }

    #[test]
    fn ipv4_unaffected_by_prefix_collapse() {
        let limiter = ConnRateLimiter::new(1, Duration::from_secs(10));
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(!limiter.is_limited(a));
        assert!(
            !limiter.is_limited(b),
            "IPv4 addresses must not be collapsed"
        );
    }

    #[test]
    fn does_not_record_when_limited() {
        let limiter = ConnRateLimiter::new(2, Duration::from_secs(10));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!limiter.is_limited(ip));
        assert!(!limiter.is_limited(ip));
        assert!(limiter.is_limited(ip));
        assert!(limiter.is_limited(ip));
        // We can't peek at internal map size from here (private), but
        // the rejection contract is preserved by the SlidingWindowLimiter
        // tests — this test just pins observable behaviour.
    }

    #[test]
    fn expired_entries_allow_new_requests() {
        // Use a tiny window so we can sleep through it.
        let limiter = ConnRateLimiter::new(1, Duration::from_millis(1));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!limiter.is_limited(ip));
        assert!(limiter.is_limited(ip));
        std::thread::sleep(Duration::from_millis(10));
        assert!(!limiter.is_limited(ip), "should allow after window expires");
    }
}
