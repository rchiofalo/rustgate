// Copyright © 2026 Roberto Chiofalo.

//! Per-IP connection rate limiting shared across transport listeners.
//!
//! Provides [`ConnRateLimiter`], a sliding-window rate limiter keyed by IP
//! address. Used by the MQTT and WebSocket listeners to reject connections
//! from IPs that exceed a configurable threshold within a time window.
//!
//! **NAT/proxy caveat:** rate limiting uses the raw TCP peer address. Behind
//! NAT or a load balancer, all clients sharing one egress IP are rate-limited
//! together, and an attacker with multiple IPs bypasses the limit entirely.
//! See the threat model (D8) for deployment guidance.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default number of tracked IPs that triggers an inline sweep of stale entries.
const DEFAULT_SWEEP_THRESHOLD: usize = 512;

/// Hard cap on distinct IP keys the limiter will track concurrently.
///
/// Bounds memory under IPv6 prefix-scan floods: an attacker cycling
/// through a /48 (2^80 source addresses) cannot bloat the map past this
/// limit. Combined with the internal `/64` prefix collapsing for IPv6,
/// 65_536 entries exactly covers the worst-case /48 scan (2^16 = 65_536
/// distinct `/64` prefixes per /48).
pub const DEFAULT_MAX_TRACKED_IPS: usize = 65_536;

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
/// The tracked-IP map is capped at [`DEFAULT_MAX_TRACKED_IPS`]; when the
/// cap is reached and a previously-unseen key arrives, the entry with the
/// oldest last-seen timestamp is evicted to make room. This protects
/// against OOM under adversarial source-address diversity while
/// preserving enforcement for the most recently active attackers.
///
/// # Thread safety
///
/// Internal state is protected by a [`std::sync::Mutex`] with poison
/// recovery, suitable for use from both sync and async contexts (the lock
/// is never held across `.await` points).
pub struct ConnRateLimiter {
    state: Mutex<ConnRateState>,
    max_connections: usize,
    window: Duration,
    sweep_threshold: usize,
    max_tracked_ips: usize,
}

/// Internal state: per-IP timestamp queues and sweep bookkeeping.
struct ConnRateState {
    map: HashMap<IpAddr, VecDeque<Instant>>,
    last_sweep: Instant,
}

impl ConnRateLimiter {
    /// Create a rate limiter that allows `max_connections` per IP within `window`.
    pub fn new(max_connections: usize, window: Duration) -> Self {
        Self {
            state: Mutex::new(ConnRateState {
                map: HashMap::new(),
                last_sweep: Instant::now(),
            }),
            max_connections,
            window,
            sweep_threshold: DEFAULT_SWEEP_THRESHOLD,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
        }
    }

    /// Override the tracked-IP map cap. Primarily useful for tests that
    /// want to exercise eviction paths without allocating 64k entries.
    pub fn with_max_tracked_ips(mut self, max_tracked_ips: usize) -> Self {
        self.max_tracked_ips = max_tracked_ips;
        self
    }

    /// Returns `true` if the IP should be rejected (rate-limited).
    ///
    /// When the IP is under the limit, records the current timestamp and
    /// returns `false`. When at or above the limit, returns `true` without
    /// recording a new timestamp.
    pub fn is_limited(&self, ip: IpAddr) -> bool {
        let key = canonical_key(ip);
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(e) => e.into_inner(),
        };

        // Periodic sweep of stale IPs to bound memory.
        if state.map.len() > self.sweep_threshold
            || now.duration_since(state.last_sweep) >= self.window
        {
            state.map.retain(|_, timestamps| {
                while timestamps.front().is_some_and(|t| *t <= cutoff) {
                    let _ = timestamps.pop_front();
                }
                !timestamps.is_empty()
            });
            state.last_sweep = now;
        }

        // Enforce the hard cap: if the map is full and this key is new,
        // evict the entry with the oldest last-seen timestamp. This is
        // O(n) in `max_tracked_ips` but only runs when the cap is
        // actually reached — real workloads stay well below it, and
        // adversarial prefix-scan floods collapse into /64 buckets, so
        // 64k keys represents the worst-case budget, not the norm.
        if state.map.len() >= self.max_tracked_ips
            && !state.map.contains_key(&key)
            && let Some(evict_key) = state
                .map
                .iter()
                .min_by_key(|(_, timestamps)| timestamps.back().copied())
                .map(|(k, _)| *k)
        {
            let _ = state.map.remove(&evict_key);
        }

        let timestamps = state.map.entry(key).or_default();

        // Prune expired entries for this IP.
        while timestamps.front().is_some_and(|t| *t <= cutoff) {
            let _ = timestamps.pop_front();
        }

        if timestamps.len() >= self.max_connections {
            return true;
        }

        timestamps.push_back(now);
        false
    }
}

/// Canonicalize a peer address into a rate-limiter bucket key.
///
/// IPv4 addresses map to themselves — /32 granularity is fine because
/// address diversity is bounded by scarcity. IPv6 collapses to the /64
/// prefix: an attacker with a /64 (the smallest allocation under RFC
/// 4291 SLAAC) can otherwise cycle 2^64 host identifiers and exhaust a
/// per-address map. Collapsing at /64 forces them to acquire additional
/// prefixes to evade the limit.
fn canonical_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for b in &mut octets[8..] {
                *b = 0;
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

impl std::fmt::Debug for ConnRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnRateLimiter")
            .field("max_connections", &self.max_connections)
            .field("window", &self.window)
            .field("sweep_threshold", &self.sweep_threshold)
            .field("max_tracked_ips", &self.max_tracked_ips)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
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

        // Fill up to the limit.
        for _ in 0..10 {
            assert!(!limiter.is_limited(ip));
        }

        // Next attempt should be blocked.
        assert!(limiter.is_limited(ip), "should block at limit");
    }

    #[test]
    fn isolates_ips() {
        let limiter = ConnRateLimiter::new(10, Duration::from_secs(10));
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust limit for ip_a.
        for _ in 0..10 {
            assert!(!limiter.is_limited(ip_a));
        }
        assert!(limiter.is_limited(ip_a), "ip_a should be blocked");

        // ip_b should still be allowed.
        assert!(!limiter.is_limited(ip_b), "ip_b should have its own limit");
    }

    #[test]
    fn resets_after_window() {
        let limiter = ConnRateLimiter::new(10, Duration::from_secs(10));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Fill up the limit with timestamps in the past.
        {
            let mut state = limiter.state.lock().unwrap();
            let old = Instant::now() - Duration::from_secs(11);
            let timestamps = state.map.entry(ip).or_default();
            for _ in 0..10 {
                timestamps.push_back(old);
            }
        }

        // Old entries should be pruned; new attempt should succeed.
        assert!(!limiter.is_limited(ip), "should allow after window expires");
    }

    #[test]
    fn expired_entries_allow_new_requests() {
        // Use a tiny window so we can sleep through it.
        let limiter = ConnRateLimiter::new(1, Duration::from_millis(1));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(!limiter.is_limited(ip));
        assert!(limiter.is_limited(ip), "should block at limit");

        std::thread::sleep(Duration::from_millis(10));

        assert!(!limiter.is_limited(ip), "should allow after window expires");
    }

    #[test]
    fn sweep_cleans_stale_ips() {
        let limiter = ConnRateLimiter::new(10, Duration::from_secs(10));
        let stale_ip: IpAddr = "10.0.0.99".parse().unwrap();

        // Insert a stale entry and backdate last_sweep to trigger a sweep.
        {
            let mut state = limiter.state.lock().unwrap();
            let old = Instant::now() - Duration::from_secs(11);
            state.map.entry(stale_ip).or_default().push_back(old);
            state.last_sweep = old;
        }

        // Any call should trigger a sweep and remove the stale IP.
        let fresh_ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!limiter.is_limited(fresh_ip));

        let state = limiter.state.lock().unwrap();
        assert!(
            !state.map.contains_key(&stale_ip),
            "stale IP should have been swept"
        );
    }

    #[test]
    fn does_not_record_when_limited() {
        let limiter = ConnRateLimiter::new(2, Duration::from_secs(10));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(!limiter.is_limited(ip));
        assert!(!limiter.is_limited(ip));

        // At limit — should be rejected but NOT add more timestamps.
        assert!(limiter.is_limited(ip));
        assert!(limiter.is_limited(ip));

        let state = limiter.state.lock().unwrap();
        let count = state.map.get(&ip).map_or(0, VecDeque::len);
        assert_eq!(count, 2, "rejected requests should not be recorded");
    }

    #[test]
    fn ipv6_addresses_in_same_64_share_bucket() {
        let limiter = ConnRateLimiter::new(2, Duration::from_secs(10));
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::ffff:ffff:ffff:ffff".parse().unwrap();

        assert!(!limiter.is_limited(a));
        assert!(!limiter.is_limited(b));
        // Third connection from any host in 2001:db8::/64 must be blocked:
        // both `a` and `b` collapse to the same /64 prefix.
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
        // Different /64 — must not be blocked by prefix_a's consumption.
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
        // Adjacent IPv4 must remain in its own bucket — v4 is /32 granular.
        assert!(
            !limiter.is_limited(b),
            "IPv4 addresses must not be collapsed"
        );
    }

    #[test]
    fn map_size_capped_under_prefix_scan() {
        // Tiny cap so we can flood it deterministically in a unit test.
        let cap = 8usize;
        let limiter = ConnRateLimiter::new(1, Duration::from_secs(10)).with_max_tracked_ips(cap);

        // Walk many distinct /64 prefixes; map must never exceed the cap.
        for i in 0..(cap * 4) {
            // Vary the third hextet so every address lands in a fresh /64.
            let ip: IpAddr = format!("2001:db8:{i:x}::1").parse().unwrap();
            let _ = limiter.is_limited(ip);

            let state = limiter.state.lock().unwrap();
            assert!(
                state.map.len() <= cap,
                "map size {} exceeded cap {} after inserting /64 #{}",
                state.map.len(),
                cap,
                i
            );
        }
    }

    #[test]
    fn eviction_drops_least_recently_seen_key() {
        let cap = 2usize;
        let limiter = ConnRateLimiter::new(1, Duration::from_secs(10)).with_max_tracked_ips(cap);

        // Seed two IPs with ordered last-seen timestamps: `oldest` first,
        // then `newer`. A third insertion must evict `oldest`.
        let oldest: IpAddr = "10.1.1.1".parse().unwrap();
        let newer: IpAddr = "10.1.1.2".parse().unwrap();
        let intruder: IpAddr = "10.1.1.3".parse().unwrap();

        assert!(!limiter.is_limited(oldest));
        // Small sleep so `newer`'s timestamp is strictly greater than
        // `oldest`'s — `Instant` has ~ns resolution on most platforms
        // but we stay robust against clocks that tick coarsely.
        std::thread::sleep(Duration::from_millis(5));
        assert!(!limiter.is_limited(newer));

        // Inserting a third key must evict `oldest` (LRU by last-seen).
        let _ = limiter.is_limited(intruder);

        let state = limiter.state.lock().unwrap();
        assert_eq!(state.map.len(), cap, "cap must hold after eviction");
        assert!(
            !state.map.contains_key(&oldest),
            "least-recently-seen entry must be the eviction victim"
        );
        assert!(state.map.contains_key(&newer));
        assert!(state.map.contains_key(&intruder));
    }

    #[test]
    fn repeat_inserts_on_same_key_do_not_trigger_eviction() {
        let cap = 2usize;
        let limiter = ConnRateLimiter::new(10, Duration::from_secs(10)).with_max_tracked_ips(cap);

        let a: IpAddr = "10.2.0.1".parse().unwrap();
        let b: IpAddr = "10.2.0.2".parse().unwrap();

        assert!(!limiter.is_limited(a));
        assert!(!limiter.is_limited(b));

        // Repeatedly hitting existing keys must not evict anything — the
        // cap guard only triggers for previously-unseen keys.
        for _ in 0..5 {
            assert!(!limiter.is_limited(a));
            assert!(!limiter.is_limited(b));
        }

        let state = limiter.state.lock().unwrap();
        assert_eq!(state.map.len(), 2);
        assert!(state.map.contains_key(&a) && state.map.contains_key(&b));
    }
}
