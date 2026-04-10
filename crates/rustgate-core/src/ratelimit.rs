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
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default number of tracked IPs that triggers an inline sweep of stale entries.
const DEFAULT_SWEEP_THRESHOLD: usize = 512;

/// Per-IP sliding-window connection rate limiter.
///
/// Tracks connection timestamps per IP address and rejects IPs that have
/// reached `max_connections` within the configured `window`. Stale entries
/// are pruned lazily — no background task is needed.
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
        }
    }

    /// Returns `true` if the IP should be rejected (rate-limited).
    ///
    /// When the IP is under the limit, records the current timestamp and
    /// returns `false`. When at or above the limit, returns `true` without
    /// recording a new timestamp.
    pub fn is_limited(&self, ip: IpAddr) -> bool {
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

        let timestamps = state.map.entry(ip).or_default();

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

impl std::fmt::Debug for ConnRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnRateLimiter")
            .field("max_connections", &self.max_connections)
            .field("window", &self.window)
            .field("sweep_threshold", &self.sweep_threshold)
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
}
