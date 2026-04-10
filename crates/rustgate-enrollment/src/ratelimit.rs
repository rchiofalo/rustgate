//! Per-IP sliding-window rate limiting for enrollment endpoints.
//!
//! Tracks individual request timestamps per IP and lazily prunes expired
//! entries on each check. No separate background prune task is needed —
//! stale IPs are cleaned up inline when the entry count exceeds a threshold
//! or enough time has passed since the last sweep.
//!
//! **NAT/proxy caveat:** rate limiting uses the raw TCP peer address. Behind
//! NAT or a load balancer, all clients sharing one egress IP are rate-limited
//! together. See the threat model (D8) for deployment guidance.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Number of distinct IPs that triggers an inline sweep of stale entries.
const SWEEP_THRESHOLD: usize = 1024;

/// Minimum interval between full sweeps to avoid excessive iteration.
const MIN_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Sliding-window rate limiter keyed by IP address.
///
/// Each request records a timestamp. On every check the limiter discards
/// timestamps older than `window`, then counts the remaining ones. If the
/// count meets or exceeds `max_requests` the request is rejected.
///
/// This replaces the previous fixed-window design that relied on a periodic
/// prune task — cleanup now happens lazily, removing the window where stale
/// entries could block legitimate requests.
#[derive(Debug)]
pub struct RateLimiter {
    state: Mutex<RateLimitState>,
    max_requests: usize,
    window: Duration,
}

#[derive(Debug)]
struct RateLimitState {
    map: HashMap<IpAddr, VecDeque<Instant>>,
    last_sweep: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// `max_requests` is the maximum number of allowed requests per IP
    /// within the given `window` duration.
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            state: Mutex::new(RateLimitState {
                map: HashMap::new(),
                last_sweep: Instant::now(),
            }),
            max_requests,
            window,
        }
    }

    /// Configured maximum requests per IP within the window.
    pub fn max_requests(&self) -> usize {
        self.max_requests
    }

    /// Check if a request from `ip` is allowed.
    ///
    /// Returns `true` if under the limit, `false` if rate-limited.
    /// Automatically prunes timestamps older than the window for this IP
    /// and periodically sweeps all IPs to reclaim memory from departed clients.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut state = match self.state.lock() {
            Ok(s) => s,
            // Poisoned mutex — allow the request rather than blocking
            Err(e) => e.into_inner(),
        };

        // Inline sweep: remove stale IPs when the map is large or enough
        // time has elapsed, so we never need a background prune task.
        if state.map.len() > SWEEP_THRESHOLD
            || now.duration_since(state.last_sweep) >= MIN_SWEEP_INTERVAL
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

        // Prune expired entries for this specific IP (O(k) where k = expired).
        while timestamps.front().is_some_and(|t| *t <= cutoff) {
            let _ = timestamps.pop_front();
        }

        if timestamps.len() >= self.max_requests {
            return false;
        }

        timestamps.push_back(now);
        true
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");

        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
    }

    #[test]
    fn rejects_over_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");

        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip), "third request should be rejected");
    }

    #[test]
    fn separate_ips_have_separate_limits() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let ip1: IpAddr = "10.0.0.1".parse().expect("valid IP");
        let ip2: IpAddr = "10.0.0.2".parse().expect("valid IP");

        assert!(limiter.check(ip1));
        assert!(!limiter.check(ip1), "ip1 over limit");
        assert!(limiter.check(ip2), "ip2 should have its own limit");
    }

    #[test]
    fn expired_entries_allow_new_requests() {
        let limiter = RateLimiter::new(1, Duration::from_millis(1));
        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");

        assert!(limiter.check(ip));
        assert!(!limiter.check(ip));

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(10));

        // Should be allowed again after window expires
        assert!(limiter.check(ip));
    }

    #[test]
    fn stale_entries_cleaned_inline() {
        let limiter = RateLimiter::new(100, Duration::from_millis(1));
        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");

        assert!(limiter.check(ip));

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(10));

        // Force a sweep by setting last_sweep far in the past
        {
            let mut state = limiter.state.lock().expect("lock");
            state.last_sweep = Instant::now() - Duration::from_secs(120);
        }

        // Next check triggers sweep and removes stale entry
        let ip2: IpAddr = "10.0.0.2".parse().expect("valid IP");
        assert!(limiter.check(ip2));

        let state = limiter.state.lock().expect("lock");
        assert!(
            !state.map.contains_key(&ip),
            "stale IP should be swept inline"
        );
    }
}
