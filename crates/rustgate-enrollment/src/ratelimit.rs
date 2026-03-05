//! Per-IP rate limiting for enrollment endpoints.
//!
//! Uses a sliding window counter to limit the number of requests per IP
//! address within a configurable time window. Stale entries are pruned
//! on each check to prevent unbounded memory growth.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sliding-window rate limiter keyed by IP address.
#[derive(Debug)]
pub struct RateLimiter {
    state: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// `max_requests` is the maximum number of allowed requests per IP
    /// within the given `window` duration.
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            max_requests,
            window,
        }
    }

    /// Check if a request from `ip` is allowed.
    ///
    /// Returns `true` if under the limit, `false` if rate-limited.
    /// Automatically prunes timestamps older than the window.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut state = match self.state.lock() {
            Ok(s) => s,
            // Poisoned mutex — allow the request rather than blocking
            Err(e) => e.into_inner(),
        };

        let timestamps = state.entry(ip).or_default();

        // Prune expired entries
        timestamps.retain(|t| *t > cutoff);

        if timestamps.len() >= self.max_requests {
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Remove all entries older than the window across all IPs.
    /// Call periodically to prevent memory growth from departed clients.
    pub fn prune(&self) {
        let cutoff = Instant::now() - self.window;

        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(e) => e.into_inner(),
        };

        state.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
}

#[cfg(test)]
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
    fn prune_removes_stale_entries() {
        let limiter = RateLimiter::new(100, Duration::from_millis(1));
        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");

        assert!(limiter.check(ip));

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(10));

        limiter.prune();

        // After pruning, the state should be empty
        let state = limiter.state.lock().expect("lock");
        assert!(state.is_empty(), "stale entries should be pruned");
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
}
