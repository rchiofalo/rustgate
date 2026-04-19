// Copyright © 2026 Roberto Chiofalo.

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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Number of distinct IPs that triggers an inline sweep of stale entries.
const SWEEP_THRESHOLD: usize = 1024;

/// Minimum interval between full sweeps to avoid excessive iteration.
const MIN_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Callback fired when the rate-limiter state mutex is poisoned.
///
/// Wired by the server binary to a Prometheus counter so operators can
/// alert on poison events (which indicate a prior panic in the limiter
/// and imply the process is degraded).
pub type PoisonCallback = Arc<dyn Fn() + Send + Sync>;

/// Sliding-window rate limiter keyed by IP address.
///
/// Each request records a timestamp. On every check the limiter discards
/// timestamps older than `window`, then counts the remaining ones. If the
/// count meets or exceeds `max_requests` the request is rejected.
///
/// This replaces the previous fixed-window design that relied on a periodic
/// prune task — cleanup now happens lazily, removing the window where stale
/// entries could block legitimate requests.
pub struct RateLimiter {
    state: Mutex<RateLimitState>,
    max_requests: usize,
    window: Duration,
    on_poison: Option<PoisonCallback>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("state", &self.state)
            .field("max_requests", &self.max_requests)
            .field("window", &self.window)
            .field("on_poison", &self.on_poison.is_some())
            .finish()
    }
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
            on_poison: None,
        }
    }

    /// Register a callback fired whenever the state mutex is observed as
    /// poisoned. Poison means a prior panic while holding the lock — the
    /// limiter now fails-closed (rejects requests) instead of recovering
    /// the inner state, so this callback is the observability hook that
    /// tells operators the limiter is degraded.
    #[must_use]
    pub fn with_poison_callback(mut self, cb: PoisonCallback) -> Self {
        self.on_poison = Some(cb);
        self
    }

    /// Configured maximum requests per IP within the window.
    pub fn max_requests(&self) -> usize {
        self.max_requests
    }

    /// Configured sliding-window duration.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Check if a request from `ip` is allowed.
    ///
    /// Returns `true` if under the limit, `false` if rate-limited.
    /// Automatically prunes timestamps older than the window for this IP
    /// and periodically sweeps all IPs to reclaim memory from departed clients.
    ///
    /// # Fail-closed on poison
    ///
    /// If the state mutex is poisoned (prior panic while holding the
    /// lock), this function returns `false` and fires the optional
    /// `on_poison` callback. The inner state is *not* recovered: trusting
    /// whatever partially-mutated map remains could bypass the rate limit
    /// (e.g., the poisoning thread could have dropped entries mid-sweep).
    /// Rejecting the request on poison is the conservative posture for a
    /// security endpoint — the caller translates `false` to HTTP 503.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut state = match self.state.lock() {
            Ok(s) => s,
            // Poisoned mutex: a previous holder panicked and may have
            // left the map in an inconsistent state. Fire the poison
            // observer (so operators see the metric) and reject the
            // request — do NOT call `e.into_inner()`, that would trust
            // corrupted state on a security-critical path.
            Err(_) => {
                if let Some(cb) = &self.on_poison {
                    cb();
                }
                tracing::warn!(
                    "enrollment rate-limiter mutex poisoned, rejecting request (fail-closed)"
                );
                return false;
            }
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
        // The window must be large enough that *both* the "over limit"
        // rejection and the "after expiry" allow are unambiguous even on a
        // loaded CI runner where `Instant::now()` between two back-to-back
        // `check()` calls can drift several milliseconds. The previous 1 ms
        // window was too tight: if the second call landed >= 1 ms after the
        // first, the cutoff comparison `t <= cutoff` pruned the first
        // timestamp, leaving the slot free and flipping the `!check` assert
        // to `check returned true`. See the CI failure documented on main
        // (fix/flaky-ratelimit-expired-entries-test).
        //
        // With a 200 ms window, two immediate calls are reliably inside
        // the same window (normal jitter is single-digit milliseconds),
        // and a 400 ms sleep comfortably exceeds the window so the third
        // call is reliably allowed.
        let limiter = RateLimiter::new(1, Duration::from_millis(200));
        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");

        assert!(limiter.check(ip));
        assert!(
            !limiter.check(ip),
            "second request inside the 200 ms window must be rate-limited"
        );

        // Wait well past the window so the first timestamp is pruned.
        std::thread::sleep(Duration::from_millis(400));

        // Should be allowed again after window expires
        assert!(
            limiter.check(ip),
            "request after the 200 ms window expired must be allowed"
        );
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

    #[test]
    fn poisoned_mutex_fails_closed_and_fires_callback() {
        // Issue #767 / F-41: on mutex poison the limiter must reject the
        // request (return false). The previous implementation called
        // `e.into_inner()` and treated the recovered state as authoritative,
        // which could bypass the limit if the prior panic left the map in
        // an inconsistent state. Security endpoints must fail-closed.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let poison_count = Arc::new(AtomicUsize::new(0));
        let poison_count_cb = Arc::clone(&poison_count);
        let limiter = RateLimiter::new(10, Duration::from_secs(60)).with_poison_callback(Arc::new(
            move || {
                let _ = poison_count_cb.fetch_add(1, Ordering::Relaxed);
            },
        ));

        // Poison the mutex: spawn a thread that locks and panics.
        let limiter_arc = Arc::new(limiter);
        let poisoner = {
            let l = Arc::clone(&limiter_arc);
            std::thread::spawn(move || {
                let _guard = l.state.lock().expect("initial lock");
                panic!("intentional poison for test");
            })
        };
        // The spawned thread panics; join returns Err but we only care
        // about side-effects on the mutex.
        assert!(poisoner.join().is_err(), "poisoner thread should panic");

        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");
        assert!(
            !limiter_arc.check(ip),
            "check() must return false on poisoned mutex (fail-closed)"
        );
        assert_eq!(
            poison_count.load(Ordering::Relaxed),
            1,
            "on_poison callback must fire on every poisoned check()"
        );

        // Subsequent checks stay fail-closed and keep firing the callback —
        // poison is sticky and there is no recovery path inside the limiter.
        assert!(!limiter_arc.check(ip));
        assert_eq!(poison_count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn poisoned_mutex_without_callback_still_fails_closed() {
        // The poison callback is optional. Absence of a callback must
        // never flip the safety posture back to fail-open.
        let limiter = RateLimiter::new(10, Duration::from_secs(60));
        let limiter_arc = Arc::new(limiter);
        let poisoner = {
            let l = Arc::clone(&limiter_arc);
            std::thread::spawn(move || {
                let _guard = l.state.lock().expect("initial lock");
                panic!("intentional poison for test");
            })
        };
        let _ = poisoner.join();

        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");
        assert!(
            !limiter_arc.check(ip),
            "must fail-closed even without callback"
        );
    }
}
