// Copyright © 2026 Roberto Chiofalo.

//! Generic per-key sliding-window rate limiter.
//!
//! Keyed by [`IpAddr`], the limiter tracks event timestamps per key and
//! rejects events whose count meets or exceeds `max` within the
//! configured `window`. Stale entries are pruned lazily on each check —
//! no background task is needed.
//!
//! # Audit emission
//!
//! On rejection, the limiter emits a structured
//! [`rustgate_core::audit::rate_limit_triggered`] event tagged with the
//! configured `category` label. Categories let SIEM dashboards
//! distinguish enforcement cadences (`"connection"` vs `"request"`)
//! without losing the unified rate-limit metric.
//!
//! # Mutex discipline
//!
//! The internal map is protected by a [`parking_lot::Mutex`]. Callers
//! must NOT hold the guard across `.await` — the limiter is sync-only.
//! `parking_lot::Mutex` does not poison on panic, so a panic inside the
//! critical section drops the guard cleanly and subsequent calls
//! continue to serve traffic (fail-open).
//!
//! # IPv6 prefix collapsing
//!
//! When `collapse_ipv6_to_64 = true` (the default for the connection
//! preset), IPv6 addresses are bucketed by `/64` prefix so an attacker
//! cycling through host identifiers in a single allocation cannot evade
//! the limit. IPv4 always tracks individual `/32` addresses.
//!
//! # Tracked-key cap
//!
//! The map size is bounded by `max_tracked_keys` (default
//! [`DEFAULT_MAX_TRACKED_KEYS`]). When the cap is reached and a
//! previously-unseen key arrives, the entry with the oldest last-seen
//! timestamp is evicted. This protects against OOM under adversarial
//! source-address diversity while preserving enforcement against the
//! most recently active attackers.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Default number of tracked keys that triggers an inline sweep of stale
/// entries (entries-since-last-sweep threshold).
pub const DEFAULT_SWEEP_INTERVAL: usize = 512;

/// Hard cap on distinct keys the limiter will track concurrently.
///
/// Bounds memory under IPv6 prefix-scan floods: an attacker cycling
/// through a /48 (2^80 source addresses) cannot bloat the map past this
/// limit. Combined with the optional `/64` prefix collapsing for IPv6,
/// 65_536 entries exactly covers the worst-case /48 scan (2^16 = 65_536
/// distinct `/64` prefixes per /48).
pub const DEFAULT_MAX_TRACKED_KEYS: usize = 65_536;

/// Generic per-key sliding-window rate limiter.
///
/// See the [module documentation](self) for the contract — this struct
/// is the unified replacement for the previously-duplicated
/// `ConnRateLimiter` and `enrollment::ratelimit::RateLimiter`.
pub struct SlidingWindowLimiter {
    state: Mutex<State>,
    max: usize,
    window: Duration,
    sweep_interval: usize,
    max_tracked_keys: usize,
    category: &'static str,
    collapse_ipv6_to_64: bool,
}

/// Internal state: per-key timestamp queues and sweep bookkeeping.
struct State {
    map: HashMap<IpAddr, VecDeque<Instant>>,
    last_sweep: Instant,
}

impl SlidingWindowLimiter {
    /// Create a limiter that allows `max` events per key within `window`.
    ///
    /// `category` is a static label included in the audit event emitted
    /// on rejection (e.g. `"connection"`, `"request"`). It feeds the
    /// `endpoint` field of [`rustgate_core::audit::rate_limit_triggered`]
    /// so SIEM filters can distinguish limiter cadences.
    pub fn new(max: usize, window: Duration, category: &'static str) -> Self {
        Self {
            state: Mutex::new(State {
                map: HashMap::new(),
                last_sweep: Instant::now(),
            }),
            max,
            window,
            sweep_interval: DEFAULT_SWEEP_INTERVAL,
            max_tracked_keys: DEFAULT_MAX_TRACKED_KEYS,
            category,
            collapse_ipv6_to_64: false,
        }
    }

    /// Override the entries-since-last-sweep threshold for lazy prune.
    /// Lower values trade a small CPU cost for tighter memory bounds;
    /// higher values amortize the sweep across more checks.
    #[must_use]
    pub fn with_sweep_interval(mut self, sweep_interval: usize) -> Self {
        self.sweep_interval = sweep_interval;
        self
    }

    /// Override the tracked-key map cap. Useful for tests that want to
    /// exercise eviction without allocating 64k entries.
    #[must_use]
    pub fn with_max_tracked_keys(mut self, max_tracked_keys: usize) -> Self {
        self.max_tracked_keys = max_tracked_keys;
        self
    }

    /// Enable `/64` prefix collapsing for IPv6 keys. Required for
    /// connection rate limiting where an attacker with a single IPv6
    /// allocation could otherwise cycle 2^64 host identifiers.
    #[must_use]
    pub fn with_ipv6_64_collapse(mut self, enabled: bool) -> Self {
        self.collapse_ipv6_to_64 = enabled;
        self
    }

    /// Configured maximum events per key within the window.
    pub fn max(&self) -> usize {
        self.max
    }

    /// Configured sliding-window duration.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Configured audit category label.
    pub fn category(&self) -> &'static str {
        self.category
    }

    /// Returns `true` if the event from `key` is allowed (under the
    /// limit), `false` if it must be rejected (rate-limited).
    ///
    /// On rejection, emits an
    /// [`rustgate_core::audit::rate_limit_triggered`] audit event with
    /// `endpoint = self.category` and `limit = self.max`.
    ///
    /// `now` is provided by the caller so test code can drive the clock
    /// deterministically.
    pub fn try_check(&self, key: IpAddr, now: Instant) -> bool {
        let key = if self.collapse_ipv6_to_64 {
            collapse_ipv6_64(key)
        } else {
            key
        };
        let cutoff = now.checked_sub(self.window).unwrap_or(now);

        let mut state = self.state.lock();

        // Periodic sweep of stale keys to bound memory. The thresholds
        // are intentionally distinct: `sweep_interval` triggers
        // amortized cleanup under high churn, the elapsed-window check
        // catches a long-quiet limiter that has accumulated stale
        // entries despite low traffic.
        if state.map.len() > self.sweep_interval
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
        // evict the entry with the oldest last-seen timestamp. O(n) in
        // `max_tracked_keys`, but only runs when the cap is reached —
        // real workloads stay well below it.
        if state.map.len() >= self.max_tracked_keys
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

        // Prune expired entries for this specific key.
        while timestamps.front().is_some_and(|t| *t <= cutoff) {
            let _ = timestamps.pop_front();
        }

        if timestamps.len() >= self.max {
            // Drop the guard before emitting the audit event so the
            // tracing subscriber cannot deadlock against the limiter's
            // own mutex (audit emission shouldn't, but the discipline
            // is cheap and matches the rest of the codebase).
            drop(state);
            let peer = format_peer(key);
            rustgate_core::audit::rate_limit_triggered(&peer, self.category, self.max);
            return false;
        }

        timestamps.push_back(now);
        true
    }

    /// Convenience wrapper that samples `Instant::now()` internally.
    /// Returns `true` when the event is rejected (rate-limited),
    /// `false` when allowed — preserving the legacy
    /// `ConnRateLimiter::is_limited` semantics for callers that have
    /// not yet migrated.
    pub fn is_limited(&self, key: IpAddr) -> bool {
        !self.try_check(key, Instant::now())
    }
}

impl std::fmt::Debug for SlidingWindowLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlidingWindowLimiter")
            .field("max", &self.max)
            .field("window", &self.window)
            .field("sweep_interval", &self.sweep_interval)
            .field("max_tracked_keys", &self.max_tracked_keys)
            .field("category", &self.category)
            .field("collapse_ipv6_to_64", &self.collapse_ipv6_to_64)
            .finish()
    }
}

/// Canonicalize an IPv6 address to its `/64` prefix; pass IPv4 through
/// unchanged. See the module docs for the rationale.
fn collapse_ipv6_64(ip: IpAddr) -> IpAddr {
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

/// Format an `IpAddr` for the audit `peer` field. We do not pre-mask
/// here: the audit boundary in `rustgate-core` already sanitizes the
/// string, and callers downstream of the audit emission may want the
/// full address for forensic correlation.
fn format_peer(key: IpAddr) -> String {
    key.to_string()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    /// Capture audit-target tracing output to a shared byte buffer.
    /// Mirrors the pattern in `rustgate-federation/src/v2/server.rs` so
    /// the audit emission test does not need a workspace-wide test
    /// helper.
    #[derive(Clone, Default)]
    struct AuditBuf(Arc<std::sync::Mutex<Vec<u8>>>);

    impl AuditBuf {
        fn snapshot(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap().clone()).to_string()
        }
    }

    impl std::io::Write for AuditBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for AuditBuf {
        type Writer = AuditBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn sliding_window_allows_under_max() {
        // N-1 calls within the window must all be allowed. Pin the
        // boundary explicitly: the rejection lives at exactly `max`,
        // not somewhere below it.
        let limiter = SlidingWindowLimiter::new(5, Duration::from_secs(60), "test");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();
        for i in 0..4 {
            assert!(
                limiter.try_check(ip, now),
                "call #{i} (under max) must be allowed"
            );
        }
    }

    #[test]
    fn sliding_window_rejects_at_max() {
        // The Nth call (where N == max) is the boundary: the
        // implementation must reject AT the limit, not strictly above
        // it. A regression from `>=` to `>` would silently allow one
        // extra event per window.
        let limiter = SlidingWindowLimiter::new(3, Duration::from_secs(60), "test");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();
        assert!(limiter.try_check(ip, now));
        assert!(limiter.try_check(ip, now));
        assert!(limiter.try_check(ip, now));
        assert!(!limiter.try_check(ip, now), "4th call must be rejected");
    }

    #[test]
    fn sliding_window_refills_after_window() {
        // Wait `window + epsilon` and the limiter must allow new calls
        // — old timestamps fall outside the cutoff and prune lazily on
        // the next check.
        let window = Duration::from_millis(100);
        let limiter = SlidingWindowLimiter::new(1, window, "test");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let t0 = Instant::now();
        assert!(limiter.try_check(ip, t0));
        assert!(!limiter.try_check(ip, t0));

        let t1 = t0 + window + Duration::from_millis(50);
        assert!(
            limiter.try_check(ip, t1),
            "call after window+epsilon must be allowed"
        );
    }

    #[test]
    fn sliding_window_emits_audit_on_reject() {
        // Wire a tracing subscriber that captures the `audit`-target
        // INFO records to an in-memory buffer; verify the rejection
        // emits a `security.rate_limited` event with the configured
        // category as the endpoint label.
        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            let limiter = SlidingWindowLimiter::new(1, Duration::from_secs(60), "request");
            let ip: IpAddr = "10.0.0.99".parse().unwrap();
            let now = Instant::now();
            assert!(limiter.try_check(ip, now), "first call must be allowed");
            assert!(!limiter.try_check(ip, now), "second call must be rejected");
        });

        let captured = buf.snapshot();
        assert!(
            captured.contains("security.rate_limited"),
            "audit log must contain `security.rate_limited` event_type, got: {captured}"
        );
        assert!(
            captured.contains("endpoint=request"),
            "audit log must include the configured category as `endpoint`, got: {captured}"
        );
        assert!(
            captured.contains("limit=1"),
            "audit log must include the configured limit, got: {captured}"
        );
        assert!(
            captured.contains("10.0.0.99"),
            "audit log must include the peer key, got: {captured}"
        );
    }

    #[test]
    fn sliding_window_isolates_per_key() {
        // Saturating one key must NOT spill into another's quota: the
        // map is keyed by IpAddr and every key carries its own deque.
        let limiter = SlidingWindowLimiter::new(2, Duration::from_secs(60), "test");
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Instant::now();
        assert!(limiter.try_check(a, now));
        assert!(limiter.try_check(a, now));
        assert!(!limiter.try_check(a, now), "A is over its limit");
        assert!(
            limiter.try_check(b, now),
            "B has its own quota, must not be limited by A"
        );
        assert!(limiter.try_check(b, now));
        assert!(!limiter.try_check(b, now));
    }

    #[test]
    fn sliding_window_lazy_prune_keeps_map_bounded() {
        // Push many unique keys with timestamps deep in the past so the
        // sweep prunes them on the next check. Assert that the map
        // shrinks back toward the active set rather than growing
        // unbounded.
        let limiter =
            SlidingWindowLimiter::new(1, Duration::from_secs(60), "test").with_sweep_interval(100);
        let t0 = Instant::now();

        // Insert 1000 stale entries (each with a timestamp older than
        // the window) — these must all evaporate on the next check.
        {
            let mut state = limiter.state.lock();
            let stale_ts = t0.checked_sub(Duration::from_secs(120)).unwrap_or(t0);
            for i in 0..1000u32 {
                let ip = IpAddr::V4(std::net::Ipv4Addr::from(i + 1));
                state.map.entry(ip).or_default().push_back(stale_ts);
            }
            // Backdate last_sweep so the sweep predicate fires.
            state.last_sweep = stale_ts;
            assert_eq!(state.map.len(), 1000, "seeded 1000 stale entries");
        }

        // One active key. The map size threshold (>sweep_interval=100)
        // forces an inline sweep that wipes the 1000 stale entries
        // before this check is recorded.
        let active: IpAddr = "10.99.99.99".parse().unwrap();
        assert!(limiter.try_check(active, t0));

        let state = limiter.state.lock();
        assert!(
            state.map.len() <= 1,
            "lazy prune must collapse map back to the active set, got {}",
            state.map.len()
        );
        assert!(
            state.map.contains_key(&active),
            "the live key must survive the sweep"
        );
    }

    #[test]
    fn sliding_window_fail_open_on_mutex_poison() {
        // parking_lot::Mutex does not poison on panic — the lock is
        // simply released when the panicking guard drops. This test
        // pins fail-open semantics: a panic that occurs while a
        // previous holder owned the guard does NOT permanently break
        // the limiter; subsequent calls continue to admit traffic up
        // to the configured limit.
        //
        // The poisoning thread must drop its guard before the second
        // try_check runs (otherwise we'd just be deadlocked, not
        // poisoned). std::sync::Mutex would have stayed poisoned;
        // parking_lot does not. The behavioural pin is identical from
        // the limiter's perspective: traffic continues to flow.
        let limiter = Arc::new(SlidingWindowLimiter::new(
            5,
            Duration::from_secs(60),
            "test",
        ));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let poisoner_limiter = Arc::clone(&limiter);
        let poisoner = std::thread::spawn(move || {
            let _guard = poisoner_limiter.state.lock();
            panic!("intentional poison for fail-open test");
        });
        // The thread panics; join returns Err but the lock is released.
        assert!(poisoner.join().is_err(), "poisoner must panic");

        // Subsequent calls must succeed (fail-open): parking_lot does
        // not propagate poison, the lock is reusable.
        let now = Instant::now();
        assert!(
            limiter.try_check(ip, now),
            "call after poison-inducing panic must be allowed (fail-open)"
        );
        assert!(
            limiter.try_check(ip, now),
            "limiter remains usable after panic"
        );
    }

    // ----- Behavioral parity tests with the legacy ConnRateLimiter -----
    //
    // These exercise the IPv6 `/64` collapse and the tracked-key cap so
    // a regression in the generic limiter is caught here before it can
    // ride through the `ConnRateLimiter` shim into production.

    #[test]
    fn ipv6_64_collapse_when_enabled() {
        let limiter = SlidingWindowLimiter::new(1, Duration::from_secs(60), "connection")
            .with_ipv6_64_collapse(true);
        let now = Instant::now();
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::ffff:ffff:ffff:ffff".parse().unwrap();
        assert!(limiter.try_check(a, now));
        assert!(
            !limiter.try_check(b, now),
            "second host in same /64 must collapse to the same bucket"
        );
    }

    #[test]
    fn ipv6_no_collapse_when_disabled() {
        let limiter = SlidingWindowLimiter::new(1, Duration::from_secs(60), "request");
        let now = Instant::now();
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap();
        assert!(limiter.try_check(a, now));
        assert!(
            limiter.try_check(b, now),
            "distinct host portions must remain distinct keys when collapse is disabled"
        );
    }

    #[test]
    fn map_size_capped_under_unique_key_flood() {
        let cap = 8;
        let limiter = SlidingWindowLimiter::new(1, Duration::from_secs(60), "test")
            .with_max_tracked_keys(cap);
        let now = Instant::now();
        for i in 0..(cap as u32 * 4) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(i + 1));
            let _ = limiter.try_check(ip, now);
            let state = limiter.state.lock();
            assert!(
                state.map.len() <= cap,
                "map size {} exceeded cap {} after inserting key #{}",
                state.map.len(),
                cap,
                i
            );
        }
    }

    #[test]
    fn rejected_calls_do_not_record_timestamps() {
        // Critical contract from the legacy enrollment limiter: a
        // rejected call must NOT extend the deque, otherwise an
        // attacker can pin a key into permanent rejection by hammering
        // it.
        let limiter = SlidingWindowLimiter::new(2, Duration::from_secs(60), "request");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();
        assert!(limiter.try_check(ip, now));
        assert!(limiter.try_check(ip, now));
        for _ in 0..5 {
            assert!(!limiter.try_check(ip, now));
        }
        let state = limiter.state.lock();
        assert_eq!(
            state.map.get(&ip).map_or(0, VecDeque::len),
            2,
            "rejected calls must not append timestamps"
        );
    }

    #[test]
    fn is_limited_inverts_try_check() {
        // The legacy `is_limited` shim returns the inverse of
        // `try_check` and samples the clock internally. Pin the
        // inversion so the deprecated wrapper cannot silently flip
        // semantics.
        let limiter = SlidingWindowLimiter::new(1, Duration::from_secs(60), "connection");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!limiter.is_limited(ip), "first call: not limited");
        assert!(limiter.is_limited(ip), "second call: limited");
    }

    #[test]
    fn debug_renders_configuration() {
        let limiter = SlidingWindowLimiter::new(7, Duration::from_secs(30), "request")
            .with_sweep_interval(64)
            .with_max_tracked_keys(1024)
            .with_ipv6_64_collapse(true);
        let dbg = format!("{limiter:?}");
        assert!(dbg.contains("max: 7"));
        assert!(dbg.contains("sweep_interval: 64"));
        assert!(dbg.contains("max_tracked_keys: 1024"));
        assert!(dbg.contains("category: \"request\""));
        assert!(dbg.contains("collapse_ipv6_to_64: true"));
    }
}
