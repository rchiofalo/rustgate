// Copyright © 2026 Roberto Chiofalo.

//! Active WebSocket health-check state shared by the read and write loops.
//!
//! `tokio-tungstenite` auto-responds to inbound Ping frames with Pong at the
//! library level, but it does not probe the peer itself. This module adds a
//! configurable heartbeat: the write loop emits `Message::Ping` every
//! [`HealthCheckConfig::ping_interval`] and records the monotonic instant of
//! each inbound Pong (from the read loop) in [`LastPong`]. If the gap between
//! now and the last observed Pong exceeds `ping_interval + pong_timeout`, the
//! peer is considered unreachable and the session is dropped.
//!
//! Both knobs default to [`Duration::ZERO`], which disables the feature so
//! existing deployments are unaffected until operators opt in.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Shared monotonic timestamp of the last Pong frame observed on a session.
///
/// Written by the read loop, read by the write loop. The lock is only ever
/// held for the duration of an `Instant` read or write, never across `.await`.
pub type LastPong = Arc<Mutex<Instant>>;

/// Construct a fresh [`LastPong`] anchored at `Instant::now()`, so a session
/// is not immediately considered stale before it has had a chance to
/// handshake a Pong.
pub fn new_last_pong() -> LastPong {
    Arc::new(Mutex::new(Instant::now()))
}

/// Active health-check knobs for a WebSocket session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthCheckConfig {
    /// Interval between outbound Ping frames.
    ///
    /// `Duration::ZERO` disables the active health check entirely — no Pings
    /// are sent and `last_pong` is never consulted.
    pub ping_interval: Duration,
    /// Additional grace period beyond `ping_interval` before a silent peer
    /// is considered unreachable.
    ///
    /// A session is dropped when `now - last_pong > ping_interval +
    /// pong_timeout`. `Duration::ZERO` disables the deadline; Pings still
    /// flow but absence of Pongs does not terminate the session. Useful for
    /// keeping middleboxes warm without closing on transient Pong drops.
    pub pong_timeout: Duration,
}

impl HealthCheckConfig {
    /// Fully disabled: no pings, no deadline.
    pub const DISABLED: Self = Self {
        ping_interval: Duration::ZERO,
        pong_timeout: Duration::ZERO,
    };

    /// `true` when outbound pings should be sent for this session.
    pub fn ping_enabled(&self) -> bool {
        !self.ping_interval.is_zero()
    }

    /// `true` when absence of Pongs should terminate the session.
    pub fn deadline_enabled(&self) -> bool {
        !self.ping_interval.is_zero() && !self.pong_timeout.is_zero()
    }

    /// Decide whether the peer has gone silent for too long.
    ///
    /// Returns `true` when `now - last_pong > ping_interval + pong_timeout`.
    /// Always returns `false` when the deadline is disabled so callers can
    /// use this as an unconditional gate.
    pub fn is_stale(&self, last_pong: Instant, now: Instant) -> bool {
        if !self.deadline_enabled() {
            return false;
        }
        let deadline = self.ping_interval.saturating_add(self.pong_timeout);
        now.saturating_duration_since(last_pong) > deadline
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self::DISABLED
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn disabled_config_never_pings() {
        let cfg = HealthCheckConfig::DISABLED;
        assert!(!cfg.ping_enabled());
        assert!(!cfg.deadline_enabled());
    }

    #[test]
    fn zero_pong_timeout_disables_deadline_but_keeps_ping() {
        let cfg = HealthCheckConfig {
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::ZERO,
        };
        assert!(cfg.ping_enabled());
        assert!(!cfg.deadline_enabled());

        // Even with a very old last_pong, stale check returns false.
        let now = Instant::now();
        let ancient = now - Duration::from_secs(3600);
        assert!(!cfg.is_stale(ancient, now));
    }

    #[test]
    fn stale_returns_false_within_window() {
        let cfg = HealthCheckConfig {
            ping_interval: Duration::from_secs(10),
            pong_timeout: Duration::from_secs(5),
        };
        let now = Instant::now();

        // Just saw a pong — absolutely fresh.
        assert!(!cfg.is_stale(now, now));

        // 14s old is inside 10 + 5 = 15s window.
        let recent = now - Duration::from_secs(14);
        assert!(!cfg.is_stale(recent, now));
    }

    #[test]
    fn stale_returns_true_past_deadline() {
        let cfg = HealthCheckConfig {
            ping_interval: Duration::from_secs(10),
            pong_timeout: Duration::from_secs(5),
        };
        let now = Instant::now();

        // 16s old exceeds the 15s tolerance.
        let ancient = now - Duration::from_secs(16);
        assert!(cfg.is_stale(ancient, now));
    }

    #[test]
    fn stale_handles_clock_skew_without_panic() {
        // last_pong later than `now` would panic with raw duration_since,
        // but saturating_duration_since clamps to zero -> not stale.
        let cfg = HealthCheckConfig {
            ping_interval: Duration::from_secs(10),
            pong_timeout: Duration::from_secs(5),
        };
        let now = Instant::now();
        let future = now + Duration::from_secs(1);
        assert!(!cfg.is_stale(future, now));
    }

    #[test]
    fn new_last_pong_is_recent() {
        let lp = new_last_pong();
        let recorded = *lp.lock();
        let drift = Instant::now().saturating_duration_since(recorded);
        assert!(drift < Duration::from_secs(1));
    }

    #[test]
    fn default_is_disabled() {
        assert_eq!(HealthCheckConfig::default(), HealthCheckConfig::DISABLED);
    }

    // ------------------------------------------------------------------
    // Boundary pins for `is_stale` — the `>` vs `>=` choice is the
    // difference between "drop exactly on deadline" and "drop one tick
    // later"; pinning both sides of the boundary so a silent `>=` edit
    // or a `<` drift is caught before it reaches production.
    // ------------------------------------------------------------------

    #[test]
    fn is_stale_returns_false_at_exact_deadline_boundary() {
        // now - last_pong == ping_interval + pong_timeout must NOT be
        // considered stale — the comparison is strictly `>`, not `>=`.
        let cfg = HealthCheckConfig {
            ping_interval: Duration::from_secs(10),
            pong_timeout: Duration::from_secs(5),
        };
        let now = Instant::now();
        let on_boundary = now - Duration::from_secs(15);
        assert!(
            !cfg.is_stale(on_boundary, now),
            "gap equal to deadline must not be stale (strictly-greater contract)",
        );
    }

    #[test]
    fn is_stale_returns_true_one_nanosecond_past_deadline() {
        // Symmetrical negation of the boundary case — a single ns over
        // the deadline MUST trip, so a regression that widened the
        // comparison to `>=` + a `-1ns` tolerance would fail here.
        let cfg = HealthCheckConfig {
            ping_interval: Duration::from_secs(10),
            pong_timeout: Duration::from_secs(5),
        };
        let now = Instant::now();
        let just_past = now - (Duration::from_secs(15) + Duration::from_nanos(1));
        assert!(
            cfg.is_stale(just_past, now),
            "gap of deadline + 1ns must be stale",
        );
    }

    // ------------------------------------------------------------------
    // `deadline_enabled` implication contract — the deadline check
    // requires BOTH `ping_interval` and `pong_timeout` to be non-zero.
    // A regression that only checked `pong_timeout` would silently
    // start dropping sessions on "ping disabled but stale timestamp"
    // configurations.
    // ------------------------------------------------------------------

    #[test]
    fn deadline_is_disabled_when_ping_interval_is_zero_even_if_pong_timeout_is_nonzero() {
        let cfg = HealthCheckConfig {
            ping_interval: Duration::ZERO,
            pong_timeout: Duration::from_secs(30),
        };
        assert!(
            !cfg.ping_enabled(),
            "ping must be disabled when interval is zero"
        );
        assert!(
            !cfg.deadline_enabled(),
            "deadline must be disabled when ping is disabled, regardless of pong_timeout",
        );
        // And the gate short-circuit follows: `is_stale` must be false
        // no matter how ancient the last_pong is.
        let now = Instant::now();
        let ancient = now - Duration::from_secs(3600);
        assert!(
            !cfg.is_stale(ancient, now),
            "is_stale must be false when deadline is disabled",
        );
    }

    // ------------------------------------------------------------------
    // Overflow / saturation contract — `saturating_add` on
    // `Duration::MAX` prevents a panic when an operator sets a
    // pathologically-large ping_interval. The deadline becomes
    // `Duration::MAX` and any finite gap is under it → never stale.
    // ------------------------------------------------------------------

    #[test]
    fn is_stale_saturates_and_does_not_panic_on_maximum_durations() {
        let cfg = HealthCheckConfig {
            ping_interval: Duration::MAX,
            pong_timeout: Duration::from_secs(1),
        };
        let now = Instant::now();
        let not_quite_ancient = now - Duration::from_secs(10_000);
        // With a saturated deadline, no finite gap crosses it.
        assert!(
            !cfg.is_stale(not_quite_ancient, now),
            "saturating_add overflow must produce a non-stale verdict on any finite gap",
        );
    }

    // ------------------------------------------------------------------
    // Type-surface contract — `HealthCheckConfig` is copied into each
    // session state struct (Copy), cached as a key in test fixtures
    // (Eq), and printed in operator logs (Debug). Pin those derives
    // via compile-time bound assertions so a regression that added a
    // non-Copy/Eq/Debug field trips here.
    // ------------------------------------------------------------------

    #[test]
    fn health_check_config_is_copy_eq_and_debug() {
        fn assert_bounds<T: Copy + Eq + PartialEq + std::fmt::Debug>() {}
        assert_bounds::<HealthCheckConfig>();
    }

    #[test]
    fn health_check_config_equality_distinguishes_each_field() {
        // A change to either field must flip equality — protects
        // against a refactor that derived `PartialEq` by only
        // comparing a subset of fields.
        let base = HealthCheckConfig {
            ping_interval: Duration::from_secs(10),
            pong_timeout: Duration::from_secs(5),
        };
        let different_ping = HealthCheckConfig {
            ping_interval: Duration::from_secs(11),
            pong_timeout: Duration::from_secs(5),
        };
        let different_pong = HealthCheckConfig {
            ping_interval: Duration::from_secs(10),
            pong_timeout: Duration::from_secs(6),
        };
        assert_eq!(base, base, "identical configs must be equal");
        assert_ne!(
            base, different_ping,
            "ping-interval delta must flip equality"
        );
        assert_ne!(
            base, different_pong,
            "pong-timeout delta must flip equality"
        );
    }

    // ------------------------------------------------------------------
    // `DISABLED` constant literal — doc comments quote the "both
    // zero" figure; pin the invariant at the constant boundary so a
    // silent bump to a non-zero default surfaces loudly.
    // ------------------------------------------------------------------

    #[test]
    fn disabled_constant_is_all_zero_durations() {
        assert_eq!(
            HealthCheckConfig::DISABLED.ping_interval,
            Duration::ZERO,
            "DISABLED.ping_interval must be zero — doc comments depend on this",
        );
        assert_eq!(
            HealthCheckConfig::DISABLED.pong_timeout,
            Duration::ZERO,
            "DISABLED.pong_timeout must be zero — doc comments depend on this",
        );
    }

    // ------------------------------------------------------------------
    // `new_last_pong` factory — must return a fresh Arc each call so
    // per-session state never aliases across sessions. A refactor to
    // a `OnceLock` / lazy singleton would silently share timestamps
    // across every open WebSocket session.
    // ------------------------------------------------------------------

    #[test]
    fn new_last_pong_returns_distinct_arc_instances() {
        let a = new_last_pong();
        let b = new_last_pong();
        assert!(
            !Arc::ptr_eq(&a, &b),
            "new_last_pong must return a fresh Arc on every call — no hidden singleton",
        );
    }

    // ------------------------------------------------------------------
    // Thread-safety bounds — `LastPong` is shared between the read
    // loop (which writes) and the write loop (which reads), both
    // running inside `tokio::spawn` futures, so the alias must be
    // `Send + Sync + Clone + 'static`. Pinning at compile time so a
    // regression to `Rc<RefCell<_>>` or similar fails here rather
    // than at the first tokio::spawn call site.
    // ------------------------------------------------------------------

    #[test]
    fn last_pong_is_send_sync_clone_static() {
        fn assert_bounds<T: Send + Sync + Clone + 'static>() {}
        assert_bounds::<LastPong>();
    }
}
