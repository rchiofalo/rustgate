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
}
