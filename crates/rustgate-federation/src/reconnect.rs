// Copyright © 2026 Roberto Chiofalo.

//! Shared reconnection utilities for federation clients.
//!
//! Provides backoff calculation and reconnection limit checking used by
//! both V1 and V2 federation outbound clients.

use std::time::Duration;

/// Maximum backoff delay (5 minutes).
const MAX_DELAY: Duration = Duration::from_secs(300);

/// Maximum exponent for backoff calculation.
///
/// Capping the exponent prevents overflow and keeps the delay growth
/// reasonable before the absolute cap kicks in.
const MAX_EXPONENT: u32 = 5;

/// Calculate exponential backoff delay.
///
/// Computes `base * 2^min(attempt, 5)`, capped at 5 minutes.
/// A zero base always returns zero regardless of the attempt count.
pub(crate) fn backoff_delay(base: Duration, attempt: u32) -> Duration {
    let exp = attempt.min(MAX_EXPONENT);
    let delay = base.saturating_mul(2u32.pow(exp));
    delay.min(MAX_DELAY)
}

/// Check whether reconnection attempts should stop.
///
/// Returns `true` when `count` has reached or exceeded `max_reconnects`.
/// A negative `max_reconnects` means unlimited retries (always returns `false`).
pub(crate) fn should_stop_reconnecting(max_reconnects: i32, count: u32) -> bool {
    max_reconnects >= 0 && count >= max_reconnects as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── backoff_delay ───────────────────────────────────────────────

    #[test]
    fn backoff_base_case() {
        let delay = backoff_delay(Duration::from_secs(15), 0);
        assert_eq!(delay, Duration::from_secs(15)); // 15 * 2^0 = 15
    }

    #[test]
    fn backoff_exponential_growth() {
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 1),
            Duration::from_secs(30)
        ); // 15 * 2
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 2),
            Duration::from_secs(60)
        ); // 15 * 4
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 3),
            Duration::from_secs(120)
        ); // 15 * 8
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 4),
            Duration::from_secs(240)
        ); // 15 * 16
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 5),
            Duration::from_secs(300)
        ); // 15 * 32 = 480 -> capped at 300
    }

    #[test]
    fn backoff_caps_at_five_minutes() {
        let delay = backoff_delay(Duration::from_secs(30), 10);
        assert_eq!(delay, Duration::from_secs(300));
    }

    #[test]
    fn backoff_caps_exponent_at_five() {
        let d5 = backoff_delay(Duration::from_secs(10), 5);
        let d6 = backoff_delay(Duration::from_secs(10), 6);
        assert_eq!(d5, d6);
    }

    #[test]
    fn backoff_with_one_second_base() {
        assert_eq!(
            backoff_delay(Duration::from_secs(1), 0),
            Duration::from_secs(1)
        );
        assert_eq!(
            backoff_delay(Duration::from_secs(1), 1),
            Duration::from_secs(2)
        );
        assert_eq!(
            backoff_delay(Duration::from_secs(1), 5),
            Duration::from_secs(32)
        );
    }

    #[test]
    fn backoff_with_zero_base() {
        assert_eq!(
            backoff_delay(Duration::from_secs(0), 0),
            Duration::from_secs(0)
        );
        assert_eq!(
            backoff_delay(Duration::from_secs(0), 5),
            Duration::from_secs(0)
        );
    }

    #[test]
    fn backoff_large_base_caps_at_five_minutes() {
        let delay = backoff_delay(Duration::from_secs(600), 0);
        assert_eq!(delay, Duration::from_secs(300));
    }

    #[test]
    fn backoff_subsecond_base() {
        let delay = backoff_delay(Duration::from_millis(500), 3);
        assert_eq!(delay, Duration::from_secs(4)); // 500ms * 8 = 4s
    }

    #[test]
    fn backoff_monotonically_increases() {
        let base = Duration::from_secs(10);
        let mut prev = Duration::from_secs(0);
        for i in 0..=5 {
            let d = backoff_delay(base, i);
            assert!(d > prev || (i == 0 && d == base), "delay should increase");
            prev = d;
        }
    }

    #[test]
    fn backoff_u32_max_attempt() {
        // Should not panic; exponent is capped at 5
        let delay = backoff_delay(Duration::from_secs(10), u32::MAX);
        assert_eq!(delay, backoff_delay(Duration::from_secs(10), 5));
    }

    // ── should_stop_reconnecting ────────────────────────────────────

    #[test]
    fn stop_unlimited() {
        assert!(!should_stop_reconnecting(-1, 0));
        assert!(!should_stop_reconnecting(-1, 100));
        assert!(!should_stop_reconnecting(-1, u32::MAX));
    }

    #[test]
    fn stop_limited() {
        assert!(!should_stop_reconnecting(3, 0));
        assert!(!should_stop_reconnecting(3, 1));
        assert!(!should_stop_reconnecting(3, 2));
        assert!(should_stop_reconnecting(3, 3));
        assert!(should_stop_reconnecting(3, 4));
    }

    #[test]
    fn stop_zero_reconnects() {
        assert!(should_stop_reconnecting(0, 0));
    }

    #[test]
    fn stop_single_reconnect() {
        assert!(!should_stop_reconnecting(1, 0));
        assert!(should_stop_reconnecting(1, 1));
    }

    #[test]
    fn stop_very_negative() {
        assert!(!should_stop_reconnecting(-100, 0));
        assert!(!should_stop_reconnecting(i32::MIN, u32::MAX));
    }

    #[test]
    fn stop_large_limit() {
        assert!(!should_stop_reconnecting(1_000_000, 999_999));
        assert!(should_stop_reconnecting(1_000_000, 1_000_000));
    }
}
