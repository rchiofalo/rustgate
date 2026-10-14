// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Exponential backoff with jitter for retry logic.
//!
//! Extends the basic reconnect backoff (see `super::reconnect`) with
//! random jitter to prevent thundering-herd effects when multiple
//! targets retry against the same upstream endpoint simultaneously.
//! Used by request-level retry loops (where multiple concurrent failures
//! would otherwise synchronize retries); the non-jittered variant suits
//! single-client long-lived reconnections better.

use std::time::Duration;

/// Maximum backoff delay (5 minutes).
const MAX_DELAY: Duration = Duration::from_secs(300);

/// Minimum backoff delay (100 ms).
///
/// Prevents tight retry loops when `backoff_base_secs` is set to 0 in
/// config, which would otherwise hammer a failing target with no delay.
const MIN_DELAY: Duration = Duration::from_millis(100);

/// Maximum exponent for backoff calculation.
///
/// Capping the exponent prevents overflow and keeps the delay growth
/// reasonable before the absolute cap kicks in.
const MAX_EXPONENT: u32 = 5;

/// Calculate exponential backoff delay with random jitter.
///
/// Computes `base * 2^min(attempt, 5)`, capped at 5 minutes, then adds
/// 0–25% random jitter via `fastrand`. The jitter prevents synchronized
/// retries across targets sharing the same upstream.
pub fn backoff_with_jitter(base: Duration, attempt: u32) -> Duration {
    let exp = attempt.min(MAX_EXPONENT);
    let delay = base.saturating_mul(2u32.pow(exp)).min(MAX_DELAY);

    // Add 0–25% random jitter
    let jitter_micros = if delay.as_micros() > 0 {
        let max_jitter = delay.as_micros() as u64 / 4;
        if max_jitter > 0 {
            Duration::from_micros(fastrand::u64(0..=max_jitter))
        } else {
            Duration::ZERO
        }
    } else {
        Duration::ZERO
    };

    // Floor at MIN_DELAY to prevent tight retry loops from zero-base config
    let total = (delay + jitter_micros).min(MAX_DELAY);
    if total.is_zero() { MIN_DELAY } else { total }
}

/// Returns `true` if the HTTP status code is retryable.
///
/// Retryable statuses:
/// - **429** (Too Many Requests) — rate-limiting; back off and retry.
/// - **5xx** (Server Error) — transient server-side failures.
///
/// 4xx client errors (except 429) are never retried — they indicate a
/// configuration problem that won't resolve on its own.
pub fn is_retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn base_case_attempt_zero() {
        let delay = backoff_with_jitter(Duration::from_secs(1), 0);
        // base * 2^0 = 1s, plus 0-25% jitter → 1.0s–1.25s
        assert!(delay >= Duration::from_secs(1));
        assert!(delay <= Duration::from_millis(1250));
    }

    #[test]
    fn exponential_growth() {
        // Run multiple times to account for jitter
        for _ in 0..10 {
            let d1 = backoff_with_jitter(Duration::from_secs(1), 1);
            assert!(d1 >= Duration::from_secs(2), "attempt 1: {d1:?}");
            assert!(d1 <= Duration::from_millis(2500));

            let d2 = backoff_with_jitter(Duration::from_secs(1), 2);
            assert!(d2 >= Duration::from_secs(4), "attempt 2: {d2:?}");
            assert!(d2 <= Duration::from_millis(5000));

            let d3 = backoff_with_jitter(Duration::from_secs(1), 3);
            assert!(d3 >= Duration::from_secs(8), "attempt 3: {d3:?}");
            assert!(d3 <= Duration::from_millis(10000));
        }
    }

    #[test]
    fn caps_at_five_minutes() {
        let delay = backoff_with_jitter(Duration::from_secs(30), 10);
        assert!(delay <= Duration::from_secs(300));
    }

    #[test]
    fn exponent_capped_at_five() {
        // Attempts 5 and 6 should yield the same base delay (before jitter)
        // With 1s base: 1 * 2^5 = 32s
        let d5_min = Duration::from_secs(32);
        let d6_min = Duration::from_secs(32);

        for _ in 0..20 {
            let d5 = backoff_with_jitter(Duration::from_secs(1), 5);
            let d6 = backoff_with_jitter(Duration::from_secs(1), 6);
            assert!(d5 >= d5_min);
            assert!(d6 >= d6_min);
            // Both should be in the same range: 32s–40s
            assert!(d5 <= Duration::from_secs(40));
            assert!(d6 <= Duration::from_secs(40));
        }
    }

    #[test]
    fn zero_base_returns_minimum_floor() {
        let delay = backoff_with_jitter(Duration::from_secs(0), 5);
        assert_eq!(delay, MIN_DELAY);
    }

    #[test]
    fn large_base_caps_at_five_minutes() {
        let delay = backoff_with_jitter(Duration::from_secs(600), 0);
        assert!(delay <= Duration::from_secs(300));
    }

    #[test]
    fn u32_max_attempt_does_not_panic() {
        let delay = backoff_with_jitter(Duration::from_secs(1), u32::MAX);
        assert!(delay <= Duration::from_secs(300));
    }

    #[test]
    fn jitter_adds_variance() {
        // Run many iterations and verify not all results are identical
        let mut results = Vec::new();
        for _ in 0..50 {
            results.push(backoff_with_jitter(Duration::from_secs(1), 2));
        }
        let first = results[0];
        let has_variance = results.iter().any(|d| *d != first);
        assert!(has_variance, "jitter should produce varying delays");
    }

    #[test]
    fn jitter_stays_within_25_percent() {
        let base = Duration::from_secs(10);
        for attempt in 0..=5 {
            let exp = attempt.min(5);
            let expected_base = base.saturating_mul(2u32.pow(exp)).min(MAX_DELAY);
            let max_with_jitter = expected_base + expected_base / 4;
            let capped_max = max_with_jitter.min(MAX_DELAY);

            for _ in 0..50 {
                let delay = backoff_with_jitter(base, attempt);
                assert!(
                    delay >= expected_base,
                    "attempt {attempt}: {delay:?} < {expected_base:?}"
                );
                assert!(
                    delay <= capped_max,
                    "attempt {attempt}: {delay:?} > {capped_max:?}"
                );
            }
        }
    }

    #[test]
    fn retryable_5xx() {
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(502));
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(599));
    }

    #[test]
    fn retryable_429() {
        assert!(is_retryable_status(429));
    }

    #[test]
    fn not_retryable_4xx() {
        assert!(!is_retryable_status(400));
        assert!(!is_retryable_status(401));
        assert!(!is_retryable_status(404));
        assert!(!is_retryable_status(422));
    }

    #[test]
    fn not_retryable_2xx() {
        assert!(!is_retryable_status(200));
        assert!(!is_retryable_status(201));
        assert!(!is_retryable_status(204));
    }

    #[test]
    fn not_retryable_3xx() {
        assert!(!is_retryable_status(301));
        assert!(!is_retryable_status(302));
    }
}
