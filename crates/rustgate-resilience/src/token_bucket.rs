// Copyright © 2026 Roberto Chiofalo.

//! Per-target token bucket rate limiter for outbound requests.
//!
//! Prevents overwhelming target endpoints with burst traffic by enforcing
//! a configurable maximum request rate per second. Tokens refill lazily
//! based on elapsed wall-clock time — no background task required.
//!
//! Follows the workspace fail-open pattern: on mutex poisoning, requests
//! are allowed rather than blocked (matching [`super::conn_rate_limiter`]).

use tokio::time::Instant;

/// Token bucket rate limiter for outbound requests.
///
/// Each target can have an independent rate limiter. Tokens are refilled
/// lazily on each [`try_acquire`](Self::try_acquire) call based on elapsed
/// time since the last refill. Thread-safe via `Mutex` with poison recovery.
#[derive(Debug)]
pub struct TokenBucket {
    max_tokens: f64,
    refill_rate: f64,
    state: std::sync::Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// - `rate_per_sec`: maximum sustained requests per second. Also the
    ///   token refill rate.
    /// - `burst`: maximum token accumulation (burst capacity). When `None`,
    ///   defaults to `rate_per_sec`, allowing a 1-second burst.
    ///
    /// The bucket starts full, so the first burst of requests up to
    /// `max_tokens` is always allowed immediately.
    pub fn new(rate_per_sec: f64, burst: Option<f64>) -> Self {
        let max_tokens = burst.unwrap_or(rate_per_sec).max(1.0);
        let refill_rate = rate_per_sec.max(0.0);
        Self {
            max_tokens,
            refill_rate,
            state: std::sync::Mutex::new(BucketState {
                tokens: max_tokens,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Try to consume one token. Returns `true` if the request is allowed.
    ///
    /// Refills tokens based on elapsed time before checking availability.
    /// On mutex poisoning, allows the request (fail-open — matching the
    /// workspace pattern in [`super::conn_rate_limiter`]).
    pub fn try_acquire(&self) -> bool {
        let Ok(mut guard) = self.state.lock() else {
            // Fail-open on mutex poison — don't block traffic on internal error
            return true;
        };

        let now = Instant::now();
        let elapsed = now.duration_since(guard.last_refill).as_secs_f64();
        guard.tokens = (guard.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        guard.last_refill = now;

        if guard.tokens >= 1.0 {
            guard.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn initial_burst_allowed() {
        let bucket = TokenBucket::new(10.0, None);
        // Should allow 10 requests immediately (bucket starts full)
        for i in 0..10 {
            assert!(bucket.try_acquire(), "request {i} should be allowed");
        }
        // 11th should be rejected
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn custom_burst_size() {
        let bucket = TokenBucket::new(5.0, Some(20.0));
        // Should allow 20 requests (custom burst)
        for i in 0..20 {
            assert!(bucket.try_acquire(), "request {i} should be allowed");
        }
        assert!(!bucket.try_acquire());
    }

    #[tokio::test]
    async fn refills_over_time() {
        let bucket = TokenBucket::new(10.0, Some(10.0));
        // Drain all tokens
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }
        assert!(!bucket.try_acquire());

        // Wait 200ms — should refill ~2 tokens (10/sec * 0.2s)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
    }

    #[test]
    fn does_not_exceed_max_tokens() {
        let bucket = TokenBucket::new(100.0, Some(5.0));
        // Even with high refill rate, max_tokens caps at 5
        for i in 0..5 {
            assert!(bucket.try_acquire(), "request {i} should be allowed");
        }
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn zero_rate_blocks_after_initial_burst() {
        let bucket = TokenBucket::new(0.0, Some(3.0));
        // Initial burst of 3
        for i in 0..3 {
            assert!(bucket.try_acquire(), "request {i} should be allowed");
        }
        // No refill ever — blocked
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn minimum_burst_of_one() {
        // Even if burst is set to 0.5, we floor to 1.0
        let bucket = TokenBucket::new(1.0, Some(0.5));
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
    }
}
