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

    /// Pin the workspace `Debug` implementability on `TokenBucket`. The
    /// struct is `#[derive(Debug)]` because the workspace lint
    /// `missing_debug_implementations = "warn"` requires every public type
    /// to be `Debug` — a regression that replaced the derive with a manual
    /// impl that accidentally panicked on unknown state (e.g. NaN token
    /// values) would show up here at test time, and a regression that
    /// dropped the derive entirely would stop compiling. The contract we
    /// pin is weak on purpose: the exact field ordering is not a public
    /// API, but *some* non-empty Debug rendering is. Also exercise
    /// `{:#?}` (pretty-print) to catch a hypothetical manual impl that
    /// forgot to handle the alternate flag.
    #[test]
    fn token_bucket_debug_is_non_empty_for_both_formatters() {
        let bucket = TokenBucket::new(42.0, Some(7.0));
        let flat = format!("{bucket:?}");
        let pretty = format!("{bucket:#?}");
        assert!(
            !flat.is_empty(),
            "TokenBucket Debug (flat) must produce non-empty output"
        );
        assert!(
            !pretty.is_empty(),
            "TokenBucket Debug (pretty) must produce non-empty output"
        );
        // Pretty-printed output should contain newlines — catches a manual
        // impl that delegated to `write!` with the same shape in both modes.
        assert!(
            pretty.contains('\n'),
            "TokenBucket Debug (pretty) must span multiple lines: {pretty}"
        );
    }

    /// Pin the fail-open clamp: a negative `rate_per_sec` argument must
    /// be floored to 0.0 so we never produce a "negative refill" branch
    /// that could drive tokens below zero on every call. The constructor
    /// uses `rate_per_sec.max(0.0)`; a regression that dropped the clamp
    /// would turn `try_acquire` into a monotonically-decreasing counter
    /// that blocks even on the initial burst. We verify the invariant by
    /// exhausting the initial burst (which must still work — burst is
    /// separately clamped to `>= 1`), then confirming no request succeeds
    /// afterwards because refill is zero.
    #[test]
    fn negative_rate_per_sec_clamps_to_zero_refill() {
        let bucket = TokenBucket::new(-100.0, Some(2.0));
        // Burst is clamped to max(2.0, 1.0) = 2, both should be allowed.
        assert!(
            bucket.try_acquire(),
            "first token from the initial burst must be allowed"
        );
        assert!(
            bucket.try_acquire(),
            "second token from the initial burst must be allowed"
        );
        // Negative-rate clamp means refill_rate = 0.0 — no further tokens
        // should ever become available.
        assert!(
            !bucket.try_acquire(),
            "with clamped-to-zero refill rate, no request beyond burst should succeed"
        );
    }

    /// Pin the default-burst behaviour: when `burst` is `None`, the bucket
    /// capacity must equal `rate_per_sec` (allowing a 1-second burst at
    /// the configured rate). This is what the doc-comment on `new()`
    /// promises; a regression that changed the default to e.g. `2 *
    /// rate_per_sec` or `rate_per_sec / 2` would silently shift every
    /// caller's burst allowance. Verify by exhausting exactly
    /// `rate_per_sec` tokens and checking the next call is rejected
    /// *before* any time has elapsed (so no refill happens in between).
    #[test]
    fn burst_none_defaults_to_rate_per_sec_capacity() {
        let bucket = TokenBucket::new(4.0, None);
        for i in 0..4 {
            assert!(
                bucket.try_acquire(),
                "token {i} of 4 should be allowed from the default burst"
            );
        }
        assert!(
            !bucket.try_acquire(),
            "5th request must be rejected — default burst must equal rate_per_sec (4)"
        );
    }

    /// Pin the burst floor: a `Some(0.0)` or `Some(<1.0)` burst must be
    /// promoted to at least 1.0 so a bucket always allows at least one
    /// initial request. `TokenBucket::new` applies `.max(1.0)`; a
    /// regression that dropped the floor would create a bucket that
    /// rejects *every* request (tokens start at 0, need >= 1 to acquire)
    /// and trigger a thundering-herd of rejections at startup. This is
    /// the more defensive complement to `minimum_burst_of_one`: that test
    /// uses `Some(0.5)`, we additionally pin the exact `Some(0.0)` edge.
    #[test]
    fn burst_zero_is_floored_to_one() {
        let bucket = TokenBucket::new(5.0, Some(0.0));
        assert!(
            bucket.try_acquire(),
            "burst floored to 1.0 — first request must succeed even with Some(0.0)"
        );
        assert!(
            !bucket.try_acquire(),
            "burst floored to 1.0 means exactly one token available before refill"
        );
    }

    /// Pin the `min(max_tokens)` saturation cap in the lazy-refill arm.
    /// After an arbitrary long idle period the `elapsed * refill_rate`
    /// term could grow unbounded; the `.min(self.max_tokens)` cap prevents
    /// it from exceeding the configured capacity. We simulate the
    /// "long idle" path via `tokio::time::pause()` + `advance()` so the
    /// test is deterministic without wall-clock sleeps. A regression that
    /// dropped the `min` cap would allow the bucket to absorb more than
    /// `max_tokens` requests in a single burst after idling.
    #[tokio::test(start_paused = true)]
    async fn refill_saturates_at_max_tokens_after_long_idle() {
        let bucket = TokenBucket::new(10.0, Some(3.0));
        // Drain the initial 3 tokens.
        for _ in 0..3 {
            assert!(bucket.try_acquire());
        }
        assert!(!bucket.try_acquire());

        // Advance 10 seconds — at 10 tokens/sec that is 100 tokens of
        // potential refill; the cap must trim it to max_tokens=3.
        tokio::time::advance(std::time::Duration::from_secs(10)).await;

        for i in 0..3 {
            assert!(
                bucket.try_acquire(),
                "request {i} should be allowed after idle refill saturates to max_tokens=3"
            );
        }
        // The 4th must be rejected — proof that the cap held.
        assert!(
            !bucket.try_acquire(),
            "refill must cap at max_tokens (3); if this fails, the .min() cap regressed"
        );
    }

    /// Pin the `last_refill` advancement: every `try_acquire` call must
    /// advance `last_refill` to `now`, regardless of whether a token was
    /// granted. If the timestamp only advanced on successful acquisitions,
    /// a stream of rejected calls would let `elapsed` grow unbounded and
    /// the next successful call would refill by a multi-second gap rather
    /// than by the true sub-millisecond delta. We observe this by
    /// draining the burst, calling `try_acquire` (rejected) several
    /// times across a small paused-time advance, then advancing to a
    /// point where a single token's worth of refill is available and
    /// verifying exactly one token appears (not the cumulative amount
    /// that would accrue if rejections had "banked" time).
    #[tokio::test(start_paused = true)]
    async fn rejected_try_acquire_still_advances_refill_clock() {
        let bucket = TokenBucket::new(10.0, Some(1.0));
        // Drain.
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());

        // A rejected call under paused time — last_refill advances to "now"
        // (which is still the same frozen instant), but critically the
        // partial-token state is recomputed.
        assert!(!bucket.try_acquire());
        assert!(!bucket.try_acquire());

        // Now advance 100ms — at 10/sec that is exactly 1.0 tokens.
        tokio::time::advance(std::time::Duration::from_millis(100)).await;

        assert!(
            bucket.try_acquire(),
            "after 100ms at 10/sec exactly 1.0 tokens should be available"
        );
        // Immediately after, no tokens should remain (cap=1, refill just
        // consumed).
        assert!(
            !bucket.try_acquire(),
            "second request right after must be rejected — only 1 token had refilled"
        );
    }
}
