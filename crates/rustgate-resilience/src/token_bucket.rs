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

    // -- defensive-invariant coverage -----------------------------------

    #[test]
    fn token_bucket_is_send_sync_static() {
        // `TokenBucket` is shared across concurrent outbound-request paths
        // via `Arc<TokenBucket>`; a regression that added a `!Send` or
        // `!Sync` field (e.g. `Rc`, `*const _`) would fail the downstream
        // `Arc<dyn … + Send + Sync>` boxing, but only at the far call site.
        // Pin here so the compile error points at the offending field.
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<TokenBucket>();
    }

    #[test]
    fn concurrent_acquires_do_not_exceed_capacity_under_contention() {
        // Thread-safety proof: with zero refill and a fixed capacity, the
        // sum of successful acquires across N contending threads must
        // equal capacity exactly — never more (double-count bug) and never
        // less (spurious-reject bug). A regression that replaced the
        // `Mutex` with a relaxed-ordering atomic without the proper CAS
        // loop would produce an off-by-one overshoot here.
        use std::sync::Arc;
        use std::thread;
        let capacity = 100.0_f64;
        let bucket = Arc::new(TokenBucket::new(0.0, Some(capacity)));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let b = Arc::clone(&bucket);
            handles.push(thread::spawn(move || {
                (0..50).filter(|_| b.try_acquire()).count()
            }));
        }
        let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            total, capacity as usize,
            "concurrent acquire total must equal capacity exactly; got {total}"
        );
    }

    #[test]
    fn mutex_poison_fails_open_not_closed() {
        // Workspace convention (`super::conn_rate_limiter`): mutex poison
        // is treated as an internal error, not a client problem — requests
        // are allowed through rather than silently blocked. A regression
        // that flipped the default to fail-closed would drop traffic on
        // every request after an unrelated panic in the same process.
        use std::sync::Arc;
        let bucket = Arc::new(TokenBucket::new(10.0, Some(10.0)));
        // Drain so a healthy bucket would naturally reject the next call.
        for _ in 0..10 {
            let _ = bucket.try_acquire();
        }
        assert!(!bucket.try_acquire());

        // Poison the inner mutex by panicking while holding the lock.
        let b = Arc::clone(&bucket);
        let _ = std::thread::spawn(move || {
            let _guard = b.state.lock().unwrap();
            panic!("intentional: poison the bucket's mutex");
        })
        .join();

        // Poisoned mutex must fail-open — allow the request through.
        assert!(
            bucket.try_acquire(),
            "poisoned mutex must fail-open (allow), not fail-closed (reject)"
        );
    }

    #[test]
    fn zero_rate_with_default_burst_allows_exactly_one_request() {
        // rate_per_sec = 0.0 with burst = None → max_tokens =
        // burst.unwrap_or(0.0).max(1.0) = 1.0. The bucket starts with one
        // token and never refills. This is the minimum-viable degraded
        // configuration: the caller gets a single request through and then
        // is blocked. A regression that replaced the `.max(1.0)` floor
        // with `.max(0.0)` would produce a bucket that rejects every
        // request on construction — silent fail-closed for misconfigured
        // deployments.
        let bucket = TokenBucket::new(0.0, None);
        assert!(
            bucket.try_acquire(),
            "initial single-token burst must always be allowed"
        );
        assert!(!bucket.try_acquire(), "no refill at rate=0");
        assert!(!bucket.try_acquire());
        assert!(!bucket.try_acquire());
    }

    #[tokio::test(start_paused = true)]
    async fn negative_rate_is_clamped_to_zero_refill() {
        // `rate_per_sec.max(0.0)` clamps negative inputs to zero. A
        // regression that used `rate_per_sec.abs()` or removed the clamp
        // would either flip the sign (refilling the bucket at a spurious
        // positive rate) or propagate negative tokens into the state
        // (corrupting the `tokens >= 1.0` comparison).
        let bucket = TokenBucket::new(-5.0, Some(3.0));
        for _ in 0..3 {
            assert!(bucket.try_acquire());
        }
        assert!(!bucket.try_acquire());
        // A 60-second advance at any positive rate would refill well past
        // capacity; clamped to zero, no refill occurs.
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        assert!(
            !bucket.try_acquire(),
            "negative rate must clamp to zero refill, not flip sign"
        );
    }

    #[test]
    fn nan_rate_and_burst_do_not_corrupt_bucket_state() {
        // `f64::max` returns the non-NaN argument when one side is NaN, so
        // `NaN.max(0.0) = 0.0` and `NaN.max(1.0) = 1.0`. This gives the
        // construction a well-defined sanitizer for pathological inputs
        // (NaN from deserialising `rate-per-sec = inf` / malformed config)
        // and produces a bucket with zero refill and a one-token burst. A
        // regression that used `if rate.is_finite() { rate } else { 0.0 }`
        // naively (missing the NaN case) would let NaN into the state
        // where `tokens + elapsed * NaN = NaN` poisons every subsequent
        // comparison.
        let bucket = TokenBucket::new(f64::NAN, Some(f64::NAN));
        assert!(
            bucket.try_acquire(),
            "NaN-burst must be floored to 1.0 so the initial token is available"
        );
        assert!(
            !bucket.try_acquire(),
            "NaN-rate must clamp to 0.0 so no refill corruption leaks in"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refill_saturates_at_max_tokens_even_after_long_idle() {
        // After a long idle period, a naive `tokens += elapsed * rate`
        // without the `.min(max_tokens)` cap would produce a 600-token
        // bucket (10/s × 60s) on a bucket advertised as having 10-capacity
        // — giving a single caller a 60× burst advantage over the
        // documented contract. Pin the cap explicitly so a refactor that
        // re-ordered the clamp/compare path stays safe.
        let bucket = TokenBucket::new(10.0, Some(10.0));
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }
        assert!(!bucket.try_acquire());
        // Advance 60s: would refill 600 tokens without the cap.
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        for i in 0..10 {
            assert!(bucket.try_acquire(), "post-idle acquire {i} must succeed");
        }
        assert!(
            !bucket.try_acquire(),
            "cap at max_tokens=10 must hold even after 60s idle"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sub_unit_refill_rate_takes_multiple_seconds_per_token() {
        // A 0.1/s bucket refills one token every 10 seconds. The
        // fractional-token accumulator must survive multiple sub-threshold
        // acquire attempts without either losing the partial tokens or
        // artificially rounding up to 1.0. A regression that coerced
        // `tokens` to `u64` (losing the fractional part on every refill)
        // would extend the effective wait to infinity.
        let bucket = TokenBucket::new(0.1, None);
        assert!(
            bucket.try_acquire(),
            "initial token from default-burst floor of 1.0"
        );
        assert!(!bucket.try_acquire(), "drained, partial refill not yet due");
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        assert!(
            !bucket.try_acquire(),
            "5s × 0.1/s = 0.5 tokens, below the 1.0 threshold"
        );
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        assert!(
            bucket.try_acquire(),
            "10s × 0.1/s = 1.0 tokens, fractional accumulation must cross the threshold"
        );
        assert!(
            !bucket.try_acquire(),
            "fresh token consumed, back to fractional state"
        );
    }
}
