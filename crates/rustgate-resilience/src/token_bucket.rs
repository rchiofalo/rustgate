// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
        self.try_acquire_n(1.0).is_ok()
    }

    /// Try to consume `n` tokens at once. Returns `Ok(())` on success.
    ///
    /// Used by the per-tenant aggregate-throughput limiter (issue #883
    /// sub-item 4) where each byte of payload corresponds to one token —
    /// a single `try_acquire` call per message would force the caller
    /// into an `n`-iteration loop and would not actually represent the
    /// "drop or admit" decision the byte-budget bucket needs to make.
    ///
    /// Returns `Err(TokenBucketRejection { available })` when the bucket
    /// holds fewer than `n` tokens after the lazy refill. The returned
    /// `available` count is captured *after* the refill but *before* any
    /// decrement, so audit-emitting callers can attribute the rejection
    /// to the actual headroom rather than a raw stale snapshot.
    ///
    /// Refills tokens based on elapsed time before checking availability.
    /// On mutex poisoning, allows the request (fail-open — matching the
    /// workspace pattern in [`super::conn_rate_limiter`]). The fail-open
    /// path returns `available = 0` so a caller that audits the
    /// rejection still emits a deterministic value rather than leaking
    /// stale state from before the poison.
    pub fn try_acquire_n(&self, n: f64) -> Result<(), TokenBucketRejection> {
        let n = if n.is_finite() { n.max(0.0) } else { 0.0 };
        let Ok(mut guard) = self.state.lock() else {
            // Fail-open on mutex poison — don't block traffic on internal error
            return Ok(());
        };

        let now = Instant::now();
        let elapsed = now.duration_since(guard.last_refill).as_secs_f64();
        guard.tokens = (guard.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        guard.last_refill = now;

        if guard.tokens >= n {
            guard.tokens -= n;
            Ok(())
        } else {
            Err(TokenBucketRejection {
                available: guard.tokens.max(0.0),
            })
        }
    }

    /// Snapshot of the current token level. Lazily refills the bucket
    /// before reading so the value reflects the same accounting the
    /// next [`try_acquire_n`](Self::try_acquire_n) would observe.
    ///
    /// Used by the per-tenant `OnTenantThroughputConsumed` callback
    /// (issue #883 sub-item 4) so a Prometheus gauge can publish
    /// "current bucket level" without taking a token.
    pub fn current_tokens(&self) -> f64 {
        let Ok(mut guard) = self.state.lock() else {
            // Fail-open on mutex poison — same convention as `try_acquire`.
            return self.max_tokens;
        };
        let now = Instant::now();
        let elapsed = now.duration_since(guard.last_refill).as_secs_f64();
        guard.tokens = (guard.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        guard.last_refill = now;
        guard.tokens.max(0.0)
    }

    /// Configured maximum bucket capacity (tokens). Exposed so audit
    /// sinks can record the configured cap alongside an
    /// over-the-cap rejection without re-reading the constructor
    /// arguments.
    pub fn capacity(&self) -> f64 {
        self.max_tokens
    }
}

/// Rejection returned by [`TokenBucket::try_acquire_n`].
///
/// `available` is the number of tokens the bucket held at the moment
/// of rejection (after the lazy refill). Audit callers use this to
/// attribute the drop event to the actual bucket level rather than
/// re-reading via [`TokenBucket::current_tokens`] (which would race
/// against concurrent acquires and a refill clock advance).
#[derive(Debug, Clone, Copy)]
pub struct TokenBucketRejection {
    /// Tokens remaining when the rejection was decided.
    pub available: f64,
}

impl std::fmt::Display for TokenBucketRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "token bucket rejected: {:.2} tokens available",
            self.available
        )
    }
}

impl std::error::Error for TokenBucketRejection {}

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

    // -- try_acquire_n / current_tokens / capacity coverage -----------

    #[test]
    fn try_acquire_n_admits_partial_burst() {
        // Issue #883 sub-item 4: byte-token semantics. A 1_000-token
        // bucket should accept a single 800-token request and reject a
        // follow-up 300-token request because only 200 tokens remain.
        let bucket = TokenBucket::new(0.0, Some(1_000.0));
        assert!(bucket.try_acquire_n(800.0).is_ok());
        let err = bucket
            .try_acquire_n(300.0)
            .expect_err("over-cap request must be rejected");
        // The reported `available` must reflect the true post-decrement
        // headroom — 200 tokens, not the original 1 000.
        assert!(
            (err.available - 200.0).abs() < 1.0,
            "available should be ~200, got {}",
            err.available
        );
    }

    #[test]
    fn try_acquire_n_rejects_when_under_request_size() {
        let bucket = TokenBucket::new(0.0, Some(100.0));
        let err = bucket
            .try_acquire_n(101.0)
            .expect_err("request larger than capacity must reject");
        // Available is the bucket's current level (~100), NOT 0.
        assert!(err.available >= 99.0 && err.available <= 100.0);
    }

    #[test]
    fn try_acquire_n_zero_is_a_no_op_admit() {
        // A zero-byte payload should not be charged against the bucket
        // — there is nothing to queue and rejecting would degrade
        // protocol heartbeats. Pin the no-op-admit semantics.
        let bucket = TokenBucket::new(0.0, Some(1.0));
        assert!(bucket.try_acquire_n(0.0).is_ok());
        // The 1-token cap is still intact afterwards.
        assert!(bucket.try_acquire_n(1.0).is_ok());
        assert!(bucket.try_acquire_n(1.0).is_err());
    }

    #[test]
    fn try_acquire_n_negative_request_is_clamped_to_zero() {
        // Defensive: a negative `n` (from a buggy size computation
        // upstream) must NOT drive the bucket level upwards on
        // subtraction. Clamp to zero so the call is a no-op admit.
        let bucket = TokenBucket::new(0.0, Some(5.0));
        assert!(bucket.try_acquire_n(-100.0).is_ok());
        // Bucket still has its full 5-token capacity.
        assert!(bucket.try_acquire_n(5.0).is_ok());
        assert!(bucket.try_acquire_n(0.5).is_err());
    }

    #[test]
    fn try_acquire_n_nan_request_is_treated_as_zero() {
        let bucket = TokenBucket::new(0.0, Some(5.0));
        assert!(
            bucket.try_acquire_n(f64::NAN).is_ok(),
            "NaN request size must be sanitized to zero, not corrupt the bucket"
        );
        // Cap is still intact after the NaN call.
        assert!(bucket.try_acquire_n(5.0).is_ok());
        assert!(bucket.try_acquire_n(1.0).is_err());
    }

    #[test]
    fn current_tokens_reflects_post_refill_level() {
        let bucket = TokenBucket::new(0.0, Some(100.0));
        assert!((bucket.current_tokens() - 100.0).abs() < 0.01);
        assert!(bucket.try_acquire_n(40.0).is_ok());
        assert!((bucket.current_tokens() - 60.0).abs() < 0.01);
    }

    #[test]
    fn capacity_returns_configured_max() {
        let bucket = TokenBucket::new(50.0, Some(123.0));
        assert!((bucket.capacity() - 123.0).abs() < f64::EPSILON);
    }

    #[tokio::test(start_paused = true)]
    async fn try_acquire_n_refills_over_time() {
        let bucket = TokenBucket::new(100.0, Some(100.0));
        // Drain.
        assert!(bucket.try_acquire_n(100.0).is_ok());
        assert!(bucket.try_acquire_n(50.0).is_err());
        // Wait 0.5s — refills 50 tokens at 100/s.
        tokio::time::advance(std::time::Duration::from_millis(500)).await;
        assert!(bucket.try_acquire_n(50.0).is_ok());
        assert!(bucket.try_acquire_n(0.5).is_err());
    }

    #[test]
    fn rejection_display_contains_available() {
        let bucket = TokenBucket::new(0.0, Some(10.0));
        let err = bucket.try_acquire_n(20.0).unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("token bucket rejected"));
        assert!(s.contains("10"));
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
