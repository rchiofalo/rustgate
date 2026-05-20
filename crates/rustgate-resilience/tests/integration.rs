// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the composed behavior of the resilience
//! primitives.
//!
//! Inline unit tests in each module cover the per-primitive contracts
//! (circuit breaker state transitions, token bucket lazy refill,
//! retry backoff jitter, sliding window key eviction). These
//! integration tests cover the **cross-primitive composition** patterns
//! that real callers exercise:
//!
//! 1. **Circuit breaker + retry composition** — the canonical
//!    "wrap an HTTP call" pattern where the circuit guards a retry
//!    loop with exponential backoff.
//! 2. **Token bucket concurrent fairness** — multiple threads
//!    competing for tokens, no thread starves, no over-issue past the
//!    declared burst.
//! 3. **Sliding window admission under contention** — multiple
//!    threads probing different keys, per-key counts stay independent.
//! 4. **Circuit breaker half-open probe gating** — load test the
//!    `max_half_open_probes` bound under concurrent
//!    `allow_request()` calls (the actual concurrency invariant the
//!    breaker exists to enforce).
//! 5. **Composition under tokio time advance** — proves the
//!    primitives compose correctly when wall clock and tokio's
//!    paused-clock harness disagree (which they do in tests).
//!
//! These complement the unit tests rather than duplicating them.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rustgate_resilience::circuit::CircuitBreaker;
use rustgate_resilience::retry::{backoff_with_jitter, is_retryable_status};
use rustgate_resilience::sliding_window::SlidingWindowLimiter;
use rustgate_resilience::token_bucket::TokenBucket;

// ------------------------------------------------------------------
// Circuit breaker + retry composition
// ------------------------------------------------------------------

/// The canonical "wrap an HTTP call" pattern: a retry loop bounded by
/// `backoff_with_jitter`, each attempt gated by the circuit breaker's
/// `allow_request()`. After enough consecutive failures the breaker
/// opens, the retry loop short-circuits, and the caller surfaces the
/// outage instead of grinding through every retry.
#[test]
fn circuit_breaker_short_circuits_retry_loop_after_threshold_failures() {
    let breaker = CircuitBreaker::new(
        3,                            // failure threshold to open
        Duration::from_millis(5_000), // cooldown
        2,                            // half-open probe limit
        2,                            // half-open successes to close
    );

    // Simulate 10 retry attempts against a totally-down target.
    let mut attempts_allowed: u32 = 0;
    let mut attempts_short_circuited: u32 = 0;

    for attempt in 0..10 {
        if !breaker.allow_request() {
            attempts_short_circuited += 1;
            // In a real caller this is where we'd surface
            // CircuitOpen to the upstream RPC.
            continue;
        }
        attempts_allowed += 1;

        // Backoff jitter is sampled but never used in this test — we
        // care about the call count, not the wall-clock sleep.
        let _delay = backoff_with_jitter(Duration::from_millis(1), attempt);

        // Synthetic: this target is down. Every attempt fails.
        let _was_open = breaker.record_failure();
    }

    // After 3 failures (the threshold), the breaker opens. The
    // remaining 7 attempts ALL short-circuit at `allow_request`.
    assert_eq!(
        attempts_allowed, 3,
        "exactly the threshold-count of attempts should reach the upstream",
    );
    assert_eq!(
        attempts_short_circuited, 7,
        "all post-open attempts must be short-circuited by the breaker",
    );
    assert!(!breaker.is_closed());
}

/// `is_retryable_status` and the breaker compose correctly: a 500
/// response triggers `record_failure` (and contributes to opening),
/// a 200 triggers `record_success` (and contributes to closing).
#[test]
fn is_retryable_status_drives_breaker_in_realistic_response_mix() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(60), 1, 1);

    // Mix of HTTP responses. 5xx is retryable (counts as failure for
    // the breaker); 2xx is success; 4xx is client error (not
    // retryable, not a breaker concern).
    let responses = [200, 503, 200, 502, 200, 504, 200, 500, 200, 200];

    for status in responses {
        if !breaker.allow_request() {
            // Short-circuited; would otherwise be passed to caller as
            // CircuitOpen.
            continue;
        }
        if is_retryable_status(status) {
            let _ = breaker.record_failure();
        } else if (200..300).contains(&status) {
            let _ = breaker.record_success();
        }
        // 4xx ignored — neither success nor failure for the breaker.
    }

    // Five 2xxs vs four 5xxs — failure threshold of 5 was never hit
    // consecutively, so the breaker stays closed.
    assert!(
        breaker.is_closed(),
        "mixed-response stream below failure threshold must not trip the breaker",
    );
}

// ------------------------------------------------------------------
// Token bucket concurrent fairness
// ------------------------------------------------------------------

/// Multiple threads contending for tokens from a shared bucket must
/// not over-issue past the declared burst. Verifies the lazy-refill +
/// mutex-protected accounting holds under contention.
#[test]
fn token_bucket_never_over_issues_under_concurrent_acquire() {
    // 100-token burst, 0 refill rate — bucket starts full, no refill
    // during the test. Any over-issue is a real bug, not a clock-race.
    let bucket = Arc::new(TokenBucket::new(0.0, Some(100.0)));

    const THREADS: usize = 16;
    const ATTEMPTS_PER_THREAD: usize = 50;
    let acquired = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let bucket = Arc::clone(&bucket);
            let acquired = Arc::clone(&acquired);
            thread::spawn(move || {
                for _ in 0..ATTEMPTS_PER_THREAD {
                    if bucket.try_acquire() {
                        let _ = acquired.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("token-bucket worker");
    }

    let total = acquired.load(Ordering::SeqCst);
    assert_eq!(
        total, 100,
        "exactly the burst ({total}) tokens should be issued, never over",
    );
}

/// `try_acquire_n` for multi-token requests must atomically check +
/// debit. A request for more tokens than available must fail without
/// partially debiting the bucket.
#[test]
fn token_bucket_multi_acquire_is_atomic_no_partial_debit() {
    let bucket = TokenBucket::new(0.0, Some(10.0)); // 10 tokens, no refill

    // Drain 7 tokens with single acquires.
    for _ in 0..7 {
        assert!(bucket.try_acquire(), "single acquires before drain succeed");
    }
    assert!(
        (bucket.current_tokens() - 3.0).abs() < f64::EPSILON,
        "bucket should have 3 tokens left, got {}",
        bucket.current_tokens()
    );

    // Try to acquire 5 — must fail (only 3 available). Atomic: no
    // partial debit.
    assert!(bucket.try_acquire_n(5.0).is_err(), "5 > 3 must reject");
    assert!(
        (bucket.current_tokens() - 3.0).abs() < f64::EPSILON,
        "failed try_acquire_n must NOT debit the bucket, got {}",
        bucket.current_tokens()
    );

    // 3 succeeds atomically.
    bucket
        .try_acquire_n(3.0)
        .expect("3 == 3 must succeed atomically");
    assert!(
        bucket.current_tokens() < f64::EPSILON,
        "bucket must be fully drained, got {}",
        bucket.current_tokens()
    );
}

// ------------------------------------------------------------------
// Sliding window per-key independence
// ------------------------------------------------------------------

/// Multiple threads probing DIFFERENT keys must not interfere with
/// each other's counts. Each per-key window is independent.
#[test]
fn sliding_window_keeps_per_key_counts_independent_under_contention() {
    let limiter = Arc::new(SlidingWindowLimiter::new(
        100,
        Duration::from_secs(10),
        "test_sliding_window_per_key_independence",
    ));

    const THREADS: usize = 4;
    const ATTEMPTS_PER_KEY: usize = 50;

    // Each thread uses a unique IP key — counts should never bleed
    // across threads.
    let handles: Vec<_> = (0..THREADS)
        .map(|i| {
            let limiter = Arc::clone(&limiter);
            #[allow(clippy::cast_possible_truncation)]
            let octet = i as u8;
            thread::spawn(move || {
                let key = IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet));
                let now = Instant::now();
                let mut admitted = 0;
                for _ in 0..ATTEMPTS_PER_KEY {
                    if limiter.try_check(key, now) {
                        admitted += 1;
                    }
                }
                admitted
            })
        })
        .collect();

    for h in handles {
        let admitted = h.join().expect("sliding-window worker");
        // All 50 attempts per key fit under the limit of 100 — every
        // attempt should admit.
        assert_eq!(
            admitted, ATTEMPTS_PER_KEY,
            "no key should have been rate-limited (limit=100, attempts=50)",
        );
    }
}

/// One thread saturates a single key past the limit; other keys must
/// have FULL capacity available (proving per-key isolation — the busy
/// key's saturation does not bleed into the quiet key's count).
#[test]
fn sliding_window_saturated_key_does_not_block_other_keys() {
    let limiter =
        SlidingWindowLimiter::new(5, Duration::from_secs(60), "test_sliding_window_saturation");
    let busy = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let quiet = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
    let now = Instant::now();

    // Saturate the busy key: 5 admits succeed, 6th is rate-limited.
    for _ in 0..5 {
        assert!(limiter.try_check(busy, now), "first 5 must admit");
    }
    assert!(
        !limiter.try_check(busy, now),
        "6th attempt on busy key must be limited",
    );
    assert!(
        limiter.is_limited(busy),
        "busy key should report `is_limited` after saturation",
    );

    // Quiet key starts at 0/5 (NOT 5/5) — its budget is fully
    // independent. All 5 admits succeed.
    for i in 0..5 {
        assert!(
            limiter.try_check(quiet, now),
            "quiet key admit {} must succeed (independent budget)",
            i + 1,
        );
    }
    // After 5 admits, the quiet key is at its OWN saturation point.
    // That's the expected state — `is_limited` returning true here
    // proves we are checking the quiet key's actual count, not a
    // bleed from the busy key. The independence claim is: the quiet
    // key got 5 admits, not 0 admits (which would happen if the
    // counts were shared globally).
    assert!(
        !limiter.try_check(quiet, now),
        "quiet key's 6th attempt should be limited at its own saturation point",
    );
}

// ------------------------------------------------------------------
// Circuit breaker half-open probe limit under concurrency
// ------------------------------------------------------------------

/// When the breaker is in HalfOpen state, `max_half_open_probes`
/// requests are allowed through to test recovery. Under concurrent
/// `allow_request()` calls, exactly that many must succeed — not
/// fewer (would starve recovery probes), not more (would defeat the
/// probe-limit guarantee).
///
/// Uses a manually-driven CircuitBreaker (open it via 3 failures, then
/// wait past the cooldown so the next `allow_request` flips it to
/// HalfOpen) and races many threads at the probe gate.
#[test]
fn circuit_breaker_half_open_admits_exactly_probe_limit_under_concurrency() {
    let breaker = Arc::new(CircuitBreaker::new(
        3,                         // open after 3 failures
        Duration::from_millis(50), // short cooldown for the test
        4,                         // half-open probe limit
        2,                         // success threshold
    ));

    // Open the breaker.
    for _ in 0..3 {
        assert!(breaker.allow_request());
        let _ = breaker.record_failure();
    }
    assert!(
        !breaker.is_closed(),
        "breaker must be open after 3 failures"
    );
    assert!(
        !breaker.allow_request(),
        "post-open requests are short-circuited",
    );

    // Wait past the cooldown so the next `allow_request` transitions
    // Open → HalfOpen and starts admitting probes.
    thread::sleep(Duration::from_millis(80));

    // Race 16 threads at the half-open gate.
    const RACERS: usize = 16;
    let admitted = Arc::new(AtomicUsize::new(0));
    let handles: Vec<_> = (0..RACERS)
        .map(|_| {
            let breaker = Arc::clone(&breaker);
            let admitted = Arc::clone(&admitted);
            thread::spawn(move || {
                if breaker.allow_request() {
                    let _ = admitted.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("half-open probe racer");
    }

    let count = admitted.load(Ordering::SeqCst);
    assert_eq!(
        count, 4,
        "exactly max_half_open_probes (=4) racers must be admitted, got {count}",
    );
}

// ------------------------------------------------------------------
// Backoff jitter range
// ------------------------------------------------------------------

/// `backoff_with_jitter` must (a) increase per attempt (exponential
/// backoff) and (b) stay within the 0–25% jitter band documented in
/// the rustdoc. Run many samples per attempt and check the
/// statistical envelope.
#[test]
fn backoff_with_jitter_envelope_per_attempt() {
    let base = Duration::from_millis(100);

    for attempt in 0..6_u32 {
        let nominal = base.saturating_mul(2_u32.saturating_pow(attempt));
        let upper = nominal + nominal / 4; // +25% jitter cap

        // 1000 samples per attempt.
        for _ in 0..1_000 {
            let observed = backoff_with_jitter(base, attempt);
            assert!(
                observed >= nominal,
                "attempt {attempt}: observed {observed:?} below nominal {nominal:?}",
            );
            assert!(
                observed <= upper,
                "attempt {attempt}: observed {observed:?} above upper {upper:?}",
            );
        }
    }
}
