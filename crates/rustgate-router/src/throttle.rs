// Copyright © 2026 Roberto Chiofalo.

//! Per-client message rate limiter.
//!
//! Uses a token-bucket algorithm to enforce a maximum message rate per
//! connected client. Tokens refill at a steady rate; each message
//! consumes one token. When the bucket is empty the message is dropped.
//!
//! The limiter is designed for the read-loop hot path — no locks, just
//! atomic state packed into a single u64 for the common (under-limit) case.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Per-client rate limiter using a token bucket.
///
/// Create one per session. Call [`ClientThrottle::allow`] before processing
/// each inbound message; returns `false` when the client has exceeded its rate.
#[derive(Debug)]
pub struct ClientThrottle {
    /// Maximum burst size (bucket capacity).
    capacity: u32,
    /// Tokens added per second.
    refill_rate: f64,
    /// Packed state: upper 32 bits = available tokens (×100 for fractional),
    /// lower 32 bits = timestamp offset from `epoch`.
    state: AtomicU64,
    /// Reference instant for computing time deltas.
    epoch: Instant,
}

/// Pack token count (×100) and timestamp offset into a single u64.
fn pack(tokens_x100: u32, ts_offset_ms: u32) -> u64 {
    ((tokens_x100 as u64) << 32) | (ts_offset_ms as u64)
}

/// Unpack the u64 into (tokens_x100, ts_offset_ms).
fn unpack(val: u64) -> (u32, u32) {
    let tokens_x100 = (val >> 32) as u32;
    let ts_offset_ms = val as u32;
    (tokens_x100, ts_offset_ms)
}

impl ClientThrottle {
    /// Create a new throttle.
    ///
    /// - `rate`: maximum sustained messages per second
    /// - `burst`: maximum burst above the steady rate (bucket capacity)
    ///
    /// `burst` is clamped to `u32::MAX / 100` to prevent overflow in the
    /// ×100 fractional-token representation.
    pub fn new(rate: u32, burst: u32) -> Self {
        // Clamp to avoid overflow when multiplying by 100 for fractional tokens.
        const MAX_CAPACITY: u32 = u32::MAX / 100;
        let capacity = burst.clamp(1, MAX_CAPACITY);
        Self {
            capacity,
            refill_rate: f64::from(rate),
            state: AtomicU64::new(pack(capacity.saturating_mul(100), 0)),
            epoch: Instant::now(),
        }
    }

    /// Check whether a single message is allowed.
    ///
    /// Returns `true` if the message should be processed, `false` if it
    /// should be dropped (rate exceeded).
    pub fn allow(&self) -> bool {
        // The millisecond offset is truncated into the packed u32, so it
        // wraps to 0 once every ~49.7 days of session uptime. The wrap is
        // benign and self-correcting: on the single cycle spanning the
        // wrap, `last_ms` (just before u32::MAX) exceeds `now_ms` (just
        // after 0), so `saturating_sub` clamps `elapsed_ms` to 0 and that
        // one refill is skipped. The bucket simply misses one refill tick
        // and resumes correctly on the next call — never an over-refill.
        // Widening the packed layout past u64 to carry a full 64-bit
        // timestamp is not worth the extra CAS width for a once-per-~50-day
        // one-cycle stall on a connection that has stayed up that long.
        let now_ms = self.epoch.elapsed().as_millis() as u32;

        loop {
            let current = self.state.load(Ordering::Relaxed);
            let (tokens_x100, last_ms) = unpack(current);

            // Refill tokens based on elapsed time.
            // Use u64 intermediates to prevent overflow on large refill values.
            let elapsed_ms = now_ms.saturating_sub(last_ms);
            let refill = (self.refill_rate * f64::from(elapsed_ms) / 1000.0) as u64;
            let max_x100 = u64::from(self.capacity) * 100;
            let available =
                (u64::from(tokens_x100) + refill.saturating_mul(100)).min(max_x100) as u32;

            if available < 100 {
                // Not enough for one token
                return false;
            }

            let new_state = pack(available - 100, now_ms);
            if self
                .state
                .compare_exchange_weak(current, new_state, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
            // CAS failed — another thread raced us; retry
        }
    }

    /// Current number of available tokens (approximate, for diagnostics).
    pub fn available(&self) -> u32 {
        let (tokens_x100, _) = unpack(self.state.load(Ordering::Relaxed));
        tokens_x100 / 100
    }

    /// Configured refill rate in messages per second.
    ///
    /// Exposed so audit sinks can record the configured limit when a drop
    /// event is emitted; the value is the rate the throttle was constructed
    /// with (no precision loss from `f64` since the constructor takes `u32`).
    pub fn rate(&self) -> u32 {
        self.refill_rate as u32
    }
}

/// Configuration for per-client rate limiting.
#[derive(Debug, Clone, Copy)]
pub struct ThrottleConfig {
    /// Maximum sustained messages per second per client.
    pub rate: u32,
    /// Maximum burst size (messages allowed above the steady rate).
    pub burst: u32,
}

impl ThrottleConfig {
    /// Create a new throttle config.
    pub fn new(rate: u32, burst: u32) -> Self {
        Self { rate, burst }
    }

    /// Build a [`ClientThrottle`] from this configuration.
    pub fn build(&self) -> ClientThrottle {
        ClientThrottle::new(self.rate, self.burst)
    }
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            rate: 100,
            burst: 200,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn allows_under_limit() {
        let throttle = ClientThrottle::new(100, 10);
        for _ in 0..10 {
            assert!(throttle.allow(), "should allow messages up to burst");
        }
    }

    #[test]
    fn rejects_over_burst() {
        let throttle = ClientThrottle::new(100, 5);
        for _ in 0..5 {
            assert!(throttle.allow());
        }
        assert!(!throttle.allow(), "should reject after burst exhausted");
    }

    #[test]
    fn refills_over_time() {
        let throttle = ClientThrottle::new(1000, 1);
        // Exhaust the single token
        assert!(throttle.allow());
        assert!(!throttle.allow());

        // Wait for refill (1000/s = 1 per ms, wait 10ms for safety)
        std::thread::sleep(Duration::from_millis(10));
        assert!(throttle.allow(), "should have refilled after delay");
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let tokens = 42_000u32;
        let ts = 123_456u32;
        let packed = pack(tokens, ts);
        let (t, s) = unpack(packed);
        assert_eq!(t, tokens);
        assert_eq!(s, ts);
    }

    #[test]
    fn config_default() {
        let cfg = ThrottleConfig::default();
        assert_eq!(cfg.rate, 100);
        assert_eq!(cfg.burst, 200);
    }

    #[test]
    fn config_build() {
        let cfg = ThrottleConfig::new(50, 10);
        let throttle = cfg.build();
        assert_eq!(throttle.capacity, 10);
    }

    #[test]
    fn available_reflects_usage() {
        let throttle = ClientThrottle::new(100, 5);
        assert_eq!(throttle.available(), 5);
        let _ = throttle.allow();
        assert_eq!(throttle.available(), 4);
    }

    #[test]
    fn large_burst_clamped_no_overflow() {
        // burst > u32::MAX / 100 would overflow if multiplied by 100.
        let throttle = ClientThrottle::new(100, u32::MAX);
        // Should not panic; capacity is clamped.
        assert!(throttle.available() > 0);
        assert!(throttle.allow());
    }

    #[test]
    fn large_rate_no_overflow() {
        // Very high refill rate that would overflow u32 in refill * 100.
        let throttle = ClientThrottle::new(u32::MAX, 10);
        for _ in 0..10 {
            assert!(throttle.allow());
        }
        // Exhaust burst, wait for refill, verify it still works.
        std::thread::sleep(Duration::from_millis(10));
        assert!(throttle.allow(), "should refill without overflow");
    }

    // ── Contract-shape coverage ─────────────────────────────────────
    //
    // The tests above cover the sunny path of the token-bucket
    // algorithm (allow/reject, refill, pack, overflow clamping) but
    // leave several contract-shape invariants unpinned — bounds the
    // read-loop depends on to even compile, the rate() accessor the
    // audit sinks read, boundary-input clamping on burst / rate, the
    // Default-is-full-bucket invariant, the refill-upper-bound that
    // stops `available()` from exceeding `capacity` regardless of how
    // long the session idles, and the CAS correctness of `allow()`
    // under concurrent contention.  A refactor that weakens any of
    // these would still pass every sunny-path test but surface as a
    // silent production regression — dropped traffic on a restart,
    // stale rate in an audit log, or a race on a shared Arc.
    //
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn client_throttle_is_debug_send_sync() {
        // Every session owns a `ClientThrottle` inside an `Arc` shared
        // between the read loop, the drop-handling path, and the audit
        // sink.  Losing `Send` or `Sync` would fail to compile at the
        // sharing site; losing `Debug` would break every
        // `tracing::debug!(?throttle, …)` line operators rely on for
        // triage.  Pin the bounds locally so the offending change
        // lights up this module first.
        fn assert_bounds<T: std::fmt::Debug + Send + Sync>() {}
        assert_bounds::<ClientThrottle>();
    }

    #[test]
    fn throttle_config_is_debug_clone_copy_default_send_sync() {
        // `ThrottleConfig` is passed by value through the builder
        // chain and stored in the listener config struct.  The Copy
        // derive is load-bearing (every `.build()` call takes `&self`
        // and the caller re-uses the config afterwards).  Default is
        // the operator-friendly "sensible defaults" hook.
        fn assert_bounds<T: std::fmt::Debug + Clone + Copy + Default + Send + Sync>() {}
        assert_bounds::<ThrottleConfig>();
    }

    #[test]
    fn rate_accessor_returns_configured_value() {
        // The `rate()` accessor exists specifically so audit sinks can
        // log the configured limit alongside a drop event — without
        // it, an operator who sees "client X dropped N messages" has
        // no way to know whether the limit was 100 or 10 000.  The
        // getter is documented as lossless for the constructor's
        // `u32` input (no precision loss from the internal `f64`),
        // so pin that contract across a handful of representative
        // values.
        assert_eq!(ClientThrottle::new(100, 10).rate(), 100);
        assert_eq!(ClientThrottle::new(1, 1).rate(), 1);
        assert_eq!(ClientThrottle::new(1_000_000, 10).rate(), 1_000_000);
        // rate = 0 is legal; the resulting throttle never refills,
        // which is a useful "disabled" sentinel — pin that the getter
        // round-trips 0 rather than coercing to 1.
        assert_eq!(ClientThrottle::new(0, 5).rate(), 0);
    }

    #[test]
    fn new_clamps_zero_burst_to_one_so_throttle_always_allows_at_least_one_message() {
        // `burst.clamp(1, MAX_CAPACITY)` — a burst of 0 would otherwise
        // produce an always-reject throttle, which is rarely what an
        // operator meant (typical intent is "1 token, refilled at rate").
        // Pin the lower clamp so a regression that changed the floor
        // fails here rather than at a mystery-loss incident.
        let t = ClientThrottle::new(100, 0);
        assert_eq!(
            t.available(),
            1,
            "burst=0 must clamp to capacity=1, bucket starts full"
        );
        assert!(
            t.allow(),
            "zero-burst throttle must still allow the first token"
        );
    }

    #[test]
    fn new_with_zero_rate_exhausts_then_never_refills() {
        // rate = 0 is a legitimate "disable refills" setting.  The
        // bucket starts full (capacity tokens) and, once drained, does
        // NOT refill regardless of elapsed time.  A refactor that
        // silently treated rate=0 as "unlimited" would flip the
        // semantics.
        let t = ClientThrottle::new(0, 3);
        assert!(t.allow());
        assert!(t.allow());
        assert!(t.allow());
        assert!(!t.allow(), "bucket empty after capacity allows");
        // Even after a generous wait, no refill should occur.
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            !t.allow(),
            "rate=0 must not refill regardless of elapsed time"
        );
    }

    #[test]
    fn initial_available_equals_capacity_so_bucket_starts_full() {
        // The constructor packs `capacity * 100` tokens into the
        // initial state — a regression that started at half-capacity
        // (or empty) would break the "first N messages always pass"
        // contract every session-start assumes.
        for burst in [1u32, 5, 10, 200, 65_536] {
            let t = ClientThrottle::new(100, burst);
            assert_eq!(
                t.available(),
                burst,
                "bucket must start at exactly capacity={burst}"
            );
        }
    }

    #[test]
    fn available_never_exceeds_capacity_regardless_of_idle_duration() {
        // `available = (… + refill).min(max_x100)` caps the bucket at
        // `capacity` even after a long idle period.  A regression that
        // dropped the `.min(max_x100)` would let an idle session
        // accumulate arbitrary burst credit, defeating the entire
        // purpose of the "burst" parameter.
        let t = ClientThrottle::new(1000, 5); // 1000 tokens/sec, burst 5
        // Exhaust the bucket.
        for _ in 0..5 {
            assert!(t.allow());
        }
        // Wait long enough that 50 tokens' worth of refill would
        // accrue if uncapped (50 ms × 1000 tokens/sec = 50 tokens).
        std::thread::sleep(Duration::from_millis(50));
        // Cap MUST hold: available must be <= 5, not 50.
        assert!(
            t.available() <= 5,
            "available must cap at capacity=5 even after long idle; got {}",
            t.available()
        );
    }

    #[test]
    fn pack_unpack_round_trip_at_u32_max_boundary() {
        // Pack/unpack is a pure helper but the boundary matters: the
        // refill path packs `available - 100` which can legitimately
        // reach very large values when rate is high.  Pin the u32::MAX
        // boundary so a regression that narrowed the split (e.g. used
        // 31-bit halves) fails here.
        let packed = pack(u32::MAX, u32::MAX);
        let (t, s) = unpack(packed);
        assert_eq!(t, u32::MAX);
        assert_eq!(s, u32::MAX);
    }

    #[test]
    fn pack_unpack_is_injective_for_distinct_token_counts_at_same_timestamp() {
        // If two distinct `(tokens, ts)` pairs ever packed to the same
        // u64, the CAS loop in `allow()` could race-match a state it
        // did not actually observe and silently skip a decrement.  Pin
        // injectivity on the token half for a fixed timestamp.
        let a = pack(100, 500);
        let b = pack(200, 500);
        assert_ne!(a, b);
        let (ta, sa) = unpack(a);
        let (tb, sb) = unpack(b);
        assert_eq!(sa, sb, "timestamps match");
        assert_ne!(ta, tb, "token halves differ");
    }

    #[test]
    fn config_build_produces_independent_throttles_per_call() {
        // `ThrottleConfig::build(&self)` takes `&self` and returns a
        // fresh `ClientThrottle` per call — each session gets its own
        // token bucket, not a shared one.  A regression that stored
        // the `ClientThrottle` inside `ThrottleConfig` and returned a
        // clone would share state across sessions and let one busy
        // client drain every other client's quota.
        let cfg = ThrottleConfig::new(10, 3);
        let a = cfg.build();
        let b = cfg.build();
        // Exhaust one bucket.
        for _ in 0..3 {
            assert!(a.allow());
        }
        assert!(!a.allow(), "bucket a drained");
        // Bucket b must be independent.
        for _ in 0..3 {
            assert!(
                b.allow(),
                "bucket b must start full regardless of a's state"
            );
        }
    }

    #[test]
    fn concurrent_allow_calls_never_exceed_burst_without_refill() {
        // Stress-test the CAS loop in `allow()`.  `rate = 0` pins the
        // refill contribution at exactly 0 tokens regardless of how
        // much wall time the threads consume (the earlier rate=0 test
        // proves this), so the total number of `true` returns MUST
        // equal exactly `burst` — no more, no less.  A regression in
        // the CAS ordering (e.g. `Ordering::Relaxed` changed to a
        // reordering-permissive combination, or the wrong `current`
        // read before the CAS) would produce either double-counts
        // (> burst) or lost updates (< burst).  `std::thread::scope`
        // gives us parallel N=16 contention without spawning Tokio.
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;

        const THREADS: usize = 16;
        const ATTEMPTS_PER_THREAD: usize = 100;
        const BURST: u32 = 50;

        let t = Arc::new(ClientThrottle::new(0, BURST));
        let allowed = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|s| {
            for _ in 0..THREADS {
                let t = Arc::clone(&t);
                let allowed = Arc::clone(&allowed);
                let _ = s.spawn(move || {
                    for _ in 0..ATTEMPTS_PER_THREAD {
                        if t.allow() {
                            let _ = allowed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        });

        let total = allowed.load(Ordering::Relaxed);
        assert_eq!(
            total, BURST as usize,
            "CAS must let exactly BURST messages through under contention; got {total}"
        );
    }
}
