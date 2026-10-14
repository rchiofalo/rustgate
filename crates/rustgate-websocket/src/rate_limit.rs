// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-connection byte-rate and frame-rate limiting for WebSocket sessions.
//!
//! Uses a sliding window approach: tracks consumption over the last second
//! and rejects frames that would exceed the configured limits.

use std::time::{Duration, Instant};

/// Per-connection rate limiter for WebSocket frames and bytes.
///
/// Tracks frame count and byte count over a 1-second sliding window.
/// Returns whether a frame should be accepted or rejected.
#[derive(Debug)]
pub struct WsRateLimiter {
    /// Maximum frames per second (0 = unlimited).
    max_frames_per_sec: u32,
    /// Maximum bytes per second (0 = unlimited).
    max_bytes_per_sec: u64,
    /// Start of the current window.
    window_start: Instant,
    /// Frames consumed in the current window.
    frame_count: u32,
    /// Bytes consumed in the current window.
    byte_count: u64,
    /// Consecutive violations before disconnecting.
    max_violations: u32,
    /// Current consecutive violation count.
    violations: u32,
}

impl WsRateLimiter {
    /// Create a new rate limiter with the given limits.
    ///
    /// Set `max_frames_per_sec` or `max_bytes_per_sec` to 0 to disable
    /// that specific limit.
    pub fn new(max_frames_per_sec: u32, max_bytes_per_sec: u64, max_violations: u32) -> Self {
        Self {
            max_frames_per_sec,
            max_bytes_per_sec,
            window_start: Instant::now(),
            frame_count: 0,
            byte_count: 0,
            max_violations,
            violations: 0,
        }
    }

    /// Check if a frame of `size` bytes should be accepted.
    ///
    /// Returns `Ok(())` if accepted, `Err(RateLimitExceeded)` if rejected.
    /// Call [`should_disconnect`](Self::should_disconnect) after rejection to
    /// check if the client should be forcefully disconnected.
    pub fn check(&mut self, size: usize) -> Result<(), RateLimitExceeded> {
        self.maybe_reset_window();

        let frame_exceeded =
            self.max_frames_per_sec > 0 && self.frame_count >= self.max_frames_per_sec;
        let byte_exceeded = self.max_bytes_per_sec > 0
            && self.byte_count.saturating_add(size as u64) > self.max_bytes_per_sec;

        if frame_exceeded || byte_exceeded {
            self.violations += 1;
            return Err(RateLimitExceeded {
                frame_exceeded,
                byte_exceeded,
            });
        }

        self.frame_count += 1;
        self.byte_count += size as u64;
        self.violations = 0;
        Ok(())
    }

    /// Returns `true` if the client should be disconnected due to
    /// sustained rate limit violations.
    pub fn should_disconnect(&self) -> bool {
        self.max_violations > 0 && self.violations >= self.max_violations
    }

    /// Current frame count in the active window.
    pub fn frame_count(&self) -> u32 {
        self.frame_count
    }

    /// Current byte count in the active window.
    pub fn byte_count(&self) -> u64 {
        self.byte_count
    }

    /// Configured maximum frames per second.
    pub fn max_frames_per_sec(&self) -> u32 {
        self.max_frames_per_sec
    }

    /// Configured maximum bytes per second.
    pub fn max_bytes_per_sec(&self) -> u64 {
        self.max_bytes_per_sec
    }

    /// Reset the window if a second has elapsed.
    fn maybe_reset_window(&mut self) {
        let elapsed = self.window_start.elapsed();
        if elapsed >= Duration::from_secs(1) {
            self.window_start = Instant::now();
            self.frame_count = 0;
            self.byte_count = 0;
        }
    }
}

/// Details about which rate limit was exceeded.
#[derive(Debug)]
pub struct RateLimitExceeded {
    /// Whether the frame-rate limit was exceeded.
    pub frame_exceeded: bool,
    /// Whether the byte-rate limit was exceeded.
    pub byte_exceeded: bool,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn allows_within_limits() {
        let mut limiter = WsRateLimiter::new(10, 1000, 5);
        for _ in 0..10 {
            assert!(limiter.check(100).is_ok());
        }
    }

    #[test]
    fn rejects_frame_rate_exceeded() {
        let mut limiter = WsRateLimiter::new(5, 0, 5);
        for _ in 0..5 {
            assert!(limiter.check(1).is_ok());
        }
        assert!(limiter.check(1).is_err());
    }

    #[test]
    fn rejects_byte_rate_exceeded() {
        let mut limiter = WsRateLimiter::new(0, 100, 5);
        assert!(limiter.check(90).is_ok());
        assert!(limiter.check(20).is_err());
    }

    #[test]
    fn disconnect_after_sustained_violations() {
        let mut limiter = WsRateLimiter::new(1, 0, 3);
        assert!(limiter.check(1).is_ok());
        // 3 consecutive violations
        assert!(limiter.check(1).is_err());
        assert!(!limiter.should_disconnect());
        assert!(limiter.check(1).is_err());
        assert!(!limiter.should_disconnect());
        assert!(limiter.check(1).is_err());
        assert!(limiter.should_disconnect());
    }

    #[test]
    fn violation_counter_resets_on_success() {
        let mut limiter = WsRateLimiter::new(2, 0, 3);
        assert!(limiter.check(1).is_ok());
        assert!(limiter.check(1).is_ok());
        // Violation
        assert!(limiter.check(1).is_err());
        // Wait for window reset (simulate by directly resetting)
        limiter.window_start = Instant::now() - std::time::Duration::from_secs(2);
        assert!(limiter.check(1).is_ok());
        assert_eq!(limiter.violations, 0);
    }

    #[test]
    fn unlimited_when_zero() {
        let mut limiter = WsRateLimiter::new(0, 0, 0);
        for _ in 0..10000 {
            assert!(limiter.check(10000).is_ok());
        }
    }

    // ------------------------------------------------------------------
    // Trait bounds — the workspace lint `missing_debug_implementations =
    // "warn"` together with `RUSTFLAGS = -Dwarnings` turns a missing
    // `Debug` derive into a hard build failure. Pin both types'
    // `Debug` bound with a compile-time assertion so a regression that
    // adds a non-Debug field (e.g. a callback `Arc<dyn Fn>` that forgot
    // the `Debug` supertrait) lands at this test file rather than at
    // some distant `tracing::debug!(?limiter, …)` call site whose error
    // message is vague.
    // ------------------------------------------------------------------

    #[test]
    fn ws_rate_limiter_and_error_type_are_debug() {
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<WsRateLimiter>();
        assert_debug::<RateLimitExceeded>();
    }

    // ------------------------------------------------------------------
    // `RateLimitExceeded` flag shape — operators and metrics observers
    // rely on the two-bool contract to know *why* a frame was rejected:
    //  - frame_exceeded=true, byte_exceeded=false → client is flooding
    //    small frames (flood attack, buggy client retry loop)
    //  - frame_exceeded=false, byte_exceeded=true → client is sending a
    //    single large frame or a moderate volume at saturating size
    //  - both=true → heavy frame while already over the frame cap
    // A silent swap of the two flags (e.g. during a refactor that
    // renamed one field) would still pass `is_err()` but would produce
    // nonsense SIEM alerts. These three tests pin each shape explicitly.
    // ------------------------------------------------------------------

    #[test]
    fn rejects_with_only_frame_exceeded_flag_when_byte_limit_disabled() {
        let mut limiter = WsRateLimiter::new(1, 0, 10);
        assert!(limiter.check(1).is_ok());
        let err = limiter
            .check(1)
            .expect_err("second frame must breach the 1/sec frame cap");
        assert!(
            err.frame_exceeded,
            "frame_exceeded must be set when the frame cap is the only configured limit that breached"
        );
        assert!(
            !err.byte_exceeded,
            "byte_exceeded must not be set when max_bytes_per_sec is 0 (disabled)"
        );
    }

    #[test]
    fn rejects_with_only_byte_exceeded_flag_when_frame_limit_disabled() {
        let mut limiter = WsRateLimiter::new(0, 100, 10);
        assert!(limiter.check(90).is_ok());
        let err = limiter
            .check(20)
            .expect_err("cumulative 110 must breach the 100 byte cap");
        assert!(
            !err.frame_exceeded,
            "frame_exceeded must not be set when max_frames_per_sec is 0 (disabled)"
        );
        assert!(
            err.byte_exceeded,
            "byte_exceeded must be set when the byte cap is the only configured limit that breached"
        );
    }

    #[test]
    fn rejects_with_both_flags_when_both_limits_breach_on_same_frame() {
        // Fill the frame cap so the next check is already at frame_exceeded,
        // then send a single frame whose size also pushes past the byte cap.
        let mut limiter = WsRateLimiter::new(2, 50, 10);
        assert!(limiter.check(20).is_ok());
        assert!(limiter.check(20).is_ok());
        // Third frame: frame_count (2) >= max_frames_per_sec (2) → frame_exceeded.
        // byte_count (40) + size (30) = 70 > 50 → byte_exceeded.
        let err = limiter
            .check(30)
            .expect_err("third frame must breach both limits");
        assert!(err.frame_exceeded, "frame-cap breach must be reflected");
        assert!(err.byte_exceeded, "byte-cap breach must also be reflected");
    }

    // ------------------------------------------------------------------
    // Single oversized frame must fail on first call — pins that the
    // `byte_count.saturating_add(size) > max_bytes_per_sec` check fires
    // on the very first frame when size alone exceeds the budget, not
    // only after accumulated history. Operators configuring small caps
    // for chat-only deployments rely on this to reject oversize first
    // frames immediately rather than letting one through.
    // ------------------------------------------------------------------

    #[test]
    fn single_oversized_frame_is_rejected_without_accumulated_history() {
        let mut limiter = WsRateLimiter::new(0, 100, 10);
        let err = limiter
            .check(101)
            .expect_err("a single 101-byte frame must fail the 100-byte cap on the first try");
        assert!(err.byte_exceeded);
        assert!(!err.frame_exceeded);
        // And the state stays at zero — the reject branch must not
        // credit the frame/byte counters for a rejected frame.
        assert_eq!(
            limiter.frame_count(),
            0,
            "rejected frames must not bump frame_count"
        );
        assert_eq!(
            limiter.byte_count(),
            0,
            "rejected frames must not bump byte_count"
        );
    }

    // ------------------------------------------------------------------
    // Getter contract — every public getter is wired to a distinct field
    // and preserves the value handed to `new()`. A refactor that swapped
    // two getters (`max_frames_per_sec` returning `max_bytes_per_sec` as
    // a `u32`-truncated view) would compile but produce nonsense metrics
    // gauges. This test pins four distinct values across the struct so
    // any two-way swap fails with a concrete equality assertion.
    // ------------------------------------------------------------------

    #[test]
    fn getters_return_their_dedicated_fields() {
        let limiter = WsRateLimiter::new(7, 4096, 3);
        assert_eq!(limiter.max_frames_per_sec(), 7);
        assert_eq!(limiter.max_bytes_per_sec(), 4096);
        assert_eq!(limiter.frame_count(), 0);
        assert_eq!(limiter.byte_count(), 0);
    }

    #[test]
    fn frame_and_byte_count_advance_independently_per_successful_check() {
        // Accumulate three frames of distinct sizes so any cross-wiring
        // between the two counters fails with a specific number.
        let mut limiter = WsRateLimiter::new(0, 0, 0);
        assert!(limiter.check(10).is_ok());
        assert!(limiter.check(25).is_ok());
        assert!(limiter.check(7).is_ok());
        assert_eq!(
            limiter.frame_count(),
            3,
            "frame_count must count frames, not bytes"
        );
        assert_eq!(
            limiter.byte_count(),
            42,
            "byte_count must sum sizes (10+25+7), not frame count"
        );
    }

    // ------------------------------------------------------------------
    // Window rollover — the sliding-window reset inside
    // `maybe_reset_window` must zero *both* counters. The existing
    // `violation_counter_resets_on_success` test only pins that
    // violations return to zero on the post-window success path; a
    // refactor that forgot to zero `byte_count` would still pass that
    // test because the next window has enough budget for the single
    // small frame in the assertion. Here we burn most of the byte
    // budget, roll the window forward, and assert that a large frame
    // (which would otherwise reject against the lingering residual)
    // succeeds — the only way that passes is if both counters reset.
    // ------------------------------------------------------------------

    #[test]
    fn window_rollover_resets_both_frame_count_and_byte_count() {
        let mut limiter = WsRateLimiter::new(2, 100, 10);
        assert!(limiter.check(80).is_ok());
        assert_eq!(limiter.frame_count(), 1);
        assert_eq!(limiter.byte_count(), 80);

        // Simulate window elapse by rewinding window_start past the
        // 1-second threshold. The next `check()` hits `maybe_reset_window`
        // which must zero frame_count and byte_count before re-admitting.
        limiter.window_start = Instant::now() - Duration::from_millis(1_500);

        // A 90-byte frame in the new window must succeed (80+90=170 > 100
        // would fail if byte_count had not been cleared).
        assert!(
            limiter.check(90).is_ok(),
            "post-rollover byte budget must be fully restored"
        );
        assert_eq!(
            limiter.frame_count(),
            1,
            "frame_count must reset then increment to 1 in the new window"
        );
        assert_eq!(
            limiter.byte_count(),
            90,
            "byte_count must reset then advance by the new frame size"
        );
    }

    // ------------------------------------------------------------------
    // `should_disconnect` wiring — two branches that the existing suite
    // only exercises through the happy path:
    //  - max_violations=0 disables violation-based disconnect entirely,
    //    so a client that sustains unbounded violations must never
    //    trigger the "force disconnect" path (only the transport-level
    //    policy can evict them).
    //  - Hitting exactly `max_violations` is the tripwire — `>=` rather
    //    than `>`. This test pins the boundary so a regression to `>`
    //    (which would require one extra violation before evicting)
    //    fails here.
    // ------------------------------------------------------------------

    #[test]
    fn zero_max_violations_never_triggers_disconnect_regardless_of_breaches() {
        let mut limiter = WsRateLimiter::new(1, 0, 0);
        assert!(limiter.check(1).is_ok());
        // Force many consecutive violations.
        for _ in 0..1_000 {
            assert!(limiter.check(1).is_err());
        }
        assert!(
            !limiter.should_disconnect(),
            "max_violations=0 must disable the disconnect path even under sustained breach"
        );
    }

    #[test]
    fn should_disconnect_fires_at_exact_threshold_not_one_later() {
        // max_violations = 2 must disconnect on the 2nd violation, not the 3rd.
        let mut limiter = WsRateLimiter::new(1, 0, 2);
        assert!(limiter.check(1).is_ok());
        // 1st violation — below threshold.
        assert!(limiter.check(1).is_err());
        assert!(
            !limiter.should_disconnect(),
            "disconnect must not fire at violations=1 when max_violations=2"
        );
        // 2nd violation — must now meet `violations >= max_violations`.
        assert!(limiter.check(1).is_err());
        assert!(
            limiter.should_disconnect(),
            "disconnect must fire at violations==max_violations (>= boundary, not > )"
        );
    }

    // ------------------------------------------------------------------
    // `saturating_add` on `byte_count + size` guard — a pathological
    // frame whose `size as u64` would overflow `byte_count + size` when
    // summed naively must still produce a clean `byte_exceeded` reject
    // rather than a panic. The guard exists specifically for the case
    // where an attacker crafts a WebSocket frame header claiming a
    // massive size; we must reject loudly, not crash the session task.
    // ------------------------------------------------------------------

    #[test]
    fn saturating_add_guards_against_size_arithmetic_overflow() {
        let mut limiter = WsRateLimiter::new(0, 100, 10);
        // Accumulate some bytes first so byte_count is non-zero going in.
        assert!(limiter.check(50).is_ok());
        // A size of usize::MAX would overflow a naive byte_count + size
        // sum; `saturating_add` pins it at u64::MAX and the comparison
        // against max_bytes_per_sec (100) rejects cleanly.
        let err = limiter
            .check(usize::MAX)
            .expect_err("usize::MAX must reject, not panic");
        assert!(err.byte_exceeded);
        assert!(!err.frame_exceeded);
        // The state stays intact for the next legitimate check.
        assert_eq!(limiter.byte_count(), 50);
    }

    // ------------------------------------------------------------------
    // Zero-sized frame admission — WebSocket allows zero-length payload
    // frames (e.g. empty text frames used as keepalive probes). These
    // must count against the frame-rate limit but not the byte-rate
    // limit, otherwise a chatty client could bypass the frame cap by
    // sending zero-byte frames forever. This test pins both sides.
    // ------------------------------------------------------------------

    #[test]
    fn zero_size_frames_count_against_frame_cap_but_not_byte_cap() {
        let mut limiter = WsRateLimiter::new(3, 1_000, 10);
        assert!(limiter.check(0).is_ok());
        assert!(limiter.check(0).is_ok());
        assert!(limiter.check(0).is_ok());
        assert_eq!(limiter.frame_count(), 3);
        assert_eq!(limiter.byte_count(), 0);
        // Fourth zero-sized frame must breach the frame cap.
        let err = limiter
            .check(0)
            .expect_err("fourth zero-sized frame must hit the 3/sec frame cap");
        assert!(err.frame_exceeded);
        assert!(!err.byte_exceeded);
    }

    // ------------------------------------------------------------------
    // Send + Sync bounds — `WsRateLimiter` lives inside per-connection
    // state that tokio tasks move across thread boundaries under the
    // multi-thread runtime. The primitive fields are all `Send + Sync`
    // today, but a refactor that added a `Rc<...>` or a `Cell<...>`
    // field (both !Send) would silently break the session spawn path.
    // Pin both bounds at compile time so such a regression lands here.
    // ------------------------------------------------------------------

    #[test]
    fn ws_rate_limiter_is_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<WsRateLimiter>();
        assert_sync::<WsRateLimiter>();
        assert_send::<RateLimitExceeded>();
        assert_sync::<RateLimitExceeded>();
    }
}
