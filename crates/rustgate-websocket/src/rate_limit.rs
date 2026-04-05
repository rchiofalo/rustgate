//! Per-connection byte-rate and frame-rate limiting for WebSocket sessions.
//!
//! Uses a sliding window approach: tracks consumption over the last second
//! and rejects frames that would exceed the configured limits.

use std::time::Instant;

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

    /// Reset the window if a second has elapsed.
    fn maybe_reset_window(&mut self) {
        let elapsed = self.window_start.elapsed();
        if elapsed.as_secs() >= 1 {
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
}
