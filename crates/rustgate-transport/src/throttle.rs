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
/// Create one per session. Call [`allow`] before processing each inbound
/// message; returns `false` when the client has exceeded its rate.
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
    pub fn new(rate: u32, burst: u32) -> Self {
        let capacity = burst.max(1);
        Self {
            capacity,
            refill_rate: f64::from(rate),
            state: AtomicU64::new(pack(capacity * 100, 0)),
            epoch: Instant::now(),
        }
    }

    /// Check whether a single message is allowed.
    ///
    /// Returns `true` if the message should be processed, `false` if it
    /// should be dropped (rate exceeded).
    pub fn allow(&self) -> bool {
        let now_ms = self.epoch.elapsed().as_millis() as u32;

        loop {
            let current = self.state.load(Ordering::Relaxed);
            let (tokens_x100, last_ms) = unpack(current);

            // Refill tokens based on elapsed time
            let elapsed_ms = now_ms.saturating_sub(last_ms);
            let refill = (self.refill_rate * f64::from(elapsed_ms) / 1000.0) as u32;
            let max_x100 = self.capacity * 100;
            let available = (tokens_x100 + refill * 100).min(max_x100);

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
}
