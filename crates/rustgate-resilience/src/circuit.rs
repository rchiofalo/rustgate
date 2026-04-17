// Copyright © 2026 Roberto Chiofalo.

//! Per-target circuit breaker.
//!
//! Implements a three-state circuit breaker (Closed → Open → HalfOpen)
//! modeled after resilience4j and Polly, with probe limiting and a
//! configurable success threshold for recovery. Transport-agnostic:
//! consumers decide how to handle rejected requests (drop, dead-letter,
//! fall back to a secondary endpoint, etc.).
//!
//! State transitions:
//! - **Closed → Open**: after `threshold` consecutive failures.
//! - **Open → HalfOpen**: after `cooldown` duration elapses.
//! - **HalfOpen → Closed**: after `success_threshold` consecutive probe
//!   successes (default 2 — avoids flapping on a single lucky request).
//! - **HalfOpen → Open**: on any probe failure (resets cooldown timer).
//!
//! Half-Open probe limiting: at most `max_half_open_probes` concurrent
//! probes are allowed. Additional requests are rejected while probes are
//! in flight, preventing thundering-herd against a recovering endpoint.

use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// Circuit breaker states represented as atomic values.
const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

/// Per-target circuit breaker.
///
/// Uses atomics for the state and failure counter so the hot path
/// (`allow_request`) requires no locking. The `opened_at` timestamp
/// is protected by the state machine invariant: only one thread
/// transitions Open → HalfOpen via compare-exchange.
#[derive(Debug)]
pub struct CircuitBreaker {
    state: AtomicU8,
    consecutive_failures: AtomicU32,
    threshold: u32,
    cooldown: Duration,
    /// Timestamp when the circuit transitioned to Open.
    /// Only meaningful when `state == STATE_OPEN`.
    opened_at: std::sync::Mutex<Option<Instant>>,
    /// Number of probe requests sent in the current HalfOpen window.
    /// Reset when transitioning into HalfOpen or back to Open/Closed.
    half_open_probes: AtomicU32,
    /// Maximum probes allowed in HalfOpen before blocking further requests.
    max_half_open_probes: u32,
    /// Consecutive successes recorded in the current HalfOpen window.
    /// Must reach `success_threshold` to close the circuit.
    half_open_successes: AtomicU32,
    /// Successful probes needed to transition HalfOpen → Closed.
    success_threshold: u32,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    ///
    /// - `threshold`: consecutive failures before tripping Closed → Open.
    /// - `cooldown`: duration to wait in Open before probing.
    /// - `max_half_open_probes`: max concurrent probes in HalfOpen (default 3).
    /// - `success_threshold`: consecutive successes to close from HalfOpen (default 2).
    pub fn new(
        threshold: u32,
        cooldown: Duration,
        max_half_open_probes: u32,
        success_threshold: u32,
    ) -> Self {
        Self {
            state: AtomicU8::new(STATE_CLOSED),
            consecutive_failures: AtomicU32::new(0),
            threshold,
            cooldown,
            opened_at: std::sync::Mutex::new(None),
            half_open_probes: AtomicU32::new(0),
            max_half_open_probes,
            half_open_successes: AtomicU32::new(0),
            success_threshold,
        }
    }

    /// Returns `true` if the request should be allowed through.
    ///
    /// - **Closed**: always allows.
    /// - **Open**: checks if cooldown has elapsed; if so, transitions to
    ///   HalfOpen and allows one probe request.
    /// - **HalfOpen**: allows up to `max_half_open_probes` concurrent probes,
    ///   then rejects further requests until a probe completes.
    pub fn allow_request(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            STATE_CLOSED => true,
            STATE_OPEN => self.try_half_open(),
            STATE_HALF_OPEN => {
                // Gate: only allow up to max_half_open_probes
                let prev = self.half_open_probes.fetch_add(1, Ordering::AcqRel);
                if prev < self.max_half_open_probes {
                    true
                } else {
                    // Roll back — we exceeded the limit
                    let _ = self.half_open_probes.fetch_sub(1, Ordering::AcqRel);
                    false
                }
            }
            _ => false,
        }
    }

    /// Record a successful request.
    ///
    /// In Closed state, resets the failure counter. In HalfOpen state,
    /// increments the success counter and closes the circuit once the
    /// `success_threshold` is reached.
    ///
    /// Returns `true` if the circuit recovered (HalfOpen → Closed).
    pub fn record_success(&self) -> bool {
        let current = self.state.load(Ordering::Acquire);
        self.consecutive_failures.store(0, Ordering::Release);

        if current == STATE_HALF_OPEN {
            let count = self.half_open_successes.fetch_add(1, Ordering::AcqRel) + 1;
            if count >= self.success_threshold {
                self.close();
                return true;
            }
        }
        false
    }

    /// Record a failed request. May trip the circuit to Open.
    ///
    /// In HalfOpen state, any failure immediately re-opens the circuit
    /// (the probe failed). In Closed state, the circuit trips after
    /// `threshold` consecutive failures.
    ///
    /// Returns `true` if the circuit tripped (Closed/HalfOpen → Open).
    pub fn record_failure(&self) -> bool {
        let current_state = self.state.load(Ordering::Acquire);

        // HalfOpen probe failed — immediately re-open
        if current_state == STATE_HALF_OPEN {
            self.trip();
            return true;
        }

        let prev = self.consecutive_failures.fetch_add(1, Ordering::AcqRel);
        let new_count = prev + 1;

        if new_count >= self.threshold {
            self.trip();
            return true;
        }
        false
    }

    /// Current state as a numeric value for metrics gauges.
    /// 0 = closed, 1 = open, 2 = half-open.
    #[cfg(any(test, feature = "metrics"))]
    #[allow(dead_code)] // Used in tests; metrics reporting will call this
    pub fn state_value(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    /// Returns `true` if the circuit is currently closed (healthy).
    pub fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_CLOSED
    }

    /// Transition to Closed state, resetting all counters.
    fn close(&self) {
        self.half_open_probes.store(0, Ordering::Release);
        self.half_open_successes.store(0, Ordering::Release);
        self.consecutive_failures.store(0, Ordering::Release);
        let prev = self.state.swap(STATE_CLOSED, Ordering::AcqRel);
        if prev != STATE_CLOSED {
            tracing::info!("circuit breaker recovered to closed");
        }
    }

    /// Transition to Open state, recording the current timestamp.
    fn trip(&self) {
        self.half_open_probes.store(0, Ordering::Release);
        self.half_open_successes.store(0, Ordering::Release);
        let prev = self.state.swap(STATE_OPEN, Ordering::AcqRel);
        if let Ok(mut guard) = self.opened_at.lock() {
            *guard = Some(Instant::now());
        }
        if prev != STATE_OPEN {
            tracing::warn!("circuit breaker tripped to open");
        }
    }

    /// Attempt to transition from Open → HalfOpen if cooldown elapsed.
    ///
    /// Uses compare-exchange so only one thread wins the transition.
    /// Resets probe and success counters for the new HalfOpen window.
    fn try_half_open(&self) -> bool {
        let cooldown_elapsed = self
            .opened_at
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .is_some_and(|t| t.elapsed() >= self.cooldown);

        if cooldown_elapsed {
            // CAS: only one thread transitions to HalfOpen
            let transitioned = self
                .state
                .compare_exchange(
                    STATE_OPEN,
                    STATE_HALF_OPEN,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok();

            if transitioned {
                self.consecutive_failures.store(0, Ordering::Release);
                // Reset probe counters for the new HalfOpen window.
                // Start at 1 — this request is the first probe.
                self.half_open_probes.store(1, Ordering::Release);
                self.half_open_successes.store(0, Ordering::Release);
            }

            transitioned
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, unused_results)]

    use super::*;

    /// Helper: standard breaker with success_threshold=1 for simple tests.
    fn breaker(threshold: u32, cooldown_ms: u64) -> CircuitBreaker {
        CircuitBreaker::new(threshold, Duration::from_millis(cooldown_ms), 3, 1)
    }

    /// Helper: breaker with configurable half-open parameters.
    fn breaker_full(
        threshold: u32,
        cooldown_ms: u64,
        max_probes: u32,
        success_threshold: u32,
    ) -> CircuitBreaker {
        CircuitBreaker::new(
            threshold,
            Duration::from_millis(cooldown_ms),
            max_probes,
            success_threshold,
        )
    }

    #[test]
    fn starts_closed() {
        let cb = breaker(3, 1000);
        assert!(cb.is_closed());
        assert_eq!(cb.state_value(), STATE_CLOSED);
        assert!(cb.allow_request());
    }

    #[test]
    fn stays_closed_below_threshold() {
        let cb = breaker(3, 1000);
        cb.record_failure();
        cb.record_failure();
        // 2 failures, threshold is 3 — still closed
        assert!(cb.is_closed());
        assert!(cb.allow_request());
    }

    #[test]
    fn trips_at_threshold() {
        let cb = breaker(3, 1000);
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.is_closed());
        assert_eq!(cb.state_value(), STATE_OPEN);
        assert!(!cb.allow_request());
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = breaker(3, 1000);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        // Failure count reset — need 3 more to trip
        cb.record_failure();
        assert!(cb.is_closed());
    }

    #[test]
    fn open_blocks_requests() {
        let cb = breaker(1, 60_000); // long cooldown
        cb.record_failure();
        assert_eq!(cb.state_value(), STATE_OPEN);
        assert!(!cb.allow_request());
    }

    #[tokio::test]
    async fn transitions_to_half_open_after_cooldown() {
        let cb = breaker(1, 10); // 10ms cooldown
        cb.record_failure();
        assert_eq!(cb.state_value(), STATE_OPEN);

        // Wait for cooldown
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Should transition to half-open and allow one request
        assert!(cb.allow_request());
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);
    }

    #[tokio::test]
    async fn half_open_success_closes_circuit() {
        let cb = breaker(1, 10); // success_threshold=1
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Probe request
        assert!(cb.allow_request());
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);

        // Probe succeeds — threshold is 1, so closes immediately
        cb.record_success();
        assert!(cb.is_closed());
        assert_eq!(cb.state_value(), STATE_CLOSED);
    }

    #[tokio::test]
    async fn half_open_failure_reopens_circuit() {
        let cb = breaker(1, 10);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Probe request
        assert!(cb.allow_request());
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);

        // Probe fails — back to open
        cb.record_failure();
        assert_eq!(cb.state_value(), STATE_OPEN);
        assert!(!cb.allow_request());
    }

    #[test]
    fn threshold_of_one_trips_immediately() {
        let cb = breaker(1, 1000);
        cb.record_failure();
        assert_eq!(cb.state_value(), STATE_OPEN);
    }

    #[test]
    fn intermittent_failures_do_not_trip() {
        let cb = breaker(3, 1000);
        // fail, succeed, fail, succeed — never hits 3 consecutive
        cb.record_failure();
        cb.record_success();
        cb.record_failure();
        cb.record_success();
        cb.record_failure();
        cb.record_success();
        assert!(cb.is_closed());
    }

    #[test]
    fn multiple_successes_keep_closed() {
        let cb = breaker(3, 1000);
        for _ in 0..10 {
            cb.record_success();
        }
        assert!(cb.is_closed());
    }

    #[tokio::test]
    async fn cooldown_not_elapsed_stays_open() {
        let cb = breaker(1, 60_000); // 60s cooldown
        cb.record_failure();
        assert_eq!(cb.state_value(), STATE_OPEN);

        // Cooldown hasn't elapsed — should stay open
        assert!(!cb.allow_request());
        assert_eq!(cb.state_value(), STATE_OPEN);
    }

    #[tokio::test]
    async fn full_cycle_closed_open_halfopen_closed() {
        let cb = breaker(2, 10);

        // Start closed
        assert!(cb.is_closed());
        assert!(cb.allow_request());

        // Trip to open
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state_value(), STATE_OPEN);

        // Wait for cooldown
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Transition to half-open
        assert!(cb.allow_request());
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);

        // Probe success → closed (success_threshold=1)
        cb.record_success();
        assert!(cb.is_closed());
        assert_eq!(cb.state_value(), STATE_CLOSED);
    }

    #[tokio::test]
    async fn full_cycle_with_probe_failure() {
        let cb = breaker(2, 10);

        // Trip to open
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state_value(), STATE_OPEN);

        // Wait for cooldown
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Transition to half-open
        assert!(cb.allow_request());
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);

        // Probe fails → back to open
        cb.record_failure();
        assert_eq!(cb.state_value(), STATE_OPEN);

        // Wait for cooldown again
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Second probe → half-open
        assert!(cb.allow_request());
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);

        // This time it succeeds → closed
        cb.record_success();
        assert!(cb.is_closed());
    }

    // -----------------------------------------------------------------------
    // Half-Open probe limiting
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn half_open_limits_probe_count() {
        // max_half_open_probes=2, so only 2 concurrent probes allowed
        let cb = breaker_full(1, 10, 2, 1);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // First request triggers Open → HalfOpen (counts as probe 1)
        assert!(cb.allow_request());
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);

        // Second probe allowed (2 <= max 2)
        assert!(cb.allow_request());

        // Third probe rejected — at limit
        assert!(!cb.allow_request());
    }

    #[tokio::test]
    async fn half_open_probe_limit_resets_on_trip() {
        let cb = breaker_full(1, 10, 2, 1);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Enter half-open, use up probes
        assert!(cb.allow_request()); // probe 1 (from try_half_open)
        assert!(cb.allow_request()); // probe 2
        assert!(!cb.allow_request()); // rejected

        // Probe fails → re-opens, resets counters
        cb.record_failure();
        assert_eq!(cb.state_value(), STATE_OPEN);

        tokio::time::sleep(Duration::from_millis(20)).await;

        // Fresh half-open window — probes available again
        assert!(cb.allow_request()); // probe 1
        assert!(cb.allow_request()); // probe 2
        assert!(!cb.allow_request()); // rejected again
    }

    // -----------------------------------------------------------------------
    // Success threshold
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn half_open_requires_multiple_successes() {
        // success_threshold=3: need 3 consecutive successes to close
        let cb = breaker_full(1, 10, 5, 3);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(cb.allow_request()); // triggers half-open
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);

        // First two successes keep circuit half-open
        cb.record_success();
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);
        cb.record_success();
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);

        // Third success meets threshold → closes
        cb.record_success();
        assert!(cb.is_closed());
    }

    #[tokio::test]
    async fn half_open_failure_resets_success_count() {
        // success_threshold=2
        let cb = breaker_full(1, 10, 5, 2);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(cb.allow_request()); // half-open
        cb.record_success(); // 1 of 2
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);

        // Failure resets everything back to open
        cb.record_failure();
        assert_eq!(cb.state_value(), STATE_OPEN);

        tokio::time::sleep(Duration::from_millis(20)).await;

        // New half-open window — success count starts from 0 again
        assert!(cb.allow_request());
        cb.record_success(); // 1 of 2
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);
        cb.record_success(); // 2 of 2 → closed
        assert!(cb.is_closed());
    }

    #[tokio::test]
    async fn success_threshold_of_one_behaves_like_original() {
        // success_threshold=1 matches the pre-improvement behavior
        let cb = breaker_full(1, 10, 3, 1);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(cb.allow_request());
        cb.record_success();
        assert!(cb.is_closed());
    }
}
