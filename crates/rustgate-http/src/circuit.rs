// Copyright © 2026 Roberto Chiofalo.

//! Per-target circuit breaker for HTTP egress.
//!
//! Implements a three-state circuit breaker (Closed → Open → HalfOpen)
//! that prevents repeated requests to failing endpoints. When open,
//! messages are logged as dead-letters rather than queued or retried.
//!
//! State transitions:
//! - **Closed → Open**: after `threshold` consecutive failures.
//! - **Open → HalfOpen**: after `cooldown` duration elapses.
//! - **HalfOpen → Closed**: on first success (probe passed).
//! - **HalfOpen → Open**: on first failure (probe failed, reset cooldown).

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
pub(crate) struct CircuitBreaker {
    state: AtomicU8,
    consecutive_failures: AtomicU32,
    threshold: u32,
    cooldown: Duration,
    /// Timestamp when the circuit transitioned to Open.
    /// Only meaningful when `state == STATE_OPEN`.
    opened_at: std::sync::Mutex<Option<Instant>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given threshold and cooldown.
    ///
    /// The breaker starts in the Closed state (all requests allowed).
    pub(crate) fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            state: AtomicU8::new(STATE_CLOSED),
            consecutive_failures: AtomicU32::new(0),
            threshold,
            cooldown,
            opened_at: std::sync::Mutex::new(None),
        }
    }

    /// Returns `true` if the request should be allowed through.
    ///
    /// - **Closed**: always allows.
    /// - **Open**: checks if cooldown has elapsed; if so, transitions to
    ///   HalfOpen and allows one probe request.
    /// - **HalfOpen**: allows (probe in progress).
    pub(crate) fn allow_request(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            STATE_CLOSED | STATE_HALF_OPEN => true,
            STATE_OPEN => self.try_half_open(),
            _ => false,
        }
    }

    /// Record a successful request. Resets the circuit to Closed.
    pub(crate) fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
        let prev = self.state.swap(STATE_CLOSED, Ordering::AcqRel);
        if prev != STATE_CLOSED {
            tracing::info!("circuit breaker recovered to closed");
        }
    }

    /// Record a failed request. May trip the circuit to Open.
    ///
    /// In HalfOpen state, any failure immediately re-opens the circuit
    /// (the probe failed). In Closed state, the circuit trips after
    /// `threshold` consecutive failures.
    pub(crate) fn record_failure(&self) {
        let current_state = self.state.load(Ordering::Acquire);

        // HalfOpen probe failed — immediately re-open
        if current_state == STATE_HALF_OPEN {
            self.trip();
            return;
        }

        let prev = self.consecutive_failures.fetch_add(1, Ordering::AcqRel);
        let new_count = prev + 1;

        if new_count >= self.threshold {
            self.trip();
        }
    }

    /// Current state as a numeric value for metrics gauges.
    /// 0 = closed, 1 = open, 2 = half-open.
    #[cfg(any(test, feature = "metrics"))]
    #[allow(dead_code)] // Used in tests; metrics reporting will call this
    pub(crate) fn state_value(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    /// Returns `true` if the circuit is currently closed (healthy).
    pub(crate) fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_CLOSED
    }

    /// Transition to Open state, recording the current timestamp.
    fn trip(&self) {
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
    /// Uses compare-exchange so only one thread wins the probe slot.
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
            }

            transitioned
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn breaker(threshold: u32, cooldown_ms: u64) -> CircuitBreaker {
        CircuitBreaker::new(threshold, Duration::from_millis(cooldown_ms))
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
        let cb = breaker(1, 10);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Probe request
        assert!(cb.allow_request());
        assert_eq!(cb.state_value(), STATE_HALF_OPEN);

        // Probe succeeds
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

        // Probe success → closed
        cb.record_success();
        assert!(cb.is_closed());
        assert!(cb.allow_request());
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
}
