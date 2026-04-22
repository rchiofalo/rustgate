// Copyright © 2026 Roberto Chiofalo.

//! Global admission control / backpressure gate.
//!
//! Tracks the total number of in-flight "queued" bytes across all sessions
//! and the router's pending route work. When the counter crosses the
//! high-water mark, the accept loop is parked (via [`BackpressureGate::wait_for_capacity`])
//! until the counter has stayed at or below the low-water mark for at least
//! the configured resume-dwell (default 1s). This prevents a flood of slow
//! readers from exhausting memory and the rapid oscillation that would
//! otherwise thrash the accept loop when load hovers at the high-water mark.
//!
//! The gate is designed to be shared via `Arc` across the TLS accept loop
//! and the router. Increment via [`BackpressureGate::add`] when enqueueing
//! message work, and decrement via [`BackpressureGate::sub`] when the work
//! completes. [`BackpressurePermit`] provides a panic-safe RAII wrapper
//! that subs on drop.
//!
//! ## Per-session delivery strategy
//!
//! The global gate protects against overall system memory exhaustion, but
//! per-session message delivery is always non-blocking. The router uses
//! `try_send` for every recipient channel so a single slow consumer
//! cannot block delivery to all other sessions:
//!
//! - **Direct** messages to full channels are persisted for offline
//!   redelivery via the store-and-forward queue.
//! - **Group** and **broadcast** messages to full channels are dropped
//!   and counted.
//! - The per-session circuit breaker disconnects persistently slow
//!   sessions after N consecutive `try_send` failures.
//!
//! ## Oscillation fix (#878)
//!
//! Without dwell, load oscillating between 90% and 100% of capacity
//! repeatedly flips admission on and off — the accept loop spins up a
//! new TLS handshake, the new session's first message pushes us back
//! over the high-water mark, admission flips off, the permit drops
//! clear below low-water, admission flips back on, and so on. This
//! thrashing wastes CPU, spams the deferred-count metric, and can
//! overwhelm the accept path's handshake-parallelism budget.
//!
//! Once the gate blocks, it stays blocked until the counter has been
//! continuously at-or-below `low_water` for at least `resume_dwell`.
//! Any rise back above `low_water` during the dwell window cancels the
//! cooldown; the timer restarts on the next drop.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

/// Default high-water mark: 512 MiB of queued/in-flight bytes.
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 512 * 1024 * 1024;

/// Default minimum time the counter must stay at/below the low-water
/// mark before admission resumes after a block. Prevents oscillation
/// when load hovers near the high-water mark.
pub const DEFAULT_RESUME_DWELL: Duration = Duration::from_secs(1);

/// Polling interval used by [`BackpressureGate::wait_for_capacity`] to
/// re-evaluate the dwell timer when no further `sub` calls arrive. Short
/// enough to be responsive, long enough to be cheap. Not user-tunable.
const DWELL_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Callback invoked whenever the accept loop is deferred due to
/// backpressure. Used to increment metrics counters without a hard
/// dependency on the `metrics` feature from this crate.
///
/// **Must be non-blocking.** The callback fires synchronously from
/// [`BackpressureGate::wait_for_capacity`], which in turn is awaited
/// on the TLS accept loop. A blocking callback (e.g. one that performs
/// synchronous I/O, acquires a heavily-contended lock, or calls into
/// user code that does either) stalls the accept loop and breaks
/// admission control. Safe targets: `AtomicU64::fetch_add`, Prometheus
/// counter `inc()`, a `tracing::debug!` line. Unsafe targets: file I/O,
/// HTTP requests, `std::sync::Mutex::lock` on a shared lock. If the
/// callback may block, dispatch the work with
/// [`rustgate_core::tasks::spawn_background`] inside the closure body.
pub type OnDeferred = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked whenever the current queued-bytes counter changes.
/// Used to refresh a gauge.
///
/// **Must be non-blocking.** This callback fires on every `add` and
/// `sub` — i.e. potentially once per message delivered — so any blocking
/// work compounds into observable message-path latency. Safe targets:
/// `IntGauge::set`, atomic counter updates. If the work is not
/// provably wait-free, dispatch it with [`rustgate_core::tasks::spawn_background`]
/// from inside the closure.
pub type OnBytesChanged = Arc<dyn Fn(usize) + Send + Sync>;

/// Returned by the three `BackpressureGate` setters (`with_resume_dwell`,
/// `set_on_deferred`, `set_on_bytes_changed`) when they can no longer take
/// effect because the gate has already been shared via `Arc::clone`.
///
/// These setters rely on `Arc::get_mut`, which only succeeds while the
/// `Arc` has a single strong reference. Before this error existed, a
/// late call silently no-op'd: a developer wiring metrics after cloning
/// the gate into the router and the accept loop would see no panic and
/// no log, and the gate would run without the metric callback
/// installed. The returned `Err` now surfaces that misordering so
/// `main()` (or any caller) can fail startup instead of drifting into
/// production with missing instrumentation.
#[derive(Debug, thiserror::Error)]
pub enum BackpressureConfigError {
    /// The gate was cloned before the setter could install its value.
    #[error(
        "backpressure gate already cloned — `{setter}` must be called before the first Arc::clone"
    )]
    AlreadyShared {
        /// Name of the setter that failed, for diagnostics.
        setter: &'static str,
    },
}

/// Shared admission-control gate.
///
/// Tracks queued bytes with an [`AtomicUsize`] and coordinates the
/// accept-loop parking via [`Notify`]. Cheap to clone via `Arc`.
pub struct BackpressureGate {
    current_bytes: AtomicUsize,
    high_water: usize,
    low_water: usize,
    resume_dwell: Duration,
    /// `true` when the gate has crossed the high-water mark and is
    /// blocking new admissions. Cleared when the counter has stayed
    /// at/below `low_water` for at least `resume_dwell`.
    blocking: AtomicBool,
    /// Nanoseconds since `dwell_epoch` at which the counter most
    /// recently transitioned from above `low_water` to at/below
    /// `low_water` while `blocking` was true. Zero means "not currently
    /// in the cooldown window" (either `blocking` is false, or the
    /// counter is above `low_water`).
    below_low_since: AtomicU64,
    /// Reference instant for the `below_low_since` timestamps. Using an
    /// epoch-relative `u64` lets the whole state fit in atomics — no
    /// `Mutex<Option<Instant>>` on the hot path.
    dwell_epoch: Instant,
    notify: Notify,
    on_deferred: Option<OnDeferred>,
    on_bytes_changed: Option<OnBytesChanged>,
}

impl std::fmt::Debug for BackpressureGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackpressureGate")
            .field("current_bytes", &self.current())
            .field("high_water", &self.high_water)
            .field("low_water", &self.low_water)
            .field("resume_dwell", &self.resume_dwell)
            .field("blocking", &self.blocking.load(Ordering::Acquire))
            .finish()
    }
}

impl BackpressureGate {
    /// Create a new gate with the given high-water mark. The low-water
    /// mark defaults to 90% of the high-water value and the resume
    /// dwell defaults to [`DEFAULT_RESUME_DWELL`] (1 second).
    pub fn new(high_water: usize) -> Arc<Self> {
        let low_water = high_water.saturating_mul(9) / 10;
        Self::with_limits(high_water, low_water)
    }

    /// Create a new gate with explicit high-water and low-water marks.
    ///
    /// If `low_water >= high_water`, `low_water` is clamped to
    /// `high_water.saturating_sub(1)` to preserve the resume invariant.
    ///
    /// The resume dwell defaults to [`DEFAULT_RESUME_DWELL`]. Call
    /// [`BackpressureGate::with_resume_dwell`] to override (including
    /// setting it to `Duration::ZERO` for the pre-#878 "resume
    /// immediately on crossing low-water" behaviour).
    pub fn with_limits(high_water: usize, low_water: usize) -> Arc<Self> {
        let low_water = if low_water >= high_water {
            high_water.saturating_sub(1)
        } else {
            low_water
        };
        Arc::new(Self {
            current_bytes: AtomicUsize::new(0),
            high_water,
            low_water,
            resume_dwell: DEFAULT_RESUME_DWELL,
            blocking: AtomicBool::new(false),
            below_low_since: AtomicU64::new(0),
            dwell_epoch: Instant::now(),
            notify: Notify::new(),
            on_deferred: None,
            on_bytes_changed: None,
        })
    }

    /// Set the minimum time the counter must stay at/below the
    /// low-water mark before admission resumes after a block.
    ///
    /// `Duration::ZERO` disables dwell (pre-#878 behaviour — admission
    /// resumes the instant the counter crosses `low_water`). This is
    /// useful for tests and for deployments where load is known to be
    /// bursty-but-not-oscillatory. In production, keep the default
    /// [`DEFAULT_RESUME_DWELL`] unless you have evidence the dwell
    /// harms your workload.
    ///
    /// Must be called before the gate is cloned (same contract as
    /// [`BackpressureGate::set_on_deferred`] and
    /// [`BackpressureGate::set_on_bytes_changed`]).
    ///
    /// Returns [`BackpressureConfigError::AlreadyShared`] when the gate
    /// has already been cloned — the previous `debug_assert!` would
    /// silently no-op in release builds (F-51).
    pub fn with_resume_dwell(
        self: &mut Arc<Self>,
        dwell: Duration,
    ) -> Result<(), BackpressureConfigError> {
        match Arc::get_mut(self) {
            Some(this) => {
                this.resume_dwell = dwell;
                Ok(())
            }
            None => Err(BackpressureConfigError::AlreadyShared {
                setter: "with_resume_dwell",
            }),
        }
    }

    /// Register a callback invoked each time the accept loop is deferred
    /// because the gate is over the high-water mark.
    ///
    /// **Callback must be non-blocking** — see the docs on [`OnDeferred`].
    ///
    /// Returns [`BackpressureConfigError::AlreadyShared`] when the gate
    /// has already been cloned — previously this dropped the callback
    /// silently in release builds (F-51).
    pub fn set_on_deferred(
        self: &mut Arc<Self>,
        cb: OnDeferred,
    ) -> Result<(), BackpressureConfigError> {
        match Arc::get_mut(self) {
            Some(this) => {
                this.on_deferred = Some(cb);
                Ok(())
            }
            None => Err(BackpressureConfigError::AlreadyShared {
                setter: "set_on_deferred",
            }),
        }
    }

    /// Register a callback invoked on every byte-count change. Typically
    /// used to refresh a Prometheus gauge.
    ///
    /// **Callback must be non-blocking** — see the docs on [`OnBytesChanged`].
    ///
    /// Returns [`BackpressureConfigError::AlreadyShared`] when the gate
    /// has already been cloned — previously this dropped the callback
    /// silently in release builds (F-51).
    pub fn set_on_bytes_changed(
        self: &mut Arc<Self>,
        cb: OnBytesChanged,
    ) -> Result<(), BackpressureConfigError> {
        match Arc::get_mut(self) {
            Some(this) => {
                this.on_bytes_changed = Some(cb);
                Ok(())
            }
            None => Err(BackpressureConfigError::AlreadyShared {
                setter: "set_on_bytes_changed",
            }),
        }
    }

    /// High-water mark in bytes.
    pub fn high_water(&self) -> usize {
        self.high_water
    }

    /// Low-water mark in bytes.
    pub fn low_water(&self) -> usize {
        self.low_water
    }

    /// Minimum time the counter must stay at/below the low-water mark
    /// before admission resumes after a block.
    pub fn resume_dwell(&self) -> Duration {
        self.resume_dwell
    }

    /// Current tracked queued bytes.
    pub fn current(&self) -> usize {
        self.current_bytes.load(Ordering::Relaxed)
    }

    /// Returns `true` if the gate is currently admitting new connections
    /// (i.e. not parked over the high-water mark).
    pub fn is_admitting(&self) -> bool {
        !self.blocking.load(Ordering::Acquire)
    }

    /// Add `n` bytes to the counter. Trips the high-water mark if crossed.
    pub fn add(&self, n: usize) {
        let prev = self
            .current_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(n))
            })
            // Closure always returns Some, so fetch_update never fails.
            .unwrap_or_else(|prev| prev);
        let now = prev.saturating_add(n);
        if let Some(cb) = self.on_bytes_changed.as_ref() {
            cb(now);
        }
        if now >= self.high_water {
            // Crossing high-water resets any dwell-in-progress: we are
            // no longer in cooldown.
            self.below_low_since.store(0, Ordering::Release);
            self.blocking.store(true, Ordering::Release);
        } else if now > self.low_water {
            // Rose above low-water while blocking was set — cancel the
            // cooldown timer so the next drop below low starts a fresh
            // dwell window. Without this, oscillation between
            // `low_water + 1` and `low_water - 1` would count as
            // continuous "below low" time even though we are clearly
            // still bouncing on the boundary.
            self.below_low_since.store(0, Ordering::Release);
        }
    }

    /// Subtract `n` bytes from the counter. Wakes the accept loop if the
    /// counter has stayed at/below the low-water mark for at least
    /// `resume_dwell` since the most recent drop below low-water.
    pub fn sub(&self, n: usize) {
        let prev = self
            .current_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(n))
            })
            .unwrap_or_else(|prev| prev);
        let now = prev.saturating_sub(n);
        if let Some(cb) = self.on_bytes_changed.as_ref() {
            cb(now);
        }
        // Fast path: if we are not currently blocking, no dwell
        // bookkeeping is needed — there is nothing to resume from.
        if !self.blocking.load(Ordering::Acquire) {
            return;
        }
        if now <= self.low_water {
            // We are at/below low-water while blocking — start the
            // cooldown clock if this is the first sub to drop us there.
            // A failed CAS is fine: it means a prior sub already
            // recorded a timestamp we want to preserve.
            let tick = self.now_ticks_nonzero();
            let _ =
                self.below_low_since
                    .compare_exchange(0, tick, Ordering::AcqRel, Ordering::Relaxed);
            self.try_resume();
        }
    }

    /// Attempt to clear the `blocking` flag if (a) we are currently
    /// blocking, (b) the counter is still at/below `low_water`, and
    /// (c) the counter has been at/below `low_water` for at least
    /// `resume_dwell`. Called from both `sub` (covers the common case
    /// where a sub is what triggers the dwell expiry) and from
    /// `wait_for_capacity`'s polling branch (covers the case where no
    /// further sub arrives after the counter has settled, but the
    /// accept loop still needs to wake up).
    fn try_resume(&self) {
        if !self.blocking.load(Ordering::Acquire) {
            return;
        }
        // Recheck that we are still at/below low-water — a concurrent
        // add could have raised us back up after the sub's snapshot.
        if self.current() > self.low_water {
            return;
        }
        let since_tick = self.below_low_since.load(Ordering::Acquire);
        if since_tick == 0 {
            return;
        }
        if self.resume_dwell.is_zero() {
            // Pre-#878 behaviour: resume immediately on first qualifying
            // sub. Short-circuit the dwell check to save an Instant::now
            // call on every message release.
        } else {
            let now_tick = self.now_ticks_nonzero();
            let elapsed = now_tick.saturating_sub(since_tick);
            let dwell_nanos = self.resume_dwell.as_nanos().min(u64::MAX as u128) as u64;
            if elapsed < dwell_nanos {
                return;
            }
        }
        // Dwell satisfied (or disabled). Clear and wake any waiters.
        if self.blocking.swap(false, Ordering::AcqRel) {
            self.below_low_since.store(0, Ordering::Release);
            self.notify.notify_waiters();
        }
    }

    /// Current tick count (nanos since `dwell_epoch`), forced non-zero
    /// so `0` can remain a "no timestamp recorded" sentinel.
    fn now_ticks_nonzero(&self) -> u64 {
        let nanos = self.dwell_epoch.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        // Zero means "not in cooldown" — avoid that value in the
        // astronomically unlikely case the system clock fires on the
        // exact epoch instant.
        nanos.max(1)
    }

    /// Park the caller until the gate is below the low-water mark.
    ///
    /// Returns immediately when [`is_admitting`](Self::is_admitting) is
    /// `true`. Otherwise, awaits a wakeup from [`sub`](Self::sub) — or,
    /// when the dwell timer is in flight and no further `sub` arrives,
    /// polls periodically (every `DWELL_POLL_INTERVAL`) so dwell expiry
    /// cannot stall indefinitely.
    ///
    /// When called from a TLS accept loop, stalling here does not
    /// immediately drop incoming TCP connections: the kernel SYN backlog
    /// (controlled by `somaxconn` / the listener backlog) absorbs new
    /// connection attempts while the loop is parked, and they are drained
    /// once admission resumes.
    pub async fn wait_for_capacity(&self) {
        // Fast path: gate is currently admitting.
        if !self.blocking.load(Ordering::Acquire) {
            return;
        }
        if let Some(cb) = self.on_deferred.as_ref() {
            cb();
        }
        loop {
            // Register for wakeup *before* re-checking the flag so we do
            // not miss a notify between the load and the await.
            let waiter = self.notify.notified();
            if !self.blocking.load(Ordering::Acquire) {
                return;
            }
            // Poll for dwell expiry on our own schedule: if no further
            // `sub` arrives after the counter has settled below
            // `low_water`, nobody else will call `try_resume` and the
            // waiter would otherwise sleep forever. Skip the timer when
            // dwell is disabled — the only wakeup path is then `sub`.
            if self.resume_dwell.is_zero() {
                waiter.await;
            } else {
                tokio::select! {
                    _ = waiter => {}
                    _ = tokio::time::sleep(DWELL_POLL_INTERVAL) => {
                        self.try_resume();
                    }
                }
            }
            if !self.blocking.load(Ordering::Acquire) {
                return;
            }
        }
    }

    /// Acquire a permit sized for `n` bytes. The permit releases the
    /// reservation when dropped, making byte accounting panic-safe.
    pub fn acquire(self: &Arc<Self>, n: usize) -> BackpressurePermit {
        self.add(n);
        BackpressurePermit {
            gate: Arc::clone(self),
            bytes: n,
        }
    }
}

/// RAII guard that subtracts its byte reservation from the gate on drop.
#[must_use = "dropping the permit immediately releases the reservation"]
pub struct BackpressurePermit {
    gate: Arc<BackpressureGate>,
    bytes: usize,
}

impl BackpressurePermit {
    /// Number of bytes reserved by this permit.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl std::fmt::Debug for BackpressurePermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackpressurePermit")
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Drop for BackpressurePermit {
    fn drop(&mut self) {
        self.gate.sub(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::time::Duration;

    use super::*;

    /// Build a gate with zero resume dwell so tests written against the
    /// pre-#878 immediate-resume semantics keep passing without having
    /// to sleep for a second. New tests that exercise the dwell behaviour
    /// use the default constructor or a short explicit dwell.
    fn zero_dwell_gate(high_water: usize) -> Arc<BackpressureGate> {
        let mut gate = BackpressureGate::new(high_water);
        BackpressureGate::with_resume_dwell(&mut gate, Duration::ZERO).unwrap();
        gate
    }

    fn zero_dwell_with_limits(high_water: usize, low_water: usize) -> Arc<BackpressureGate> {
        let mut gate = BackpressureGate::with_limits(high_water, low_water);
        BackpressureGate::with_resume_dwell(&mut gate, Duration::ZERO).unwrap();
        gate
    }

    #[test]
    fn admits_below_high_water() {
        let gate = zero_dwell_gate(1_000);
        assert!(gate.is_admitting());
        gate.add(100);
        assert_eq!(gate.current(), 100);
        assert!(gate.is_admitting());
    }

    #[test]
    fn blocks_at_high_water() {
        let gate = zero_dwell_gate(1_000);
        gate.add(1_000);
        assert!(!gate.is_admitting());
    }

    #[test]
    fn resumes_after_low_water() {
        // high=1000, low=900
        let gate = zero_dwell_gate(1_000);
        gate.add(1_000);
        assert!(!gate.is_admitting());
        // Drop to 950, still above low-water
        gate.sub(50);
        assert!(!gate.is_admitting());
        // Drop to 899 (<= low_water 900)
        gate.sub(51);
        assert!(gate.is_admitting());
    }

    #[test]
    fn permit_raii_releases() {
        let gate = zero_dwell_gate(1_000);
        {
            let _p = gate.acquire(400);
            assert_eq!(gate.current(), 400);
        }
        assert_eq!(gate.current(), 0);
    }

    #[tokio::test]
    async fn wait_for_capacity_blocks_then_wakes() {
        let gate = zero_dwell_with_limits(100, 50);
        gate.add(100);
        assert!(!gate.is_admitting());

        let gate2 = Arc::clone(&gate);
        let waiter = tokio::spawn(async move {
            gate2.wait_for_capacity().await;
        });

        // Still blocked; sleep briefly and confirm waiter hasn't finished.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());

        // Cross below low-water
        gate.sub(60);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should wake")
            .expect("join");
        assert!(gate.is_admitting());
    }

    #[tokio::test]
    async fn wait_for_capacity_returns_immediately_when_admitting() {
        let gate = zero_dwell_gate(1_000);
        // Should not deadlock.
        tokio::time::timeout(Duration::from_millis(100), gate.wait_for_capacity())
            .await
            .expect("should return immediately");
    }

    #[test]
    fn shared_permit_releases_only_on_last_clone_drop() {
        use std::sync::Arc;
        use std::time::SystemTime;

        use bytes::Bytes;
        use rustgate_core::identity::Identity;
        use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

        use crate::router::RoutedMessage;

        let gate = zero_dwell_gate(10_000);
        let permit = Arc::new(gate.acquire(1024));
        assert_eq!(gate.current(), 1024);

        let sender = Identity::plaintext("sender".to_string(), Default::default()).unwrap();
        let msg = Arc::new(RoutableMessage {
            source: sender.clone(),
            destination: Destination::Broadcast,
            payload: Bytes::from(vec![0u8; 1024]),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "test".to_string(),
                message_type: MessageType::Chat,
                ttl: None,
            },
        });

        // Build several recipient envelopes from the same shared permit —
        // modeling `Router::route` fan-out into per-session mpsc channels.
        let env = RoutedMessage::with_permit(Arc::clone(&msg), Arc::clone(&permit));
        let copies = [env.clone(), env.clone(), env.clone()];

        // Drop the "route()-local" Arc<Permit> handle: the per-recipient
        // envelopes still hold it, so the counter must stay pegged.
        drop(permit);
        assert_eq!(
            gate.current(),
            1024,
            "permit must stay alive while any envelope clone holds it"
        );

        // Drop envelopes one by one; only the last drop releases.
        let mut iter = copies.into_iter();
        drop(iter.next());
        assert_eq!(gate.current(), 1024);
        drop(iter.next());
        assert_eq!(gate.current(), 1024);
        drop(iter.next());
        assert_eq!(gate.current(), 1024);
        drop(env);
        assert_eq!(
            gate.current(),
            0,
            "final envelope drop must release the permit"
        );
    }

    #[test]
    fn add_saturates_instead_of_wrapping() {
        let gate = zero_dwell_gate(usize::MAX);
        gate.add(usize::MAX);
        gate.add(1);
        assert_eq!(gate.current(), usize::MAX, "add must saturate, not wrap");
    }

    #[test]
    fn sub_saturates_instead_of_wrapping() {
        let gate = zero_dwell_gate(1_000);
        gate.add(10);
        gate.sub(20);
        assert_eq!(
            gate.current(),
            0,
            "sub must saturate to zero, not underflow"
        );
    }

    #[test]
    fn low_water_clamped_if_ge_high() {
        let gate = BackpressureGate::with_limits(100, 200);
        assert_eq!(gate.low_water(), 99);
    }

    #[test]
    fn deferred_callback_invoked_when_blocked() {
        use std::sync::atomic::AtomicUsize;
        let counter = Arc::new(AtomicUsize::new(0));
        let mut gate = zero_dwell_gate(100);
        let c = Arc::clone(&counter);
        BackpressureGate::set_on_deferred(
            &mut gate,
            Arc::new(move || {
                let _ = c.fetch_add(1, Ordering::Relaxed);
            }),
        )
        .unwrap();
        gate.add(100);
        // Poll wait_for_capacity once; it should trip the callback then
        // park, so we race it with a short timeout.
        let gate2 = Arc::clone(&gate);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("rt");
        rt.block_on(async move {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                gate2.wait_for_capacity(),
            )
            .await;
        });
        assert!(counter.load(Ordering::Relaxed) >= 1);
    }

    // ── #878 regression tests (oscillation fix) ─────────────────────

    #[test]
    fn default_resume_dwell_is_one_second() {
        // The oscillation fix only matters if the default is non-zero.
        // Pin DEFAULT_RESUME_DWELL so a change to zero is a reviewable
        // diff rather than a silent revert.
        let gate = BackpressureGate::new(1_000);
        assert_eq!(gate.resume_dwell(), DEFAULT_RESUME_DWELL);
        assert_eq!(gate.resume_dwell(), Duration::from_secs(1));
    }

    #[test]
    fn zero_dwell_preserves_immediate_resume_behaviour() {
        // Explicit opt-out matches pre-#878 semantics byte-for-byte.
        let gate = zero_dwell_gate(1_000);
        assert_eq!(gate.resume_dwell(), Duration::ZERO);
        gate.add(1_000);
        assert!(!gate.is_admitting());
        gate.sub(200); // 800 <= 900
        assert!(gate.is_admitting(), "zero dwell must resume immediately");
    }

    #[tokio::test(start_paused = true)]
    async fn default_dwell_keeps_gate_blocked_until_timer_expires() {
        // The core #878 assertion: dropping below low-water is not
        // enough on its own. The gate must stay blocked until the
        // counter has been below low for at least `resume_dwell`.
        let gate = BackpressureGate::with_limits(1_000, 900);
        assert_eq!(gate.resume_dwell(), DEFAULT_RESUME_DWELL);
        gate.add(1_000);
        assert!(!gate.is_admitting(), "should block at high-water");

        // Drop below low-water. With zero dwell this would resume
        // immediately; with dwell it must stay blocked.
        gate.sub(200); // 800 <= 900
        assert!(
            !gate.is_admitting(),
            "must stay blocked during dwell window",
        );

        // Advance less than the dwell — still blocked.
        tokio::time::advance(Duration::from_millis(500)).await;
        // try_resume runs only on sub() or wait_for_capacity(); fire a
        // zero-byte sub to cover the first path deterministically.
        gate.sub(0);
        assert!(
            !gate.is_admitting(),
            "must stay blocked at 500ms into 1s dwell",
        );

        // Advance past the dwell — now a sub should release.
        tokio::time::advance(Duration::from_millis(600)).await;
        gate.sub(0);
        assert!(
            gate.is_admitting(),
            "must resume once dwell elapses and counter stays below low",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn oscillation_cancels_dwell_and_stays_blocked() {
        // Precise regression guard against #878: load oscillates between
        // `low_water + small` and `low_water - small` within the dwell
        // window. Without the fix, the sub that crosses below low
        // immediately resumes admission — even though load is plainly
        // still hovering at the boundary. With the fix, each bounce
        // above low cancels the in-flight cooldown, so the gate stays
        // blocked.
        let gate = BackpressureGate::with_limits(1_000, 900);
        gate.add(1_000);
        assert!(!gate.is_admitting());

        for cycle in 0..5 {
            // Drop to 880 (below low-water by 20).
            gate.sub(120);
            tokio::time::advance(Duration::from_millis(200)).await;
            // Rise back to 920 (above low-water by 20).
            gate.add(40);
            tokio::time::advance(Duration::from_millis(200)).await;
            assert!(
                !gate.is_admitting(),
                "cycle {cycle}: oscillating load must not resume admission",
            );
            // Net zero at end of cycle (880 - 40 = 840 remains; let's
            // keep going without net accumulation across cycles).
            gate.add(80); // back to 1000
        }

        // Now actually commit to staying below — release enough to
        // settle below low-water with no oscillation, wait the full
        // dwell, and confirm resume.
        gate.sub(200); // 1000 -> 800 (below low)
        tokio::time::advance(Duration::from_millis(1_100)).await;
        gate.sub(0);
        assert!(
            gate.is_admitting(),
            "steady sub-low-water for full dwell must eventually resume",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_capacity_polls_for_dwell_expiry_without_further_subs() {
        // If no further `sub` arrives after the counter settles below
        // low-water, `wait_for_capacity` must still wake up once the
        // dwell expires. Previously this depended on an external
        // wakeup; the DWELL_POLL_INTERVAL branch now handles it.
        let mut gate = BackpressureGate::with_limits(1_000, 900);
        BackpressureGate::with_resume_dwell(&mut gate, Duration::from_millis(300)).unwrap();
        gate.add(1_000);
        gate.sub(200); // 800 <= 900
        assert!(!gate.is_admitting());

        let gate2 = Arc::clone(&gate);
        let waiter = tokio::spawn(async move {
            gate2.wait_for_capacity().await;
        });

        // No further `sub` will fire — the only wakeup path is the
        // internal DWELL_POLL_INTERVAL branch re-running try_resume.
        tokio::time::advance(Duration::from_millis(500)).await;
        // Yield so the waiter can observe the dwell expiry.
        tokio::task::yield_now().await;
        let join_result = tokio::time::timeout(Duration::from_secs(1), waiter).await;
        assert!(
            join_result.is_ok(),
            "wait_for_capacity must wake on internal dwell poll without external sub",
        );
        assert!(gate.is_admitting());
    }

    #[tokio::test(start_paused = true)]
    async fn add_above_high_water_resets_in_flight_dwell() {
        // If the counter rises all the way back above high-water while
        // in cooldown, the dwell must be reset — a subsequent drop
        // below low must start a fresh window, not reuse the old one.
        let gate = BackpressureGate::with_limits(1_000, 900);
        gate.add(1_000);
        gate.sub(200); // 800, start dwell
        tokio::time::advance(Duration::from_millis(800)).await;
        // Re-cross high-water before dwell expires.
        gate.add(200); // 1_000, blocking re-asserted, dwell reset
        assert!(!gate.is_admitting());

        // Drop back below low immediately — the earlier 800ms of dwell
        // must NOT count. Advance only 500ms and confirm still blocked.
        gate.sub(200); // 800 again
        tokio::time::advance(Duration::from_millis(500)).await;
        gate.sub(0);
        assert!(
            !gate.is_admitting(),
            "dwell must have been reset by the crossing back above high-water",
        );

        // Wait the rest of the dwell and confirm resume.
        tokio::time::advance(Duration::from_millis(600)).await;
        gate.sub(0);
        assert!(gate.is_admitting());
    }

    #[test]
    fn with_resume_dwell_updates_field() {
        let mut gate = BackpressureGate::new(1_000);
        BackpressureGate::with_resume_dwell(&mut gate, Duration::from_millis(250)).unwrap();
        assert_eq!(gate.resume_dwell(), Duration::from_millis(250));
    }

    #[test]
    fn setters_return_err_after_clone() {
        // F-51: previously these setters silently no-op'd after the gate
        // was shared. They must now surface the misordering so callers
        // can fail startup instead of drifting without instrumentation.
        let mut gate = BackpressureGate::new(1_000);
        let _held = Arc::clone(&gate);

        let dwell_err = BackpressureGate::with_resume_dwell(&mut gate, Duration::from_millis(250))
            .expect_err("with_resume_dwell must fail after clone");
        match dwell_err {
            BackpressureConfigError::AlreadyShared { setter } => {
                assert_eq!(setter, "with_resume_dwell");
            }
        }

        let deferred_err = BackpressureGate::set_on_deferred(&mut gate, Arc::new(|| {}))
            .expect_err("set_on_deferred must fail after clone");
        match deferred_err {
            BackpressureConfigError::AlreadyShared { setter } => {
                assert_eq!(setter, "set_on_deferred");
            }
        }

        let bytes_err = BackpressureGate::set_on_bytes_changed(&mut gate, Arc::new(|_| {}))
            .expect_err("set_on_bytes_changed must fail after clone");
        match bytes_err {
            BackpressureConfigError::AlreadyShared { setter } => {
                assert_eq!(setter, "set_on_bytes_changed");
            }
        }
    }

    #[test]
    fn setters_succeed_before_clone() {
        let mut gate = BackpressureGate::new(1_000);
        BackpressureGate::with_resume_dwell(&mut gate, Duration::from_millis(250)).unwrap();
        BackpressureGate::set_on_deferred(&mut gate, Arc::new(|| {})).unwrap();
        BackpressureGate::set_on_bytes_changed(&mut gate, Arc::new(|_| {})).unwrap();
        assert_eq!(gate.resume_dwell(), Duration::from_millis(250));
    }

    #[test]
    fn config_error_display_names_setter() {
        let err = BackpressureConfigError::AlreadyShared {
            setter: "set_on_deferred",
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("set_on_deferred"),
            "Display must surface setter name: {rendered}",
        );
        assert!(
            rendered.contains("already cloned"),
            "Display must explain the cause: {rendered}",
        );
    }

    #[test]
    fn debug_format_includes_resume_dwell() {
        // Operators grep production logs for the gate's debug repr when
        // diagnosing admission behaviour. Pin the new field's presence
        // so a future hand-rolled Debug impl cannot silently drop it.
        let gate = BackpressureGate::new(1_000);
        let rendered = format!("{gate:?}");
        assert!(
            rendered.contains("resume_dwell"),
            "Debug output {rendered} missing resume_dwell field",
        );
    }
}
