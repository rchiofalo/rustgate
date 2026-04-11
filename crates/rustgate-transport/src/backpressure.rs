//! Global admission control / backpressure gate.
//!
//! Tracks the total number of in-flight "queued" bytes across all sessions
//! and the router's pending route work. When the counter crosses the
//! high-water mark, the accept loop is parked (via [`BackpressureGate::wait_for_capacity`])
//! until the counter drops back below the low-water mark. This prevents a
//! flood of slow readers from exhausting memory.
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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::sync::Notify;

/// Default high-water mark: 512 MiB of queued/in-flight bytes.
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 512 * 1024 * 1024;

/// Callback invoked whenever the accept loop is deferred due to
/// backpressure. Used to increment metrics counters without a hard
/// dependency on the `metrics` feature from this crate.
pub type OnDeferred = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked whenever the current queued-bytes counter changes.
/// Used to refresh a gauge.
pub type OnBytesChanged = Arc<dyn Fn(usize) + Send + Sync>;

/// Shared admission-control gate.
///
/// Tracks queued bytes with an [`AtomicUsize`] and coordinates the
/// accept-loop parking via [`Notify`]. Cheap to clone via `Arc`.
pub struct BackpressureGate {
    current_bytes: AtomicUsize,
    high_water: usize,
    low_water: usize,
    /// `true` when the gate has crossed the high-water mark and is
    /// blocking new admissions. Cleared when the counter returns below
    /// the low-water mark.
    blocking: AtomicBool,
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
            .field("blocking", &self.blocking.load(Ordering::Acquire))
            .finish()
    }
}

impl BackpressureGate {
    /// Create a new gate with the given high-water mark. The low-water
    /// mark defaults to 90% of the high-water value.
    pub fn new(high_water: usize) -> Arc<Self> {
        let low_water = high_water.saturating_mul(9) / 10;
        Self::with_limits(high_water, low_water)
    }

    /// Create a new gate with explicit high-water and low-water marks.
    ///
    /// If `low_water >= high_water`, `low_water` is clamped to
    /// `high_water.saturating_sub(1)` to preserve the resume invariant.
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
            blocking: AtomicBool::new(false),
            notify: Notify::new(),
            on_deferred: None,
            on_bytes_changed: None,
        })
    }

    /// Register a callback invoked each time the accept loop is deferred
    /// because the gate is over the high-water mark.
    pub fn set_on_deferred(self: &mut Arc<Self>, cb: OnDeferred) {
        debug_assert!(
            Arc::get_mut(self).is_some(),
            "set_on_deferred must be called before the gate is cloned"
        );
        if let Some(this) = Arc::get_mut(self) {
            this.on_deferred = Some(cb);
        }
    }

    /// Register a callback invoked on every byte-count change. Typically
    /// used to refresh a Prometheus gauge.
    pub fn set_on_bytes_changed(self: &mut Arc<Self>, cb: OnBytesChanged) {
        debug_assert!(
            Arc::get_mut(self).is_some(),
            "set_on_bytes_changed must be called before the gate is cloned"
        );
        if let Some(this) = Arc::get_mut(self) {
            this.on_bytes_changed = Some(cb);
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
            self.blocking.store(true, Ordering::Release);
        }
    }

    /// Subtract `n` bytes from the counter. Wakes the accept loop if the
    /// counter dropped below the low-water mark.
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
        if now <= self.low_water && self.blocking.swap(false, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    /// Park the caller until the gate is below the low-water mark.
    ///
    /// Returns immediately when [`is_admitting`](Self::is_admitting) is
    /// `true`. Otherwise, awaits a wakeup from [`sub`](Self::sub).
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
            waiter.await;
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

    #[test]
    fn admits_below_high_water() {
        let gate = BackpressureGate::new(1_000);
        assert!(gate.is_admitting());
        gate.add(100);
        assert_eq!(gate.current(), 100);
        assert!(gate.is_admitting());
    }

    #[test]
    fn blocks_at_high_water() {
        let gate = BackpressureGate::new(1_000);
        gate.add(1_000);
        assert!(!gate.is_admitting());
    }

    #[test]
    fn resumes_after_low_water() {
        // high=1000, low=900
        let gate = BackpressureGate::new(1_000);
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
        let gate = BackpressureGate::new(1_000);
        {
            let _p = gate.acquire(400);
            assert_eq!(gate.current(), 400);
        }
        assert_eq!(gate.current(), 0);
    }

    #[tokio::test]
    async fn wait_for_capacity_blocks_then_wakes() {
        let gate = BackpressureGate::with_limits(100, 50);
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
        let gate = BackpressureGate::new(1_000);
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

        let gate = BackpressureGate::new(10_000);
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
        let gate = BackpressureGate::new(usize::MAX);
        gate.add(usize::MAX);
        gate.add(1);
        assert_eq!(gate.current(), usize::MAX, "add must saturate, not wrap");
    }

    #[test]
    fn sub_saturates_instead_of_wrapping() {
        let gate = BackpressureGate::new(1_000);
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
        let mut gate = BackpressureGate::new(100);
        let c = Arc::clone(&counter);
        gate.set_on_deferred(Arc::new(move || {
            let _ = c.fetch_add(1, Ordering::Relaxed);
        }));
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
}
