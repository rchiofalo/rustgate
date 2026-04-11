//! Federation peer handle with circuit breaker and connection state.
//!
//! Each configured federation peer gets a [`PeerHandle`] that tracks its
//! connection state, circuit breaker health, and message counters. The
//! circuit breaker pattern ([`CircuitState`]) prevents wasting resources
//! on peers that are consistently failing — after a configurable number
//! of consecutive failures the circuit "opens" and messages are skipped
//! until a recovery timeout elapses.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use rustgate_core::PeerId;

use crate::config::PeerConfig;

/// Circuit breaker state for a federation peer.
///
/// Tracks whether a peer is healthy enough to receive messages:
/// - `Closed` — healthy, messages flow normally.
/// - `Open` — tripped after consecutive failures, messages are skipped.
/// - `HalfOpen` — recovery probe: one message is allowed through to test the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

impl TryFrom<u8> for CircuitState {
    type Error = u8;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(CircuitState::Closed),
            1 => Ok(CircuitState::Open),
            2 => Ok(CircuitState::HalfOpen),
            _ => Err(v),
        }
    }
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::Open => write!(f, "open"),
            CircuitState::HalfOpen => write!(f, "half_open"),
        }
    }
}

impl serde::Serialize for CircuitState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Connection state for a federation peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Reconnecting = 3,
}

impl TryFrom<u8> for PeerState {
    type Error = u8;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(PeerState::Disconnected),
            1 => Ok(PeerState::Connecting),
            2 => Ok(PeerState::Connected),
            3 => Ok(PeerState::Reconnecting),
            _ => Err(v),
        }
    }
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerState::Disconnected => write!(f, "disconnected"),
            PeerState::Connecting => write!(f, "connecting"),
            PeerState::Connected => write!(f, "connected"),
            PeerState::Reconnecting => write!(f, "reconnecting"),
        }
    }
}

/// Mutable peer timestamps and error state, protected by a single lock.
///
/// Consolidating these fields avoids acquiring four separate mutexes
/// when building a status snapshot or updating related state.
#[derive(Debug, Default)]
struct PeerTimestamps {
    /// Timestamp of the last received heartbeat.
    last_heartbeat: Option<Instant>,
    /// Last error message, if any.
    last_error: Option<String>,
    /// Timestamp when the current connection was established.
    connected_at: Option<Instant>,
    /// When the circuit last tripped open.
    circuit_opened_at: Option<Instant>,
}

/// Tracks the runtime state of a federation peer connection.
///
/// Thread-safe — all fields use atomic types or a consolidated mutex.
#[derive(Debug)]
pub struct PeerHandle {
    /// Peer identifier.
    pub id: PeerId,
    /// Static configuration.
    pub config: PeerConfig,
    /// Current connection state (atomic for lock-free reads).
    state: AtomicU8,
    /// Consolidated mutable timestamps and error state.
    timestamps: Mutex<PeerTimestamps>,
    /// Total messages sent to this peer.
    pub messages_sent: AtomicU64,
    /// Total messages received from this peer.
    pub messages_recv: AtomicU64,
    /// Number of reconnection attempts since last successful connection.
    reconnect_count: AtomicU64,
    // ── Circuit breaker ──────────────────────────────────────────────
    /// Current circuit breaker state.
    circuit: AtomicU8,
    /// Consecutive send failures (resets on success).
    consecutive_failures: AtomicU32,
    /// Number of consecutive failures before the circuit opens.
    failure_threshold: u32,
    /// Seconds to wait before transitioning Open → HalfOpen.
    recovery_timeout_secs: u64,
    /// Lifetime count of circuit-breaker trips (for observability).
    circuit_trips: AtomicU64,
    /// Bytes currently sitting in this peer's outbound queue (for lag metrics).
    queue_bytes: AtomicU64,
    /// FIFO of (enqueue time, byte size) pairs for in-flight messages — head
    /// is the oldest message still queued. Used to compute "oldest message age"
    /// without scanning the actual mpsc channel.
    queue_ages: Mutex<VecDeque<(SystemTime, usize)>>,
    /// EWMA round-trip latency to this peer in nanoseconds (from heartbeats).
    /// Zero means no RTT samples have been recorded yet.
    latency_nanos: AtomicU64,
}

impl PeerHandle {
    /// Default failure threshold when not specified.
    const DEFAULT_FAILURE_THRESHOLD: u32 = 5;
    /// Default recovery timeout (seconds) when not specified.
    const DEFAULT_RECOVERY_TIMEOUT_SECS: u64 = 60;

    /// Create a new peer handle from configuration.
    pub fn new(config: PeerConfig) -> Self {
        let id = config.id.clone();
        Self {
            id,
            config,
            state: AtomicU8::new(PeerState::Disconnected as u8),
            timestamps: Mutex::new(PeerTimestamps::default()),
            messages_sent: AtomicU64::new(0),
            messages_recv: AtomicU64::new(0),
            reconnect_count: AtomicU64::new(0),
            circuit: AtomicU8::new(CircuitState::Closed as u8),
            consecutive_failures: AtomicU32::new(0),
            failure_threshold: Self::DEFAULT_FAILURE_THRESHOLD,
            recovery_timeout_secs: Self::DEFAULT_RECOVERY_TIMEOUT_SECS,
            circuit_trips: AtomicU64::new(0),
            queue_bytes: AtomicU64::new(0),
            queue_ages: Mutex::new(VecDeque::new()),
            latency_nanos: AtomicU64::new(0),
        }
    }

    /// Record that `bytes` worth of payload has been enqueued for delivery
    /// to this peer. Updates the per-peer queue-bytes counter and tracks
    /// the message's enqueue time so the oldest-message age can be reported.
    pub fn record_enqueue(&self, bytes: usize) {
        let _ = self.queue_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        if let Ok(mut guard) = self.queue_ages.lock() {
            guard.push_back((SystemTime::now(), bytes));
        }
    }

    /// Record that a previously enqueued message has been delivered or
    /// dropped. Decrements the queue-bytes counter and pops the oldest
    /// pending entry so the next call reports the new head's age.
    pub fn record_dequeue(&self) {
        let popped_bytes = match self.queue_ages.lock() {
            Ok(mut guard) => guard.pop_front().map(|(_, b)| b),
            Err(_) => None,
        };
        if let Some(bytes) = popped_bytes {
            let _ = self.queue_bytes.fetch_sub(bytes as u64, Ordering::Relaxed);
        }
    }

    /// Reset the queue accounting to empty. Used when a send loop terminates
    /// permanently (e.g. shutdown, max reconnects exhausted) and any messages
    /// still buffered in the outbound channel will be dropped without delivery.
    /// Without this, the per-peer queue-bytes gauge would leak counter weight
    /// for the lifetime of the process.
    pub fn reset_queue(&self) {
        self.queue_bytes.store(0, Ordering::Relaxed);
        if let Ok(mut guard) = self.queue_ages.lock() {
            guard.clear();
        }
    }

    /// Current queued bytes for this peer.
    pub fn queue_bytes(&self) -> u64 {
        self.queue_bytes.load(Ordering::Relaxed)
    }

    /// Age (in seconds) of the oldest queued message for this peer, or
    /// `None` if the queue is empty.
    pub fn oldest_queued_age_secs(&self) -> Option<f64> {
        let ts = self.queue_ages.lock().ok()?.front().map(|(t, _)| *t)?;
        ts.elapsed().ok().map(|d| d.as_secs_f64())
    }

    /// Record an observed round-trip time and update the EWMA.
    ///
    /// Uses integer EWMA with alpha=0.3: `new = (3 * sample + 7 * old) / 10`.
    /// The first sample initializes the estimate directly (no smoothing).
    pub fn record_rtt(&self, rtt_nanos: u64) {
        let old = self.latency_nanos.load(Ordering::Relaxed);
        let new = if old == 0 {
            rtt_nanos
        } else {
            (3 * rtt_nanos + 7 * old) / 10
        };
        self.latency_nanos.store(new, Ordering::Relaxed);
    }

    /// Returns the current EWMA latency in nanoseconds, or 0 if no samples.
    pub fn latency_nanos(&self) -> u64 {
        self.latency_nanos.load(Ordering::Relaxed)
    }

    /// Create a new peer handle with explicit circuit breaker parameters.
    pub fn with_circuit_breaker(
        config: PeerConfig,
        failure_threshold: u32,
        recovery_timeout_secs: u64,
    ) -> Self {
        let mut handle = Self::new(config);
        handle.failure_threshold = failure_threshold;
        handle.recovery_timeout_secs = recovery_timeout_secs;
        handle
    }

    /// Get the current connection state.
    pub fn state(&self) -> PeerState {
        PeerState::try_from(self.state.load(Ordering::Relaxed)).unwrap_or(PeerState::Disconnected)
    }

    /// Set the connection state.
    pub fn set_state(&self, state: PeerState) {
        self.state.store(state as u8, Ordering::Relaxed);
    }

    /// Check if the peer is currently connected.
    pub fn is_connected(&self) -> bool {
        self.state() == PeerState::Connected
    }

    /// Record a received heartbeat at the current instant.
    pub fn record_heartbeat(&self) {
        if let Ok(mut guard) = self.timestamps.lock() {
            guard.last_heartbeat = Some(Instant::now());
        }
    }

    /// Get the elapsed time since the last heartbeat.
    ///
    /// Returns `None` if no heartbeat has been received.
    pub fn since_last_heartbeat(&self) -> Option<std::time::Duration> {
        self.timestamps
            .lock()
            .ok()
            .and_then(|guard| guard.last_heartbeat.map(|ts| ts.elapsed()))
    }

    /// Record a successful connection.
    pub fn mark_connected(&self) {
        self.set_state(PeerState::Connected);
        if let Ok(mut guard) = self.timestamps.lock() {
            let now = Instant::now();
            guard.connected_at = Some(now);
            guard.last_heartbeat = Some(now);
        }
        self.reconnect_count.store(0, Ordering::Relaxed);
    }

    /// Record a disconnection.
    pub fn mark_disconnected(&self) {
        self.set_state(PeerState::Disconnected);
        if let Ok(mut guard) = self.timestamps.lock() {
            guard.connected_at = None;
        }
    }

    /// Record an error.
    pub fn set_error(&self, err: &str) {
        if let Ok(mut guard) = self.timestamps.lock() {
            guard.last_error = Some(err.to_string());
        }
    }

    /// Get the last error message.
    pub fn last_error(&self) -> Option<String> {
        self.timestamps
            .lock()
            .ok()
            .and_then(|guard| guard.last_error.clone())
    }

    /// Get the duration this peer has been connected.
    pub fn connected_duration(&self) -> Option<std::time::Duration> {
        self.timestamps
            .lock()
            .ok()
            .and_then(|guard| guard.connected_at.map(|ts| ts.elapsed()))
    }

    /// Increment and return the reconnection attempt counter.
    pub fn increment_reconnect_count(&self) -> u64 {
        self.reconnect_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Get the current reconnection attempt count.
    pub fn reconnect_count(&self) -> u64 {
        self.reconnect_count.load(Ordering::Relaxed)
    }

    /// Increment the sent message counter.
    pub fn record_sent(&self) {
        let _ = self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the received message counter.
    pub fn record_recv(&self) {
        let _ = self.messages_recv.fetch_add(1, Ordering::Relaxed);
    }

    // ── Circuit breaker ──────────────────────────────────────────────

    /// Get the current circuit breaker state, applying time-based transitions.
    ///
    /// If the circuit is `Open` and the recovery timeout has elapsed, it
    /// automatically transitions to `HalfOpen` to allow a probe message.
    pub fn circuit_state(&self) -> CircuitState {
        let state = CircuitState::try_from(self.circuit.load(Ordering::Acquire))
            .unwrap_or(CircuitState::Closed);
        if state == CircuitState::Open
            && let Ok(guard) = self.timestamps.lock()
            && let Some(opened_at) = guard.circuit_opened_at
            && opened_at.elapsed().as_secs() >= self.recovery_timeout_secs
        {
            self.circuit
                .store(CircuitState::HalfOpen as u8, Ordering::Release);
            return CircuitState::HalfOpen;
        }
        state
    }

    /// Check if the peer is available for sending (connected and circuit not open).
    pub fn is_available(&self) -> bool {
        self.is_connected() && self.circuit_state() != CircuitState::Open
    }

    /// Record a successful send, resetting the circuit breaker.
    ///
    /// If the circuit was `HalfOpen`, it transitions back to `Closed`.
    /// Returns `true` if the circuit was recovered from `HalfOpen`.
    pub fn record_success(&self) -> bool {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let prev = CircuitState::try_from(self.circuit.load(Ordering::Acquire))
            .unwrap_or(CircuitState::Closed);
        if prev == CircuitState::HalfOpen {
            self.circuit
                .store(CircuitState::Closed as u8, Ordering::Release);
            if let Ok(mut guard) = self.timestamps.lock() {
                guard.circuit_opened_at = None;
            }
            return true;
        }
        false
    }

    /// Record a send failure, potentially tripping the circuit breaker.
    ///
    /// Returns `true` if this failure caused the circuit to open.
    pub fn record_failure(&self) -> bool {
        let prev_state = CircuitState::try_from(self.circuit.load(Ordering::Acquire))
            .unwrap_or(CircuitState::Closed);

        // HalfOpen probe failed — immediately reopen
        if prev_state == CircuitState::HalfOpen {
            self.circuit
                .store(CircuitState::Open as u8, Ordering::Release);
            if let Ok(mut guard) = self.timestamps.lock() {
                guard.circuit_opened_at = Some(Instant::now());
            }
            let _ = self.circuit_trips.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.failure_threshold && prev_state == CircuitState::Closed {
            self.circuit
                .store(CircuitState::Open as u8, Ordering::Release);
            if let Ok(mut guard) = self.timestamps.lock() {
                guard.circuit_opened_at = Some(Instant::now());
            }
            let _ = self.circuit_trips.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Get the total number of times the circuit breaker has tripped.
    pub fn circuit_trip_count(&self) -> u64 {
        self.circuit_trips.load(Ordering::Relaxed)
    }

    /// Get a snapshot of this peer's status for reporting.
    pub fn status(&self) -> PeerStatus {
        PeerStatus {
            id: self.id.clone(),
            address: self.config.address.clone(),
            state: self.state(),
            groups: self.config.groups.clone(),
            inbound_groups: self.config.inbound_groups.clone(),
            outbound_groups: self.config.outbound_groups.clone(),
            enabled: self.config.enabled,
            is_outbound: self.config.is_outbound,
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_recv: self.messages_recv.load(Ordering::Relaxed),
            last_error: self.last_error(),
            connected_duration_secs: self.connected_duration().map(|d| d.as_secs()),
            reconnect_count: self.reconnect_count(),
            circuit_state: self.circuit_state(),
            circuit_trips: self.circuit_trip_count(),
        }
    }
}

/// Compare two peers for routing preference ordering.
///
/// Returns `Ordering` suitable for `sort_by`: same-region peers first,
/// then peers with measured latency before unmeasured, then lower latency
/// before higher, then lower priority number (higher priority) first.
pub fn compare_routing_preference(
    a: &PeerHandle,
    b: &PeerHandle,
    local_region: Option<&str>,
) -> std::cmp::Ordering {
    let a_same_region = local_region.is_some_and(|r| a.config.region.as_deref() == Some(r));
    let b_same_region = local_region.is_some_and(|r| b.config.region.as_deref() == Some(r));

    let a_latency = a.latency_nanos();
    let b_latency = b.latency_nanos();

    // Peers with measured latency sort before peers with no data
    let a_has_data = a_latency > 0;
    let b_has_data = b_latency > 0;

    // Same-region peers first
    b_same_region
        .cmp(&a_same_region)
        // Peers with measured latency before unmeasured
        .then(b_has_data.cmp(&a_has_data))
        // Then lower latency
        .then(a_latency.cmp(&b_latency))
        // Then lower priority number (higher priority)
        .then(a.config.priority.cmp(&b.config.priority))
}

/// Serializable snapshot of a peer's current status.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerStatus {
    pub id: PeerId,
    pub address: String,
    pub state: PeerState,
    pub groups: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_groups: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_groups: Option<Vec<String>>,
    pub enabled: bool,
    pub is_outbound: bool,
    pub messages_sent: u64,
    pub messages_recv: u64,
    pub last_error: Option<String>,
    pub connected_duration_secs: Option<u64>,
    pub reconnect_count: u64,
    pub circuit_state: CircuitState,
    pub circuit_trips: u64,
}

impl serde::Serialize for PeerState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RoutingMode;

    fn test_config() -> PeerConfig {
        PeerConfig {
            id: "test-peer".into(),
            address: "10.0.0.1:9001".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        }
    }

    #[test]
    fn lag_tracking_enqueue_and_drain() {
        let handle = PeerHandle::new(test_config());
        assert_eq!(handle.queue_bytes(), 0);
        assert!(handle.oldest_queued_age_secs().is_none());

        handle.record_enqueue(100);
        handle.record_enqueue(250);
        assert_eq!(handle.queue_bytes(), 350);
        let age = handle.oldest_queued_age_secs().expect("age present");
        assert!(age >= 0.0);

        handle.record_dequeue();
        assert_eq!(handle.queue_bytes(), 250);
        assert!(handle.oldest_queued_age_secs().is_some());

        handle.record_dequeue();
        assert_eq!(handle.queue_bytes(), 0);
        assert!(handle.oldest_queued_age_secs().is_none());
    }

    #[test]
    fn reset_queue_clears_pending_accounting() {
        let handle = PeerHandle::new(test_config());
        handle.record_enqueue(100);
        handle.record_enqueue(250);
        handle.record_enqueue(400);
        assert_eq!(handle.queue_bytes(), 750);
        assert!(handle.oldest_queued_age_secs().is_some());

        handle.reset_queue();
        assert_eq!(handle.queue_bytes(), 0);
        assert!(handle.oldest_queued_age_secs().is_none());
    }

    #[test]
    fn lag_tracking_dequeue_when_empty_is_noop() {
        let handle = PeerHandle::new(test_config());
        handle.record_dequeue();
        assert_eq!(handle.queue_bytes(), 0);
    }

    #[test]
    fn new_peer_starts_disconnected() {
        let handle = PeerHandle::new(test_config());
        assert_eq!(handle.state(), PeerState::Disconnected);
        assert!(!handle.is_connected());
    }

    #[test]
    fn state_transitions() {
        let handle = PeerHandle::new(test_config());

        handle.set_state(PeerState::Connecting);
        assert_eq!(handle.state(), PeerState::Connecting);

        handle.mark_connected();
        assert_eq!(handle.state(), PeerState::Connected);
        assert!(handle.is_connected());

        handle.mark_disconnected();
        assert_eq!(handle.state(), PeerState::Disconnected);
        assert!(!handle.is_connected());
    }

    #[test]
    fn heartbeat_tracking() {
        let handle = PeerHandle::new(test_config());
        assert!(handle.since_last_heartbeat().is_none());

        handle.record_heartbeat();
        let elapsed = handle
            .since_last_heartbeat()
            .expect("should have heartbeat");
        // Should be very recent (< 1 second)
        assert!(elapsed.as_millis() < 1000);
    }

    #[test]
    fn message_counters() {
        let handle = PeerHandle::new(test_config());
        assert_eq!(handle.messages_sent.load(Ordering::Relaxed), 0);
        assert_eq!(handle.messages_recv.load(Ordering::Relaxed), 0);

        handle.record_sent();
        handle.record_sent();
        handle.record_recv();

        assert_eq!(handle.messages_sent.load(Ordering::Relaxed), 2);
        assert_eq!(handle.messages_recv.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn error_tracking() {
        let handle = PeerHandle::new(test_config());
        assert!(handle.last_error().is_none());

        handle.set_error("connection refused");
        assert_eq!(handle.last_error().as_deref(), Some("connection refused"));
    }

    #[test]
    fn reconnect_counter() {
        let handle = PeerHandle::new(test_config());
        assert_eq!(handle.reconnect_count(), 0);

        assert_eq!(handle.increment_reconnect_count(), 1);
        assert_eq!(handle.increment_reconnect_count(), 2);
        assert_eq!(handle.reconnect_count(), 2);

        // mark_connected resets the counter
        handle.mark_connected();
        assert_eq!(handle.reconnect_count(), 0);
    }

    #[test]
    fn connected_duration_tracking() {
        let handle = PeerHandle::new(test_config());
        assert!(handle.connected_duration().is_none());

        handle.mark_connected();
        let duration = handle.connected_duration().expect("should be connected");
        assert!(duration.as_millis() < 1000);

        handle.mark_disconnected();
        assert!(handle.connected_duration().is_none());
    }

    #[test]
    fn status_snapshot() {
        let handle = PeerHandle::new(test_config());
        handle.mark_connected();
        handle.record_sent();

        let status = handle.status();
        assert_eq!(status.id, "test-peer");
        assert_eq!(status.state, PeerState::Connected);
        assert_eq!(status.messages_sent, 1);
        assert!(status.connected_duration_secs.is_some());
    }

    #[test]
    fn peer_state_display() {
        assert_eq!(PeerState::Disconnected.to_string(), "disconnected");
        assert_eq!(PeerState::Connecting.to_string(), "connecting");
        assert_eq!(PeerState::Connected.to_string(), "connected");
        assert_eq!(PeerState::Reconnecting.to_string(), "reconnecting");
    }

    #[test]
    fn peer_state_try_from_u8_valid_values() {
        assert_eq!(PeerState::try_from(0), Ok(PeerState::Disconnected));
        assert_eq!(PeerState::try_from(1), Ok(PeerState::Connecting));
        assert_eq!(PeerState::try_from(2), Ok(PeerState::Connected));
        assert_eq!(PeerState::try_from(3), Ok(PeerState::Reconnecting));
    }

    #[test]
    fn peer_state_try_from_u8_invalid_returns_error() {
        assert_eq!(PeerState::try_from(4), Err(4));
        assert_eq!(PeerState::try_from(255), Err(255));
    }

    #[test]
    fn peer_state_clone_and_copy() {
        let state = PeerState::Connected;
        let copied = state;
        let cloned = state;
        assert_eq!(state, copied);
        assert_eq!(state, cloned);
    }

    #[test]
    fn mark_connected_resets_reconnect_count() {
        let handle = PeerHandle::new(test_config());
        let _ = handle.increment_reconnect_count();
        let _ = handle.increment_reconnect_count();
        let _ = handle.increment_reconnect_count();
        assert_eq!(handle.reconnect_count(), 3);

        handle.mark_connected();
        assert_eq!(handle.reconnect_count(), 0);
    }

    #[test]
    fn mark_connected_records_heartbeat() {
        let handle = PeerHandle::new(test_config());
        assert!(handle.since_last_heartbeat().is_none());

        handle.mark_connected();
        assert!(handle.since_last_heartbeat().is_some());
    }

    #[test]
    fn mark_disconnected_clears_connected_at() {
        let handle = PeerHandle::new(test_config());
        handle.mark_connected();
        assert!(handle.connected_duration().is_some());

        handle.mark_disconnected();
        assert!(handle.connected_duration().is_none());
    }

    #[test]
    fn error_can_be_overwritten() {
        let handle = PeerHandle::new(test_config());
        handle.set_error("first error");
        assert_eq!(handle.last_error().as_deref(), Some("first error"));

        handle.set_error("second error");
        assert_eq!(handle.last_error().as_deref(), Some("second error"));
    }

    #[test]
    fn error_with_empty_string() {
        let handle = PeerHandle::new(test_config());
        handle.set_error("");
        assert_eq!(handle.last_error().as_deref(), Some(""));
    }

    #[test]
    fn status_includes_config_fields() {
        let handle = PeerHandle::new(test_config());
        let status = handle.status();
        assert_eq!(status.address, "10.0.0.1:9001");
        assert_eq!(status.groups, vec!["Alpha"]);
        assert!(status.enabled);
        assert!(status.is_outbound);
    }

    #[test]
    fn status_includes_error() {
        let handle = PeerHandle::new(test_config());
        handle.set_error("connection timeout");
        let status = handle.status();
        assert_eq!(status.last_error.as_deref(), Some("connection timeout"));
    }

    #[test]
    fn status_no_connected_duration_when_disconnected() {
        let handle = PeerHandle::new(test_config());
        let status = handle.status();
        assert!(status.connected_duration_secs.is_none());
    }

    #[test]
    fn status_reconnect_count() {
        let handle = PeerHandle::new(test_config());
        let _ = handle.increment_reconnect_count();
        let _ = handle.increment_reconnect_count();
        let status = handle.status();
        assert_eq!(status.reconnect_count, 2);
    }

    #[test]
    fn peer_state_serialize_as_string() {
        let status = PeerStatus {
            id: "test".into(),
            address: "1.2.3.4:9001".into(),
            state: PeerState::Connected,
            groups: vec![],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            messages_sent: 0,
            messages_recv: 0,
            last_error: None,
            connected_duration_secs: None,
            reconnect_count: 0,
            circuit_state: CircuitState::Closed,
            circuit_trips: 0,
        };
        let json = serde_json::to_string(&status).expect("serialize");
        assert!(json.contains("\"connected\""));
    }

    #[test]
    fn peer_state_all_variants_serialize() {
        for (state, expected) in [
            (PeerState::Disconnected, "disconnected"),
            (PeerState::Connecting, "connecting"),
            (PeerState::Connected, "connected"),
            (PeerState::Reconnecting, "reconnecting"),
        ] {
            let json = serde_json::to_string(&state).expect("serialize");
            assert_eq!(json, format!("\"{expected}\""));
        }
    }

    #[test]
    fn set_state_all_transitions() {
        let handle = PeerHandle::new(test_config());

        // Test all valid state transitions
        for state in [
            PeerState::Connecting,
            PeerState::Connected,
            PeerState::Reconnecting,
            PeerState::Disconnected,
        ] {
            handle.set_state(state);
            assert_eq!(handle.state(), state);
        }
    }

    #[test]
    fn message_counters_accumulate() {
        let handle = PeerHandle::new(test_config());
        for _ in 0..100 {
            handle.record_sent();
        }
        for _ in 0..50 {
            handle.record_recv();
        }
        assert_eq!(handle.messages_sent.load(Ordering::Relaxed), 100);
        assert_eq!(handle.messages_recv.load(Ordering::Relaxed), 50);
    }

    #[test]
    fn new_peer_has_zero_message_counters() {
        let handle = PeerHandle::new(test_config());
        let status = handle.status();
        assert_eq!(status.messages_sent, 0);
        assert_eq!(status.messages_recv, 0);
    }

    #[test]
    fn peer_id_matches_config() {
        let handle = PeerHandle::new(test_config());
        assert_eq!(handle.id, "test-peer");
        assert_eq!(handle.config.id, "test-peer");
    }

    #[test]
    fn new_peer_has_no_error() {
        let handle = PeerHandle::new(test_config());
        let status = handle.status();
        assert!(status.last_error.is_none());
    }

    #[test]
    fn reconnect_count_increments_sequentially() {
        let handle = PeerHandle::new(test_config());
        assert_eq!(handle.increment_reconnect_count(), 1);
        assert_eq!(handle.increment_reconnect_count(), 2);
        assert_eq!(handle.increment_reconnect_count(), 3);
        assert_eq!(handle.increment_reconnect_count(), 4);
        assert_eq!(handle.increment_reconnect_count(), 5);
        assert_eq!(handle.reconnect_count(), 5);
    }

    // ── Circuit breaker tests ────────────────────────────────────────

    #[test]
    fn new_peer_circuit_starts_closed() {
        let handle = PeerHandle::new(test_config());
        assert_eq!(handle.circuit_state(), CircuitState::Closed);
        assert_eq!(handle.circuit_trip_count(), 0);
    }

    #[test]
    fn circuit_stays_closed_below_threshold() {
        let handle = PeerHandle::with_circuit_breaker(test_config(), 5, 60);
        handle.mark_connected();

        for _ in 0..4 {
            assert!(!handle.record_failure());
        }
        assert_eq!(handle.circuit_state(), CircuitState::Closed);
        assert!(handle.is_available());
    }

    #[test]
    fn circuit_opens_at_threshold() {
        let handle = PeerHandle::with_circuit_breaker(test_config(), 3, 60);
        handle.mark_connected();

        assert!(!handle.record_failure());
        assert!(!handle.record_failure());
        assert!(handle.record_failure()); // 3rd failure trips it
        assert_eq!(handle.circuit_state(), CircuitState::Open);
        assert!(!handle.is_available());
        assert_eq!(handle.circuit_trip_count(), 1);
    }

    #[test]
    fn open_circuit_transitions_to_half_open_after_timeout() {
        let handle = PeerHandle::with_circuit_breaker(test_config(), 1, 0);
        handle.mark_connected();

        // Trip the circuit
        assert!(handle.record_failure());

        // With 0-second timeout, checking state should immediately yield HalfOpen
        // (the auto-transition fires because elapsed >= 0 is always true)
        assert_eq!(handle.circuit_state(), CircuitState::HalfOpen);
        assert!(handle.is_available());
    }

    #[test]
    fn half_open_closes_on_success() {
        let handle = PeerHandle::with_circuit_breaker(test_config(), 1, 0);
        handle.mark_connected();

        let _ = handle.record_failure();
        // Transition to HalfOpen
        assert_eq!(handle.circuit_state(), CircuitState::HalfOpen);

        // Success closes the circuit
        assert!(handle.record_success());
        assert_eq!(handle.circuit_state(), CircuitState::Closed);
        assert!(handle.is_available());
    }

    #[test]
    fn half_open_reopens_on_failure() {
        let handle = PeerHandle::with_circuit_breaker(test_config(), 1, 0);
        handle.mark_connected();

        let _ = handle.record_failure();
        // Transition to HalfOpen via timeout check
        assert_eq!(handle.circuit_state(), CircuitState::HalfOpen);

        // Failure in HalfOpen reopens the circuit (trip count goes to 2)
        assert!(handle.record_failure());
        assert_eq!(handle.circuit_trip_count(), 2);
        // With 0-second timeout, circuit_state() auto-transitions Open → HalfOpen
        // so we verify the trip count instead of observing Open directly
        assert_eq!(handle.circuit_state(), CircuitState::HalfOpen);
    }

    #[test]
    fn success_resets_failure_counter() {
        let handle = PeerHandle::with_circuit_breaker(test_config(), 5, 60);
        handle.mark_connected();

        // Accumulate 4 failures (just below threshold)
        for _ in 0..4 {
            let _ = handle.record_failure();
        }

        // Success resets the counter
        let _ = handle.record_success();

        // 4 more failures should not trip (counter was reset)
        for _ in 0..4 {
            assert!(!handle.record_failure());
        }
        assert_eq!(handle.circuit_state(), CircuitState::Closed);
    }

    #[test]
    fn disconnected_peer_is_not_available() {
        let handle = PeerHandle::new(test_config());
        assert!(!handle.is_available());
    }

    #[test]
    fn connected_peer_with_closed_circuit_is_available() {
        let handle = PeerHandle::new(test_config());
        handle.mark_connected();
        assert!(handle.is_available());
    }

    #[test]
    fn status_includes_circuit_breaker() {
        let handle = PeerHandle::with_circuit_breaker(test_config(), 2, 60);
        handle.mark_connected();
        let _ = handle.record_failure();
        let _ = handle.record_failure();

        let status = handle.status();
        assert_eq!(status.circuit_state, CircuitState::Open);
        assert_eq!(status.circuit_trips, 1);
    }

    #[test]
    fn circuit_state_display() {
        assert_eq!(CircuitState::Closed.to_string(), "closed");
        assert_eq!(CircuitState::Open.to_string(), "open");
        assert_eq!(CircuitState::HalfOpen.to_string(), "half_open");
    }

    #[test]
    fn circuit_state_try_from_u8_valid_values() {
        assert_eq!(CircuitState::try_from(0), Ok(CircuitState::Closed));
        assert_eq!(CircuitState::try_from(1), Ok(CircuitState::Open));
        assert_eq!(CircuitState::try_from(2), Ok(CircuitState::HalfOpen));
    }

    #[test]
    fn circuit_state_try_from_u8_invalid_returns_error() {
        assert_eq!(CircuitState::try_from(3), Err(3));
        assert_eq!(CircuitState::try_from(255), Err(255));
    }

    #[test]
    fn circuit_state_serializes_as_string() {
        let json = serde_json::to_string(&CircuitState::Open).expect("serialize");
        assert_eq!(json, "\"open\"");
    }

    #[test]
    fn open_circuit_stays_open_before_timeout() {
        let handle = PeerHandle::with_circuit_breaker(test_config(), 2, 3600);
        handle.mark_connected();

        let _ = handle.record_failure();
        let _ = handle.record_failure();
        // Circuit is open with 1-hour timeout — should stay Open
        assert_eq!(handle.circuit_state(), CircuitState::Open);
        assert!(!handle.is_available());
    }

    #[test]
    fn with_circuit_breaker_custom_params() {
        let handle = PeerHandle::with_circuit_breaker(test_config(), 10, 120);
        assert_eq!(handle.failure_threshold, 10);
        assert_eq!(handle.recovery_timeout_secs, 120);
    }
}
