use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Instant;

use crate::config::PeerConfig;

/// Connection state for a federation peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Reconnecting = 3,
}

impl PeerState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => PeerState::Disconnected,
            1 => PeerState::Connecting,
            2 => PeerState::Connected,
            3 => PeerState::Reconnecting,
            _ => PeerState::Disconnected,
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

/// Tracks the runtime state of a federation peer connection.
///
/// Thread-safe — all fields use atomic types or mutexes.
#[derive(Debug)]
pub struct PeerHandle {
    /// Peer identifier.
    pub id: String,
    /// Static configuration.
    pub config: PeerConfig,
    /// Current connection state (atomic for lock-free reads).
    state: AtomicU8,
    /// Timestamp of the last received heartbeat.
    last_heartbeat: Mutex<Option<Instant>>,
    /// Total messages sent to this peer.
    pub messages_sent: AtomicU64,
    /// Total messages received from this peer.
    pub messages_recv: AtomicU64,
    /// Last error message, if any.
    last_error: Mutex<Option<String>>,
    /// Timestamp when the current connection was established.
    connected_at: Mutex<Option<Instant>>,
    /// Number of reconnection attempts since last successful connection.
    reconnect_count: AtomicU64,
}

impl PeerHandle {
    /// Create a new peer handle from configuration.
    pub fn new(config: PeerConfig) -> Self {
        let id = config.id.clone();
        Self {
            id,
            config,
            state: AtomicU8::new(PeerState::Disconnected as u8),
            last_heartbeat: Mutex::new(None),
            messages_sent: AtomicU64::new(0),
            messages_recv: AtomicU64::new(0),
            last_error: Mutex::new(None),
            connected_at: Mutex::new(None),
            reconnect_count: AtomicU64::new(0),
        }
    }

    /// Get the current connection state.
    pub fn state(&self) -> PeerState {
        PeerState::from_u8(self.state.load(Ordering::Relaxed))
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
        if let Ok(mut guard) = self.last_heartbeat.lock() {
            *guard = Some(Instant::now());
        }
    }

    /// Get the elapsed time since the last heartbeat.
    ///
    /// Returns `None` if no heartbeat has been received.
    pub fn since_last_heartbeat(&self) -> Option<std::time::Duration> {
        self.last_heartbeat
            .lock()
            .ok()
            .and_then(|guard| guard.map(|ts| ts.elapsed()))
    }

    /// Record a successful connection.
    pub fn mark_connected(&self) {
        self.set_state(PeerState::Connected);
        if let Ok(mut guard) = self.connected_at.lock() {
            *guard = Some(Instant::now());
        }
        self.reconnect_count.store(0, Ordering::Relaxed);
        self.record_heartbeat();
    }

    /// Record a disconnection.
    pub fn mark_disconnected(&self) {
        self.set_state(PeerState::Disconnected);
        if let Ok(mut guard) = self.connected_at.lock() {
            *guard = None;
        }
    }

    /// Record an error.
    pub fn set_error(&self, err: &str) {
        if let Ok(mut guard) = self.last_error.lock() {
            *guard = Some(err.to_string());
        }
    }

    /// Get the last error message.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|guard| guard.clone())
    }

    /// Get the duration this peer has been connected.
    pub fn connected_duration(&self) -> Option<std::time::Duration> {
        self.connected_at
            .lock()
            .ok()
            .and_then(|guard| guard.map(|ts| ts.elapsed()))
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

    /// Get a snapshot of this peer's status for reporting.
    pub fn status(&self) -> PeerStatus {
        PeerStatus {
            id: self.id.clone(),
            address: self.config.address.clone(),
            state: self.state(),
            groups: self.config.groups.clone(),
            enabled: self.config.enabled,
            is_outbound: self.config.is_outbound,
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_recv: self.messages_recv.load(Ordering::Relaxed),
            last_error: self.last_error(),
            connected_duration_secs: self.connected_duration().map(|d| d.as_secs()),
            reconnect_count: self.reconnect_count(),
        }
    }
}

/// Serializable snapshot of a peer's current status.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerStatus {
    pub id: String,
    pub address: String,
    pub state: PeerState,
    pub groups: Vec<String>,
    pub enabled: bool,
    pub is_outbound: bool,
    pub messages_sent: u64,
    pub messages_recv: u64,
    pub last_error: Option<String>,
    pub connected_duration_secs: Option<u64>,
    pub reconnect_count: u64,
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
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
        }
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
    fn peer_state_from_u8_valid_values() {
        assert_eq!(PeerState::from_u8(0), PeerState::Disconnected);
        assert_eq!(PeerState::from_u8(1), PeerState::Connecting);
        assert_eq!(PeerState::from_u8(2), PeerState::Connected);
        assert_eq!(PeerState::from_u8(3), PeerState::Reconnecting);
    }

    #[test]
    fn peer_state_from_u8_invalid_defaults_to_disconnected() {
        assert_eq!(PeerState::from_u8(4), PeerState::Disconnected);
        assert_eq!(PeerState::from_u8(255), PeerState::Disconnected);
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
            enabled: true,
            is_outbound: true,
            messages_sent: 0,
            messages_recv: 0,
            last_error: None,
            connected_duration_secs: None,
            reconnect_count: 0,
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
}
