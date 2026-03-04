//! V1 federation outbound client.
//!
//! Connects to a remote federation peer over mTLS and runs read/write
//! loops with heartbeat sending and automatic reconnection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use rustgate_core::protocol::HeaderSize;
use rustgate_transport::LengthPrefixedCodec;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

use crate::connector::PeerConnector;
use crate::heartbeat::{create_heartbeat, is_heartbeat};
use crate::peer::{PeerHandle, PeerState};

/// Callback invoked for each non-heartbeat message received from the peer.
///
/// Arguments: (peer_id, payload_bytes)
pub type OnMessage = Arc<dyn Fn(String, Bytes) + Send + Sync>;

/// V1 federation outbound client.
///
/// Maintains a persistent connection to a remote peer with automatic
/// reconnection using exponential backoff.
#[derive(Debug)]
pub struct V1Client {
    /// Handle to the background connection task.
    task_handle: Option<JoinHandle<()>>,
    /// Shutdown signal sender.
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Channel for sending outbound messages to the peer.
    outbound_tx: mpsc::Sender<Bytes>,
    /// Peer state tracking.
    peer: Arc<PeerHandle>,
}

impl V1Client {
    /// Create and start a V1 outbound client.
    ///
    /// The client immediately begins connecting to the remote peer
    /// and will reconnect automatically on disconnection.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        peer: Arc<PeerHandle>,
        connector: PeerConnector,
        addr: SocketAddr,
        server_name: String,
        server_uid: String,
        heartbeat_interval: Duration,
        heartbeat_timeout: Duration,
        reconnect_delay: Duration,
        max_reconnects: i32,
        on_message: OnMessage,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Bytes>(64);

        let peer_clone = Arc::clone(&peer);
        let task_handle = tokio::spawn(connection_loop(
            peer_clone,
            connector,
            addr,
            server_name,
            server_uid,
            heartbeat_interval,
            heartbeat_timeout,
            reconnect_delay,
            max_reconnects,
            on_message,
            outbound_rx,
            shutdown_rx,
        ));

        Self {
            task_handle: Some(task_handle),
            shutdown_tx: Some(shutdown_tx),
            outbound_tx,
            peer,
        }
    }

    /// Send a message to the remote peer.
    ///
    /// Returns an error if the send channel is full or the client is shut down.
    pub async fn send(&self, data: Bytes) -> anyhow::Result<()> {
        self.outbound_tx
            .send(data)
            .await
            .map_err(|_| anyhow::anyhow!("V1 client send channel closed"))
    }

    /// Get the current peer state.
    pub fn peer(&self) -> &PeerHandle {
        &self.peer
    }

    /// Gracefully shut down the client.
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        self.peer.set_state(PeerState::Disconnected);
    }
}

/// Main connection loop with reconnection logic.
///
/// Keeps trying to connect to the remote peer. On disconnect, waits with
/// exponential backoff before retrying.
#[allow(clippy::too_many_arguments)]
async fn connection_loop(
    peer: Arc<PeerHandle>,
    connector: PeerConnector,
    addr: SocketAddr,
    server_name: String,
    server_uid: String,
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
    reconnect_delay: Duration,
    max_reconnects: i32,
    on_message: OnMessage,
    mut outbound_rx: mpsc::Receiver<Bytes>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let peer_id = peer.id.clone();
    let mut reconnect_count: u32 = 0;

    loop {
        // Check shutdown before connecting
        if *shutdown_rx.borrow() {
            debug!(peer_id = %peer_id, "V1 client shutdown requested");
            return;
        }

        peer.set_state(PeerState::Connecting);
        info!(
            peer_id = %peer_id,
            addr = %addr,
            attempt = reconnect_count + 1,
            "connecting to V1 federation peer"
        );

        // Attempt connection
        let connect_result = connector.connect(addr, &server_name).await;
        let (tls_stream, identity) = match connect_result {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    peer_id = %peer_id,
                    error = %e,
                    "failed to connect to V1 federation peer"
                );
                peer.set_state(PeerState::Reconnecting);
                peer.set_error(&e.to_string());

                if should_stop_reconnecting(max_reconnects, reconnect_count) {
                    error!(
                        peer_id = %peer_id,
                        max_reconnects = max_reconnects,
                        "max reconnection attempts reached, giving up"
                    );
                    peer.set_state(PeerState::Disconnected);
                    return;
                }

                let delay = backoff_delay(reconnect_delay, reconnect_count);
                reconnect_count += 1;

                tokio::select! {
                    _ = tokio::time::sleep(delay) => continue,
                    _ = shutdown_rx.changed() => return,
                }
            }
        };

        // Connected successfully
        peer.mark_connected();
        reconnect_count = 0;
        info!(
            peer_id = %peer_id,
            peer_cn = %identity.cn,
            addr = %addr,
            "connected to V1 federation peer"
        );

        // Run the session
        let session_result = run_session(
            &peer,
            tls_stream,
            &server_uid,
            heartbeat_interval,
            heartbeat_timeout,
            &on_message,
            &mut outbound_rx,
            &mut shutdown_rx,
        )
        .await;

        peer.set_state(PeerState::Disconnected);

        match session_result {
            Ok(()) => {
                info!(peer_id = %peer_id, "V1 federation peer disconnected cleanly");
            }
            Err(e) => {
                warn!(peer_id = %peer_id, error = %e, "V1 federation peer session error");
                peer.set_error(&e.to_string());
            }
        }

        if *shutdown_rx.borrow() {
            return;
        }

        // Wait before reconnecting
        peer.set_state(PeerState::Reconnecting);
        if should_stop_reconnecting(max_reconnects, reconnect_count) {
            error!(
                peer_id = %peer_id,
                max_reconnects = max_reconnects,
                "max reconnection attempts reached, giving up"
            );
            peer.set_state(PeerState::Disconnected);
            return;
        }

        let delay = backoff_delay(reconnect_delay, reconnect_count);
        reconnect_count += 1;

        info!(
            peer_id = %peer_id,
            delay = ?delay,
            "waiting before reconnecting to V1 federation peer"
        );

        tokio::select! {
            _ = tokio::time::sleep(delay) => {},
            _ = shutdown_rx.changed() => return,
        }
    }
}

/// Run a connected V1 session — read/write loops + heartbeat.
#[allow(clippy::too_many_arguments)]
async fn run_session(
    peer: &PeerHandle,
    tls_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    server_uid: &str,
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
    on_message: &OnMessage,
    outbound_rx: &mut mpsc::Receiver<Bytes>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let peer_id = peer.id.clone();
    let codec = LengthPrefixedCodec::new(HeaderSize::Four);
    let mut framed = Framed::new(tls_stream, codec);

    // Heartbeat tracking
    let mut last_heartbeat_received = tokio::time::Instant::now();
    let mut heartbeat_send_interval = tokio::time::interval(heartbeat_interval);
    let _ = heartbeat_send_interval.tick().await; // skip immediate tick

    let mut heartbeat_check_interval = tokio::time::interval(Duration::from_secs(5));
    let _ = heartbeat_check_interval.tick().await; // skip immediate tick

    loop {
        tokio::select! {
            // Read from peer
            frame = framed.next() => {
                match frame {
                    Some(Ok(data)) => {
                        if is_heartbeat(&data) {
                            debug!(peer_id = %peer_id, "V1 heartbeat received from peer");
                            last_heartbeat_received = tokio::time::Instant::now();
                        } else {
                            peer.record_recv();
                            on_message(peer_id.clone(), data.freeze());
                        }
                    }
                    Some(Err(e)) => {
                        return Err(anyhow::anyhow!("read error: {e}"));
                    }
                    None => {
                        return Ok(()); // peer closed connection
                    }
                }
            }

            // Send queued outbound messages
            msg = outbound_rx.recv() => {
                match msg {
                    Some(data) => {
                        let buf = BytesMut::from(data.as_ref());
                        framed.send(buf).await
                            .map_err(|e| anyhow::anyhow!("write error: {e}"))?;
                        peer.record_sent();
                    }
                    None => {
                        return Ok(()); // outbound channel closed
                    }
                }
            }

            // Send heartbeat at interval
            _ = heartbeat_send_interval.tick() => {
                let hb = create_heartbeat(server_uid);
                let buf = BytesMut::from(hb.as_ref());
                framed.send(buf).await
                    .map_err(|e| anyhow::anyhow!("heartbeat send error: {e}"))?;
                debug!(peer_id = %peer_id, "V1 heartbeat sent to peer");
            }

            // Check heartbeat timeout
            _ = heartbeat_check_interval.tick() => {
                if last_heartbeat_received.elapsed() > heartbeat_timeout {
                    return Err(anyhow::anyhow!(
                        "heartbeat timeout: no heartbeat in {:?}",
                        last_heartbeat_received.elapsed()
                    ));
                }
            }

            // Shutdown signal
            _ = shutdown_rx.changed() => {
                return Ok(());
            }
        }
    }
}

/// Calculate exponential backoff delay.
///
/// delay = base * 2^min(count, 5), capped at 5 minutes.
fn backoff_delay(base: Duration, count: u32) -> Duration {
    let exponent = count.min(5);
    let multiplier = 2u64.pow(exponent);
    let delay = base.saturating_mul(multiplier as u32);
    let max_delay = Duration::from_secs(300); // 5 minutes
    delay.min(max_delay)
}

/// Check whether we should stop trying to reconnect.
fn should_stop_reconnecting(max_reconnects: i32, count: u32) -> bool {
    if max_reconnects < 0 {
        return false; // unlimited
    }
    count >= max_reconnects as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── backoff_delay ───────────────────────────────────────────────

    #[test]
    fn backoff_delay_base_case() {
        let delay = backoff_delay(Duration::from_secs(15), 0);
        assert_eq!(delay, Duration::from_secs(15)); // 15 * 2^0 = 15
    }

    #[test]
    fn backoff_delay_exponential() {
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 1),
            Duration::from_secs(30)
        ); // 15 * 2
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 2),
            Duration::from_secs(60)
        ); // 15 * 4
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 3),
            Duration::from_secs(120)
        ); // 15 * 8
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 4),
            Duration::from_secs(240)
        ); // 15 * 16
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 5),
            Duration::from_secs(300)
        ); // 15 * 32 = 480 → capped at 300
    }

    #[test]
    fn backoff_delay_caps_at_five_minutes() {
        let delay = backoff_delay(Duration::from_secs(30), 10);
        assert_eq!(delay, Duration::from_secs(300));
    }

    #[test]
    fn backoff_delay_caps_exponent_at_five() {
        // Exponent is capped at 5, so count=6 gives same as count=5
        let d5 = backoff_delay(Duration::from_secs(10), 5);
        let d6 = backoff_delay(Duration::from_secs(10), 6);
        assert_eq!(d5, d6);
    }

    #[test]
    fn backoff_delay_with_one_second_base() {
        assert_eq!(
            backoff_delay(Duration::from_secs(1), 0),
            Duration::from_secs(1)
        );
        assert_eq!(
            backoff_delay(Duration::from_secs(1), 1),
            Duration::from_secs(2)
        );
        assert_eq!(
            backoff_delay(Duration::from_secs(1), 5),
            Duration::from_secs(32)
        );
    }

    #[test]
    fn backoff_delay_with_zero_base() {
        assert_eq!(
            backoff_delay(Duration::from_secs(0), 0),
            Duration::from_secs(0)
        );
        assert_eq!(
            backoff_delay(Duration::from_secs(0), 5),
            Duration::from_secs(0)
        );
    }

    #[test]
    fn backoff_delay_with_large_base_caps_at_five_minutes() {
        // A large base that would exceed 5 minutes even at count=0
        let delay = backoff_delay(Duration::from_secs(600), 0);
        assert_eq!(delay, Duration::from_secs(300)); // capped
    }

    #[test]
    fn backoff_delay_with_subsecond_base() {
        let delay = backoff_delay(Duration::from_millis(500), 3);
        // 500ms * 8 = 4000ms = 4s
        assert_eq!(delay, Duration::from_secs(4));
    }

    #[test]
    fn backoff_delay_all_exponents_monotonically_increase() {
        let base = Duration::from_secs(10);
        let mut prev = Duration::from_secs(0);
        for i in 0..=5 {
            let d = backoff_delay(base, i);
            assert!(d > prev || (i == 0 && d == base), "delay should increase");
            prev = d;
        }
    }

    // ── should_stop_reconnecting ────────────────────────────────────

    #[test]
    fn should_stop_unlimited() {
        assert!(!should_stop_reconnecting(-1, 0));
        assert!(!should_stop_reconnecting(-1, 100));
        assert!(!should_stop_reconnecting(-1, u32::MAX));
    }

    #[test]
    fn should_stop_limited() {
        assert!(!should_stop_reconnecting(3, 0));
        assert!(!should_stop_reconnecting(3, 1));
        assert!(!should_stop_reconnecting(3, 2));
        assert!(should_stop_reconnecting(3, 3));
        assert!(should_stop_reconnecting(3, 4));
    }

    #[test]
    fn should_stop_zero_reconnects() {
        assert!(should_stop_reconnecting(0, 0));
    }

    #[test]
    fn should_stop_single_reconnect() {
        assert!(!should_stop_reconnecting(1, 0));
        assert!(should_stop_reconnecting(1, 1));
    }

    #[test]
    fn should_stop_very_negative() {
        // Any negative value means unlimited
        assert!(!should_stop_reconnecting(-100, 0));
        assert!(!should_stop_reconnecting(i32::MIN, u32::MAX));
    }

    #[test]
    fn should_stop_large_limit() {
        assert!(!should_stop_reconnecting(1_000_000, 999_999));
        assert!(should_stop_reconnecting(1_000_000, 1_000_000));
    }

    // ── V1Client lifecycle ──────────────────────────────────────────

    #[tokio::test]
    async fn client_start_and_shutdown() {
        use rustgate_test_utils::certs::TestCa;

        use crate::config::{PeerConfig, RoutingMode};

        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);

        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("connector");

        let peer_config = PeerConfig {
            id: "test-peer".into(),
            address: "127.0.0.1:19999".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 1,
        };

        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});

        let mut client = V1Client::start(
            peer,
            connector,
            "127.0.0.1:19999".parse().expect("addr"),
            "localhost".into(),
            "test-uid".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            Duration::from_secs(1),
            0, // no reconnects — should give up quickly
            on_msg,
        );

        // Give it a moment to attempt connection and fail
        tokio::time::sleep(Duration::from_millis(200)).await;

        client.shutdown().await;
        assert_eq!(client.peer().state(), PeerState::Disconnected);
    }

    #[tokio::test]
    async fn client_send_fails_after_shutdown() {
        use rustgate_test_utils::certs::TestCa;

        use crate::config::{PeerConfig, RoutingMode};

        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);

        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("connector");

        let peer_config = PeerConfig {
            id: "test-peer".into(),
            address: "127.0.0.1:19998".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 1,
        };

        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});

        let mut client = V1Client::start(
            peer,
            connector,
            "127.0.0.1:19998".parse().expect("addr"),
            "localhost".into(),
            "test-uid".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            Duration::from_secs(1),
            0,
            on_msg,
        );

        client.shutdown().await;

        // After shutdown, the outbound channel receiver is dropped
        // so sends should fail eventually
        let result = client.send(Bytes::from("test")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn client_peer_tracks_error_on_connection_failure() {
        use rustgate_test_utils::certs::TestCa;

        use crate::config::{PeerConfig, RoutingMode};

        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);

        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("connector");

        let peer_config = PeerConfig {
            id: "error-test-peer".into(),
            address: "127.0.0.1:19997".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 1,
        };

        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});

        let mut client = V1Client::start(
            Arc::clone(&peer),
            connector,
            "127.0.0.1:19997".parse().expect("addr"),
            "localhost".into(),
            "test-uid".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            Duration::from_millis(100),
            0, // no reconnects
            on_msg,
        );

        // Wait for the connection attempt to fail and the loop to exit
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Peer should have recorded the connection error
        assert!(peer.last_error().is_some());

        client.shutdown().await;
    }

    #[tokio::test]
    async fn client_peer_accessor_returns_handle() {
        use rustgate_test_utils::certs::TestCa;

        use crate::config::{PeerConfig, RoutingMode};

        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);

        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("connector");

        let peer_config = PeerConfig {
            id: "accessor-peer".into(),
            address: "127.0.0.1:19996".into(),
            groups: vec!["Beta".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 1,
        };

        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});

        let mut client = V1Client::start(
            peer,
            connector,
            "127.0.0.1:19996".parse().expect("addr"),
            "localhost".into(),
            "test-uid".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            Duration::from_secs(1),
            0,
            on_msg,
        );

        // Verify peer accessor works
        assert_eq!(client.peer().id, "accessor-peer");
        assert_eq!(client.peer().config.groups, vec!["Beta"]);

        client.shutdown().await;
    }
}
