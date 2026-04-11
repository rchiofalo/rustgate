// Copyright © 2026 Roberto Chiofalo.

//! V1 federation outbound client.
//!
//! Connects to a remote federation peer over mTLS and runs read/write
//! loops with heartbeat sending and automatic reconnection.

use std::fmt;
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

use crate::connector::OutboundConnector;
use crate::heartbeat::{create_heartbeat, is_heartbeat};
use crate::peer::{PeerHandle, PeerState};
use crate::reconnect::{backoff_delay, should_stop_reconnecting};
use crate::replay_buffer::BufferedMessage;

/// Callback invoked for each non-heartbeat message received from the peer.
///
/// Arguments: (peer_id, payload_bytes)
pub type OnMessage = Arc<dyn Fn(String, Bytes) + Send + Sync>;

/// Callback that drains the replay buffer on reconnection.
///
/// Returns deduped buffered messages and clears the buffer atomically.
/// Arguments: `(peer_id) -> Vec<BufferedMessage>`
pub type ReplayDrain = Arc<dyn Fn(&str) -> Vec<BufferedMessage> + Send + Sync>;

/// Configuration for a V1 federation outbound client.
pub struct V1ClientConfig {
    pub connector: OutboundConnector,
    pub addr: SocketAddr,
    pub server_name: String,
    pub server_uid: String,
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub reconnect_delay: Duration,
    pub max_reconnects: i32,
    pub on_message: OnMessage,
    /// Optional replay drain callback. When set, called after reconnection
    /// to retrieve and resend buffered messages before entering the live
    /// session loop.
    pub replay_drain: Option<ReplayDrain>,
}

impl fmt::Debug for V1ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V1ClientConfig")
            .field("addr", &self.addr)
            .field("server_name", &self.server_name)
            .field("server_uid", &self.server_uid)
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("heartbeat_timeout", &self.heartbeat_timeout)
            .field("reconnect_delay", &self.reconnect_delay)
            .field("max_reconnects", &self.max_reconnects)
            .finish_non_exhaustive()
    }
}

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
    pub fn start(peer: Arc<PeerHandle>, config: V1ClientConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Bytes>(64);

        let peer_clone = Arc::clone(&peer);
        let task_handle = tokio::spawn(connection_loop(
            peer_clone,
            config,
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
        let bytes_len = data.len();
        self.peer.record_enqueue(bytes_len);
        match self.outbound_tx.send(data).await {
            Ok(()) => Ok(()),
            Err(_) => {
                // Send failed before delivery — undo the enqueue accounting.
                self.peer.record_dequeue();
                Err(anyhow::anyhow!("V1 client send channel closed"))
            }
        }
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
async fn connection_loop(
    peer: Arc<PeerHandle>,
    config: V1ClientConfig,
    mut outbound_rx: mpsc::Receiver<Bytes>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let peer_id = peer.id.clone();
    let mut reconnect_count: u32 = 0;

    // Run the reconnect loop in an inner async block so every exit path falls
    // through to the queue-drain below. Without this, messages still buffered
    // in `outbound_rx` when the client gives up (max reconnects, shutdown,
    // unrecoverable error) would leak counter weight on the per-peer queue
    // gauges for the lifetime of the process.
    let _: () = async {
        loop {
            // Check shutdown before connecting
            if *shutdown_rx.borrow() {
                debug!(peer_id = %peer_id, "V1 client shutdown requested");
                return;
            }

            peer.set_state(PeerState::Connecting);
            info!(
                peer_id = %peer_id,
                addr = %config.addr,
                attempt = reconnect_count + 1,
                "connecting to V1 federation peer"
            );

            // Attempt connection
            let connect_result = config
                .connector
                .connect(config.addr, &config.server_name)
                .await;
            let (tls_stream, identity) = match connect_result {
                Ok(result) => result,
                Err(e) => {
                    rustgate_core::audit::federation_connect_failed(&peer_id, &e.to_string());
                    warn!(
                        peer_id = %peer_id,
                        error = %e,
                        "failed to connect to V1 federation peer"
                    );
                    peer.set_state(PeerState::Reconnecting);
                    peer.set_error(&e.to_string());

                    if should_stop_reconnecting(config.max_reconnects, reconnect_count) {
                        error!(
                            peer_id = %peer_id,
                            max_reconnects = config.max_reconnects,
                            "max reconnection attempts reached, giving up"
                        );
                        peer.set_state(PeerState::Disconnected);
                        return;
                    }

                    let delay = backoff_delay(config.reconnect_delay, reconnect_count);
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
            rustgate_core::audit::federation_peer_connected(&peer_id, &identity.cn, "outbound");
            info!(
                peer_id = %peer_id,
                peer_cn = %identity.cn,
                addr = %config.addr,
                "connected to V1 federation peer"
            );

            // Drain replay buffer for this peer (returns deduped messages and clears)
            let replay_messages: Vec<BufferedMessage> = config
                .replay_drain
                .as_ref()
                .map(|drain| drain(peer_id.as_ref()))
                .unwrap_or_default();

            if !replay_messages.is_empty() {
                info!(
                    peer_id = %peer_id,
                    replayed_count = replay_messages.len(),
                    "replaying buffered messages after reconnection"
                );
            }

            // Run the session (replay messages are sent before entering the live loop)
            let session_result = run_session(
                &peer,
                tls_stream,
                &config,
                &mut outbound_rx,
                &mut shutdown_rx,
                replay_messages,
            )
            .await;

            peer.set_state(PeerState::Disconnected);

            match session_result {
                Ok(()) => {
                    rustgate_core::audit::federation_peer_disconnected(&peer_id, "clean shutdown");
                    info!(peer_id = %peer_id, "V1 federation peer disconnected cleanly");
                }
                Err(e) => {
                    rustgate_core::audit::federation_peer_disconnected(&peer_id, &e.to_string());
                    warn!(peer_id = %peer_id, error = %e, "V1 federation peer session error");
                    peer.set_error(&e.to_string());
                }
            }

            if *shutdown_rx.borrow() {
                return;
            }

            // Wait before reconnecting
            peer.set_state(PeerState::Reconnecting);
            if should_stop_reconnecting(config.max_reconnects, reconnect_count) {
                error!(
                    peer_id = %peer_id,
                    max_reconnects = config.max_reconnects,
                    "max reconnection attempts reached, giving up"
                );
                peer.set_state(PeerState::Disconnected);
                return;
            }

            let delay = backoff_delay(config.reconnect_delay, reconnect_count);
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
    .await;

    // Drain any messages still buffered in the outbound channel and clear
    // the per-peer queue accounting so the metrics gauges return to zero.
    outbound_rx.close();
    let mut drained = 0usize;
    while outbound_rx.try_recv().is_ok() {
        drained += 1;
    }
    if drained > 0 {
        debug!(
            peer_id = %peer_id,
            drained,
            "discarded buffered messages on V1 client exit"
        );
    }
    peer.reset_queue();
}

/// Run a connected V1 session — read/write loops + heartbeat.
async fn run_session(
    peer: &PeerHandle,
    tls_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    config: &V1ClientConfig,
    outbound_rx: &mut mpsc::Receiver<Bytes>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    replay_messages: Vec<BufferedMessage>,
) -> anyhow::Result<()> {
    let peer_id = peer.id.clone();
    let codec = LengthPrefixedCodec::new(HeaderSize::Four);
    let mut framed = Framed::new(tls_stream, codec);

    // Send replay messages before entering the live loop
    for msg in &replay_messages {
        let buf = BytesMut::from(msg.payload.as_ref());
        framed
            .send(buf)
            .await
            .map_err(|e| anyhow::anyhow!("replay send error: {e}"))?;
        peer.record_sent();
    }

    if !replay_messages.is_empty() {
        debug!(
            peer_id = %peer_id,
            count = replay_messages.len(),
            "finished replaying buffered messages"
        );
    }

    // Heartbeat tracking
    let mut last_heartbeat_received = tokio::time::Instant::now();
    let mut heartbeat_send_interval = tokio::time::interval(config.heartbeat_interval);
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
                            (config.on_message)(peer_id.to_string(), data.freeze());
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
                        peer.record_dequeue();
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
                let hb = create_heartbeat(&config.server_uid);
                let buf = BytesMut::from(hb.as_ref());
                framed.send(buf).await
                    .map_err(|e| anyhow::anyhow!("heartbeat send error: {e}"))?;
                debug!(peer_id = %peer_id, "V1 heartbeat sent to peer");
            }

            // Check heartbeat timeout
            _ = heartbeat_check_interval.tick() => {
                if last_heartbeat_received.elapsed() > config.heartbeat_timeout {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::PeerConnector;

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
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };

        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});

        let mut client = V1Client::start(
            peer,
            V1ClientConfig {
                connector: OutboundConnector::Static(connector),
                addr: "127.0.0.1:19999".parse().expect("addr"),
                server_name: "localhost".into(),
                server_uid: "test-uid".into(),
                heartbeat_interval: Duration::from_secs(30),
                heartbeat_timeout: Duration::from_secs(90),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0, // no reconnects — should give up quickly
                on_message: on_msg,
                replay_drain: None,
            },
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
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };

        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});

        let mut client = V1Client::start(
            peer,
            V1ClientConfig {
                connector: OutboundConnector::Static(connector),
                addr: "127.0.0.1:19998".parse().expect("addr"),
                server_name: "localhost".into(),
                server_uid: "test-uid".into(),
                heartbeat_interval: Duration::from_secs(30),
                heartbeat_timeout: Duration::from_secs(90),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_message: on_msg,
                replay_drain: None,
            },
        );

        client.shutdown().await;

        // After shutdown, the outbound channel receiver is dropped
        // so sends should fail eventually
        let result = client.send(Bytes::from("test")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn client_drains_queue_bytes_on_shutdown_with_pending_sends() {
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
            id: "drain-peer".into(),
            address: "127.0.0.1:19996".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 1,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };

        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});

        let mut client = V1Client::start(
            Arc::clone(&peer),
            V1ClientConfig {
                connector: OutboundConnector::Static(connector),
                // Unreachable address — connection_loop fails fast and exits
                // because max_reconnects = 0.
                addr: "127.0.0.1:19996".parse().expect("addr"),
                server_name: "localhost".into(),
                server_uid: "test-uid".into(),
                heartbeat_interval: Duration::from_secs(30),
                heartbeat_timeout: Duration::from_secs(90),
                reconnect_delay: Duration::from_millis(50),
                max_reconnects: 0,
                on_message: on_msg,
                replay_drain: None,
            },
        );

        // Enqueue several messages while the client is still alive. Sends
        // succeed because the outbound channel has buffer capacity, but the
        // peer can never connect so nothing is ever delivered. Each
        // successful send increments the per-peer queue-bytes counter.
        for i in 0..5u8 {
            let payload = Bytes::from(vec![i; 64]);
            // Send may fail once the loop has exited; either outcome is fine
            // — the post-condition we care about is queue_bytes == 0.
            let _ = client.send(payload).await;
        }

        // Wait for the connection attempt to fail and the loop to exit on
        // its own (max_reconnects = 0). The drain runs after the inner loop
        // returns and must zero out the per-peer queue accounting even though
        // the buffered messages were never delivered.
        tokio::time::sleep(Duration::from_millis(300)).await;
        client.shutdown().await;

        assert_eq!(
            peer.queue_bytes(),
            0,
            "queue_bytes must return to zero after the V1 send loop exits with pending messages"
        );
        assert!(peer.oldest_queued_age_secs().is_none());
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
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };

        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});

        let mut client = V1Client::start(
            Arc::clone(&peer),
            V1ClientConfig {
                connector: OutboundConnector::Static(connector),
                addr: "127.0.0.1:19997".parse().expect("addr"),
                server_name: "localhost".into(),
                server_uid: "test-uid".into(),
                heartbeat_interval: Duration::from_secs(30),
                heartbeat_timeout: Duration::from_secs(90),
                reconnect_delay: Duration::from_millis(100),
                max_reconnects: 0, // no reconnects
                on_message: on_msg,
                replay_drain: None,
            },
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
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };

        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});

        let mut client = V1Client::start(
            peer,
            V1ClientConfig {
                connector: OutboundConnector::Static(connector),
                addr: "127.0.0.1:19996".parse().expect("addr"),
                server_name: "localhost".into(),
                server_uid: "test-uid".into(),
                heartbeat_interval: Duration::from_secs(30),
                heartbeat_timeout: Duration::from_secs(90),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_message: on_msg,
                replay_drain: None,
            },
        );

        // Verify peer accessor works
        assert_eq!(client.peer().id, "accessor-peer");
        assert_eq!(client.peer().config.groups, vec!["Beta"]);

        client.shutdown().await;
    }
}
