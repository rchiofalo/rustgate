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
use rustgate_core::masking::hash_cn;
use rustgate_core::protocol::HeaderSize;
use rustgate_resilience::backpressure::{BackpressureGate, BackpressurePermit};
use rustgate_resilience::reconnect::{backoff_delay, should_stop_reconnecting};
use rustgate_transport::LengthPrefixedCodec;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

use crate::connector::OutboundConnector;
use crate::error::{FederationError, Result};
use crate::heartbeat::{create_heartbeat, is_heartbeat};
use crate::peer::{PeerHandle, PeerState};
use crate::replay_buffer::BufferedMessage;

rustgate_core::on_callback!(
    /// Callback invoked for each non-heartbeat message received from the peer.
    ///
    /// Arguments: (peer_id, payload_bytes).
    ///
    /// F-113: receives a typed [`rustgate_core::PeerId`]. The wire-format
    /// boundary (`peer.id` is already a `PeerId`) constructs the value;
    /// downstream consumers gain compile-time enforcement that `peer_id`
    /// is not a free-form `String` (e.g. a CN, group name, or UID).
    pub OnMessage,
    rustgate_core::PeerId,
    Bytes
);

/// Callback that drains the replay buffer on reconnection.
///
/// Returns deduped buffered messages and clears the buffer atomically.
/// Arguments: `(peer_id) -> Vec<BufferedMessage>`.
///
/// F-113: takes a typed `&PeerId`. The lookup against the
/// `HashMap<PeerId, ReplayBuffer>` is unchanged because `PeerId`
/// implements `Borrow<str>`.
pub type ReplayDrain = Arc<dyn Fn(&rustgate_core::PeerId) -> Vec<BufferedMessage> + Send + Sync>;

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

/// Envelope queued for delivery to a remote V1 peer.
///
/// The optional [`BackpressurePermit`] keeps the global byte reservation
/// alive while the message sits in the bounded mpsc channel and is flushed
/// over the wire — dropping the envelope at the dequeue site releases the
/// reservation automatically.
pub(crate) struct V1Queued {
    pub data: Bytes,
    // justification: RAII field — held solely so its `Drop` releases the
    // gate reservation when the session loop dequeues the envelope.
    #[allow(dead_code)]
    pub permit: Option<Arc<BackpressurePermit>>,
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
    outbound_tx: mpsc::Sender<V1Queued>,
    /// Peer state tracking.
    peer: Arc<PeerHandle>,
    /// Optional global backpressure gate shared with ingress admission.
    gate: Option<Arc<BackpressureGate>>,
}

impl V1Client {
    /// Create and start a V1 outbound client.
    ///
    /// The client immediately begins connecting to the remote peer
    /// and will reconnect automatically on disconnection.
    ///
    /// # Runtime requirement
    ///
    /// **Must be called from within a tokio runtime context.** This
    /// constructor invokes [`tokio::spawn`] to drive the connection
    /// loop in the background. Calling it from outside a tokio
    /// runtime panics with `there is no reactor running`.
    pub fn start(peer: Arc<PeerHandle>, config: V1ClientConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (outbound_tx, outbound_rx) = mpsc::channel::<V1Queued>(64);

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
            gate: None,
        }
    }

    /// Attach a shared [`BackpressureGate`] so federated outbound traffic
    /// participates in global admission control.
    ///
    /// Every message entering [`V1Client::send`] reserves a byte permit on
    /// the gate while it sits in the bounded outbound channel and is
    /// flushed over the wire. A stalled peer whose channel is saturating
    /// now also pressures the shared gate — the router will see
    /// `is_admitting()` flip to false once the aggregate in-flight byte
    /// count crosses the high-water mark.
    pub fn with_backpressure(&mut self, gate: Arc<BackpressureGate>) {
        self.gate = Some(gate);
    }

    /// Send a message to the remote peer.
    ///
    /// Returns an error if the send channel is full or the client is shut down.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(peer = %self.peer.id, bytes = data.len()),
        err,
    )]
    pub async fn send(&self, data: Bytes) -> Result<()> {
        let bytes_len = data.len();
        self.peer.record_enqueue(bytes_len);
        let permit = self.gate.as_ref().map(|g| Arc::new(g.acquire(bytes_len)));
        let queued = V1Queued { data, permit };
        match self.outbound_tx.send(queued).await {
            Ok(()) => Ok(()),
            Err(_) => {
                // Send failed before delivery — undo the enqueue accounting.
                // `queued` was moved into `send`; the permit on the error
                // value (if any) drops automatically with the returned
                // `SendError` when the caller propagates this error.
                self.peer.record_dequeue();
                Err(FederationError::other("V1 client send channel closed"))
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
    mut outbound_rx: mpsc::Receiver<V1Queued>,
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
                debug!(peer_id = %hash_cn(peer_id.as_str()), "V1 client shutdown requested");
                return;
            }

            peer.set_state(PeerState::Connecting);
            info!(
                peer_id = %hash_cn(peer_id.as_str()),
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
                peer_id = %hash_cn(peer_id.as_str()),
                peer_cn = %hash_cn(&identity.cn),
                addr = %config.addr,
                "connected to V1 federation peer"
            );

            // Drain replay buffer for this peer (returns deduped messages and clears).
            // F-113: ReplayDrain now takes `&PeerId`; pass the typed handle directly.
            let replay_messages: Vec<BufferedMessage> = config
                .replay_drain
                .as_ref()
                .map(|drain| drain(&peer_id))
                .unwrap_or_default();

            if !replay_messages.is_empty() {
                info!(
                    peer_id = %hash_cn(peer_id.as_str()),
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
                    info!(peer_id = %hash_cn(peer_id.as_str()), "V1 federation peer disconnected cleanly");
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
                peer_id = %hash_cn(peer_id.as_str()),
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
            peer_id = %hash_cn(peer_id.as_str()),
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
    outbound_rx: &mut mpsc::Receiver<V1Queued>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    replay_messages: Vec<BufferedMessage>,
) -> Result<()> {
    let peer_id = peer.id.clone();
    let codec = LengthPrefixedCodec::new(HeaderSize::Four);
    let mut framed = Framed::new(tls_stream, codec);

    // Send replay messages before entering the live loop
    for msg in &replay_messages {
        let buf = BytesMut::from(msg.payload.as_ref());
        framed
            .send(buf)
            .await
            .map_err(|e| FederationError::other(format!("replay send error: {e}")))?;
        peer.record_sent();
    }

    if !replay_messages.is_empty() {
        debug!(
            peer_id = %hash_cn(peer_id.as_str()),
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
                            debug!(peer_id = %hash_cn(peer_id.as_str()), "V1 heartbeat received from peer");
                            last_heartbeat_received = tokio::time::Instant::now();
                        } else {
                            peer.record_recv();
                            (config.on_message)(peer_id.clone(), data.freeze());
                        }
                    }
                    Some(Err(e)) => {
                        return Err(FederationError::other(format!("read error: {e}")));
                    }
                    None => {
                        return Ok(()); // peer closed connection
                    }
                }
            }

            // Send queued outbound messages
            msg = outbound_rx.recv() => {
                match msg {
                    Some(queued) => {
                        let buf = BytesMut::from(queued.data.as_ref());
                        peer.record_dequeue();
                        framed.send(buf).await
                            .map_err(|e| FederationError::other(format!("write error: {e}")))?;
                        peer.record_sent();
                        // `queued` drops here — releases the `BackpressurePermit`
                        // reservation (if any) back to the global gate.
                        drop(queued);
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
                    .map_err(|e| FederationError::other(format!("heartbeat send error: {e}")))?;
                debug!(peer_id = %hash_cn(peer_id.as_str()), "V1 heartbeat sent to peer");
            }

            // Check heartbeat timeout
            _ = heartbeat_check_interval.tick() => {
                if last_heartbeat_received.elapsed() > config.heartbeat_timeout {
                    return Err(FederationError::other(format!(
                        "heartbeat timeout: no heartbeat in {:?}",
                        last_heartbeat_received.elapsed()
                    )));
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
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;
    use crate::connector::PeerConnector;

    // ── Contract-shape coverage ─────────────────────────────────────
    //
    // These tests pin surface that never touches a socket: `Debug`
    // redaction, callback type-alias bounds, and idempotent shutdown.
    // A refactor that accidentally weakens any of these — e.g. drops
    // `Send` from `OnMessage`, narrows `Debug` to `derive` and leaks
    // closure pointers, or makes `shutdown()` panic on double-call —
    // would still pass every integration-style test below but would
    // break downstream call sites in subtle ways.  Keeping these pins
    // fast and pure lets the integration tests stay on the happy path.
    //
    // ────────────────────────────────────────────────────────────────

    /// Build a representative `V1ClientConfig` without starting the
    /// client.  Only used by the Debug / bounds tests; no socket work.
    fn build_config_for_debug() -> V1ClientConfig {
        use rustgate_test_utils::certs::TestCa;
        let ca = TestCa::new("Debug Test CA");
        let client_cert = ca.issue_client_cert("debug-client", &["Alpha"]);
        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("connector");
        let on_msg: OnMessage = Arc::new(|_id, _data| {});
        V1ClientConfig {
            connector: OutboundConnector::Static(connector),
            addr: "192.0.2.42:19990".parse().expect("addr"),
            server_name: "debug-server-name".into(),
            server_uid: "debug-server-uid".into(),
            heartbeat_interval: Duration::from_secs(42),
            heartbeat_timeout: Duration::from_secs(96),
            reconnect_delay: Duration::from_secs(7),
            max_reconnects: 3,
            on_message: on_msg,
            replay_drain: None,
        }
    }

    // ── Type-alias Send + Sync + 'static bounds ─────────────────────

    #[test]
    fn on_message_is_send_sync_static() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<OnMessage>();
    }

    #[test]
    fn replay_drain_is_send_sync_static() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<ReplayDrain>();
    }

    // ── `V1ClientConfig` Debug redaction ────────────────────────────

    #[test]
    fn config_debug_surfaces_operator_fields_and_redacts_closures() {
        let cfg = build_config_for_debug();
        let rendered = format!("{cfg:?}");

        // Operator-facing fields MUST be present so a
        // `tracing::debug!(?cfg, …)` line lets the on-call identify
        // which peer a failure points at.
        assert!(rendered.contains("V1ClientConfig"));
        assert!(
            rendered.contains("192.0.2.42"),
            "addr must surface in Debug, got: {rendered}"
        );
        assert!(
            rendered.contains("debug-server-name"),
            "server_name must surface in Debug, got: {rendered}"
        );
        assert!(
            rendered.contains("debug-server-uid"),
            "server_uid must surface in Debug, got: {rendered}"
        );
        assert!(
            rendered.contains("max_reconnects"),
            "max_reconnects must surface in Debug, got: {rendered}"
        );

        // `finish_non_exhaustive()` adds `..` — pin the redaction
        // sentinel so a refactor swapping to `finish()` (which would
        // produce a hard-error if a new non-Debug field is added)
        // fails here rather than losing the "fields exist but are not
        // shown" signal in operator logs.
        assert!(
            rendered.contains(".."),
            "finish_non_exhaustive sentinel `..` must be present, got: {rendered}"
        );

        // Callback pointer fields must NEVER appear — a silent swap to
        // `#[derive(Debug)]` would fail to compile today (the closures
        // aren't Debug) but a future wrapper around `Arc<dyn Fn>` that
        // did impl Debug (e.g. a newtype that printed its vtable)
        // would re-open the leak path.
        assert!(
            !rendered.contains("on_message"),
            "Debug must not name the on_message callback field, got: {rendered}"
        );
        assert!(
            !rendered.contains("replay_drain"),
            "Debug must not name the replay_drain callback field, got: {rendered}"
        );
        assert!(
            !rendered.contains("connector"),
            "Debug must not leak the connector internals, got: {rendered}"
        );
    }

    #[test]
    fn config_debug_renders_durations_in_debug_format() {
        // The heartbeat interval / timeout / reconnect delay must
        // appear in Debug form — a refactor that stringified them
        // via `Display` (without units) would produce ambiguous
        // "42" vs "42s" and break operator triage. Pin the Debug
        // rendering by looking for the unit token tokio / std prints.
        let cfg = build_config_for_debug();
        let rendered = format!("{cfg:?}");
        // Duration Debug renders as `42s`, `96s`, `7s`.
        assert!(
            rendered.contains("42s"),
            "heartbeat_interval duration must render in Debug, got: {rendered}"
        );
        assert!(
            rendered.contains("96s"),
            "heartbeat_timeout duration must render in Debug, got: {rendered}"
        );
        assert!(
            rendered.contains("7s"),
            "reconnect_delay duration must render in Debug, got: {rendered}"
        );
    }

    // ── `V1Client` Debug derive ─────────────────────────────────────

    #[tokio::test(flavor = "current_thread")]
    async fn v1_client_type_implements_debug() {
        fn assert_debug<T: fmt::Debug + ?Sized>() {}
        assert_debug::<V1Client>();

        // Also confirm a live instance formats without panicking. We
        // build the client with max_reconnects = 0 and an unreachable
        // address so the background loop exits promptly; the point is
        // to exercise the Debug derive on a real `Some(JoinHandle)` +
        // `Some(watch::Sender)` shape, not to drive the loop to
        // completion. We shut down before the outer timeout fires.
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
            id: "debug-instance-peer".into(),
            address: "127.0.0.1:19995".into(),
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
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
        };
        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});
        let mut client = V1Client::start(
            peer,
            V1ClientConfig {
                connector: OutboundConnector::Static(connector),
                addr: "127.0.0.1:19995".parse().expect("addr"),
                server_name: "localhost".into(),
                server_uid: "debug-instance-uid".into(),
                heartbeat_interval: Duration::from_secs(30),
                heartbeat_timeout: Duration::from_secs(90),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_message: on_msg,
                replay_drain: None,
            },
        );
        let rendered = format!("{client:?}");
        assert!(rendered.contains("V1Client"));
        client.shutdown().await;
    }

    // ── `V1ClientConfig` Send bound ─────────────────────────────────

    #[test]
    fn v1_client_config_is_send() {
        // The config is moved across an `await` into `tokio::spawn` in
        // `V1Client::start` — if any field ever became `!Send` (e.g. a
        // future `Rc` slipped in), the spawn would fail to compile at
        // every call site. Pin that bound locally.
        fn assert_send<T: Send>() {}
        assert_send::<V1ClientConfig>();
    }

    // ── `V1Client` is Send + Sync ───────────────────────────────────

    #[test]
    fn v1_client_is_send_and_sync() {
        // `V1Client` is owned by `FederationManager` on one task and
        // may be polled / shut down from another. Losing Send/Sync
        // would force a refactor of the manager's concurrency model.
        fn assert_bounds<T: Send + Sync>() {}
        assert_bounds::<V1Client>();
    }

    // ── Idempotent shutdown ─────────────────────────────────────────

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_is_idempotent_across_repeated_calls() {
        // The `Option::take` pattern on `task_handle` / `shutdown_tx`
        // must tolerate a second call — operators wire SIGTERM to
        // multiple shutdown paths (the subsystem drain, an atexit
        // hook, an explicit admin call) and a panic on re-entry would
        // crash the binary during the very sequence that's supposed
        // to drain cleanly.
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
            id: "idempotent-shutdown-peer".into(),
            address: "127.0.0.1:19994".into(),
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
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
        };
        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});
        let mut client = V1Client::start(
            peer,
            V1ClientConfig {
                connector: OutboundConnector::Static(connector),
                addr: "127.0.0.1:19994".parse().expect("addr"),
                server_name: "localhost".into(),
                server_uid: "idempotent-shutdown-uid".into(),
                heartbeat_interval: Duration::from_secs(30),
                heartbeat_timeout: Duration::from_secs(90),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_message: on_msg,
                replay_drain: None,
            },
        );

        client.shutdown().await;
        // Second shutdown MUST be a silent no-op — both Option::take
        // branches return None and nothing further happens.
        client.shutdown().await;
        // Third call for defence in depth.
        client.shutdown().await;
    }

    // ── Peer accessor agrees across repeated calls ──────────────────

    #[tokio::test(flavor = "current_thread")]
    async fn peer_accessor_returns_same_reference_across_calls() {
        // `V1Client::peer()` returns `&PeerHandle`; the field is
        // `Arc<PeerHandle>` and the accessor deref'ed. Two consecutive
        // calls must return references to the same underlying handle
        // (pointer equality via `std::ptr::eq` on the dereferenced
        // target) — a regression that accidentally wrapped each call
        // in `Arc::new` would break every cache / metric keyed on
        // handle identity.
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
            id: "peer-accessor-identity".into(),
            address: "127.0.0.1:19993".into(),
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
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
        };
        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});
        let mut client = V1Client::start(
            peer,
            V1ClientConfig {
                connector: OutboundConnector::Static(connector),
                addr: "127.0.0.1:19993".parse().expect("addr"),
                server_name: "localhost".into(),
                server_uid: "peer-accessor-uid".into(),
                heartbeat_interval: Duration::from_secs(30),
                heartbeat_timeout: Duration::from_secs(90),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_message: on_msg,
                replay_drain: None,
            },
        );
        let handle_a: &PeerHandle = client.peer();
        let handle_b: &PeerHandle = client.peer();
        assert!(
            std::ptr::eq(handle_a, handle_b),
            "peer() must return stable references to the same Arc target"
        );
        client.shutdown().await;
    }

    // ── `V1Client::send` after shutdown error path ──────────────────

    #[tokio::test(flavor = "current_thread")]
    async fn send_error_is_returned_with_documented_message() {
        // After `shutdown()`, the inner send channel is closed. The
        // existing `client_send_fails_after_shutdown` test asserts
        // `is_err()` but not the error content. Pin the documented
        // "V1 client send channel closed" message so an observer that
        // greps audit lines on send failures keeps working.
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
            id: "send-error-peer".into(),
            address: "127.0.0.1:19992".into(),
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
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
        };
        let peer = Arc::new(PeerHandle::new(peer_config));
        let on_msg: OnMessage = Arc::new(|_id, _data| {});
        let mut client = V1Client::start(
            Arc::clone(&peer),
            V1ClientConfig {
                connector: OutboundConnector::Static(connector),
                addr: "127.0.0.1:19992".parse().expect("addr"),
                server_name: "localhost".into(),
                server_uid: "send-error-uid".into(),
                heartbeat_interval: Duration::from_secs(30),
                heartbeat_timeout: Duration::from_secs(90),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_message: on_msg,
                replay_drain: None,
            },
        );
        client.shutdown().await;

        // Give the receiver a beat to be fully dropped.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Bound the send with a timeout so a regression that held the
        // sender side open fails loudly here instead of hanging CI.
        let fut = client.send(Bytes::from_static(b"post-shutdown"));
        let result = tokio::time::timeout(Duration::from_secs(2), fut)
            .await
            .expect("send must return promptly after shutdown, not hang");
        let err = result.expect_err("send after shutdown must return Err, not Ok");
        let msg = format!("{err}");
        assert!(
            msg.contains("V1 client send channel closed"),
            "error message must match the documented contract, got: {msg}"
        );
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
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
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
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
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
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
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
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
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
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
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
