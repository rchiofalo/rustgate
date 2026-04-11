// Copyright © 2026 Roberto Chiofalo.

//! V1 federation inbound server.
//!
//! Accepts mTLS connections from remote federation peers and runs
//! per-connection read/write loops with heartbeat detection.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustgate_core::protocol::HeaderSize;
use rustgate_transport::{LengthPrefixedCodec, TlsConfig, TlsListener};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use crate::heartbeat::{create_heartbeat, is_heartbeat};

/// Callback invoked for each non-heartbeat message received from a federation peer.
///
/// Arguments: (peer_cn, payload_bytes)
pub type OnMessage = Arc<dyn Fn(String, Bytes) + Send + Sync>;

/// V1 federation server that accepts inbound peer connections.
///
/// Each accepted connection gets its own read loop that decodes
/// length-prefixed XML frames, detects heartbeats, and forwards
/// other messages via the provided callback.
#[derive(Debug)]
pub struct V1Server {
    listener_handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl V1Server {
    /// Start the V1 federation server on the given address.
    ///
    /// Returns immediately after spawning the accept loop. The server
    /// runs in the background until `shutdown()` is called.
    pub async fn start(
        listen_addr: std::net::SocketAddr,
        tls_config: &TlsConfig,
        server_uid: String,
        heartbeat_interval: Duration,
        heartbeat_timeout: Duration,
        on_message: OnMessage,
        max_message_size: Option<usize>,
    ) -> anyhow::Result<Self> {
        let listener = TlsListener::bind(listen_addr, tls_config).await?;
        Self::start_with_listener(
            listener,
            server_uid,
            heartbeat_interval,
            heartbeat_timeout,
            on_message,
            max_message_size,
        )
    }

    /// Start the V1 federation server with a pre-built `TlsListener`.
    ///
    /// Use this when you need custom TLS configuration, such as a
    /// `DynamicCertVerifier` for runtime trust store changes.
    pub fn start_with_listener(
        listener: TlsListener,
        server_uid: String,
        heartbeat_interval: Duration,
        heartbeat_timeout: Duration,
        on_message: OnMessage,
        max_message_size: Option<usize>,
    ) -> anyhow::Result<Self> {
        let local_addr = listener.local_addr()?;
        info!(addr = %local_addr, "V1 federation server listening");

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = tokio::spawn(accept_loop(
            listener,
            server_uid,
            heartbeat_interval,
            heartbeat_timeout,
            on_message,
            shutdown_rx,
            max_message_size,
        ));

        Ok(Self {
            listener_handle: Some(handle),
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Gracefully shut down the server and all active connections.
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.listener_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

/// Main accept loop — runs until shutdown signal.
async fn accept_loop(
    listener: TlsListener,
    server_uid: String,
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
    on_message: OnMessage,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    max_message_size: Option<usize>,
) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                info!("V1 federation server shutting down");
                return;
            }
            result = listener.accept() => {
                match result {
                    Ok(session) => {
                        let peer_cn = session.identity().cn.clone();
                        let peer_addr = session.peer_addr();
                        info!(
                            peer_cn = %peer_cn,
                            peer_addr = %peer_addr,
                            "V1 federation peer connected (inbound)"
                        );

                        let on_msg = Arc::clone(&on_message);
                        let uid = server_uid.clone();
                        drop(tokio::spawn(handle_inbound_peer(
                            session,
                            uid,
                            heartbeat_interval,
                            heartbeat_timeout,
                            on_msg,
                            max_message_size,
                        )));
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to accept V1 federation connection");
                    }
                }
            }
        }
    }
}

/// Handle a single inbound V1 federation peer connection.
///
/// Runs a read loop that decodes length-prefixed XML frames and a
/// heartbeat sender that sends CoT heartbeats at the configured interval.
async fn handle_inbound_peer(
    session: rustgate_transport::AuthenticatedSession,
    server_uid: String,
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
    on_message: OnMessage,
    max_message_size: Option<usize>,
) {
    use futures::{SinkExt, StreamExt};

    let peer_cn = session.identity().cn.clone();
    let peer_addr = session.peer_addr();

    let mut codec = LengthPrefixedCodec::new(HeaderSize::Four);
    if let Some(max_size) = max_message_size {
        codec = codec.with_max_frame_size(max_size);
    }
    let mut framed = Framed::new(session, codec);

    // Channel for sending messages to the write side
    let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(64);

    // Spawn heartbeat sender
    let hb_write_tx = write_tx.clone();
    let hb_uid = server_uid.clone();
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(heartbeat_interval);
        let _ = interval.tick().await; // skip immediate first tick
        loop {
            let _ = interval.tick().await;
            let hb = create_heartbeat(&hb_uid);
            if hb_write_tx.send(hb).await.is_err() {
                break;
            }
        }
    });

    // Track last heartbeat received from peer (no separate task needed)
    let mut last_heartbeat_received = tokio::time::Instant::now();
    let mut heartbeat_check_interval = tokio::time::interval(Duration::from_secs(5));
    let _ = heartbeat_check_interval.tick().await; // skip immediate first tick

    // Main I/O loop: interleave reads, writes, and heartbeat checks
    let read_cn = peer_cn.clone();
    let io_result: anyhow::Result<()> = async {
        loop {
            tokio::select! {
                // Read from peer
                frame = framed.next() => {
                    match frame {
                        Some(Ok(data)) => {
                            if is_heartbeat(&data) {
                                debug!(peer_cn = %read_cn, "V1 heartbeat received");
                                last_heartbeat_received = tokio::time::Instant::now();
                            } else {
                                on_message(read_cn.clone(), data.freeze());
                            }
                        }
                        Some(Err(e)) => {
                            return Err(anyhow::anyhow!("read error: {e}"));
                        }
                        None => {
                            return Ok(()); // clean disconnect
                        }
                    }
                }
                // Write queued messages (heartbeats and forwarded messages)
                msg = write_rx.recv() => {
                    match msg {
                        Some(data) => {
                            let buf = BytesMut::from(data.as_ref());
                            if let Err(e) = framed.send(buf).await {
                                return Err(anyhow::anyhow!("write error: {e}"));
                            }
                        }
                        None => {
                            return Ok(()); // channel closed
                        }
                    }
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
            }
        }
    }
    .await;

    heartbeat_handle.abort();

    match io_result {
        Ok(()) => {
            info!(
                peer_cn = %peer_cn,
                peer_addr = %peer_addr,
                "V1 federation peer disconnected cleanly"
            );
        }
        Err(e) => {
            warn!(
                peer_cn = %peer_cn,
                peer_addr = %peer_addr,
                error = %e,
                "V1 federation peer disconnected with error"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use rustgate_test_utils::certs::TestCa;

    use super::*;

    /// Helper: build TlsConfig from test CA and server cert
    fn test_tls_config(ca: &TestCa) -> TlsConfig {
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
        TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
            .expect("tls config")
    }

    #[tokio::test]
    async fn server_starts_and_shuts_down() {
        let ca = TestCa::new("Test CA");
        let tls_config = test_tls_config(&ca);

        let on_msg: OnMessage = Arc::new(|_cn, _data| {});
        let mut server = V1Server::start(
            "127.0.0.1:0".parse().expect("addr"),
            &tls_config,
            "test-server".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            on_msg,
            None,
        )
        .await
        .expect("start server");

        server.shutdown().await;
    }

    #[tokio::test]
    async fn server_starts_with_callback() {
        let ca = TestCa::new("Test CA");
        let tls_config = test_tls_config(&ca);

        let (msg_tx, mut msg_rx) = mpsc::channel::<(String, Bytes)>(16);
        let on_msg: OnMessage = Arc::new(move |cn, data| {
            let _ = msg_tx.try_send((cn, data));
        });

        let mut server = V1Server::start(
            "127.0.0.1:0".parse().expect("addr"),
            &tls_config,
            "test-server".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            on_msg,
            None,
        )
        .await
        .expect("start server");

        // No messages should arrive without any connections
        assert!(msg_rx.try_recv().is_err());

        server.shutdown().await;
    }

    #[tokio::test]
    async fn server_double_shutdown_is_safe() {
        let ca = TestCa::new("Test CA");
        let tls_config = test_tls_config(&ca);

        let on_msg: OnMessage = Arc::new(|_cn, _data| {});
        let mut server = V1Server::start(
            "127.0.0.1:0".parse().expect("addr"),
            &tls_config,
            "test-server".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            on_msg,
            None,
        )
        .await
        .expect("start server");

        server.shutdown().await;
        server.shutdown().await; // should not panic
    }

    #[tokio::test]
    async fn server_triple_shutdown_is_safe() {
        let ca = TestCa::new("Test CA");
        let tls_config = test_tls_config(&ca);

        let on_msg: OnMessage = Arc::new(|_cn, _data| {});
        let mut server = V1Server::start(
            "127.0.0.1:0".parse().expect("addr"),
            &tls_config,
            "test-server".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            on_msg,
            None,
        )
        .await
        .expect("start server");

        server.shutdown().await;
        server.shutdown().await;
        server.shutdown().await; // should not panic
    }

    #[tokio::test]
    async fn server_with_short_heartbeat_interval() {
        let ca = TestCa::new("Test CA");
        let tls_config = test_tls_config(&ca);

        let on_msg: OnMessage = Arc::new(|_cn, _data| {});
        let mut server = V1Server::start(
            "127.0.0.1:0".parse().expect("addr"),
            &tls_config,
            "test-server".into(),
            Duration::from_millis(100),
            Duration::from_millis(500),
            on_msg,
            None,
        )
        .await
        .expect("start server");

        // Let it run briefly with short intervals
        tokio::time::sleep(Duration::from_millis(200)).await;

        server.shutdown().await;
    }

    #[tokio::test]
    async fn server_with_custom_uid() {
        let ca = TestCa::new("Test CA");
        let tls_config = test_tls_config(&ca);

        let on_msg: OnMessage = Arc::new(|_cn, _data| {});
        let mut server = V1Server::start(
            "127.0.0.1:0".parse().expect("addr"),
            &tls_config,
            "custom-federation-server-uid-12345".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            on_msg,
            None,
        )
        .await
        .expect("start server");

        server.shutdown().await;
    }

    #[tokio::test]
    async fn multiple_servers_on_different_ports() {
        let ca = TestCa::new("Test CA");
        let tls_config = test_tls_config(&ca);

        let on_msg1: OnMessage = Arc::new(|_cn, _data| {});
        let on_msg2: OnMessage = Arc::new(|_cn, _data| {});

        let mut server1 = V1Server::start(
            "127.0.0.1:0".parse().expect("addr"),
            &tls_config,
            "server-1".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            on_msg1,
            None,
        )
        .await
        .expect("start server 1");

        let mut server2 = V1Server::start(
            "127.0.0.1:0".parse().expect("addr"),
            &tls_config,
            "server-2".into(),
            Duration::from_secs(30),
            Duration::from_secs(90),
            on_msg2,
            None,
        )
        .await
        .expect("start server 2");

        server1.shutdown().await;
        server2.shutdown().await;
    }

    #[tokio::test]
    async fn server_on_message_callback_is_arc() {
        // Verify on_message callback can be shared across invocations
        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter_clone = Arc::clone(&counter);
        let on_msg: OnMessage = Arc::new(move |_cn, _data| {
            let _ = counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });

        // Clone should share the same counter
        let on_msg2 = Arc::clone(&on_msg);

        // Call both; they should both increment the same counter
        on_msg("peer1".into(), Bytes::from("data1"));
        on_msg2("peer2".into(), Bytes::from("data2"));

        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 2);
    }
}
