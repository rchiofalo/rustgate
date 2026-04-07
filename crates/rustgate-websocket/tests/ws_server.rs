#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for WebSocket server session routing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::{SinkExt, StreamExt};
use rustgate_core::codec::Codec;
use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_transport::{Router, TakXmlCodec, ThrottleConfig, TlsConfig};
use rustgate_websocket::{WebSocketServer, WsListener, WsServerConfig};
use tokio::sync::{Notify, Semaphore};
use tokio_tungstenite::tungstenite::Message;

async fn ws_connect(
    addr: std::net::SocketAddr,
    tls_config: &rustls::ClientConfig,
) -> tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config.clone()));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");

    let (ws_stream, _) =
        tokio_tungstenite::client_async(format!("wss://localhost:{}", addr.port()), tls_stream)
            .await
            .expect("ws upgrade");

    ws_stream
}

/// Receive one WS frame with a timeout.
async fn recv_ws(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    >,
    label: &str,
) -> Vec<u8> {
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .unwrap_or_else(|_| panic!("{label}: timeout"))
        .unwrap_or_else(|| panic!("{label}: stream ended"))
        .unwrap_or_else(|e| panic!("{label}: frame error: {e}"));

    match frame {
        Message::Binary(data) => data.to_vec(),
        Message::Text(text) => text.as_bytes().to_vec(),
        other => panic!("{label}: unexpected frame type: {other:?}"),
    }
}

/// Assert no data frame arrives within the timeout window.
async fn assert_no_ws_message(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    >,
    label: &str,
) {
    match tokio::time::timeout(std::time::Duration::from_secs(1), ws.next()).await {
        Err(_) => {}                          // Timeout — nothing arrived
        Ok(None) => {}                        // Stream closed
        Ok(Some(Err(_))) => {}                // Read error
        Ok(Some(Ok(Message::Close(_)))) => {} // Close frame is fine
        Ok(Some(Ok(frame))) => {
            panic!("{label}: unexpected frame: {frame:?}");
        }
    }
}

/// Spin up a WebSocket server with the given codec and connection limit.
struct TestWsServer {
    addr: std::net::SocketAddr,
    router: Arc<Router>,
    shutdown: Arc<Notify>,
    ca: TestCa,
    _server_handle: tokio::task::JoinHandle<()>,
}

impl TestWsServer {
    async fn new(codec: Arc<dyn Codec>, max_connections: usize) -> Self {
        Self::with_throttle(codec, max_connections, None).await
    }

    async fn with_throttle(
        codec: Arc<dyn Codec>,
        max_connections: usize,
        throttle_config: Option<ThrottleConfig>,
    ) -> Self {
        let ca = TestCa::new("Test CA");
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

        let tls_config =
            TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
                .expect("tls config");

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let listener = WsListener::bind(addr, &tls_config).expect("bind");
        let bound_addr = listener.local_addr().expect("local addr");

        let router = Arc::new(Router::new());
        let shutdown = Arc::new(Notify::new());
        let connection_limit = Arc::new(Semaphore::new(max_connections));

        let config = WsServerConfig {
            listener,
            router: Arc::clone(&router),
            connection_limit,
            codec,
            nats_publish: None,
            fed_forward: None,
            throttle_config,
            replay_filter: None,
            circuit_breaker_threshold: 0,
            ws_max_frames_per_sec: 0,
            ws_max_bytes_per_sec: 0,
            ws_max_violations: 0,
            shutdown: Arc::clone(&shutdown),
        };

        let server_handle = tokio::spawn(WebSocketServer::run(config));

        // Give the server a moment to start accepting
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        Self {
            addr: bound_addr,
            router,
            shutdown,
            ca,
            _server_handle: server_handle,
        }
    }

    fn issue_client(&self, cn: &str, groups: &[&str]) -> rustgate_test_utils::certs::TestCert {
        self.ca.issue_client_cert(cn, groups)
    }

    async fn connect(
        &self,
        cert: &rustgate_test_utils::certs::TestCert,
    ) -> tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>
    {
        let tls_config = build_client_tls_config(&cert.cert_pem, &cert.key_pem, &self.ca.cert_pem);
        ws_connect(self.addr, &tls_config).await
    }

    /// Wait for sessions to register with the router.
    async fn wait_registered(&self, expected: usize) {
        for _ in 0..40 {
            if self.router.session_count().await >= expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!(
            "timed out waiting for {} sessions, got {}",
            expected,
            // This is a test helper — the panic is intentional for diagnostics
            self.router.session_count().await
        );
    }
}

impl Drop for TestWsServer {
    fn drop(&mut self) {
        self.shutdown.notify_one();
    }
}

// ── tests ────────────────────────────────────────────────────────────────

/// Two WebSocket clients in the same group can exchange messages through the router.
#[tokio::test]
async fn ws_session_routes_through_router() {
    let server = TestWsServer::new(Arc::new(TakXmlCodec), 64).await;
    let alice_cert = server.issue_client("alice", &["alpha"]);
    let bob_cert = server.issue_client("bob", &["alpha"]);

    let mut alice_ws = server.connect(&alice_cert).await;
    let mut bob_ws = server.connect(&bob_cert).await;
    server.wait_registered(2).await;

    // Alice sends a CoT position broadcast — bob should receive it
    let cot_xml = br#"<event uid="alice-pos" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><__group name="alpha"/></detail></event>"#;
    alice_ws
        .send(Message::Binary(cot_xml.to_vec().into()))
        .await
        .expect("alice send");

    let received = recv_ws(&mut bob_ws, "bob receives alice broadcast").await;
    assert_eq!(received, cot_xml.as_slice());
}

/// Sender must not receive their own broadcast back.
#[tokio::test]
async fn ws_no_self_echo() {
    let server = TestWsServer::new(Arc::new(TakXmlCodec), 64).await;
    let alice_cert = server.issue_client("alice", &["alpha"]);

    let mut alice_ws = server.connect(&alice_cert).await;
    server.wait_registered(1).await;

    let cot_xml = br#"<event uid="alice-pos" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><__group name="alpha"/></detail></event>"#;
    alice_ws
        .send(Message::Binary(cot_xml.to_vec().into()))
        .await
        .expect("alice send");

    assert_no_ws_message(&mut alice_ws, "alice self-echo").await;
}

/// Clients in different groups must not receive each other's messages.
#[tokio::test]
async fn ws_cross_group_isolation() {
    let server = TestWsServer::new(Arc::new(TakXmlCodec), 64).await;
    let alice_cert = server.issue_client("alice", &["alpha"]);
    let bob_cert = server.issue_client("bob", &["alpha"]);
    let charlie_cert = server.issue_client("charlie", &["bravo"]);

    let mut alice_ws = server.connect(&alice_cert).await;
    let mut bob_ws = server.connect(&bob_cert).await;
    let mut charlie_ws = server.connect(&charlie_cert).await;
    server.wait_registered(3).await;

    // Alice sends a group-targeted message — bob should receive, charlie should not.
    // The <dest group="alpha"/> element makes MessageBuilder produce Destination::Group("alpha").
    let cot_xml = br#"<event uid="alpha-msg" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><__group name="alpha"/><dest group="alpha"/></detail></event>"#;
    alice_ws
        .send(Message::Binary(cot_xml.to_vec().into()))
        .await
        .expect("alice send");

    // Bob is in alpha — should receive
    let received = recv_ws(&mut bob_ws, "bob receives alpha msg").await;
    assert_eq!(received, cot_xml.as_slice());

    // Charlie is in bravo — should not receive
    assert_no_ws_message(&mut charlie_ws, "charlie cross-group").await;
}

/// Disconnecting a WebSocket client removes the session from the router.
#[tokio::test]
async fn ws_disconnect_cleanup() {
    let server = TestWsServer::new(Arc::new(TakXmlCodec), 64).await;
    let alice_cert = server.issue_client("alice", &["ops"]);
    let bob_cert = server.issue_client("bob", &["ops"]);
    let charlie_cert = server.issue_client("charlie", &["ops"]);

    let alice_ws = server.connect(&alice_cert).await;
    let mut bob_ws = server.connect(&bob_cert).await;
    let mut charlie_ws = server.connect(&charlie_cert).await;
    server.wait_registered(3).await;

    assert_eq!(server.router.session_count().await, 3);

    // Alice disconnects
    drop(alice_ws);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(server.router.session_count().await, 2);

    // Bob sends — charlie still receives, alice is gone
    let cot_xml = br#"<event uid="bob-msg" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><__group name="ops"/></detail></event>"#;
    bob_ws
        .send(Message::Binary(cot_xml.to_vec().into()))
        .await
        .expect("bob send");

    let received = recv_ws(&mut charlie_ws, "charlie after alice disconnect").await;
    assert_eq!(received, cot_xml.as_slice());
}

/// Text WebSocket frames are handled alongside binary frames.
#[tokio::test]
async fn ws_text_frame_routes() {
    let server = TestWsServer::new(Arc::new(TakXmlCodec), 64).await;
    let alice_cert = server.issue_client("alice", &["alpha"]);
    let bob_cert = server.issue_client("bob", &["alpha"]);

    let mut alice_ws = server.connect(&alice_cert).await;
    let mut bob_ws = server.connect(&bob_cert).await;
    server.wait_registered(2).await;

    // Alice sends CoT as a Text frame (some WS clients do this)
    let cot_xml = r#"<event uid="text-msg" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><__group name="alpha"/></detail></event>"#;
    alice_ws
        .send(Message::Text(cot_xml.into()))
        .await
        .expect("alice send text");

    // Bob should receive it (encoded as Binary by the write loop)
    let received = recv_ws(&mut bob_ws, "bob receives text-originated msg").await;
    assert_eq!(received, cot_xml.as_bytes());
}

/// WebSocket Close frame causes clean session teardown.
#[tokio::test]
async fn ws_close_frame_cleanup() {
    let server = TestWsServer::new(Arc::new(TakXmlCodec), 64).await;
    let alice_cert = server.issue_client("alice", &["ops"]);

    let mut alice_ws = server.connect(&alice_cert).await;
    server.wait_registered(1).await;

    assert_eq!(server.router.session_count().await, 1);

    // Send a Close frame
    alice_ws
        .send(Message::Close(None))
        .await
        .expect("alice close");

    // Drain any close response from the server
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), alice_ws.next()).await;

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(server.router.session_count().await, 0);
}

/// Connection limit is enforced — second connection is rejected when
/// semaphore permits are exhausted.
#[tokio::test]
async fn ws_server_enforces_connection_limit() {
    let server = TestWsServer::new(Arc::new(TakXmlCodec), 1).await;
    let user1_cert = server.issue_client("user1", &["ops"]);
    let user2_cert = server.issue_client("user2", &["ops"]);

    // First connection should succeed
    let _ws1 = server.connect(&user1_cert).await;
    server.wait_registered(1).await;

    assert_eq!(server.router.session_count().await, 1);

    // Second connection: the TLS+WS handshake may succeed (happens before
    // the semaphore check), but the session must never register with the router.
    let _ws2 = server.connect(&user2_cert).await;

    // Give the server time to process (or reject)
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Router should still have only 1 session — the second was rejected
    assert_eq!(
        server.router.session_count().await,
        1,
        "second connection should be rejected by connection limit"
    );
}

/// Late-joining client receives cached position from an earlier participant.
#[tokio::test]
async fn ws_position_cache_replay() {
    let server = TestWsServer::new(Arc::new(TakXmlCodec), 64).await;
    let alice_cert = server.issue_client("alice", &["alpha"]);
    let bob_cert = server.issue_client("bob", &["alpha"]);

    // Alice connects and sends a position
    let mut alice_ws = server.connect(&alice_cert).await;
    server.wait_registered(1).await;

    let cot_position = br#"<event uid="alice-pos" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="15.0"/><detail><__group name="alpha"/></detail></event>"#;
    alice_ws
        .send(Message::Binary(cot_position.to_vec().into()))
        .await
        .expect("alice position");

    // Wait for the position to be routed and cached
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Bob connects later — should receive alice's cached position
    let mut bob_ws = server.connect(&bob_cert).await;

    let replayed = recv_ws(&mut bob_ws, "bob receives cached position").await;
    assert_eq!(replayed, cot_position.as_slice());
}

/// Codec encoding produces the same output for CoT-sourced messages.
#[tokio::test]
async fn ws_codec_encoding() {
    let server = TestWsServer::new(Arc::new(TakXmlCodec), 64).await;
    let alice_cert = server.issue_client("alice", &["alpha"]);
    let bob_cert = server.issue_client("bob", &["alpha"]);

    let mut alice_ws = server.connect(&alice_cert).await;
    let mut bob_ws = server.connect(&bob_cert).await;
    server.wait_registered(2).await;

    let cot_xml = br#"<event uid="cot-enc" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><__group name="alpha"/></detail></event>"#;
    alice_ws
        .send(Message::Binary(cot_xml.to_vec().into()))
        .await
        .expect("alice send");

    let received = recv_ws(&mut bob_ws, "bob receives cot-encoded msg").await;
    assert_eq!(received, cot_xml.as_slice());
}

/// NATS publish and federation forward callbacks fire for each routed message.
#[tokio::test]
async fn ws_nats_and_federation_callbacks_fire() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let listener = WsListener::bind(addr, &tls_config).expect("bind");
    let bound_addr = listener.local_addr().expect("local addr");

    let router = Arc::new(Router::new());
    let shutdown = Arc::new(Notify::new());

    let nats_count = Arc::new(AtomicUsize::new(0));
    let fed_count = Arc::new(AtomicUsize::new(0));

    let nats_counter = Arc::clone(&nats_count);
    let nats_publish: rustgate_websocket::OnNatsPublish = Arc::new(move |_msg| {
        let _ = nats_counter.fetch_add(1, Ordering::Relaxed);
    });

    let fed_counter = Arc::clone(&fed_count);
    let fed_forward: rustgate_websocket::OnFederationForward =
        Arc::new(move |_payload, _groups, _meta| {
            let _ = fed_counter.fetch_add(1, Ordering::Relaxed);
        });

    let config = WsServerConfig {
        listener,
        router: Arc::clone(&router),
        connection_limit: Arc::new(Semaphore::new(64)),
        codec: Arc::new(TakXmlCodec),
        nats_publish: Some(nats_publish),
        fed_forward: Some(fed_forward),
        throttle_config: None,
        replay_filter: None,
        circuit_breaker_threshold: 0,
        ws_max_frames_per_sec: 0,
        ws_max_bytes_per_sec: 0,
        ws_max_violations: 0,
        shutdown: Arc::clone(&shutdown),
    };

    let _server_handle = tokio::spawn(WebSocketServer::run(config));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);

    let client_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let mut alice_ws = ws_connect(bound_addr, &client_tls).await;

    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob_ws = ws_connect(bound_addr, &bob_tls).await;

    // Wait for both sessions to register
    for _ in 0..40 {
        if router.session_count().await >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Alice sends two messages
    let msg1 = br#"<event uid="msg-1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><__group name="alpha"/></detail></event>"#;
    let msg2 = br#"<event uid="msg-2" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="39.0" lon="-76.0" hae="0.0"/><detail><__group name="alpha"/></detail></event>"#;

    alice_ws
        .send(Message::Binary(msg1.to_vec().into()))
        .await
        .expect("send 1");
    alice_ws
        .send(Message::Binary(msg2.to_vec().into()))
        .await
        .expect("send 2");

    // Bob receives both (confirms routing worked)
    let _ = recv_ws(&mut bob_ws, "bob msg 1").await;
    let _ = recv_ws(&mut bob_ws, "bob msg 2").await;

    // Allow callbacks to complete
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert_eq!(
        nats_count.load(Ordering::Relaxed),
        2,
        "NATS callback should fire for each message"
    );
    assert_eq!(
        fed_count.load(Ordering::Relaxed),
        2,
        "federation callback should fire for each message"
    );

    shutdown.notify_one();
}

/// Messages exceeding the per-connection rate limit are dropped.
#[tokio::test]
async fn ws_rate_limit_drops_excess_messages() {
    // burst=2 means only the first 2 messages pass immediately; the rest are dropped.
    let server =
        TestWsServer::with_throttle(Arc::new(TakXmlCodec), 64, Some(ThrottleConfig::new(1, 2)))
            .await;
    let alice_cert = server.issue_client("alice", &["alpha"]);
    let bob_cert = server.issue_client("bob", &["alpha"]);

    let mut alice_ws = server.connect(&alice_cert).await;
    let mut bob_ws = server.connect(&bob_cert).await;
    server.wait_registered(2).await;

    // Send 5 messages rapidly — only first 2 should pass (burst=2)
    for i in 0..5 {
        let cot_xml = format!(
            r#"<event uid="msg-{i}" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><__group name="alpha"/></detail></event>"#
        );
        alice_ws
            .send(Message::Binary(cot_xml.into_bytes().into()))
            .await
            .expect("alice send");
    }

    // Bob should receive at most 2 messages (the burst allowance)
    let mut received_count = 0usize;
    for _ in 0..5 {
        match tokio::time::timeout(std::time::Duration::from_secs(1), bob_ws.next()).await {
            Ok(Some(Ok(Message::Binary(_) | Message::Text(_)))) => received_count += 1,
            _ => break,
        }
    }

    assert!(
        received_count <= 2,
        "expected at most 2 messages through rate limit, got {received_count}"
    );
    assert!(
        received_count >= 1,
        "expected at least 1 message through rate limit, got {received_count}"
    );
}

/// Rate limiting is disabled when throttle config is None (msg_rate=0).
#[tokio::test]
async fn ws_rate_limit_disabled_when_none() {
    let server = TestWsServer::with_throttle(Arc::new(TakXmlCodec), 64, None).await;
    let alice_cert = server.issue_client("alice", &["alpha"]);
    let bob_cert = server.issue_client("bob", &["alpha"]);

    let mut alice_ws = server.connect(&alice_cert).await;
    let mut bob_ws = server.connect(&bob_cert).await;
    server.wait_registered(2).await;

    // Send 10 messages — all should pass when rate limiting is disabled
    for i in 0..10 {
        let cot_xml = format!(
            r#"<event uid="msg-{i}" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><__group name="alpha"/></detail></event>"#
        );
        alice_ws
            .send(Message::Binary(cot_xml.into_bytes().into()))
            .await
            .expect("alice send");
    }

    let mut received_count = 0usize;
    for _ in 0..10 {
        match tokio::time::timeout(std::time::Duration::from_secs(2), bob_ws.next()).await {
            Ok(Some(Ok(Message::Binary(_) | Message::Text(_)))) => received_count += 1,
            _ => break,
        }
    }

    assert_eq!(
        received_count, 10,
        "all messages should pass when rate limiting is disabled"
    );
}
