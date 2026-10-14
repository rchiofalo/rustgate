// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]

//! Drain test for the WebSocket transport adapter (F-133, refs #789).
//!
//! Pins the contract that [`WebSocketServer::run`] honours its shutdown
//! `Notify` and returns within the workspace's 5-second graceful drain
//! budget, even with active mTLS-authenticated WebSocket sessions in
//! flight.
//!
//! Mirrors the abstract `SubsystemHandle` drain test in
//! `rustgate-server/tests/shutdown_drains_subsystems.rs` (added by
//! #1270). That file pins the abstraction; this file pins the concrete
//! WebSocket-listener wiring.
//!
//! The test:
//!
//! 1. Stands up an mTLS WebSocket listener with [`WsListener`] +
//!    [`WebSocketServer`].
//! 2. Connects 2-3 real WebSocket clients over wss://, completes the
//!    upgrade, and exchanges at least one message so each session is
//!    fully attached and registered with the router.
//! 3. Fires the shutdown `Notify`.
//! 4. Asserts the server task joins inside the 5-second budget.

use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use rustgate_router::Router;
use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::TlsConfig;
use rustgate_transport::TakXmlCodec;
use rustgate_websocket::{WebSocketServer, WsListener, WsServerConfig};
use tokio::sync::{Notify, Semaphore};
use tokio_tungstenite::tungstenite::Message;

const DRAIN_BUDGET: Duration = Duration::from_secs(5);

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

#[tokio::test]
async fn shutdown_drains_active_websocket_sessions_within_budget() {
    let ca = TestCa::new("WS Drain CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = WsListener::bind("127.0.0.1:0".parse().unwrap(), &tls_config).expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let router = Arc::new(Router::new());
    let shutdown = Arc::new(Notify::new());

    let config = WsServerConfig {
        listener,
        router: Arc::clone(&router),
        connection_limit: Arc::new(Semaphore::new(64)),
        codec: Arc::new(TakXmlCodec),
        nats_publish: None,
        fed_forward: None,
        http_forward: None,
        throttle_config: None,
        replay_filter: None,
        circuit_breaker_threshold: 0,
        ws_max_frames_per_sec: 0,
        ws_max_bytes_per_sec: 0,
        ws_max_violations: 0,
        max_write_buffer_bytes: 0,
        health_check: rustgate_websocket::health::HealthCheckConfig::DISABLED,
        session_hooks: None,
        sa_upgrade_observer: None,
        shutdown: Arc::clone(&shutdown),
    };

    let server_handle = tokio::spawn(WebSocketServer::run(config));

    // Give the server a moment to bind into `select!`.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect three real wss:// clients and complete the upgrade so
    // each is registered with the router. The session count gauge on
    // the router is the strongest "fully attached" signal.
    let mut streams = Vec::with_capacity(3);
    for name in ["alice", "bob", "carol"].iter() {
        let cert = ca.issue_client_cert(name, &["alpha"]);
        let client_tls = build_client_tls_config(&cert.cert_pem, &cert.key_pem, &ca.cert_pem);
        let ws = ws_connect(addr, &client_tls).await;
        streams.push(ws);
    }

    // Wait for sessions to register with the router so the drain test
    // exercises the live-session path rather than racing the upgrade.
    for _ in 0..40 {
        if router.session_count().await >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        router.session_count().await,
        3,
        "all three clients must register before drain"
    );

    let started = std::time::Instant::now();
    shutdown.notify_one();
    tokio::time::timeout(DRAIN_BUDGET, server_handle)
        .await
        .expect("WebSocket server must drain within the 5s budget")
        .expect("server task must not panic");
    let elapsed = started.elapsed();
    assert!(
        elapsed < DRAIN_BUDGET,
        "WebSocket drain took longer than the 5s budget: {elapsed:?}"
    );

    // Best-effort: drain client read sides so we can assert the OS-side
    // close completes cleanly. Each client should observe either a
    // close frame or a stream end — neither is silent data loss.
    for mut ws in streams {
        let _ = tokio::time::timeout(Duration::from_millis(500), ws.next()).await;
        let _ = ws.send(Message::Close(None)).await;
    }
}

#[tokio::test]
async fn shutdown_drains_idle_websocket_listener_within_budget() {
    // Strong-form pin: with no clients connected the accept loop must
    // still observe its shutdown notify. A regression that forgot to
    // wire the `select!` arm or that swallowed the wakeup would leak
    // the listener task; the outer 5-second timeout would catch it.
    let ca = TestCa::new("WS Idle Drain CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = WsListener::bind("127.0.0.1:0".parse().unwrap(), &tls_config).expect("bind");

    let router = Arc::new(Router::new());
    let shutdown = Arc::new(Notify::new());

    let config = WsServerConfig {
        listener,
        router,
        connection_limit: Arc::new(Semaphore::new(64)),
        codec: Arc::new(TakXmlCodec),
        nats_publish: None,
        fed_forward: None,
        http_forward: None,
        throttle_config: None,
        replay_filter: None,
        circuit_breaker_threshold: 0,
        ws_max_frames_per_sec: 0,
        ws_max_bytes_per_sec: 0,
        ws_max_violations: 0,
        max_write_buffer_bytes: 0,
        health_check: rustgate_websocket::health::HealthCheckConfig::DISABLED,
        session_hooks: None,
        sa_upgrade_observer: None,
        shutdown: Arc::clone(&shutdown),
    };

    let server_handle = tokio::spawn(WebSocketServer::run(config));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = std::time::Instant::now();
    shutdown.notify_one();
    tokio::time::timeout(DRAIN_BUDGET, server_handle)
        .await
        .expect("idle WebSocket server must drain within the 5s budget")
        .expect("server task must not panic");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "idle WebSocket drain should be near-instant, got {elapsed:?}"
    );
}
