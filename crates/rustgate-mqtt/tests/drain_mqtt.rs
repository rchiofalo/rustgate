// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Drain test for the MQTT transport adapter (F-133, refs #789).
//!
//! Pins the contract that [`MqttServer::run`] honours its shutdown
//! `Notify` and returns within the workspace's 5-second graceful drain
//! budget, even with active mTLS-authenticated sessions in flight.
//!
//! Mirrors the abstract `SubsystemHandle` drain test in
//! `rustgate-server/tests/shutdown_drains_subsystems.rs` (added by
//! #1270). That file pins the abstraction; this file pins the concrete
//! MQTT-listener wiring that `setup::start_mqtt_subsystem` consumes.
//!
//! The test:
//!
//! 1. Stands up an mTLS listener with [`MqttListener`] + [`MqttServer`].
//! 2. Connects 2-3 real MQTT clients over mTLS, completing CONNECT
//!    and reading CONNACK so each session is fully attached.
//! 3. Fires the shutdown `Notify`.
//! 4. Asserts the listener task joins inside the 5-second budget and
//!    that no message in the ConnAck path was silently dropped (each
//!    client received its CONNACK before drain).

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use rustgate_mqtt::{MqttListener, MqttServer, MqttServerConfig, WildcardPolicy};
use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::TlsConfig;
use rustgate_transport::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, Semaphore};

const DRAIN_BUDGET: Duration = Duration::from_secs(5);

async fn mqtt_connect(
    addr: std::net::SocketAddr,
    client_config: &rustls::ClientConfig,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config.clone()));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect")
}

async fn write_connect(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    client_id: &str,
) {
    let mut buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new(client_id);
    let _ = connect.write(&mut buf).expect("encode CONNECT");
    stream.write_all(&buf).await.expect("write CONNECT");
    stream.flush().await.expect("flush CONNECT");
}

async fn read_connack(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> mqttbytes::v5::ConnAck {
    let mut buf = BytesMut::new();
    loop {
        match mqttbytes::v5::read(&mut buf, 1024 * 1024) {
            Ok(mqttbytes::v5::Packet::ConnAck(connack)) => return connack,
            Ok(other) => panic!("expected ConnAck, got {other:?}"),
            Err(mqttbytes::Error::InsufficientBytes(_)) => {}
            Err(e) => panic!("CONNACK parse error: {e:?}"),
        }
        let n = stream.read_buf(&mut buf).await.expect("read");
        assert!(n > 0, "EOF before CONNACK");
    }
}

#[tokio::test]
async fn shutdown_drains_active_mqtt_sessions_within_budget() {
    let ca = TestCa::new("MQTT Drain CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener =
        MqttListener::bind("127.0.0.1:0".parse().unwrap(), &tls_config).expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let router = Arc::new(Router::new());
    let shutdown = Arc::new(Notify::new());

    let config = MqttServerConfig {
        listener,
        router,
        connection_limit: Arc::new(Semaphore::new(64)),
        shutdown: Arc::clone(&shutdown),
        topic_prefix: None,
        max_packet_size: 1024 * 1024,
        receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
        topic_alias_max: MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX,
        max_session_expiry_secs: MqttServerConfig::DEFAULT_MAX_SESSION_EXPIRY_SECS,
        max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
        min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
        server_keep_alive_secs: MqttServerConfig::DEFAULT_SERVER_KEEP_ALIVE_SECS,
        response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
        wildcard_policy: WildcardPolicy::default(),
        on_accept: None,
        on_reject: None,
        session_hooks: None,
        forwarding_hooks: None,
    };

    let server_handle = tokio::spawn(MqttServer::run(config));

    // Connect three real mTLS clients and drive each to a successful
    // CONNACK so the listener has 3 fully attached sessions when
    // shutdown fires.
    let mut streams = Vec::with_capacity(3);
    for (i, name) in ["alice", "bob", "carol"].iter().enumerate() {
        let cert = ca.issue_client_cert(name, &["alpha"]);
        let client_tls = build_client_tls_config(&cert.cert_pem, &cert.key_pem, &ca.cert_pem);
        let mut stream = mqtt_connect(addr, &client_tls).await;
        write_connect(&mut stream, &format!("drain-client-{i}")).await;
        let connack = read_connack(&mut stream).await;
        assert_eq!(
            connack.code,
            mqttbytes::v5::ConnectReturnCode::Success,
            "client {name} must receive successful CONNACK before shutdown"
        );
        streams.push(stream);
    }

    // Trigger shutdown — the accept loop must drop out of its select
    // arm and the spawned server task must return inside the budget.
    let started = std::time::Instant::now();
    shutdown.notify_one();
    tokio::time::timeout(DRAIN_BUDGET, server_handle)
        .await
        .expect("MQTT server must drain within the 5s budget")
        .expect("server task must not panic");
    let elapsed = started.elapsed();
    assert!(
        elapsed < DRAIN_BUDGET,
        "MQTT drain took longer than the 5s budget: {elapsed:?}"
    );

    // Drop the client streams — the OS will tear down the TLS
    // connections; per the drain contract the broker has already
    // acknowledged shutdown so any further client I/O is best-effort.
    drop(streams);
}

#[tokio::test]
async fn shutdown_drains_idle_mqtt_listener_within_budget() {
    // Strong-form pin: with no clients connected the accept loop must
    // still observe its shutdown notify. A regression that forgot to
    // wire the `select!` arm would leak the listener task and only
    // exit on socket teardown — this test would catch it via the
    // outer 5-second timeout.
    let ca = TestCa::new("MQTT Idle Drain CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener =
        MqttListener::bind("127.0.0.1:0".parse().unwrap(), &tls_config).expect("bind listener");
    let router = Arc::new(Router::new());
    let shutdown = Arc::new(Notify::new());

    let config = MqttServerConfig {
        listener,
        router,
        connection_limit: Arc::new(Semaphore::new(64)),
        shutdown: Arc::clone(&shutdown),
        topic_prefix: None,
        max_packet_size: 1024 * 1024,
        receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
        topic_alias_max: MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX,
        max_session_expiry_secs: MqttServerConfig::DEFAULT_MAX_SESSION_EXPIRY_SECS,
        max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
        min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
        server_keep_alive_secs: MqttServerConfig::DEFAULT_SERVER_KEEP_ALIVE_SECS,
        response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
        wildcard_policy: WildcardPolicy::default(),
        on_accept: None,
        on_reject: None,
        session_hooks: None,
        forwarding_hooks: None,
    };

    let server_handle = tokio::spawn(MqttServer::run(config));

    // Give the accept loop a moment to enter `select!`.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = std::time::Instant::now();
    shutdown.notify_one();
    tokio::time::timeout(DRAIN_BUDGET, server_handle)
        .await
        .expect("idle MQTT server must drain within the 5s budget")
        .expect("server task must not panic");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "idle MQTT drain should be near-instant, got {elapsed:?}"
    );
}
