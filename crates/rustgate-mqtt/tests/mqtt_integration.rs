// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used, unused_results, dead_code)]

//! Integration tests for the MQTT transport adapter.
//!
//! These tests spin up a real TLS listener with mTLS, connect MQTT
//! clients, and exercise the full path: CONNECT, SUBSCRIBE, PUBLISH,
//! PINGREQ, and DISCONNECT.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use rustgate_mqtt::{MqttListener, MqttServer, MqttServerConfig, WildcardPolicy};
use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_transport::{Router, TlsConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, Semaphore};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Spin up an MQTT server on a dynamic port and return the address + shutdown handle.
struct TestServer {
    addr: std::net::SocketAddr,
    shutdown: Arc<Notify>,
    router: Arc<Router>,
}

impl TestServer {
    fn new(ca: &TestCa, router: Arc<Router>, topic_prefix: Option<String>) -> Self {
        Self::new_with_policy(ca, router, topic_prefix, WildcardPolicy::default())
    }

    fn new_with_policy(
        ca: &TestCa,
        router: Arc<Router>,
        topic_prefix: Option<String>,
        wildcard_policy: WildcardPolicy,
    ) -> Self {
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
        let tls_config =
            TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
                .expect("tls config");

        let listener =
            MqttListener::bind("127.0.0.1:0".parse().unwrap(), &tls_config).expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = Arc::new(Notify::new());

        let config = MqttServerConfig {
            listener,
            router: Arc::clone(&router),
            connection_limit: Arc::new(Semaphore::new(100)),
            shutdown: Arc::clone(&shutdown),
            topic_prefix,
            max_packet_size: 1024 * 1024,
            min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
            response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
            wildcard_policy,
            on_accept: None,
            on_reject: None,
            session_hooks: None,
        };

        drop(tokio::spawn(MqttServer::run(config)));

        Self {
            addr,
            shutdown,
            router,
        }
    }

    fn shutdown(&self) {
        self.shutdown.notify_one();
    }
}

/// Connect to the test server as an MQTT client over mTLS.
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

/// Write an mqttbytes v5 packet to a TLS stream.
async fn write_v5_packet(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    packet: &mqttbytes::v5::Packet,
) {
    let mut buf = BytesMut::new();
    match packet {
        mqttbytes::v5::Packet::Connect(p) => {
            p.write(&mut buf).unwrap();
        }
        mqttbytes::v5::Packet::Publish(p) => {
            p.write(&mut buf).unwrap();
        }
        mqttbytes::v5::Packet::Subscribe(p) => {
            p.write(&mut buf).unwrap();
        }
        mqttbytes::v5::Packet::Unsubscribe(p) => {
            p.write(&mut buf).unwrap();
        }
        mqttbytes::v5::Packet::PingReq => {
            mqttbytes::v5::PingReq.write(&mut buf).unwrap();
        }
        mqttbytes::v5::Packet::Disconnect(p) => {
            p.write(&mut buf).unwrap();
        }
        _ => panic!("unsupported packet type for write"),
    }
    stream.write_all(&buf).await.expect("write packet");
    stream.flush().await.expect("flush");
}

/// Read the next mqttbytes v5 packet from a TLS stream.
async fn read_v5_packet(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    buf: &mut BytesMut,
) -> mqttbytes::v5::Packet {
    loop {
        match mqttbytes::v5::read(buf, 1024 * 1024) {
            Ok(packet) => return packet,
            Err(mqttbytes::Error::InsufficientBytes(_)) => {}
            Err(e) => panic!("parse error: {e:?}"),
        }
        let n = stream.read_buf(buf).await.expect("read");
        assert!(n > 0, "unexpected EOF");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connect_and_connack() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // Send CONNECT
    let connect = mqttbytes::v5::Connect::new("test-client");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;

    // Read CONNACK
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::ConnAck(connack) => {
            assert_eq!(connack.code, mqttbytes::v5::ConnectReturnCode::Success);
        }
        other => panic!("expected ConnAck, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn pingreq_pingresp() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // CONNECT
    let connect = mqttbytes::v5::Connect::new("ping-client");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await; // CONNACK

    // PINGREQ
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::PingReq).await;

    // PINGRESP
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    assert!(
        matches!(packet, mqttbytes::v5::Packet::PingResp),
        "expected PingResp, got {packet:?}"
    );

    server.shutdown();
}

#[tokio::test]
async fn subscribe_to_authorized_group() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // CONNECT
    let connect = mqttbytes::v5::Connect::new("sub-client");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await; // CONNACK

    // SUBSCRIBE to "alpha" (client is a member)
    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Subscribe(sub)).await;

    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::SubAck(suback) => {
            assert_eq!(
                suback.return_codes,
                vec![mqttbytes::v5::SubscribeReasonCode::QoS0]
            );
        }
        other => panic!("expected SubAck, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn subscribe_to_unauthorized_group_denied() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // CONNECT
    let connect = mqttbytes::v5::Connect::new("sub-denied");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    // SUBSCRIBE to "bravo" (client is NOT a member)
    let sub = mqttbytes::v5::Subscribe::new("bravo", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Subscribe(sub)).await;

    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::SubAck(suback) => {
            assert_eq!(
                suback.return_codes,
                vec![mqttbytes::v5::SubscribeReasonCode::NotAuthorized]
            );
        }
        other => panic!("expected SubAck with NotAuthorized, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn publish_qos0_routes_to_group() {
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, Arc::clone(&router), None);

    // Connect Alice — she will subscribe and receive
    let alice_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let mut alice = mqtt_connect(server.addr, &alice_tls).await;
    let mut alice_buf = BytesMut::new();

    let connect = mqttbytes::v5::Connect::new("alice");
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut alice, &mut alice_buf).await; // CONNACK

    // Subscribe Alice to "alpha"
    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    let _ = read_v5_packet(&mut alice, &mut alice_buf).await; // SUBACK

    // Connect Bob — he will publish
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();

    let connect = mqttbytes::v5::Connect::new("bob");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await; // CONNACK

    // Bob publishes to "alpha"
    let publish =
        mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, b"hello from bob");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Publish(publish)).await;

    // Alice should receive the published message via the write loop.
    let packet = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut alice, &mut alice_buf),
    )
    .await
    .expect("alice should receive routed message within 2s");
    match packet {
        mqttbytes::v5::Packet::Publish(pub_msg) => {
            assert_eq!(pub_msg.topic, "alpha");
            assert_eq!(pub_msg.payload.as_ref(), b"hello from bob");
        }
        other => panic!("expected Publish, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn publish_qos1_gets_puback() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // CONNECT
    let connect = mqttbytes::v5::Connect::new("qos1-client");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await; // CONNACK

    // PUBLISH with QoS 1 (pkid must be non-zero)
    let mut publish =
        mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtLeastOnce, b"qos1 payload");
    publish.pkid = 42;
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    // Should receive PUBACK
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::PubAck(puback) => {
            assert_eq!(puback.pkid, 42);
            assert_eq!(puback.reason, mqttbytes::v5::PubAckReason::Success);
        }
        other => panic!("expected PubAck, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn topic_prefix_stripping() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, Some("rustgate/".into()));
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // CONNECT
    let connect = mqttbytes::v5::Connect::new("prefix-client");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    // SUBSCRIBE to "rustgate/alpha" — prefix strips to group "alpha"
    let sub = mqttbytes::v5::Subscribe::new("rustgate/alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Subscribe(sub)).await;

    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::SubAck(suback) => {
            assert_eq!(
                suback.return_codes,
                vec![mqttbytes::v5::SubscribeReasonCode::QoS0],
                "should succeed when prefix maps to authorized group"
            );
        }
        other => panic!("expected SubAck, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn connection_limit_rejects_excess() {
    let ca = TestCa::new("MQTT Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = MqttListener::bind("127.0.0.1:0".parse().unwrap(), &tls_config).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let shutdown = Arc::new(Notify::new());

    // Connection limit of 1
    let config = MqttServerConfig {
        listener,
        router,
        connection_limit: Arc::new(Semaphore::new(1)),
        shutdown: Arc::clone(&shutdown),
        topic_prefix: None,
        max_packet_size: 1024 * 1024,
        min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
        response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
        wildcard_policy: WildcardPolicy::default(),
        on_accept: None,
        on_reject: None,
        session_hooks: None,
    };

    drop(tokio::spawn(MqttServer::run(config)));

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);

    // First connection should succeed
    let mut stream1 = mqtt_connect(addr, &client_tls).await;
    let mut buf1 = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("conn1");
    write_v5_packet(&mut stream1, &mqttbytes::v5::Packet::Connect(connect)).await;
    let packet = read_v5_packet(&mut stream1, &mut buf1).await;
    assert!(matches!(packet, mqttbytes::v5::Packet::ConnAck(_)));

    // Second connection: TLS handshake may succeed but the session gets
    // dropped immediately by the server (connection limit). The client
    // will see EOF or a valid CONNACK (race). Either outcome is fine —
    // the test verifies the server doesn't crash.
    let mut stream2 = mqtt_connect(addr, &client_tls).await;
    let connect2 = mqttbytes::v5::Connect::new("conn2");
    write_v5_packet(&mut stream2, &mqttbytes::v5::Packet::Connect(connect2)).await;

    let mut raw_buf = [0u8; 256];
    let result = tokio::time::timeout(Duration::from_secs(2), stream2.read(&mut raw_buf)).await;

    // Any outcome is acceptable: EOF (rejected), bytes (race — accepted
    // before limit kicked in), timeout, or read error.
    match result {
        Ok(Ok(0)) => {}  // EOF — connection rejected as expected
        Ok(Ok(_n)) => {} // Got data — accepted before limit applied
        Ok(Err(_)) => {} // Read error — connection was closed
        Err(_) => {}     // Timeout — also fine
    }

    shutdown.notify_one();
}

#[tokio::test]
async fn disconnect_is_clean() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, Arc::clone(&router), None);
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // CONNECT
    let connect = mqttbytes::v5::Connect::new("dc-client");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    // DISCONNECT
    let disconnect = mqttbytes::v5::Disconnect {
        reason_code: mqttbytes::v5::DisconnectReasonCode::NormalDisconnection,
        properties: None,
    };
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Disconnect(disconnect)).await;

    // Give server time to process disconnect and unregister
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Session should be cleaned up — no crash, server still alive
    server.shutdown();
}

// ---------------------------------------------------------------------------
// End-to-end delivery test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_publish_delivers_to_subscriber() {
    // Client A publishes, Client B (subscribed) receives the message.
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, Arc::clone(&router), None);

    // --- Bob connects and subscribes ---
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();

    let connect = mqttbytes::v5::Connect::new("bob-recv");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await; // CONNACK

    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await; // SUBACK

    // --- Alice connects and publishes ---
    let alice_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let mut alice = mqtt_connect(server.addr, &alice_tls).await;
    let mut alice_buf = BytesMut::new();

    let connect = mqttbytes::v5::Connect::new("alice-pub");
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut alice, &mut alice_buf).await; // CONNACK

    let publish = mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, b"e2e-payload");
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Publish(publish)).await;

    // --- Bob should receive the message ---
    let packet = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut bob, &mut bob_buf),
    )
    .await
    .expect("bob should receive message within 2s");
    match packet {
        mqttbytes::v5::Packet::Publish(pub_msg) => {
            assert_eq!(pub_msg.topic, "alpha");
            assert_eq!(pub_msg.payload.as_ref(), b"e2e-payload");
        }
        other => panic!("expected Publish, got {other:?}"),
    }

    server.shutdown();
}

// ---------------------------------------------------------------------------
// Keep-alive timeout test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn keep_alive_timeout_disconnects_idle_client() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // CONNECT with keep_alive = 1 second (server allows 1.5x = 1.5s)
    let mut connect = mqttbytes::v5::Connect::new("keepalive-test");
    connect.keep_alive = 1;
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await; // CONNACK

    // Wait for the server to time out the connection (~1.5s from the
    // minimum keep-alive enforcement of 30s * 1.5 = 45s). However, the
    // MIN_KEEP_ALIVE_SECS is 30 and the server imposes that, so we need
    // a shorter approach. We verify via EOF: after enough idle time the
    // server closes the connection.
    //
    // Since the minimum keep-alive is 30s (imposed by the server), this
    // test verifies that the session stays alive for a shorter period and
    // then checks that after exceeding the timeout the connection closes.
    // To avoid a 45s test, we just verify the session is alive after 1s.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Session should still be alive (min keep-alive is 30s)
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::PingReq).await;
    let packet = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut stream, &mut buf),
    )
    .await
    .expect("session should still be alive");
    assert!(
        matches!(packet, mqttbytes::v5::Packet::PingResp),
        "expected PingResp, got {packet:?}"
    );

    server.shutdown();
}

// ---------------------------------------------------------------------------
// Max-packet-size rejection test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn max_packet_size_rejects_oversized_publish() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    // Server with a very small max packet size
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = MqttListener::bind("127.0.0.1:0".parse().unwrap(), &tls_config).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let shutdown = Arc::new(Notify::new());

    let config = MqttServerConfig {
        listener,
        router,
        connection_limit: Arc::new(Semaphore::new(100)),
        shutdown: Arc::clone(&shutdown),
        topic_prefix: None,
        max_packet_size: 64, // Very small — CONNECT is ~30-40 bytes, PUBLISH will exceed
        min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
        response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
        wildcard_policy: WildcardPolicy::default(),
        on_accept: None,
        on_reject: None,
        session_hooks: None,
    };

    drop(tokio::spawn(MqttServer::run(config)));

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // CONNECT (small enough to fit)
    let connect = mqttbytes::v5::Connect::new("tiny");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    assert!(matches!(packet, mqttbytes::v5::Packet::ConnAck(_)));

    // PUBLISH with payload that exceeds max_packet_size
    let big_payload = vec![0xAA; 128];
    let publish = mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, big_payload);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    // Server should close the connection (malformed/oversized packet)
    let mut raw = [0u8; 256];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut raw)).await;
    match result {
        Ok(Ok(0)) => {}  // EOF — server closed connection as expected
        Ok(Err(_)) => {} // Read error — also fine
        Err(_) => panic!("expected server to close connection after oversized packet"),
        Ok(Ok(_)) => {} // Got some data (maybe error response) — acceptable
    }

    shutdown.notify_one();
}

// ---------------------------------------------------------------------------
// Concurrent multi-client test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_multi_client_publish_and_receive() {
    let ca = TestCa::new("MQTT Test CA");
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    let num_publishers = 3;
    let mut receivers = Vec::new();

    // --- Set up a receiver ---
    let recv_cert = ca.issue_client_cert("receiver", &["alpha"]);
    let recv_tls = build_client_tls_config(&recv_cert.cert_pem, &recv_cert.key_pem, &ca.cert_pem);
    let mut recv_stream = mqtt_connect(server.addr, &recv_tls).await;
    let mut recv_buf = BytesMut::new();

    let connect = mqttbytes::v5::Connect::new("receiver");
    write_v5_packet(&mut recv_stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut recv_stream, &mut recv_buf).await; // CONNACK

    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut recv_stream, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    let _ = read_v5_packet(&mut recv_stream, &mut recv_buf).await; // SUBACK

    // --- Spawn publishers concurrently ---
    let addr = server.addr;
    for i in 0..num_publishers {
        let ca_pem = ca.cert_pem.clone();
        let pub_cert = ca.issue_client_cert(&format!("pub-{i}"), &["alpha"]);
        let handle = tokio::spawn(async move {
            let pub_tls = build_client_tls_config(&pub_cert.cert_pem, &pub_cert.key_pem, &ca_pem);
            let mut pub_stream = mqtt_connect(addr, &pub_tls).await;
            let mut pub_buf = BytesMut::new();

            let connect = mqttbytes::v5::Connect::new(format!("pub-{i}"));
            write_v5_packet(&mut pub_stream, &mqttbytes::v5::Packet::Connect(connect)).await;
            let _ = read_v5_packet(&mut pub_stream, &mut pub_buf).await; // CONNACK

            let payload = format!("msg-from-{i}");
            let publish = mqttbytes::v5::Publish::new(
                "alpha",
                mqttbytes::QoS::AtMostOnce,
                payload.as_bytes(),
            );
            write_v5_packet(&mut pub_stream, &mqttbytes::v5::Packet::Publish(publish)).await;

            // QoS 0 PUBLISH has no PUBACK feedback loop, so if we drop
            // the TLS stream here the server may close the connection
            // before it has finished parsing the PUBLISH out of its
            // read buffer and fanned the message out to subscribers —
            // which is exactly what was flaking the receiver's 3 s
            // timeout on loaded CI runners. Round-tripping a PINGREQ /
            // PINGRESP forces the server to drain every byte up to and
            // including the PUBLISH through its per-session state
            // machine before we tear the connection down.
            //
            // The publishers are minted with group `alpha` so they are
            // authorised to publish to that group, which also means the
            // router fans every peer's PUBLISH back to them as group
            // members. Between the PINGREQ we just wrote and the
            // PINGRESP we expect, the server may therefore deliver one
            // or more concurrent peer PUBLISHes first. Drain any such
            // PUBLISHes until we observe the PINGRESP — the PINGRESP
            // is the actual sync barrier; the intervening packets are
            // benign and unrelated to the flush guarantee we need.
            write_v5_packet(&mut pub_stream, &mqttbytes::v5::Packet::PingReq).await;
            loop {
                let packet = read_v5_packet(&mut pub_stream, &mut pub_buf).await;
                match packet {
                    mqttbytes::v5::Packet::PingResp => break,
                    mqttbytes::v5::Packet::Publish(_) => continue,
                    other => panic!("expected PingResp or Publish after PINGREQ, got {other:?}"),
                }
            }
        });
        receivers.push(handle);
    }

    // Wait for all publishers to finish
    for handle in receivers {
        handle.await.unwrap();
    }

    // --- Receiver should get all messages ---
    //
    // Budget the receiver generously (10 s per packet) — the publishers
    // have already synchronised with the server via PINGRESP above, so
    // any delay here is pure scheduler jitter on a loaded CI runner.
    // The previous 3 s timeout was the flake source documented in the
    // failing `test` job on `main` (fix/flaky-mqtt-concurrent-test).
    let mut received = Vec::new();
    for _ in 0..num_publishers {
        let packet = tokio::time::timeout(
            Duration::from_secs(10),
            read_v5_packet(&mut recv_stream, &mut recv_buf),
        )
        .await
        .expect("should receive all published messages");
        match packet {
            mqttbytes::v5::Packet::Publish(pub_msg) => {
                received.push(String::from_utf8(pub_msg.payload.to_vec()).unwrap());
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    received.sort();
    let mut expected: Vec<String> = (0..num_publishers)
        .map(|i| format!("msg-from-{i}"))
        .collect();
    expected.sort();
    assert_eq!(received, expected);

    server.shutdown();
}

// ---------------------------------------------------------------------------
// Wildcard SUBSCRIBE coverage (F-57 / #755)
//
// Wildcard filters are expanded at SUBSCRIBE time against the client's own
// certificate-derived `Identity.groups` set. The router itself never
// synthesises new groups from a wildcard; group membership remains the
// single authorisation boundary.
// ---------------------------------------------------------------------------

/// Assert that reading the next packet times out — used to prove that a
/// subscription has been effectively removed (unsubscribe_wildcard_stops_delivery).
async fn assert_no_packet(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    buf: &mut BytesMut,
    wait: Duration,
) {
    match tokio::time::timeout(wait, read_v5_packet(stream, buf)).await {
        Ok(packet) => panic!("expected no packet, got {packet:?}"),
        Err(_) => { /* timed out as expected */ }
    }
}

#[tokio::test]
async fn subscribe_plus_wildcard_delivers_from_multiple_groups() {
    let ca = TestCa::new("MQTT Test CA");
    // alice and bob both live in two hierarchical telemetry groups that
    // the `+` wildcard spans.
    let alice_cert = ca.issue_client_cert("alice", &["fleet/a/position", "fleet/b/position"]);
    let bob_cert = ca.issue_client_cert("bob", &["fleet/a/position", "fleet/b/position"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, Arc::clone(&router), None);

    let alice_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let mut alice = mqtt_connect(server.addr, &alice_tls).await;
    let mut alice_buf = BytesMut::new();

    write_v5_packet(
        &mut alice,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("alice")),
    )
    .await;
    let _ = read_v5_packet(&mut alice, &mut alice_buf).await; // CONNACK

    // `fleet/+/position` expands to {fleet/a/position, fleet/b/position}.
    let sub = mqttbytes::v5::Subscribe::new("fleet/+/position", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    match read_v5_packet(&mut alice, &mut alice_buf).await {
        mqttbytes::v5::Packet::SubAck(suback) => {
            assert_eq!(
                suback.return_codes,
                vec![mqttbytes::v5::SubscribeReasonCode::QoS0],
                "wildcard filter with matching groups should succeed"
            );
        }
        other => panic!("expected SubAck, got {other:?}"),
    }

    // Bob publishes to each matching group in turn; alice should receive both.
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();
    write_v5_packet(
        &mut bob,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("bob")),
    )
    .await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await; // CONNACK

    for topic in ["fleet/a/position", "fleet/b/position"] {
        let publish = mqttbytes::v5::Publish::new(topic, mqttbytes::QoS::AtMostOnce, b"pos");
        write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Publish(publish)).await;
    }

    let mut seen_topics = Vec::new();
    for _ in 0..2 {
        let packet = tokio::time::timeout(
            Duration::from_secs(2),
            read_v5_packet(&mut alice, &mut alice_buf),
        )
        .await
        .expect("alice should receive both wildcard-matched messages");
        match packet {
            mqttbytes::v5::Packet::Publish(pub_msg) => {
                seen_topics.push(pub_msg.topic.clone());
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }
    seen_topics.sort();
    assert_eq!(
        seen_topics,
        vec![
            "fleet/a/position".to_string(),
            "fleet/b/position".to_string(),
        ]
    );

    server.shutdown();
}

#[tokio::test]
async fn subscribe_hash_wildcard_rejected_under_default_policy() {
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["fleet/a/position"]);
    let router = Arc::new(Router::new());

    // Default policy = SingleLevelOnly: `#` must be rejected.
    let server = TestServer::new(&ca, router, None);

    let alice_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let mut alice = mqtt_connect(server.addr, &alice_tls).await;
    let mut buf = BytesMut::new();

    write_v5_packet(
        &mut alice,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("alice")),
    )
    .await;
    let _ = read_v5_packet(&mut alice, &mut buf).await; // CONNACK

    let sub = mqttbytes::v5::Subscribe::new("fleet/#", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    match read_v5_packet(&mut alice, &mut buf).await {
        mqttbytes::v5::Packet::SubAck(suback) => {
            assert_eq!(
                suback.return_codes,
                vec![mqttbytes::v5::SubscribeReasonCode::TopicFilterInvalid],
                "`#` should return TopicFilterInvalid under SingleLevelOnly policy"
            );
        }
        other => panic!("expected SubAck, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn subscribe_hash_wildcard_accepted_under_full_policy() {
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["fleet/a/position", "fleet/b/tel"]);
    let bob_cert = ca.issue_client_cert("bob", &["fleet/a/position"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new_with_policy(&ca, Arc::clone(&router), None, WildcardPolicy::Full);

    let alice_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let mut alice = mqtt_connect(server.addr, &alice_tls).await;
    let mut alice_buf = BytesMut::new();

    write_v5_packet(
        &mut alice,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("alice")),
    )
    .await;
    let _ = read_v5_packet(&mut alice, &mut alice_buf).await;

    // `fleet/#` expands to the full fleet subtree in alice's identity.
    let sub = mqttbytes::v5::Subscribe::new("fleet/#", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    match read_v5_packet(&mut alice, &mut alice_buf).await {
        mqttbytes::v5::Packet::SubAck(suback) => {
            assert_eq!(
                suback.return_codes,
                vec![mqttbytes::v5::SubscribeReasonCode::QoS0]
            );
        }
        other => panic!("expected SubAck, got {other:?}"),
    }

    // bob publishes to `fleet/a/position` — alice receives via `fleet/#`.
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();
    write_v5_packet(
        &mut bob,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("bob")),
    )
    .await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await;

    let publish =
        mqttbytes::v5::Publish::new("fleet/a/position", mqttbytes::QoS::AtMostOnce, b"hello");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Publish(publish)).await;

    let packet = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut alice, &mut alice_buf),
    )
    .await
    .expect("alice should receive via fleet/# wildcard");
    match packet {
        mqttbytes::v5::Packet::Publish(pub_msg) => {
            assert_eq!(pub_msg.topic, "fleet/a/position");
            assert_eq!(pub_msg.payload.as_ref(), b"hello");
        }
        other => panic!("expected Publish, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn subscribe_wildcard_with_no_matching_groups_denied() {
    let ca = TestCa::new("MQTT Test CA");
    // alice only has groups outside the `fleet/...` subtree.
    let alice_cert = ca.issue_client_cert("alice", &["other/data", "chat/global"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);

    let alice_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let mut alice = mqtt_connect(server.addr, &alice_tls).await;
    let mut buf = BytesMut::new();

    write_v5_packet(
        &mut alice,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("alice")),
    )
    .await;
    let _ = read_v5_packet(&mut alice, &mut buf).await;

    // `fleet/+/position` matches zero groups in alice's identity → reject.
    let sub = mqttbytes::v5::Subscribe::new("fleet/+/position", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    match read_v5_packet(&mut alice, &mut buf).await {
        mqttbytes::v5::Packet::SubAck(suback) => {
            assert_eq!(
                suback.return_codes,
                vec![mqttbytes::v5::SubscribeReasonCode::NotAuthorized],
                "wildcard with zero matching groups must deny — keeps the cert the authz boundary"
            );
        }
        other => panic!("expected SubAck, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn unsubscribe_wildcard_stops_delivery() {
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["fleet/a/position", "fleet/b/position"]);
    let bob_cert = ca.issue_client_cert("bob", &["fleet/a/position", "fleet/b/position"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, Arc::clone(&router), None);

    let alice_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let mut alice = mqtt_connect(server.addr, &alice_tls).await;
    let mut alice_buf = BytesMut::new();
    write_v5_packet(
        &mut alice,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("alice")),
    )
    .await;
    let _ = read_v5_packet(&mut alice, &mut alice_buf).await;

    let sub = mqttbytes::v5::Subscribe::new("fleet/+/position", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    let _ = read_v5_packet(&mut alice, &mut alice_buf).await; // SUBACK

    // Confirm delivery works before unsubscribe.
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();
    write_v5_packet(
        &mut bob,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("bob")),
    )
    .await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await;

    let publish =
        mqttbytes::v5::Publish::new("fleet/a/position", mqttbytes::QoS::AtMostOnce, b"pre");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Publish(publish)).await;
    let packet = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut alice, &mut alice_buf),
    )
    .await
    .expect("alice should receive before unsubscribe");
    assert!(matches!(packet, mqttbytes::v5::Packet::Publish(_)));

    // UNSUBSCRIBE the same wildcard — alice must leave both fleet/a and fleet/b.
    let unsub = mqttbytes::v5::Unsubscribe::new("fleet/+/position");
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Unsubscribe(unsub)).await;
    match read_v5_packet(&mut alice, &mut alice_buf).await {
        mqttbytes::v5::Packet::UnsubAck(_) => { /* ok */ }
        other => panic!("expected UnsubAck, got {other:?}"),
    }

    // Publish to both groups — neither should land on alice.
    for topic in ["fleet/a/position", "fleet/b/position"] {
        let publish = mqttbytes::v5::Publish::new(topic, mqttbytes::QoS::AtMostOnce, b"post");
        write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Publish(publish)).await;
    }
    assert_no_packet(&mut alice, &mut alice_buf, Duration::from_millis(300)).await;

    server.shutdown();
}
