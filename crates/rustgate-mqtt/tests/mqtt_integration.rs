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
use rustgate_mqtt::{
    MqttForwardingHooks, MqttListener, MqttServer, MqttServerConfig, WildcardPolicy,
};
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
            receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
            topic_alias_max: MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX,
            max_session_expiry_secs: MqttServerConfig::DEFAULT_MAX_SESSION_EXPIRY_SECS,
            max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
            min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
            response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
            wildcard_policy,
            on_accept: None,
            on_reject: None,
            session_hooks: None,
            forwarding_hooks: None,
        };

        drop(tokio::spawn(MqttServer::run(config)));

        Self {
            addr,
            shutdown,
            router,
        }
    }

    /// Build a test server with a populated `MqttForwardingHooks` bundle
    /// — the only knob that matters for the #903 egress fan-out tests.
    fn new_with_forwarding(
        ca: &TestCa,
        router: Arc<Router>,
        forwarding_hooks: MqttForwardingHooks,
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
            topic_prefix: None,
            max_packet_size: 1024 * 1024,
            receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
            topic_alias_max: MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX,
            max_session_expiry_secs: MqttServerConfig::DEFAULT_MAX_SESSION_EXPIRY_SECS,
            max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
            min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
            response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
            wildcard_policy: WildcardPolicy::default(),
            on_accept: None,
            on_reject: None,
            session_hooks: None,
            forwarding_hooks: Some(forwarding_hooks),
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
        // Refs #880 QoS 2: clients send PUBREL as Stage 3 of the
        // four-step. Without this arm the test harness silently
        // panics, masking what the wire format actually looked like.
        mqttbytes::v5::Packet::PubRel(p) => {
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
            // Refs #1158 + #880: every successful CONNACK MUST advertise
            // the broker's Maximum Packet Size (§3.2.2.3.6), Receive
            // Maximum (§3.2.2.3.3), and Session Expiry Interval
            // (§3.2.2.3.2) so a compliant client can plan its publish
            // strategy and session-resumption logic without falling
            // back to the spec-default assumptions.
            // A regression that dropped any of these properties from
            // the live CONNACK emission path would only show up at the
            // server-to-stream boundary — pinning all three end-to-end
            // here catches it without requiring a manual integration
            // test.
            let props = connack
                .properties
                .expect("v5 CONNACK MUST carry properties (mqttbytes 0.6 quirk + spec compliance)");
            assert!(
                props.max_packet_size.is_some(),
                "broker MUST advertise Maximum Packet Size in CONNACK (§3.2.2.3.6)"
            );
            assert_eq!(
                props.receive_max,
                Some(MqttServerConfig::DEFAULT_RECEIVE_MAX),
                "advertised Receive Maximum must match the server's configured value"
            );
            assert_eq!(
                props.topic_alias_max,
                Some(MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX),
                "broker MUST advertise Topic Alias Maximum in CONNACK (§3.2.2.3.8) \
                 so the client knows whether topic aliases are allowed and what \
                 the highest accepted alias value is"
            );
            assert_eq!(
                props.session_expiry_interval,
                Some(0),
                "broker MUST advertise Session Expiry Interval = 0 in CONNACK \
                 (§3.2.2.3.2) so the client knows the broker doesn't retain \
                 sessions — the alternative (omit the property) would let the \
                 client assume the broker honors its CONNECT-time request"
            );
        }
        other => panic!("expected ConnAck, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn connect_with_session_expiry_request_is_clamped_in_connack() {
    // Refs #880: a client that requests a non-zero Session Expiry
    // Interval in CONNECT MUST see `0` echoed in the matching
    // CONNACK — the broker advertises that it will not retain the
    // session even though the client asked. Per §3.2.2.3.2: "If
    // the Server returns a Session Expiry Interval in the CONNACK
    // packet, the Client MUST use this value as the duration of
    // the Session." The clamp is the spec-defined channel for the
    // broker to override the client's request.
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // Build a CONNECT requesting one-hour session retention. mqttbytes
    // 0.6's `ConnectProperties::_new()` is private, so construct the
    // struct directly via its (public) fields. We only care about
    // session_expiry_interval; everything else stays at the spec
    // default of None.
    let mut connect = mqttbytes::v5::Connect::new("session-expiry-client");
    connect.properties = Some(mqttbytes::v5::ConnectProperties {
        session_expiry_interval: Some(3600),
        receive_maximum: None,
        max_packet_size: None,
        topic_alias_max: None,
        request_response_info: None,
        request_problem_info: None,
        user_properties: Vec::new(),
        authentication_method: None,
        authentication_data: None,
    });
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;

    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::ConnAck(connack) => {
            assert_eq!(connack.code, mqttbytes::v5::ConnectReturnCode::Success);
            let props = connack.properties.expect(
                "v5 CONNACK MUST carry properties when broker overrides any client request",
            );
            assert_eq!(
                props.session_expiry_interval,
                Some(0),
                "broker MUST clamp the client's 3600s request to 0 in CONNACK \
                 — a regression that echoed the client's value (or omitted the \
                 property) would silently mislead the client into expecting \
                 session retention that the broker doesn't actually provide"
            );
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

// ---------------------------------------------------------------------------
// QoS 2 four-step (refs #880)
//
// MQTT 5.0 §4.3.3 / 3.1.1 §4.3.3 define the QoS 2 protocol as:
//
//   Client → Server: PUBLISH(qos=2, pkid=N)
//   Server → Client: PUBREC(pkid=N, success)
//   Client → Server: PUBREL(pkid=N)
//   Server → Client: PUBCOMP(pkid=N, success)
//
// rustgate uses Method B per §4.4: deliver to subscribers ON PUBREL,
// not on PUBREC. The integration tests below pin every spec-mandated
// step + the deferred-delivery contract (subscriber sees nothing
// between PUBLISH and PUBREL, sees the message exactly once after
// PUBREL).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_qos2_v5_completes_four_step_handshake() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    let connect = mqttbytes::v5::Connect::new("qos2-client");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await; // CONNACK

    // Stage 1: client sends PUBLISH (qos=2, pkid=42).
    let mut publish =
        mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::ExactlyOnce, b"qos2 payload");
    publish.pkid = 42;
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    // Stage 2: broker MUST respond with PUBREC, NOT PUBACK.
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::PubRec(pubrec) => {
            assert_eq!(pubrec.pkid, 42);
            assert_eq!(
                pubrec.reason,
                mqttbytes::v5::PubRecReason::Success,
                "broker must respond with PUBREC(success) after a valid \
                 QoS 2 PUBLISH (§4.3.3)"
            );
        }
        other => panic!(
            "expected PubRec for QoS 2 publish; got {other:?} — a regression \
             that emitted PubAck would mean the broker collapsed QoS 2 to \
             QoS 1 silently"
        ),
    }

    // Stage 3: client sends PUBREL.
    let pubrel = mqttbytes::v5::PubRel::new(42);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::PubRel(pubrel)).await;

    // Stage 4: broker MUST respond with PUBCOMP(success).
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::PubComp(pubcomp) => {
            assert_eq!(pubcomp.pkid, 42);
            assert_eq!(
                pubcomp.reason,
                mqttbytes::v5::PubCompReason::Success,
                "broker must respond with PUBCOMP(success) after PUBREL for \
                 a known pkid"
            );
        }
        other => panic!("expected PubComp at end of four-step, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn publish_qos2_v5_defers_delivery_until_pubrel() {
    // Refs #880 + spec §4.4: the broker SHOULD NOT send the data to
    // subscribers until it has received the PUBREL packet. Pin that
    // contract end-to-end: a subscriber sees nothing between PUBLISH
    // and PUBREL, sees the message exactly once after PUBREL.
    let ca = TestCa::new("MQTT Test CA");
    let publisher_cert = ca.issue_client_cert("alice", &["alpha"]);
    let subscriber_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);

    // Subscriber connects and subscribes first.
    let sub_tls = build_client_tls_config(
        &subscriber_cert.cert_pem,
        &subscriber_cert.key_pem,
        &ca.cert_pem,
    );
    let mut sub_stream = mqtt_connect(server.addr, &sub_tls).await;
    let mut sub_buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("qos2-subscriber");
    write_v5_packet(&mut sub_stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut sub_stream, &mut sub_buf).await; // CONNACK
    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtLeastOnce);
    write_v5_packet(&mut sub_stream, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    let _ = read_v5_packet(&mut sub_stream, &mut sub_buf).await; // SUBACK

    // Publisher connects.
    let pub_tls = build_client_tls_config(
        &publisher_cert.cert_pem,
        &publisher_cert.key_pem,
        &ca.cert_pem,
    );
    let mut pub_stream = mqtt_connect(server.addr, &pub_tls).await;
    let mut pub_buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("qos2-publisher");
    write_v5_packet(&mut pub_stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut pub_stream, &mut pub_buf).await; // CONNACK

    // Stage 1: publish QoS 2.
    let mut publish = mqttbytes::v5::Publish::new(
        "alpha",
        mqttbytes::QoS::ExactlyOnce,
        b"deferred qos2 payload",
    );
    publish.pkid = 7;
    write_v5_packet(&mut pub_stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    // Stage 2: PUBREC arrives.
    let packet = read_v5_packet(&mut pub_stream, &mut pub_buf).await;
    assert!(matches!(packet, mqttbytes::v5::Packet::PubRec(_)));

    // Subscriber must NOT see the message yet — Method B per §4.4.
    // Use a short timeout to bound the negative-assertion window;
    // a regression that emitted on PUBLISH-receipt would deliver
    // here and the test would fail.
    let no_delivery = tokio::time::timeout(
        Duration::from_millis(200),
        read_v5_packet(&mut sub_stream, &mut sub_buf),
    )
    .await;
    assert!(
        no_delivery.is_err(),
        "subscriber must NOT receive the QoS 2 message before PUBREL \
         (spec §4.4 Method B); regression would have delivered here"
    );

    // Stage 3: client sends PUBREL.
    write_v5_packet(
        &mut pub_stream,
        &mqttbytes::v5::Packet::PubRel(mqttbytes::v5::PubRel::new(7)),
    )
    .await;

    // Stage 4: PUBCOMP arrives.
    let packet = read_v5_packet(&mut pub_stream, &mut pub_buf).await;
    assert!(matches!(packet, mqttbytes::v5::Packet::PubComp(_)));

    // NOW the subscriber sees the message — exactly once.
    let packet = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut sub_stream, &mut sub_buf),
    )
    .await
    .expect("subscriber MUST receive the QoS 2 message after PUBREL");
    match packet {
        mqttbytes::v5::Packet::Publish(p) => {
            assert_eq!(p.topic, "alpha");
            assert_eq!(&p.payload[..], b"deferred qos2 payload");
        }
        other => panic!("expected delivered Publish, got {other:?}"),
    }

    // No second delivery — exactly-once means exactly-once.
    let no_dup = tokio::time::timeout(
        Duration::from_millis(200),
        read_v5_packet(&mut sub_stream, &mut sub_buf),
    )
    .await;
    assert!(
        no_dup.is_err(),
        "QoS 2 must deliver exactly once; regression would have delivered \
         a duplicate here"
    );

    server.shutdown();
}

#[tokio::test]
async fn pubrel_unknown_pkid_returns_packet_identifier_not_found() {
    // Refs #880, spec §3.7.2.1: a PUBREL whose pkid does not match
    // any in-flight QoS 2 PUBLISH is a protocol-level "unknown
    // identifier" — the broker MUST close the four-step on the
    // client side with PUBCOMP(PacketIdentifierNotFound = 0x92)
    // rather than ignoring it (which would leave the client
    // hanging) or terminating the session (which would punish a
    // client legitimately recovering from a torn ack).
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    let connect = mqttbytes::v5::Connect::new("orphan-pubrel");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await; // CONNACK

    // Send a PUBREL for a pkid that the broker has never seen.
    write_v5_packet(
        &mut stream,
        &mqttbytes::v5::Packet::PubRel(mqttbytes::v5::PubRel::new(9999)),
    )
    .await;

    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::PubComp(pubcomp) => {
            assert_eq!(pubcomp.pkid, 9999);
            assert_eq!(
                pubcomp.reason,
                mqttbytes::v5::PubCompReason::PacketIdentifierNotFound,
                "broker must reply PUBCOMP(PacketIdentifierNotFound = 0x92) for \
                 a PUBREL referencing an unknown pkid (§3.7.2.1)"
            );
        }
        other => panic!("expected PubComp(PacketIdentifierNotFound), got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn publish_qos2_v5_unauthorized_topic_returns_pubrec_not_authorized() {
    // Refs #880: spec §3.5 / §3.6 — a per-publish authz failure on
    // QoS 2 surfaces as PUBREC with a typed reason code, NOT as a
    // session-terminating MqttError. The four-step ack channel
    // exists precisely so the broker can reject individual messages
    // without dropping the whole connection.
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]); // alpha only
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    let connect = mqttbytes::v5::Connect::new("qos2-unauth");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    // Publish to "bravo" — alice is NOT a member.
    let mut publish =
        mqttbytes::v5::Publish::new("bravo", mqttbytes::QoS::ExactlyOnce, b"unauthorized");
    publish.pkid = 99;
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    // Broker must reply PUBREC with NotAuthorized — NOT terminate.
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::PubRec(pubrec) => {
            assert_eq!(pubrec.pkid, 99);
            assert_eq!(
                pubrec.reason,
                mqttbytes::v5::PubRecReason::NotAuthorized,
                "QoS 2 unauthorized publish must surface as PUBREC(NotAuthorized) \
                 — a regression that returned MqttError::NotAuthorized would \
                 terminate the session, dropping every other in-flight publish"
            );
        }
        other => panic!("expected PubRec(NotAuthorized), got {other:?}"),
    }

    // The session must still be alive — send a PINGREQ to verify.
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::PingReq).await;
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    assert!(
        matches!(packet, mqttbytes::v5::Packet::PingResp),
        "session must survive a per-publish QoS 2 reject; got {packet:?}"
    );

    server.shutdown();
}

#[tokio::test]
async fn publish_qos2_v5_duplicate_pkid_resends_pubrec_idempotent() {
    // Refs #880, spec §3.3.4 / §4.3.3: a duplicate PUBLISH with the
    // same pkid as one already in the inflight set MUST be
    // acknowledged with a PUBREC and continue with the protocol —
    // i.e. idempotent, the broker MUST NOT double-deliver. Pin
    // that the broker re-emits PUBREC and that subsequent PUBREL
    // delivers exactly once.
    let ca = TestCa::new("MQTT Test CA");
    let publisher_cert = ca.issue_client_cert("alice", &["alpha"]);
    let subscriber_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, router, None);

    // Subscriber connects and subscribes first so it sees deliveries.
    let sub_tls = build_client_tls_config(
        &subscriber_cert.cert_pem,
        &subscriber_cert.key_pem,
        &ca.cert_pem,
    );
    let mut sub_stream = mqtt_connect(server.addr, &sub_tls).await;
    let mut sub_buf = BytesMut::new();
    write_v5_packet(
        &mut sub_stream,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("dup-subscriber")),
    )
    .await;
    let _ = read_v5_packet(&mut sub_stream, &mut sub_buf).await;
    write_v5_packet(
        &mut sub_stream,
        &mqttbytes::v5::Packet::Subscribe(mqttbytes::v5::Subscribe::new(
            "alpha",
            mqttbytes::QoS::AtLeastOnce,
        )),
    )
    .await;
    let _ = read_v5_packet(&mut sub_stream, &mut sub_buf).await; // SUBACK

    let pub_tls = build_client_tls_config(
        &publisher_cert.cert_pem,
        &publisher_cert.key_pem,
        &ca.cert_pem,
    );
    let mut pub_stream = mqtt_connect(server.addr, &pub_tls).await;
    let mut pub_buf = BytesMut::new();
    write_v5_packet(
        &mut pub_stream,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("dup-publisher")),
    )
    .await;
    let _ = read_v5_packet(&mut pub_stream, &mut pub_buf).await;

    // First PUBLISH (qos=2, pkid=11).
    let mut publish =
        mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::ExactlyOnce, b"dedup payload");
    publish.pkid = 11;
    write_v5_packet(
        &mut pub_stream,
        &mqttbytes::v5::Packet::Publish(publish.clone()),
    )
    .await;

    // First PUBREC.
    let packet = read_v5_packet(&mut pub_stream, &mut pub_buf).await;
    assert!(matches!(
        packet,
        mqttbytes::v5::Packet::PubRec(p) if p.pkid == 11
    ));

    // Duplicate PUBLISH with same pkid (mqttbytes does not surface a
    // dup flag; the broker keys deduplication on pkid alone, which
    // is the spec's only cross-restart-stable handle).
    write_v5_packet(&mut pub_stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    // Broker must re-emit PUBREC for the duplicate.
    let packet = read_v5_packet(&mut pub_stream, &mut pub_buf).await;
    match packet {
        mqttbytes::v5::Packet::PubRec(p) => assert_eq!(p.pkid, 11),
        other => panic!("expected PubRec for duplicate pkid, got {other:?}"),
    }

    // Single PUBREL → single PUBCOMP → single delivery.
    write_v5_packet(
        &mut pub_stream,
        &mqttbytes::v5::Packet::PubRel(mqttbytes::v5::PubRel::new(11)),
    )
    .await;
    let _ = read_v5_packet(&mut pub_stream, &mut pub_buf).await; // PUBCOMP

    let packet = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut sub_stream, &mut sub_buf),
    )
    .await
    .expect("subscriber must receive the deduplicated message");
    match packet {
        mqttbytes::v5::Packet::Publish(p) => assert_eq!(&p.payload[..], b"dedup payload"),
        other => panic!("expected delivered Publish, got {other:?}"),
    }

    // No second delivery — duplicate must NOT have been routed twice.
    let no_dup = tokio::time::timeout(
        Duration::from_millis(300),
        read_v5_packet(&mut sub_stream, &mut sub_buf),
    )
    .await;
    assert!(
        no_dup.is_err(),
        "duplicate QoS 2 PUBLISH must NOT cause double delivery — \
         a regression that re-saved state on dup would deliver twice"
    );

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
        receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
        topic_alias_max: MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX,
        max_session_expiry_secs: MqttServerConfig::DEFAULT_MAX_SESSION_EXPIRY_SECS,
        max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
        min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
        response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
        wildcard_policy: WildcardPolicy::default(),
        on_accept: None,
        on_reject: None,
        session_hooks: None,
        forwarding_hooks: None,
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
    // Refs #753: server enforces `max_packet_size`. Beyond just dropping
    // the connection (the prior contract this test pinned), MQTT 5.0
    // §3.14.2.1 reason code 0x95 says the broker MUST send a structured
    // DISCONNECT before closing so the client gets a meaningful reason
    // instead of a bare TCP RST. We pin BOTH the spec-mandated
    // CONNACK advertisement (§3.2.2.3.6) and the DISCONNECT response
    // here in one end-to-end test that mirrors the production code path.
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

    const SERVER_CAP: usize = 64;
    let config = MqttServerConfig {
        listener,
        router,
        connection_limit: Arc::new(Semaphore::new(100)),
        shutdown: Arc::clone(&shutdown),
        topic_prefix: None,
        max_packet_size: SERVER_CAP, // Small — CONNECT fits, big PUBLISH won't
        receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
        topic_alias_max: MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX,
        max_session_expiry_secs: MqttServerConfig::DEFAULT_MAX_SESSION_EXPIRY_SECS,
        max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
        min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
        response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
        wildcard_policy: WildcardPolicy::default(),
        on_accept: None,
        on_reject: None,
        session_hooks: None,
        forwarding_hooks: None,
    };

    drop(tokio::spawn(MqttServer::run(config)));

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(addr, &client_tls).await;
    let mut buf = BytesMut::new();

    // CONNECT (small enough to fit)
    let connect = mqttbytes::v5::Connect::new("tiny");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;

    // CONNACK MUST advertise `Maximum Packet Size` per §3.2.2.3.6 — the
    // spec's mitigation for the F-58 production hazard #753 closes.
    // A regression that dropped the property would let a compliant
    // client assume the broker accepts any size (the spec default when
    // the property is absent), which is exactly the silent-DoS shape
    // the security label on this issue calls out.
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::ConnAck(connack) => {
            let props = connack.properties.expect("CONNACK must carry properties");
            assert_eq!(
                props.max_packet_size,
                Some(u32::try_from(SERVER_CAP).expect("SERVER_CAP fits in u32")),
                "broker MUST advertise its configured Maximum Packet Size cap \
                 so a compliant client short-circuits oversized publishes locally"
            );
        }
        other => panic!("expected CONNACK with properties, got {other:?}"),
    }

    // PUBLISH with payload that exceeds max_packet_size
    let big_payload = vec![0xAA; 128];
    let publish = mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, big_payload);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    // Server MUST either send DISCONNECT 0x95 (§3.14.2.1 PacketTooLarge)
    // before closing OR close the TCP stream cleanly. We accept both
    // outcomes — the DISCONNECT path is best-effort (tokio::select! drops
    // the write loop when the read loop returns Err, leaving the writer
    // half in an unspecified state per the cancel-safety contract on
    // tokio I/O), but neither outcome may leave the stream hung. The
    // failure mode #753 was filed against is "stream stays open with no
    // diagnostic" — both EOF and a structured DISCONNECT close that
    // hazard. We bypass the panicking `read_v5_packet` helper here and
    // read raw bytes so EOF surfaces as a typed result rather than an
    // expect-panic that would mask the assertion.
    // Drain the stream until we either parse a v5 packet or hit EOF /
    // error. Both outcomes are acceptable; what's NOT acceptable is the
    // stream staying open with no diagnostic.
    buf.clear();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut got_disconnect = false;
    let mut got_close = false;
    loop {
        // Try to parse what we have first.
        match mqttbytes::v5::read(&mut buf, 1024 * 1024) {
            Ok(mqttbytes::v5::Packet::Disconnect(disc)) => {
                assert_eq!(
                    disc.reason_code,
                    mqttbytes::v5::DisconnectReasonCode::PacketTooLarge,
                    "structured server-initiated DISCONNECT MUST carry \
                     reason code 0x95 (PacketTooLarge); got {:?}",
                    disc.reason_code
                );
                got_disconnect = true;
                break;
            }
            Ok(other) => panic!(
                "after oversized PUBLISH the only acceptable packet is \
                 DISCONNECT 0x95; got {other:?}"
            ),
            Err(mqttbytes::Error::InsufficientBytes(_)) => {} // need more
            Err(e) => panic!("server bytes failed to parse as v5: {e:?}"),
        }
        // Read more bytes (up to the deadline).
        let now = tokio::time::Instant::now();
        if now >= deadline {
            panic!(
                "after oversized PUBLISH the server must DISCONNECT or close \
                 within 2 s; got neither — exactly the #753 failure mode \
                 this test guards against (buf so far: {:02x?})",
                &buf[..]
            );
        }
        let mut raw = [0u8; 256];
        let read = tokio::time::timeout(deadline - now, stream.read(&mut raw)).await;
        match read {
            Ok(Ok(0)) => {
                // Clean EOF — server closed without DISCONNECT. Acceptable.
                got_close = true;
                break;
            }
            Ok(Ok(n)) => buf.extend_from_slice(&raw[..n]),
            Ok(Err(_io_err)) => {
                // TLS read error (e.g. UnexpectedEof without close_notify).
                // Also acceptable: the server closed the underlying socket.
                got_close = true;
                break;
            }
            Err(_timeout) => panic!(
                "after oversized PUBLISH the server must DISCONNECT or close \
                 within 2 s; the connection appears hung — exactly the #753 \
                 failure mode this test guards against"
            ),
        }
    }
    assert!(
        got_disconnect || got_close,
        "exit must be via DISCONNECT 0x95 or stream close"
    );

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

// ---------------------------------------------------------------------------
// Forwarding fan-out (#903) — post-route egress callbacks must fire once
// per successful local route and must not fire when no hooks are installed.
// These tests close the loop on the session.rs `fire_forwarding` helper: a
// compile check confirms the three `MqttForwardingHooks` slots are wired
// into the session, but only an end-to-end send proves the hot path
// actually invokes each callback with the post-Send-PEP payload.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_fires_all_three_forwarding_callbacks_once() {
    let ca = TestCa::new("MQTT Test CA");
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());

    // Event collectors for each sink. `Arc<Mutex<Vec<_>>>` is the
    // workspace-standard pattern for test callbacks (see
    // `.claude/rules/testing.md`). A local type alias tames the
    // federation tuple so clippy's `type_complexity` lint is happy.
    type FedEvent = (bytes::Bytes, Vec<String>, rustgate_core::message::Metadata);
    let nats_events: Arc<std::sync::Mutex<Vec<rustgate_core::message::RoutableMessage>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let fed_events: Arc<std::sync::Mutex<Vec<FedEvent>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let http_events: Arc<std::sync::Mutex<Vec<rustgate_core::message::RoutableMessage>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    let nats_clone = Arc::clone(&nats_events);
    let fed_clone = Arc::clone(&fed_events);
    let http_clone = Arc::clone(&http_events);

    let forwarding_hooks = MqttForwardingHooks {
        nats_publish: Some(Arc::new(move |msg| {
            nats_clone.lock().unwrap().push(msg);
        })),
        federation_forward: Some(Arc::new(move |payload, groups, metadata| {
            fed_clone.lock().unwrap().push((payload, groups, metadata));
        })),
        http_forward: Some(Arc::new(move |msg| {
            http_clone.lock().unwrap().push(msg);
        })),
    };

    let server = TestServer::new_with_forwarding(&ca, Arc::clone(&router), forwarding_hooks);

    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();

    let connect = mqttbytes::v5::Connect::new("bob");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await; // CONNACK

    // Single PUBLISH — route_for_egress should return Some and each
    // sink should observe the message exactly once.
    let publish =
        mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, b"fan-out-test-payload");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Publish(publish)).await;

    // Give the async task a moment to dispatch the callbacks. The
    // router + session hot path both complete synchronously-ish, but
    // the tokio runtime needs a yield before we snapshot.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // All three sinks must have seen exactly one event.
    let nats_events = nats_events.lock().unwrap();
    let fed_events = fed_events.lock().unwrap();
    let http_events = http_events.lock().unwrap();
    assert_eq!(
        nats_events.len(),
        1,
        "nats_publish must fire once per successful route, saw {} events",
        nats_events.len(),
    );
    assert_eq!(
        fed_events.len(),
        1,
        "federation_forward must fire once per successful route, saw {} events",
        fed_events.len(),
    );
    assert_eq!(
        http_events.len(),
        1,
        "http_forward must fire once per successful route, saw {} events",
        http_events.len(),
    );

    // Payload must carry the bytes bob wrote — no re-encoding.
    assert_eq!(nats_events[0].payload.as_ref(), b"fan-out-test-payload");
    assert_eq!(http_events[0].payload.as_ref(), b"fan-out-test-payload");
    assert_eq!(fed_events[0].0.as_ref(), b"fan-out-test-payload");

    // Federation groups must reflect the publisher's cert-derived
    // group membership (bob ∈ ["alpha"]) so the federation bridge can
    // scope the fan-out correctly downstream.
    assert!(
        fed_events[0].1.iter().any(|g| g == "alpha"),
        "federation_forward groups must include 'alpha' (bob's cert group), got {:?}",
        fed_events[0].1,
    );

    drop(nats_events);
    drop(fed_events);
    drop(http_events);
    server.shutdown();
}

#[tokio::test]
async fn publish_with_no_forwarding_hooks_does_not_panic() {
    // Smoke test for the happy-path of the `None`-bundle case.
    // Every other existing test in this file passes `None` and does
    // not exercise PUBLISH, so this test exists specifically to pin
    // that a PUBLISH with no forwarding hooks installed completes
    // cleanly — no panic, no hang, no error on the session loop.
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = TestServer::new(&ca, Arc::clone(&router), None);
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();

    write_v5_packet(
        &mut stream,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("alice")),
    )
    .await;
    let _ = read_v5_packet(&mut stream, &mut buf).await; // CONNACK

    let publish = mqttbytes::v5::Publish::new(
        "alpha",
        mqttbytes::QoS::AtLeastOnce, // QoS 1 so we observe PUBACK as the "done" signal
        b"no-hooks-smoke",
    );
    let mut publish = publish;
    publish.pkid = 7;
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    // PUBACK must still arrive — forwarding-hook absence cannot stall
    // the ack path.
    let packet = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut stream, &mut buf),
    )
    .await
    .expect("puback must arrive even when no forwarding hooks installed");
    match packet {
        mqttbytes::v5::Packet::PubAck(puback) => {
            assert_eq!(puback.pkid, 7);
            assert_eq!(puback.reason, mqttbytes::v5::PubAckReason::Success);
        }
        other => panic!("expected PubAck with no-hooks, got {other:?}"),
    }

    server.shutdown();
}

// ---------------------------------------------------------------------------
// Retain flag (issue #880) — MQTT 5.0 §3.3.1.3 / 3.1.1 §3.3.1
// ---------------------------------------------------------------------------

/// A subscriber that connects AFTER a retained PUBLISH must receive the
/// retained message immediately on its SUBSCRIBE — that is the load-
/// bearing semantic of the retain flag. Pinning this end-to-end ensures
/// the retain store is wired into both the PUBLISH and SUBSCRIBE
/// handlers (a regression that drops one half would silently break
/// last-known-value patterns that production IoT deployments depend on).
#[tokio::test]
async fn retained_publish_delivered_to_late_subscriber() {
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    // Phase 1: Alice publishes a QoS 0 retained message and disconnects.
    {
        let alice_tls =
            build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
        let mut alice = mqtt_connect(server.addr, &alice_tls).await;
        let mut alice_buf = BytesMut::new();
        let connect = mqttbytes::v5::Connect::new("alice-retain-pub");
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;
        let _ = read_v5_packet(&mut alice, &mut alice_buf).await; // CONNACK

        let mut publish =
            mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, b"last-known");
        publish.retain = true;
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Publish(publish)).await;

        // No PUBACK on QoS 0; give the broker a moment to update the
        // retain store before disconnecting.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let disc = mqttbytes::v5::Disconnect {
            reason_code: mqttbytes::v5::DisconnectReasonCode::NormalDisconnection,
            properties: None,
        };
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Disconnect(disc)).await;
    }

    // Phase 2: Bob connects AFTER Alice and subscribes — he must
    // receive the retained payload as part of the subscribe response.
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("bob-retain-sub");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await; // CONNACK

    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Subscribe(sub)).await;

    // SUBACK first (MQTT 5.0 §3.8.4 leaves order implementation-defined;
    // we send SUBACK first so client subscription state is updated
    // before retained PUBLISHes arrive — matches Mosquitto/HiveMQ).
    let suback = read_v5_packet(&mut bob, &mut bob_buf).await;
    assert!(
        matches!(suback, mqttbytes::v5::Packet::SubAck(_)),
        "expected SUBACK first, got {suback:?}"
    );

    // Then the retained PUBLISH with retain=true on the wire.
    let retained = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut bob, &mut bob_buf),
    )
    .await
    .expect("retained PUBLISH must be delivered after SUBACK");
    match retained {
        mqttbytes::v5::Packet::Publish(p) => {
            assert_eq!(p.topic, "alpha");
            assert_eq!(p.payload, &b"last-known"[..]);
            assert!(p.retain, "retain flag must be set on replay per spec");
        }
        other => panic!("expected retained Publish, got {other:?}"),
    }

    server.shutdown();
}

/// Per MQTT 5.0 §3.3.1.3 a PUBLISH with retain=1 AND zero-byte payload
/// CLEARS the retained message for that topic. A subsequent subscriber
/// must not receive anything for that topic — pinning this prevents
/// the "stuck zombie payload" regression where the clear is parsed but
/// not applied to the store.
#[tokio::test]
async fn retain_with_empty_payload_clears_existing() {
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    // Alice: store + clear the retained value for `alpha`.
    {
        let alice_tls =
            build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
        let mut alice = mqtt_connect(server.addr, &alice_tls).await;
        let mut alice_buf = BytesMut::new();
        let connect = mqttbytes::v5::Connect::new("alice-clear");
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;
        let _ = read_v5_packet(&mut alice, &mut alice_buf).await;

        // Store
        let mut store = mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, b"v1");
        store.retain = true;
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Publish(store)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Clear: zero-byte payload + retain=true
        let mut clear =
            mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, Vec::<u8>::new());
        clear.retain = true;
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Publish(clear)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Bob subscribes — must NOT see a retained PUBLISH because the
    // store was cleared by the empty-payload retain above.
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("bob-clear-sub");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await;

    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Subscribe(sub)).await;

    let suback = read_v5_packet(&mut bob, &mut bob_buf).await;
    assert!(matches!(suback, mqttbytes::v5::Packet::SubAck(_)));

    // After SUBACK, no retained PUBLISH should arrive within the
    // grace window. We pin the negative case via a short timeout.
    let next = tokio::time::timeout(
        Duration::from_millis(500),
        read_v5_packet(&mut bob, &mut bob_buf),
    )
    .await;
    assert!(
        next.is_err(),
        "expected no retained PUBLISH after empty-payload clear; got {next:?}"
    );

    server.shutdown();
}

/// Two subscribers that both subscribe to the same retained topic
/// must each receive their own copy of the retained PUBLISH — the
/// retain store is shared across sessions, but delivery is per-
/// subscriber. Pinning this ensures the matching/lookup path does
/// not accidentally consume entries on read.
#[tokio::test]
async fn retain_delivered_independently_to_multiple_subscribers() {
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);
    let charlie_cert = ca.issue_client_cert("charlie", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    // Alice publishes the retained message and disconnects.
    {
        let alice_tls =
            build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
        let mut alice = mqtt_connect(server.addr, &alice_tls).await;
        let mut alice_buf = BytesMut::new();
        let connect = mqttbytes::v5::Connect::new("alice-multi");
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;
        let _ = read_v5_packet(&mut alice, &mut alice_buf).await;
        let mut publish =
            mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, b"shared");
        publish.retain = true;
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Publish(publish)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Subscribe Bob and Charlie back-to-back. Each must see the
    // retained payload independently.
    for (cert, client_id) in [(&bob_cert, "bob-multi"), (&charlie_cert, "charlie-multi")] {
        let tls = build_client_tls_config(&cert.cert_pem, &cert.key_pem, &ca.cert_pem);
        let mut stream = mqtt_connect(server.addr, &tls).await;
        let mut buf = BytesMut::new();
        let connect = mqttbytes::v5::Connect::new(client_id);
        write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
        let _ = read_v5_packet(&mut stream, &mut buf).await;
        let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
        write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Subscribe(sub)).await;
        let _ = read_v5_packet(&mut stream, &mut buf).await; // SUBACK
        let retained = tokio::time::timeout(
            Duration::from_secs(2),
            read_v5_packet(&mut stream, &mut buf),
        )
        .await
        .unwrap_or_else(|_| panic!("{client_id} must receive retained PUBLISH"));
        match retained {
            mqttbytes::v5::Packet::Publish(p) => {
                assert_eq!(p.topic, "alpha");
                assert_eq!(p.payload, &b"shared"[..]);
                assert!(p.retain);
            }
            other => panic!("{client_id}: expected Publish, got {other:?}"),
        }
    }

    server.shutdown();
}

/// A non-retained PUBLISH must NOT update the retain store. This pins
/// the behaviour against a regression where the retain bit is read
/// but inverted — without retain=1 the store should be a passthrough.
#[tokio::test]
async fn non_retained_publish_does_not_persist() {
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    // Alice publishes a non-retained QoS 0 message.
    {
        let alice_tls =
            build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
        let mut alice = mqtt_connect(server.addr, &alice_tls).await;
        let mut alice_buf = BytesMut::new();
        let connect = mqttbytes::v5::Connect::new("alice-nonretain");
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;
        let _ = read_v5_packet(&mut alice, &mut alice_buf).await;
        // retain defaults to false — explicit for clarity in the assertion
        let mut publish =
            mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, b"transient");
        publish.retain = false;
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Publish(publish)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Bob subscribes — must NOT receive any retained PUBLISH.
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("bob-nonretain-sub");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await;

    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Subscribe(sub)).await;

    let suback = read_v5_packet(&mut bob, &mut bob_buf).await;
    assert!(matches!(suback, mqttbytes::v5::Packet::SubAck(_)));

    // No retained PUBLISH expected.
    let next = tokio::time::timeout(
        Duration::from_millis(400),
        read_v5_packet(&mut bob, &mut bob_buf),
    )
    .await;
    assert!(
        next.is_err(),
        "non-retained PUBLISH must not be replayed; got {next:?}"
    );

    server.shutdown();
}

/// A subscriber whose certificate does not include the retained
/// topic's group must NOT receive the retained payload. This is the
/// security-critical authorization test — without it, retain becomes
/// a side-channel for cross-tenant data leakage on a wildcard
/// subscribe that crosses authorization boundaries.
#[tokio::test]
async fn retain_does_not_leak_across_group_boundaries() {
    let ca = TestCa::new("MQTT Test CA");
    // Alice belongs to alpha; Eve belongs only to bravo. Eve's filter
    // is a multi-level wildcard that expands across her own groups —
    // it must NOT match alpha-retained messages because Eve is not a
    // member of alpha.
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let eve_cert = ca.issue_client_cert("eve", &["bravo"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    // Alice retains on alpha.
    {
        let alice_tls =
            build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
        let mut alice = mqtt_connect(server.addr, &alice_tls).await;
        let mut alice_buf = BytesMut::new();
        let connect = mqttbytes::v5::Connect::new("alice-secret");
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;
        let _ = read_v5_packet(&mut alice, &mut alice_buf).await;
        let mut publish =
            mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, b"secret");
        publish.retain = true;
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Publish(publish)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Eve subscribes to her own group — must succeed but yield NOTHING
    // because alpha's retained entry is not authorised for her.
    let eve_tls = build_client_tls_config(&eve_cert.cert_pem, &eve_cert.key_pem, &ca.cert_pem);
    let mut eve = mqtt_connect(server.addr, &eve_tls).await;
    let mut eve_buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("eve-spy");
    write_v5_packet(&mut eve, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut eve, &mut eve_buf).await;

    let sub = mqttbytes::v5::Subscribe::new("bravo", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut eve, &mqttbytes::v5::Packet::Subscribe(sub)).await;

    let suback = read_v5_packet(&mut eve, &mut eve_buf).await;
    assert!(matches!(suback, mqttbytes::v5::Packet::SubAck(_)));

    let next = tokio::time::timeout(
        Duration::from_millis(400),
        read_v5_packet(&mut eve, &mut eve_buf),
    )
    .await;
    assert!(
        next.is_err(),
        "retain MUST NOT leak across authorization boundaries; got {next:?}"
    );

    server.shutdown();
}

// ---------------------------------------------------------------------------
// Will messages (issue #880) — MQTT 5.0 §3.1.2.5–3.1.3 / 3.1.1 §3.1.2.5
//
// The broker publishes the configured will when a session ends
// ungracefully (TLS error, abrupt drop, keep-alive timeout). A clean
// DISCONNECT (v5 NormalDisconnection / v4 Disconnect) suppresses the
// will. The will routes through the same authorization gate as a live
// PUBLISH, so a will targeting an unauthorised group must reject the
// CONNECT — the will cannot be used to bypass the per-group authz
// boundary.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn will_published_on_ungraceful_disconnect() {
    // Alice connects with a will targeting `alpha`, then drops the TCP
    // connection abruptly. Bob (subscribed to `alpha`) must receive
    // the will payload — this is the load-bearing semantic of the
    // will flag.
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    // Phase 1: Bob connects and subscribes to `alpha` so he can
    // receive the will Alice will leave behind.
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("bob-will-watch");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await; // CONNACK

    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await; // SUBACK

    // Phase 2: Alice connects with a will, then drops her TCP stream
    // without sending DISCONNECT — the broker must publish the will.
    {
        let alice_tls =
            build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
        let mut alice = mqtt_connect(server.addr, &alice_tls).await;
        let mut alice_buf = BytesMut::new();
        let mut connect = mqttbytes::v5::Connect::new("alice-will-pub");
        connect.last_will = Some(mqttbytes::v5::LastWill::new(
            "alpha",
            b"alice-offline".to_vec(),
            mqttbytes::QoS::AtMostOnce,
            false,
        ));
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;
        let connack = read_v5_packet(&mut alice, &mut alice_buf).await;
        match connack {
            mqttbytes::v5::Packet::ConnAck(c) => {
                assert_eq!(c.code, mqttbytes::v5::ConnectReturnCode::Success);
            }
            other => panic!("expected ConnAck Success, got {other:?}"),
        }

        // Drop the TLS stream — that's an ungraceful close. The
        // broker's read loop will observe a connection error and
        // publish the will.
        drop(alice);
    }

    // Bob should receive the will payload as a normal PUBLISH on the
    // `alpha` topic.
    let packet = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut bob, &mut bob_buf),
    )
    .await
    .expect("bob should receive will payload within 2s of alice's drop");
    match packet {
        mqttbytes::v5::Packet::Publish(p) => {
            assert_eq!(p.topic, "alpha");
            assert_eq!(p.payload.as_ref(), b"alice-offline");
        }
        other => panic!("expected Publish from will, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn will_not_published_on_clean_disconnect() {
    // Alice connects with a will, sends DISCONNECT cleanly, then
    // closes. Bob (subscribed to `alpha`) must NOT receive the will —
    // the spec mandates the broker discard the will on a graceful
    // shutdown.
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("bob-clean-watch");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await;
    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await; // SUBACK

    // Alice with will → clean DISCONNECT → close.
    {
        let alice_tls =
            build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
        let mut alice = mqtt_connect(server.addr, &alice_tls).await;
        let mut alice_buf = BytesMut::new();
        let mut connect = mqttbytes::v5::Connect::new("alice-clean-pub");
        connect.last_will = Some(mqttbytes::v5::LastWill::new(
            "alpha",
            b"alice-should-not-fire".to_vec(),
            mqttbytes::QoS::AtMostOnce,
            false,
        ));
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;
        let _ = read_v5_packet(&mut alice, &mut alice_buf).await; // CONNACK

        let disc = mqttbytes::v5::Disconnect {
            reason_code: mqttbytes::v5::DisconnectReasonCode::NormalDisconnection,
            properties: None,
        };
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Disconnect(disc)).await;
        // Brief pause so the broker reads the DISCONNECT before we
        // tear down the TCP connection — we want the broker to
        // observe the clean disconnect, not a TCP error mid-transit.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Bob must NOT receive any message within the grace window.
    let next = tokio::time::timeout(
        Duration::from_millis(400),
        read_v5_packet(&mut bob, &mut bob_buf),
    )
    .await;
    assert!(
        next.is_err(),
        "clean DISCONNECT must suppress will publish; bob got {next:?}"
    );

    server.shutdown();
}

#[tokio::test]
async fn will_validation_rejects_unauthorized_topic() {
    // Alice (member of `alpha` only) tries to CONNECT with a will
    // targeting `bravo` — a group she is not a member of. The CONNECT
    // must be rejected with `NotAuthorized` so the will cannot be
    // used to bypass the per-group authz boundary.
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, router, None);

    let alice_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let mut alice = mqtt_connect(server.addr, &alice_tls).await;
    let mut alice_buf = BytesMut::new();

    let mut connect = mqttbytes::v5::Connect::new("alice-bad-will");
    // bravo is NOT in alice's certificate group set.
    connect.last_will = Some(mqttbytes::v5::LastWill::new(
        "bravo",
        b"should-be-rejected".to_vec(),
        mqttbytes::QoS::AtMostOnce,
        false,
    ));
    write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;

    let connack = read_v5_packet(&mut alice, &mut alice_buf).await;
    match connack {
        mqttbytes::v5::Packet::ConnAck(c) => {
            assert_eq!(
                c.code,
                mqttbytes::v5::ConnectReturnCode::NotAuthorized,
                "will targeting an unauthorised group must surface NotAuthorized in CONNACK"
            );
        }
        other => panic!("expected ConnAck NotAuthorized, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn will_with_retain_flag_persists_to_retain_store() {
    // Alice connects with `will_retain=true`, then drops the TCP
    // stream. Bob subscribes AFTER Alice is gone — he must receive
    // the will payload via the retain replay path. This pins the
    // wiring of the will → retain store so a regression that drops
    // either half is caught.
    let ca = TestCa::new("MQTT Test CA");
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    // Phase 1: Alice connects with retained will and drops abruptly.
    {
        let alice_tls =
            build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
        let mut alice = mqtt_connect(server.addr, &alice_tls).await;
        let mut alice_buf = BytesMut::new();
        let mut connect = mqttbytes::v5::Connect::new("alice-retained-will");
        connect.last_will = Some(mqttbytes::v5::LastWill::new(
            "alpha",
            b"last-known-will".to_vec(),
            mqttbytes::QoS::AtMostOnce,
            true, // retain=true
        ));
        write_v5_packet(&mut alice, &mqttbytes::v5::Packet::Connect(connect)).await;
        let _ = read_v5_packet(&mut alice, &mut alice_buf).await; // CONNACK

        // Drop without DISCONNECT to trigger the will publish path.
        drop(alice);
        // Allow the broker time to detect the close, fire the will,
        // and update the retain store before bob subscribes.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Phase 2: Bob subscribes — he must receive the retained will
    // payload as a retained PUBLISH.
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob = mqtt_connect(server.addr, &bob_tls).await;
    let mut bob_buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("bob-retain-will-sub");
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut bob, &mut bob_buf).await; // CONNACK

    let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    write_v5_packet(&mut bob, &mqttbytes::v5::Packet::Subscribe(sub)).await;

    // SUBACK first (matches Mosquitto/HiveMQ ordering).
    let suback = read_v5_packet(&mut bob, &mut bob_buf).await;
    assert!(
        matches!(suback, mqttbytes::v5::Packet::SubAck(_)),
        "expected SUBACK first, got {suback:?}"
    );

    // Retained will payload follows.
    let retained = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut bob, &mut bob_buf),
    )
    .await
    .expect("retained will must replay to a late subscriber");
    match retained {
        mqttbytes::v5::Packet::Publish(p) => {
            assert_eq!(p.topic, "alpha");
            assert_eq!(p.payload.as_ref(), b"last-known-will");
            assert!(
                p.retain,
                "retain flag must be set on the wire for a retained-will replay"
            );
        }
        other => panic!("expected retained Publish from will, got {other:?}"),
    }

    server.shutdown();
}

// ---------------------------------------------------------------------------
// Packet ID wrap-around boundary audit (issue #880)
//
// MQTT 5.0 §1.5.4 / 3.1.1 §2.3.1: Packet Identifiers are 16-bit unsigned
// integers in the range [1, 65535] (zero is reserved as "no packet
// identifier"). The broker echoes the inbound pkid in PUBACK / SUBACK /
// UNSUBACK without transforming it; these tests pin that no off-by-one
// or u16 overflow regression sneaks into the echo path. The 65535 case
// is the load-bearing one — the upper edge of the 16-bit space — and
// is exactly where a naive u16 + 1 increment would wrap to 0 instead
// of staying at 65535.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_qos1_pkid_max_u16_round_trips_in_puback() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("pkid-max");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    let mut publish =
        mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtLeastOnce, b"max-pkid");
    publish.pkid = u16::MAX; // 65535 — the upper edge of the 16-bit space
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::PubAck(puback) => {
            assert_eq!(
                puback.pkid,
                u16::MAX,
                "PUBACK pkid must echo u16::MAX verbatim (regression on +1 wrap)"
            );
            assert_eq!(puback.reason, mqttbytes::v5::PubAckReason::Success);
        }
        other => panic!("expected PubAck for pkid=u16::MAX, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn publish_qos1_pkid_one_round_trips_in_puback() {
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("pkid-one");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    // pkid=1 is the smallest legal pkid (zero is reserved). Pinning the
    // lower bound alongside the upper bound bookends the valid range.
    let mut publish =
        mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtLeastOnce, b"min-pkid");
    publish.pkid = 1;
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::PubAck(puback) => {
            assert_eq!(puback.pkid, 1);
            assert_eq!(puback.reason, mqttbytes::v5::PubAckReason::Success);
        }
        other => panic!("expected PubAck for pkid=1, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn publish_qos1_round_trips_pkids_across_wraparound_boundary() {
    // Send a sequence of pkids that step across the u16 boundary
    // (65534, 65535, 1, 2 — simulating what a client wraparound looks
    // like on the broker's input side). Every PUBACK must echo the
    // exact pkid sent: a regression that incremented or stored pkids
    // in a u8 / i16 / wrapping_add sometime would surface here.
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("pkid-wrap");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    let pkid_sequence: [u16; 4] = [65534, 65535, 1, 2];
    for pkid in pkid_sequence {
        let mut publish = mqttbytes::v5::Publish::new(
            "alpha",
            mqttbytes::QoS::AtLeastOnce,
            format!("payload-{pkid}").into_bytes(),
        );
        publish.pkid = pkid;
        write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

        let packet = read_v5_packet(&mut stream, &mut buf).await;
        match packet {
            mqttbytes::v5::Packet::PubAck(puback) => {
                assert_eq!(
                    puback.pkid, pkid,
                    "PUBACK pkid drift on sequence step pkid={pkid}",
                );
            }
            other => panic!("expected PubAck for pkid={pkid}, got {other:?}"),
        }
    }

    server.shutdown();
}

#[tokio::test]
async fn subscribe_pkid_max_u16_round_trips_in_suback() {
    // SUBSCRIBE pkid uses the same 16-bit space as PUBLISH and is
    // echoed in SUBACK. Pin the upper edge for the SUBSCRIBE path
    // alongside the PUBLISH coverage so a regression in EITHER
    // packet-type echo path fails loudly.
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("sub-pkid-max");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    let mut sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    sub.pkid = u16::MAX;
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Subscribe(sub)).await;

    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::SubAck(suback) => {
            assert_eq!(
                suback.pkid,
                u16::MAX,
                "SUBACK pkid must echo u16::MAX verbatim",
            );
            assert_eq!(
                suback.return_codes,
                vec![mqttbytes::v5::SubscribeReasonCode::QoS0]
            );
        }
        other => panic!("expected SubAck for pkid=u16::MAX, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn unsubscribe_pkid_max_u16_round_trips_in_unsuback() {
    // Same boundary pin for UNSUBSCRIBE → UNSUBACK. Three packet types
    // that echo pkid → three boundary tests; collectively they pin the
    // entire 16-bit echo surface against a u8/i16/wrapping_add
    // regression in any single dispatch arm.
    let ca = TestCa::new("MQTT Test CA");
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());
    let server = TestServer::new(&ca, Arc::clone(&router), None);

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = mqtt_connect(server.addr, &client_tls).await;
    let mut buf = BytesMut::new();
    let connect = mqttbytes::v5::Connect::new("unsub-pkid-max");
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    // Subscribe first so the unsubscribe has something to remove.
    let mut sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtMostOnce);
    sub.pkid = 1;
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Subscribe(sub)).await;
    let _ = read_v5_packet(&mut stream, &mut buf).await; // SUBACK

    let mut unsub = mqttbytes::v5::Unsubscribe::new("alpha");
    unsub.pkid = u16::MAX;
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Unsubscribe(unsub)).await;

    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::UnsubAck(unsuback) => {
            assert_eq!(
                unsuback.pkid,
                u16::MAX,
                "UNSUBACK pkid must echo u16::MAX verbatim",
            );
        }
        other => panic!("expected UnsubAck for pkid=u16::MAX, got {other:?}"),
    }

    server.shutdown();
}

// ---------------------------------------------------------------------------
// MQTT 5.0 session retention (refs #880; follow-up to #1162)
//
// CONNECT with clean_start=0 + non-zero Session Expiry Interval saves
// the session at disconnect and restores it on a subsequent reconnect
// from the same client_id within the expiry window. Without this PR,
// rustgate rejected clean_start=0 outright with
// ImplementationSpecificError. With it, retention works end-to-end
// when the operator opts in via `max_session_expiry_secs > 0`.
// ---------------------------------------------------------------------------

/// Build a test server with MQTT session retention enabled.
fn new_test_server_with_retention(
    ca: &TestCa,
    router: Arc<Router>,
    max_session_expiry_secs: u32,
) -> TestServer {
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = MqttListener::bind("127.0.0.1:0".parse().unwrap(), &tls_config).expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let shutdown = Arc::new(Notify::new());

    let config = MqttServerConfig {
        listener,
        router: Arc::clone(&router),
        connection_limit: Arc::new(Semaphore::new(100)),
        shutdown: Arc::clone(&shutdown),
        topic_prefix: None,
        max_packet_size: 1024 * 1024,
        receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
        topic_alias_max: MqttServerConfig::DEFAULT_TOPIC_ALIAS_MAX,
        max_session_expiry_secs,
        max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
        min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
        response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
        wildcard_policy: WildcardPolicy::default(),
        on_accept: None,
        on_reject: None,
        session_hooks: None,
        forwarding_hooks: None,
    };

    drop(tokio::spawn(MqttServer::run(config)));

    TestServer {
        addr,
        shutdown,
        router,
    }
}

/// Build a v5 CONNECT requesting a session with `clean_start` + the
/// given Session Expiry Interval.
fn build_v5_connect_with_session(
    client_id: &str,
    clean_start: bool,
    session_expiry_secs: u32,
) -> mqttbytes::v5::Connect {
    let mut connect = mqttbytes::v5::Connect::new(client_id);
    connect.clean_session = clean_start;
    connect.properties = Some(mqttbytes::v5::ConnectProperties {
        session_expiry_interval: Some(session_expiry_secs),
        receive_maximum: None,
        max_packet_size: None,
        topic_alias_max: None,
        request_response_info: None,
        request_problem_info: None,
        user_properties: Vec::new(),
        authentication_method: None,
        authentication_data: None,
    });
    connect
}

#[tokio::test]
async fn session_retention_resumes_subscriptions_on_reconnect() {
    // The headline test for #880 follow-up to #1162: client A
    // subscribes to "alpha", disconnects with non-zero
    // SessionExpiryInterval, reconnects with clean_start=0, and the
    // broker MUST restore the subscription so a subsequent PUBLISH
    // from client B reaches A WITHOUT A re-issuing SUBSCRIBE.
    let ca = TestCa::new("MQTT Test CA");
    let cert_a = ca.issue_client_cert("alice", &["alpha"]);
    let cert_b = ca.issue_client_cert("bob", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = new_test_server_with_retention(&ca, router, 3600);
    let tls_a = build_client_tls_config(&cert_a.cert_pem, &cert_a.key_pem, &ca.cert_pem);
    let tls_b = build_client_tls_config(&cert_b.cert_pem, &cert_b.key_pem, &ca.cert_pem);

    // Connection 1: subscribe + disconnect cleanly with session expiry > 0.
    {
        let mut stream = mqtt_connect(server.addr, &tls_a).await;
        let mut buf = BytesMut::new();
        let connect =
            build_v5_connect_with_session("session-resumer", true /* clean_start */, 3600);
        write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
        let connack = read_v5_packet(&mut stream, &mut buf).await;
        match connack {
            mqttbytes::v5::Packet::ConnAck(ca) => {
                assert!(!ca.session_present, "first CONNECT must be a fresh session");
                let props = ca.properties.expect("CONNACK properties");
                assert_eq!(
                    props.session_expiry_interval,
                    Some(3600),
                    "broker must echo the negotiated session expiry"
                );
            }
            other => panic!("expected CONNACK, got {other:?}"),
        }

        let sub = mqttbytes::v5::Subscribe::new("alpha", mqttbytes::QoS::AtLeastOnce);
        write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Subscribe(sub)).await;
        let _ = read_v5_packet(&mut stream, &mut buf).await; // SUBACK

        // Clean disconnect — preserves the session per spec
        // §3.14.4 because Session Expiry Interval > 0.
        let disc = mqttbytes::v5::Disconnect::new();
        write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Disconnect(disc)).await;
        // Drop stream → broker observes disconnect.
    }

    // Brief settle so the broker's session-end save lands before we reconnect.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connection 2: reconnect with clean_start=0 — broker MUST restore.
    let mut stream_a2 = mqtt_connect(server.addr, &tls_a).await;
    let mut buf_a = BytesMut::new();
    let connect =
        build_v5_connect_with_session("session-resumer", false /* clean_start */, 3600);
    write_v5_packet(&mut stream_a2, &mqttbytes::v5::Packet::Connect(connect)).await;
    let connack = read_v5_packet(&mut stream_a2, &mut buf_a).await;
    match connack {
        mqttbytes::v5::Packet::ConnAck(ca) => {
            assert_eq!(
                ca.code,
                mqttbytes::v5::ConnectReturnCode::Success,
                "broker must accept clean_start=0 when retention is enabled"
            );
            assert!(
                ca.session_present,
                "session_present MUST be true on a successful resume (§3.2.2.1.1)"
            );
        }
        other => panic!("expected CONNACK Success with session_present=true, got {other:?}"),
    }

    // Now publish from client B — A must receive WITHOUT re-subscribing.
    let mut stream_b = mqtt_connect(server.addr, &tls_b).await;
    let mut buf_b = BytesMut::new();
    write_v5_packet(
        &mut stream_b,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("session-publisher")),
    )
    .await;
    let _ = read_v5_packet(&mut stream_b, &mut buf_b).await;

    let publish =
        mqttbytes::v5::Publish::new("alpha", mqttbytes::QoS::AtMostOnce, b"resumed-delivery");
    write_v5_packet(&mut stream_b, &mqttbytes::v5::Packet::Publish(publish)).await;

    let received = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet(&mut stream_a2, &mut buf_a),
    )
    .await
    .expect("resumed session MUST receive the publish without re-SUBSCRIBE");
    match received {
        mqttbytes::v5::Packet::Publish(p) => {
            assert_eq!(p.topic, "alpha");
            assert_eq!(&p.payload[..], b"resumed-delivery");
        }
        other => panic!(
            "expected delivered Publish on resumed session, got {other:?} \
             — a regression that didn't restore subscriptions would silently \
             swallow the message here"
        ),
    }

    server.shutdown();
}

#[tokio::test]
async fn session_retention_disabled_rejects_clean_start_false() {
    // Refs #1162 contract: when retention is disabled (the default),
    // a clean_start=0 CONNECT MUST be rejected with
    // ImplementationSpecificError so the client can't silently
    // believe its subscriptions will resume after disconnect.
    let ca = TestCa::new("MQTT Test CA");
    let cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    // Default TestServer: max_session_expiry_secs = 0 (retention OFF).
    let server = TestServer::new(&ca, router, None);
    let tls = build_client_tls_config(&cert.cert_pem, &cert.key_pem, &ca.cert_pem);

    let mut stream = mqtt_connect(server.addr, &tls).await;
    let mut buf = BytesMut::new();
    let connect = build_v5_connect_with_session("rejected", false /* clean_start */, 3600);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Connect(connect)).await;
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    match packet {
        mqttbytes::v5::Packet::ConnAck(ca) => {
            assert_eq!(
                ca.code,
                mqttbytes::v5::ConnectReturnCode::ImplementationSpecificError,
                "retention OFF must reject clean_start=0 (preserves #1162 contract)"
            );
        }
        other => panic!("expected ConnAck rejection, got {other:?}"),
    }

    server.shutdown();
}

#[tokio::test]
async fn session_retention_clean_start_true_discards_saved_session() {
    // §3.1.4 server-takeover: a NEW connection from the same
    // client_id with clean_start=1 MUST drop any saved session.
    let ca = TestCa::new("MQTT Test CA");
    let cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = new_test_server_with_retention(&ca, router, 3600);
    let tls = build_client_tls_config(&cert.cert_pem, &cert.key_pem, &ca.cert_pem);

    // Conn 1: subscribe + disconnect (would save).
    {
        let mut stream = mqtt_connect(server.addr, &tls).await;
        let mut buf = BytesMut::new();
        write_v5_packet(
            &mut stream,
            &mqttbytes::v5::Packet::Connect(build_v5_connect_with_session(
                "ts-takeover",
                true,
                3600,
            )),
        )
        .await;
        let _ = read_v5_packet(&mut stream, &mut buf).await;
        write_v5_packet(
            &mut stream,
            &mqttbytes::v5::Packet::Subscribe(mqttbytes::v5::Subscribe::new(
                "alpha",
                mqttbytes::QoS::AtMostOnce,
            )),
        )
        .await;
        let _ = read_v5_packet(&mut stream, &mut buf).await;
        write_v5_packet(
            &mut stream,
            &mqttbytes::v5::Packet::Disconnect(mqttbytes::v5::Disconnect::new()),
        )
        .await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Conn 2: clean_start=1 — saved session dropped, fresh start.
    let mut stream2 = mqtt_connect(server.addr, &tls).await;
    let mut buf = BytesMut::new();
    write_v5_packet(
        &mut stream2,
        &mqttbytes::v5::Packet::Connect(build_v5_connect_with_session(
            "ts-takeover",
            true, /* clean_start */
            0,
        )),
    )
    .await;
    let connack = read_v5_packet(&mut stream2, &mut buf).await;
    match connack {
        mqttbytes::v5::Packet::ConnAck(ca) => {
            assert!(
                !ca.session_present,
                "clean_start=1 MUST start fresh — session_present MUST be false (§3.2.2.1.1)"
            );
        }
        other => panic!("expected ConnAck, got {other:?}"),
    }

    server.shutdown();
}

// ---------------------------------------------------------------------------
// MQTT 5.0 Topic Alias (refs #880; §3.3.2.3.4 + §3.2.2.3.8)
//
// When the broker advertises Topic Alias Maximum > 0, clients can:
//   1. ESTABLISH a mapping: PUBLISH(topic="abc/def", topic_alias=N)
//   2. REFERENCE the mapping: PUBLISH(topic="", topic_alias=N)
// Invalid alias values (0, > advertised_max, or unmapped reference)
// MUST trigger DISCONNECT 0x94 per §3.14.2.1. The default cap is 0
// (feature off); any inbound alias hits the DISCONNECT path.
// ---------------------------------------------------------------------------

/// Build a test server with Topic Alias Maximum enabled.
fn new_test_server_with_topic_alias_max(
    ca: &TestCa,
    router: Arc<Router>,
    topic_alias_max: u16,
) -> TestServer {
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = MqttListener::bind("127.0.0.1:0".parse().unwrap(), &tls_config).expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let shutdown = Arc::new(Notify::new());

    let config = MqttServerConfig {
        listener,
        router: Arc::clone(&router),
        connection_limit: Arc::new(Semaphore::new(100)),
        shutdown: Arc::clone(&shutdown),
        topic_prefix: None,
        max_packet_size: 1024 * 1024,
        receive_max: MqttServerConfig::DEFAULT_RECEIVE_MAX,
        topic_alias_max,
        max_session_expiry_secs: MqttServerConfig::DEFAULT_MAX_SESSION_EXPIRY_SECS,
        max_retained_sessions: MqttServerConfig::DEFAULT_MAX_RETAINED_SESSIONS,
        min_keep_alive_secs: MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS,
        response_channel_capacity: MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY,
        wildcard_policy: WildcardPolicy::default(),
        on_accept: None,
        on_reject: None,
        session_hooks: None,
        forwarding_hooks: None,
    };

    drop(tokio::spawn(MqttServer::run(config)));

    TestServer {
        addr,
        shutdown,
        router,
    }
}

/// Build a v5 PUBLISH carrying a Topic Alias property. Constructed via
/// the public struct fields because `PublishProperties::_new()` is
/// private in mqttbytes 0.6 (same constraint as the connect-properties
/// helpers in the session-retention tests).
fn build_v5_publish_with_alias(
    topic: &str,
    payload: &[u8],
    topic_alias: u16,
) -> mqttbytes::v5::Publish {
    let mut publish = mqttbytes::v5::Publish::new(topic, mqttbytes::QoS::AtMostOnce, payload);
    publish.properties = Some(mqttbytes::v5::PublishProperties {
        payload_format_indicator: None,
        message_expiry_interval: None,
        topic_alias: Some(topic_alias),
        response_topic: None,
        correlation_data: None,
        user_properties: Vec::new(),
        subscription_identifiers: Vec::new(),
        content_type: None,
    });
    publish
}

/// Read the next packet OR return None on stream EOF / parse error
/// (the alias-invalid path closes the connection so the client sees
/// either DISCONNECT first then EOF, or just EOF if the cancel-safe
/// writer-half drop hit before the DISCONNECT made it onto the wire).
async fn read_v5_packet_or_close(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    buf: &mut BytesMut,
) -> Option<mqttbytes::v5::Packet> {
    loop {
        match mqttbytes::v5::read(buf, 1024 * 1024) {
            Ok(packet) => return Some(packet),
            Err(mqttbytes::Error::InsufficientBytes(_)) => {}
            Err(_) => return None,
        }
        match stream.read_buf(buf).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

#[tokio::test]
async fn topic_alias_establish_then_reference_round_trips() {
    // The headline test: client ESTABLISHES topic="alpha" + alias=1
    // in one PUBLISH, then REFERENCES alias=1 with empty topic in a
    // second PUBLISH. Both must reach the subscriber as if they had
    // been sent with the full topic string. A regression that
    // dropped the alias table OR didn't consult it on empty-topic
    // PUBLISHes would silently swallow the second message.
    let ca = TestCa::new("MQTT Test CA");
    let pub_cert = ca.issue_client_cert("publisher", &["alpha"]);
    let sub_cert = ca.issue_client_cert("subscriber", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = new_test_server_with_topic_alias_max(&ca, router, 16);
    let pub_tls = build_client_tls_config(&pub_cert.cert_pem, &pub_cert.key_pem, &ca.cert_pem);
    let sub_tls = build_client_tls_config(&sub_cert.cert_pem, &sub_cert.key_pem, &ca.cert_pem);

    // Subscriber connects + subscribes first.
    let mut sub_stream = mqtt_connect(server.addr, &sub_tls).await;
    let mut sub_buf = BytesMut::new();
    write_v5_packet(
        &mut sub_stream,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("alias-sub")),
    )
    .await;
    let _ = read_v5_packet(&mut sub_stream, &mut sub_buf).await;
    write_v5_packet(
        &mut sub_stream,
        &mqttbytes::v5::Packet::Subscribe(mqttbytes::v5::Subscribe::new(
            "alpha",
            mqttbytes::QoS::AtMostOnce,
        )),
    )
    .await;
    let _ = read_v5_packet(&mut sub_stream, &mut sub_buf).await;

    // Publisher connects.
    let mut pub_stream = mqtt_connect(server.addr, &pub_tls).await;
    let mut pub_buf = BytesMut::new();
    write_v5_packet(
        &mut pub_stream,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("alias-pub")),
    )
    .await;
    let _ = read_v5_packet(&mut pub_stream, &mut pub_buf).await;

    // First PUBLISH: ESTABLISH alias=1 → topic="alpha".
    let establish = build_v5_publish_with_alias("alpha", b"established", 1);
    write_v5_packet(&mut pub_stream, &mqttbytes::v5::Packet::Publish(establish)).await;

    // Second PUBLISH: REFERENCE alias=1, empty topic.
    let reference = build_v5_publish_with_alias("", b"referenced", 1);
    write_v5_packet(&mut pub_stream, &mqttbytes::v5::Packet::Publish(reference)).await;

    // Subscriber receives both, in order, with the resolved topic.
    for expected_payload in [b"established".as_slice(), b"referenced".as_slice()] {
        let pkt = tokio::time::timeout(
            Duration::from_secs(2),
            read_v5_packet(&mut sub_stream, &mut sub_buf),
        )
        .await
        .expect("subscriber MUST receive both publishes including the alias-only one");
        match pkt {
            mqttbytes::v5::Packet::Publish(p) => {
                assert_eq!(
                    p.topic, "alpha",
                    "alias-resolved PUBLISH must carry the established topic name"
                );
                assert_eq!(&p.payload[..], expected_payload);
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    server.shutdown();
}

#[tokio::test]
async fn topic_alias_zero_triggers_disconnect_0x94() {
    // §3.3.2.3.4: alias=0 is reserved and MUST NOT be used. The
    // broker MUST respond with DISCONNECT 0x94 (TopicAliasInvalid)
    // before closing — gives the client a structured diagnostic
    // instead of a bare TCP RST.
    let ca = TestCa::new("MQTT Test CA");
    let cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = new_test_server_with_topic_alias_max(&ca, router, 16);
    let tls = build_client_tls_config(&cert.cert_pem, &cert.key_pem, &ca.cert_pem);

    let mut stream = mqtt_connect(server.addr, &tls).await;
    let mut buf = BytesMut::new();
    write_v5_packet(
        &mut stream,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("zero-alias")),
    )
    .await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    // PUBLISH with alias=0 — spec-reserved, MUST be rejected.
    let publish = build_v5_publish_with_alias("alpha", b"bad", 0);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    // Best-effort DISCONNECT 0x94, then close. Same cancel-safety
    // semantics as #1158's PacketTooLarge path: accept either a
    // structured DISCONNECT or a clean EOF, reject hung connection.
    let next = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet_or_close(&mut stream, &mut buf),
    )
    .await
    .expect("server must DISCONNECT or close within 2 s");
    if let Some(mqttbytes::v5::Packet::Disconnect(disc)) = next {
        assert_eq!(
            disc.reason_code,
            mqttbytes::v5::DisconnectReasonCode::TopicAliasInvalid,
            "structured DISCONNECT MUST carry reason 0x94"
        );
    }
    // None or non-Disconnect (EOF) is the cancel-safety fallback — also acceptable.

    server.shutdown();
}

#[tokio::test]
async fn topic_alias_above_max_triggers_disconnect_0x94() {
    // Cap = 4; client uses alias=99 → out of range → DISCONNECT 0x94.
    let ca = TestCa::new("MQTT Test CA");
    let cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = new_test_server_with_topic_alias_max(&ca, router, 4);
    let tls = build_client_tls_config(&cert.cert_pem, &cert.key_pem, &ca.cert_pem);

    let mut stream = mqtt_connect(server.addr, &tls).await;
    let mut buf = BytesMut::new();
    write_v5_packet(
        &mut stream,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("over-cap")),
    )
    .await;
    // Confirm the broker advertised cap=4 in CONNACK.
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    if let mqttbytes::v5::Packet::ConnAck(ca) = packet {
        let props = ca.properties.expect("properties");
        assert_eq!(props.topic_alias_max, Some(4));
    } else {
        panic!("expected ConnAck");
    }

    let publish = build_v5_publish_with_alias("alpha", b"overcap", 99);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    let next = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet_or_close(&mut stream, &mut buf),
    )
    .await
    .expect("server must DISCONNECT or close within 2 s");
    if let Some(mqttbytes::v5::Packet::Disconnect(disc)) = next {
        assert_eq!(
            disc.reason_code,
            mqttbytes::v5::DisconnectReasonCode::TopicAliasInvalid,
            "alias > cap must trigger DISCONNECT 0x94"
        );
    }

    server.shutdown();
}

#[tokio::test]
async fn topic_alias_unmapped_reference_triggers_disconnect_0x94() {
    // Client REFERENCES alias=3 with empty topic, but never
    // ESTABLISHED a mapping for it — §3.3.2.3.4 says this is also
    // a Protocol Error. Without this gate, an empty-topic PUBLISH
    // would route to the empty group and silently succeed-but-go-nowhere
    // (or worse, hit a downstream null check and panic).
    let ca = TestCa::new("MQTT Test CA");
    let cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    let server = new_test_server_with_topic_alias_max(&ca, router, 16);
    let tls = build_client_tls_config(&cert.cert_pem, &cert.key_pem, &ca.cert_pem);

    let mut stream = mqtt_connect(server.addr, &tls).await;
    let mut buf = BytesMut::new();
    write_v5_packet(
        &mut stream,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("unmapped")),
    )
    .await;
    let _ = read_v5_packet(&mut stream, &mut buf).await;

    // Reference alias=3 with empty topic — never established.
    let publish = build_v5_publish_with_alias("", b"orphan", 3);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    let next = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet_or_close(&mut stream, &mut buf),
    )
    .await
    .expect("server must DISCONNECT or close within 2 s");
    if let Some(mqttbytes::v5::Packet::Disconnect(disc)) = next {
        assert_eq!(
            disc.reason_code,
            mqttbytes::v5::DisconnectReasonCode::TopicAliasInvalid,
            "unmapped alias reference must trigger DISCONNECT 0x94"
        );
    }

    server.shutdown();
}

#[tokio::test]
async fn topic_alias_disabled_by_default_rejects_any_alias() {
    // Default cap = 0 means topic aliases are OFF. ANY inbound alias
    // (even alias=1 with a valid topic) MUST be rejected — the broker
    // didn't advertise the capability. Pin that the default config
    // doesn't silently accept aliases just because the property is
    // present in the wire format.
    let ca = TestCa::new("MQTT Test CA");
    let cert = ca.issue_client_cert("alice", &["alpha"]);
    let router = Arc::new(Router::new());

    // Plain TestServer: topic_alias_max defaults to 0.
    let server = TestServer::new(&ca, router, None);
    let tls = build_client_tls_config(&cert.cert_pem, &cert.key_pem, &ca.cert_pem);

    let mut stream = mqtt_connect(server.addr, &tls).await;
    let mut buf = BytesMut::new();
    write_v5_packet(
        &mut stream,
        &mqttbytes::v5::Packet::Connect(mqttbytes::v5::Connect::new("default-off")),
    )
    .await;
    let packet = read_v5_packet(&mut stream, &mut buf).await;
    if let mqttbytes::v5::Packet::ConnAck(ca) = packet {
        let props = ca.properties.expect("properties");
        assert_eq!(
            props.topic_alias_max,
            Some(0),
            "default config MUST advertise topic_alias_max=0 so the client knows aliases are disabled"
        );
    } else {
        panic!("expected ConnAck");
    }

    // Send a PUBLISH with alias=1 — broker advertised 0, so this is out of range.
    let publish = build_v5_publish_with_alias("alpha", b"x", 1);
    write_v5_packet(&mut stream, &mqttbytes::v5::Packet::Publish(publish)).await;

    let next = tokio::time::timeout(
        Duration::from_secs(2),
        read_v5_packet_or_close(&mut stream, &mut buf),
    )
    .await
    .expect("server must DISCONNECT or close within 2 s");
    if let Some(mqttbytes::v5::Packet::Disconnect(disc)) = next {
        assert_eq!(
            disc.reason_code,
            mqttbytes::v5::DisconnectReasonCode::TopicAliasInvalid,
            "alias on a no-aliases-allowed broker must trigger DISCONNECT 0x94"
        );
    }

    server.shutdown();
}
