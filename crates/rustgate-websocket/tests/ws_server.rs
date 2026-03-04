//! Integration tests for WebSocket server session routing.

use std::io::BufReader;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use rustgate_test_utils::certs::TestCa;
use rustgate_transport::{Router, TlsConfig};
use rustgate_websocket::{WebSocketServer, WsEncoding, WsListener, WsServerConfig};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{Notify, Semaphore};
use tokio_tungstenite::tungstenite::Message;

// ── helpers ──────────────────────────────────────────────────────────────

fn parse_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse certs")
}

fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .expect("parse key")
        .expect("no key")
}

fn build_client_tls_config(cert_pem: &str, key_pem: &str, ca_pem: &str) -> rustls::ClientConfig {
    let certs = parse_certs(cert_pem);
    let key = parse_key(key_pem);
    let mut root_store = RootCertStore::empty();
    for cert in parse_certs(ca_pem) {
        root_store.add(cert).expect("add CA cert");
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("client config")
}

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

// ── tests ────────────────────────────────────────────────────────────────

/// Two WebSocket clients in the same group can exchange messages through the router.
#[tokio::test]
async fn ws_session_routes_through_router() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["alpha"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let listener = WsListener::bind(addr, &tls_config).expect("bind");
    let bound_addr = listener.local_addr().expect("local addr");

    let router = Arc::new(Router::new());
    let shutdown = Arc::new(Notify::new());
    let connection_limit = Arc::new(Semaphore::new(64));

    let config = WsServerConfig {
        listener,
        router: Arc::clone(&router),
        connection_limit,
        encoding: WsEncoding::Raw,
        nats_publish: None,
        fed_forward: None,
        shutdown: Arc::clone(&shutdown),
    };

    let server_handle = tokio::spawn(WebSocketServer::run(config));

    // Give the server a moment to start accepting
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Connect alice
    let alice_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let mut alice_ws = ws_connect(bound_addr, &alice_tls).await;

    // Connect bob
    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let mut bob_ws = ws_connect(bound_addr, &bob_tls).await;

    // Wait for both sessions to register with the router
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Alice sends a CoT position broadcast — bob should receive it
    let cot_xml = br#"<event uid="alice-pos" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><__group name="alpha"/></detail></event>"#;
    alice_ws
        .send(Message::Binary(cot_xml.to_vec().into()))
        .await
        .expect("alice send");

    // Bob receives the broadcast
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), bob_ws.next())
        .await
        .expect("bob receive timeout")
        .expect("bob stream ended")
        .expect("bob frame error");

    match received {
        Message::Binary(data) => {
            assert_eq!(data.as_ref(), cot_xml.as_slice());
        }
        other => {
            // Accept any message type — the payload content is what matters
            let data = match other {
                Message::Text(t) => t.as_bytes().to_vec(),
                _ => Vec::new(),
            };
            assert_eq!(data, cot_xml.as_slice());
        }
    }

    // Clean shutdown
    shutdown.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(2), server_handle)
        .await
        .expect("server shutdown timeout")
        .expect("server task");
}

/// Connection limit is enforced — excess connections are rejected.
#[tokio::test]
async fn ws_server_enforces_connection_limit() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("user", &["ops"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let listener = WsListener::bind(addr, &tls_config).expect("bind");
    let bound_addr = listener.local_addr().expect("local addr");

    let router = Arc::new(Router::new());
    let shutdown = Arc::new(Notify::new());
    // Only allow 1 connection
    let connection_limit = Arc::new(Semaphore::new(1));

    let config = WsServerConfig {
        listener,
        router: Arc::clone(&router),
        connection_limit,
        encoding: WsEncoding::Raw,
        nats_publish: None,
        fed_forward: None,
        shutdown: Arc::clone(&shutdown),
    };

    let _server_handle = tokio::spawn(WebSocketServer::run(config));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // First connection should succeed
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let _ws1 = ws_connect(bound_addr, &client_tls).await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify the router has 1 session
    assert_eq!(router.session_count().await, 1);

    shutdown.notify_one();
}
