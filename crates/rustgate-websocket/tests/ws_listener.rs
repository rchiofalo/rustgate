// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for WebSocket listener with mTLS authentication.

use std::sync::Arc;

use futures::SinkExt;
use futures::stream::StreamExt;
use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::TlsConfig;
use rustgate_websocket::WsListener;
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

// ── tests ────────────────────────────────────────────────────────────────

/// Full mTLS + WebSocket roundtrip: connect, exchange messages, verify identity.
#[tokio::test]
async fn ws_mtls_handshake_and_identity() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["engineers", "admins"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let listener = WsListener::bind(addr, &tls_config).expect("bind");
    let bound_addr = listener.local_addr().expect("local addr");

    let server_handle = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept");
        let identity = session.identity().clone();

        let mut ws = session.into_stream();
        let msg = ws.next().await.expect("recv").expect("msg");
        assert_eq!(msg, Message::Text("hello".into()));

        ws.send(Message::Text("world".into())).await.expect("send");

        identity
    });

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut ws = ws_connect(bound_addr, &client_tls).await;

    ws.send(Message::Text("hello".into())).await.expect("send");

    let reply = ws.next().await.expect("recv").expect("msg");
    assert_eq!(reply, Message::Text("world".into()));

    let identity = server_handle.await.expect("server task");
    assert_eq!(&*identity.cn, "alice");
    assert_eq!(identity.groups.len(), 2);
    assert!(identity.is_member_of("engineers"));
    assert!(identity.is_member_of("admins"));
    assert!(!identity.fingerprint.is_empty());
}

/// Client cert signed by a different CA must be rejected at the TLS layer.
#[tokio::test]
async fn ws_rejects_untrusted_client() {
    let server_ca = TestCa::new("Server CA");
    let rogue_ca = TestCa::new("Rogue CA");

    let server_cert = server_ca.issue_server_cert("localhost", &["localhost"]);
    let rogue_cert = rogue_ca.issue_client_cert("mallory", &["hackers"]);

    let tls_config = TlsConfig::from_pem(
        &server_cert.cert_pem,
        &server_cert.key_pem,
        &server_ca.cert_pem,
    )
    .expect("tls config");

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let listener = WsListener::bind(addr, &tls_config).expect("bind");
    let bound_addr = listener.local_addr().expect("local addr");

    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
    });

    // Client trusts the server CA but presents a cert from a different CA
    let client_tls = build_client_tls_config(
        &rogue_cert.cert_pem,
        &rogue_cert.key_pem,
        &server_ca.cert_pem,
    );

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
    let tcp = tokio::net::TcpStream::connect(bound_addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let tls_result = connector.connect(server_name, tcp).await;

    // TLS handshake should fail (or connection should be unusable)
    let failed = match tls_result {
        Err(_) => true,
        Ok(mut stream) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if stream.write_all(b"x").await.is_err() || stream.flush().await.is_err() {
                true
            } else {
                let mut buf = [0u8; 1];
                match tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => true,
                    Ok(Ok(_)) => false,
                }
            }
        }
    };

    assert!(failed, "untrusted client should not be able to communicate");

    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err(),
        "server should timeout \u{2014} no valid session"
    );
}

/// Expired client cert must be rejected at the TLS layer.
#[tokio::test]
async fn ws_rejects_expired_client_cert() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let expired_cert = ca.issue_expired_client_cert("expired-user", &["ops"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let listener = WsListener::bind(addr, &tls_config).expect("bind");
    let bound_addr = listener.local_addr().expect("local addr");

    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
    });

    let client_tls =
        build_client_tls_config(&expired_cert.cert_pem, &expired_cert.key_pem, &ca.cert_pem);

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
    let tcp = tokio::net::TcpStream::connect(bound_addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let tls_result = connector.connect(server_name, tcp).await;

    let failed = match tls_result {
        Err(_) => true,
        Ok(mut stream) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if stream.write_all(b"x").await.is_err() || stream.flush().await.is_err() {
                true
            } else {
                let mut buf = [0u8; 1];
                match tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => true,
                    Ok(Ok(_)) => false,
                }
            }
        }
    };

    assert!(failed, "expired client cert should be rejected");

    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err(),
        "server should timeout \u{2014} no valid session from expired cert"
    );
}

/// Multiple clients connect sequentially with distinct identities.
#[tokio::test]
async fn ws_accept_multiple_clients() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["bravo"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let listener = WsListener::bind(addr, &tls_config).expect("bind");
    let bound_addr = listener.local_addr().expect("local addr");

    let server_handle = tokio::spawn(async move {
        let s1 = listener.accept().await.expect("accept alice");
        let cn1 = s1.identity().cn.clone();
        let groups1 = s1.identity().groups.clone();
        drop(s1);

        let s2 = listener.accept().await.expect("accept bob");
        let cn2 = s2.identity().cn.clone();
        let groups2 = s2.identity().groups.clone();

        (cn1, groups1, cn2, groups2)
    });

    let alice_tls =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let ws1 = ws_connect(bound_addr, &alice_tls).await;

    // Give server time to process before dropping
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(ws1);

    let bob_tls = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let _ws2 = ws_connect(bound_addr, &bob_tls).await;

    let (cn1, groups1, cn2, groups2) = server_handle.await.expect("server task");
    assert_eq!(&*cn1, "alice");
    assert!(groups1.contains("alpha"));
    assert_eq!(&*cn2, "bob");
    assert!(groups2.contains("bravo"));
}
