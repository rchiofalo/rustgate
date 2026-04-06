//! Integration tests for TLS listener with mTLS authentication.

use std::sync::Arc;

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::{build_client_tls_config, parse_certs, parse_key};
use rustgate_transport::{
    ExpectedKeyUsage, TlsConfig, TlsListener, TlsMinVersion, extract_identity, validate_key_usage,
};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn connect(
    addr: std::net::SocketAddr,
    config: &rustls::ClientConfig,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config.clone()));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect")
}

// ── identity extraction ──────────────────────────────────────────────────

/// A client cert with no OU fields should produce an identity with zero groups.
#[test]
fn extract_identity_no_groups() {
    let ca = TestCa::new("Test CA");
    let cert = ca.issue_client_cert("solo-operator", &[]);
    let certs = parse_certs(&cert.cert_pem);
    let identity = extract_identity(certs.first().expect("no cert")).expect("extract");

    assert_eq!(identity.cn, "solo-operator");
    assert!(identity.groups.is_empty());
}

/// A cert with no Common Name must produce an error, not panic.
#[test]
fn extract_identity_no_cn_returns_error() {
    let ca = TestCa::new("Test CA");
    let cert = ca.issue_client_cert_no_cn();
    let certs = parse_certs(&cert.cert_pem);
    let result = extract_identity(certs.first().expect("no cert"));

    assert!(result.is_err(), "missing CN should return Err");
}

// ── mTLS handshake ───────────────────────────────────────────────────────

/// Full mTLS roundtrip: connect, exchange bytes, verify identity on server side.
#[tokio::test]
async fn mtls_handshake_and_identity() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["engineers", "admins"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept");
        let identity = session.identity().clone();
        let (mut reader, mut writer) = session.split();

        let mut buf = [0u8; 5];
        let _ = reader.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"hello");
        writer.write_all(b"world").await.expect("write");

        identity
    });

    let config = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = connect(addr, &config).await;

    stream.write_all(b"hello").await.expect("client write");
    let mut buf = [0u8; 5];
    let _ = stream.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"world");

    let identity = server_handle.await.expect("server task");
    assert_eq!(identity.cn, "alice");
    assert_eq!(identity.groups.len(), 2);
    assert!(identity.is_member_of("engineers"));
    assert!(identity.is_member_of("admins"));
    assert!(!identity.fingerprint.is_empty());
}

/// Untrusted client cert (signed by a different CA) must be rejected.
#[tokio::test]
async fn mtls_rejects_untrusted_client() {
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

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
    });

    let config = build_client_tls_config(
        &rogue_cert.cert_pem,
        &rogue_cert.key_pem,
        &server_ca.cert_pem,
    );
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let result = connector.connect(server_name, tcp).await;

    let failed = match result {
        Err(_) => true,
        Ok(mut stream) => {
            // TLS 1.3 may defer the alert — try using the connection
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
        "server should timeout — no valid session"
    );
}

/// Accept multiple clients sequentially through the same listener.
#[tokio::test]
async fn accept_multiple_clients_sequentially() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let alice_cert = ca.issue_client_cert("alice", &["alpha"]);
    let bob_cert = ca.issue_client_cert("bob", &["bravo"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let s1 = listener.accept().await.expect("accept alice");
        let cn1 = s1.identity().cn.clone();
        drop(s1);

        let s2 = listener.accept().await.expect("accept bob");
        let cn2 = s2.identity().cn.clone();

        (cn1, cn2)
    });

    let alice_config =
        build_client_tls_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let _stream1 = connect(addr, &alice_config).await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(_stream1);

    let bob_config = build_client_tls_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let _stream2 = connect(addr, &bob_config).await;

    let (cn1, cn2) = server_handle.await.expect("server task");
    assert_eq!(cn1, "alice");
    assert_eq!(cn2, "bob");
}

// ── handshake concurrency limiting ──────────────────────────────────────

/// With `max_concurrent_handshakes = 1`, a second handshake must wait until
/// the first completes. Verify that both connections eventually succeed.
#[tokio::test]
async fn handshake_concurrency_limit_allows_sequential() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["alpha"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    // Only 1 handshake at a time.
    let listener = TlsListener::bind_with_handshake_limit("127.0.0.1:0", &tls_config, 1)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let s1 = listener.accept().await.expect("accept first");
        let cn1 = s1.identity().cn.clone();
        drop(s1);

        let s2 = listener.accept().await.expect("accept second");
        let cn2 = s2.identity().cn.clone();
        (cn1, cn2)
    });

    let config = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);

    // First connection succeeds immediately.
    let _stream1 = connect(addr, &config).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(_stream1);

    // Second connection succeeds after the first slot frees up.
    let _stream2 = connect(addr, &config).await;

    let (cn1, cn2) = server_handle.await.expect("server task");
    assert_eq!(cn1, "alice");
    assert_eq!(cn2, "alice");
}

/// With a handshake limit of 1, two simultaneous handshakes are serialized
/// but both eventually complete.
#[tokio::test]
async fn handshake_concurrency_limit_serializes_parallel_connections() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let alice = ca.issue_client_cert("alice", &["team"]);
    let bob = ca.issue_client_cert("bob", &["team"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    let listener = TlsListener::bind_with_handshake_limit("127.0.0.1:0", &tls_config, 1)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let mut names = Vec::new();
        for _ in 0..2 {
            let session = listener.accept().await.expect("accept");
            names.push(session.identity().cn.clone());
        }
        names
    });

    let alice_config = build_client_tls_config(&alice.cert_pem, &alice.key_pem, &ca.cert_pem);
    let bob_config = build_client_tls_config(&bob.cert_pem, &bob.key_pem, &ca.cert_pem);

    // Spawn two connections concurrently; the semaphore serializes handshakes.
    let (a, b) = tokio::join!(connect(addr, &alice_config), connect(addr, &bob_config),);
    let _stream_a = a;
    let _stream_b = b;

    let names = server_handle.await.expect("server task");
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"alice".to_string()));
    assert!(names.contains(&"bob".to_string()));
}

/// Verify the default `bind` constructor still works (backwards compatibility).
#[tokio::test]
async fn bind_default_handshake_limit() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("charlie", &[]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    // Use the original `bind` (no explicit limit) — should still work.
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept");
        session.identity().cn.clone()
    });

    let config = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let _stream = connect(addr, &config).await;

    let cn = server_handle.await.expect("server task");
    assert_eq!(cn, "charlie");
}

// ── TLS version enforcement ─────────────────────────────────────────────

/// TLS 1.3-only server rejects clients that can only speak TLS 1.2.
#[tokio::test]
async fn tls13_only_rejects_tls12_client() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["team"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config")
        .with_tls_min_version(TlsMinVersion::Tls13);

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept()).await
    });

    // Build a client config that only supports TLS 1.2
    let certs = parse_certs(&client_cert.cert_pem);
    let key = parse_key(&client_cert.key_pem);
    let mut root_store = RootCertStore::empty();
    for cert in parse_certs(&ca.cert_pem) {
        root_store.add(cert).expect("add CA cert");
    }
    let client_config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)
            .expect("client config");

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let result = connector.connect(server_name, tcp).await;

    assert!(
        result.is_err(),
        "TLS 1.2-only client should fail against TLS 1.3-only server"
    );

    // Server should time out since no valid session was established
    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err(),
        "server should timeout — no valid TLS 1.3 session"
    );
}

/// TLS 1.3-only server accepts clients that support TLS 1.3.
#[tokio::test]
async fn tls13_only_accepts_tls13_client() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["team"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config")
        .with_tls_min_version(TlsMinVersion::Tls13);

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept");
        session.identity().cn.clone()
    });

    // Build a client config that supports TLS 1.3
    let config = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut stream = connect(addr, &config).await;
    stream.write_all(b"ping").await.expect("client write");

    let cn = server_handle.await.expect("server task");
    assert_eq!(cn, "alice");
}

// ── Key usage validation ────────────────────────────────────────────────

/// Client certificate with ClientAuth EKU passes validation.
#[test]
fn validate_key_usage_client_auth_accepted() {
    let ca = TestCa::new("Test CA");
    let cert = ca.issue_client_cert("alice", &["team"]);
    let certs = parse_certs(&cert.cert_pem);

    let result = validate_key_usage(
        certs.first().expect("no cert"),
        ExpectedKeyUsage::ClientAuth,
    );
    assert!(
        result.is_ok(),
        "ClientAuth cert should pass ClientAuth validation"
    );
}

/// Server certificate with ServerAuth EKU passes validation.
#[test]
fn validate_key_usage_server_auth_accepted() {
    let ca = TestCa::new("Test CA");
    let cert = ca.issue_server_cert("localhost", &["localhost"]);
    let certs = parse_certs(&cert.cert_pem);

    let result = validate_key_usage(
        certs.first().expect("no cert"),
        ExpectedKeyUsage::ServerAuth,
    );
    assert!(
        result.is_ok(),
        "ServerAuth cert should pass ServerAuth validation"
    );
}

/// Server-auth-only certificate is rejected when ClientAuth is expected.
#[test]
fn validate_key_usage_rejects_server_cert_as_client() {
    let ca = TestCa::new("Test CA");
    let cert = ca.issue_server_auth_only_cert("bad-client");
    let certs = parse_certs(&cert.cert_pem);

    let result = validate_key_usage(
        certs.first().expect("no cert"),
        ExpectedKeyUsage::ClientAuth,
    );
    assert!(
        result.is_err(),
        "ServerAuth-only cert should fail ClientAuth validation"
    );
}

/// Client-auth-only certificate is rejected when ServerAuth is expected.
#[test]
fn validate_key_usage_rejects_client_cert_as_server() {
    let ca = TestCa::new("Test CA");
    let cert = ca.issue_client_cert("alice", &[]);
    let certs = parse_certs(&cert.cert_pem);

    let result = validate_key_usage(
        certs.first().expect("no cert"),
        ExpectedKeyUsage::ServerAuth,
    );
    assert!(
        result.is_err(),
        "ClientAuth-only cert should fail ServerAuth validation"
    );
}

/// Server-auth-only certificate is rejected during mTLS handshake identity extraction.
#[tokio::test]
async fn mtls_rejects_server_auth_only_client_cert() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    // Issue a cert with ServerAuth EKU — wrong for a client
    let bad_client_cert = ca.issue_server_auth_only_cert("bad-client");

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        // The server should reject — either at handshake or identity extraction
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
    });

    let config = build_client_tls_config(
        &bad_client_cert.cert_pem,
        &bad_client_cert.key_pem,
        &ca.cert_pem,
    );
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    // The connection may succeed at TLS level (rustls doesn't check EKU by default)
    // but our identity extraction should reject it
    let _client_result = connector.connect(server_name, tcp).await;

    let server_result = server_handle.await.expect("server task");
    // Server should return an error from identity extraction (key usage validation)
    // or time out if the handshake itself was rejected.
    let rejected = match server_result {
        Ok(Err(e)) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("Extended Key Usage"),
                "error should mention Extended Key Usage, got: {msg}"
            );
            true
        }
        Ok(Ok(_)) => false,
        Err(_) => true, // Timeout — handshake rejected at TLS level
    };
    assert!(
        rejected,
        "server should reject server-auth-only client cert"
    );
}

// ── Session resumption ─────────────────────────────────────────────────

/// Verify that the server disables TLS session resumption (session tickets),
/// forcing a full mTLS handshake on every connection. We check this by
/// inspecting `handshake_kind()` on the client connection — both connections
/// must report `HandshakeKind::Full`, not `HandshakeKind::Resumed`.
#[tokio::test]
async fn tls_session_resumption_disabled() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["operators"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let s1 = listener.accept().await.expect("accept first");
        let id1 = s1.identity().clone();
        drop(s1);

        let s2 = listener.accept().await.expect("accept second");
        let id2 = s2.identity().clone();

        (id1, id2)
    });

    // Build a single client config — rustls enables session caching by default
    // via `Resumption::in_memory_sessions(256)`. If the server allowed session
    // tickets, the second connection would resume without a full handshake.
    let config = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);

    // First connection: must be a full handshake.
    let stream1 = connect(addr, &config).await;
    let kind1 = stream1.get_ref().1.handshake_kind();
    assert_eq!(
        kind1,
        Some(rustls::HandshakeKind::Full),
        "first connection must be a full handshake, got {kind1:?}"
    );
    drop(stream1);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Second connection with the same config: must ALSO be a full handshake
    // because the server does not issue session tickets (NoServerSessionStorage).
    let stream2 = connect(addr, &config).await;
    let kind2 = stream2.get_ref().1.handshake_kind();
    assert_eq!(
        kind2,
        Some(rustls::HandshakeKind::Full),
        "second connection must be a full handshake (no resumption), got {kind2:?}"
    );
    drop(stream2);

    let (id1, id2) = server_handle.await.expect("server task");

    // Both connections extracted valid identities.
    assert_eq!(id1.cn, "alice");
    assert!(id1.is_member_of("operators"));
    assert_eq!(id2.cn, "alice");
    assert!(id2.is_member_of("operators"));
    assert_eq!(id1.fingerprint, id2.fingerprint);
}
