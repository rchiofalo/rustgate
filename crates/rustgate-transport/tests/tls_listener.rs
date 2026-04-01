//! Integration tests for TLS listener with mTLS authentication.

use std::sync::Arc;

use rustgate_test_utils::certs::TestCa;
use rustgate_transport::{TlsConfig, TlsListener, extract_identity};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── helpers ──────────────────────────────────────────────────────────────

fn parse_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse certs")
}

fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).expect("parse key")
}

fn build_client_config(cert_pem: &str, key_pem: &str, ca_pem: &str) -> rustls::ClientConfig {
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

    let config = build_client_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
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

    let config = build_client_config(
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

    let alice_config = build_client_config(&alice_cert.cert_pem, &alice_cert.key_pem, &ca.cert_pem);
    let _stream1 = connect(addr, &alice_config).await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(_stream1);

    let bob_config = build_client_config(&bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem);
    let _stream2 = connect(addr, &bob_config).await;

    let (cn1, cn2) = server_handle.await.expect("server task");
    assert_eq!(cn1, "alice");
    assert_eq!(cn2, "bob");
}
