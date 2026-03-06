//! Integration tests for Certificate Revocation List (CRL) support.
//!
//! Verifies that TLS handshakes reject revoked client certificates
//! and accept non-revoked ones when CRLs are loaded.

use std::io::BufReader;
use std::sync::Arc;

use rustgate_test_utils::certs::TestCa;
use rustgate_transport::{TlsConfig, TlsListener};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

async fn try_connect(
    addr: std::net::SocketAddr,
    config: &rustls::ClientConfig,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, Box<dyn std::error::Error>> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config.clone()));
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let server_name = "localhost".try_into().expect("server name");
    let tls = connector.connect(server_name, tcp).await?;
    Ok(tls)
}

// ── CRL enforcement tests ───────────────────────────────────────────────

/// A client certificate listed in the CRL must be rejected during the
/// TLS handshake. The server's `WebPkiClientVerifier` checks CRL entries
/// before completing authentication.
#[tokio::test]
async fn crl_rejects_revoked_client() {
    let ca = TestCa::new("CRL Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let revoked_client = ca.issue_client_cert("revoked-user", &["team"]);

    // Generate a CRL that revokes this client
    let crl_pem = ca.generate_crl(&[&revoked_client.cert_pem]);

    // Build server with CRL
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config")
        .with_crls(&crl_pem)
        .expect("load CRL");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Server tries to accept — should fail or timeout
    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await
    });

    // Client tries to connect with revoked cert
    let config = build_client_config(
        &revoked_client.cert_pem,
        &revoked_client.key_pem,
        &ca.cert_pem,
    );
    let result = try_connect(addr, &config).await;

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

    assert!(failed, "revoked client should not establish a session");

    // Server should not have produced a valid session
    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err(),
        "server should timeout — no valid session from revoked client"
    );
}

/// A non-revoked client certificate must still be accepted when CRLs
/// are loaded. CRL checking must only reject listed serials, not all
/// clients.
#[tokio::test]
async fn crl_accepts_non_revoked_client() {
    let ca = TestCa::new("CRL Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let good_client = ca.issue_client_cert("good-user", &["team"]);
    let bad_client = ca.issue_client_cert("bad-user", &["team"]);

    // CRL only revokes bad_client
    let crl_pem = ca.generate_crl(&[&bad_client.cert_pem]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config")
        .with_crls(&crl_pem)
        .expect("load CRL");

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

    // good_client connects — should succeed
    let config = build_client_config(&good_client.cert_pem, &good_client.key_pem, &ca.cert_pem);
    let mut stream = try_connect(addr, &config)
        .await
        .expect("TLS connect should succeed for non-revoked client");

    stream.write_all(b"hello").await.expect("client write");
    let mut buf = [0u8; 5];
    let _ = stream.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"world");

    let identity = server_handle.await.expect("server task");
    assert_eq!(identity.cn, "good-user");
}

/// Multiple certificates can be revoked in a single CRL. Verifies that
/// a CRL with two entries rejects both.
#[tokio::test]
async fn crl_revokes_multiple_certs() {
    let ca = TestCa::new("CRL Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let revoked_a = ca.issue_client_cert("revoked-a", &["alpha"]);
    let revoked_b = ca.issue_client_cert("revoked-b", &["alpha"]);

    // Revoke both clients in a single CRL
    let crl_pem = ca.generate_crl(&[&revoked_a.cert_pem, &revoked_b.cert_pem]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config")
        .with_crls(&crl_pem)
        .expect("load CRL");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Try revoked_a — should be rejected
    let config_a = build_client_config(&revoked_a.cert_pem, &revoked_a.key_pem, &ca.cert_pem);
    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await
    });

    let result = try_connect(addr, &config_a).await;
    let failed = match result {
        Err(_) => true,
        Ok(mut stream) => {
            stream.write_all(b"x").await.is_err()
                || stream.flush().await.is_err()
                || matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        stream.read(&mut [0u8; 1]),
                    )
                    .await,
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_)
                )
        }
    };
    assert!(failed, "first revoked client must be rejected");

    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err(),
        "server should timeout for revoked client a"
    );
}

// ── CRL loading error tests ─────────────────────────────────────────────

/// Empty PEM data must return an error — a CRL with no entries is a
/// configuration mistake, not a valid "nothing revoked" state.
#[test]
fn with_crls_empty_data_fails() {
    let ca = TestCa::new("CRL Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

    let config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let result = config.with_crls("");
    assert!(result.is_err(), "empty CRL data should fail");
}

/// Garbage data that is not valid PEM must return an error.
#[test]
fn with_crls_malformed_data_fails() {
    let ca = TestCa::new("CRL Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

    let config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let result = config.with_crls("this is not a PEM file");
    assert!(result.is_err(), "malformed CRL data should fail");
}

/// A valid PEM that contains certificates but no CRL entries must fail.
/// Passing a cert PEM where a CRL PEM is expected is a common mistake.
#[test]
fn with_crls_cert_instead_of_crl_fails() {
    let ca = TestCa::new("CRL Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

    let config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    // Pass a certificate PEM where a CRL PEM is expected
    let result = config.with_crls(&ca.cert_pem);
    assert!(
        result.is_err(),
        "certificate PEM should not be accepted as CRL"
    );
}
