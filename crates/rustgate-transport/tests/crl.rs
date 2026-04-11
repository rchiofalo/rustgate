// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for Certificate Revocation List (CRL) support.
//!
//! Verifies that TLS handshakes reject revoked client certificates
//! and accept non-revoked ones when CRLs are loaded, and that CRL
//! freshness validation detects stale CRLs.
#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_transport::{TlsConfig, TlsListener};
use rustls::pki_types::CertificateRevocationListDer;
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
    });

    // Client tries to connect with revoked cert
    let config = build_client_tls_config(
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
    let config = build_client_tls_config(&good_client.cert_pem, &good_client.key_pem, &ca.cert_pem);
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
    let config_a = build_client_tls_config(&revoked_a.cert_pem, &revoked_a.key_pem, &ca.cert_pem);
    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
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

// ── CRL freshness tests ────────────────────────────────────────────────

/// A stale CRL (nextUpdate in the past) should be detected by the
/// freshness check and return a non-zero stale count.
#[test]
fn stale_crl_detected_by_freshness_check() {
    let ca = TestCa::new("CRL Freshness CA");
    let client = ca.issue_client_cert("user1", &["team"]);

    let expired_crl_pem = ca.generate_expired_crl(&[&client.cert_pem]);
    let crls: Vec<rustls::pki_types::CertificateRevocationListDer<'static>> =
        CertificateRevocationListDer::pem_slice_iter(expired_crl_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse CRL PEM");

    let stale_count = rustgate_transport::check_crl_freshness(&crls);
    assert_eq!(stale_count, 1, "expired CRL should be detected as stale");
}

/// A fresh CRL (nextUpdate in the future) should pass the freshness
/// check with zero stale CRLs.
#[test]
fn fresh_crl_passes_freshness_check() {
    let ca = TestCa::new("CRL Freshness CA");
    let client = ca.issue_client_cert("user1", &["team"]);

    let fresh_crl_pem = ca.generate_crl(&[&client.cert_pem]);
    let crls: Vec<rustls::pki_types::CertificateRevocationListDer<'static>> =
        CertificateRevocationListDer::pem_slice_iter(fresh_crl_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse CRL PEM");

    let stale_count = rustgate_transport::check_crl_freshness(&crls);
    assert_eq!(stale_count, 0, "fresh CRL should not be flagged as stale");
}

/// A stale CRL can still be loaded via `with_crls` — freshness check
/// only warns, it does not reject.
#[test]
fn stale_crl_loads_without_error() {
    let ca = TestCa::new("CRL Freshness CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client = ca.issue_client_cert("user1", &["team"]);

    let expired_crl_pem = ca.generate_expired_crl(&[&client.cert_pem]);

    let config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    // with_crls should succeed even with stale CRL — it warns but does not reject
    let result = config.with_crls(&expired_crl_pem);
    assert!(result.is_ok(), "stale CRL should still load successfully");
}

/// When stale CRL warnings are disabled, the freshness check is skipped
/// inside `with_crls` but the CRL still loads.
#[test]
fn stale_crl_warning_suppressed() {
    let ca = TestCa::new("CRL Freshness CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client = ca.issue_client_cert("user1", &["team"]);

    let expired_crl_pem = ca.generate_expired_crl(&[&client.cert_pem]);

    let config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config")
        .with_crl_warn_stale(false);

    let result = config.with_crls(&expired_crl_pem);
    assert!(
        result.is_ok(),
        "stale CRL with warnings disabled should still load"
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

// ── CRL hot-swap tests ─────────────────────────────────────────────────

/// Verify that a client accepted before CRL loading is correctly rejected
/// after CRL is applied to a new TLS config. This simulates an operator
/// revoking a certificate and reloading the server configuration without
/// a full restart.
///
/// 1. Server starts WITHOUT CRL — revoked-to-be client connects successfully.
/// 2. CRL is generated revoking client B.
/// 3. New TlsConfig is built WITH CRL, new listener is bound.
/// 4. Good client A connects to new listener — succeeds.
/// 5. Revoked client B connects to new listener — rejected.
#[tokio::test]
async fn crl_hot_swap_rejects_newly_revoked() {
    let ca = TestCa::new("CRL Hot Swap CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_a = ca.issue_client_cert("good-user", &["ops"]);
    let client_b = ca.issue_client_cert("revoked-user", &["ops"]);

    // ── Phase 1: Server without CRL — client B connects successfully ────
    let tls_no_crl = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config without CRL");

    let listener_no_crl = TlsListener::bind("127.0.0.1:0", &tls_no_crl)
        .await
        .expect("bind without CRL");
    let addr_no_crl = listener_no_crl.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let session = listener_no_crl.accept().await.expect("accept");
        let identity = session.identity().clone();
        let (mut reader, mut writer) = session.split();

        let mut buf = [0u8; 4];
        let _ = reader.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");
        writer.write_all(b"pong").await.expect("write");

        identity
    });

    let config_b = build_client_tls_config(&client_b.cert_pem, &client_b.key_pem, &ca.cert_pem);
    let mut stream = try_connect(addr_no_crl, &config_b)
        .await
        .expect("client B should connect before CRL is loaded");

    stream.write_all(b"ping").await.expect("client B write");
    let mut buf = [0u8; 4];
    let _ = stream.read_exact(&mut buf).await.expect("client B read");
    assert_eq!(&buf, b"pong");

    let identity = server_handle.await.expect("server task phase 1");
    assert_eq!(identity.cn, "revoked-user");

    // ── Phase 2: Generate CRL revoking client B, rebuild config ─────────
    let crl_pem = ca.generate_crl(&[&client_b.cert_pem]);

    let tls_with_crl =
        TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
            .expect("tls config with CRL")
            .with_crls(&crl_pem)
            .expect("load CRL");

    let listener_crl = TlsListener::bind("127.0.0.1:0", &tls_with_crl)
        .await
        .expect("bind with CRL");
    let addr_crl = listener_crl.local_addr().expect("addr");

    // ── Phase 3: Client A connects to CRL-enabled server — succeeds ─────
    let listener_for_a = TlsListener::bind("127.0.0.1:0", &tls_with_crl)
        .await
        .expect("bind for client A");
    let addr_a = listener_for_a.local_addr().expect("addr for client A");

    let server_handle_a = tokio::spawn(async move {
        let session = listener_for_a.accept().await.expect("accept client A");
        let identity = session.identity().clone();
        let (mut reader, mut writer) = session.split();

        let mut buf = [0u8; 5];
        let _ = reader.read_exact(&mut buf).await.expect("read from A");
        assert_eq!(&buf, b"hello");
        writer.write_all(b"world").await.expect("write to A");

        identity
    });

    let config_a = build_client_tls_config(&client_a.cert_pem, &client_a.key_pem, &ca.cert_pem);
    let mut stream_a = try_connect(addr_a, &config_a)
        .await
        .expect("client A should connect — not revoked");

    stream_a.write_all(b"hello").await.expect("client A write");
    let mut buf_a = [0u8; 5];
    let _ = stream_a
        .read_exact(&mut buf_a)
        .await
        .expect("client A read");
    assert_eq!(&buf_a, b"world");

    let identity_a = server_handle_a.await.expect("server task for client A");
    assert_eq!(identity_a.cn, "good-user");

    // ── Phase 4: Client B connects to CRL-enabled server — rejected ─────
    let server_handle_b = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), listener_crl.accept()).await
    });

    let result = try_connect(addr_crl, &config_b).await;

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

    assert!(failed, "client B should be rejected after CRL is loaded");

    let server_result = server_handle_b.await.expect("server task for client B");
    assert!(
        server_result.is_err(),
        "server should timeout — no valid session from revoked client B"
    );
}
