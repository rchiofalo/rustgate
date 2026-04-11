// Copyright © 2026 Roberto Chiofalo.

//! FIPS 140-3 crypto provider integration tests.
//!
//! These tests verify that the aws-lc-rs FIPS provider installs correctly
//! and that TLS handshakes work with the FIPS-validated backend.
//!
//! Only compiled when the `fips` feature is enabled. Run with:
//! ```sh
//! cargo test -p rustgate-transport --features fips
//! ```
#![cfg(feature = "fips")]

use std::sync::{Arc, OnceLock};

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_transport::{TlsConfig, TlsListener, install_fips_provider, is_fips_provider_active};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── setup ────────────────────────────────────────────────────────────────

/// Install the FIPS provider exactly once across all tests in this binary.
///
/// Must be called before `TestCa::new()` to ensure aws-lc-rs is the active
/// provider. The test-utils `ensure_crypto_provider()` will silently skip
/// installing ring because a provider is already installed.
static FIPS_INIT: OnceLock<()> = OnceLock::new();
fn ensure_fips() {
    let _ = FIPS_INIT.get_or_init(|| {
        install_fips_provider().expect("failed to install FIPS provider");
    });
}

// ── FIPS provider tests ─────────────────────────────────────────────────

/// After installing the FIPS provider, a second `install_fips_provider()`
/// must return an error because `CryptoProvider::install_default` only
/// permits one installation per process.
#[test]
fn fips_double_install_returns_error() {
    ensure_fips();

    let result = install_fips_provider();
    assert!(
        result.is_err(),
        "second install_fips_provider() should return Err"
    );
}

/// After installing the FIPS provider, `is_fips_provider_active()` must
/// return `true`. This is the gatekeeper function for `--fips-required`.
#[test]
fn fips_provider_reports_active() {
    ensure_fips();
    assert!(
        is_fips_provider_active(),
        "is_fips_provider_active() must return true after install_fips_provider()"
    );
}

/// Verify the installed provider self-reports as FIPS via the rustls API.
#[test]
fn fips_provider_reports_fips_mode() {
    ensure_fips();
    let provider =
        rustls::crypto::CryptoProvider::get_default().expect("crypto provider should be installed");
    assert!(
        provider.fips(),
        "CryptoProvider::fips() must return true under the FIPS feature"
    );
}

/// Full mTLS handshake using the FIPS provider. Verifies that certificate
/// generation, TLS server setup, client connection, and bidirectional data
/// exchange all work correctly with the aws-lc-rs backend.
#[tokio::test]
async fn fips_mtls_handshake() {
    ensure_fips();

    let ca = TestCa::new("FIPS Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("fips-operator", &["fips-team"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config with FIPS provider");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept");
        let identity = session.identity().clone();
        let (mut reader, mut writer) = session.split();

        let mut buf = [0u8; 9];
        let _ = reader.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"fips-data");
        writer.write_all(b"fips-resp").await.expect("write");

        identity
    });

    let config = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect with FIPS provider");

    stream.write_all(b"fips-data").await.expect("client write");
    let mut buf = [0u8; 9];
    let _ = stream.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"fips-resp");

    let identity = server_handle.await.expect("server task");
    assert_eq!(identity.cn, "fips-operator");
    assert!(identity.is_member_of("fips-team"));
}

/// Verify the negotiated cipher suite is from the FIPS-approved set.
#[tokio::test]
async fn fips_negotiated_cipher_suite_is_approved() {
    ensure_fips();

    let ca = TestCa::new("FIPS Cipher CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("cipher-check", &["team"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let _session = listener.accept().await.expect("accept");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });

    let config = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");

    let (_, conn) = stream.get_ref();
    let suite = conn
        .negotiated_cipher_suite()
        .expect("should have negotiated a cipher suite");

    // All FIPS-approved suites use AES-GCM or AES-CCM. The suite name
    // must contain AES (covers TLS_AES_128_GCM_SHA256,
    // TLS_AES_256_GCM_SHA384, TLS_ECDHE_*_AES_*_GCM_SHA*).
    let suite_name = format!("{:?}", suite.suite());
    assert!(
        suite_name.contains("AES"),
        "negotiated cipher suite {suite_name} is not FIPS-approved (expected AES-based suite)"
    );

    server_handle.abort();
}

/// FIPS provider works with CRL-enabled TLS config. Ensures the two
/// features compose correctly — CRL checking under the FIPS backend.
#[tokio::test]
async fn fips_with_crl_rejects_revoked() {
    ensure_fips();

    let ca = TestCa::new("FIPS CRL CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let revoked_client = ca.issue_client_cert("revoked-fips", &["team"]);

    let crl_pem = ca.generate_crl(&[&revoked_client.cert_pem]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config")
        .with_crls(&crl_pem)
        .expect("load CRL");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Server must be accepting for the TLS handshake to proceed
    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await
    });

    // Revoked client tries to connect
    let revoked_config = build_client_tls_config(
        &revoked_client.cert_pem,
        &revoked_client.key_pem,
        &ca.cert_pem,
    );
    let connector = tokio_rustls::TlsConnector::from(Arc::new(revoked_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name: rustls::pki_types::ServerName<'_> =
        "localhost".try_into().expect("server name");
    let result = connector.connect(server_name, tcp).await;

    let revoked_failed = match result {
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
    assert!(
        revoked_failed,
        "revoked client should not connect under FIPS provider"
    );

    // Server should not have produced a valid session
    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err(),
        "server should timeout — revoked client under FIPS + CRL"
    );
}

/// Verify that negotiated TLS parameters (protocol version and cipher suite)
/// are FIPS-approved at the connection level after a successful handshake.
#[tokio::test]
async fn fips_server_config_reports_fips() {
    ensure_fips();

    let ca = TestCa::new("FIPS Config CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("config-check", &["team"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let _session = listener.accept().await.expect("accept");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });

    let config = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");

    let (_, conn) = stream.get_ref();

    // Protocol version must be TLS 1.2 or 1.3 — both are FIPS-approved.
    let version = conn
        .protocol_version()
        .expect("should have negotiated a protocol version");
    assert!(
        version == rustls::ProtocolVersion::TLSv1_2 || version == rustls::ProtocolVersion::TLSv1_3,
        "negotiated protocol version {version:?} is not FIPS-approved (expected TLS 1.2 or 1.3)"
    );

    // Cipher suite must be AES-based (FIPS-approved suites use AES-GCM).
    let suite = conn
        .negotiated_cipher_suite()
        .expect("should have negotiated a cipher suite");
    let suite_name = format!("{:?}", suite.suite());
    assert!(
        suite_name.contains("AES"),
        "negotiated cipher suite {suite_name} is not FIPS-approved (expected AES-based suite)"
    );

    // Verify peer certificates are accessible on the connection.
    assert!(
        conn.peer_certificates().is_some(),
        "peer certificates should be available after mTLS handshake"
    );

    server_handle.abort();
}

/// Verify the FIPS crypto provider does not offer ChaCha20-Poly1305 cipher
/// suites. ChaCha20 is not NIST-approved and must be excluded from the FIPS
/// provider's cipher suite list.
#[test]
fn fips_provider_excludes_chacha20() {
    ensure_fips();

    let provider =
        rustls::crypto::CryptoProvider::get_default().expect("crypto provider should be installed");

    let suite_names: Vec<String> = provider
        .cipher_suites
        .iter()
        .map(|s| format!("{:?}", s.suite()))
        .collect();

    for name in &suite_names {
        assert!(
            !name.contains("CHACHA20"),
            "FIPS provider must not offer ChaCha20-Poly1305, but found: {name}"
        );
    }
}
