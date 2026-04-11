// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for TLS config building and TLS listener binding.
//!
//! Uses `TestCa` from `rustgate-test-utils` to generate ephemeral
//! certificates, and exercises the public `TlsConfig` / `TlsListener`
//! APIs from `rustgate-transport`.

use rustgate_test_utils::certs::TestCa;
use rustgate_transport::{TlsConfig, TlsListener, TlsMinVersion};

// ── TlsConfig::from_pem ─────────────────────────────────────────────

#[test]
fn valid_pem_builds_tls_config() {
    let ca = TestCa::new("test-ca");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let config = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem);
    assert!(config.is_ok(), "valid PEM should produce Ok(TlsConfig)");
}

#[test]
fn invalid_cert_pem_fails() {
    let ca = TestCa::new("test-ca");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let result = TlsConfig::from_pem("not a certificate", &server.key_pem, &ca.cert_pem);
    assert!(result.is_err(), "invalid cert PEM should fail");
}

#[test]
fn invalid_key_pem_fails() {
    let ca = TestCa::new("test-ca");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let result = TlsConfig::from_pem(&server.cert_pem, "not a key", &ca.cert_pem);
    assert!(result.is_err(), "invalid key PEM should fail");
}

#[test]
fn invalid_ca_pem_fails() {
    let ca = TestCa::new("test-ca");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let result = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, "not a CA cert");
    assert!(result.is_err(), "invalid CA PEM should fail");
}

#[test]
fn empty_cert_pem_fails() {
    let ca = TestCa::new("test-ca");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let result = TlsConfig::from_pem("", &server.key_pem, &ca.cert_pem);
    assert!(result.is_err(), "empty cert PEM should fail");
}

#[test]
fn empty_key_pem_fails() {
    let ca = TestCa::new("test-ca");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let result = TlsConfig::from_pem(&server.cert_pem, "", &ca.cert_pem);
    assert!(result.is_err(), "empty key PEM should fail");
}

// ── CRL loading ─────────────────────────────────────────────────────

#[test]
fn valid_crl_loads_successfully() {
    let ca = TestCa::new("test-ca-crl");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let client = ca.issue_client_cert("user1", &[]);
    let crl = ca.generate_crl(&[&client.cert_pem]);

    let config = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).unwrap();
    let result = config.with_crls(&crl);
    assert!(result.is_ok(), "valid CRL should load successfully");
}

#[test]
fn invalid_crl_pem_fails() {
    let ca = TestCa::new("test-ca-crl");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let config = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).unwrap();
    let result = config.with_crls("not a CRL");
    assert!(result.is_err(), "invalid CRL PEM should fail");
}

#[test]
fn empty_crl_pem_fails() {
    let ca = TestCa::new("test-ca-crl");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let config = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).unwrap();
    let result = config.with_crls("");
    assert!(result.is_err(), "empty CRL PEM should fail");
}

// ── TLS min version ─────────────────────────────────────────────────

#[test]
fn tls_min_version_12_accepted() {
    let v = TlsMinVersion::from_str_version("1.2");
    assert!(v.is_ok());
    assert_eq!(v.unwrap(), TlsMinVersion::Tls12);
}

#[test]
fn tls_min_version_13_accepted() {
    let v = TlsMinVersion::from_str_version("1.3");
    assert!(v.is_ok());
    assert_eq!(v.unwrap(), TlsMinVersion::Tls13);
}

#[test]
fn tls_min_version_invalid_rejected() {
    let v = TlsMinVersion::from_str_version("1.1");
    assert!(v.is_err(), "TLS 1.1 should be rejected");
}

#[test]
fn tls_config_with_min_version_builds_server_config() {
    let ca = TestCa::new("test-ca-version");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let config = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
        .unwrap()
        .with_tls_min_version(TlsMinVersion::Tls13);

    let server_config = config.build_server_config();
    assert!(
        server_config.is_ok(),
        "TLS 1.3 config should build successfully"
    );
}

// ── TlsListener::bind ───────────────────────────────────────────────

#[tokio::test]
async fn tls_listener_binds_to_localhost_ephemeral_port() {
    let ca = TestCa::new("test-ca-listener");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let config = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).unwrap();

    let listener = TlsListener::bind("127.0.0.1:0", &config).await;
    assert!(
        listener.is_ok(),
        "should bind to ephemeral port: {:?}",
        listener.err()
    );

    let addr = listener.unwrap().local_addr().unwrap();
    assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
    assert_ne!(addr.port(), 0, "should have been assigned a real port");
}

#[tokio::test]
async fn tls_listener_binds_with_custom_handshake_limit() {
    let ca = TestCa::new("test-ca-hs-limit");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let config = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).unwrap();

    let listener = TlsListener::bind_with_handshake_limit("127.0.0.1:0", &config, 10).await;
    assert!(
        listener.is_ok(),
        "should bind with custom handshake limit: {:?}",
        listener.err()
    );
}

#[tokio::test]
async fn tls_listener_with_crl_and_min_version() {
    let ca = TestCa::new("test-ca-full");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let client = ca.issue_client_cert("revoked-user", &[]);
    let crl = ca.generate_crl(&[&client.cert_pem]);

    let config = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
        .unwrap()
        .with_tls_min_version(TlsMinVersion::Tls13)
        .with_crls(&crl)
        .unwrap();

    let listener = TlsListener::bind("127.0.0.1:0", &config).await;
    assert!(
        listener.is_ok(),
        "full config (CRL + TLS 1.3) should bind: {:?}",
        listener.err()
    );
}

// ── build_server_config ─────────────────────────────────────────────

#[test]
fn build_server_config_succeeds_with_valid_certs() {
    let ca = TestCa::new("test-ca-build");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let config = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem).unwrap();
    let result = config.build_server_config();
    assert!(
        result.is_ok(),
        "build_server_config should succeed: {:?}",
        result.err()
    );
}

#[test]
fn build_server_config_with_crl() {
    let ca = TestCa::new("test-ca-build-crl");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let client = ca.issue_client_cert("user", &["group-a"]);
    let crl = ca.generate_crl(&[&client.cert_pem]);

    let config = TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
        .unwrap()
        .with_crls(&crl)
        .unwrap();

    let result = config.build_server_config();
    assert!(
        result.is_ok(),
        "build_server_config with CRL should succeed: {:?}",
        result.err()
    );
}
