//! Integration tests for server certificate hot-reload via `CertReloader`.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_transport::{CertReloader, TlsConfig, TlsListener};

/// Connect to a TLS server and return the peer certificate serial number.
async fn connect_and_get_serial(
    addr: std::net::SocketAddr,
    config: &rustls::ClientConfig,
) -> String {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config.clone()));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");

    let certs = tls
        .get_ref()
        .1
        .peer_certificates()
        .expect("server should present certificates");
    assert!(!certs.is_empty());

    // Parse the leaf certificate serial number
    let (_, cert) =
        x509_parser::prelude::parse_x509_certificate(certs[0].as_ref()).expect("parse server cert");
    cert.serial.to_str_radix(16)
}

/// End-to-end test: start a TLS server with CertReloader, connect, rotate
/// the certificate, connect again, and verify the new certificate is served.
#[tokio::test]
async fn cert_rotation_serves_new_certificate() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = TestCa::new("Rotation Test CA");
    let server_cert_1 = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("test-client", &["team"]);

    // Write initial cert/key to temp files
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server.key");
    std::fs::write(&cert_path, &server_cert_1.cert_pem).unwrap();
    std::fs::write(&key_path, &server_cert_1.key_pem).unwrap();

    // Build TlsConfig for the client verifier (CA + client auth)
    let tls_config = TlsConfig::from_pem(
        &server_cert_1.cert_pem,
        &server_cert_1.key_pem,
        &ca.cert_pem,
    )
    .unwrap();

    // Create the CertReloader and build a reloadable server config
    let reloader = CertReloader::new(&cert_path, &key_path).unwrap();
    let verifier = tls_config.build_default_verifier().unwrap();
    let server_config = tls_config
        .build_reloadable_server_config(verifier, reloader.clone())
        .unwrap();

    // Bind listener
    let listener = TlsListener::bind_with_server_config("127.0.0.1:0", Arc::new(server_config), 10)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn accept loop
    let listener = Arc::new(tokio::sync::Mutex::new(listener));
    let accept_listener = listener.clone();
    let accept_handle = tokio::spawn(async move {
        loop {
            let l = accept_listener.lock().await;
            match l.accept().await {
                Ok(_session) => {
                    // Session accepted — we only need the handshake to complete
                    // so the client can inspect the server certificate.
                }
                Err(_) => break,
            }
        }
    });

    // Build client config
    let client_config =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);

    // First connection — get the initial certificate serial
    let serial_1 = connect_and_get_serial(addr, &client_config).await;

    // Issue a NEW server certificate and overwrite the files
    let server_cert_2 = ca.issue_server_cert("localhost", &["localhost"]);
    std::fs::write(&cert_path, &server_cert_2.cert_pem).unwrap();
    std::fs::write(&key_path, &server_cert_2.key_pem).unwrap();

    // Trigger reload
    let rotated = reloader.reload().unwrap();
    assert!(rotated, "reload should detect changed files");

    // Second connection — should see the NEW certificate
    let serial_2 = connect_and_get_serial(addr, &client_config).await;

    assert_ne!(
        serial_1, serial_2,
        "second connection should see rotated certificate"
    );

    // Cleanup
    accept_handle.abort();
}

/// Helper to write a server cert to the given directory.
fn write_server_cert(ca: &TestCa, cn: &str, dir: &std::path::Path) {
    let cert = ca.issue_server_cert(cn, &[cn]);
    std::fs::write(dir.join("cert.pem"), &cert.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &cert.key_pem).unwrap();
}

/// Reload with unchanged files returns false (no rotation).
#[tokio::test]
async fn reload_unchanged_returns_false() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = TestCa::new("Unchanged Test CA");
    let dir = tempfile::tempdir().unwrap();
    write_server_cert(&ca, "server.test", dir.path());

    let reloader =
        CertReloader::new(dir.path().join("cert.pem"), dir.path().join("key.pem")).unwrap();
    assert!(!reloader.reload().unwrap());
    assert!(!reloader.reload().unwrap());
}

/// Reload with corrupted cert files returns an error without panicking.
#[tokio::test]
async fn reload_corrupted_cert_returns_error() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = TestCa::new("Corrupt Test CA");
    let dir = tempfile::tempdir().unwrap();
    write_server_cert(&ca, "server.test", dir.path());

    let cert_path = dir.path().join("cert.pem");
    let reloader = CertReloader::new(&cert_path, dir.path().join("key.pem")).unwrap();

    // Corrupt the cert
    std::fs::write(&cert_path, "garbage").unwrap();

    let result = reloader.reload();
    assert!(result.is_err());
}
