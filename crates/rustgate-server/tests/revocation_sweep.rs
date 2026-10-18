// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end test for the mid-session revocation sweep (#1496, ADR 0025
//! piece 3): a client whose certificate is revoked *after* it connected is
//! disconnected without a server restart, while other clients stay up.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::net::TcpListener;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustgate_test_utils::certs::{TestCa, TestCert};
use rustgate_test_utils::tls::build_client_tls_config;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Kills the server process when the test ends, pass or fail.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_file(dir: &std::path::Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
    path
}

async fn wait_for_listener(port: u16, log: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let log = std::fs::read_to_string(log).unwrap_or_default();
    panic!("server did not start listening on port {port}; log:\n{log}");
}

async fn connect(port: u16, client: &TestCert, ca: &TestCa) -> TlsStream<TcpStream> {
    let config = build_client_tls_config(&client.cert_pem, &client.key_pem, &ca.cert_pem);
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    connector
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .expect("mTLS handshake")
}

/// `true` when the server closed the connection within `within`.
async fn closed_within(stream: &mut TlsStream<TcpStream>, within: Duration) -> bool {
    let mut buf = [0u8; 1024];
    let deadline = Instant::now() + within;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            // Timed out with the connection still open.
            Err(_) => return false,
            // EOF or a TLS/IO error: the server dropped the session.
            Ok(Ok(0) | Err(_)) => return true,
            // The server sent data (e.g. a protocol advertisement); keep reading.
            Ok(Ok(_)) => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_session_is_evicted_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new("Sweep Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let alice = ca.issue_client_cert("alice", &["blue"]);
    let bob = ca.issue_client_cert("bob", &["blue"]);

    let cert = write_file(dir.path(), "server.pem", &server_cert.cert_pem);
    let key = write_file(dir.path(), "server.key", &server_cert.key_pem);
    // The server refuses private keys readable by group or other.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let ca_path = write_file(dir.path(), "ca.pem", &ca.cert_pem);
    let crl = write_file(dir.path(), "crl.pem", &ca.generate_crl(&[]));
    let port = free_port();
    let log = std::fs::File::create(dir.path().join("server.log")).unwrap();

    let _server = Server(
        Command::new(env!("CARGO_BIN_EXE_rustgate"))
            .args([
                "--bind",
                &format!("127.0.0.1:{port}"),
                "--cert",
                cert.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
                "--ca",
                ca_path.to_str().unwrap(),
                "--crl",
                crl.to_str().unwrap(),
                "--crl-refresh-interval",
                "1",
                "--revocation-sweep-interval",
                "1",
            ])
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("start rustgate"),
    );
    wait_for_listener(port, &dir.path().join("server.log")).await;

    let mut alice_conn = connect(port, &alice, &ca).await;
    let mut bob_conn = connect(port, &bob, &ca).await;
    // Both sessions survive several sweeps while nothing is revoked.
    assert!(
        !closed_within(&mut alice_conn, Duration::from_secs(3)).await,
        "alice was disconnected before any revocation"
    );

    // Revoke alice only. The CRL watcher picks it up within one refresh
    // interval and the sweep evicts her within one sweep interval.
    std::fs::write(&crl, ca.generate_crl(&[&alice.cert_pem])).unwrap();

    let evicted = closed_within(&mut alice_conn, Duration::from_secs(15)).await;
    let log_text = std::fs::read_to_string(dir.path().join("server.log")).unwrap_or_default();
    assert!(
        evicted,
        "revoked session was not disconnected; server log:\n{log_text}"
    );
    assert!(
        log_text.contains("session.evicted"),
        "missing session.evicted audit event; server log:\n{log_text}"
    );
    assert!(
        !closed_within(&mut bob_conn, Duration::from_secs(3)).await,
        "an unrevoked session was disconnected"
    );
}
