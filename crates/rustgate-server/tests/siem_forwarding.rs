// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end test for SIEM forwarding (#1780): a running server sends its
//! audit events to a syslog-over-TLS collector.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use rustgate_test_utils::certs::TestCa;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Kills the server process when the test ends, pass or fail.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write(dir: &std::path::Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    // The server refuses private keys readable by group or other.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

async fn read_frame<R: tokio::io::AsyncRead + Unpin>(stream: &mut R) -> Option<String> {
    let mut len = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let _ = stream.read_exact(&mut byte).await.ok()?;
        if byte[0] == b' ' {
            break;
        }
        len.push(byte[0]);
    }
    let len: usize = String::from_utf8(len).ok()?.parse().ok()?;
    let mut message = vec![0u8; len];
    let _ = stream.read_exact(&mut message).await.ok()?;
    String::from_utf8(message).ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn server_forwards_its_audit_events_to_the_collector() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new("SIEM E2E CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let collector_cert = ca.issue_server_cert("localhost", &["localhost"]);

    let collector_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            CertificateDer::pem_slice_iter(collector_cert.cert_pem.as_bytes())
                .map(|c| c.unwrap())
                .collect(),
            PrivateKeyDer::from_pem_slice(collector_cert.key_pem.as_bytes()).unwrap(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(collector_config));
    let collector = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let collector_port = collector.local_addr().unwrap().port();

    let cert = write(dir.path(), "server.pem", &server_cert.cert_pem);
    let key = write(dir.path(), "server.key", &server_cert.key_pem);
    let ca_path = write(dir.path(), "ca.pem", &ca.cert_pem);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
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
                "--siem-endpoint",
                &format!("localhost:{collector_port}"),
                "--siem-ca",
                ca_path.to_str().unwrap(),
                "--siem-format",
                "cef",
            ])
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("start rustgate"),
    );

    let accepted = tokio::time::timeout(Duration::from_secs(20), collector.accept()).await;
    let server_log = || std::fs::read_to_string(dir.path().join("server.log")).unwrap_or_default();
    let (tcp, _) = accepted
        .unwrap_or_else(|_| {
            panic!(
                "server never connected to the collector; log:\n{}",
                server_log()
            )
        })
        .unwrap();
    let mut tls = acceptor.accept(tcp).await.unwrap();

    let mut seen = Vec::new();
    while !(seen.iter().any(|m: &String| m.contains("|server.started|"))
        && seen.iter().any(|m: &String| m.contains("|siem.connected|")))
    {
        let message = tokio::time::timeout(Duration::from_secs(20), read_frame(&mut tls))
            .await
            .unwrap_or_else(|_| panic!("no audit event arrived; got {seen:?}"))
            .expect("frame");
        assert!(message.starts_with('<'), "not RFC 5424: {message}");
        assert!(
            message.contains(" rustgate ") && message.contains(" audit - CEF:0|rustgate|"),
            "{message}"
        );
        seen.push(message);
        assert!(seen.len() < 50, "expected events not seen: {seen:?}");
    }
}
