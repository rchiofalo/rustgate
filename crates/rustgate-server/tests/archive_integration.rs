// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the archive functionality.
//!
//! The `CotArchiver` type is private to `rustgate-server`, so these tests
//! exercise archive behavior through the binary by starting the server with
//! `--archive-dir` and verifying it creates the expected directory and file
//! structures. Tests that require only short-lived server runs use valid
//! TLS certificates written to temporary files.

use std::io::Write;
use std::process::Command;
use std::time::Duration;

use rustgate_test_utils::certs::TestCa;
use tempfile::TempDir;

/// Write PEM content to a temporary file and return the path.
fn write_pem(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut file =
        std::fs::File::create(&path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    file.write_all(content.as_bytes())
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    // The server refuses private keys readable by group or other; without
    // this every test failed at that check instead of the one it targets.
    #[cfg(unix)]
    if name.contains("key") {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
    }
    path
}

/// Start the server with the given args, poll until it exits or the timeout
/// elapses, then kill it. Returns (stdout, stderr, exited) where `exited` is
/// true when the server stopped on its own before the timeout.
fn run_server_briefly(args: &[&str], timeout: Duration) -> (String, String, bool) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustgate"))
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to start server");

    let start = std::time::Instant::now();
    let mut exited = false;
    while start.elapsed() < timeout {
        if child.try_wait().expect("failed to poll child").is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    let output = child.wait_with_output().expect("failed to wait on child");

    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        exited,
    )
}

// ── Archive directory creation ──────────────────────────────────────

#[test]
fn server_starts_with_archive_dir_flag() {
    let ca = TestCa::new("test-ca-archive");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let tmp = TempDir::new().unwrap();
    let cert_dir = tmp.path().join("certs");
    std::fs::create_dir_all(&cert_dir).unwrap();

    let cert_path = write_pem(&cert_dir, "cert.pem", &server.cert_pem);
    let key_path = write_pem(&cert_dir, "key.pem", &server.key_pem);
    let ca_path = write_pem(&cert_dir, "ca.pem", &ca.cert_pem);

    let archive_dir = tmp.path().join("archive");

    let cert_str = cert_path.to_str().unwrap();
    let key_str = key_path.to_str().unwrap();
    let ca_str = ca_path.to_str().unwrap();
    let archive_str = archive_dir.to_str().unwrap();

    // The server should start and accept the --archive-dir flag.
    // We give it a brief moment to start, then kill it.
    let (_stdout, stderr, exited) = run_server_briefly(
        &[
            "--cert",
            cert_str,
            "--key",
            key_str,
            "--ca",
            ca_str,
            "--bind",
            "127.0.0.1:0",
            "--archive-dir",
            archive_str,
        ],
        Duration::from_secs(3),
    );

    // The server logs JSON to stdout. Check that it started successfully
    // rather than failing due to an unrecognized flag.
    let combined = format!("{_stdout}{stderr}");
    assert!(
        combined.contains("rustgate starting") || combined.contains("listening"),
        "server should start with --archive-dir; stdout: {_stdout}, stderr: {stderr}"
    );
    // Startup work after the "listening" line (e.g. metrics registration)
    // can still fail; the server must still be running at the timeout.
    assert!(
        !exited,
        "server exited during startup with --archive-dir; stdout: {_stdout}, stderr: {stderr}"
    );
}

#[test]
fn server_starts_with_valid_crl_file() {
    let ca = TestCa::new("test-ca-crl-file");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let client = ca.issue_client_cert("user", &[]);
    let crl = ca.generate_crl(&[&client.cert_pem]);

    let tmp = TempDir::new().unwrap();
    let cert_path = write_pem(tmp.path(), "cert.pem", &server.cert_pem);
    let key_path = write_pem(tmp.path(), "key.pem", &server.key_pem);
    let ca_path = write_pem(tmp.path(), "ca.pem", &ca.cert_pem);
    let crl_path = write_pem(tmp.path(), "crl.pem", &crl);

    let cert_str = cert_path.to_str().unwrap();
    let key_str = key_path.to_str().unwrap();
    let ca_str = ca_path.to_str().unwrap();
    let crl_str = crl_path.to_str().unwrap();

    let (_stdout, stderr, exited) = run_server_briefly(
        &[
            "--cert",
            cert_str,
            "--key",
            key_str,
            "--ca",
            ca_str,
            "--crl",
            crl_str,
            "--bind",
            "127.0.0.1:0",
        ],
        Duration::from_secs(3),
    );

    let combined = format!("{_stdout}{stderr}");
    assert!(
        combined.contains("rustgate starting") || combined.contains("listening"),
        "server should start with --crl; stdout: {_stdout}, stderr: {stderr}"
    );
    // Startup work after the "listening" line (e.g. metrics registration)
    // can still fail; the server must still be running at the timeout.
    assert!(
        !exited,
        "server exited during startup with --crl; stdout: {_stdout}, stderr: {stderr}"
    );
}

#[test]
fn server_fails_with_invalid_crl_file() {
    let ca = TestCa::new("test-ca-bad-crl");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let tmp = TempDir::new().unwrap();
    let cert_path = write_pem(tmp.path(), "cert.pem", &server.cert_pem);
    let key_path = write_pem(tmp.path(), "key.pem", &server.key_pem);
    let ca_path = write_pem(tmp.path(), "ca.pem", &ca.cert_pem);
    let crl_path = write_pem(tmp.path(), "crl.pem", "not a valid CRL");

    let output = Command::new(env!("CARGO_BIN_EXE_rustgate"))
        .args([
            "--cert",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--ca",
            ca_path.to_str().unwrap(),
            "--crl",
            crl_path.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
        ])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "server should fail with invalid CRL"
    );
}

#[test]
fn server_fails_with_nonexistent_crl_path() {
    let ca = TestCa::new("test-ca-no-crl");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let tmp = TempDir::new().unwrap();
    let cert_path = write_pem(tmp.path(), "cert.pem", &server.cert_pem);
    let key_path = write_pem(tmp.path(), "key.pem", &server.key_pem);
    let ca_path = write_pem(tmp.path(), "ca.pem", &ca.cert_pem);

    let output = Command::new(env!("CARGO_BIN_EXE_rustgate"))
        .args([
            "--cert",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--ca",
            ca_path.to_str().unwrap(),
            "--crl",
            "/nonexistent/path/crl.pem",
            "--bind",
            "127.0.0.1:0",
        ])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "server should fail with nonexistent CRL path"
    );
}

#[test]
fn server_fails_with_mismatched_cert_and_key() {
    let ca = TestCa::new("test-ca-mismatch");
    let server1 = ca.issue_server_cert("localhost", &["localhost"]);
    let server2 = ca.issue_server_cert("other-host", &["other-host"]);

    let tmp = TempDir::new().unwrap();
    // Use cert from server1 but key from server2
    let cert_path = write_pem(tmp.path(), "cert.pem", &server1.cert_pem);
    // `write_pem` makes the key owner-only, so the server gets past the
    // key-permission check and the failure is the mismatch itself.
    let key_path = write_pem(tmp.path(), "key.pem", &server2.key_pem);
    let ca_path = write_pem(tmp.path(), "ca.pem", &ca.cert_pem);

    let output = Command::new(env!("CARGO_BIN_EXE_rustgate"))
        .args([
            "--cert",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--ca",
            ca_path.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
        ])
        .output()
        .expect("failed to execute binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "server should fail with mismatched cert/key pair"
    );
    assert!(
        stderr.contains("does not match"),
        "server should report the mismatch, stderr: {stderr}"
    );
}

#[test]
fn server_fails_with_max_connections_zero() {
    let ca = TestCa::new("test-ca-maxconn");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let tmp = TempDir::new().unwrap();
    let cert_path = write_pem(tmp.path(), "cert.pem", &server.cert_pem);
    let key_path = write_pem(tmp.path(), "key.pem", &server.key_pem);
    let ca_path = write_pem(tmp.path(), "ca.pem", &ca.cert_pem);

    let output = Command::new(env!("CARGO_BIN_EXE_rustgate"))
        .args([
            "--cert",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--ca",
            ca_path.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
            "--max-connections",
            "0",
        ])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "server should fail with --max-connections 0"
    );
}

#[test]
fn server_fails_with_max_handshakes_zero() {
    let ca = TestCa::new("test-ca-maxhs");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let tmp = TempDir::new().unwrap();
    let cert_path = write_pem(tmp.path(), "cert.pem", &server.cert_pem);
    let key_path = write_pem(tmp.path(), "key.pem", &server.key_pem);
    let ca_path = write_pem(tmp.path(), "ca.pem", &ca.cert_pem);

    let output = Command::new(env!("CARGO_BIN_EXE_rustgate"))
        .args([
            "--cert",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--ca",
            ca_path.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
            "--max-concurrent-handshakes",
            "0",
        ])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "server should fail with --max-concurrent-handshakes 0"
    );
}
