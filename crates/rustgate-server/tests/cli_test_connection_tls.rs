// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the augmented `test-connection --tls` probe
//! and the `generate-config --minimal` flag.
//!
//! These tests run the `rustgate` binary end-to-end (clap parsing,
//! filesystem I/O, exit codes, output contract). The TLS probe in
//! particular requires a live TCP listener with a real `rustls`
//! handshake, so each test stands up an ephemeral test server using the
//! same `rustgate-test-utils::TestCa` helpers the rest of the workspace
//! uses.
//!
//! Refs #900 — augments the `test-connection` and `generate-config`
//! subcommands shipped via PRs #1138 and #1141. `dump-state` and
//! `crl-info` remain (separate PR).

use std::io::Write;
use std::process::{Command, Output};
use std::sync::Arc;

use rustgate_test_utils::certs::TestCa;
use serde_json::Value;
use tempfile::NamedTempFile;
use tokio::net::TcpListener;

/// Path to the built `rustgate` binary. Populated automatically by
/// cargo when a `[[bin]] name = "rustgate"` target exists in the crate.
fn rustgate_bin() -> String {
    env!("CARGO_BIN_EXE_rustgate").to_string()
}

/// Drop a PEM blob into a tempfile and return the handle. NamedTempFile
/// cleans up on drop, so callers must keep the handle alive for the
/// duration of any spawn that reads from the path.
fn write_pem(pem: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp PEM");
    f.write_all(pem.as_bytes()).expect("write PEM bytes");
    f.flush().expect("flush PEM");
    f
}

/// Run `rustgate <args>` and capture stdout / stderr / exit code.
fn run(args: &[&str]) -> Output {
    Command::new(rustgate_bin())
        .args(args)
        .output()
        .expect("spawn rustgate binary")
}

/// Spin up a TLS test server on `127.0.0.1` that accepts a single
/// connection, drives the handshake to completion, then drops the
/// stream. Returns the bound `host:port`.
///
/// `server_cert` and `server_key` are PEM strings as produced by
/// `TestCa::issue_server_cert*`. `ca` is the same CA's cert chain used
/// to validate the client mTLS material.
fn spawn_tls_server(server_cert: &str, server_key: &str, ca: &str) -> String {
    let server_certs = rustgate_test_utils::tls::parse_certs(server_cert);
    let server_key = rustgate_test_utils::tls::parse_key(server_key);

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustgate_test_utils::tls::parse_certs(ca) {
        roots.add(cert).expect("add CA cert");
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");

    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .expect("server config");

    // Bind on the current test thread's runtime so the listener is live
    // before the probe spawns its own tokio runtime against `addr`.
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let listener = runtime.block_on(async { TcpListener::bind("127.0.0.1:0").await.unwrap() });
    let addr = listener.local_addr().expect("local addr");

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    // Spawn one accept on a background thread so the test can fork the
    // child process and let the probe drive the handshake.
    let _join = std::thread::spawn(move || {
        runtime.block_on(async move {
            // Accept a single connection — the TLS probe only opens one.
            // We keep the stream alive briefly so `rustls` has time to
            // finish the handshake on the other side.
            if let Ok((tcp, _peer)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });
    });

    addr.to_string()
}

// ── test-connection --tls ──────────────────────────────────────────

#[test]
fn test_connection_tls_succeeds_against_test_server() {
    let ca = TestCa::new("test-conn-tls-ok");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let client = ca.issue_client_cert("test-client", &["ops"]);

    let cert = write_pem(&client.cert_pem);
    let key = write_pem(&client.key_pem);
    let ca_file = write_pem(&ca.cert_pem);

    let addr = spawn_tls_server(&server.cert_pem, &server.key_pem, &ca.cert_pem);

    let out = run(&[
        "test-connection",
        "--tls",
        &addr,
        "--target-cert",
        cert.path().to_str().unwrap(),
        "--target-key",
        key.path().to_str().unwrap(),
        "--target-ca",
        ca_file.path().to_str().unwrap(),
        "--server-name",
        "localhost",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["target_type"], "tls");
    assert_eq!(json["status"], "connected");
    // Negotiated cipher and TLS version are populated on success.
    assert!(
        json.get("negotiated_cipher").is_some(),
        "missing negotiated_cipher"
    );
    assert!(json.get("tls_version").is_some(), "missing tls_version");
    // Peer certificate Subject CN should be the server cert CN.
    assert_eq!(json["peer_subject_cn"], "localhost");
    // Peer notAfter and days-until are present.
    assert!(
        json.get("peer_not_after").is_some(),
        "missing peer_not_after"
    );
    assert!(
        json.get("peer_days_until_expiry").is_some(),
        "missing peer_days_until_expiry"
    );
}

#[test]
fn test_connection_tls_fails_with_wrong_ca() {
    // Two separate CAs — the client trusts CA-A but the server presents
    // a cert signed by CA-B. The handshake must fail at cert validation.
    let ca_server = TestCa::new("test-conn-tls-server-ca");
    let ca_client_trust = TestCa::new("test-conn-tls-client-trust");
    let server = ca_server.issue_server_cert("localhost", &["localhost"]);
    // Issue the client cert under the server CA so the server side
    // accepts it; the failure is purely on the client's CA validation
    // of the server cert.
    let client = ca_server.issue_client_cert("test-client", &["ops"]);

    let cert = write_pem(&client.cert_pem);
    let key = write_pem(&client.key_pem);
    // Trust the *wrong* CA so the server cert fails validation.
    let ca_file = write_pem(&ca_client_trust.cert_pem);

    let addr = spawn_tls_server(&server.cert_pem, &server.key_pem, &ca_server.cert_pem);

    let out = run(&[
        "test-connection",
        "--tls",
        &addr,
        "--target-cert",
        cert.path().to_str().unwrap(),
        "--target-key",
        key.path().to_str().unwrap(),
        "--target-ca",
        ca_file.path().to_str().unwrap(),
        "--server-name",
        "localhost",
        "--json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 for cert validation failure, got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["target_type"], "tls");
    // Status will be "error" or "refused" depending on how rustls maps
    // the cert validation failure into io::Error — both map to exit 1
    // in the TLS ladder, which is what we actually want to pin.
    let status = json["status"].as_str().expect("string status");
    assert!(
        matches!(status, "error" | "refused"),
        "unexpected status {status:?} on cert validation failure"
    );
    assert!(json["error"].is_string(), "expected error message");
}

#[test]
fn test_connection_tls_warns_on_expiring_peer_cert() {
    // Issue a server cert that expires in 5 days. With the default
    // warn-days of 30, the probe must report `near_expiry` and exit 2.
    let ca = TestCa::new("test-conn-tls-near-expiry");
    let server = ca.issue_near_expiry_server_cert("localhost", &["localhost"], 5);
    let client = ca.issue_client_cert("test-client", &["ops"]);

    let cert = write_pem(&client.cert_pem);
    let key = write_pem(&client.key_pem);
    let ca_file = write_pem(&ca.cert_pem);

    let addr = spawn_tls_server(&server.cert_pem, &server.key_pem, &ca.cert_pem);

    let out = run(&[
        "test-connection",
        "--tls",
        &addr,
        "--target-cert",
        cert.path().to_str().unwrap(),
        "--target-key",
        key.path().to_str().unwrap(),
        "--target-ca",
        ca_file.path().to_str().unwrap(),
        "--server-name",
        "localhost",
        "--peer-cert-warn-days",
        "30",
        "--json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 for near-expiry, got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["status"], "near_expiry");
    let days = json["peer_days_until_expiry"]
        .as_i64()
        .expect("days_until i64");
    // Test cert was issued with `days_remaining = 5`; allow some slack
    // for clock skew at the boundary (tests sometimes round to 4 if the
    // helper subtracted a day for the `not_before` window).
    assert!(
        (3..=5).contains(&days),
        "expected ~5 days remaining, got {days}"
    );
}

#[test]
fn test_connection_tls_handles_network_unreachable() {
    // 127.0.0.1:1 is the canonical "guaranteed unreachable" address —
    // no kernel listens there in the bootstrap phase, so connect()
    // returns ECONNREFUSED immediately.
    let ca = TestCa::new("test-conn-tls-unreachable");
    let client = ca.issue_client_cert("test-client", &["ops"]);

    let cert = write_pem(&client.cert_pem);
    let key = write_pem(&client.key_pem);
    let ca_file = write_pem(&ca.cert_pem);

    let out = run(&[
        "test-connection",
        "--tls",
        "127.0.0.1:1",
        "--target-cert",
        cert.path().to_str().unwrap(),
        "--target-key",
        key.path().to_str().unwrap(),
        "--target-ca",
        ca_file.path().to_str().unwrap(),
        "--server-name",
        "localhost",
        "--json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 for unreachable network, got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["target_type"], "tls");
    assert!(
        json["error"].is_string(),
        "expected error message in TLS-unreachable JSON"
    );
}

// ── generate-config --minimal ──────────────────────────────────────

#[test]
fn generate_config_minimal_emits_valid_toml() {
    // Smoke test: the minimal template parses as TOML even with the
    // REPLACE_ME placeholders untouched, so an operator can validate
    // syntax before editing.
    let out = run(&["generate-config", "--minimal"]);
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}",
        out.status.code()
    );
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let parsed = toml::from_str::<toml::Value>(&stdout)
        .unwrap_or_else(|e| panic!("minimal template is not valid TOML: {e}\n{stdout}"));
    assert!(parsed.is_table(), "top-level should be a TOML table");
}

#[test]
fn generate_config_minimal_includes_required_tls_keys() {
    let out = run(&["generate-config", "--minimal"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    // The minimal mode keeps the mTLS triple uncommented with the
    // REPLACE_ME placeholder so the operator can spot what they need
    // to fill in at a glance.
    for key in ["cert", "key", "ca"] {
        assert!(
            stdout.contains(&format!("{key} = \"REPLACE_ME\"")),
            "minimal template missing required key `{key}`:\n{stdout}"
        );
    }
}

#[test]
fn generate_config_minimal_omits_nats_and_federation() {
    // The minimal template skips every field outside the curated list.
    // NATS and federation are the two largest sub-systems, so use them
    // as the canary for "did the filter actually apply?".
    let out = run(&["generate-config", "--minimal"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    // Look for the *kebab keys*, not the section headers — the section
    // header logic is a separate concern from per-field filtering.
    assert!(
        !stdout.contains("nats-url ="),
        "minimal template should omit `nats-url`:\n{stdout}"
    );
    assert!(
        !stdout.contains("federation-v1-bind ="),
        "minimal template should omit `federation-v1-bind`:\n{stdout}"
    );
}

#[test]
fn generate_config_minimal_is_strictly_smaller_than_full() {
    let full = run(&["generate-config"]);
    let minimal = run(&["generate-config", "--minimal"]);
    assert!(full.status.success() && minimal.status.success());
    let full_len = full.stdout.len();
    let min_len = minimal.stdout.len();
    assert!(
        min_len < full_len,
        "minimal template ({min_len} bytes) must be strictly smaller than full ({full_len} bytes)"
    );
}

#[test]
fn generate_config_minimal_round_trips_through_check_config() {
    // A filled minimal template should pass `check-config --config
    // FILE` (the existing diagnostic shipped earlier), proving the
    // fields the minimal mode emits are sufficient to satisfy the
    // deserializer's deny_unknown_fields and the cross-field checks.
    let minimal = run(&["generate-config", "--minimal"]);
    assert!(minimal.status.success());
    let body = String::from_utf8(minimal.stdout).expect("utf-8 stdout");
    // Replace REPLACE_ME with the path of a real (test-issued) cert /
    // key / CA so cross-field validation has something concrete to
    // reference. The keys do not have to be cryptographically valid
    // for the deserializer-level check — `check-config` (without
    // `--strict`) only round-trips through serde and verifies invariants
    // like "tls_min_version is one of {1.2, 1.3}".
    let ca = TestCa::new("minimal-roundtrip");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let cert_file = write_pem(&server.cert_pem);
    let key_file = write_pem(&server.key_pem);
    let ca_file = write_pem(&ca.cert_pem);

    // Substitute each REPLACE_ME with the matching real path. The
    // template emits cert/key/ca in that exact order, so a sequential
    // replace is safe for this test (ordering is pinned by the
    // `MINIMAL_FIELDS` list which puts cert before key before ca).
    let mut filled = body;
    for path in [cert_file.path(), key_file.path(), ca_file.path()] {
        filled = filled.replacen("REPLACE_ME", path.to_str().unwrap(), 1);
    }
    let mut tmp = NamedTempFile::new().expect("tempfile");
    tmp.write_all(filled.as_bytes()).expect("write");
    tmp.flush().expect("flush");

    let out = run(&["check-config", "--config", tmp.path().to_str().unwrap()]);
    assert!(
        out.status.success(),
        "filled minimal template failed check-config: stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

// ── Argument validation ────────────────────────────────────────────

#[test]
fn test_connection_tls_requires_cert_key_ca() {
    // Without `--target-cert`, clap's `requires_all` should reject the
    // command at parse time with a non-zero exit code.
    let out = run(&["test-connection", "--tls", "127.0.0.1:443"]);
    assert!(!out.status.success(), "expected non-zero exit");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("--target-cert")
            || combined.contains("target_cert")
            || combined.contains("required"),
        "expected an error mentioning the missing cert/key/ca flags:\n{combined}"
    );
}
