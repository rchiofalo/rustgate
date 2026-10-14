// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the `cert-info` and `check-cert-expiry`
//! diagnostic CLI subcommands.
//!
//! These tests exercise the binary surface end-to-end (clap parsing,
//! file I/O, exit codes, JSON contract, human output) so the
//! operator-facing contract documented in `crates/rustgate-server/src/
//! diagnostics/{cert_info,check_cert_expiry}.rs` is pinned through
//! the public CLI rather than the in-crate `pub(crate)` helpers. The
//! diagnostics modules' own unit tests cover the structured-data
//! shape; these tests cover what an operator running the binary
//! actually sees on stdout / stderr / `$?`.
//!
//! Refs #900 (F-178, F-179) — `test-connection`, `generate-config`,
//! `dump-state`, and `crl-info` ship in a follow-up PR (batch 38).

use std::io::Write;
use std::process::{Command, Output};

use rustgate_test_utils::certs::TestCa;
use serde_json::Value;
use tempfile::NamedTempFile;

/// Path to the built `rustgate` binary. `cargo nextest` and `cargo
/// test` both populate `CARGO_BIN_EXE_<name>` automatically when a
/// `[[bin]]` target with that name exists in the crate.
fn rustgate_bin() -> String {
    env!("CARGO_BIN_EXE_rustgate").to_string()
}

/// Drop the given PEM blob into a fresh tempfile. The handle is
/// returned so the caller can keep the file alive for the duration of
/// the spawn (NamedTempFile cleans up on drop).
fn write_pem(pem: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp PEM");
    f.write_all(pem.as_bytes()).expect("write PEM bytes");
    f.flush().expect("flush PEM");
    f
}

/// Concatenate several PEM blobs into one bundle file. Used to verify
/// the `check-cert-expiry` walker honours every `CERTIFICATE` block
/// inside a chain file.
fn write_pem_bundle(blobs: &[&str]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp bundle");
    for blob in blobs {
        f.write_all(blob.as_bytes()).expect("write bundle entry");
        if !blob.ends_with('\n') {
            f.write_all(b"\n").expect("append newline");
        }
    }
    f.flush().expect("flush bundle");
    f
}

/// Run `rustgate <args>` and capture stdout / stderr / exit code.
fn run(args: &[&str]) -> Output {
    Command::new(rustgate_bin())
        .args(args)
        .output()
        .expect("spawn rustgate binary")
}

// ── cert-info ──────────────────────────────────────────────────────

#[test]
fn cert_info_prints_subject_for_valid_pem() {
    // Issue a fresh client cert and ensure the human output names the
    // CN — the most common "is this the right cert?" question an
    // operator asks at the CLI.
    let ca = TestCa::new("integration-ca");
    let client = ca.issue_client_cert("alice", &["ops"]);
    let pem = write_pem(&client.cert_pem);

    let out = run(&["cert-info", pem.path().to_str().unwrap()]);
    assert!(
        out.status.success(),
        "cert-info on a valid PEM must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Subject CN:"),
        "human output must label the subject CN; got: {stdout}",
    );
    assert!(
        stdout.contains("alice"),
        "human output must include the CN value; got: {stdout}",
    );
    assert!(
        stdout.contains("integration-ca"),
        "human output must include the issuer CN; got: {stdout}",
    );
}

#[test]
fn cert_info_json_format_emits_valid_json() {
    // The JSON form is the public contract for downstream tooling
    // (jq, monitoring agents, etc.). Parse the output as
    // `serde_json::Value` and pin the keys an operator's pipeline is
    // most likely to consume.
    let ca = TestCa::new("integration-ca");
    let client = ca.issue_client_cert("alice", &["ops", "admin"]);
    let pem = write_pem(&client.cert_pem);

    let out = run(&["cert-info", "--json", pem.path().to_str().unwrap()]);
    assert!(
        out.status.success(),
        "cert-info --json must exit 0 on a valid cert; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("output must be valid JSON: {e}\noutput: {stdout}"));
    assert_eq!(
        v.get("subject_cn").and_then(Value::as_str),
        Some("alice"),
        "JSON must expose the subject_cn field with the issued CN",
    );
    assert_eq!(
        v.get("issuer_cn").and_then(Value::as_str),
        Some("integration-ca"),
        "JSON must expose the issuer CN",
    );
    assert_eq!(
        v.get("expired").and_then(Value::as_bool),
        Some(false),
        "freshly issued cert must report expired=false",
    );
    assert_eq!(
        v.get("valid_now").and_then(Value::as_bool),
        Some(true),
        "freshly issued cert must report valid_now=true",
    );
    let groups = v
        .get("groups")
        .and_then(Value::as_array)
        .expect("groups must be a JSON array");
    let group_strs: Vec<&str> = groups.iter().filter_map(Value::as_str).collect();
    assert!(group_strs.contains(&"ops"));
    assert!(group_strs.contains(&"admin"));
    let fpr = v
        .get("fingerprint_sha256")
        .and_then(Value::as_str)
        .expect("fingerprint_sha256 must be a string");
    assert_eq!(fpr.len(), 64, "SHA-256 hex must be 64 chars; got: {fpr}");
}

#[test]
fn cert_info_handles_expired_cert_gracefully() {
    // An expired certificate is still a parseable certificate; the
    // command must surface its fields without panicking and must
    // signal the expiry both in the structured `expired` field and in
    // the human output. Exit code stays 0 — `cert-info` is a viewer,
    // not a validator (see check-cert-expiry for the alerting path).
    let ca = TestCa::new("integration-ca");
    let expired = ca.issue_expired_client_cert("ghost", &[]);
    let pem = write_pem(&expired.cert_pem);

    let json = run(&["cert-info", "--json", pem.path().to_str().unwrap()]);
    assert!(
        json.status.success(),
        "cert-info on an expired cert must still exit 0 (it's a viewer); stderr={}",
        String::from_utf8_lossy(&json.stderr),
    );
    let v: Value = serde_json::from_slice(&json.stdout).expect("JSON must parse for expired cert");
    assert_eq!(
        v.get("expired").and_then(Value::as_bool),
        Some(true),
        "expired cert must report expired=true",
    );
    assert_eq!(
        v.get("valid_now").and_then(Value::as_bool),
        Some(false),
        "expired cert must report valid_now=false",
    );
    let secs = v
        .get("seconds_until_expiry")
        .and_then(Value::as_i64)
        .expect("seconds_until_expiry must be an integer");
    assert!(
        secs <= 0,
        "expired cert must report non-positive seconds_until_expiry; got {secs}",
    );

    // Human render must remain panic-free and clearly signal expiry
    // so an operator who runs the command without --json gets the
    // same warning.
    let human = run(&["cert-info", pem.path().to_str().unwrap()]);
    assert!(human.status.success());
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(
        stdout.contains("expired"),
        "human output must announce expiry; got: {stdout}",
    );
}

// ── check-cert-expiry ──────────────────────────────────────────────

#[test]
fn check_cert_expiry_returns_0_for_long_lived_cert() {
    // Default warn-days threshold (30); a freshly-issued cert
    // (rcgen default ~year-long validity) should be well outside the
    // warning window. Exit 0 is what cron / monitoring scripts use to
    // gate their "all clear" path.
    let ca = TestCa::new("integration-ca");
    let client = ca.issue_client_cert("alice", &[]);
    let pem = write_pem(&client.cert_pem);

    let out = run(&["check-cert-expiry", pem.path().to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "long-lived cert must produce exit code 0; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Overall status: ok"),
        "human output must announce ok status; got: {stdout}",
    );
}

#[test]
fn check_cert_expiry_returns_1_for_expiring_soon() {
    // A cert with 10 days of remaining validity falls inside the
    // default 30-day warning window. The contract says exit 1 — an
    // operator's cron job uses this to fire a soft alert ("rotate
    // soon") without paging anyone.
    let ca = TestCa::new("integration-ca");
    let soon = ca.issue_near_expiry_server_cert("soon", &["soon.example.com"], 10);
    let pem = write_pem(&soon.cert_pem);

    let out = run(&["check-cert-expiry", pem.path().to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "10-day cert with default 30-day threshold must exit 1; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Overall status: expiring"),
        "human output must announce expiring status; got: {stdout}",
    );
}

#[test]
fn check_cert_expiry_returns_2_for_already_expired() {
    // An expired cert is the worst tier — production-affecting. Exit
    // 2 is the page-someone level. Pair the assertion with a JSON
    // shape check so we also catch contract drift on the
    // `overall_status` / `min_days_until_expiry` keys consumed by
    // monitoring agents.
    let ca = TestCa::new("integration-ca");
    let expired = ca.issue_expired_client_cert("ghost", &[]);
    let pem = write_pem(&expired.cert_pem);

    let out = run(&["check-cert-expiry", "--json", pem.path().to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expired cert must exit 2; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let v: Value = serde_json::from_slice(&out.stdout)
        .expect("expected stable JSON output even for expired cert");
    assert_eq!(
        v.get("overall_status").and_then(Value::as_str),
        Some("expired"),
        "overall_status must be \"expired\" for an already-expired cert",
    );
    let min_days = v
        .get("min_days_until_expiry")
        .and_then(Value::as_i64)
        .expect("min_days_until_expiry must be an integer for at least one parseable cert");
    assert!(
        min_days < 0,
        "expired cert must report a negative min_days_until_expiry; got {min_days}",
    );
}

#[test]
fn check_cert_expiry_respects_custom_warn_days_flag() {
    // A 10-day cert with a 5-day warn window should report ok — the
    // cert's expiry is still beyond the operator's threshold, so the
    // monitoring path stays quiet. Pins the `--warn-days` flag is
    // honoured end-to-end through clap.
    let ca = TestCa::new("integration-ca");
    let soon = ca.issue_near_expiry_server_cert("soon", &["soon.example.com"], 10);
    let pem = write_pem(&soon.cert_pem);

    let out = run(&[
        "check-cert-expiry",
        "--warn-days",
        "5",
        pem.path().to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "10-day cert with --warn-days 5 must exit 0; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("warn threshold: 5 days"),
        "human output must echo the custom threshold; got: {stdout}",
    );
}

#[test]
fn check_cert_expiry_handles_bundle_with_mixed_validity() {
    // Belt-and-braces: a chain file containing both a fresh cert and
    // an expired cert must report both entries and elevate the
    // overall verdict to expired (exit 2). This pins the bundle
    // walker's worst-status semantics through the binary boundary —
    // the unit tests in `check_cert_expiry.rs` cover the same shape
    // at the helper level.
    let ca = TestCa::new("integration-ca");
    let fresh = ca.issue_client_cert("alice", &[]);
    let expired = ca.issue_expired_client_cert("ghost", &[]);
    let bundle = write_pem_bundle(&[&fresh.cert_pem, &expired.cert_pem]);

    let out = run(&[
        "check-cert-expiry",
        "--json",
        bundle.path().to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "bundle containing an expired cert must exit 2 even if other certs are fresh",
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("JSON must parse for bundle");
    let certs = v["files"][0]["certs"]
        .as_array()
        .expect("per-file certs array");
    assert_eq!(certs.len(), 2, "every CERTIFICATE block must be inspected");
    assert_eq!(
        v.get("overall_status").and_then(Value::as_str),
        Some("expired"),
    );
}

#[test]
fn check_cert_expiry_missing_file_exits_2() {
    // A path that does not resolve is an operational failure — the
    // CLI must surface that as the same hard-fail (exit 2) tier as
    // an expired cert so cron-based monitoring catches it.
    let out = run(&["check-cert-expiry", "/definitely/not/a/real/path/cert.pem"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing file must exit 2; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Overall status: error"),
        "missing file must surface as error in human output; got: {stdout}",
    );
}
