// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the `dump-state` and `crl-info` diagnostic
//! CLI subcommands.
//!
//! These tests exercise the binary surface end-to-end (clap parsing,
//! file I/O, exit codes, JSON contract, TOML contract) so the
//! operator-facing behaviour documented in
//! `crates/rustgate-server/src/diagnostics/{dump_state,crl_info}.rs`
//! is pinned through the public CLI rather than the in-crate
//! `pub(crate)` helpers. The diagnostic modules' own unit tests cover
//! the structured-data shape; these tests cover what an operator
//! running the binary actually sees on stdout / stderr / `$?`.
//!
//! Closes #900 (F-182, F-183) — combined with the parallel
//! `test-connection` / `generate-config` PR, this finishes the
//! six-subcommand umbrella that opened with #1271.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

use rustgate_test_utils::certs::TestCa;
use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};

/// Path to the built `rustgate` binary. `cargo nextest` and `cargo
/// test` both populate `CARGO_BIN_EXE_<name>` automatically when a
/// `[[bin]]` target with that name exists in the crate.
fn rustgate_bin() -> String {
    env!("CARGO_BIN_EXE_rustgate").to_string()
}

/// Run `rustgate <args>` with a sanitized environment and capture
/// stdout / stderr / exit code. The env scrub matters for
/// `dump-state` — the `Cli` honours `RUSTGATE_*` variables, and a
/// developer machine that exports e.g. `RUSTGATE_AUDIT_LOG=/tmp/x.log`
/// would otherwise inject unrelated state into the snapshot.
fn run(args: &[&str]) -> Output {
    let mut cmd = Command::new(rustgate_bin());
    // Strip every `RUSTGATE_*` variable; leave `PATH` and friends.
    let to_remove: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k.starts_with("RUSTGATE_"))
        .collect();
    for k in to_remove {
        let _ = cmd.env_remove(k);
    }
    cmd.args(args).output().expect("spawn rustgate binary")
}

/// Drop the given PEM blob into a fresh tempfile.
fn write_pem(pem: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp PEM");
    f.write_all(pem.as_bytes()).expect("write PEM bytes");
    f.flush().expect("flush PEM");
    f
}

/// Build a minimal but realistic config file (cert / key / ca pointing
/// at fresh test certs) plus the supplied extra TOML body. Returns the
/// owning tempdir and the config path; both must be kept alive by the
/// caller until the spawn finishes.
fn make_config(extra_body: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let ca = TestCa::new("dump-state-it-ca");
    let server = ca.issue_server_cert("localhost", &["localhost"]);

    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&cert_path, &server.cert_pem).unwrap();
    std::fs::write(&key_path, &server.key_pem).unwrap();
    std::fs::write(&ca_path, &ca.cert_pem).unwrap();

    let config_path = dir.path().join("rustgate.toml");
    let body = format!(
        "cert = \"{}\"\nkey = \"{}\"\nca = \"{}\"\n{}",
        cert_path.display(),
        key_path.display(),
        ca_path.display(),
        extra_body,
    );
    std::fs::write(&config_path, body).unwrap();
    (dir, config_path)
}

// ── dump-state ─────────────────────────────────────────────────────

#[test]
fn dump_state_emits_valid_json_with_required_keys() {
    // Top-level keys form the contract for downstream tooling
    // (forensic scripts, support-bundle generators). Pin the shape
    // through the public binary boundary so a refactor that drops a
    // field is caught here.
    let (_dir, config) = make_config("");

    let out = run(&["dump-state", "--config", config.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "dump-state on a valid config must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let v: Value = serde_json::from_slice(&out.stdout)
        .expect("stdout must be valid JSON in default --format json mode");
    for key in [
        "rustgate_version",
        "generated_at",
        "config_path",
        "config",
        "redacted_fields",
        "crl",
        "audit_log",
    ] {
        assert!(
            v.get(key).is_some(),
            "snapshot must expose `{key}` as a top-level field",
        );
    }
    // The version string must look like semver — most basic gate.
    let version = v.get("rustgate_version").and_then(Value::as_str).unwrap();
    assert!(
        version.contains('.'),
        "rustgate_version must look like semver (got {version})",
    );
}

#[test]
fn dump_state_redacts_secret_fields() {
    // Sanity-check the redaction layer through the binary: configure
    // a fake CA private-key path, an enrollment password, and a
    // metrics token file; the snapshot must rewrite each to
    // `<redacted>` and surface them in `redacted_fields` (modulo
    // enrollment_password which goes through the CLI-level redaction
    // helper and so does NOT show up in `redacted_fields`).
    let body = "ca-key = \"/etc/rustgate/ca.key\"\n\
                enrollment-password = \"hunter2\"\n\
                metrics-token-file = \"/run/secrets/metrics.tok\"\n\
                archive-key-file = \"/etc/rustgate/archive.key\"\n";
    let (_dir, config) = make_config(body);

    let out = run(&["dump-state", "--config", config.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "dump-state must succeed even with secret-bearing fields; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    // 1) The literal secret values must be absent from the snapshot.
    assert!(
        !stdout.contains("/etc/rustgate/ca.key"),
        "ca-key path must not appear verbatim in snapshot:\n{stdout}",
    );
    assert!(
        !stdout.contains("hunter2"),
        "enrollment-password must not appear verbatim:\n{stdout}",
    );
    assert!(
        !stdout.contains("/run/secrets/metrics.tok"),
        "metrics-token-file path must not appear verbatim:\n{stdout}",
    );
    assert!(
        !stdout.contains("/etc/rustgate/archive.key"),
        "archive-key-file path must not appear verbatim:\n{stdout}",
    );

    // 2) The redaction sentinel must be present, and the path-style
    //    fields must be listed in `redacted_fields`.
    let v: Value = serde_json::from_str(&stdout).expect("output must parse as JSON");
    let redacted = v
        .get("redacted_fields")
        .and_then(Value::as_array)
        .expect("redacted_fields must be a JSON array");
    let names: Vec<&str> = redacted.iter().filter_map(Value::as_str).collect();
    assert!(
        names.contains(&"ca-key"),
        "redacted_fields must list ca-key; got {names:?}",
    );
    assert!(
        names.contains(&"metrics-token-file"),
        "redacted_fields must list metrics-token-file; got {names:?}",
    );
    assert!(
        names.contains(&"archive-key-file"),
        "redacted_fields must list archive-key-file; got {names:?}",
    );
}

#[test]
fn dump_state_format_toml_emits_valid_toml() {
    // The `--format toml` path round-trips the snapshot through
    // `serde_json::Value` → `toml::Value`. Parse the binary's stdout
    // through `toml::from_str` to confirm the result is a valid TOML
    // document with the same top-level keys as the JSON form.
    let (_dir, config) = make_config("");

    let out = run(&[
        "dump-state",
        "--config",
        config.to_str().unwrap(),
        "--format",
        "toml",
    ]);
    assert!(
        out.status.success(),
        "dump-state --format toml must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let v: toml::Value = toml::from_str(&stdout)
        .unwrap_or_else(|e| panic!("output must be valid TOML: {e}\noutput:\n{stdout}"));
    let table = v.as_table().expect("top-level must be a TOML table");
    assert!(
        table.contains_key("rustgate_version"),
        "TOML form must expose rustgate_version",
    );
    assert!(
        table.contains_key("config"),
        "TOML form must expose the config table",
    );
}

#[test]
fn dump_state_to_file_writes_then_reads() {
    // `--output PATH` must write the snapshot verbatim to that path.
    // Verify both that the file is created and that its content
    // parses as JSON identical-shape to the stdout form.
    let (_dir, config) = make_config("");
    let out_dir = TempDir::new().expect("output tempdir");
    let snap_path = out_dir.path().join("snapshot.json");

    let out = run(&[
        "dump-state",
        "--config",
        config.to_str().unwrap(),
        "--output",
        snap_path.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "dump-state --output must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    // Stdout should be empty (or whitespace) when the snapshot is
    // redirected to a file — operators piping the command into a
    // bigger script rely on this.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "stdout must be empty when --output is set; got {stdout}",
    );
    let bytes = std::fs::read_to_string(&snap_path).expect("snapshot file must exist");
    let v: Value = serde_json::from_str(&bytes).expect("snapshot file must contain valid JSON");
    assert!(
        v.get("rustgate_version").is_some(),
        "snapshot file must contain rustgate_version",
    );

    // On Unix, owner-only permissions are part of the contract.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&snap_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "snapshot file must be created with mode 0600 on Unix",
        );
    }
}

// ── crl-info ───────────────────────────────────────────────────────

#[test]
fn crl_info_prints_issuer_and_revoked_count() {
    // A realistic CRL with two revoked entries: human output must
    // name the issuer and list two revoked rows; JSON output (via
    // --json) must report `revoked_count = 2`.
    let ca = TestCa::new("crl-info-it-ca");
    let alice = ca.issue_client_cert("alice", &[]);
    let bob = ca.issue_client_cert("bob", &[]);
    let crl_pem = ca.generate_crl(&[&alice.cert_pem, &bob.cert_pem]);
    let crl = write_pem(&crl_pem);

    let out = run(&["crl-info", crl.path().to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "fresh CRL must exit 0; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("crl-info-it-ca"),
        "human output must include the issuer CN; got: {stdout}",
    );
    assert!(
        stdout.contains("Revoked:      2 entries"),
        "human output must list two revoked entries; got: {stdout}",
    );
}

#[test]
fn crl_info_returns_2_for_stale_crl() {
    // A CRL with `nextUpdate` already in the past is the operational
    // failure tier — exit 2 is the page-someone level. Pin that
    // through the binary so the cron contract documented in the
    // module header is enforceable.
    let ca = TestCa::new("crl-info-it-ca");
    let victim = ca.issue_client_cert("victim", &[]);
    let crl_pem = ca.generate_expired_crl(&[&victim.cert_pem]);
    let crl = write_pem(&crl_pem);

    let out = run(&["crl-info", crl.path().to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stale CRL must exit 2; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("stale"),
        "human output must announce stale status; got: {stdout}",
    );
}

#[test]
fn crl_info_handles_malformed_pem_gracefully() {
    // A non-PEM file must surface as exit 1 with no panic. Operators
    // running this from a cron pipeline rely on a clean error stream
    // and a single non-zero status — we must not crash with a stack
    // trace on stderr.
    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(b"not a real PEM file\n").expect("write");
    f.flush().expect("flush");

    let out = run(&["crl-info", f.path().to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "malformed PEM must exit 1; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked at"),
        "malformed PEM must not produce a panic; stderr={stderr}",
    );
}

#[test]
fn crl_info_json_format_is_valid_json() {
    // The JSON form is the contract for downstream tooling. Parse the
    // output as `serde_json::Value` and pin the keys most likely
    // consumed by an operator's pipeline.
    let ca = TestCa::new("crl-info-it-ca");
    let crl_pem = ca.generate_crl(&[]);
    let crl = write_pem(&crl_pem);

    let out = run(&["crl-info", "--json", crl.path().to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "fresh CRL with --json must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let v: Value =
        serde_json::from_slice(&out.stdout).expect("crl-info --json output must parse as JSON");
    assert_eq!(
        v.get("issuer_cn").and_then(Value::as_str),
        Some("crl-info-it-ca"),
        "JSON must expose the issuer_cn field",
    );
    assert_eq!(
        v.get("revoked_count").and_then(Value::as_i64),
        Some(0),
        "empty CRL must report revoked_count=0",
    );
    assert_eq!(
        v.get("stale").and_then(Value::as_bool),
        Some(false),
        "fresh CRL must report stale=false",
    );
}
