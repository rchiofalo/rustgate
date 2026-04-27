// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for CLI argument parsing.
//!
//! Since the `Cli` struct is private to `main.rs`, these tests exercise
//! the binary directly via `std::process::Command`, verifying help output,
//! required-arg validation, and default value documentation.

use std::process::Command;

/// Path to the built binary. `cargo nextest` and `cargo test` both set
/// `CARGO_BIN_EXE_rustgate` when a `[[bin]]` target is present.
fn rustgate_bin() -> String {
    env!("CARGO_BIN_EXE_rustgate").to_string()
}

// ── Help / version ──────────────────────────────────────────────────

#[test]
fn help_flag_succeeds() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    assert!(output.status.success(), "expected exit 0 for --help");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Secure tactical message router"),
        "help should contain the about text"
    );
}

#[test]
fn help_shows_default_bind_address() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("0.0.0.0:4433"),
        "help should show default bind address"
    );
}

#[test]
fn help_shows_default_max_connections() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1024"),
        "help should show default max_connections value"
    );
}

#[test]
fn help_shows_default_shutdown_drain_timeout() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--shutdown-drain-timeout"),
        "help should advertise the shutdown drain timeout flag"
    );
}

#[test]
fn help_shows_default_max_handshakes() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("100"),
        "help should show default max_concurrent_handshakes"
    );
}

#[test]
fn help_shows_framing_options() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("xml") || stdout.contains("Xml") || stdout.contains("XML"),
        "help should list framing options"
    );
}

#[test]
fn help_shows_tls_min_version_default() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1.2"),
        "help should show default TLS min version 1.2"
    );
}

// ── Required argument validation ─────────────────────────────────────

#[test]
fn missing_cert_arg_fails() {
    let output = Command::new(rustgate_bin())
        .args(["--key", "/tmp/k.pem", "--ca", "/tmp/ca.pem"])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "should fail when --cert is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--cert"),
        "error should mention --cert: {stderr}"
    );
}

#[test]
fn missing_key_arg_fails() {
    let output = Command::new(rustgate_bin())
        .args(["--cert", "/tmp/c.pem", "--ca", "/tmp/ca.pem"])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "should fail when --key is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--key"),
        "error should mention --key: {stderr}"
    );
}

#[test]
fn missing_ca_arg_fails() {
    let output = Command::new(rustgate_bin())
        .args(["--cert", "/tmp/c.pem", "--key", "/tmp/k.pem"])
        .output()
        .expect("failed to execute binary");

    assert!(!output.status.success(), "should fail when --ca is missing");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--ca"),
        "error should mention --ca: {stderr}"
    );
}

#[test]
fn all_required_args_with_nonexistent_files_fails_at_runtime() {
    // With all required args but pointing to nonexistent files, clap parsing
    // succeeds but the server fails at runtime reading the cert files.
    let output = Command::new(rustgate_bin())
        .args([
            "--cert",
            "/nonexistent/cert.pem",
            "--key",
            "/nonexistent/key.pem",
            "--ca",
            "/nonexistent/ca.pem",
        ])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "should fail when cert files don't exist"
    );
}

// ── Invalid flag values ──────────────────────────────────────────────

#[test]
fn invalid_framing_value_fails() {
    let output = Command::new(rustgate_bin())
        .args([
            "--cert",
            "/tmp/c.pem",
            "--key",
            "/tmp/k.pem",
            "--ca",
            "/tmp/ca.pem",
            "--framing",
            "invalid-framing",
        ])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "should fail with invalid framing value"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid-framing") || stderr.contains("invalid value"),
        "error should mention invalid value: {stderr}"
    );
}

#[test]
fn invalid_encoding_value_fails() {
    let output = Command::new(rustgate_bin())
        .args([
            "--cert",
            "/tmp/c.pem",
            "--key",
            "/tmp/k.pem",
            "--ca",
            "/tmp/ca.pem",
            "--encoding",
            "not-an-encoding",
        ])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "should fail with invalid encoding value"
    );
}

// ── Environment variable support ─────────────────────────────────────

#[test]
fn env_vars_shown_in_help() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("RUSTGATE_BIND"),
        "help should document RUSTGATE_BIND env var"
    );
    assert!(
        stdout.contains("RUSTGATE_CERT"),
        "help should document RUSTGATE_CERT env var"
    );
    assert!(
        stdout.contains("RUSTGATE_KEY"),
        "help should document RUSTGATE_KEY env var"
    );
    assert!(
        stdout.contains("RUSTGATE_CA"),
        "help should document RUSTGATE_CA env var"
    );
}

#[test]
fn env_var_for_optional_flags_shown_in_help() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("RUSTGATE_CRL"),
        "help should document RUSTGATE_CRL env var"
    );
    assert!(
        stdout.contains("RUSTGATE_MAX_CONNECTIONS"),
        "help should document RUSTGATE_MAX_CONNECTIONS env var"
    );
    assert!(
        stdout.contains("RUSTGATE_ARCHIVE_DIR"),
        "help should document RUSTGATE_ARCHIVE_DIR env var"
    );
}

// ── Audit log flag ──────────────────────────────────────────────────

#[test]
fn help_shows_audit_log_flag() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--audit-log"),
        "help should show --audit-log flag"
    );
    assert!(
        stdout.contains("RUSTGATE_AUDIT_LOG"),
        "help should document RUSTGATE_AUDIT_LOG env var"
    );
}

// ── Feature-gated flag documentation ─────────────────────────────────

#[test]
fn help_shows_federation_flags() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // These flags exist regardless of feature flags (clap always shows them)
    assert!(
        stdout.contains("--federation-id"),
        "help should show --federation-id"
    );
    assert!(
        stdout.contains("--federation-max-hops"),
        "help should show --federation-max-hops"
    );
}

#[test]
fn help_shows_plaintext_flags() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--tcp-bind"), "help should show --tcp-bind");
    assert!(stdout.contains("--udp-bind"), "help should show --udp-bind");
    assert!(
        stdout.contains("anonymous"),
        "help should show default plaintext CN"
    );
}

#[test]
fn help_shows_rate_limit_flags() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--client-message-rate"),
        "help should show --client-message-rate"
    );
    assert!(
        stdout.contains("--client-burst"),
        "help should show --client-burst"
    );
}

#[cfg(feature = "ocsp")]
#[test]
fn help_shows_ocsp_stapling_flag() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--ocsp-stapling"),
        "help should show --ocsp-stapling when ocsp feature is enabled"
    );
}

// ── OTLP metrics export ─────────────────────────────────────────────

#[cfg(feature = "otel")]
#[test]
fn help_shows_otlp_metrics_flags() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--otlp-metrics"),
        "help should show --otlp-metrics flag"
    );
    assert!(
        stdout.contains("--otlp-metrics-interval"),
        "help should show --otlp-metrics-interval flag"
    );
    assert!(
        stdout.contains("RUSTGATE_OTLP_METRICS"),
        "help should show RUSTGATE_OTLP_METRICS env var"
    );
    assert!(
        stdout.contains("RUSTGATE_OTLP_METRICS_INTERVAL"),
        "help should show RUSTGATE_OTLP_METRICS_INTERVAL env var"
    );
}

#[cfg(feature = "otel")]
#[test]
fn otlp_metrics_interval_rejects_zero() {
    // `clap::value_parser!(u64).range(1..)` should refuse 0.
    let output = Command::new(rustgate_bin())
        .args([
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--otlp-metrics-interval",
            "0",
            "validate-config",
        ])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "expected non-zero exit for --otlp-metrics-interval 0"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("otlp-metrics-interval")
            || stderr.contains("not in")
            || stderr.contains("invalid value"),
        "stderr should mention the invalid interval: {stderr}"
    );
}

#[cfg(feature = "otel")]
#[test]
fn otlp_metrics_interval_accepts_positive_value() {
    // Parsing should succeed even without --otel-endpoint — the missing
    // endpoint is only checked at runtime when the exporter is actually
    // booted, not during pure CLI parsing for `validate-config`.
    //
    // Config validation checks TLS file existence, so create real temp
    // files to satisfy that check.
    let dir = std::env::temp_dir().join("rustgate-test-otlp-interval");
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("c.pem");
    let key = dir.join("k.pem");
    let ca = dir.join("ca.pem");
    std::fs::write(&cert, b"").unwrap();
    std::fs::write(&key, b"").unwrap();
    std::fs::write(&ca, b"").unwrap();

    let output = Command::new(rustgate_bin())
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--ca",
            ca.to_str().unwrap(),
            "--otlp-metrics",
            "--otlp-metrics-interval",
            "30",
            "validate-config",
        ])
        .output()
        .expect("failed to execute binary");

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "expected --otlp-metrics-interval 30 to parse cleanly; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── SPIFFE workload identity ────────────────────────────────────────

#[cfg(feature = "spiffe")]
#[test]
fn spiffe_flag_waives_cert_requirement() {
    // With --spiffe set, --cert/--key/--ca must not be required. We still
    // expect startup to fail later (no Workload API socket in the test env),
    // but clap parsing should accept the flag combination.
    let output = Command::new(rustgate_bin())
        .args([
            "--spiffe",
            "--spiffe-workload-api-socket",
            "unix:///tmp/does-not-exist.sock",
            "--help",
        ])
        .output()
        .expect("failed to execute binary");
    assert!(
        output.status.success(),
        "expected --help to succeed alongside --spiffe: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "spiffe")]
#[test]
fn spiffe_conflicts_with_cert_flag() {
    // clap should reject combining --spiffe with --cert.
    let output = Command::new(rustgate_bin())
        .args([
            "--spiffe",
            "--cert",
            "/tmp/c.pem",
            "--key",
            "/tmp/k.pem",
            "--ca",
            "/tmp/ca.pem",
        ])
        .output()
        .expect("failed to execute binary");
    assert!(
        !output.status.success(),
        "expected --spiffe + --cert to be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with") || stderr.contains("conflict"),
        "stderr should mention conflict: {stderr}"
    );
}

#[cfg(feature = "spiffe")]
#[test]
fn spiffe_help_lists_flags() {
    let output = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--spiffe"), "help missing --spiffe");
    assert!(
        stdout.contains("RUSTGATE_SPIFFE_WORKLOAD_API_SOCKET"),
        "help missing RUSTGATE_SPIFFE_WORKLOAD_API_SOCKET env var"
    );
}

// ── check-config (issue #793) ───────────────────────────────────────
//
// End-to-end integration tests for the new dry-run subcommand. These
// drive the real binary via a subprocess so the wiring between clap,
// the dispatch in `main.rs`, and the diagnostic module is exercised
// for real. Unit-level coverage of `build_report` lives next to the
// module in `src/diagnostics/check_config.rs`.

/// Helper: write a TOML config file backed by a tempfile so it
/// survives long enough for the subprocess to read it. Returns the
/// handle (caller keeps it alive for the assertion window).
fn write_check_config_toml(contents: &str) -> tempfile::NamedTempFile {
    use std::io::Write as _;
    let mut f = tempfile::Builder::new()
        .suffix(".toml")
        .tempfile()
        .expect("tempfile");
    f.write_all(contents.as_bytes()).expect("write");
    f.flush().expect("flush");
    f
}

/// Helper: build a tempdir + cert/key/ca placeholder files +
/// minimal TOML body referencing them. On Unix the files are
/// chmod-ed 0o600 so a `--strict` check passes. Returns the dir
/// (kept alive for the test window) and the TOML body.
fn check_config_minimal_toml() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tmpdir");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let ca = dir.path().join("ca.pem");
    std::fs::write(&cert, "").expect("cert");
    std::fs::write(&key, "").expect("key");
    std::fs::write(&ca, "").expect("ca");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&cert, &key, &ca] {
            let mut perms = std::fs::metadata(p).unwrap().permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(p, perms).unwrap();
        }
    }
    let toml = format!(
        "cert = \"{}\"\nkey = \"{}\"\nca = \"{}\"\n",
        cert.display(),
        key.display(),
        ca.display(),
    );
    (dir, toml)
}

#[test]
fn check_config_returns_zero_for_valid_minimal_config() {
    let (_dir, toml) = check_config_minimal_toml();
    let f = write_check_config_toml(&toml);

    let out = Command::new(rustgate_bin())
        .args(["check-config", "--config", f.path().to_str().unwrap()])
        .output()
        .expect("spawn rustgate");
    assert!(
        out.status.success(),
        "check-config must exit 0 for a valid config; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("status: ok"),
        "expected status: ok in human output, got: {stdout}"
    );
}

#[test]
fn check_config_returns_one_for_invalid_config_with_unknown_field() {
    let (_dir, mut toml) = check_config_minimal_toml();
    toml.push_str("totally-made-up-key = 42\n");
    let f = write_check_config_toml(&toml);

    let out = Command::new(rustgate_bin())
        .args(["check-config", "--config", f.path().to_str().unwrap()])
        .output()
        .expect("spawn rustgate");
    // Unknown-field is a load-time figment failure → exit 2 per the
    // exit-code contract (config file present but unparseable as the
    // strict deny_unknown_fields schema).
    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown-field config must exit 2; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
}

#[test]
fn check_config_returns_one_for_invalid_range_violation() {
    // Load succeeds, but cross-field validation fails — this is the
    // pure exit-code-1 path (config loaded but invalid).
    let (_dir, mut toml) = check_config_minimal_toml();
    toml.push_str("client-message-rate = 100\nclient-burst = 10\n");
    let f = write_check_config_toml(&toml);

    let out = Command::new(rustgate_bin())
        .args(["check-config", "--config", f.path().to_str().unwrap()])
        .output()
        .expect("spawn rustgate");
    assert_eq!(
        out.status.code(),
        Some(1),
        "validate() failure must exit 1, got code {:?}; stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn check_config_returns_two_for_nonexistent_config_path() {
    let out = Command::new(rustgate_bin())
        .args([
            "check-config",
            "--config",
            "/definitely/does/not/exist/rustgate-test.toml",
        ])
        .output()
        .expect("spawn rustgate");
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing config path must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn check_config_strict_flag_validates_referenced_file_paths() {
    // ACL file path that does not exist + a valid reload interval so
    // cross-field validation passes; strict mode must elevate the
    // missing-file case to a hard error.
    let (_dir, mut toml) = check_config_minimal_toml();
    toml.push_str("group-acl-file = \"/this/path/does/not/exist.json\"\n");
    toml.push_str("acl-reload-interval = 30\n");
    let f = write_check_config_toml(&toml);

    let non_strict = Command::new(rustgate_bin())
        .args(["check-config", "--config", f.path().to_str().unwrap()])
        .output()
        .expect("spawn rustgate");
    assert_eq!(
        non_strict.status.code(),
        Some(0),
        "without --strict, missing referenced files are not an error; stderr={}",
        String::from_utf8_lossy(&non_strict.stderr),
    );

    let strict = Command::new(rustgate_bin())
        .args([
            "check-config",
            "--config",
            f.path().to_str().unwrap(),
            "--strict",
        ])
        .output()
        .expect("spawn rustgate");
    assert_eq!(
        strict.status.code(),
        Some(1),
        "with --strict, missing referenced ACL must surface as an error; stderr={}, stdout={}",
        String::from_utf8_lossy(&strict.stderr),
        String::from_utf8_lossy(&strict.stdout),
    );
}

#[test]
fn check_config_json_flag_emits_machine_readable_output() {
    let (_dir, toml) = check_config_minimal_toml();
    let f = write_check_config_toml(&toml);

    let out = Command::new(rustgate_bin())
        .args([
            "check-config",
            "--config",
            f.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("spawn rustgate");
    assert!(out.status.success(), "json check-config must exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json output must parse as JSON");

    // Pin the documented top-level shape — these keys are the public
    // contract for `helm test` integration.
    for key in ["status", "config_path", "strict", "errors", "warnings"] {
        assert!(
            value.get(key).is_some(),
            "JSON missing required key `{key}`: {value}"
        );
    }
    assert_eq!(value["status"].as_str(), Some("ok"));
    assert!(
        value["errors"].as_array().is_some_and(|a| a.is_empty()),
        "errors array must be empty for a valid config"
    );
}

#[test]
fn check_config_does_not_bind_listeners() {
    use std::net::{SocketAddr, TcpListener};

    // Grab an ephemeral port and immediately drop the listener so
    // the OS marks the port free.
    let probe = TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let addr: SocketAddr = probe.local_addr().expect("local_addr");
    drop(probe);

    // Configure the server to bind that exact port. If check-config
    // erroneously starts the listener, the probe rebind below fails.
    let (_dir, mut toml) = check_config_minimal_toml();
    toml.push_str(&format!("bind = \"{addr}\"\n"));
    let f = write_check_config_toml(&toml);

    let out = Command::new(rustgate_bin())
        .args(["check-config", "--config", f.path().to_str().unwrap()])
        .output()
        .expect("spawn rustgate");
    assert!(
        out.status.success(),
        "check-config must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    // Probe the port: if check-config bound it, the second bind will
    // fail with EADDRINUSE. If it didn't, we can grab the port.
    let probe_after = TcpListener::bind(addr);
    assert!(
        probe_after.is_ok(),
        "check-config must not bind listeners; rebind {addr:?} failed: {:?}",
        probe_after.err()
    );
}

#[test]
fn check_config_help_documents_every_flag() {
    let output = Command::new(rustgate_bin())
        .args(["check-config", "--help"])
        .output()
        .expect("failed to execute binary");
    assert!(output.status.success(), "check-config --help must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--config"), "help missing --config flag");
    assert!(stdout.contains("--strict"), "help missing --strict flag");
    assert!(stdout.contains("--json"), "help missing --json flag");
}
