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
