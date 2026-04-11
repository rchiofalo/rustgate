#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for TOML configuration file support.
//!
//! These tests exercise the rustgate binary as a subprocess to verify the
//! `--config` flag, the `print-config` and `validate-config` subcommands,
//! and the merge precedence between defaults, file values, environment
//! variables, and CLI flags.

use std::io::Write;
use std::process::Command;

use serial_test::serial;

fn rustgate_bin() -> String {
    env!("CARGO_BIN_EXE_rustgate").to_string()
}

fn write_temp(contents: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::Builder::new()
        .suffix(".toml")
        .tempfile()
        .expect("create temp toml");
    f.write_all(contents.as_bytes()).expect("write toml");
    f
}

// ── required args ───────────────────────────────────────────────────

#[test]
#[serial]
fn rustgate_without_cert_or_config_fails_at_clap_parse() {
    // With neither --cert nor --config, clap must refuse to parse before
    // we ever reach the merge/validate logic. This guarantees the
    // pre-config-file behaviour is preserved.
    let out = Command::new(rustgate_bin())
        .env_remove("RUSTGATE_CERT")
        .env_remove("RUSTGATE_KEY")
        .env_remove("RUSTGATE_CA")
        .env_remove("RUSTGATE_CONFIG")
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "rustgate with no args must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--cert"),
        "clap error should mention --cert: {stderr}"
    );
}

// ── validate-config ─────────────────────────────────────────────────

#[test]
#[serial]
fn validate_config_accepts_minimal_valid_file() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let ca = dir.path().join("ca.pem");
    std::fs::write(&cert, "").expect("write cert");
    std::fs::write(&key, "").expect("write key");
    std::fs::write(&ca, "").expect("write ca");
    let toml = format!(
        "cert = \"{}\"
key  = \"{}\"
ca   = \"{}\"
",
        cert.display(),
        key.display(),
        ca.display(),
    );
    let f = write_temp(&toml);
    let out = Command::new(rustgate_bin())
        .args(["--config", f.path().to_str().unwrap(), "validate-config"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "validate-config failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("valid"));
}

#[test]
#[serial]
fn validate_config_rejects_missing_required_fields() {
    // No cert/key/ca anywhere — must fail.
    let f = write_temp("bind = \"0.0.0.0:4433\"\n");
    let out = Command::new(rustgate_bin())
        .args(["--config", f.path().to_str().unwrap(), "validate-config"])
        .env_remove("RUSTGATE_CERT")
        .env_remove("RUSTGATE_KEY")
        .env_remove("RUSTGATE_CA")
        .output()
        .expect("spawn");
    assert!(!out.status.success());
}

#[test]
#[serial]
fn validate_config_rejects_unknown_keys() {
    let toml = r#"
cert = "/tmp/cert.pem"
key  = "/tmp/key.pem"
ca   = "/tmp/ca.pem"
totally_made_up_key = "nope"
"#;
    let f = write_temp(toml);
    let out = Command::new(rustgate_bin())
        .args(["--config", f.path().to_str().unwrap(), "validate-config"])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "should reject unknown keys");
}

#[test]
#[serial]
fn validate_config_rejects_malformed_toml() {
    let f = write_temp("this is not = valid toml [[[");
    let out = Command::new(rustgate_bin())
        .args(["--config", f.path().to_str().unwrap(), "validate-config"])
        .output()
        .expect("spawn");
    assert!(!out.status.success());
}

// ── print-config ────────────────────────────────────────────────────

#[test]
#[serial]
fn print_config_emits_reparseable_toml() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let ca = dir.path().join("ca.pem");
    std::fs::write(&cert, "").expect("write cert");
    std::fs::write(&key, "").expect("write key");
    std::fs::write(&ca, "").expect("write ca");
    let toml = format!(
        "bind = \"127.0.0.1:14433\"\ncert = \"{}\"
key  = \"{}\"
ca   = \"{}\"
max-connections = 256\n",
        cert.display(),
        key.display(),
        ca.display(),
    );
    let f = write_temp(&toml);
    let out = Command::new(rustgate_bin())
        .args(["--config", f.path().to_str().unwrap(), "print-config"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "print-config failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    // Reparse as TOML and assert on typed field values rather than fragile
    // substring matches.
    let parsed: toml::Value = toml::from_str(&stdout).expect("emitted TOML must reparse");
    let t = parsed.as_table().expect("table");
    assert_eq!(
        t.get("bind").and_then(|v| v.as_str()),
        Some("127.0.0.1:14433")
    );
    assert_eq!(
        t.get("max-connections").and_then(|v| v.as_integer()),
        Some(256)
    );

    // Feed the printed TOML back through validate-config.
    let f2 = write_temp(&stdout);
    let validated = Command::new(rustgate_bin())
        .args(["--config", f2.path().to_str().unwrap(), "validate-config"])
        .output()
        .expect("spawn");
    assert!(
        validated.status.success(),
        "round-trip validate failed: {}",
        String::from_utf8_lossy(&validated.stderr)
    );
}

// ── precedence ──────────────────────────────────────────────────────

#[test]
#[serial]
fn cli_flag_overrides_env_and_file() {
    // file says A, env says B, CLI says C → effective is C.
    let toml = r#"
bind = "127.0.0.1:11111"
cert = "/tmp/cert.pem"
key  = "/tmp/key.pem"
ca   = "/tmp/ca.pem"
"#;
    let f = write_temp(toml);
    let out = Command::new(rustgate_bin())
        .args([
            "--config",
            f.path().to_str().unwrap(),
            "--bind",
            "127.0.0.1:33333",
            "print-config",
        ])
        .env("RUSTGATE_BIND", "127.0.0.1:22222")
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let parsed: toml::Value = toml::from_str(&stdout).expect("reparse");
    assert_eq!(
        parsed
            .as_table()
            .and_then(|t| t.get("bind"))
            .and_then(|v| v.as_str()),
        Some("127.0.0.1:33333")
    );
}

#[test]
#[serial]
fn env_overrides_file() {
    // file says A, env says B, no CLI → effective is B.
    let toml = r#"
bind = "127.0.0.1:11111"
cert = "/tmp/cert.pem"
key  = "/tmp/key.pem"
ca   = "/tmp/ca.pem"
"#;
    let f = write_temp(toml);
    let out = Command::new(rustgate_bin())
        .args(["--config", f.path().to_str().unwrap(), "print-config"])
        .env("RUSTGATE_BIND", "127.0.0.1:22222")
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let parsed: toml::Value = toml::from_str(&stdout).expect("reparse");
    assert_eq!(
        parsed
            .as_table()
            .and_then(|t| t.get("bind"))
            .and_then(|v| v.as_str()),
        Some("127.0.0.1:22222")
    );
}

#[test]
#[serial]
fn file_overrides_defaults() {
    // file says A, no env, no CLI → effective is A (not the clap default).
    let toml = r#"
bind = "127.0.0.1:11111"
cert = "/tmp/cert.pem"
key  = "/tmp/key.pem"
ca   = "/tmp/ca.pem"
max-connections = 77
"#;
    let f = write_temp(toml);
    let out = Command::new(rustgate_bin())
        .args(["--config", f.path().to_str().unwrap(), "print-config"])
        .env_remove("RUSTGATE_BIND")
        .env_remove("RUSTGATE_MAX_CONNECTIONS")
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let parsed: toml::Value = toml::from_str(&stdout).expect("reparse");
    let t = parsed.as_table().expect("table");
    assert_eq!(
        t.get("bind").and_then(|v| v.as_str()),
        Some("127.0.0.1:11111")
    );
    assert_eq!(
        t.get("max-connections").and_then(|v| v.as_integer()),
        Some(77)
    );
}

#[test]
#[serial]
fn print_config_redacts_enrollment_password() {
    let toml = r#"
cert = "/tmp/cert.pem"
key  = "/tmp/key.pem"
ca   = "/tmp/ca.pem"
enrollment-password = "hunter2-please-do-not-leak"
"#;
    let f = write_temp(toml);
    let out = Command::new(rustgate_bin())
        .args(["--config", f.path().to_str().unwrap(), "print-config"])
        .env_remove("RUSTGATE_ENROLLMENT_PASSWORD")
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        !stdout.contains("hunter2-please-do-not-leak"),
        "enrollment password leaked into print-config output: {stdout}"
    );
    let parsed: toml::Value = toml::from_str(&stdout).expect("reparse");
    assert_eq!(
        parsed
            .as_table()
            .and_then(|t| t.get("enrollment-password"))
            .and_then(|v| v.as_str()),
        Some("<redacted>")
    );
}

#[test]
#[serial]
fn round_trip_preserves_field_values() {
    // Round-trip: write a TOML file with a representative set of fields,
    // run print-config, parse the result, and assert each field matches.
    let toml = r#"
bind = "0.0.0.0:14433"
cert = "/tmp/cert.pem"
key  = "/tmp/key.pem"
ca   = "/tmp/ca.pem"
tls-min-version = "1.3"
fips-required = true
max-connections = 512
max-concurrent-handshakes = 25
federation-id = "round-trip-test"
federation-max-hops = 3
replay-window = 600
plaintext-cn = "anon-rt"
"#;
    let f = write_temp(toml);
    let out = Command::new(rustgate_bin())
        .args(["--config", f.path().to_str().unwrap(), "print-config"])
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let parsed: toml::Value =
        toml::from_str(&String::from_utf8_lossy(&out.stdout)).expect("reparse");
    let t = parsed.as_table().expect("table");

    let get_str = |k: &str| t.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let get_i = |k: &str| t.get(k).and_then(|v| v.as_integer()).unwrap_or(-1);
    let get_b = |k: &str| t.get(k).and_then(|v| v.as_bool()).unwrap_or(false);

    assert_eq!(get_str("bind"), "0.0.0.0:14433");
    assert_eq!(get_str("tls-min-version"), "1.3");
    assert!(get_b("fips-required"));
    assert_eq!(get_i("max-connections"), 512);
    assert_eq!(get_i("max-concurrent-handshakes"), 25);
    assert_eq!(get_str("federation-id"), "round-trip-test");
    assert_eq!(get_i("federation-max-hops"), 3);
    assert_eq!(get_i("replay-window"), 600);
    assert_eq!(get_str("plaintext-cn"), "anon-rt");
}
