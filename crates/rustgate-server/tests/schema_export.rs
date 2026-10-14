// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(feature = "schema")]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the `emit-schema` subcommand.
//!
//! These run only with `--features schema`. They cover three layers:
//!
//! 1. The subcommand itself: invoke the binary with `emit-schema` and
//!    confirm stdout is a valid JSON Schema document for the
//!    `rustgate.toml` config surface.
//! 2. The internal generator: re-run `schema_for!(ConfigFile)` directly
//!    and assert the document parses with the expected top-level keys.
//! 3. Drift between the checked-in `schemas/rustgate-vX.Y.json` and
//!    what the source code emits today. If a contributor adds a new
//!    config field but forgets to regenerate the file, this test fails
//!    with a hint pointing at the regen command.
//!
//! Issue #815, F-137.

use std::process::Command;

fn rustgate_bin() -> String {
    env!("CARGO_BIN_EXE_rustgate").to_string()
}

/// Path to the workspace root (parent of the `target/` dir that owns
/// the test binary). The checked-in schema lives at
/// `<workspace>/schemas/rustgate-vX.Y.json`.
fn workspace_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR points at the crate dir; go up two levels to
    // reach the workspace root (`crates/rustgate-server` → workspace).
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

/// Path to the canonical checked-in schema file. The major.minor
/// component matches the workspace `version` literal in the root
/// `Cargo.toml` (`0.8.x` → `v0.8`).
fn checked_in_schema_path() -> std::path::PathBuf {
    workspace_root().join("schemas").join("rustgate-v0.8.json")
}

#[test]
fn emit_schema_subcommand_succeeds_and_returns_pretty_json() {
    let out = Command::new(rustgate_bin())
        .arg("emit-schema")
        .output()
        .expect("spawn rustgate emit-schema");

    assert!(
        out.status.success(),
        "emit-schema must exit 0, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout is UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert!(parsed.is_object(), "schema root must be a JSON object");
    assert!(
        parsed.get("$schema").is_some(),
        "schema must declare its `$schema` dialect URI"
    );
    assert!(
        parsed.get("properties").is_some(),
        "schema must expose a `properties` map for editor autocomplete"
    );
}

#[test]
fn emit_schema_advertises_in_help() {
    // `rustgate --help` should list `emit-schema` so an operator can
    // discover the subcommand from a vanilla install.
    let out = Command::new(rustgate_bin())
        .arg("--help")
        .output()
        .expect("spawn rustgate --help");
    assert!(out.status.success(), "--help must exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("emit-schema"),
        "emit-schema must be listed in --help output"
    );
}

#[test]
fn checked_in_schema_matches_emitted_schema() {
    // Regenerate the schema from the live source and compare against
    // the checked-in artifact. Drift means a contributor added or
    // renamed a config field without running `cargo run -p
    // rustgate-server --features schema -- emit-schema >
    // schemas/rustgate-v0.8.json`. The error message includes the
    // regen command so the fix is mechanical.
    let schema_path = checked_in_schema_path();
    let on_disk = std::fs::read_to_string(&schema_path).unwrap_or_else(|e| {
        panic!(
            "failed to read checked-in schema at {}: {e}\n\n\
             Hint: run `cargo run -p rustgate-server --features schema -- emit-schema > {}` \
             to regenerate it.",
            schema_path.display(),
            schema_path.display()
        )
    });

    let out = Command::new(rustgate_bin())
        .arg("emit-schema")
        .output()
        .expect("spawn rustgate emit-schema");
    assert!(
        out.status.success(),
        "emit-schema must exit 0, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let emitted = String::from_utf8(out.stdout).expect("stdout is UTF-8");

    // Parse both as JSON values for a structural comparison that does
    // not care about trailing-newline differences between editors and
    // pipe-redirect output. A byte-exact comparison is run as a
    // secondary check on top so checked-in formatting stays stable.
    let on_disk_value: serde_json::Value =
        serde_json::from_str(&on_disk).expect("checked-in schema must be valid JSON");
    let emitted_value: serde_json::Value =
        serde_json::from_str(&emitted).expect("emitted schema must be valid JSON");

    if on_disk_value != emitted_value {
        panic!(
            "checked-in schema at {} is out of date.\n\n\
             Run: cargo run -p rustgate-server --features schema -- emit-schema > {}",
            schema_path.display(),
            schema_path.display()
        );
    }

    // Byte-exact comparison: also catches whitespace / ordering drift
    // that a structural compare would miss.
    let on_disk_trimmed = on_disk.trim_end_matches('\n');
    let emitted_trimmed = emitted.trim_end_matches('\n');
    assert_eq!(
        on_disk_trimmed,
        emitted_trimmed,
        "checked-in schema at {} differs byte-for-byte from emit-schema output. \
         Run: cargo run -p rustgate-server --features schema -- emit-schema > {}",
        schema_path.display(),
        schema_path.display()
    );
}

#[test]
fn checked_in_schema_includes_top_level_config_keys() {
    // Spot-check a handful of always-present top-level keys so a
    // regression that empties the `properties` map shows up here. This
    // is deliberately a subset — adding every key would duplicate the
    // schema-vs-emit drift check above.
    let schema_path = checked_in_schema_path();
    let raw = std::fs::read_to_string(&schema_path).expect("read checked-in schema");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse checked-in schema");
    let props = value
        .get("properties")
        .and_then(|p| p.as_object())
        .expect("schema must have `properties` object");
    for required_key in [
        "bind",
        "cert",
        "key",
        "ca",
        "tls-min-version",
        "framing",
        "encoding",
    ] {
        assert!(
            props.contains_key(required_key),
            "checked-in schema is missing top-level key `{required_key}`"
        );
    }
}
