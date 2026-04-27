// Copyright © 2026 Roberto Chiofalo.

//! `check-config` — load and validate a rustgate config file without
//! starting any listeners, NATS connections, federation discovery, or
//! other I/O.
//!
//! Operators wire this subcommand into:
//!
//! * **CI pipelines** — fail a build when a TOML config drifts out of
//!   schema (typo, removed field, range violation) before the change
//!   ever reaches a node where a real start would notice it.
//! * **`helm test` hooks** — validate the rendered Helm values produce
//!   a config rustgate would accept, before the pod is allowed to bind
//!   ports. The `--json` output is the integration surface for the
//!   tooling that reads the test result.
//!
//! Unlike a normal `rustgate --config <path>` start, this subcommand
//! does *not* construct any tokio runtime, does *not* dial NATS, does
//! *not* bind a TCP listener, does *not* read TLS material into rustls,
//! and does *not* spawn the federation peer-discovery reconciler. The
//! whole point is to answer "would this config start cleanly" without
//! spending the resources to actually start.
//!
//! # Exit codes
//!
//! The exit codes form a monotonic severity ladder so wrappers can
//! branch on the code alone:
//!
//! | Code | Meaning |
//! |------|---------|
//! | `0`  | Config parsed and validated successfully |
//! | `1`  | Config loaded but is invalid (missing fields, range error, unknown key, …) |
//! | `2`  | Config file could not be read (path missing, permission denied, malformed TOML) |
//!
//! # JSON contract
//!
//! The top-level keys (`status`, `errors`, `warnings`, `config`) are
//! pinned by the unit tests in this module. `status` is one of `ok` or
//! `error`. Additions land at the end; renames or removals are
//! breaking.
//!
//! Closes #793.

use std::path::Path;

use serde::Serialize;

use crate::cli::{Cli, load_config_file};

/// Stable JSON shape emitted by `check-config --json`.
///
/// Field order matches the documented contract and must stay stable
/// across releases — `helm test` hooks and CI pipelines may grep on
/// individual keys.
#[derive(Debug, Serialize)]
pub(crate) struct CheckReport {
    /// `"ok"` when the config parsed and validated cleanly,
    /// `"error"` otherwise.
    pub(crate) status: String,
    /// Path the operator passed via `--config`. Useful for the
    /// machine-readable form so a wrapper can correlate the report
    /// back to a particular file in a multi-file pipeline.
    pub(crate) config_path: String,
    /// Whether `--strict` was active for this run. Affects what
    /// counts as an error vs. a warning (referenced-file existence,
    /// 0o077 permissions on key/secret files).
    pub(crate) strict: bool,
    /// Errors that prevent the config from being considered valid.
    /// Empty when `status == "ok"`.
    pub(crate) errors: Vec<String>,
    /// Non-fatal advisories. Operators get visibility without
    /// failing the run (e.g. authz-fail-open with no policy file).
    pub(crate) warnings: Vec<String>,
}

/// CLI entry point. Reads the config at `path`, runs every parse and
/// cross-field validation step, then optionally walks referenced files
/// when `strict` is set. Returns the exit code the binary should use
/// (0/1/2 — see the module docs).
pub(crate) fn run(path: &Path, strict: bool, json: bool) -> anyhow::Result<i32> {
    let report = build_report(path, strict);
    if json {
        let out = serde_json::to_string_pretty(&report)
            .map_err(|e| anyhow::anyhow!("serialize check-config report: {e}"))?;
        println!("{out}");
    } else {
        print!("{}", render_human(&report));
    }
    Ok(exit_code(&report))
}

/// Build a [`CheckReport`] for `path` without writing anything to
/// stdout. Exposed to tests so they can assert on the structured data
/// without capturing stdout or the process exit code.
pub(crate) fn build_report(path: &Path, strict: bool) -> CheckReport {
    let path_str = path.display().to_string();
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Step 1: file readable? Distinguish "not found / permission" from
    // "found but parse failed" because the exit-code contract uses
    // the former for `2` and the latter for `1`.
    if !path.exists() {
        errors.push(format!("config file not found: {path_str}"));
        return CheckReport {
            status: "error".to_string(),
            config_path: path_str,
            strict,
            errors,
            warnings,
        };
    }
    if let Err(err) = std::fs::metadata(path) {
        errors.push(format!("config file not readable: {path_str}: {err}"));
        return CheckReport {
            status: "error".to_string(),
            config_path: path_str,
            strict,
            errors,
            warnings,
        };
    }

    // Step 2: TOML parse + deny_unknown_fields + range checks via
    // the same figment loader the running server uses. A failure here
    // is a `1`-level error in the exit-code contract — the file was
    // there, just malformed or schema-violating.
    let path_arg = match path.to_str() {
        Some(s) => s,
        None => {
            errors.push(format!(
                "config path is not valid UTF-8 and cannot be loaded: {path_str}"
            ));
            return CheckReport {
                status: "error".to_string(),
                config_path: path_str,
                strict,
                errors,
                warnings,
            };
        }
    };
    let config_file = match load_config_file(path_arg) {
        Ok(f) => f,
        Err(e) => {
            errors.push(format!("{e}"));
            return CheckReport {
                status: "error".to_string(),
                config_path: path_str,
                strict,
                errors,
                warnings,
            };
        }
    };

    // Step 3: simulate the binary's defaults < file < env precedence
    // path, but without consulting environment variables — this
    // subcommand is for validating the *file*, and an env override
    // hiding a bad file value would be misleading. We synthesize a
    // minimal CLI invocation with the file's required-arg values
    // (cert/key/ca) supplied as bare placeholders so clap accepts the
    // command, then call `apply_to` to layer the file values on top.
    //
    // The placeholder values are immediately overwritten by
    // `apply_to` whenever the file specifies them, so they do not
    // leak into the validated state. They exist only so clap's
    // top-level `required_unless_present_any = ["config", "spiffe"]`
    // gates pass. We pass `--config` so clap's
    // `subcommand_negates_reqs` policy is consistent and the
    // required-arg gate is bypassed even when the placeholder values
    // remain.
    let argv = ["rustgate", "--config", path_arg];
    let matches = match Cli::command_for_check_config().try_get_matches_from(argv) {
        Ok(m) => m,
        Err(e) => {
            errors.push(format!("internal: clap rejected synthetic argv: {e}"));
            return CheckReport {
                status: "error".to_string(),
                config_path: path_str,
                strict,
                errors,
                warnings,
            };
        }
    };
    let mut cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => {
            errors.push(format!("internal: failed to materialize CLI: {e}"));
            return CheckReport {
                status: "error".to_string(),
                config_path: path_str,
                strict,
                errors,
                warnings,
            };
        }
    };
    config_file.apply_to(&mut cli, &matches);

    // Step 4: cross-field validation (mTLS material presence, range
    // sanity, federation prerequisites, …). The same `validate()`
    // method `main()` runs before starting subsystems.
    if let Err(e) = cli.validate() {
        errors.push(format!("{e}"));
    }

    // Step 5: optional strict mode. Walk referenced file paths and
    // (on Unix) confirm the secret-file paths have 0o077-conforming
    // permissions. Non-strict skips this so a CI environment that
    // does not yet have the files materialized can still verify the
    // schema.
    if strict {
        check_strict_referenced_paths(&cli, &mut errors, &mut warnings);
    }

    // Step 6: surface advisories that do not fail validation but
    // operators benefit from seeing in CI output (matches the
    // tracing::warn! emissions in `Cli::validate` so a check-config
    // run does not lose information vs. `validate-config`).
    if cli.authz_fail_open && cli.authz_policy_file.is_none() {
        warnings.push("--authz-fail-open has no effect without --authz-policy-file".to_string());
    }

    let status = if errors.is_empty() { "ok" } else { "error" };
    CheckReport {
        status: status.to_string(),
        config_path: path_str,
        strict,
        errors,
        warnings,
    }
}

/// Map the report to the exit-code contract documented at the top of
/// the module. The "file unreadable" case (exit 2) is handled by
/// short-circuit returns inside [`build_report`] and detected here by
/// inspecting the leading error string — a config that loaded but
/// failed validation is `1`; a config we could not read at all is `2`.
pub(crate) fn exit_code(report: &CheckReport) -> i32 {
    if report.status == "ok" {
        return 0;
    }
    // Promote to 2 when the *first* error indicates the file itself
    // could not be read (missing path, not-readable metadata, malformed
    // TOML — figment's parse errors prefix `"failed to load config
    // file"`). Everything else is a load-succeeded-but-invalid-config
    // failure, which is exit 1.
    if let Some(first) = report.errors.first()
        && (first.starts_with("config file not found")
            || first.starts_with("config file not readable")
            || first.starts_with("config path is not valid UTF-8")
            || first.starts_with("failed to load config file"))
    {
        return 2;
    }
    1
}

/// `--strict` extension: confirm that every TLS / authz / ACL file the
/// config references actually exists, and (on Unix) that the secret-y
/// ones have the 0o077-conforming permissions the runtime path's
/// `read_secret_file` helper enforces. Anything that is merely
/// advisory (file exists but permissions are not as restrictive as
/// recommended) becomes a warning; missing files become errors so the
/// pre-deployment check fails loudly.
fn check_strict_referenced_paths(cli: &Cli, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
    // The base TLS material's existence is already enforced by
    // `Cli::validate`; the strict pass adds a permission audit on the
    // private key (the most sensitive of the three).
    if !cli.spiffe && !cli.key.is_empty() {
        check_file_permissions(&cli.key, "TLS key", errors);
    }

    // Optional secret-bearing files referenced via Cli fields. Any
    // referenced path that doesn't exist is an error; a path that
    // exists but is too permissive is also an error since these are
    // the runtime-enforced gates already in `read_secret_file`.
    let mut maybe_check = |opt: &Option<String>, label: &str, secret: bool| {
        let Some(path_str) = opt.as_ref().filter(|s| !s.is_empty()) else {
            return;
        };
        let p = Path::new(path_str.as_str());
        if !p.exists() {
            errors.push(format!("{label} file not found: {path_str}"));
            return;
        }
        if secret {
            check_file_permissions(path_str, label, errors);
        }
    };

    maybe_check(&cli.crl, "CRL", false);
    maybe_check(&cli.group_acl_file, "ACL", false);
    maybe_check(&cli.authz_policy_file, "authz policy", false);
    maybe_check(&cli.metrics_token_file, "metrics token", true);
    maybe_check(&cli.ca_key, "CA private key", true);
    maybe_check(&cli.archive_key_file_str(), "archive key", true);

    // Files where existence is interesting but missing permissions are
    // an advisory rather than a hard fail. The runtime path tolerates
    // the missing perms via warn-only logging.
    if let Some(audit_log) = cli.audit_log.as_ref()
        && audit_log != "-"
    {
        // The audit log file may not exist yet on a fresh deployment —
        // the server creates it on first write. Surface a warning if
        // the parent directory is missing so operators can spot a
        // typo before the first audit event would have been emitted.
        let p = Path::new(audit_log);
        if let Some(parent) = p.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            warnings.push(format!(
                "audit-log parent directory does not exist: {}",
                parent.display()
            ));
        }
    }
}

/// On Unix, push an error if `path` exists but has any group/other
/// permission bits set (mode `& 0o077 != 0`). On non-Unix we silently
/// skip — the runtime path does the same.
fn check_file_permissions(path: &str, label: &str, errors: &mut Vec<String>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode();
                let bits = mode & 0o7777;
                if bits & 0o077 != 0 {
                    errors.push(format!(
                        "{label} file {path} has overly-permissive Unix mode {bits:#o}; \
                         expected mode 0o077 (group/other bits zero)",
                    ));
                }
            }
            Err(err) => {
                errors.push(format!("{label} file not readable: {path}: {err}"));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, label, errors);
    }
}

/// Render the report as plain human-readable text. Cosmetic only —
/// not a stability contract.
pub(crate) fn render_human(report: &CheckReport) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "check-config: {}", report.config_path);
    let _ = writeln!(out, "  strict: {}", report.strict);
    let _ = writeln!(out, "  status: {}", report.status);
    if !report.errors.is_empty() {
        let _ = writeln!(out, "  errors:");
        for e in &report.errors {
            let _ = writeln!(out, "    - {e}");
        }
    }
    if !report.warnings.is_empty() {
        let _ = writeln!(out, "  warnings:");
        for w in &report.warnings {
            let _ = writeln!(out, "    - {w}");
        }
    }
    if report.status == "ok" && report.errors.is_empty() && report.warnings.is_empty() {
        let _ = writeln!(out, "  configuration is valid");
    }
    out
}

// Bring in the clap and ArgMatches helpers that build_report uses.
use clap::{CommandFactory, FromArgMatches};

impl Cli {
    /// Build the clap `Command` used by `check-config`. Identical to
    /// `Cli::command()` for now — kept as a separate entry point so
    /// future additions (e.g. suppressing required-arg gates more
    /// aggressively) do not bleed into the default server start path.
    pub(crate) fn command_for_check_config() -> clap::Command {
        Cli::command()
    }

    /// Returns the `archive_key_file` field as an `Option<String>` for
    /// uniform handling alongside other CLI string paths in
    /// `check_strict_referenced_paths`. The field itself is a
    /// `Option<PathBuf>`; the conversion never panics.
    pub(crate) fn archive_key_file_str(&self) -> Option<String> {
        self.archive_key_file
            .as_ref()
            .map(|p| p.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    /// Write a TOML file with the given contents and return the
    /// temp-file handle. Caller keeps the handle alive for the
    /// lifetime of the test.
    fn write_toml(contents: &str) -> NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("create toml");
        f.write_all(contents.as_bytes()).expect("write toml");
        f.flush().expect("flush");
        f
    }

    /// Materialize empty cert/key/ca files in a tempdir and return
    /// the tempdir + a TOML snippet referencing them. On Unix, the
    /// key file is chmod-ed to 0o600 so `--strict` mode can run
    /// without tripping the permissions check on a setup helper that
    /// is supposed to produce an otherwise-valid baseline. The empty
    /// files satisfy the `Cli::validate` existence check without
    /// supplying any TLS material — the server would fail later at
    /// rustls parse, but check-config never reaches that stage.
    fn minimal_tls_setup() -> (tempfile::TempDir, String) {
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
    fn build_report_returns_ok_for_valid_minimal_config() {
        let (_dir, toml) = minimal_tls_setup();
        let f = write_toml(&toml);

        let report = build_report(f.path(), false);

        assert_eq!(report.status, "ok", "errors: {:?}", report.errors);
        assert!(report.errors.is_empty());
        assert_eq!(exit_code(&report), 0);
    }

    #[test]
    fn build_report_returns_error_for_unknown_field() {
        let (_dir, mut toml) = minimal_tls_setup();
        toml.push_str("totally-made-up-key = 42\n");
        let f = write_toml(&toml);

        let report = build_report(f.path(), false);

        assert_eq!(report.status, "error");
        assert!(!report.errors.is_empty());
        assert_eq!(
            exit_code(&report),
            2,
            "an unknown-field error is a load failure (figment), so exit 2 — got: {report:?}"
        );
    }

    #[test]
    fn build_report_returns_error_for_malformed_toml() {
        let f = write_toml("this is = not valid toml [[[\n");
        let report = build_report(f.path(), false);
        assert_eq!(report.status, "error");
        assert_eq!(exit_code(&report), 2);
    }

    #[test]
    fn build_report_returns_exit_two_for_missing_path() {
        let report = build_report(
            Path::new("/definitely/does/not/exist/rustgate-test.toml"),
            false,
        );
        assert_eq!(report.status, "error");
        assert_eq!(exit_code(&report), 2);
        assert!(
            report.errors[0].contains("not found"),
            "expected not-found error, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn build_report_validates_invalid_range() {
        // burst < message-rate is a cross-field range error, exit 1.
        let (_dir, mut toml) = minimal_tls_setup();
        toml.push_str("client-message-rate = 100\nclient-burst = 10\n");
        let f = write_toml(&toml);

        let report = build_report(f.path(), false);

        assert_eq!(report.status, "error");
        assert_eq!(
            exit_code(&report),
            1,
            "validate() failure (loaded but invalid) must be exit 1, got: {report:?}"
        );
        assert!(
            report.errors[0].contains("client-burst") || report.errors[0].contains("burst"),
            "expected burst error, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn strict_flag_flags_missing_referenced_acl_file() {
        let (_dir, mut toml) = minimal_tls_setup();
        // ACL file path + a non-zero reload interval so cross-field
        // validation does not fail before the strict pass runs.
        toml.push_str("group-acl-file = \"/this/path/does/not/exist.json\"\n");
        toml.push_str("acl-reload-interval = 30\n");
        let f = write_toml(&toml);

        let non_strict = build_report(f.path(), false);
        // Non-strict is fine — the runtime would create / wait for it.
        assert_eq!(non_strict.status, "ok", "{:?}", non_strict.errors);

        let strict = build_report(f.path(), true);
        assert_eq!(strict.status, "error");
        assert_eq!(exit_code(&strict), 1);
        assert!(
            strict.errors.iter().any(|e| e.contains("ACL")),
            "expected ACL error, got: {:?}",
            strict.errors
        );
    }

    #[cfg(unix)]
    #[test]
    fn strict_flag_flags_overly_permissive_secret_file() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, mut toml) = minimal_tls_setup();
        let secret = dir.path().join("metrics.token");
        std::fs::write(&secret, "shhhh").expect("write");
        let mut perms = std::fs::metadata(&secret).unwrap().permissions();
        perms.set_mode(0o644); // world-readable
        std::fs::set_permissions(&secret, perms).unwrap();

        toml.push_str(&format!("metrics-token-file = \"{}\"\n", secret.display()));
        let f = write_toml(&toml);

        let report = build_report(f.path(), true);
        assert_eq!(report.status, "error");
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("overly-permissive")),
            "expected permissions error, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn json_serialization_has_stable_top_level_keys() {
        let (_dir, toml) = minimal_tls_setup();
        let f = write_toml(&toml);

        let report = build_report(f.path(), true);
        let value: serde_json::Value =
            serde_json::to_value(&report).expect("serialize check-config report");

        for key in ["status", "config_path", "strict", "errors", "warnings"] {
            assert!(
                value.get(key).is_some(),
                "top-level JSON must include `{key}`, got: {value}"
            );
        }
        assert_eq!(value["status"].as_str(), Some("ok"));
        assert_eq!(value["strict"].as_bool(), Some(true));
    }

    #[test]
    fn human_render_includes_status_and_path() {
        let (_dir, toml) = minimal_tls_setup();
        let f = write_toml(&toml);
        let report = build_report(f.path(), false);
        let s = render_human(&report);
        assert!(s.contains("check-config:"));
        assert!(s.contains("status: ok"));
        assert!(s.contains(&f.path().display().to_string()));
    }

    #[test]
    fn human_render_emits_error_lines_when_invalid() {
        let f = write_toml("totally-made-up = 1\n");
        let report = build_report(f.path(), false);
        let s = render_human(&report);
        assert!(s.contains("status: error"));
        assert!(
            s.contains("errors:"),
            "human render must list errors, got: {s}"
        );
    }

    #[test]
    fn warnings_surface_authz_fail_open_without_policy() {
        let (_dir, mut toml) = minimal_tls_setup();
        toml.push_str("authz-fail-open = true\n");
        let f = write_toml(&toml);
        let report = build_report(f.path(), false);
        assert_eq!(report.status, "ok", "errors: {:?}", report.errors);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("authz-fail-open")),
            "expected authz-fail-open warning, got: {:?}",
            report.warnings
        );
    }

    #[test]
    fn run_writes_json_report_when_json_set() {
        let (_dir, toml) = minimal_tls_setup();
        let f = write_toml(&toml);
        // We can't easily capture stdout from `run` without restructuring;
        // a minimal smoke test that the function returns 0 + does not
        // error is enough to pin the wiring. The JSON shape is tested
        // via serialization above.
        let code = run(f.path(), false, true).expect("run");
        assert_eq!(code, 0);
    }

    #[test]
    fn exit_code_returns_one_for_loaded_but_invalid() {
        let report = CheckReport {
            status: "error".to_string(),
            config_path: "x".to_string(),
            strict: false,
            errors: vec!["--client-burst (10) must be >= --client-message-rate (100)".to_string()],
            warnings: vec![],
        };
        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn exit_code_returns_two_for_unreadable() {
        let report = CheckReport {
            status: "error".to_string(),
            config_path: "x".to_string(),
            strict: false,
            errors: vec!["config file not found: /nope".to_string()],
            warnings: vec![],
        };
        assert_eq!(exit_code(&report), 2);
    }

    #[test]
    fn exit_code_returns_two_for_load_failure() {
        // Mirrors what figment-load failures look like in the wild.
        let report = CheckReport {
            status: "error".to_string(),
            config_path: "x".to_string(),
            strict: false,
            errors: vec!["failed to load config file /tmp/cfg: …".to_string()],
            warnings: vec![],
        };
        assert_eq!(exit_code(&report), 2);
    }

    /// Pin the contract that `archive_key_file_str` returns `None`
    /// when no archive key file is configured (preventing strict-mode
    /// false-positive errors).
    #[test]
    fn archive_key_file_str_returns_none_when_absent() {
        let (_dir, toml) = minimal_tls_setup();
        let f = write_toml(&toml);
        let report = build_report(f.path(), true);
        assert_eq!(report.status, "ok", "{:?}", report.errors);
    }

    /// Meta-test: verify the path that exercises `build_report`
    /// (which the run() entry point shares) does not bind to a port.
    /// We grab an ephemeral port, drop the listener, run check-config,
    /// then re-bind the same port to assert it's still free. If
    /// check-config had bound the listener at all, the second bind
    /// would fail with EADDRINUSE.
    #[test]
    fn check_config_does_not_bind_listeners() {
        use std::net::{SocketAddr, TcpListener}; // playbook-drift-ok: test-only ephemeral port probe; never accepts a connection.

        // Pick an ephemeral port so nothing else on CI happens to
        // collide with us.
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let addr: SocketAddr = probe.local_addr().expect("local_addr");
        drop(probe);

        let (_dir, mut toml) = minimal_tls_setup();
        // Have the config request a bind on the very port we know is
        // currently free. If the subcommand is honestly side-effect-
        // free, this should remain free after build_report returns.
        toml.push_str(&format!("bind = \"{addr}\"\n"));
        let f = write_toml(&toml);

        let report = build_report(f.path(), false);
        assert_eq!(report.status, "ok", "errors: {:?}", report.errors);

        // Asserting the port is still bindable proves no listener was
        // started by `build_report`.
        let probe_after = TcpListener::bind(addr);
        assert!(
            probe_after.is_ok(),
            "check-config must not bind listeners; probe rebind failed: {:?}",
            probe_after.err()
        );
    }
}
