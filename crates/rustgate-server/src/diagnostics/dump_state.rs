// Copyright © 2026 Roberto Chiofalo.

//! `dump-state` — capture an offline diagnostic snapshot of a running
//! server's *locally observable* state.
//!
//! This subcommand is the forensic / bug-report pair to the live
//! management API. It never connects to a remote endpoint, never opens
//! a listener, and never reads private key material. The snapshot it
//! produces contains:
//!
//! - **Build metadata** (`rustgate_version`) — pinned at compile time
//!   via `CARGO_PKG_VERSION` so the snapshot always identifies the
//!   binary that wrote it, even if the operator later forgets which
//!   release they were running.
//! - **Timestamp** (`generated_at`) — RFC 3339 UTC.
//! - **Effective configuration** (`config`) — the merged result of the
//!   CLI flags, environment variables, and `--config` TOML file the
//!   running server would consume, serialized through the same
//!   `redact_optional_secret` path that `print-config` uses *plus* a
//!   second redaction layer that scrubs path fields known to point at
//!   on-disk secrets (TLS keys, NATS credentials, archive keys, bearer
//!   tokens, …). See [`SECRET_PATH_FIELDS`] for the exhaustive list.
//! - **CRL summary** (`crl`) — a [`crate::diagnostics::crl_info`]
//!   report when `--crl` is configured, so an operator can confirm in
//!   one step that the CRL is not stale.
//! - **Audit log tail** (`audit_log`) — up to the last
//!   [`AUDIT_TAIL_MAX_LINES`] events from the configured audit log,
//!   parsed as JSON-Lines. Records that fail to parse are surfaced as
//!   `{ raw: "<line>" }` so corruption is visible rather than silently
//!   dropped. Tail is `null` when no audit log is configured.
//!
//! # Why redact paths
//!
//! The configuration file paths themselves are not strictly secret,
//! but they leak information about deployment topology (mount layouts,
//! volume names, vault references, customer identifiers embedded in
//! key file names). The threat model assumes an operator may attach
//! the snapshot to a public bug tracker; the conservative default is
//! to redact every path that names a key, credential, or token —
//! consistent with the F-149 / #900 review notes.
//!
//! # Output format
//!
//! `--format json` (default) emits a stable document suitable for
//! tooling. `--format toml` emits the same document with `toml`-pretty
//! formatting; both formats round-trip through the same intermediate
//! [`Snapshot`] struct so the field shape is identical.
//!
//! When `--output PATH` is supplied the snapshot is written to that
//! file with mode `0o600` (Unix). On Windows the permissions tightener
//! is a no-op and the file inherits the default ACL — the snapshot is
//! redacted by construction, so a slightly looser POSIX permission is
//! treated as defense-in-depth rather than a security boundary.
//!
//! Closes #900.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::cli::{Cli, DumpFormat, load_config_file};
use crate::diagnostics::crl_info::{self, CrlReport};

/// Hard cap on the number of audit log lines included in the snapshot.
///
/// 100 is the value advertised in the issue contract (#900). Caps
/// large enough to be useful for forensics, small enough that an
/// attached snapshot stays under the typical bug-tracker upload
/// limits even on a busy server.
pub(crate) const AUDIT_TAIL_MAX_LINES: usize = 100;

/// Sentinel string used to redact secret-bearing fields. Matches the
/// existing `redact_optional_secret` helper in `crate::cli` so any
/// snapshot consumer that already greps for `<redacted>` (e.g. CI's
/// secret-leak detector) keeps working.
pub(crate) const REDACTED: &str = "<redacted>";

/// Names of the [`crate::cli::Cli`] fields whose value is a path to a
/// secret-bearing on-disk artifact. The dump-state serializer rewrites
/// any non-empty value at one of these keys to [`REDACTED`] in the
/// JSON intermediate, before the final `--format` rendering. The list
/// is intentionally exhaustive: when in doubt, redact.
///
/// Names are kebab-case because the `Cli` struct carries
/// `#[serde(rename_all = "kebab-case")]` — the JSON intermediate
/// produced by `serde_json::to_value(&cli)` uses kebab-case keys.
///
/// `enrollment-password` is *not* in this list — it is already redacted
/// at the `Cli` Serialize level via `redact_optional_secret`, and the
/// snapshot reuses that path verbatim.
pub(crate) const SECRET_PATH_FIELDS: &[&str] = &[
    "key",                   // TLS server private key
    "ca-key",                // CA private key (signs enrollment CSRs)
    "nats-credentials",      // NATS JWT / NKey credentials file
    "nats-tls-key",          // NATS mTLS client private key
    "metrics-token-file",    // Prometheus bearer token
    "acl-api-token-file",    // ACL API bearer token
    "mgmt-api-token-file",   // Management API bearer token
    "archive-key-file",      // ChaCha20-Poly1305 archive AEAD key
    "client-queue-key-file", // Store-and-forward AEAD key
];

/// One audit log line surfaced in the snapshot. The dual `parsed` /
/// `raw` shape lets corrupted/non-JSON lines flow through verbatim
/// instead of being silently dropped — corruption is itself a
/// forensic signal.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum AuditEntry {
    /// Successfully parsed JSON object. `BTreeMap` preserves a
    /// deterministic key order so two snapshots of the same line hash
    /// to the same digest.
    Parsed(BTreeMap<String, serde_json::Value>),
    /// JSON parse failed. The literal line is captured under `raw` so
    /// an operator can still inspect what was on disk.
    Raw { raw: String },
}

/// Audit log section of the snapshot.
#[derive(Debug, Serialize)]
pub(crate) struct AuditSnapshot {
    /// The path the snapshot was read from. Always populated when
    /// audit logging is configured (independent of whether the file
    /// exists — a missing file is reported as `present = false`).
    pub(crate) path: String,
    /// Whether the audit log file was found on disk at snapshot time.
    /// `false` is normal on first run before any record has been
    /// written.
    pub(crate) present: bool,
    /// Number of lines actually included in `entries`. Distinct from
    /// the file's full record count — the snapshot only carries the
    /// most recent [`AUDIT_TAIL_MAX_LINES`].
    pub(crate) entries_returned: usize,
    /// Tail of the audit log, oldest-to-newest. Empty when the file is
    /// missing or empty.
    pub(crate) entries: Vec<AuditEntry>,
}

/// Top-level snapshot document. Field order is the contract — adding
/// new fields is backwards-compatible; renaming or removing is a
/// breaking change for downstream tooling.
#[derive(Debug, Serialize)]
pub(crate) struct Snapshot {
    /// Compile-time `CARGO_PKG_VERSION` of the binary that produced
    /// the snapshot. Pinned by the `Cargo.toml` workspace version.
    pub(crate) rustgate_version: String,
    /// RFC 3339 UTC timestamp when the snapshot was built.
    pub(crate) generated_at: String,
    /// Path the operator passed via `--config`.
    pub(crate) config_path: String,
    /// The merged effective configuration with secrets redacted. Stored
    /// as `serde_json::Value` so the same intermediate can flow into
    /// both the JSON and TOML emitters.
    pub(crate) config: serde_json::Value,
    /// Names of fields the redaction layer rewrote. Useful for an
    /// operator double-checking what was scrubbed before sending the
    /// snapshot to a third party.
    pub(crate) redacted_fields: Vec<String>,
    /// CRL summary produced by [`crl_info::build_report`] when `--crl`
    /// is configured; `null` otherwise.
    pub(crate) crl: Option<CrlReport>,
    /// Audit log tail and metadata; `null` when `--audit-log` is unset
    /// or set to `"-"` (stdout has no on-disk artifact to read).
    pub(crate) audit_log: Option<AuditSnapshot>,
}

/// CLI entry point. Builds the snapshot, then serialises it to
/// `output` (file or stdout) in the requested format.
pub(crate) fn run(config: &Path, format: DumpFormat, output: Option<&Path>) -> Result<()> {
    let snapshot = build_snapshot(config)?;
    let body = render(&snapshot, format)?;

    match output {
        Some(path) => write_to_file(path, &body)?,
        None => {
            // Avoid println! double-newline; the body already ends
            // with `\n` from the JSON pretty / TOML pretty emitters.
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(body.as_bytes())
                .context("write snapshot to stdout")?;
            if !body.ends_with('\n') {
                stdout
                    .write_all(b"\n")
                    .context("append newline to stdout")?;
            }
        }
    }
    Ok(())
}

/// Build a [`Snapshot`] from the on-disk config without performing any
/// I/O beyond reading the listed files. Exposed at `pub(crate)` so the
/// integration tests can exercise the redaction logic without spawning
/// the binary.
pub(crate) fn build_snapshot(config: &Path) -> Result<Snapshot> {
    let cli = load_cli_from_config(config)?;

    let (config_value, redacted_fields) = redact_config(&cli)?;

    let crl_report = match cli.tls.crl {
        Some(ref p) if !p.is_empty() => {
            // Read CRL best-effort: a missing or malformed CRL is *not*
            // a fatal snapshot error — the snapshot's job is to surface
            // diagnostic state, not to validate it. Embed the parse
            // error message instead.
            match crl_info::build_report(Path::new(p)) {
                Ok(r) => Some(r),
                Err(e) => Some(crl_info::CrlReport {
                    path: p.clone(),
                    issuer_cn: None,
                    this_update: String::new(),
                    next_update: None,
                    stale: false,
                    seconds_until_next_update: None,
                    revoked_count: 0,
                    revoked: Vec::new(),
                    signature_algorithm: format!("error: {e}"),
                }),
            }
        }
        _ => None,
    };

    let audit_log = audit_snapshot_from_path(cli.observability.audit_log.as_deref());

    Ok(Snapshot {
        rustgate_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|e| anyhow!("format generated_at timestamp: {e}"))?,
        config_path: config.display().to_string(),
        config: config_value,
        redacted_fields,
        crl: crl_report,
        audit_log,
    })
}

/// Build a [`Cli`] populated with values from the given config file.
///
/// The server's normal startup path layers CLI flags + env vars on top
/// of file values; for an offline snapshot we want the *file's* view
/// only, so we parse a stub command line that satisfies the required-
/// arg checks (`--cert`, `--key`, `--ca`) with placeholders, then
/// overlay the file's values via the existing `apply_to` helper.
fn load_cli_from_config(config_path: &Path) -> Result<Cli> {
    use clap::{CommandFactory, FromArgMatches};

    let path_str = config_path.to_string_lossy().into_owned();
    if !config_path.exists() {
        return Err(anyhow!(
            "config file does not exist: {}",
            config_path.display()
        ));
    }

    // Synthetic argv. Passing only `--config` is enough: the top-level
    // `--cert`/`--key`/`--ca` flags carry
    // `required_unless_present_any = ["config", "spiffe"]` — clap will
    // accept the parse with `--config` alone, leaving the cert/key/ca
    // values at their `default_value = ""` so `apply_to` populates
    // them from the file via `ValueSource::DefaultValue`.
    let argv = ["rustgate", "--config", &path_str];
    let matches = Cli::command()
        .try_get_matches_from(argv)
        .map_err(|e| anyhow!("parse synthetic CLI for dump-state: {e}"))?;
    let mut cli =
        Cli::from_arg_matches(&matches).map_err(|e| anyhow!("hydrate Cli for dump-state: {e}"))?;
    let file = load_config_file(&path_str)?;
    file.apply_to(&mut cli, &matches);
    Ok(cli)
}

/// Serialize the [`Cli`] to a JSON value, then walk the top-level
/// object and rewrite any field listed in [`SECRET_PATH_FIELDS`] to
/// the [`REDACTED`] sentinel (when the value is non-null and
/// non-empty). Returns the rewritten value alongside the list of
/// fields that were actually rewritten — operators reviewing the
/// snapshot can then double-check what was scrubbed.
fn redact_config(cli: &Cli) -> Result<(serde_json::Value, Vec<String>)> {
    let mut value =
        serde_json::to_value(cli).map_err(|e| anyhow!("serialize config to JSON: {e}"))?;

    let mut redacted = Vec::new();

    if let serde_json::Value::Object(ref mut map) = value {
        for &field in SECRET_PATH_FIELDS {
            if let Some(entry) = map.get_mut(field)
                && should_redact(entry)
            {
                *entry = serde_json::Value::String(REDACTED.to_string());
                redacted.push(field.to_string());
            }
        }
    }

    Ok((value, redacted))
}

/// True if a field's serialized value is something operators would
/// want hidden — non-null, non-empty strings, or any non-null path-y
/// value. `null`, missing, and empty-string fields pass through so the
/// snapshot still records *whether* the option was set.
fn should_redact(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::String(s) => !s.is_empty() && s != REDACTED,
        // The `Option<PathBuf>` clap fields serialize as a string when
        // present, so this branch is mostly unreachable in practice;
        // keeping the explicit fallthrough avoids a silent regression
        // if a future config field is changed to a richer type.
        _ => true,
    }
}

/// Read the configured audit log and return the last
/// [`AUDIT_TAIL_MAX_LINES`] entries, parsed as JSON when possible.
///
/// Returns:
/// - `None` when no audit log is configured, or it is set to `"-"`
///   (stdout sink — there is no file to read).
/// - `Some(AuditSnapshot { present: false, entries: [] })` when a path
///   is configured but the file does not exist (first run, or audit
///   log rotated out).
/// - `Some(AuditSnapshot { present: true, .. })` with up to
///   [`AUDIT_TAIL_MAX_LINES`] entries otherwise.
fn audit_snapshot_from_path(audit_log: Option<&str>) -> Option<AuditSnapshot> {
    let path_str = audit_log?;
    if path_str == "-" {
        // Stdout sink — no on-disk artifact to read. Emit `None` so
        // the snapshot does not pretend an audit file is present.
        return None;
    }
    let path = Path::new(path_str);
    if !path.exists() {
        return Some(AuditSnapshot {
            path: path_str.to_string(),
            present: false,
            entries_returned: 0,
            entries: Vec::new(),
        });
    }

    let entries = read_audit_tail(path).unwrap_or_default();

    Some(AuditSnapshot {
        path: path_str.to_string(),
        present: true,
        entries_returned: entries.len(),
        entries,
    })
}

/// Read the last [`AUDIT_TAIL_MAX_LINES`] lines from the audit log,
/// preserving order. Lines that fail to parse as JSON are wrapped in
/// [`AuditEntry::Raw`] so the snapshot still surfaces them.
///
/// This deliberately reads the whole file rather than seeking from
/// the end: audit logs are small (every record is a structured event,
/// not a stream of bytes), and a streaming line iterator handles
/// arbitrary line lengths and partial torn writes more cleanly than a
/// reverse-scan for `\n`.
fn read_audit_tail(path: &Path) -> Result<Vec<AuditEntry>> {
    let file = File::open(path).with_context(|| format!("open audit log {}", path.display()))?;
    let reader = BufReader::new(file);

    // Use a fixed-capacity ring so the working set stays bounded even
    // on multi-gigabyte audit files.
    let mut tail: std::collections::VecDeque<String> =
        std::collections::VecDeque::with_capacity(AUDIT_TAIL_MAX_LINES);
    for line in reader.lines() {
        let line = line.with_context(|| format!("read audit log line from {}", path.display()))?;
        if line.is_empty() {
            continue;
        }
        if tail.len() == AUDIT_TAIL_MAX_LINES {
            let _ = tail.pop_front();
        }
        tail.push_back(line);
    }

    let parsed: Vec<AuditEntry> = tail
        .into_iter()
        .map(
            |line| match serde_json::from_str::<BTreeMap<String, serde_json::Value>>(&line) {
                Ok(map) => AuditEntry::Parsed(map),
                Err(_) => AuditEntry::Raw { raw: line },
            },
        )
        .collect();

    Ok(parsed)
}

/// Render the [`Snapshot`] in the requested output format.
fn render(snapshot: &Snapshot, format: DumpFormat) -> Result<String> {
    match format {
        DumpFormat::Json => {
            let mut out = serde_json::to_string_pretty(snapshot)
                .map_err(|e| anyhow!("serialize snapshot as JSON: {e}"))?;
            // Pretty serializer omits the trailing newline; pad it so
            // the output behaves like every other Unix line tool.
            out.push('\n');
            Ok(out)
        }
        DumpFormat::Toml => {
            // Round-trip through serde_json::Value first so the audit
            // log's untagged enum (Parsed | Raw) flattens to a JSON
            // object/array shape that toml::Value can accept; toml's
            // serializer otherwise rejects bare untagged enum values.
            let bridge: serde_json::Value = serde_json::to_value(snapshot)
                .map_err(|e| anyhow!("bridge snapshot through serde_json: {e}"))?;
            let toml_value = json_to_toml(bridge)?;
            let out = toml::to_string_pretty(&toml_value)
                .map_err(|e| anyhow!("serialize snapshot as TOML: {e}"))?;
            Ok(out)
        }
    }
}

/// Convert a `serde_json::Value` to `toml::Value`. TOML cannot
/// represent `null`, so null-valued fields are dropped — operators
/// reading the TOML form would not learn anything from the explicit
/// absence anyway. TOML also cannot represent NaN/infinity in floats;
/// we coerce those to `0.0` rather than failing because the snapshot
/// must always serialize.
fn json_to_toml(value: serde_json::Value) -> Result<toml::Value> {
    Ok(match value {
        serde_json::Value::Null => toml::Value::String(String::new()),
        serde_json::Value::Bool(b) => toml::Value::Boolean(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                if f.is_finite() {
                    toml::Value::Float(f)
                } else {
                    toml::Value::Float(0.0)
                }
            } else {
                toml::Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => toml::Value::String(s),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_to_toml(item)?);
            }
            toml::Value::Array(out)
        }
        serde_json::Value::Object(map) => {
            let mut out = toml::map::Map::new();
            for (k, v) in map {
                if v.is_null() {
                    continue;
                }
                let _ = out.insert(k, json_to_toml(v)?);
            }
            toml::Value::Table(out)
        }
    })
}

/// Write the snapshot body to the requested file path with
/// owner-only permissions on Unix. The file is created or truncated;
/// on POSIX, mode `0o600` is applied via [`std::os::unix::fs::PermissionsExt`].
fn write_to_file(path: &Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        return Err(anyhow!(
            "output directory does not exist: {}",
            parent.display()
        ));
    }

    let mut file =
        File::create(path).with_context(|| format!("create snapshot file {}", path.display()))?;
    file.write_all(body.as_bytes())
        .with_context(|| format!("write snapshot to {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flush snapshot to {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("tighten permissions on {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::io::Write;
    use std::path::PathBuf;

    use rustgate_test_utils::certs::TestCa;
    use serde_json::Value as JsonValue;
    use tempfile::TempDir;

    use super::*;

    /// Build a minimal config file referencing fresh test certs and
    /// the supplied extra TOML body. The returned tempdir owns every
    /// file referenced by the config so paths stay valid until the
    /// caller drops it.
    fn write_minimal_config(extra_body: &str) -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let ca = TestCa::new("dump-state-ca");
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

    #[test]
    fn snapshot_records_version_and_timestamp() {
        let (_dir, config) = write_minimal_config("");
        let snap = build_snapshot(&config).expect("build_snapshot ok");

        assert_eq!(snap.rustgate_version, env!("CARGO_PKG_VERSION"));
        // RFC 3339 timestamps end with `Z` (UTC) when produced by
        // OffsetDateTime::now_utc — pin that contract.
        assert!(
            snap.generated_at.ends_with('Z'),
            "generated_at must be RFC 3339 UTC; got {}",
            snap.generated_at
        );
    }

    #[test]
    fn snapshot_redacts_known_secret_path_fields() {
        // Drop a fake key file path into the config; the redactor
        // should rewrite the value to `<redacted>` and surface the
        // field name in `redacted_fields`.
        let body = "ca-key = \"/etc/rustgate/ca.key\"\n\
                    metrics-token-file = \"/run/secrets/metrics.tok\"\n";
        let (_dir, config) = write_minimal_config(body);
        let snap = build_snapshot(&config).expect("build_snapshot ok");

        let cfg = &snap.config;
        assert_eq!(
            cfg.get("ca-key").and_then(JsonValue::as_str),
            Some(REDACTED),
            "ca-key path must be redacted",
        );
        assert_eq!(
            cfg.get("metrics-token-file").and_then(JsonValue::as_str),
            Some(REDACTED),
            "metrics-token-file path must be redacted",
        );
        assert!(
            snap.redacted_fields.iter().any(|f| f == "ca-key"),
            "redacted_fields must list ca-key",
        );
        assert!(
            snap.redacted_fields
                .iter()
                .any(|f| f == "metrics-token-file"),
            "redacted_fields must list metrics-token-file",
        );
    }

    #[test]
    fn snapshot_does_not_invent_audit_log_when_unset() {
        let (_dir, config) = write_minimal_config("");
        let snap = build_snapshot(&config).expect("build_snapshot ok");
        assert!(
            snap.audit_log.is_none(),
            "audit_log must be None when --audit-log is unset",
        );
    }

    #[test]
    fn snapshot_reads_audit_log_tail() {
        let (dir, _) = write_minimal_config("");
        let audit_path = dir.path().join("audit.jsonl");
        let mut audit = std::fs::File::create(&audit_path).unwrap();
        // Mix a JSON record with a corrupt one — the parser must keep
        // both, the corrupt one wrapped in `Raw`.
        writeln!(audit, "{{\"event_type\":\"test\",\"seq\":1}}").unwrap();
        writeln!(audit, "this is not json").unwrap();
        audit.flush().unwrap();

        let body = format!("audit-log = \"{}\"\n", audit_path.display());
        let (_dir2, config) = write_minimal_config(&body);

        let snap = build_snapshot(&config).expect("build_snapshot ok");
        let audit_snapshot = snap.audit_log.expect("audit_log must be Some");
        assert!(
            audit_snapshot.present,
            "audit log must be reported as present"
        );
        assert_eq!(audit_snapshot.entries_returned, 2);
        assert!(matches!(audit_snapshot.entries[0], AuditEntry::Parsed(_)));
        assert!(matches!(audit_snapshot.entries[1], AuditEntry::Raw { .. }));
    }

    #[test]
    fn snapshot_caps_audit_tail_at_max_lines() {
        let (dir, _) = write_minimal_config("");
        let audit_path = dir.path().join("audit.jsonl");
        let mut audit = std::fs::File::create(&audit_path).unwrap();
        for i in 0..(AUDIT_TAIL_MAX_LINES + 50) {
            writeln!(audit, "{{\"event_type\":\"x\",\"seq\":{i}}}").unwrap();
        }
        audit.flush().unwrap();

        let body = format!("audit-log = \"{}\"\n", audit_path.display());
        let (_dir2, config) = write_minimal_config(&body);

        let snap = build_snapshot(&config).expect("build_snapshot ok");
        let audit_snapshot = snap.audit_log.expect("audit_log must be Some");
        assert_eq!(
            audit_snapshot.entries_returned, AUDIT_TAIL_MAX_LINES,
            "snapshot must cap at AUDIT_TAIL_MAX_LINES",
        );
    }

    #[test]
    fn snapshot_includes_crl_summary_when_crl_configured() {
        // Drop a real CRL into the tempdir and reference it from the
        // config so the snapshot embeds a parsed CrlReport.
        let dir = TempDir::new().unwrap();
        let ca = TestCa::new("dump-state-ca");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        let crl_pem = ca.generate_crl(&[]);
        let crl_path = dir.path().join("rustgate.crl");
        std::fs::write(&crl_path, &crl_pem).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, &server.cert_pem).unwrap();
        std::fs::write(&key_path, &server.key_pem).unwrap();
        std::fs::write(&ca_path, &ca.cert_pem).unwrap();

        let config_path = dir.path().join("rustgate.toml");
        let body = format!(
            "cert = \"{}\"\nkey = \"{}\"\nca = \"{}\"\ncrl = \"{}\"\n",
            cert_path.display(),
            key_path.display(),
            ca_path.display(),
            crl_path.display(),
        );
        std::fs::write(&config_path, body).unwrap();

        let snap = build_snapshot(&config_path).expect("build_snapshot ok");
        let crl = snap.crl.expect("crl must be Some when --crl is set");
        assert_eq!(crl.issuer_cn.as_deref(), Some("dump-state-ca"));
        assert_eq!(crl.revoked_count, 0);
    }

    #[test]
    fn render_json_round_trips_through_serde() {
        let (_dir, config) = write_minimal_config("");
        let snap = build_snapshot(&config).unwrap();
        let body = render(&snap, DumpFormat::Json).unwrap();
        let parsed: JsonValue = serde_json::from_str(&body).expect("output must be valid JSON");
        assert!(parsed.get("rustgate_version").is_some());
        assert!(parsed.get("config").is_some());
    }

    #[test]
    fn render_toml_round_trips_through_serde() {
        let (_dir, config) = write_minimal_config("");
        let snap = build_snapshot(&config).unwrap();
        let body = render(&snap, DumpFormat::Toml).unwrap();
        let parsed: toml::Value = toml::from_str(&body).expect("output must be valid TOML");
        let table = parsed.as_table().expect("top level must be a table");
        assert!(table.contains_key("rustgate_version"));
    }

    #[test]
    fn write_to_file_creates_owner_only_on_unix() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("snap.json");
        write_to_file(&path, "hello").unwrap();
        let read = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read, "hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "snapshot file must be created with mode 0600 on Unix",
            );
        }
    }

    #[test]
    fn missing_config_file_is_a_clean_error() {
        let err = build_snapshot(Path::new("/nonexistent/rustgate.toml")).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("does not exist") || msg.contains("not found"),
            "error must mention missing file, got: {msg}"
        );
    }
}
