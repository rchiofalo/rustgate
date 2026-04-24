// Copyright © 2026 Roberto Chiofalo.

//! `check-cert-expiry` — inspect one or more PEM files and report which
//! X.509 certificates are near (or past) their `notAfter` time.
//!
//! Unlike [`crate::diagnostics::cert_info`], this subcommand is designed
//! for *automation*: an operator runs it from cron, a CI smoke test, or
//! `systemd`'s `OnFailure=` pre-flight and reacts to the exit code. The
//! actual report (human block or stable JSON) is supplementary.
//!
//! # Exit codes
//!
//! The exit codes form a monotonic severity ladder:
//!
//! | Code | Meaning |
//! |------|---------|
//! | `0`  | Every certificate in every file is valid and not within `--warn-days` |
//! | `1`  | At least one certificate is within the warning window, and none worse |
//! | `2`  | At least one certificate is expired, not-yet-valid, or the file could not be read/parsed |
//!
//! Downstream scripts can therefore branch on the code alone:
//!
//! ```text
//! rustgate check-cert-expiry --warn-days 30 /etc/rustgate/tls/*.pem
//! rc=$?
//! [ $rc -eq 0 ] && exit 0
//! [ $rc -eq 1 ] && alert_page "cert rotation due soon"
//! [ $rc -eq 2 ] && alert_critical "expired cert in production"
//! ```
//!
//! # Input format
//!
//! Every positional argument is a path to a PEM file. Each file may
//! hold zero or more `CERTIFICATE` blocks; every block is inspected
//! independently so bundles, chain files, and single-cert files are all
//! handled. Non-`CERTIFICATE` blocks (private keys, DH parameters) are
//! ignored — they are not an error, matching how operators commonly mix
//! key material with its cert.
//!
//! A file with zero `CERTIFICATE` blocks is reported as an error
//! (status `no_certificate_blocks`) so an operator pointing at the wrong
//! file gets a loud signal rather than a silent "all-good" ack.
//!
//! # JSON contract
//!
//! The top-level keys (`warn_days`, `overall_status`, `min_days_until_expiry`,
//! `files`) and the per-entry keys are pinned by the tests in this
//! module. Additions land at the end; renames or removals are breaking.
//!
//! Addresses Finding F-179 (issue #900).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::OID_X509_COMMON_NAME;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;
use x509_parser::x509::X509Name;

/// Default warning threshold (days). Chosen to give a typical operator
/// enough lead time to cut a maintenance window before a cert expires.
pub(crate) const DEFAULT_WARN_DAYS: u32 = 30;

/// Status of a single certificate in the report.
///
/// Rendered as lowercase strings in JSON so downstream jq/grep scripts
/// can match without worrying about case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertStatus {
    /// `notAfter` is beyond the warning window — nothing to do.
    Ok,
    /// Currently valid, but `notAfter` lands within the warning window.
    Expiring,
    /// `notAfter` is already in the past.
    Expired,
    /// `notBefore` is in the future. Unusual in production and almost
    /// always a sign that the clock or the cert is wrong — treated at
    /// the same severity as expired because the TLS stack will reject
    /// it either way.
    NotYetValid,
}

impl CertStatus {
    /// Order the statuses so `worst_of` can bubble up the most severe
    /// result. Higher number == worse.
    fn severity(self) -> u8 {
        match self {
            CertStatus::Ok => 0,
            CertStatus::Expiring => 1,
            CertStatus::NotYetValid | CertStatus::Expired => 2,
        }
    }

    /// Render as the stable JSON string. Kept separate from `Serialize`
    /// so it can also feed the overall-status string at the top of the
    /// report (which is a `String`, not this enum, because the overall
    /// slot also carries the synthetic `error` variant for file-level
    /// failures).
    fn as_str(self) -> &'static str {
        match self {
            CertStatus::Ok => "ok",
            CertStatus::Expiring => "expiring",
            CertStatus::Expired => "expired",
            CertStatus::NotYetValid => "not_yet_valid",
        }
    }
}

/// Per-certificate row in the report.
#[derive(Debug, Serialize)]
pub(crate) struct CertExpiryEntry {
    /// Zero-based index within the file's PEM stream. Lets operators
    /// distinguish "the second cert in the bundle" from its siblings.
    pub(crate) index: usize,
    pub(crate) subject_cn: Option<String>,
    pub(crate) not_before: String,
    pub(crate) not_after: String,
    /// Seconds from now until `notAfter`. Negative for expired certs.
    pub(crate) seconds_until_expiry: i64,
    /// `seconds_until_expiry` divided by 86_400, sign-preserving. A
    /// cert that expires in 12 hours reports `0` here; consumers
    /// wanting sub-day precision look at the seconds field. An already-
    /// expired cert reports a negative number.
    pub(crate) days_until_expiry: i64,
    pub(crate) status: CertStatus,
}

/// Per-file report section. Either `error` is set (file could not be
/// read, no CERTIFICATE block found, etc.) or `certs` is populated —
/// never both.
#[derive(Debug, Serialize)]
pub(crate) struct FileReport {
    pub(crate) path: String,
    pub(crate) error: Option<String>,
    pub(crate) certs: Vec<CertExpiryEntry>,
}

/// Overall report emitted by `check-cert-expiry`.
///
/// The structure is the public contract for operators. `overall_status`
/// is a string (not the enum) because it may also be `"error"`, which
/// distinguishes file-level failures from in-cert status.
#[derive(Debug, Serialize)]
pub(crate) struct ExpiryReport {
    pub(crate) warn_days: u32,
    /// Aggregated verdict. One of `ok`, `expiring`, `expired`,
    /// `not_yet_valid`, or `error` (the last for file-level failures
    /// with no certs at all).
    pub(crate) overall_status: String,
    /// Minimum days-until-expiry across every cert inspected. `None`
    /// when the run had no parseable certs (every file errored).
    pub(crate) min_days_until_expiry: Option<i64>,
    pub(crate) files: Vec<FileReport>,
}

/// CLI entry point. Reads each file, builds the report, prints it, and
/// returns the exit code the binary should use (0/1/2 — see the module
/// docs). This is split from [`run`] so tests can assert on the exit
/// code without capturing `std::process::exit`.
pub(crate) fn run(paths: &[PathBuf], warn_days: u32, json: bool) -> Result<i32> {
    if paths.is_empty() {
        return Err(anyhow!(
            "check-cert-expiry requires at least one PEM file path"
        ));
    }
    let now = OffsetDateTime::now_utc();
    let report = build_report(paths, warn_days, now);
    if json {
        let out = serde_json::to_string_pretty(&report)
            .map_err(|e| anyhow!("serialize expiry report: {e}"))?;
        println!("{out}");
    } else {
        print!("{}", render_human(&report));
    }
    Ok(exit_code(&report))
}

/// Build a report from a fixed `now` so tests can pin the clock.
///
/// Exposed at crate level so unit tests can assert on the structured
/// data without capturing stdout or depending on wall-clock time.
pub(crate) fn build_report(paths: &[PathBuf], warn_days: u32, now: OffsetDateTime) -> ExpiryReport {
    let now_ts = now.unix_timestamp();
    let warn_cutoff_seconds = i64::from(warn_days).saturating_mul(86_400);

    let files: Vec<FileReport> = paths
        .iter()
        .map(|p| build_file_report(p, now_ts, warn_cutoff_seconds))
        .collect();

    let min_days_until_expiry = files
        .iter()
        .flat_map(|f| f.certs.iter())
        .map(|c| c.days_until_expiry)
        .min();

    let overall_status = compute_overall_status(&files);

    ExpiryReport {
        warn_days,
        overall_status,
        min_days_until_expiry,
        files,
    }
}

/// Inspect a single file and produce a `FileReport`.
///
/// File-level errors (missing, unreadable, no `CERTIFICATE` block) are
/// surfaced via `error`; parse errors on individual certificates inside
/// an otherwise-readable bundle are surfaced as synthesized entries
/// with status `expired` (so automation treats them as a hard failure —
/// silently ignoring them would be worse than a false alarm).
fn build_file_report(path: &Path, now_ts: i64, warn_cutoff_seconds: i64) -> FileReport {
    let path_str = path.display().to_string();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return FileReport {
                path: path_str,
                error: Some(format!("read: {e}")),
                certs: Vec::new(),
            };
        }
    };

    let mut certs: Vec<CertExpiryEntry> = Vec::new();
    let mut parse_error: Option<String> = None;
    for (index, der_result) in CertificateDer::pem_slice_iter(&bytes).enumerate() {
        let der: CertificateDer<'static> = match der_result {
            Ok(d) => d,
            Err(e) => {
                parse_error = Some(format!("invalid PEM at block {index}: {e}"));
                break;
            }
        };
        match build_cert_entry(index, der.as_ref(), now_ts, warn_cutoff_seconds) {
            Ok(entry) => certs.push(entry),
            Err(e) => {
                parse_error = Some(format!("parse certificate at block {index}: {e}"));
                break;
            }
        }
    }

    if let Some(msg) = parse_error {
        return FileReport {
            path: path_str,
            error: Some(msg),
            certs: Vec::new(),
        };
    }

    if certs.is_empty() {
        return FileReport {
            path: path_str,
            error: Some("no_certificate_blocks".to_string()),
            certs: Vec::new(),
        };
    }

    FileReport {
        path: path_str,
        error: None,
        certs,
    }
}

/// Parse one DER certificate and classify it against the warning
/// cutoff. Separated from the file walker so unit tests can feed known
/// DER bytes.
fn build_cert_entry(
    index: usize,
    der: &[u8],
    now_ts: i64,
    warn_cutoff_seconds: i64,
) -> Result<CertExpiryEntry> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| anyhow!("parse X.509 certificate: {e}"))?;

    let subject_cn = first_rdn_value(cert.subject(), &OID_X509_COMMON_NAME);
    let not_before = asn1_to_rfc3339(cert.validity().not_before)?;
    let not_after = asn1_to_rfc3339(cert.validity().not_after)?;

    let not_before_ts = cert.validity().not_before.timestamp();
    let not_after_ts = cert.validity().not_after.timestamp();
    let seconds_until_expiry = not_after_ts.saturating_sub(now_ts);
    let days_until_expiry = seconds_until_expiry.div_euclid(86_400);

    // Status ladder: not-yet-valid trumps expired (a clock-skew cert is
    // at least as bad as an expired one), expiring is the warning tier,
    // ok is the default. The `now_ts < not_before_ts` check has to run
    // first because an already-expired-and-not-yet-valid cert (invalid
    // but technically possible with clock skew or corrupt certs) should
    // surface as not-yet-valid so operators know to check the clock.
    let status = if now_ts < not_before_ts {
        CertStatus::NotYetValid
    } else if seconds_until_expiry <= 0 {
        CertStatus::Expired
    } else if seconds_until_expiry <= warn_cutoff_seconds {
        CertStatus::Expiring
    } else {
        CertStatus::Ok
    };

    Ok(CertExpiryEntry {
        index,
        subject_cn,
        not_before,
        not_after,
        seconds_until_expiry,
        days_until_expiry,
        status,
    })
}

/// Aggregate the per-file / per-cert statuses into a top-level string.
///
/// `"error"` is reserved for the case where *every* file failed before
/// producing any certs. If even one file produced a parseable cert, we
/// surface the worst-cert severity so a single unreadable file does
/// not mask an expiring cert next door.
fn compute_overall_status(files: &[FileReport]) -> String {
    let mut worst: Option<CertStatus> = None;
    let mut saw_any_cert = false;
    let mut saw_any_error = false;

    for f in files {
        if f.error.is_some() {
            saw_any_error = true;
        }
        for c in &f.certs {
            saw_any_cert = true;
            worst = Some(match worst {
                Some(w) if w.severity() >= c.status.severity() => w,
                _ => c.status,
            });
        }
    }

    match (saw_any_cert, saw_any_error, worst) {
        // No certs parsed anywhere — pure error state.
        (false, _, _) => "error".to_string(),
        // Some files errored but others produced certs — elevate to at
        // least "expired" since an unreadable cert file in prod is an
        // operational failure.
        (true, true, Some(w)) if w.severity() < CertStatus::Expired.severity() => {
            CertStatus::Expired.as_str().to_string()
        }
        (true, true, None) => "error".to_string(),
        (true, _, Some(w)) => w.as_str().to_string(),
        (true, _, None) => CertStatus::Ok.as_str().to_string(),
    }
}

/// Map the report to the exit code contract documented at the top of
/// the module: 0 = ok, 1 = expiring (and nothing worse), 2 = anything
/// worse or a file-level error.
pub(crate) fn exit_code(report: &ExpiryReport) -> i32 {
    match report.overall_status.as_str() {
        "ok" => 0,
        "expiring" => 1,
        // "expired", "not_yet_valid", "error", and any unknown string
        // all map to 2 — err on the side of a hard failure.
        _ => 2,
    }
}

/// First RDN value matching the given OID. Mirrors the helper in
/// `cert_info.rs` so both subcommands report the same CN for a given
/// certificate.
fn first_rdn_value(
    name: &X509Name<'_>,
    oid: &x509_parser::der_parser::oid::Oid<'_>,
) -> Option<String> {
    name.iter_by_oid(oid)
        .next()
        .and_then(|rdn| rdn.as_str().ok().map(|s| s.to_string()))
}

/// RFC 3339 rendering of an `ASN1Time`. Returns an error instead of
/// panicking if the ASN.1 time cannot be represented as
/// `OffsetDateTime` (should not happen for a valid X.509 cert).
fn asn1_to_rfc3339(t: ASN1Time) -> Result<String> {
    let ts = t.timestamp();
    let odt = OffsetDateTime::from_unix_timestamp(ts)
        .map_err(|e| anyhow!("invalid ASN.1 time {ts}: {e}"))?;
    odt.format(&Rfc3339)
        .map_err(|e| anyhow!("format ASN.1 time {ts}: {e}"))
}

/// Human-readable rendering. Cosmetic — not a stability contract.
pub(crate) fn render_human(r: &ExpiryReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "check-cert-expiry (warn threshold: {} days)",
        r.warn_days
    );
    let _ = writeln!(out, "  Overall status: {}", r.overall_status);
    if let Some(d) = r.min_days_until_expiry {
        let _ = writeln!(out, "  Min days to expiry: {d}");
    } else {
        let _ = writeln!(out, "  Min days to expiry: (no parseable certs)");
    }
    for f in &r.files {
        let _ = writeln!(out, "  File: {}", f.path);
        if let Some(ref err) = f.error {
            let _ = writeln!(out, "    error: {err}");
            continue;
        }
        for c in &f.certs {
            let cn = c.subject_cn.as_deref().unwrap_or("(none)");
            let _ = writeln!(
                out,
                "    [{}] cn={} status={} days={} not_after={}",
                c.index,
                cn,
                c.status.as_str(),
                c.days_until_expiry,
                c.not_after
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::io::Write;

    use rustgate_test_utils::certs::TestCa;
    use tempfile::NamedTempFile;
    use time::Duration as TimeDuration;

    use super::*;

    fn write_pem(pem: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(pem.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    /// Concatenate several PEM blobs into one file so we can exercise
    /// bundles / chains.
    fn write_pem_bundle(pems: &[&str]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for pem in pems {
            f.write_all(pem.as_bytes()).unwrap();
            if !pem.ends_with('\n') {
                f.write_all(b"\n").unwrap();
            }
        }
        f.flush().unwrap();
        f
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[test]
    fn fresh_cert_reports_ok() {
        let ca = TestCa::new("expiry-test-ca");
        let client = ca.issue_client_cert("alice", &[]);
        let f = write_pem(&client.cert_pem);

        let report = build_report(&[f.path().to_path_buf()], DEFAULT_WARN_DAYS, now());

        assert_eq!(report.overall_status, "ok");
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].certs.len(), 1);
        assert_eq!(report.files[0].certs[0].status, CertStatus::Ok);
        assert!(
            report.files[0].certs[0].days_until_expiry > i64::from(DEFAULT_WARN_DAYS),
            "fresh cert's days_until_expiry ({}) must exceed warn threshold ({})",
            report.files[0].certs[0].days_until_expiry,
            DEFAULT_WARN_DAYS
        );
        assert_eq!(exit_code(&report), 0, "ok report must produce exit code 0");
    }

    #[test]
    fn expiring_cert_reports_expiring_with_exit_code_1() {
        let ca = TestCa::new("expiry-test-ca");
        // `issue_near_expiry_server_cert` pins validity so the test is
        // deterministic regardless of rcgen default validity windows
        // (which are typically the full 1970..=9999 range).
        let soon = ca.issue_near_expiry_server_cert("soon", &["soon.example.com"], 10);
        let f = write_pem(&soon.cert_pem);

        let report = build_report(&[f.path().to_path_buf()], 30, now());

        assert_eq!(report.overall_status, "expiring");
        assert_eq!(report.files[0].certs[0].status, CertStatus::Expiring);
        assert!(
            (0..=30).contains(&report.files[0].certs[0].days_until_expiry),
            "cert expiring in 10 days must report days_until_expiry in [0,30], got {}",
            report.files[0].certs[0].days_until_expiry
        );
        assert_eq!(
            exit_code(&report),
            1,
            "expiring report must produce exit code 1"
        );
    }

    #[test]
    fn warn_days_zero_only_flags_already_expired_not_currently_valid_certs() {
        // Corner case: `--warn-days 0` degenerates into a binary check
        // (valid vs expired). A cert valid for 1 more day must still
        // report ok, not expiring.
        let ca = TestCa::new("expiry-test-ca");
        let soon = ca.issue_near_expiry_server_cert("soon", &["soon.example.com"], 1);
        let f = write_pem(&soon.cert_pem);
        let report = build_report(&[f.path().to_path_buf()], 0, now());
        assert_eq!(report.overall_status, "ok");
        assert_eq!(exit_code(&report), 0);
    }

    #[test]
    fn expired_cert_reports_expired_with_exit_code_2() {
        let ca = TestCa::new("expiry-test-ca");
        let expired = ca.issue_expired_client_cert("ghost", &[]);
        let f = write_pem(&expired.cert_pem);

        let report = build_report(&[f.path().to_path_buf()], DEFAULT_WARN_DAYS, now());

        assert_eq!(report.overall_status, "expired");
        assert_eq!(report.files[0].certs[0].status, CertStatus::Expired);
        assert!(
            report.files[0].certs[0].days_until_expiry <= 0,
            "expired cert must report non-positive days_until_expiry"
        );
        assert!(
            report.files[0].certs[0].seconds_until_expiry <= 0,
            "expired cert must report non-positive seconds_until_expiry"
        );
        assert_eq!(
            exit_code(&report),
            2,
            "expired report must produce exit code 2"
        );
    }

    #[test]
    fn not_yet_valid_cert_uses_pinned_clock() {
        // We want a cert whose `notBefore` is known, so we can pin a
        // fake "now" before it. `issue_near_expiry_server_cert` sets
        // `notBefore = real_now - 1 day`; pushing the fake clock back
        // 5 days is safely before that and therefore not-yet-valid.
        let ca = TestCa::new("expiry-test-ca");
        let cert = ca.issue_near_expiry_server_cert("future", &["future.example.com"], 365);
        let f = write_pem(&cert.cert_pem);

        let past = now() - TimeDuration::days(5);
        let report = build_report(&[f.path().to_path_buf()], DEFAULT_WARN_DAYS, past);

        assert_eq!(report.overall_status, "not_yet_valid");
        assert_eq!(report.files[0].certs[0].status, CertStatus::NotYetValid);
        assert_eq!(
            exit_code(&report),
            2,
            "not_yet_valid must also map to exit code 2"
        );
    }

    #[test]
    fn missing_file_is_reported_with_error_status() {
        let report = build_report(
            &[PathBuf::from("/definitely/not/there.pem")],
            DEFAULT_WARN_DAYS,
            now(),
        );
        assert_eq!(report.overall_status, "error");
        assert_eq!(report.min_days_until_expiry, None);
        assert!(
            report.files[0]
                .error
                .as_deref()
                .unwrap()
                .starts_with("read:")
        );
        assert_eq!(exit_code(&report), 2);
    }

    #[test]
    fn file_without_certificate_block_surfaces_helpful_error() {
        let f = write_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        let report = build_report(&[f.path().to_path_buf()], DEFAULT_WARN_DAYS, now());
        assert_eq!(report.overall_status, "error");
        assert_eq!(
            report.files[0].error.as_deref(),
            Some("no_certificate_blocks"),
            "key-only PEM must surface the canonical marker"
        );
    }

    #[test]
    fn bundle_reports_every_cert_and_takes_worst_status() {
        let ca = TestCa::new("expiry-test-ca");
        let fresh = ca.issue_client_cert("alice", &[]);
        let expired = ca.issue_expired_client_cert("ghost", &[]);
        let f = write_pem_bundle(&[&fresh.cert_pem, &expired.cert_pem]);

        let report = build_report(&[f.path().to_path_buf()], DEFAULT_WARN_DAYS, now());

        assert_eq!(
            report.files[0].certs.len(),
            2,
            "every CERTIFICATE block in a bundle must be inspected"
        );
        // Indices must be 0, 1 in order — operators rely on this to tie
        // a cert back to its position in the bundle.
        assert_eq!(report.files[0].certs[0].index, 0);
        assert_eq!(report.files[0].certs[1].index, 1);
        // Worst-cert wins at the top.
        assert_eq!(report.overall_status, "expired");
        assert!(report.min_days_until_expiry.unwrap() < 0);
    }

    #[test]
    fn mixed_files_elevate_overall_when_one_errors_and_another_is_ok() {
        // An OK cert in one file + an unreadable path in another must
        // surface as "expired" at the top so the unreadable file cannot
        // hide behind the healthy one — a missing cert file in prod is
        // an operational problem even if another cert checks out.
        let ca = TestCa::new("expiry-test-ca");
        let client = ca.issue_client_cert("alice", &[]);
        let good = write_pem(&client.cert_pem);
        let bad = PathBuf::from("/definitely/not/there.pem");

        let report = build_report(&[good.path().to_path_buf(), bad], DEFAULT_WARN_DAYS, now());

        assert_eq!(
            report.overall_status, "expired",
            "file-level error alongside an otherwise-OK cert must escalate overall_status"
        );
        assert_eq!(exit_code(&report), 2);
        assert_eq!(report.files[0].error, None);
        assert!(report.files[1].error.is_some());
    }

    #[test]
    fn expiring_plus_unreadable_still_escalates_to_expired() {
        let ca = TestCa::new("expiry-test-ca");
        let client = ca.issue_client_cert("alice", &[]);
        let expiring = write_pem(&client.cert_pem);
        let bad = PathBuf::from("/definitely/not/there.pem");

        // warn_days pulls the fresh cert into the warning window.
        let report = build_report(&[expiring.path().to_path_buf(), bad], 400, now());

        assert_eq!(
            report.overall_status, "expired",
            "an unreadable file must escalate even when the parseable cert is merely expiring"
        );
        assert_eq!(exit_code(&report), 2);
    }

    #[test]
    fn min_days_until_expiry_is_smallest_across_all_certs() {
        let ca = TestCa::new("expiry-test-ca");
        let alice = ca.issue_client_cert("alice", &[]);
        let bob = ca.issue_client_cert("bob", &[]);
        let expired = ca.issue_expired_client_cert("ghost", &[]);
        let f = write_pem_bundle(&[&alice.cert_pem, &bob.cert_pem, &expired.cert_pem]);

        let report = build_report(&[f.path().to_path_buf()], DEFAULT_WARN_DAYS, now());

        let min = report.min_days_until_expiry.unwrap();
        assert!(min < 0, "min must reflect the already-expired cert");
        // Everything else must be >= min.
        for cert in &report.files[0].certs {
            assert!(cert.days_until_expiry >= min);
        }
    }

    #[test]
    fn run_rejects_empty_path_list() {
        let err = run(&[], DEFAULT_WARN_DAYS, false).expect_err("empty paths must fail");
        assert!(
            err.to_string().contains("at least one PEM file"),
            "error must name the requirement, got: {err}"
        );
    }

    #[test]
    fn json_report_has_stable_top_level_keys() {
        let ca = TestCa::new("expiry-test-ca");
        let client = ca.issue_client_cert("alice", &[]);
        let f = write_pem(&client.cert_pem);
        let report = build_report(&[f.path().to_path_buf()], DEFAULT_WARN_DAYS, now());
        let j = serde_json::to_value(&report).unwrap();

        for key in [
            "warn_days",
            "overall_status",
            "min_days_until_expiry",
            "files",
        ] {
            assert!(
                j.get(key).is_some(),
                "top-level JSON must include key `{key}`"
            );
        }
        let entry = &j["files"][0]["certs"][0];
        for key in [
            "index",
            "subject_cn",
            "not_before",
            "not_after",
            "seconds_until_expiry",
            "days_until_expiry",
            "status",
        ] {
            assert!(
                entry.get(key).is_some(),
                "per-cert JSON must include key `{key}`"
            );
        }
        assert_eq!(entry["status"].as_str(), Some("ok"));
    }

    #[test]
    fn human_render_names_file_and_overall_status() {
        let ca = TestCa::new("expiry-test-ca");
        let client = ca.issue_client_cert("alice", &[]);
        let f = write_pem(&client.cert_pem);
        let report = build_report(&[f.path().to_path_buf()], DEFAULT_WARN_DAYS, now());
        let s = render_human(&report);

        assert!(s.contains("check-cert-expiry"));
        assert!(s.contains("warn threshold: 30 days"));
        assert!(s.contains("Overall status: ok"));
        assert!(s.contains("cn=alice"));
        assert!(s.contains("status=ok"));
    }

    #[test]
    fn human_render_flags_expired_file_level_error() {
        let report = build_report(
            &[PathBuf::from("/definitely/not/there.pem")],
            DEFAULT_WARN_DAYS,
            now(),
        );
        let s = render_human(&report);
        assert!(s.contains("Overall status: error"));
        assert!(
            s.contains("error: read:"),
            "human render must surface the read-error prefix so operators see what broke"
        );
    }

    #[test]
    fn status_severity_ordering_is_monotonic() {
        // Defense-in-depth: if the severity table ever drifts we want
        // the test to fail loudly rather than let overall_status
        // silently downgrade.
        assert!(CertStatus::Ok.severity() < CertStatus::Expiring.severity());
        assert!(CertStatus::Expiring.severity() < CertStatus::Expired.severity());
        assert_eq!(
            CertStatus::Expired.severity(),
            CertStatus::NotYetValid.severity()
        );
    }
}
