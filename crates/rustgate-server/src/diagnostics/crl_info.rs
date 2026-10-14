// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! `crl-info` — inspect a PEM-encoded X.509 CRL.
//!
//! Parses the first CRL in the given PEM file and writes a stable
//! summary (issuer, `thisUpdate` / `nextUpdate`, freshness, revoked
//! entry count, and each entry's serial + revocation date + reason)
//! to stdout.
//!
//! Addresses Finding F-183 (issue #900).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use rustls_pki_types::CertificateRevocationListDer;
use rustls_pki_types::pem::PemObject;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use x509_parser::oid_registry::OID_X509_COMMON_NAME;
use x509_parser::parse_x509_crl;
use x509_parser::time::ASN1Time;

/// Single revoked-entry row as it appears in the report.
///
/// `reason` is `None` when the CRL entry does not carry the RFC 5280
/// `CRLReason` extension — RFC-compliant but surprisingly common in
/// practice, so we distinguish "unspecified" from "absent".
#[derive(Debug, Serialize)]
pub(crate) struct RevokedEntry {
    pub(crate) serial_hex: String,
    pub(crate) revocation_date: String,
    pub(crate) reason: Option<String>,
}

/// Report shape emitted by `crl-info --json`. Field order is the
/// public contract.
#[derive(Debug, Serialize)]
pub(crate) struct CrlReport {
    pub(crate) path: String,
    pub(crate) issuer_cn: Option<String>,
    pub(crate) this_update: String,
    pub(crate) next_update: Option<String>,
    /// True iff `nextUpdate` is in the past right now. `false` when
    /// `nextUpdate` is absent (we cannot conclude staleness without a
    /// reference — the caller must treat it as "unknown").
    pub(crate) stale: bool,
    /// Seconds until `nextUpdate`; negative if already stale; `None`
    /// when the CRL has no `nextUpdate` field.
    pub(crate) seconds_until_next_update: Option<i64>,
    pub(crate) revoked_count: usize,
    pub(crate) revoked: Vec<RevokedEntry>,
    pub(crate) signature_algorithm: String,
}

/// CLI entry point. Returns the operator-facing exit code:
///
/// | Code | Meaning |
/// |------|---------|
/// | `0`  | CRL parsed cleanly and `nextUpdate` is in the future (or absent) |
/// | `1`  | The PEM is missing/malformed, or it does not contain an X.509 CRL block — surfaced via `Err` |
/// | `2`  | `nextUpdate` is in the past (CRL stale; operator must refresh) |
///
/// Exit code `1` is mapped through `?` so the caller in `main.rs` can
/// translate the `anyhow::Error` to a non-zero status. The stale path
/// is signalled in-band (Ok(2)) because the CRL itself parses cleanly
/// and the operator still wants to see the report fields.
pub(crate) fn run(path: &Path, json: bool) -> Result<i32> {
    let report = build_report(path)?;
    if json {
        let out = serde_json::to_string_pretty(&report)
            .map_err(|e| anyhow!("serialize CRL report: {e}"))?;
        println!("{out}");
    } else {
        print!("{}", render_human(&report));
    }
    Ok(if report.stale { 2 } else { 0 })
}

pub(crate) fn build_report(path: &Path) -> Result<CrlReport> {
    let bytes = std::fs::read(path).with_context(|| format!("read CRL file {}", path.display()))?;
    let crl_der: CertificateRevocationListDer<'static> =
        CertificateRevocationListDer::pem_slice_iter(&bytes)
            .next()
            .ok_or_else(|| anyhow!("no X509 CRL block found in {}", path.display()))?
            .map_err(|e| anyhow!("invalid PEM in {}: {e}", path.display()))?;

    build_report_from_der(path.to_path_buf(), crl_der.as_ref())
}

pub(crate) fn build_report_from_der(path: PathBuf, der: &[u8]) -> Result<CrlReport> {
    let (_, crl) = parse_x509_crl(der).map_err(|e| anyhow!("parse X.509 CRL: {e}"))?;

    let issuer_cn = crl
        .issuer()
        .iter_by_oid(&OID_X509_COMMON_NAME)
        .next()
        .and_then(|rdn| rdn.as_str().ok().map(|s| s.to_string()));

    let this_update = asn1_to_rfc3339(crl.last_update())?;
    let next_update_ts = crl.next_update().map(|t| t.timestamp());
    let next_update = match crl.next_update() {
        Some(t) => Some(asn1_to_rfc3339(t)?),
        None => None,
    };

    let now_ts = OffsetDateTime::now_utc().unix_timestamp();
    let (stale, seconds_until_next_update) = match next_update_ts {
        Some(ts) => (now_ts > ts, Some(ts - now_ts)),
        None => (false, None),
    };

    let mut revoked = Vec::new();
    for r in crl.iter_revoked_certificates() {
        let serial_hex = hex::encode(r.user_certificate.to_bytes_be());
        let revocation_date = asn1_to_rfc3339(r.revocation_date)?;
        let reason = r.reason_code().map(|(_, code)| code.to_string());
        revoked.push(RevokedEntry {
            serial_hex,
            revocation_date,
            reason,
        });
    }
    let revoked_count = revoked.len();

    let signature_algorithm = crl.signature_algorithm.algorithm.to_id_string();

    Ok(CrlReport {
        path: path.display().to_string(),
        issuer_cn,
        this_update,
        next_update,
        stale,
        seconds_until_next_update,
        revoked_count,
        revoked,
        signature_algorithm,
    })
}

fn asn1_to_rfc3339(t: ASN1Time) -> Result<String> {
    let ts = t.timestamp();
    let odt = OffsetDateTime::from_unix_timestamp(ts)
        .map_err(|e| anyhow!("invalid ASN.1 time {ts}: {e}"))?;
    odt.format(&Rfc3339)
        .map_err(|e| anyhow!("format ASN.1 time {ts}: {e}"))
}

pub(crate) fn render_human(r: &CrlReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "CRL: {}", r.path);
    let _ = writeln!(
        out,
        "  Issuer CN:    {}",
        r.issuer_cn.as_deref().unwrap_or("(none)")
    );
    let _ = writeln!(out, "  This Update:  {}", r.this_update);
    match &r.next_update {
        Some(n) => {
            let _ = writeln!(out, "  Next Update:  {n}");
        }
        None => {
            let _ = writeln!(out, "  Next Update:  (absent)");
        }
    }
    let status = match (r.stale, r.seconds_until_next_update) {
        (true, Some(s)) => format!("stale ({} days past nextUpdate)", -s / 86_400),
        (false, Some(s)) if s >= 0 => format!("valid ({} days until nextUpdate)", s / 86_400),
        // s < 0 but stale=false cannot happen given how we populate both
        // — fall through to a safe generic so `cargo clippy -- -D warnings`
        // still accepts the match as total.
        (false, Some(_)) => "valid".to_string(),
        (_, None) => "unknown (no nextUpdate)".to_string(),
    };
    let _ = writeln!(out, "  Status:       {status}");
    let _ = writeln!(out, "  Signature:    {}", r.signature_algorithm);
    let _ = writeln!(out, "  Revoked:      {} entries", r.revoked_count);
    for (i, e) in r.revoked.iter().enumerate() {
        let _ = writeln!(
            out,
            "    [{}] serial={} revoked={} reason={}",
            i + 1,
            e.serial_hex,
            e.revocation_date,
            e.reason.as_deref().unwrap_or("(none)")
        );
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use rustgate_test_utils::certs::TestCa;
    use tempfile::NamedTempFile;

    use super::*;

    fn write_pem(pem: &str) -> NamedTempFile {
        use std::io::Write;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(pem.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn empty_crl_reports_zero_revocations() {
        let ca = TestCa::new("diag-test-ca");
        let crl = ca.generate_crl(&[]);
        let file = write_pem(&crl);

        let r = build_report(file.path()).expect("build_report ok");

        assert_eq!(r.revoked_count, 0);
        assert!(r.revoked.is_empty());
        assert_eq!(r.issuer_cn.as_deref(), Some("diag-test-ca"));
        assert!(!r.stale, "fresh CRL must not be stale");
    }

    #[test]
    fn single_revocation_is_reported() {
        let ca = TestCa::new("diag-test-ca");
        let victim = ca.issue_client_cert("victim", &[]);
        let crl = ca.generate_crl(&[&victim.cert_pem]);
        let file = write_pem(&crl);

        let r = build_report(file.path()).expect("build_report ok");

        assert_eq!(r.revoked_count, 1);
        assert_eq!(r.revoked.len(), 1);
        let entry = &r.revoked[0];
        assert!(!entry.serial_hex.is_empty(), "serial_hex must be populated");
        // Revocation date must be in the recent past — reject anything
        // older than a day or in the future, which would indicate a
        // parser/time mixup.
        let ts = OffsetDateTime::parse(&entry.revocation_date, &Rfc3339).unwrap();
        let now = OffsetDateTime::now_utc();
        let delta = (now - ts).whole_seconds();
        assert!(
            (0..86_400).contains(&delta),
            "revocation date must be recent, got {delta}s ago"
        );
    }

    #[test]
    fn multiple_revocations_preserve_each_serial() {
        let ca = TestCa::new("diag-test-ca");
        let a = ca.issue_client_cert("a", &[]);
        let b = ca.issue_client_cert("b", &[]);
        let c = ca.issue_client_cert("c", &[]);
        let crl = ca.generate_crl(&[&a.cert_pem, &b.cert_pem, &c.cert_pem]);
        let file = write_pem(&crl);

        let r = build_report(file.path()).expect("build_report ok");

        assert_eq!(r.revoked_count, 3);
        let mut serials: Vec<_> = r.revoked.iter().map(|e| e.serial_hex.clone()).collect();
        serials.sort();
        serials.dedup();
        assert_eq!(
            serials.len(),
            3,
            "each revoked cert must have a unique serial"
        );
    }

    #[test]
    fn expired_crl_is_stale() {
        let ca = TestCa::new("diag-test-ca");
        let victim = ca.issue_client_cert("victim", &[]);
        let crl = ca.generate_expired_crl(&[&victim.cert_pem]);
        let file = write_pem(&crl);

        let r = build_report(file.path()).expect("build_report ok");

        assert!(
            r.stale,
            "generate_expired_crl must produce a CRL with nextUpdate in the past"
        );
        assert!(
            r.seconds_until_next_update.unwrap_or(0) < 0,
            "seconds_until_next_update must be negative for stale CRL"
        );
    }

    #[test]
    fn rejects_missing_file() {
        let err = build_report(Path::new("/nope/crl.pem")).expect_err("must fail on missing file");
        let msg = format!("{err}");
        assert!(
            msg.contains("read CRL file"),
            "error must mention the CRL read operation, got: {msg}"
        );
    }

    #[test]
    fn rejects_non_crl_pem() {
        let ca = TestCa::new("diag-test-ca");
        let client = ca.issue_client_cert("alice", &[]);
        // Feed a cert PEM to the CRL parser — must not silently succeed.
        let file = write_pem(&client.cert_pem);

        let err = build_report(file.path()).expect_err("must reject cert PEM");
        let msg = format!("{err}");
        assert!(
            msg.contains("no X509 CRL block"),
            "rejecting cert PEM must call out the missing CRL block, got: {msg}"
        );
    }

    #[test]
    fn json_report_is_stable_structure() {
        let ca = TestCa::new("diag-test-ca");
        let crl = ca.generate_crl(&[]);
        let file = write_pem(&crl);
        let r = build_report(file.path()).unwrap();
        let j = serde_json::to_value(&r).unwrap();

        for key in [
            "path",
            "issuer_cn",
            "this_update",
            "next_update",
            "stale",
            "seconds_until_next_update",
            "revoked_count",
            "revoked",
            "signature_algorithm",
        ] {
            assert!(
                j.get(key).is_some(),
                "JSON report missing expected key `{key}`"
            );
        }
    }

    #[test]
    fn human_output_includes_every_revoked_entry() {
        let ca = TestCa::new("diag-test-ca");
        let a = ca.issue_client_cert("a", &[]);
        let b = ca.issue_client_cert("b", &[]);
        let crl = ca.generate_crl(&[&a.cert_pem, &b.cert_pem]);
        let file = write_pem(&crl);
        let r = build_report(file.path()).unwrap();

        let rendered = render_human(&r);
        let entry_lines = rendered.lines().filter(|l| l.starts_with("    [")).count();
        assert_eq!(
            entry_lines, 2,
            "human output must include one line per revoked entry"
        );
    }

    #[test]
    fn rejects_garbage_file() {
        use std::io::Write;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"not a pem file\n").unwrap();
        f.flush().unwrap();

        let err = build_report(f.path()).expect_err("must reject non-PEM");
        let msg = format!("{err}");
        assert!(
            msg.contains("no X509 CRL block"),
            "plain text with no PEM headers must surface the no-block error, got: {msg}"
        );
    }
}
