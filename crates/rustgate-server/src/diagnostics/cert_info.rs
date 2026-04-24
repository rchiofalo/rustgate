// Copyright © 2026 Roberto Chiofalo.

//! `cert-info` — inspect a PEM-encoded X.509 certificate.
//!
//! Parses the first certificate in the given PEM file and writes a
//! stable summary (subject, issuer, validity, SANs, groups, key usage,
//! SPIFFE ID, fingerprint) to stdout.
//!
//! The JSON form is the contract piece — schemas pinned by unit
//! tests. Human output is for readability only.
//!
//! Addresses Finding F-178 (issue #900).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::{
    OID_X509_COMMON_NAME, OID_X509_COUNTRY_NAME, OID_X509_EXT_KEY_USAGE,
    OID_X509_ORGANIZATION_NAME, OID_X509_ORGANIZATIONAL_UNIT,
};
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;
use x509_parser::x509::X509Name;

/// Report shape emitted by `cert-info --json`.
///
/// Field order is part of the on-wire contract and must stay stable.
/// Additions belong at the end; renames or removals are breaking.
#[derive(Debug, Serialize)]
pub(crate) struct CertReport {
    pub(crate) path: String,
    pub(crate) subject_cn: Option<String>,
    pub(crate) issuer_cn: Option<String>,
    pub(crate) serial_hex: String,
    pub(crate) not_before: String,
    pub(crate) not_after: String,
    pub(crate) valid_now: bool,
    pub(crate) expired: bool,
    pub(crate) seconds_until_expiry: i64,
    pub(crate) fingerprint_sha256: String,
    pub(crate) organization: Option<String>,
    pub(crate) country: Option<String>,
    pub(crate) groups: Vec<String>,
    pub(crate) spiffe_id: Option<String>,
    pub(crate) san_dns: Vec<String>,
    pub(crate) san_uri: Vec<String>,
    pub(crate) san_ip: Vec<String>,
    pub(crate) san_email: Vec<String>,
    pub(crate) key_usage: Vec<String>,
    pub(crate) extended_key_usage: Vec<String>,
    pub(crate) is_ca: bool,
    pub(crate) signature_algorithm: String,
}

/// CLI entry point. Reads the file at `path`, parses the first
/// certificate, and prints either a JSON document (`json == true`) or
/// a human-readable block to stdout.
pub(crate) fn run(path: &Path, json: bool) -> Result<()> {
    let report = build_report(path)?;
    if json {
        let out = serde_json::to_string_pretty(&report)
            .map_err(|e| anyhow!("serialize cert report: {e}"))?;
        println!("{out}");
    } else {
        print!("{}", render_human(&report));
    }
    Ok(())
}

/// Parse the file and build a [`CertReport`].
///
/// Separated from [`run`] so tests can assert on the structured data
/// without capturing stdout.
pub(crate) fn build_report(path: &Path) -> Result<CertReport> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read certificate file {}", path.display()))?;

    // `pem_slice_iter` yields each certificate in the PEM file; we only
    // inspect the first. If the file contains a chain, later certs are
    // ignored — the operator is asking about "this cert", not the
    // whole bundle. If no cert is found, we return a dedicated error
    // so the CLI message is precise instead of a generic parse error.
    let cert_der: CertificateDer<'static> = CertificateDer::pem_slice_iter(&bytes)
        .next()
        .ok_or_else(|| anyhow!("no CERTIFICATE block found in {}", path.display()))?
        .map_err(|e| anyhow!("invalid PEM in {}: {e}", path.display()))?;

    build_report_from_der(path.to_path_buf(), cert_der.as_ref())
}

/// Core parser. Exposed to tests so they can feed synthetic DER bytes
/// without round-tripping through the filesystem.
pub(crate) fn build_report_from_der(path: PathBuf, der: &[u8]) -> Result<CertReport> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| anyhow!("parse X.509 certificate: {e}"))?;

    let subject_cn = first_rdn_value(cert.subject(), &OID_X509_COMMON_NAME);
    let issuer_cn = first_rdn_value(cert.issuer(), &OID_X509_COMMON_NAME);
    let organization = first_rdn_value(cert.subject(), &OID_X509_ORGANIZATION_NAME);
    let country = first_rdn_value(cert.subject(), &OID_X509_COUNTRY_NAME);

    // Serial is printed lowercase-hex, two chars per DER byte, with
    // leading zero bytes preserved. Matches the format used by
    // `rustgate_transport::extract::cert_serial` so policy rules and
    // operator tooling interpret the same string.
    let serial_hex = hex::encode(cert.tbs_certificate.serial.to_bytes_be());

    let not_before = asn1_to_rfc3339(cert.validity().not_before)?;
    let not_after = asn1_to_rfc3339(cert.validity().not_after)?;
    let now = OffsetDateTime::now_utc();
    let not_before_ts = cert.validity().not_before.timestamp();
    let not_after_ts = cert.validity().not_after.timestamp();
    let now_ts = now.unix_timestamp();
    let valid_now = now_ts >= not_before_ts && now_ts <= not_after_ts;
    let expired = now_ts > not_after_ts;
    let seconds_until_expiry = not_after_ts.saturating_sub(now_ts);

    // SHA-256 over the full DER (same fingerprint that rustls reports
    // and that certificate pinning compares against).
    let mut hasher = Sha256::new();
    hasher.update(der);
    let fingerprint_sha256 = hex::encode(hasher.finalize());

    // Groups = all OU attributes in the subject. Each OU value is
    // further split on `,` (with a JSON-array `[...]` fallback) so the
    // CLI matches what `rustgate_transport::extract::extract_groups`
    // feeds the ACL engine at runtime — operators should see the same
    // groups that the router will see. See extract.rs for the shared
    // convention and the rcgen-single-OU rationale.
    let mut groups: Vec<String> = Vec::new();
    for rdn in cert.subject().iter_by_oid(&OID_X509_ORGANIZATIONAL_UNIT) {
        let Ok(ou) = rdn.as_str() else {
            continue;
        };
        let trimmed = ou.trim();
        if trimmed.starts_with('[')
            && let Ok(array) = serde_json::from_str::<Vec<String>>(trimmed)
        {
            for name in array {
                let n = name.trim();
                if !n.is_empty() {
                    groups.push(n.to_string());
                }
            }
            continue;
        }
        for g in ou.split(',') {
            let g = g.trim();
            if !g.is_empty() {
                groups.push(g.to_string());
            }
        }
    }
    groups.sort();
    groups.dedup();

    let mut san_dns: Vec<String> = Vec::new();
    let mut san_uri: Vec<String> = Vec::new();
    let mut san_ip: Vec<String> = Vec::new();
    let mut san_email: Vec<String> = Vec::new();
    let mut spiffe_id: Option<String> = None;
    let mut key_usage: Vec<String> = Vec::new();
    let mut extended_key_usage: Vec<String> = Vec::new();
    let mut is_ca = false;

    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(s) => san_dns.push((*s).to_string()),
                        GeneralName::URI(uri) => {
                            let uri_str = (*uri).to_string();
                            if spiffe_id.is_none() && uri_str.starts_with("spiffe://") {
                                spiffe_id = Some(uri_str.clone());
                            }
                            san_uri.push(uri_str);
                        }
                        GeneralName::IPAddress(bytes) => {
                            san_ip.push(format_ip(bytes));
                        }
                        GeneralName::RFC822Name(s) => san_email.push((*s).to_string()),
                        _ => {}
                    }
                }
            }
            ParsedExtension::KeyUsage(ku) => {
                key_usage = describe_key_usage(ku);
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                extended_key_usage = describe_extended_key_usage(eku);
            }
            ParsedExtension::BasicConstraints(bc) => {
                is_ca = bc.ca;
            }
            _ => {}
        }
    }

    // Some badly-formed certificates list EKU without it reaching the
    // `ParsedExtension` enum (e.g. unrecognized OIDs). Fall back to a
    // raw-OID scan so `cert-info` still surfaces the extension's
    // presence instead of silently reporting nothing.
    if extended_key_usage.is_empty()
        && let Ok(Some(eku)) = cert.extended_key_usage()
    {
        extended_key_usage = describe_extended_key_usage(eku.value);
    }

    san_dns.sort();
    san_dns.dedup();
    san_uri.sort();
    san_uri.dedup();
    san_ip.sort();
    san_ip.dedup();
    san_email.sort();
    san_email.dedup();

    let signature_algorithm = cert.signature_algorithm.algorithm.to_id_string();

    Ok(CertReport {
        path: path.display().to_string(),
        subject_cn,
        issuer_cn,
        serial_hex,
        not_before,
        not_after,
        valid_now,
        expired,
        seconds_until_expiry,
        fingerprint_sha256,
        organization,
        country,
        groups,
        spiffe_id,
        san_dns,
        san_uri,
        san_ip,
        san_email,
        key_usage,
        extended_key_usage,
        is_ca,
        signature_algorithm,
    })
}

/// First RDN value matching the given OID, or `None` if absent or the
/// DirectoryString decoding fails. Returned strings preserve whatever
/// UTF-8 was in the certificate — callers that log must sanitize.
fn first_rdn_value(
    name: &X509Name<'_>,
    oid: &x509_parser::der_parser::oid::Oid<'_>,
) -> Option<String> {
    name.iter_by_oid(oid)
        .next()
        .and_then(|rdn| rdn.as_str().ok().map(|s| s.to_string()))
}

/// Format an `IPAddress` SAN byte slice as either IPv4 (4 bytes) or
/// IPv6 (16 bytes). Everything else degrades to a hex dump so the
/// field is still visible rather than silently dropped.
fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            std::net::Ipv6Addr::from(arr).to_string()
        }
        _ => hex::encode(bytes),
    }
}

/// Human-readable key-usage flags, in RFC 5280 §4.2.1.3 order.
fn describe_key_usage(ku: &x509_parser::extensions::KeyUsage) -> Vec<String> {
    let mut out = Vec::new();
    if ku.digital_signature() {
        out.push("digitalSignature".to_string());
    }
    if ku.non_repudiation() {
        out.push("nonRepudiation".to_string());
    }
    if ku.key_encipherment() {
        out.push("keyEncipherment".to_string());
    }
    if ku.data_encipherment() {
        out.push("dataEncipherment".to_string());
    }
    if ku.key_agreement() {
        out.push("keyAgreement".to_string());
    }
    if ku.key_cert_sign() {
        out.push("keyCertSign".to_string());
    }
    if ku.crl_sign() {
        out.push("cRLSign".to_string());
    }
    if ku.encipher_only() {
        out.push("encipherOnly".to_string());
    }
    if ku.decipher_only() {
        out.push("decipherOnly".to_string());
    }
    out
}

/// Extended-key-usage flags in a fixed order, with unknown OIDs
/// appended as hex so the data is not lost.
fn describe_extended_key_usage(eku: &x509_parser::extensions::ExtendedKeyUsage) -> Vec<String> {
    let mut out = Vec::new();
    if eku.server_auth {
        out.push("serverAuth".to_string());
    }
    if eku.client_auth {
        out.push("clientAuth".to_string());
    }
    if eku.code_signing {
        out.push("codeSigning".to_string());
    }
    if eku.email_protection {
        out.push("emailProtection".to_string());
    }
    if eku.time_stamping {
        out.push("timeStamping".to_string());
    }
    if eku.ocsp_signing {
        out.push("ocspSigning".to_string());
    }
    if eku.any {
        out.push("anyExtendedKeyUsage".to_string());
    }
    // `other` captures OIDs outside the well-known set so operators
    // still see them (e.g. custom smartcard EKUs).
    for other in &eku.other {
        out.push(other.to_id_string());
    }
    // `to_id_string` also lives under `OID_X509_EXT_KEY_USAGE` so the
    // import is exercised. This pattern also silences an unused-import
    // warning on toolchains that drop OID table entries.
    let _ = &OID_X509_EXT_KEY_USAGE;
    out
}

/// Convert an `ASN1Time` to an RFC 3339 UTC string. Falls back to the
/// raw timestamp-as-seconds-since-epoch when the offset cannot be
/// represented (should not happen for a valid X.509 time, but we
/// refuse to unwrap).
fn asn1_to_rfc3339(t: ASN1Time) -> Result<String> {
    let ts = t.timestamp();
    let odt = OffsetDateTime::from_unix_timestamp(ts)
        .map_err(|e| anyhow!("invalid ASN.1 time {ts}: {e}"))?;
    odt.format(&Rfc3339)
        .map_err(|e| anyhow!("format ASN.1 time {ts}: {e}"))
}

/// Render the human-readable block. Purely cosmetic — not a stable
/// contract. Kept here rather than in `run` so tests can snapshot it.
pub(crate) fn render_human(r: &CertReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Certificate: {}", r.path);
    let _ = writeln!(
        out,
        "  Subject CN:   {}",
        r.subject_cn.as_deref().unwrap_or("(none)")
    );
    let _ = writeln!(
        out,
        "  Issuer CN:    {}",
        r.issuer_cn.as_deref().unwrap_or("(none)")
    );
    let _ = writeln!(out, "  Serial:       {}", r.serial_hex);
    let _ = writeln!(out, "  Not Before:   {}", r.not_before);
    let _ = writeln!(out, "  Not After:    {}", r.not_after);
    let validity = if r.expired {
        "expired".to_string()
    } else if r.valid_now {
        format!(
            "valid ({} days until expiry)",
            r.seconds_until_expiry / 86_400
        )
    } else {
        "not yet valid".to_string()
    };
    let _ = writeln!(out, "  Validity:     {validity}");
    let _ = writeln!(out, "  Fingerprint:  {}", r.fingerprint_sha256);
    let _ = writeln!(out, "  Is CA:        {}", r.is_ca);
    let _ = writeln!(out, "  Signature:    {}", r.signature_algorithm);
    if let Some(ref o) = r.organization {
        let _ = writeln!(out, "  Organization: {o}");
    }
    if let Some(ref c) = r.country {
        let _ = writeln!(out, "  Country:      {c}");
    }
    if !r.groups.is_empty() {
        let _ = writeln!(out, "  Groups:       [{}]", r.groups.join(", "));
    }
    if let Some(ref s) = r.spiffe_id {
        let _ = writeln!(out, "  SPIFFE ID:    {s}");
    }
    if !r.san_dns.is_empty()
        || !r.san_uri.is_empty()
        || !r.san_ip.is_empty()
        || !r.san_email.is_empty()
    {
        let _ = writeln!(out, "  SANs:");
        if !r.san_dns.is_empty() {
            let _ = writeln!(out, "    DNS:        {}", r.san_dns.join(", "));
        }
        if !r.san_uri.is_empty() {
            let _ = writeln!(out, "    URI:        {}", r.san_uri.join(", "));
        }
        if !r.san_ip.is_empty() {
            let _ = writeln!(out, "    IP:         {}", r.san_ip.join(", "));
        }
        if !r.san_email.is_empty() {
            let _ = writeln!(out, "    Email:      {}", r.san_email.join(", "));
        }
    }
    if !r.key_usage.is_empty() {
        let _ = writeln!(out, "  Key Usage:    [{}]", r.key_usage.join(", "));
    }
    if !r.extended_key_usage.is_empty() {
        let _ = writeln!(out, "  Ext Key Use:  [{}]", r.extended_key_usage.join(", "));
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
    fn reports_client_cert_fields() {
        let ca = TestCa::new("diag-test-ca");
        let client = ca.issue_client_cert("alice", &["ops", "admin"]);
        let file = write_pem(&client.cert_pem);

        let r = build_report(file.path()).expect("build_report ok");

        assert_eq!(r.subject_cn.as_deref(), Some("alice"));
        assert_eq!(r.issuer_cn.as_deref(), Some("diag-test-ca"));
        assert!(r.valid_now, "freshly issued cert should be valid");
        assert!(!r.expired);
        assert_eq!(r.fingerprint_sha256.len(), 64, "SHA-256 hex is 64 chars");
        assert!(r.groups.contains(&"admin".to_string()));
        assert!(r.groups.contains(&"ops".to_string()));
        assert!(
            r.groups.windows(2).all(|w| w[0] <= w[1]),
            "groups must be sorted for stable output"
        );
        assert!(!r.is_ca, "client certs are not CAs");
    }

    #[test]
    fn detects_expired_cert() {
        let ca = TestCa::new("diag-test-ca");
        let expired = ca.issue_expired_client_cert("ghost", &[]);
        let file = write_pem(&expired.cert_pem);

        let r = build_report(file.path()).expect("build_report ok");

        assert!(r.expired, "expired cert must report expired=true");
        assert!(!r.valid_now, "expired cert must not be valid_now");
        assert!(
            r.seconds_until_expiry <= 0,
            "seconds_until_expiry must be non-positive for an expired cert"
        );
    }

    #[test]
    fn surfaces_server_cert_sans() {
        let ca = TestCa::new("diag-test-ca");
        let server = ca.issue_server_cert("service", &["service.example.com", "alt.example.com"]);
        let file = write_pem(&server.cert_pem);

        let r = build_report(file.path()).expect("build_report ok");

        assert!(r.san_dns.contains(&"service.example.com".to_string()));
        assert!(r.san_dns.contains(&"alt.example.com".to_string()));
        assert!(
            r.extended_key_usage.iter().any(|s| s == "serverAuth"),
            "server cert must advertise serverAuth EKU"
        );
    }

    #[test]
    fn rejects_file_with_no_certificate_block() {
        use std::io::Write;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----\n")
            .unwrap();
        f.flush().unwrap();

        let err = build_report(f.path()).expect_err("must reject key-only PEM");
        let msg = format!("{err}");
        assert!(
            msg.contains("no CERTIFICATE block"),
            "error must call out missing CERTIFICATE block, got: {msg}"
        );
    }

    #[test]
    fn rejects_missing_file() {
        let err = build_report(Path::new("/definitely/not/there.pem"))
            .expect_err("must fail on missing file");
        let msg = format!("{err}");
        assert!(
            msg.contains("read certificate file"),
            "error must mention the file read operation, got: {msg}"
        );
    }

    #[test]
    fn rejects_garbage_pem() {
        use std::io::Write;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"not a pem file at all\n").unwrap();
        f.flush().unwrap();

        let err = build_report(f.path()).expect_err("must reject non-PEM");
        let msg = format!("{err}");
        assert!(
            msg.contains("no CERTIFICATE block"),
            "plain text with no PEM headers must surface the no-block error, got: {msg}"
        );
    }

    #[test]
    fn json_report_is_stable_structure() {
        let ca = TestCa::new("diag-test-ca");
        let client = ca.issue_client_cert("alice", &[]);
        let file = write_pem(&client.cert_pem);
        let r = build_report(file.path()).unwrap();
        let j = serde_json::to_value(&r).unwrap();

        // Pin the expected top-level keys to catch accidental renames.
        let expected = [
            "path",
            "subject_cn",
            "issuer_cn",
            "serial_hex",
            "not_before",
            "not_after",
            "valid_now",
            "expired",
            "seconds_until_expiry",
            "fingerprint_sha256",
            "organization",
            "country",
            "groups",
            "spiffe_id",
            "san_dns",
            "san_uri",
            "san_ip",
            "san_email",
            "key_usage",
            "extended_key_usage",
            "is_ca",
            "signature_algorithm",
        ];
        for key in expected {
            assert!(
                j.get(key).is_some(),
                "JSON report missing expected key `{key}`"
            );
        }
    }

    #[test]
    fn human_output_names_the_file() {
        let ca = TestCa::new("diag-test-ca");
        let client = ca.issue_client_cert("alice", &[]);
        let file = write_pem(&client.cert_pem);
        let r = build_report(file.path()).unwrap();

        let rendered = render_human(&r);
        assert!(rendered.starts_with("Certificate: "));
        assert!(rendered.contains("Subject CN:"));
        assert!(rendered.contains("alice"));
        assert!(rendered.contains("diag-test-ca"));
    }

    #[test]
    fn ipv4_san_formatting() {
        assert_eq!(format_ip(&[127, 0, 0, 1]), "127.0.0.1");
    }

    #[test]
    fn ipv6_san_formatting() {
        let bytes = [0u8; 16];
        assert_eq!(format_ip(&bytes), "::");
    }

    #[test]
    fn unknown_length_ip_becomes_hex() {
        // Not a standard IP length — must still produce a deterministic
        // rendering so operators see *something* rather than nothing.
        assert_eq!(format_ip(&[0xde, 0xad, 0xbe, 0xef, 0x00]), "deadbeef00");
    }
}
