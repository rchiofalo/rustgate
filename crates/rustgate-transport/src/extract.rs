//! X.509 certificate parsing and identity extraction.

use std::collections::{BTreeMap, BTreeSet};

use rustgate_core::error::{Result, RustgateError, TransportError};
use rustgate_core::identity::{AttrValue, Identity};
use rustgate_core::sanitize::sanitize_for_log;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{
    OID_X509_COMMON_NAME, OID_X509_COUNTRY_NAME, OID_X509_EXT_EXTENDED_KEY_USAGE,
    OID_X509_ORGANIZATION_NAME, OID_X509_ORGANIZATIONAL_UNIT,
};
use x509_parser::prelude::*;

/// Extract identity from an X.509 certificate.
///
/// Parses the certificate DER and extracts:
/// - CN (Common Name) → `Identity.cn`
/// - OU (Organizational Unit) fields → `Identity.groups`
/// - SHA-256 fingerprint → `Identity.fingerprint`
pub fn extract_identity(cert_der: &CertificateDer<'_>) -> Result<Identity> {
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| TransportError::Other(format!("failed to parse X.509 certificate: {e}")))?;

    let cn = sanitize_for_log(&extract_cn(&cert)?);
    let groups = extract_groups(&cert)
        .into_iter()
        .map(|g| sanitize_for_log(&g))
        .collect();
    let fingerprint = compute_fingerprint(cert_der);

    let (attributes, spiffe_id) = extract_attributes(&cert, cert_der);

    let mut identity = Identity::new(cn, fingerprint, groups).map_err(|e| {
        RustgateError::from(TransportError::Other(format!(
            "invalid identity from certificate: {e}"
        )))
    })?;
    identity = identity.with_attributes(attributes);
    if let Some(spiffe) = spiffe_id {
        identity = identity.with_spiffe_id(spiffe);
    }
    Ok(identity)
}

/// Extract ABAC attributes and (optionally) a SPIFFE ID from a parsed cert.
///
/// Never fails: missing SANs / subject fields simply yield an empty map.
/// The returned map is populated with the following keys when data is
/// present:
///
/// - `spiffe_id` (Str) — first URI SAN starting with `spiffe://`
/// - `san_dns` (Set) — all DNS SANs, sorted and deduplicated
/// - `san_email` (Set) — all RFC822 SANs, sorted and deduplicated
/// - `san_uri` (Set) — all URI SANs, sorted and deduplicated
/// - `org` (Str) — first subject O (organizationName) value
/// - `country` (Str) — first subject C (countryName) value
/// - `issuer_cn` (Str) — first issuer CN value
/// - `cert_serial` (Str) — certificate serial number as lowercase hex
fn extract_attributes(
    cert: &X509Certificate<'_>,
    cert_der: &CertificateDer<'_>,
) -> (BTreeMap<String, AttrValue>, Option<String>) {
    let mut attrs: BTreeMap<String, AttrValue> = BTreeMap::new();
    let mut spiffe_id: Option<String> = None;

    // Subject organization (O).
    if let Some(org) = first_subject_attr(cert, &OID_X509_ORGANIZATION_NAME) {
        let _ = attrs.insert("org".to_string(), AttrValue::Str(sanitize_for_log(&org)));
    }
    // Subject country (C).
    if let Some(country) = first_subject_attr(cert, &OID_X509_COUNTRY_NAME) {
        let _ = attrs.insert(
            "country".to_string(),
            AttrValue::Str(sanitize_for_log(&country)),
        );
    }
    // Issuer CN.
    let mut issuer_cn: Option<String> = None;
    for rdn in cert.issuer().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &OID_X509_COMMON_NAME
                && let Ok(v) = attr.attr_value().as_str()
            {
                issuer_cn = Some(v.to_string());
                break;
            }
        }
        if issuer_cn.is_some() {
            break;
        }
    }
    if let Some(cn) = issuer_cn {
        let _ = attrs.insert(
            "issuer_cn".to_string(),
            AttrValue::Str(sanitize_for_log(&cn)),
        );
    }

    // Certificate serial (lowercase hex of DER bytes).
    let serial_bytes = cert.tbs_certificate.serial.to_bytes_be();
    let serial_hex: String = serial_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let _ = attrs.insert("cert_serial".to_string(), AttrValue::Str(serial_hex));

    // SAN extension — URI / DNS / email.
    if let Ok(exts) = cert.extensions_map()
        && let Some(ext) = exts.get(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        && let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension()
    {
        let mut dns_names: Vec<String> = Vec::new();
        let mut emails: Vec<String> = Vec::new();
        let mut uris: Vec<String> = Vec::new();
        for name in &san.general_names {
            match name {
                GeneralName::DNSName(s) => dns_names.push(sanitize_for_log(s)),
                GeneralName::RFC822Name(s) => emails.push(sanitize_for_log(s)),
                GeneralName::URI(s) => {
                    let sanitized = sanitize_for_log(s);
                    // SPIFFE ID extraction: only accept URIs that pass the
                    // canonicalizer/validator (RFC 3986 scheme "spiffe",
                    // valid trust-domain charset, non-empty path). A
                    // malformed SPIFFE-looking URI is treated as a plain
                    // URI SAN — we still record it under `san_uri`, but it
                    // will not populate `Identity.spiffe_id` and cannot
                    // match a `spiffe_prefix` policy rule.
                    if spiffe_id.is_none()
                        && let Some(canonical) = canonicalize_spiffe_id(&sanitized)
                    {
                        spiffe_id = Some(canonical);
                    }
                    uris.push(sanitized);
                }
                _ => {}
            }
        }
        if !dns_names.is_empty() {
            dns_names.sort();
            dns_names.dedup();
            let _ = attrs.insert("san_dns".to_string(), AttrValue::Set(dns_names));
        }
        if !emails.is_empty() {
            emails.sort();
            emails.dedup();
            let _ = attrs.insert("san_email".to_string(), AttrValue::Set(emails));
        }
        if !uris.is_empty() {
            uris.sort();
            uris.dedup();
            let _ = attrs.insert("san_uri".to_string(), AttrValue::Set(uris));
        }
    }

    if let Some(ref id) = spiffe_id {
        let _ = attrs.insert("spiffe_id".to_string(), AttrValue::Str(id.clone()));
    }

    let _ = cert_der; // reserved for future use (e.g. SKI).
    (attrs, spiffe_id)
}

/// Canonicalize a SPIFFE ID per the [SPIFFE ID spec][spec].
///
/// Per the spec, the scheme (`spiffe`) and the trust-domain authority are
/// **case-insensitive** while the path is **case-sensitive**. Trust-domain
/// names may contain only lowercase ASCII letters, digits, dots, dashes, and
/// underscores and must be at most 255 bytes. This helper lowercases the
/// scheme and trust domain, leaves the path alone, and returns `None` if the
/// input is not a syntactically valid SPIFFE ID.
///
/// Dropping invalid SPIFFE-looking URIs is a defense-in-depth measure: a
/// policy author writing `spiffe_prefix: "spiffe://prod/"` should not have
/// that match a cert presenting `spiffe://PROD%2Fadmin` or similar malformed
/// input.
///
/// [spec]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
fn canonicalize_spiffe_id(uri: &str) -> Option<String> {
    const SCHEME: &str = "spiffe://";
    if uri.len() < SCHEME.len() {
        return None;
    }
    let (scheme, rest) = uri.split_at(SCHEME.len());
    if !scheme.eq_ignore_ascii_case(SCHEME) {
        return None;
    }
    // Trust domain ends at the first `/` or end-of-string.
    let (trust_domain, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if trust_domain.is_empty() || trust_domain.len() > 255 {
        return None;
    }
    // Trust domain charset: ASCII lowercase letters, digits, dot, dash, underscore.
    // The spec is case-insensitive for the authority, so we also accept uppercase
    // letters and lowercase them below.
    let charset_ok = trust_domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !charset_ok {
        return None;
    }
    // Reject empty path segments like `spiffe://trust/foo//bar` and any
    // literal percent-encoding ambiguity in the path by requiring each path
    // segment to be non-empty. The spec allows percent-encoding but we stay
    // conservative: segment must be at least one character.
    if !path.is_empty() {
        for segment in path.split('/').skip(1) {
            if segment.is_empty() {
                return None;
            }
        }
    }
    let mut canonical = String::with_capacity(SCHEME.len() + trust_domain.len() + path.len());
    canonical.push_str("spiffe://");
    // Lowercase the trust domain.
    for b in trust_domain.bytes() {
        canonical.push(b.to_ascii_lowercase() as char);
    }
    canonical.push_str(path);
    Some(canonical)
}

fn first_subject_attr(
    cert: &X509Certificate<'_>,
    oid: &x509_parser::der_parser::oid::Oid<'_>,
) -> Option<String> {
    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == oid
                && let Ok(v) = attr.attr_value().as_str()
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn extract_cn(cert: &X509Certificate<'_>) -> Result<String> {
    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &OID_X509_COMMON_NAME {
                let cn = attr
                    .attr_value()
                    .as_str()
                    .map_err(|e| {
                        RustgateError::from(TransportError::Other(format!(
                            "invalid CN encoding: {e}"
                        )))
                    })?
                    .to_string();
                return Ok(cn);
            }
        }
    }

    Err(TransportError::MissingCommonName.into())
}

/// Extract `groups` from the cert's OU fields.
///
/// Each `OU=` RDN is treated as a comma-separated list of group names so an
/// issuer can encode multiple memberships in a single RDN. This convention
/// predates rustgate-authz and is preserved for compatibility with existing
/// CNs issued by the enrollment path.
///
/// **Operator note:** because this function splits OU values on a literal
/// `,`, group names MUST NOT contain an unescaped comma. RFC 4514 allows
/// escaping commas inside a DN attribute with `\,`, but x509-parser
/// unescapes them before this function sees the string, so an OU of
/// `R\,D,ops` arrives here as `R,D,ops` and becomes three groups rather
/// than two. If you need a literal comma in a group name, issue multiple
/// OU RDNs instead of packing them into one.
fn extract_groups(cert: &X509Certificate<'_>) -> BTreeSet<String> {
    let mut groups = BTreeSet::new();

    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &OID_X509_ORGANIZATIONAL_UNIT
                && let Ok(ou) = attr.attr_value().as_str()
            {
                // Support both single values and comma-separated group lists.
                // See the docstring for the escape caveat.
                for group in ou.split(',') {
                    let group = group.trim();
                    if !group.is_empty() {
                        let _ = groups.insert(group.to_string());
                    }
                }
            }
        }
    }

    groups
}

/// Extended Key Usage purpose expected from a certificate.
///
/// Used with [`validate_key_usage`] to enforce that client-presented
/// certificates include the correct EKU extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedKeyUsage {
    /// Certificate must include `id-kp-clientAuth`.
    ClientAuth,
    /// Certificate must include `id-kp-serverAuth`.
    ServerAuth,
}

/// Validate that the certificate contains the expected Extended Key Usage extension.
///
/// Returns `Ok(())` if the certificate has the required EKU, or an error if:
/// - The certificate has no EKU extension at all
/// - The EKU extension does not include the expected purpose
///
/// This prevents a server certificate from being used as a client certificate
/// and vice versa, even if the CA signature is valid.
pub fn validate_key_usage(cert_der: &CertificateDer<'_>, expected: ExpectedKeyUsage) -> Result<()> {
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| TransportError::Other(format!("failed to parse X.509 certificate: {e}")))?;

    let extensions_map = cert.extensions_map().map_err(|e| {
        RustgateError::from(TransportError::Other(format!(
            "failed to parse certificate extensions: {e}"
        )))
    })?;

    let eku_ext = extensions_map
        .get(&OID_X509_EXT_EXTENDED_KEY_USAGE)
        .ok_or_else(|| {
            RustgateError::from(TransportError::Other(
                "certificate has no Extended Key Usage extension".to_string(),
            ))
        })?;

    let parsed = eku_ext.parsed_extension();
    if let ParsedExtension::ExtendedKeyUsage(eku) = parsed {
        let has_usage = match expected {
            ExpectedKeyUsage::ClientAuth => eku.client_auth,
            ExpectedKeyUsage::ServerAuth => eku.server_auth,
        };

        if has_usage {
            Ok(())
        } else {
            Err(TransportError::MissingKeyUsage {
                expected: format!("{expected:?}"),
            }
            .into())
        }
    } else {
        Err(
            TransportError::Other("failed to parse Extended Key Usage extension".to_string())
                .into(),
        )
    }
}

fn compute_fingerprint(cert_der: &CertificateDer<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der.as_ref());
    let result = hasher.finalize();

    result
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use rustgate_test_utils::certs::TestCa;
    use rustls::pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;

    use super::*;

    fn parse_cert_pem(pem: &str) -> CertificateDer<'static> {
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
    }

    #[test]
    fn extracts_spiffe_id_from_uri_san() {
        let ca = TestCa::new("attr-ca");
        let cert = ca.issue_client_cert_with_attrs(
            "alice",
            &[],
            Some("spiffe://example.org/svc/alice"),
            None,
            None,
            &[],
            &[],
        );
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert_eq!(
            id.spiffe_id.as_deref(),
            Some("spiffe://example.org/svc/alice")
        );
        assert_eq!(
            id.attributes.get("spiffe_id"),
            Some(&AttrValue::Str("spiffe://example.org/svc/alice".into()))
        );
        assert!(matches!(
            id.attributes.get("san_uri"),
            Some(AttrValue::Set(_))
        ));
    }

    #[test]
    fn extracts_dns_and_email_sans() {
        let ca = TestCa::new("attr-ca");
        let cert = ca.issue_client_cert_with_attrs(
            "bob",
            &[],
            None,
            None,
            None,
            &["b.example.com", "a.example.com"],
            &["bob@example.com"],
        );
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        let dns = id.attributes.get("san_dns").unwrap();
        match dns {
            AttrValue::Set(v) => assert_eq!(
                v,
                &vec!["a.example.com".to_string(), "b.example.com".into()]
            ),
            other => panic!("expected Set, got {other:?}"),
        }
        assert_eq!(
            id.attributes.get("san_email"),
            Some(&AttrValue::Set(vec!["bob@example.com".into()]))
        );
        assert!(id.spiffe_id.is_none());
    }

    #[test]
    fn extracts_subject_org_and_country() {
        let ca = TestCa::new("attr-ca");
        let cert =
            ca.issue_client_cert_with_attrs("carol", &[], None, Some("Acme"), Some("US"), &[], &[]);
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert_eq!(
            id.attributes.get("org"),
            Some(&AttrValue::Str("Acme".into()))
        );
        assert_eq!(
            id.attributes.get("country"),
            Some(&AttrValue::Str("US".into()))
        );
    }

    #[test]
    fn extracts_issuer_cn_and_cert_serial() {
        let ca = TestCa::new("issuer-root");
        let cert = ca.issue_client_cert("dave", &[]);
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert_eq!(
            id.attributes.get("issuer_cn"),
            Some(&AttrValue::Str("issuer-root".into()))
        );
        match id.attributes.get("cert_serial") {
            Some(AttrValue::Str(s)) => {
                assert!(!s.is_empty());
                assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
            }
            other => panic!("expected cert_serial Str, got {other:?}"),
        }
    }

    #[test]
    fn extract_identity_canonicalizes_spiffe_trust_domain() {
        let ca = TestCa::new("attr-ca");
        // Cert presents an uppercase trust domain; extraction must lowercase it.
        let cert = ca.issue_client_cert_with_attrs(
            "carol",
            &[],
            Some("spiffe://Example.ORG/ns/prod/svc"),
            None,
            None,
            &[],
            &[],
        );
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert_eq!(
            id.spiffe_id.as_deref(),
            Some("spiffe://example.org/ns/prod/svc"),
            "trust domain must be lowercased per SPIFFE spec"
        );
    }

    #[test]
    fn canonicalize_spiffe_lowercases_trust_domain_only() {
        assert_eq!(
            canonicalize_spiffe_id("spiffe://Example.ORG/ns/Prod/Svc"),
            Some("spiffe://example.org/ns/Prod/Svc".to_string()),
            "trust domain case-insensitive, path case-sensitive"
        );
        assert_eq!(
            canonicalize_spiffe_id("SPIFFE://trust.example/svc"),
            Some("spiffe://trust.example/svc".to_string()),
            "scheme case-insensitive"
        );
        assert_eq!(
            canonicalize_spiffe_id("spiffe://trust.example"),
            Some("spiffe://trust.example".to_string()),
            "trailing slash optional"
        );
    }

    #[test]
    fn canonicalize_spiffe_rejects_malformed() {
        assert!(canonicalize_spiffe_id("http://trust.example/foo").is_none());
        assert!(
            canonicalize_spiffe_id("spiffe://").is_none(),
            "empty authority"
        );
        assert!(
            canonicalize_spiffe_id("spiffe:///path").is_none(),
            "empty trust domain"
        );
        assert!(
            canonicalize_spiffe_id("spiffe://trust!bad/svc").is_none(),
            "disallowed charset in authority"
        );
        assert!(
            canonicalize_spiffe_id("spiffe://trust/foo//bar").is_none(),
            "empty path segment"
        );
        assert!(
            canonicalize_spiffe_id(&format!("spiffe://{}/svc", "a".repeat(256))).is_none(),
            "authority > 255 bytes"
        );
    }

    #[test]
    fn no_sans_yields_no_san_attrs_but_still_succeeds() {
        let ca = TestCa::new("attr-ca");
        let cert = ca.issue_client_cert("eve", &[]);
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert!(id.spiffe_id.is_none());
        assert!(id.attributes.get("san_dns").is_none());
        assert!(id.attributes.get("san_email").is_none());
        assert!(id.attributes.get("san_uri").is_none());
        // cert_serial and issuer_cn always present
        assert!(id.attributes.contains_key("cert_serial"));
        assert!(id.attributes.contains_key("issuer_cn"));
    }
}
