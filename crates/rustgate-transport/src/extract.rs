//! X.509 certificate parsing and identity extraction.

use rustgate_core::error::{Result, RustgateError};
use rustgate_core::identity::Identity;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use x509_parser::oid_registry::{OID_X509_COMMON_NAME, OID_X509_ORGANIZATIONAL_UNIT};
use x509_parser::prelude::*;

/// Extract identity from an X.509 certificate.
///
/// Parses the certificate DER and extracts:
/// - CN (Common Name) → `Identity.cn`
/// - OU (Organizational Unit) fields → `Identity.groups`
/// - SHA-256 fingerprint → `Identity.fingerprint`
pub fn extract_identity(cert_der: &CertificateDer<'_>) -> Result<Identity> {
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| RustgateError::Transport(format!("failed to parse X.509 certificate: {e}")))?;

    let cn = extract_cn(&cert)?;
    let groups = extract_groups(&cert);
    let fingerprint = compute_fingerprint(cert_der);

    Ok(Identity {
        cn,
        fingerprint,
        groups,
    })
}

fn extract_cn(cert: &X509Certificate<'_>) -> Result<String> {
    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &OID_X509_COMMON_NAME {
                let cn = attr
                    .attr_value()
                    .as_str()
                    .map_err(|e| {
                        RustgateError::Transport(format!("invalid CN encoding: {e}"))
                    })?
                    .to_string();
                return Ok(cn);
            }
        }
    }

    Err(RustgateError::Transport(
        "certificate has no Common Name (CN)".to_string(),
    ))
}

fn extract_groups(cert: &X509Certificate<'_>) -> BTreeSet<String> {
    let mut groups = BTreeSet::new();

    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &OID_X509_ORGANIZATIONAL_UNIT
                && let Ok(ou) = attr.attr_value().as_str()
            {
                // Support both single values and comma-separated group lists
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
