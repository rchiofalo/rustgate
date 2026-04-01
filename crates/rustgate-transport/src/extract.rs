//! X.509 certificate parsing and identity extraction.

use std::collections::BTreeSet;

use rustgate_core::error::{Result, RustgateError, TransportError};
use rustgate_core::identity::Identity;
use rustgate_core::sanitize::sanitize_for_log;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_parser::oid_registry::{
    OID_X509_COMMON_NAME, OID_X509_EXT_EXTENDED_KEY_USAGE, OID_X509_ORGANIZATIONAL_UNIT,
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

    Identity::new(cn, fingerprint, groups).map_err(|e| {
        TransportError::Other(format!("invalid identity from certificate: {e}")).into()
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
