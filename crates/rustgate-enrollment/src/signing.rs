//! CSR signing logic.
//!
//! Loads a CA certificate and private key from PEM, parses incoming PKCS#10
//! certificate signing requests, and issues signed client certificates.

use std::io::BufReader;

use rcgen::{
    Certificate, CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

use crate::error::EnrollmentError;

/// Signs PKCS#10 certificate signing requests with the server CA.
pub struct CsrSigner {
    /// Reconstructed CA Certificate handle for use as issuer in `signed_by()`.
    ca_cert: Certificate,
    /// CA private key for signing.
    ca_key: KeyPair,
    /// Original CA certificate DER bytes for enrollment responses.
    /// Kept separate because the reconstructed `ca_cert` may have a different
    /// signature (re-signed during loading), but clients need the actual CA cert.
    ca_cert_der: Vec<u8>,
    /// Organization name for /tls/config responses.
    organization: String,
}

impl std::fmt::Debug for CsrSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsrSigner")
            .field("organization", &self.organization)
            .finish_non_exhaustive()
    }
}

impl CsrSigner {
    /// Create a signer from PEM-encoded CA certificate and private key.
    ///
    /// The CA cert PEM is parsed twice:
    /// 1. Via `rustls_pemfile` to extract the original DER bytes (for responses).
    /// 2. Via `rcgen::CertificateParams::from_ca_cert_der()` to reconstruct
    ///    signing parameters. The params are then re-self-signed with the key
    ///    to produce a `Certificate` handle that `signed_by()` requires.
    pub fn from_pem(
        ca_cert_pem: &str,
        ca_key_pem: &str,
        organization: &str,
    ) -> Result<Self, EnrollmentError> {
        // Extract original DER for enrollment responses
        let mut reader = BufReader::new(ca_cert_pem.as_bytes());
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    EnrollmentError::Config(format!("failed to parse CA cert PEM: {e}"))
                })?;

        let ca_cert_der = certs
            .into_iter()
            .next()
            .ok_or_else(|| EnrollmentError::Config("no certificate found in CA PEM".to_string()))?
            .to_vec();

        // Load CA key
        let ca_key = KeyPair::from_pem(ca_key_pem)
            .map_err(|e| EnrollmentError::Config(format!("failed to parse CA key PEM: {e}")))?;

        // Reconstruct CA params from the cert DER and re-self-sign to get
        // a Certificate handle. The re-signing produces different signature
        // bytes but preserves the subject DN and extensions — which is all
        // that `signed_by()` uses from the issuer.
        let ca_params = CertificateParams::from_ca_cert_der(
            &rustls_pki_types::CertificateDer::from(ca_cert_der.as_slice()),
        )
        .map_err(|e| EnrollmentError::Config(format!("failed to parse CA cert params: {e}")))?;

        let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| {
            EnrollmentError::Config(format!("failed to reconstruct CA certificate: {e}"))
        })?;

        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_der,
            organization: organization.to_string(),
        })
    }

    /// Sign a PKCS#10 CSR and return the signed client certificate as DER bytes.
    ///
    /// Accepts PEM-encoded CSR (with or without PEM headers — raw base64 is
    /// wrapped with headers automatically). The `username` from successful
    /// Basic Auth is enforced as the certificate CN to prevent subject
    /// injection — the CSR only contributes the public key.
    ///
    /// The signed certificate has:
    /// - CN = authenticated username (overrides CSR subject)
    /// - O = server's configured organization
    /// - 365-day validity (starting 5 minutes in the past for clock skew)
    /// - KeyUsage: DigitalSignature
    /// - ExtKeyUsage: ClientAuth
    pub fn sign_csr(&self, csr_pem: &str, username: &str) -> Result<Vec<u8>, EnrollmentError> {
        let normalized = ensure_pem_headers(csr_pem);

        let csr = CertificateSigningRequestParams::from_pem(&normalized)
            .map_err(|e| EnrollmentError::Csr(format!("failed to parse CSR: {e}")))?;

        // Build subject DN from the authenticated identity — never trust
        // the CSR's subject fields. The CSR only contributes the public key.
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, username);
        dn.push(rcgen::DnType::OrganizationName, &self.organization);

        let mut params = csr.params;
        params.distinguished_name = dn;
        // Strip any SANs or custom extensions from the CSR — only the
        // server-controlled DN, validity, key usage, and EKU should survive.
        params.subject_alt_names = Vec::new();
        params.custom_extensions = Vec::new();
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        let signed = params
            .signed_by(&csr.public_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| EnrollmentError::Signing(format!("failed to sign certificate: {e}")))?;

        Ok(signed.der().to_vec())
    }

    /// The original CA certificate DER bytes for enrollment responses.
    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// Organization name for /tls/config responses.
    pub fn organization(&self) -> &str {
        &self.organization
    }
}

/// Ensure a CSR string has PEM headers.
///
/// TAK clients may send raw base64-encoded CSR data without the
/// `-----BEGIN CERTIFICATE REQUEST-----` / `-----END ...-----` markers.
/// rcgen requires PEM headers, so we add them if missing.
fn ensure_pem_headers(csr: &str) -> String {
    let trimmed = csr.trim();
    if trimmed.starts_with("-----BEGIN") {
        return trimmed.to_string();
    }
    format!("-----BEGIN CERTIFICATE REQUEST-----\n{trimmed}\n-----END CERTIFICATE REQUEST-----")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ca() -> (String, String) {
        let ca = rustgate_test_utils::certs::TestCa::new("Test CA");
        (ca.cert_pem, ca.key_pem)
    }

    fn generate_csr(cn: &str) -> String {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

        let key = KeyPair::generate().expect("keygen");
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        dn.push(DnType::OrganizationName, "TestOrg");
        params.distinguished_name = dn;

        let csr = params.serialize_request(&key).expect("csr");
        csr.pem().expect("pem")
    }

    #[test]
    fn sign_csr_round_trip() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");

        let csr_pem = generate_csr("ignored-cn");
        let signed_der = signer.sign_csr(&csr_pem, "test-client").expect("sign");

        // CN comes from the authenticated username, not the CSR
        let (_, cert) =
            x509_parser::parse_x509_certificate(&signed_der).expect("parse signed cert");
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok()),
            Some("test-client")
        );

        // Verify it has ClientAuth EKU
        let eku = cert
            .extended_key_usage()
            .expect("EKU present")
            .expect("parse EKU");
        assert!(eku.value.client_auth);
    }

    #[test]
    fn sign_csr_overrides_subject() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");

        // CSR claims CN=attacker, but sign_csr enforces CN=legit-user
        let csr_pem = generate_csr("attacker");
        let signed_der = signer.sign_csr(&csr_pem, "legit-user").expect("sign");

        let (_, cert) = x509_parser::parse_x509_certificate(&signed_der).expect("parse");
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok()),
            Some("legit-user")
        );
    }

    #[test]
    fn sign_csr_without_pem_headers() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");

        let csr_pem = generate_csr("raw-client");
        // Strip PEM headers to simulate TAK client behavior
        let raw = csr_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("\n");

        let signed_der = signer.sign_csr(&raw, "raw-client").expect("sign raw");
        let (_, cert) = x509_parser::parse_x509_certificate(&signed_der).expect("parse");
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok()),
            Some("raw-client")
        );
    }

    #[test]
    fn sign_csr_invalid_data() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");

        let result = signer.sign_csr("not a valid CSR", "user");
        assert!(result.is_err());
    }

    #[test]
    fn sign_csr_enforces_org() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");

        // CSR has org "TestOrg" but signer enforces its own org regardless
        let csr_pem = generate_csr("org-test");
        let signed_der = signer.sign_csr(&csr_pem, "org-test").expect("sign");

        let (_, cert) = x509_parser::parse_x509_certificate(&signed_der).expect("parse");
        let org = cert
            .subject()
            .iter_organization()
            .next()
            .and_then(|o| o.as_str().ok());
        assert_eq!(org, Some("TestOrg"));
    }

    #[test]
    fn ca_cert_der_is_valid() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");

        let (_, ca) =
            x509_parser::parse_x509_certificate(signer.ca_cert_der()).expect("parse CA DER");
        assert!(ca.is_ca());
    }

    #[test]
    fn sign_csr_strips_subject_alt_names() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");

        // Generate a CSR with a SAN
        let key = rcgen::KeyPair::generate().expect("keygen");
        let mut params = CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "san-test");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            "evil.example.com".try_into().expect("dns name"),
        )];
        let csr = params.serialize_request(&key).expect("csr");
        let csr_pem = csr.pem().expect("pem");

        let signed_der = signer.sign_csr(&csr_pem, "san-test").expect("sign");
        let (_, cert) = x509_parser::parse_x509_certificate(&signed_der).expect("parse");

        // The SAN from the CSR should NOT be in the signed cert
        let san = cert
            .subject_alternative_name()
            .expect("SAN extension parse should not error");
        assert!(san.is_none(), "signed cert should have no SANs");
    }

    #[test]
    fn ensure_pem_headers_adds_when_missing() {
        let raw = "MIICdTCCAV0CAQAwEjEQMA4GA1UEAwwHdGVzdC1jbg==";
        let result = ensure_pem_headers(raw);
        assert!(result.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(result.ends_with("-----END CERTIFICATE REQUEST-----"));
        assert!(result.contains(raw));
    }

    #[test]
    fn ensure_pem_headers_preserves_existing() {
        let pem = "-----BEGIN CERTIFICATE REQUEST-----\ndata\n-----END CERTIFICATE REQUEST-----";
        assert_eq!(ensure_pem_headers(pem), pem);
    }
}
