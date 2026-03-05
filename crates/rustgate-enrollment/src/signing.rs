//! CSR signing logic.
//!
//! Loads a CA certificate and private key from PEM, parses incoming PKCS#10
//! certificate signing requests, and issues signed client certificates.
//!
//! Supports PKCS#8 (`-----BEGIN PRIVATE KEY-----`), PKCS#1
//! (`-----BEGIN RSA PRIVATE KEY-----`), and SEC1
//! (`-----BEGIN EC PRIVATE KEY-----`) CA key formats.

use std::io::BufReader;

use rcgen::{
    CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::PrivateKeyDer;

use crate::error::EnrollmentError;

/// Signs PKCS#10 certificate signing requests with the server CA.
pub struct CsrSigner {
    /// CA issuer handle combining certificate params and signing key.
    issuer: Issuer<'static, KeyPair>,
    /// Original CA certificate DER bytes for enrollment responses.
    /// Kept separate because `Issuer` is reconstructed from the DER and
    /// clients need the exact original CA cert bytes.
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

        // Load CA key — supports PKCS#8, PKCS#1 (RSA), and SEC1 (EC) PEM formats.
        let ca_key = load_private_key(ca_key_pem)?;

        // Build an Issuer directly from the CA cert DER and private key.
        // The Issuer extracts the subject DN and extensions needed for signing
        // without re-self-signing (which was required in rcgen 0.13).
        let issuer = Issuer::from_ca_cert_der(
            &rustls_pki_types::CertificateDer::from(ca_cert_der.as_slice()),
            ca_key,
        )
        .map_err(|e| EnrollmentError::Config(format!("failed to build CA issuer: {e}")))?;

        Ok(Self {
            issuer,
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
            .signed_by(&csr.public_key, &self.issuer)
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

/// Load a private key from PEM, supporting PKCS#8, PKCS#1, and SEC1 formats.
///
/// `rustls_pemfile` handles all three PEM tag types, but rcgen with the
/// `ring` backend only accepts PKCS#8 DER. For PKCS#1 (RSA) keys, we
/// wrap the DER in a PKCS#8 envelope before handing it to rcgen.
fn load_private_key(pem: &str) -> Result<KeyPair, EnrollmentError> {
    let mut reader = BufReader::new(pem.as_bytes());
    let key_der = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| EnrollmentError::Config(format!("failed to parse CA key PEM: {e}")))?
        .ok_or_else(|| EnrollmentError::Config("no private key found in CA key PEM".to_string()))?;

    let pkcs8_der = match &key_der {
        PrivateKeyDer::Pkcs8(_) => key_der,
        PrivateKeyDer::Pkcs1(pkcs1) => {
            PrivateKeyDer::Pkcs8(pkcs1_to_pkcs8(pkcs1.secret_pkcs1_der()).into())
        }
        PrivateKeyDer::Sec1(sec1) => {
            PrivateKeyDer::Pkcs8(sec1_to_pkcs8(sec1.secret_sec1_der()).into())
        }
        _ => {
            return Err(EnrollmentError::Config(
                "unsupported key format".to_string(),
            ));
        }
    };

    KeyPair::try_from(&pkcs8_der)
        .map_err(|e| EnrollmentError::Config(format!("failed to load CA key: {e}")))
}

/// Wrap PKCS#1 RSA private key DER in a PKCS#8 envelope.
///
/// Constructs a PKCS#8 `PrivateKeyInfo` ASN.1 structure:
/// ```text
/// SEQUENCE {
///   INTEGER 0                                     -- version
///   SEQUENCE {                                    -- algorithm
///     OID 1.2.840.113549.1.1.1 (rsaEncryption)
///     NULL
///   }
///   OCTET STRING { <pkcs1_der> }                  -- privateKey
/// }
/// ```
fn pkcs1_to_pkcs8(pkcs1_der: &[u8]) -> Vec<u8> {
    // Version: INTEGER 0
    const VERSION: &[u8] = &[0x02, 0x01, 0x00];
    // AlgorithmIdentifier: SEQUENCE { OID rsaEncryption, NULL }
    const ALGO_ID: &[u8] = &[
        0x30, 0x0d, // SEQUENCE, 13 bytes
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, // OID 1.2.840.113549.1.1.1
        0x05, 0x00, // NULL
    ];

    let octet_string = der_wrap(0x04, pkcs1_der);
    let inner_len = VERSION.len() + ALGO_ID.len() + octet_string.len();

    let mut out = Vec::with_capacity(4 + inner_len);
    out.push(0x30); // SEQUENCE tag
    der_push_length(&mut out, inner_len);
    out.extend_from_slice(VERSION);
    out.extend_from_slice(ALGO_ID);
    out.extend_from_slice(&octet_string);
    out
}

/// Wrap SEC1 EC private key DER in a PKCS#8 envelope.
///
/// Uses the `id-ecPublicKey` OID with an absent `parameters` field.
/// Ring infers the curve from the key itself, so omitting the named
/// curve OID is safe and avoids hard-coding curve-specific constants.
///
/// ```text
/// SEQUENCE {
///   INTEGER 0                                     -- version
///   SEQUENCE {                                    -- algorithm
///     OID 1.2.840.10045.2.1 (id-ecPublicKey)
///   }
///   OCTET STRING { <sec1_der> }                   -- privateKey
/// }
/// ```
fn sec1_to_pkcs8(sec1_der: &[u8]) -> Vec<u8> {
    // Version: INTEGER 0
    const VERSION: &[u8] = &[0x02, 0x01, 0x00];
    // AlgorithmIdentifier: SEQUENCE { OID id-ecPublicKey }
    // Note: parameters (named curve) omitted — ring infers from key data
    const ALGO_ID: &[u8] = &[
        0x30, 0x09, // SEQUENCE, 9 bytes
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
    ];

    let octet_string = der_wrap(0x04, sec1_der);
    let inner_len = VERSION.len() + ALGO_ID.len() + octet_string.len();

    let mut out = Vec::with_capacity(4 + inner_len);
    out.push(0x30); // SEQUENCE tag
    der_push_length(&mut out, inner_len);
    out.extend_from_slice(VERSION);
    out.extend_from_slice(ALGO_ID);
    out.extend_from_slice(&octet_string);
    out
}

/// Wrap `data` in a DER TLV with the given `tag`.
fn der_wrap(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.push(tag);
    der_push_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

/// Encode a DER definite-length field (supports lengths up to 65535).
fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
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
        let mut params = rcgen::CertificateParams::default();
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

    // Pre-generated RSA 2048-bit CA for PKCS#1 format tests.
    // Generated with: openssl genrsa 2048 / openssl req -new -x509
    // This key is PKCS#1 format (BEGIN RSA PRIVATE KEY).
    const RSA_CA_KEY_PKCS1: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAl0VTjNoBKyMO5e8zOLGHPrQXJZWwLYs+2kKLFN+I/00YNPfN
lqkZlf0mMzyF7VCQkySiDJyHFmHk2qasp59eV9y+SWf7HPj3AkPgoT7jYXBEeWxK
xH7eNBIm5LGalsYiFToSLacdjYe8MmOUt/iyMOnEwBCyzesGNLHvchOwlDplAlA/
JFcU68R/DHNP7JUg5ApsAbm/1Z7t7BBG1/gMV7D3kXNrz2op7k/vZ+HjgbKbRv3L
AmXi7iyAnOm0TW+7BTmGE6SclcdgntwRUpeyK5LpMKlYzsRD2NmY37seLFepvbTB
PGwjJkzcl19aTIYYO2dk2Io1uCYFtPqtvVpirQIDAQABAoIBAE6dNcWOimrrplNy
03DUOhApMZpTx6Jzqi9tw7AOV7kuTLVCTzLMIMLlM9QO0R867le6AwmA02eban8D
fdkDJtmMm8u0YTl2XZBszDGgaDT8Tmm4EMc7k6kGAfZ6InfW8mGLs2TMY7xo3TJm
tCRD9/8Zjimuw+3mBWyfSGxFtU/imI1EYy9bcXKEtW8UTUv7J3nf6sBLnI7Wpec7
FjVmiCEpIe3BpRBdrNY2CeoVTaFdwUfUHjXmC7SWEOlfIfxks1v7978mrH98VXbn
kGNKu4buYVM7o4EbqTaFNVYjzPM8nbVeQkocgrxBB9Heh9EIicByPxAZSvC65lYr
CdBx1iECgYEAxqLOTnHRyutsspbyzEAZR0E1KRfshQW+fvmQOo4gH0FMGHLhljrs
Y8dIOr/mk6B1HGOIhiZy4RmTNRwMdXgLIXJN8J0KAFO0sCcv+n0Bgwc3KJzliWwH
aGNPKjiRLZekkhV16t5PkftT7i6TrkGorotIL4pYm8mFFXhUvCl4V7kCgYEAwvTO
QCHbHMh81vYA+zZDUOutwhaxuI63OwhZsEyp/0OtnUMG+m7GsFVTCKaTEdWvRgmu
7ywloBciqvkWlctDZPoK2LBVge1TxDQjLxF0IPvUsjs61163GOlfUcXBIX9CNkWA
z6UsP1Lqh4S/D9sHLtPRMSdgZd230VgYXY/L9JUCgYEApRcJCq+Uoud6RxAoKdQY
bl1m1omYvZJhmlzHH7OiRPfbS/KnRVohwGgPwyxdclMJIpgjDwQDtMyxyZFPVY55
CcpbtuB+QHlRkppvSOv+hq1HjcyhBc8wdPUdBcVP/Cmt0PBfOd6dGYJeZnZ1rX3K
uY7vZvu/23Lo1khVfLGm4JkCgYBRDZR+Z1UAl34HpQltZ/b+uq1oByVmVLdrLKKV
QJpgzVNuEYLiNZIXl7HI4/A7NvsDBF2dhF40O8onCR5RsstXPPmrc0xpkzEDXqXO
GNSOLgUVALkK947qJYSCq9QKyCzQAX93VPWbci6dnxwMTISk/F15sSRL1a1ptNWU
eIdULQKBgGwWiEovrVSD9sCEQQ7y9JYAgIFxba80Npi2g0hVR8P0Z1TlyQfI9RBh
zm4JhU93uOSaicOZw1/RxD/s3KX0jC4wqWv+n/BDgMOKn9WqCXccizCMBY1GcGlX
axw9E8ofF+5cJZf1l+LoRuV0S1cLh+Xilkdo9MRysOermXIi7NRe
-----END RSA PRIVATE KEY-----";

    const RSA_CA_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIC0jCCAbqgAwIBAgIJAOTZFYo3PYcGMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV
BAMMC1Rlc3QgUlNBIENBMB4XDTI2MDMwNTAwNTAyMVoXDTI3MDMwNTAwNTAyMVow
FjEUMBIGA1UEAwwLVGVzdCBSU0EgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCXRVOM2gErIw7l7zM4sYc+tBcllbAtiz7aQosU34j/TRg0982WqRmV
/SYzPIXtUJCTJKIMnIcWYeTapqynn15X3L5JZ/sc+PcCQ+ChPuNhcER5bErEft40
EibksZqWxiIVOhItpx2Nh7wyY5S3+LIw6cTAELLN6wY0se9yE7CUOmUCUD8kVxTr
xH8Mc0/slSDkCmwBub/Vnu3sEEbX+AxXsPeRc2vPainuT+9n4eOBsptG/csCZeLu
LICc6bRNb7sFOYYTpJyVx2Ce3BFSl7IrkukwqVjOxEPY2Zjfux4sV6m9tME8bCMm
TNyXX1pMhhg7Z2TYijW4JgW0+q29WmKtAgMBAAGjIzAhMA8GA1UdEwEB/wQFMAMB
Af8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQAMiLgeVtHEHL67
CnIxY0QSZwaCu7uXMei9HRM5Vd+0TgqKLcqRKGbSc5cOj4p3aVmWgGCBXMqzuVqS
gFVg4wChDibzCaTyEglL6lzM8SHmzgB8VsNJN70nlaUmKkl7uoCm18bwgXLj5nLa
2NqaiEwkluafamdMUhCNp7i1M+KOVkrLjMva7uUqQytdV39PNmfX5RVJMXXB3WCA
bnqEoVqO7Os4lJs1pFsoWF5D8FA6HgUkHDfIChAW4nzpyeOBf7SjQtRNMGxCfEMO
liLgeU5DyHx4hByvxFJtFJwolr91kMZeqGmncwRAUbtlBgl/TvIdva84lX5vdVN1
cyOZxZiK
-----END CERTIFICATE-----";

    #[test]
    fn from_pem_accepts_pkcs1_rsa_key() {
        assert!(
            RSA_CA_KEY_PKCS1.contains("BEGIN RSA PRIVATE KEY"),
            "test key should be PKCS#1 format"
        );

        let signer = CsrSigner::from_pem(RSA_CA_CERT, RSA_CA_KEY_PKCS1, "TestOrg");
        assert!(
            signer.is_ok(),
            "CsrSigner should accept PKCS#1 key: {:?}",
            signer.err()
        );
    }

    #[test]
    fn sign_csr_with_pkcs1_ca_key() {
        let signer = CsrSigner::from_pem(RSA_CA_CERT, RSA_CA_KEY_PKCS1, "TestOrg")
            .expect("signer with PKCS#1");

        let csr_pem = generate_csr("pkcs1-client");
        let signed_der = signer
            .sign_csr(&csr_pem, "pkcs1-client")
            .expect("sign with PKCS#1 CA key");

        let (_, cert) = x509_parser::parse_x509_certificate(&signed_der).expect("parse");
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok()),
            Some("pkcs1-client")
        );

        // Verify the signed cert chains to our RSA CA
        let eku = cert
            .extended_key_usage()
            .expect("EKU present")
            .expect("parse EKU");
        assert!(eku.value.client_auth, "cert should have ClientAuth EKU");
    }

    #[test]
    fn pkcs1_to_pkcs8_produces_valid_der() {
        // Parse the PKCS#1 key and convert to PKCS#8
        let mut reader = BufReader::new(RSA_CA_KEY_PKCS1.as_bytes());
        let key_der = rustls_pemfile::private_key(&mut reader)
            .expect("parse")
            .expect("present");

        match &key_der {
            PrivateKeyDer::Pkcs1(pkcs1) => {
                let pkcs8 = super::pkcs1_to_pkcs8(pkcs1.secret_pkcs1_der());
                // PKCS#8 starts with SEQUENCE tag
                assert_eq!(pkcs8[0], 0x30, "should be a SEQUENCE");
                // Should be parseable by rcgen
                let wrapped = PrivateKeyDer::Pkcs8(pkcs8.into());
                let key = KeyPair::try_from(&wrapped);
                assert!(
                    key.is_ok(),
                    "converted PKCS#8 should be valid: {:?}",
                    key.err()
                );
            }
            other => panic!(
                "expected PKCS#1 key, got {:?}",
                std::mem::discriminant(other)
            ),
        }
    }

    #[test]
    fn load_private_key_accepts_pkcs8() {
        // PKCS#8 (from TestCa which uses ECDSA) should also work
        let (_, key_pem) = test_ca();
        let key = load_private_key(&key_pem);
        assert!(key.is_ok(), "should accept PKCS#8 key: {:?}", key.err());
    }

    #[test]
    fn load_private_key_rejects_invalid_pem() {
        let result = load_private_key("not a valid PEM");
        assert!(result.is_err());
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
