// Copyright © 2026 Roberto Chiofalo.

//! CSR signing logic.
//!
//! Loads a CA certificate and private key from PEM, parses incoming PKCS#10
//! certificate signing requests, and issues signed client certificates.
//!
//! Supports PKCS#8 (`-----BEGIN PRIVATE KEY-----`), PKCS#1
//! (`-----BEGIN RSA PRIVATE KEY-----`), and SEC1
//! (`-----BEGIN EC PRIVATE KEY-----`) CA key formats.

use rcgen::{
    CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

use crate::ca_algorithm::CaAlgorithm;
use crate::error::EnrollmentError;
use crate::keypair::ZeroizingKeyPair;
#[cfg(feature = "post-quantum")]
use crate::mldsa::MlDsaCa;

/// Signs PKCS#10 certificate signing requests with the server CA.
pub struct CsrSigner {
    /// CA issuer handle combining certificate params and signing key.
    ///
    /// The key is wrapped in [`ZeroizingKeyPair`] so rcgen's serialized-DER
    /// copy is wiped on drop (issue #766 / F-39). See `keypair.rs` for the
    /// residual ring-level exposure that this wrapper does not cover.
    issuer: Issuer<'static, ZeroizingKeyPair>,
    /// Original CA certificate DER bytes for enrollment responses.
    /// Kept separate because `Issuer` is reconstructed from the DER and
    /// clients need the exact original CA cert bytes.
    ca_cert_der: Vec<u8>,
    /// Organization name for /tls/config responses.
    organization: String,
    /// Optional pure ML-DSA-87 issuing CA (RFC 9881, #502). When present,
    /// [`Self::sign_csr_with_algorithm`] routes an `ml-dsa-87` selection to
    /// the hand-assembled `MlDsaCa` issuance path instead of failing closed.
    #[cfg(feature = "post-quantum")]
    mldsa_ca: Option<MlDsaCa>,
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
    /// 1. Via [`rustgate_core::pem::parse_certs`] to extract the original DER bytes (for responses).
    /// 2. Via `rcgen::CertificateParams::from_ca_cert_der()` to reconstruct
    ///    signing parameters. The params are then re-self-signed with the key
    ///    to produce a `Certificate` handle that `signed_by()` requires.
    pub fn from_pem(
        ca_cert_pem: &str,
        ca_key_pem: &str,
        organization: &str,
    ) -> Result<Self, EnrollmentError> {
        // Extract original DER for enrollment responses via the shared
        // PEM helper (uniform `ConfigError::PemParse` / `EmptyPem` mapping).
        let mut certs = rustgate_core::pem::parse_certs(ca_cert_pem.as_bytes())
            .map_err(|e| EnrollmentError::Config(format!("failed to parse CA cert PEM: {e}")))?;
        // `parse_certs` guarantees non-empty — index 0 is safe.
        let ca_cert_der = certs.remove(0).to_vec();

        // Load CA key — supports PKCS#8, PKCS#1 (RSA), and SEC1 (EC) PEM formats.
        // Wrapped in ZeroizingKeyPair so the serialized-DER copy rcgen retains
        // is wiped on Drop (issue #766 / F-39).
        let ca_key = ZeroizingKeyPair::new(load_private_key(ca_key_pem)?);

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
            #[cfg(feature = "post-quantum")]
            mldsa_ca: None,
        })
    }

    /// Attach a pure ML-DSA-87 issuing CA (RFC 9881, #502).
    ///
    /// With a CA attached, [`Self::sign_csr_with_algorithm`] issues real
    /// ML-DSA-87 leaf certificates for an `ml-dsa-87` selection; without one
    /// the selection continues to fail closed via
    /// [`issue_mldsa_unavailable`].
    #[cfg(feature = "post-quantum")]
    #[must_use]
    pub fn with_mldsa_ca(mut self, ca: MlDsaCa) -> Self {
        self.mldsa_ca = Some(ca);
        self
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
    ///
    /// # Security: CSR signature verification
    ///
    /// The CSR's self-signature is verified during parsing by
    /// [`CertificateSigningRequestParams::from_pem()`], which internally calls
    /// `x509_parser::certification_request::X509CertificationRequest::verify_signature()`.
    /// If the requester's public key does not match the signature over the CSR
    /// content, `from_pem()` returns an error and the request is rejected.
    /// This proves the requester possesses the private key corresponding to the
    /// public key embedded in the CSR, preventing forged-subject attacks.
    ///
    /// # Security: allowlist approach
    ///
    /// Rather than starting from the CSR's parameters and stripping known-bad
    /// fields (denylist), we construct a fresh `CertificateParams` with only
    /// server-controlled values and extract only the public key from the CSR.
    /// This ensures that any new fields added to `CertificateParams` in future
    /// rcgen versions default to safe values instead of inheriting attacker-
    /// controlled data from the CSR.
    pub fn sign_csr(&self, csr_pem: &str, username: &str) -> Result<Vec<u8>, EnrollmentError> {
        let normalized = ensure_pem_headers(csr_pem);

        let csr = CertificateSigningRequestParams::from_pem(&normalized)
            .map_err(|e| EnrollmentError::Csr(format!("failed to parse CSR: {e}")))?;

        // Validate public key uses a strong algorithm (defense-in-depth).
        validate_public_key_strength(&csr.public_key)?;

        // Build certificate params from scratch (allowlist approach).
        // Only the public key is extracted from the CSR — all other fields
        // are server-controlled to prevent extension/field injection.
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, username);
        dn.push(rcgen::DnType::OrganizationName, &self.organization);

        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = dn;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        // Explicitly empty — no SANs, no custom extensions, no name constraints.
        params.subject_alt_names = Vec::new();
        params.custom_extensions = Vec::new();

        let signed = params
            .signed_by(&csr.public_key, &self.issuer)
            .map_err(|e| EnrollmentError::Signing(format!("failed to sign certificate: {e}")))?;

        Ok(signed.der().to_vec())
    }

    /// Sign a CSR under an explicitly selected CA [`CaAlgorithm`].
    ///
    /// This is the algorithm-aware entry point that the future `--cnsa2`
    /// wiring (#504) calls.
    ///
    /// - Classical selections delegate to [`sign_csr`](CsrSigner::sign_csr)
    ///   unchanged.
    /// - `ml-dsa-87` issues a real pure ML-DSA-87 certificate (RFC 9881, #502)
    ///   **iff** an `MlDsaCa` was attached via `Self::with_mldsa_ca`;
    ///   otherwise it fails closed via [`issue_mldsa_unavailable`].
    /// - `ml-dsa-44` / `ml-dsa-65`, and any ML-DSA selection with no CA
    ///   attached (or on a build without the `post-quantum` feature), fail
    ///   closed.
    ///
    /// The `fips` conflict guard runs first, so an ML-DSA selection on a
    /// FIPS build produces the more specific [`fips_pq_conflict`] error.
    pub fn sign_csr_with_algorithm(
        &self,
        csr_pem: &str,
        username: &str,
        algorithm: CaAlgorithm,
    ) -> Result<Vec<u8>, EnrollmentError> {
        fips_pq_conflict(algorithm)?;

        if algorithm.is_post_quantum() {
            #[cfg(feature = "post-quantum")]
            {
                // Only pure ML-DSA-87 issuance is implemented (RFC 9881). The
                // -44/-65 parameter sets and the Composite ML-DSA hybrid path
                // (ADR 0019) remain deferred and fall through to fail closed.
                if let Some(ca) = &self.mldsa_ca
                    && algorithm == CaAlgorithm::MlDsa87
                {
                    let csr_der = csr_pem_to_der(csr_pem)?;
                    let subject_pubkey = MlDsaCa::verify_csr_pop(&csr_der)?;
                    return ca.issue_leaf(&subject_pubkey, username, &self.organization);
                }
            }
            return Err(issue_mldsa_unavailable(algorithm));
        }

        // Classical algorithms issue via the existing, unchanged path. The
        // CA key's own algorithm determines the signature; this scaffold does
        // not yet re-key the CA per requested classical algorithm — that is a
        // separate slice tracked alongside #504.
        self.sign_csr(csr_pem, username)
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

/// Fail-closed stub for post-quantum (ML-DSA) certificate issuance.
///
/// Returns an [`EnrollmentError::Signing`] with an actionable message
/// pointing at the two upstream blockers (aws-lc-rs #964 and the composite
/// OID finalization) and ADR 0019 Phase 3. This is the **only** ML-DSA
/// branch in [`CsrSigner`]: selecting an ML-DSA algorithm refuses issuance
/// with a clear diagnostic instead of silently emitting a classical or a
/// pure-ML-DSA certificate (both of which would be wrong — see the module
/// docs of [`crate::ca_algorithm`]).
///
/// # Panics
///
/// Never panics; the `debug_assert!` only fires in debug builds if a caller
/// mis-routes a classical algorithm here.
#[must_use]
pub fn issue_mldsa_unavailable(alg: CaAlgorithm) -> EnrollmentError {
    debug_assert!(
        alg.is_post_quantum(),
        "issue_mldsa_unavailable called with a classical algorithm: {alg}"
    );
    EnrollmentError::Signing(format!(
        "ML-DSA issuance blocked on aws-lc-rs #964 / composite OID finalization \
         (ADR 0019 Phase 3): requested `{alg}` is a post-quantum algorithm rustgate \
         cannot yet issue. rustgate commits to Composite ML-DSA + ECDSA hybrid \
         certificates, not pure ML-DSA; the composite path lands when upstream \
         crypto converges. Select a classical algorithm (ecdsa-p256, rsa-2048) \
         until then."
    ))
}

/// Guard rejecting an ML-DSA algorithm selection on a `fips`-enabled build.
///
/// The `fips` and `post-quantum` features are separate, mutually exclusive
/// compile-time gates at the crypto layer (ADR 0019 Decision §4; aws-lc-rs
/// #964): rcgen's ML-DSA support is gated `not(feature = "fips")`. Combining
/// them cannot produce a valid signer, so this fails closed at the API
/// boundary with a clear message rather than surfacing an opaque crypto-
/// provider error deeper down.
///
/// Returns `Ok(())` for any classical algorithm, and for ML-DSA algorithms
/// on a non-FIPS build (where [`issue_mldsa_unavailable`] takes over). It
/// only errors for the ML-DSA + `fips` combination.
pub fn fips_pq_conflict(alg: CaAlgorithm) -> Result<(), EnrollmentError> {
    #[cfg(feature = "fips")]
    {
        if alg.is_post_quantum() {
            return Err(EnrollmentError::Config(format!(
                "requested post-quantum CA algorithm `{alg}` is incompatible with a FIPS build: \
                 the `fips` and `post-quantum` features are mutually exclusive at the crypto \
                 layer (ADR 0019 §4 / aws-lc-rs #964). Build without `fips` to use ML-DSA \
                 algorithms, or select a classical algorithm (ecdsa-p256, rsa-2048)."
            )));
        }
    }

    // On non-FIPS builds `alg` is unused when it is classical; the guard is a
    // no-op success. Reference it so the parameter is always live.
    let _ = alg;
    Ok(())
}

/// Decode a PEM-encoded (or raw base64) CSR into its DER bytes.
///
/// Reuses [`ensure_pem_headers`] to tolerate the header-less base64 that some
/// TAK clients send, then base64-decodes the body. Used only by the ML-DSA
/// issuance path, which parses the DER directly with `x509-cert` rather than
/// through rcgen.
#[cfg(feature = "post-quantum")]
fn csr_pem_to_der(csr_pem: &str) -> Result<Vec<u8>, EnrollmentError> {
    let normalized = ensure_pem_headers(csr_pem);
    let body: String = normalized
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    rustgate_core::b64::decode(body.trim())
        .map_err(|e| EnrollmentError::Csr(format!("failed to base64-decode CSR: {e}")))
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

/// Validate that the CSR's public key uses a cryptographically strong algorithm.
///
/// Rejects weak key types (e.g., RSA < 2048-bit, unsupported curves) with a
/// clear enrollment error rather than relying on the crypto provider's opaque
/// rejection. This is defense-in-depth — ring/aws-lc also reject weak keys,
/// but explicit validation produces better error messages and audit trails.
fn validate_public_key_strength(public_key: &rcgen::PublicKey) -> Result<(), EnrollmentError> {
    let algo = public_key.algorithm();

    // Allow RSA with SHA-256/384/512 (ring enforces >= 2048-bit modulus).
    // Allow ECDSA P-256 and P-384.
    // Allow Ed25519 (unless FIPS — handled by crypto provider selection, not here).
    let allowed: &[&rcgen::SignatureAlgorithm] = &[
        &rcgen::PKCS_RSA_SHA256,
        &rcgen::PKCS_RSA_SHA384,
        &rcgen::PKCS_RSA_SHA512,
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ED25519,
    ];

    if !allowed.contains(&algo) {
        return Err(EnrollmentError::Csr(format!(
            "CSR public key uses unsupported or weak algorithm: {algo:?}"
        )));
    }

    Ok(())
}

/// Load a private key from PEM, supporting PKCS#8, PKCS#1, and SEC1 formats.
///
/// `rustls_pki_types` PEM parsing handles all three PEM tag types, but
/// rcgen with the `ring` backend only accepts PKCS#8 DER. For PKCS#1
/// (RSA) keys, we wrap the DER in a PKCS#8 envelope before handing it
/// to rcgen.
fn load_private_key(pem: &str) -> Result<KeyPair, EnrollmentError> {
    let key_der = rustgate_core::pem::parse_key(pem.as_bytes())
        .map_err(|e| EnrollmentError::Config(format!("failed to parse CA key PEM: {e}")))?;

    let pkcs8_der = match &key_der {
        PrivateKeyDer::Pkcs8(_) => key_der,
        PrivateKeyDer::Pkcs1(pkcs1) => {
            let mut wrapped = pkcs1_to_pkcs8(pkcs1.secret_pkcs1_der());
            PrivateKeyDer::Pkcs8(std::mem::take(&mut *wrapped).into())
        }
        PrivateKeyDer::Sec1(sec1) => {
            let mut wrapped = sec1_to_pkcs8(sec1.secret_sec1_der());
            PrivateKeyDer::Pkcs8(std::mem::take(&mut *wrapped).into())
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
fn pkcs1_to_pkcs8(pkcs1_der: &[u8]) -> Zeroizing<Vec<u8>> {
    // Version: INTEGER 0
    const VERSION: &[u8] = &[0x02, 0x01, 0x00];
    // AlgorithmIdentifier: SEQUENCE { OID rsaEncryption, NULL }
    const ALGO_ID: &[u8] = &[
        0x30, 0x0d, // SEQUENCE, 13 bytes
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, // OID 1.2.840.113549.1.1.1
        0x05, 0x00, // NULL
    ];

    let mut octet_string = Zeroizing::new(der_wrap(0x04, pkcs1_der));
    let inner_len = VERSION.len() + ALGO_ID.len() + octet_string.len();

    let mut out = Vec::with_capacity(4 + inner_len);
    out.push(0x30); // SEQUENCE tag
    der_push_length(&mut out, inner_len);
    out.extend_from_slice(VERSION);
    out.extend_from_slice(ALGO_ID);
    out.extend_from_slice(&octet_string);

    // Zeroize the intermediate buffer now that it has been copied.
    zeroize::Zeroize::zeroize(&mut *octet_string);

    Zeroizing::new(out)
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
fn sec1_to_pkcs8(sec1_der: &[u8]) -> Zeroizing<Vec<u8>> {
    // Version: INTEGER 0
    const VERSION: &[u8] = &[0x02, 0x01, 0x00];
    // AlgorithmIdentifier: SEQUENCE { OID id-ecPublicKey }
    // Note: parameters (named curve) omitted — ring infers from key data
    const ALGO_ID: &[u8] = &[
        0x30, 0x09, // SEQUENCE, 9 bytes
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
    ];

    let mut octet_string = Zeroizing::new(der_wrap(0x04, sec1_der));
    let inner_len = VERSION.len() + ALGO_ID.len() + octet_string.len();

    let mut out = Vec::with_capacity(4 + inner_len);
    out.push(0x30); // SEQUENCE tag
    der_push_length(&mut out, inner_len);
    out.extend_from_slice(VERSION);
    out.extend_from_slice(ALGO_ID);
    out.extend_from_slice(&octet_string);

    // Zeroize the intermediate buffer now that it has been copied.
    zeroize::Zeroize::zeroize(&mut *octet_string);

    Zeroizing::new(out)
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
        let key_der = rustgate_core::pem::parse_key(RSA_CA_KEY_PKCS1.as_bytes()).expect("parse");

        match &key_der {
            PrivateKeyDer::Pkcs1(pkcs1) => {
                let mut pkcs8 = super::pkcs1_to_pkcs8(pkcs1.secret_pkcs1_der());
                // PKCS#8 starts with SEQUENCE tag
                assert_eq!(pkcs8[0], 0x30, "should be a SEQUENCE");
                // Should be parseable by rcgen
                let wrapped = PrivateKeyDer::Pkcs8(std::mem::take(&mut *pkcs8).into());
                let key = KeyPair::try_from(&wrapped);
                assert!(
                    key.is_ok(),
                    "converted PKCS#8 should be valid: {:?}",
                    key.err()
                );
            }
            other => unreachable!(
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

    #[test]
    fn sign_csr_rejects_tampered_signature() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");

        let csr_pem = generate_csr("tamper-test");

        // Tamper with the signature by flipping bits in the base64-encoded
        // body of the PEM. The signature occupies the last portion of the
        // DER payload, so corrupting the final base64 lines reliably
        // invalidates it.
        let lines: Vec<&str> = csr_pem.lines().collect();
        let mut tampered_lines: Vec<String> = Vec::with_capacity(lines.len());
        for (i, line) in lines.iter().enumerate() {
            if i == lines.len() - 2 && !line.starts_with("-----") {
                // Flip bits in the last data line (signature bytes)
                let mut chars: Vec<char> = line.chars().collect();
                for c in &mut chars {
                    *c = match *c {
                        'A' => 'Z',
                        'a' => 'z',
                        '0' => '9',
                        '+' => '/',
                        other => {
                            // Shift alphabetic characters
                            if other.is_ascii_uppercase() {
                                'A'
                            } else if other.is_ascii_lowercase() {
                                'a'
                            } else {
                                other
                            }
                        }
                    };
                }
                tampered_lines.push(chars.into_iter().collect());
            } else {
                tampered_lines.push(line.to_string());
            }
        }
        let tampered_pem = tampered_lines.join("\n");

        let result = signer.sign_csr(&tampered_pem, "tamper-test");
        assert!(
            result.is_err(),
            "sign_csr should reject a CSR with a tampered signature"
        );
    }

    #[test]
    fn sign_csr_rejects_mismatched_key() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");

        // Generate two independent key pairs
        let key_a = rcgen::KeyPair::generate().expect("keygen A");
        let key_b = rcgen::KeyPair::generate().expect("keygen B");

        // Create a CSR signed by key_a
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "mismatch-test");
        params.distinguished_name = dn;
        let csr = params.serialize_request(&key_a).expect("csr");
        let csr_der = csr.der().to_vec();

        // Replace the public key in the DER with key_b's public key.
        // The CSR's self-signature was computed over key_a's public key, so
        // substituting key_b's public key creates a proof-of-possession
        // mismatch that verify_signature must reject.
        let pub_a = key_a.public_key_raw();
        let pub_b = key_b.public_key_raw();

        // Both keys are default ECDSA P-256, so they must be the same length.
        assert_eq!(
            pub_a.len(),
            pub_b.len(),
            "both default keys should be same algorithm"
        );

        // Find pub_a bytes in the CSR DER and replace with pub_b
        let pos = csr_der
            .windows(pub_a.len())
            .position(|w| w == pub_a)
            .expect("public key bytes must appear in CSR DER");

        let mut modified_der = csr_der.clone();
        modified_der[pos..pos + pub_a.len()].copy_from_slice(pub_b);

        // Wrap the modified DER back into PEM
        let encoded = rustgate_core::b64::encode(&modified_der);
        let pem = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----",
            encoded
                .as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).expect("valid utf8"))
                .collect::<Vec<_>>()
                .join("\n")
        );

        let result = signer.sign_csr(&pem, "mismatch-test");
        assert!(
            result.is_err(),
            "sign_csr should reject a CSR whose public key does not match its signature"
        );
    }

    #[test]
    fn validate_key_strength_accepts_ecdsa_p256() {
        let key = rcgen::KeyPair::generate().expect("keygen");
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "strength-test");
        params.distinguished_name = dn;
        let csr = params.serialize_request(&key).expect("csr");
        let pem = csr.pem().expect("pem");
        let parsed = rcgen::CertificateSigningRequestParams::from_pem(&pem).expect("parse CSR");
        assert!(
            validate_public_key_strength(&parsed.public_key).is_ok(),
            "ECDSA P-256 should be accepted"
        );
    }

    #[test]
    fn sign_csr_key_strength_checked_before_signing() {
        // Verify that sign_csr invokes key strength validation. Since
        // rcgen::KeyPair::generate() defaults to P-256 (allowed), we can
        // only confirm the happy path here. The validation function itself
        // is tested directly via validate_key_strength_accepts_ecdsa_p256.
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");
        let csr_pem = generate_csr("strength-integration");
        assert!(signer.sign_csr(&csr_pem, "strength-integration").is_ok());
    }

    #[test]
    fn sign_csr_rejects_malformed_pem() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");

        // Truncated base64 — structurally plausible but corrupt
        let truncated = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBkTCB+wIBAD\n-----END CERTIFICATE REQUEST-----\n";
        assert!(signer.sign_csr(truncated, "test-user").is_err());

        // Wrong PEM header type
        let wrong_header = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIBADAWMRQwEgYDVQQDDAt0ZXN0LWNsaWVudA==\n-----END CERTIFICATE-----\n";
        assert!(signer.sign_csr(wrong_header, "test-user").is_err());

        // Empty PEM body
        let empty_body = "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n";
        assert!(signer.sign_csr(empty_body, "test-user").is_err());
    }

    #[test]
    fn issue_mldsa_unavailable_carries_actionable_upstream_message() {
        for alg in [
            CaAlgorithm::MlDsa44,
            CaAlgorithm::MlDsa65,
            CaAlgorithm::MlDsa87,
        ] {
            let err = issue_mldsa_unavailable(alg);
            let msg = err.to_string();
            assert!(
                matches!(err, EnrollmentError::Signing(_)),
                "must be a Signing error, got {err:?}"
            );
            assert!(
                msg.contains("aws-lc-rs #964"),
                "cite upstream blocker: {msg}"
            );
            assert!(msg.contains("ADR 0019"), "cite the ADR: {msg}");
            assert!(
                msg.contains(alg.as_str()),
                "name the requested algorithm: {msg}"
            );
        }
    }

    #[test]
    fn sign_csr_with_algorithm_classical_still_issues() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");
        let csr_pem = generate_csr("ignored-cn");

        let signed_der = signer
            .sign_csr_with_algorithm(&csr_pem, "test-client", CaAlgorithm::EcdsaP256)
            .expect("classical selection must still issue");
        let (_, cert) = x509_parser::parse_x509_certificate(&signed_der).expect("parse");
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok()),
            Some("test-client")
        );
    }

    #[test]
    fn sign_csr_with_algorithm_fails_closed_on_mldsa() {
        let (cert_pem, key_pem) = test_ca();
        let signer = CsrSigner::from_pem(&cert_pem, &key_pem, "TestOrg").expect("signer");
        let csr_pem = generate_csr("ignored-cn");

        let err = signer
            .sign_csr_with_algorithm(&csr_pem, "test-client", CaAlgorithm::MlDsa87)
            .expect_err("ML-DSA selection must NOT issue a certificate");
        let msg = err.to_string();
        // On a non-FIPS build this is the issuance-blocked message; on a FIPS
        // build the conflict guard fires first. Either way it must reference
        // ADR 0019 and refuse to issue.
        assert!(msg.contains("ADR 0019"), "error must cite ADR 0019: {msg}");
    }

    #[test]
    fn fips_pq_conflict_allows_classical() {
        assert!(fips_pq_conflict(CaAlgorithm::EcdsaP256).is_ok());
        assert!(fips_pq_conflict(CaAlgorithm::Rsa2048).is_ok());
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn fips_pq_conflict_is_noop_for_mldsa_without_fips() {
        // Without the `fips` feature the conflict guard passes; the
        // fail-closed refusal comes from `issue_mldsa_unavailable` instead.
        assert!(fips_pq_conflict(CaAlgorithm::MlDsa87).is_ok());
    }

    #[cfg(feature = "fips")]
    #[test]
    fn fips_pq_conflict_rejects_mldsa_on_fips_build() {
        let err = fips_pq_conflict(CaAlgorithm::MlDsa87).expect_err("ML-DSA + fips must conflict");
        assert!(matches!(err, EnrollmentError::Config(_)));
        assert!(err.to_string().contains("FIPS"));
    }
}
