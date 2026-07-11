// Copyright © 2026 Roberto Chiofalo.

//! Pure ML-DSA-87 X.509 certificate and CRL issuance (RFC 9881).
//!
//! `rcgen` — the classical issuance engine in [`crate::signing`] and
//! [`crate::revocation`] — cannot emit ML-DSA certificates: its ML-DSA path
//! is gated behind `aws_lc_rs_unstable`, is mutually exclusive with `fips`,
//! and produces pure certificates in a shape rustgate does not control. This
//! module therefore hand-assembles the X.509 structures with `x509-cert` /
//! `der` and signs the DER-encoded `TBSCertificate` / `TBSCertList` with the
//! pure-Rust [`fips204`] FIPS 204 implementation.
//!
//! # Scope — pure ML-DSA-87, not composite
//!
//! This delivers **pure** ML-DSA-87 issuance under the RFC 9881 OID
//! `2.16.840.1.101.3.4.3.19` (parameters absent). The Composite ML-DSA +
//! ECDSA hybrid path that ADR 0019 targets for the CNSA 2.0 transition
//! window remains deferred until `draft-ietf-lamps-pq-composite-sigs`
//! becomes an RFC and the composite OIDs are finalized; see
//! [`crate::ca_algorithm`]. Selecting an ML-DSA algorithm without an
//! [`MlDsaCa`] configured on the signer still fails closed
//! ([`crate::signing::issue_mldsa_unavailable`]).
//!
//! # Security posture
//!
//! - The subject Common Name is taken from the **authenticated username**,
//!   never from the CSR subject — mirroring the allowlist hardening in
//!   [`crate::signing::CsrSigner::sign_csr`]. The CSR contributes only its
//!   ML-DSA public key, and only after its proof-of-possession self-signature
//!   verifies ([`MlDsaCa::verify_csr_pop`]).
//! - Issued leaves carry exactly BasicConstraints `CA:FALSE`, KeyUsage
//!   `digitalSignature`, and ExtKeyUsage `clientAuth` — no SANs, no custom
//!   extensions.
//! - The CA secret key is held as serialized bytes in [`Zeroizing`] and the
//!   `fips204` private key is reconstructed per signature; the transient
//!   stack copy of the serialized key is wiped immediately after expansion.
//!   (The expanded `fips204` key itself is not `Zeroize`-able upstream, so
//!   that residual lives on the stack for the duration of one signing call.)

use std::fmt;
use std::time::{Duration, SystemTime};

use der::asn1::{BitString, GeneralizedTime, OctetString, SetOfVec, Uint, UtcTime, Utf8StringRef};
use der::oid::{AssociatedOid, ObjectIdentifier};
use der::{Any, Decode, Encode};
use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer, Verifier};
use ring::rand::{SecureRandom, SystemRandom};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{
    BasicConstraints, CrlNumber, CrlReason, ExtendedKeyUsage, KeyUsage, KeyUsages,
};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::request::CertReq;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use zeroize::Zeroizing;

use crate::error::EnrollmentError;

/// id-ml-dsa-87 (RFC 9881 / NIST CSOR): `2.16.840.1.101.3.4.3.19`.
///
/// `new_unwrap` is a `const fn`; evaluating it in this `const` binding means
/// a malformed literal would fail at compile time (const-eval), never at
/// runtime.
const OID_ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");
/// id-at-commonName (`2.5.4.3`).
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// id-at-organizationName (`2.5.4.10`).
const OID_ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
/// id-kp-clientAuth (`1.3.6.1.5.5.7.3.2`).
const OID_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// Leaf certificate validity window (365 days), matching the classical path.
const LEAF_VALIDITY: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// Backdate `notBefore` to tolerate client/server clock skew, matching the
/// classical path's 5-minute backdate.
const CLOCK_SKEW_BACKDATE: Duration = Duration::from_secs(5 * 60);

/// The RFC 9881 `AlgorithmIdentifier` for id-ml-dsa-87 with **absent**
/// parameters (`parameters` is `None`, i.e. the field is omitted).
#[must_use]
pub fn id_ml_dsa_87() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: OID_ML_DSA_87,
        parameters: None,
    }
}

/// A revoked-certificate entry for [`MlDsaCa::issue_crl`].
#[derive(Debug, Clone)]
pub struct MlDsaRevokedCert {
    /// Big-endian serial-number magnitude bytes (leading zeros are stripped
    /// during encoding).
    pub serial: Vec<u8>,
    /// When the certificate was revoked.
    pub revocation_time: SystemTime,
    /// Optional RFC 5280 reason code (emitted as a CRL entry extension).
    pub reason: Option<CrlReason>,
}

/// A pure ML-DSA-87 issuing CA: the CA certificate DER plus the `fips204`
/// secret key needed to sign issued leaves and CRLs.
///
/// The secret key is stored as its serialized `fips204` form wrapped in
/// [`Zeroizing`] so it is wiped on drop; the expanded signing key is
/// reconstructed on demand for each signature.
pub struct MlDsaCa {
    /// The CA certificate as DER (returned verbatim to enrolling clients).
    ca_cert_der: Vec<u8>,
    /// The CA certificate subject, used as the `issuer` of issued leaves/CRLs.
    issuer_name: Name,
    /// Serialized `fips204` ML-DSA-87 secret key (`SK_LEN` bytes), wiped on
    /// drop.
    secret_key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for MlDsaCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaCa")
            .field("ca_cert_der_len", &self.ca_cert_der.len())
            .field("secret_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl MlDsaCa {
    /// Construct an issuing CA from operator-supplied cert DER and the
    /// serialized `fips204` ML-DSA-87 secret key.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError::Config`] if the certificate does not parse,
    /// does not advertise id-ml-dsa-87, or if the secret key is not exactly
    /// `SK_LEN` bytes.
    pub fn from_der(cert_der: Vec<u8>, secret_key: Vec<u8>) -> Result<Self, EnrollmentError> {
        let cert = Certificate::from_der(&cert_der).map_err(|e| {
            EnrollmentError::Config(format!("failed to parse ML-DSA CA certificate: {e}"))
        })?;

        if cert.signature_algorithm.oid != OID_ML_DSA_87 {
            return Err(EnrollmentError::Config(format!(
                "ML-DSA CA certificate signature algorithm is `{}`, expected id-ml-dsa-87 \
                 (2.16.840.1.101.3.4.3.19)",
                cert.signature_algorithm.oid
            )));
        }

        if secret_key.len() != ml_dsa_87::SK_LEN {
            return Err(EnrollmentError::Config(format!(
                "ML-DSA-87 CA secret key must be {} bytes, got {}",
                ml_dsa_87::SK_LEN,
                secret_key.len()
            )));
        }

        let issuer_name = cert.tbs_certificate.subject.clone();
        Ok(Self {
            ca_cert_der: cert_der,
            issuer_name,
            secret_key: Zeroizing::new(secret_key),
        })
    }

    /// The CA certificate DER, for inclusion in enrollment responses.
    #[must_use]
    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// Reconstruct the expanded `fips204` signing key from the stored bytes.
    ///
    /// The transient stack copy of the serialized key is zeroized after the
    /// key is expanded.
    fn private_key(&self) -> Result<ml_dsa_87::PrivateKey, EnrollmentError> {
        if self.secret_key.len() != ml_dsa_87::SK_LEN {
            return Err(EnrollmentError::Config(format!(
                "ML-DSA-87 CA secret key must be {} bytes, got {}",
                ml_dsa_87::SK_LEN,
                self.secret_key.len()
            )));
        }
        // `[u8; SK_LEN]` is `Copy`, so `try_from_bytes` receives its own copy
        // and the local `arr` remains ours to wipe.
        let mut arr = [0u8; ml_dsa_87::SK_LEN];
        arr.copy_from_slice(&self.secret_key);
        let key = ml_dsa_87::PrivateKey::try_from_bytes(arr).map_err(|e| {
            EnrollmentError::Config(format!("failed to load ML-DSA-87 CA secret key: {e}"))
        })?;
        zeroize::Zeroize::zeroize(&mut arr);
        Ok(key)
    }

    /// ML-DSA-sign a byte string with the CA key using the empty context
    /// (`ctx = &[]`), as RFC 9881 mandates for X.509 signatures.
    fn sign_bytes(&self, msg: &[u8]) -> Result<[u8; ml_dsa_87::SIG_LEN], EnrollmentError> {
        let key = self.private_key()?;
        key.try_sign(msg, &[])
            .map_err(|e| EnrollmentError::Signing(format!("ML-DSA-87 signing failed: {e}")))
    }

    /// Verify a PKCS#10 CSR's ML-DSA-87 proof-of-possession self-signature and
    /// return the raw ML-DSA public key bytes.
    ///
    /// Parses the `CertReq`, checks that both the subject SPKI algorithm and
    /// the request's outer signature algorithm are id-ml-dsa-87, then verifies
    /// the signature over the DER-encoded `CertReqInfo` with the embedded
    /// public key. A tampered or mismatched signature is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError::Csr`] for any parse failure, non-ML-DSA
    /// algorithm, malformed key/signature length, or failed proof-of-possession.
    pub fn verify_csr_pop(csr_der: &[u8]) -> Result<Vec<u8>, EnrollmentError> {
        let csr = CertReq::from_der(csr_der)
            .map_err(|e| EnrollmentError::Csr(format!("failed to parse ML-DSA CSR: {e}")))?;

        if csr.info.public_key.algorithm.oid != OID_ML_DSA_87 {
            return Err(EnrollmentError::Csr(format!(
                "CSR subject public key algorithm is `{}`, expected id-ml-dsa-87",
                csr.info.public_key.algorithm.oid
            )));
        }
        if csr.algorithm.oid != OID_ML_DSA_87 {
            return Err(EnrollmentError::Csr(format!(
                "CSR signature algorithm is `{}`, expected id-ml-dsa-87",
                csr.algorithm.oid
            )));
        }

        let pk_bytes = csr
            .info
            .public_key
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| {
                EnrollmentError::Csr("CSR public key BIT STRING has unused bits".to_string())
            })?;
        if pk_bytes.len() != ml_dsa_87::PK_LEN {
            return Err(EnrollmentError::Csr(format!(
                "CSR public key is {} bytes, expected {} for ML-DSA-87",
                pk_bytes.len(),
                ml_dsa_87::PK_LEN
            )));
        }
        let mut pk_arr = [0u8; ml_dsa_87::PK_LEN];
        pk_arr.copy_from_slice(pk_bytes);
        let public_key = ml_dsa_87::PublicKey::try_from_bytes(pk_arr)
            .map_err(|e| EnrollmentError::Csr(format!("invalid ML-DSA-87 public key: {e}")))?;

        // The signed content is the DER-encoded CertReqInfo. DER is canonical,
        // so re-encoding the parsed structure reproduces the signed bytes.
        let info_der = csr
            .info
            .to_der()
            .map_err(|e| EnrollmentError::Csr(format!("failed to re-encode CertReqInfo: {e}")))?;

        let sig_bytes = csr.signature.as_bytes().ok_or_else(|| {
            EnrollmentError::Csr("CSR signature BIT STRING has unused bits".to_string())
        })?;
        if sig_bytes.len() != ml_dsa_87::SIG_LEN {
            return Err(EnrollmentError::Csr(format!(
                "CSR signature is {} bytes, expected {} for ML-DSA-87",
                sig_bytes.len(),
                ml_dsa_87::SIG_LEN
            )));
        }
        let mut sig_arr = [0u8; ml_dsa_87::SIG_LEN];
        sig_arr.copy_from_slice(sig_bytes);

        if !public_key.verify(&info_der, &sig_arr, &[]) {
            return Err(EnrollmentError::Csr(
                "CSR proof-of-possession signature verification failed".to_string(),
            ));
        }

        Ok(pk_bytes.to_vec())
    }

    /// Issue a leaf client certificate over the given raw ML-DSA-87 public key.
    ///
    /// The `subject_pubkey` is the raw `PK_LEN`-byte ML-DSA public key (as
    /// returned by [`Self::verify_csr_pop`]); the SubjectPublicKeyInfo is
    /// rebuilt canonically here rather than trusting the CSR's encoding. The
    /// Common Name is the authenticated `cn` (not the CSR subject) and the
    /// Organization is `org`.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError::Csr`] for a wrong-length public key and
    /// [`EnrollmentError::Signing`] for any encoding or signing failure.
    pub fn issue_leaf(
        &self,
        subject_pubkey: &[u8],
        cn: &str,
        org: &str,
    ) -> Result<Vec<u8>, EnrollmentError> {
        if subject_pubkey.len() != ml_dsa_87::PK_LEN {
            return Err(EnrollmentError::Csr(format!(
                "subject public key is {} bytes, expected {} for ML-DSA-87",
                subject_pubkey.len(),
                ml_dsa_87::PK_LEN
            )));
        }

        let spki = SubjectPublicKeyInfoOwned {
            algorithm: id_ml_dsa_87(),
            subject_public_key: BitString::from_bytes(subject_pubkey)
                .map_err(|e| sign_err("failed to encode subject public key", e))?,
        };

        let now = SystemTime::now();
        let validity = Validity {
            not_before: to_x509_time(now - CLOCK_SKEW_BACKDATE)?,
            not_after: to_x509_time(now + LEAF_VALIDITY)?,
        };

        // Exactly the classical hardening: CA:FALSE, digitalSignature,
        // clientAuth. No SANs, no custom extensions.
        let extensions = vec![
            make_extension(
                &BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                },
                true,
            )?,
            make_extension(&KeyUsage(KeyUsages::DigitalSignature.into()), true)?,
            make_extension(&ExtendedKeyUsage(vec![OID_CLIENT_AUTH]), false)?,
        ];

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: random_serial()?,
            signature: id_ml_dsa_87(),
            issuer: self.issuer_name.clone(),
            validity,
            subject: build_dn(cn, org)?,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };

        let tbs_der = tbs
            .to_der()
            .map_err(|e| sign_err("failed to DER-encode TBSCertificate", e))?;
        let sig = self.sign_bytes(&tbs_der)?;

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: id_ml_dsa_87(),
            signature: BitString::from_bytes(&sig)
                .map_err(|e| sign_err("failed to encode certificate signature", e))?,
        };

        cert.to_der()
            .map_err(|e| sign_err("failed to DER-encode certificate", e))
    }

    /// Issue an ML-DSA-87-signed X.509 CRL.
    ///
    /// Mirrors the semantics of the classical
    /// [`crate::revocation::RevocationStore`] CRL generation: a monotonic
    /// `crl_number` (id-ce-cRLNumber extension), `thisUpdate` / `nextUpdate`,
    /// and per-entry reason codes.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError::Signing`] for any encoding or signing
    /// failure, or a malformed serial number.
    pub fn issue_crl(
        &self,
        revoked: &[MlDsaRevokedCert],
        this_update: SystemTime,
        next_update: SystemTime,
        crl_number: u64,
    ) -> Result<Vec<u8>, EnrollmentError> {
        let revoked_certs = revoked
            .iter()
            .map(|entry| {
                let serial = SerialNumber::new(&entry.serial)
                    .map_err(|e| sign_err("invalid revoked-certificate serial", e))?;
                let crl_entry_extensions = entry
                    .reason
                    .map(|reason| make_extension(&reason, false))
                    .transpose()?
                    .map(|ext| vec![ext]);
                Ok(RevokedCert {
                    serial_number: serial,
                    revocation_date: to_x509_time(entry.revocation_time)?,
                    crl_entry_extensions,
                })
            })
            .collect::<Result<Vec<_>, EnrollmentError>>()?;

        let crl_number_ext = make_extension(
            &CrlNumber(
                Uint::new(&crl_number.to_be_bytes())
                    .map_err(|e| sign_err("failed to encode crlNumber", e))?,
            ),
            false,
        )?;

        let tbs = TbsCertList {
            version: Version::V2,
            signature: id_ml_dsa_87(),
            issuer: self.issuer_name.clone(),
            this_update: to_x509_time(this_update)?,
            next_update: Some(to_x509_time(next_update)?),
            revoked_certificates: if revoked_certs.is_empty() {
                None
            } else {
                Some(revoked_certs)
            },
            crl_extensions: Some(vec![crl_number_ext]),
        };

        let tbs_der = tbs
            .to_der()
            .map_err(|e| sign_err("failed to DER-encode TBSCertList", e))?;
        let sig = self.sign_bytes(&tbs_der)?;

        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: id_ml_dsa_87(),
            signature: BitString::from_bytes(&sig)
                .map_err(|e| sign_err("failed to encode CRL signature", e))?,
        };

        crl.to_der()
            .map_err(|e| sign_err("failed to DER-encode CRL", e))
    }
}

/// Map an encoding/signing error to [`EnrollmentError::Signing`] with context.
fn sign_err(context: &str, e: impl fmt::Display) -> EnrollmentError {
    EnrollmentError::Signing(format!("{context}: {e}"))
}

/// Build a distinguished name with `O` then `CN` relative distinguished names,
/// each carrying a UTF8String attribute value.
///
/// Building the RDNs programmatically (rather than from an RFC 4514 string)
/// avoids DN-injection when `cn` or `org` contain `,`, `=`, or other
/// escape-significant characters.
fn build_dn(cn: &str, org: &str) -> Result<Name, EnrollmentError> {
    let rdn = |oid: ObjectIdentifier,
               value: &str|
     -> Result<RelativeDistinguishedName, EnrollmentError> {
        let attr = AttributeTypeAndValue {
            oid,
            value: Any::encode_from(
                &Utf8StringRef::new(value)
                    .map_err(|e| sign_err("invalid distinguished-name value", e))?,
            )
            .map_err(|e| sign_err("failed to encode distinguished-name value", e))?,
        };
        let mut set = SetOfVec::new();
        set.insert(attr)
            .map_err(|e| sign_err("failed to build relative distinguished name", e))?;
        Ok(RelativeDistinguishedName(set))
    };

    Ok(RdnSequence(vec![
        rdn(OID_ORGANIZATION_NAME, org)?,
        rdn(OID_COMMON_NAME, cn)?,
    ]))
}

/// Build an X.509 [`Extension`] from a typed, OID-associated, DER-encodable
/// value.
fn make_extension<T>(value: &T, critical: bool) -> Result<Extension, EnrollmentError>
where
    T: Encode + AssociatedOid,
{
    let der = value
        .to_der()
        .map_err(|e| sign_err("failed to encode extension value", e))?;
    Ok(Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(der)
            .map_err(|e| sign_err("failed to wrap extension value", e))?,
    })
}

/// Convert a [`SystemTime`] to an X.509 [`Time`], choosing UTCTime for years
/// before 2050 and GeneralizedTime otherwise, per RFC 5280 §4.1.2.5.
fn to_x509_time(t: SystemTime) -> Result<Time, EnrollmentError> {
    let gt = GeneralizedTime::from_system_time(t).map_err(|e| sign_err("invalid time value", e))?;
    let dt = gt.to_date_time();
    if dt.year() < 2050 {
        let utc = UtcTime::from_date_time(dt).map_err(|e| sign_err("invalid UTCTime value", e))?;
        Ok(Time::UtcTime(utc))
    } else {
        Ok(Time::GeneralTime(gt))
    }
}

/// Generate a random, positive, ≤ 20-byte X.509 serial number.
///
/// The high bit of the first byte is cleared (so the DER integer stays
/// positive without a leading sign octet, keeping the encoding at 20 bytes)
/// and its high nibble is forced non-zero (so the value is never zero and has
/// no leading zero byte to strip).
fn random_serial() -> Result<SerialNumber, EnrollmentError> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes)
        .map_err(|_| EnrollmentError::Signing("failed to generate serial number".to_string()))?;
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    SerialNumber::new(&bytes).map_err(|e| sign_err("failed to build serial number", e))
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results
)]
mod tests {
    use x509_cert::request::CertReqInfo;

    use super::*;

    /// Generate an ML-DSA-87 CSR for `cn`, returning `(csr_der, pubkey_bytes)`.
    fn build_mldsa_csr(cn: &str) -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = ml_dsa_87::try_keygen().expect("keygen");
        let pk_bytes = pk.into_bytes();

        let spki = SubjectPublicKeyInfoOwned {
            algorithm: id_ml_dsa_87(),
            subject_public_key: BitString::from_bytes(&pk_bytes).expect("pk bitstring"),
        };
        let info = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: build_dn(cn, "CsrOrg").expect("dn"),
            public_key: spki,
            attributes: Default::default(),
        };
        let info_der = info.to_der().expect("info der");
        let sig = sk.try_sign(&info_der, &[]).expect("sign csr");
        let csr = CertReq {
            info,
            algorithm: id_ml_dsa_87(),
            signature: BitString::from_bytes(&sig).expect("sig bitstring"),
        };
        (csr.to_der().expect("csr der"), pk_bytes.to_vec())
    }

    /// Reconstruct a `fips204` public key from raw bytes.
    fn public_key_from_bytes(bytes: &[u8]) -> ml_dsa_87::PublicKey {
        let mut arr = [0u8; ml_dsa_87::PK_LEN];
        arr.copy_from_slice(bytes);
        ml_dsa_87::PublicKey::try_from_bytes(arr).expect("pk from bytes")
    }

    /// The RFC 9881 id-ml-dsa-87 OID string.
    const ML_DSA_87_OID_STR: &str = "2.16.840.1.101.3.4.3.19";

    #[test]
    fn oid_absent_parameters() {
        let alg = id_ml_dsa_87();
        assert_eq!(alg.oid.to_string(), ML_DSA_87_OID_STR);
        assert!(
            alg.parameters.is_none(),
            "RFC 9881 requires absent parameters for id-ml-dsa-87"
        );
    }

    /// CRITICAL correctness gate: full round-trip. Generate an ML-DSA CA,
    /// build an ML-DSA CSR, verify PoP, issue a leaf, re-parse it with
    /// `x509-parser`, and independently verify the certificate signature by
    /// re-signing-checking the TBS bytes against the CA public key with
    /// `fips204`. Also pins the signatureAlgorithm OID with absent params.
    #[test]
    fn issue_leaf_round_trip_independently_verifies() {
        let ca = rustgate_test_utils::mldsa::generate_mldsa_ca("Round Trip CA");
        let signer = MlDsaCa::from_der(ca.cert_der.clone(), ca.secret_key.clone())
            .expect("construct MlDsaCa");

        let (csr_der, csr_pk) = build_mldsa_csr("csr-subject-ignored");
        let verified_pk = MlDsaCa::verify_csr_pop(&csr_der).expect("PoP must verify");
        assert_eq!(
            verified_pk, csr_pk,
            "verify_csr_pop returns the CSR public key"
        );

        let leaf_der = signer
            .issue_leaf(&verified_pk, "authenticated-user", "IssuerOrg")
            .expect("issue leaf");

        // Re-parse with the independent x509-parser implementation.
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).expect("parse issued leaf");

        // signatureAlgorithm OID == id-ml-dsa-87, parameters absent.
        assert_eq!(
            leaf.signature_algorithm.algorithm.to_string(),
            ML_DSA_87_OID_STR
        );
        assert!(
            leaf.signature_algorithm.parameters.is_none(),
            "issued cert signatureAlgorithm must have absent parameters"
        );

        // Independently verify: extract the raw TBS bytes and the signature
        // from the x509-parser view (an independent DER implementation), then
        // verify against the CA public key with fips204.
        let tbs_raw = leaf.tbs_certificate.as_ref();
        let sig_raw: &[u8] = leaf.signature_value.data.as_ref();
        assert_eq!(
            sig_raw.len(),
            ml_dsa_87::SIG_LEN,
            "signature length must match ML-DSA-87"
        );
        let mut sig_arr = [0u8; ml_dsa_87::SIG_LEN];
        sig_arr.copy_from_slice(sig_raw);
        let ca_pk = public_key_from_bytes(&ca.public_key);
        assert!(
            ca_pk.verify(tbs_raw, &sig_arr, &[]),
            "independent fips204 verification of the leaf signature must pass"
        );

        // A single-bit flip in the TBS must break verification (sanity).
        let mut tampered = tbs_raw.to_vec();
        tampered[0] ^= 0x01;
        assert!(
            !ca_pk.verify(&tampered, &sig_arr, &[]),
            "tampered TBS must fail independent verification"
        );
    }

    #[test]
    fn issue_leaf_uses_authenticated_cn_and_no_sans() {
        let ca = rustgate_test_utils::mldsa::generate_mldsa_ca("CN Test CA");
        let signer = MlDsaCa::from_der(ca.cert_der, ca.secret_key).expect("construct MlDsaCa");

        let (csr_der, _) = build_mldsa_csr("attacker-cn");
        let pk = MlDsaCa::verify_csr_pop(&csr_der).expect("PoP");
        let leaf_der = signer
            .issue_leaf(&pk, "real-user", "RealOrg")
            .expect("issue");

        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).expect("parse");

        assert_eq!(
            leaf.subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok()),
            Some("real-user"),
            "CN must be the authenticated username, not the CSR subject"
        );
        assert_eq!(
            leaf.subject()
                .iter_organization()
                .next()
                .and_then(|o| o.as_str().ok()),
            Some("RealOrg")
        );
        assert!(
            leaf.subject_alternative_name()
                .expect("SAN parse")
                .is_none(),
            "issued leaf must carry no SANs"
        );
        let eku = leaf
            .extended_key_usage()
            .expect("EKU present")
            .expect("EKU parse");
        assert!(eku.value.client_auth, "leaf must have clientAuth EKU");
        assert!(!leaf.is_ca(), "leaf must be CA:FALSE");
    }

    #[test]
    fn verify_csr_pop_rejects_tampered_signature() {
        let (mut csr_der, _) = build_mldsa_csr("tamper");
        // Flip a bit deep in the signature region (the signature is the last
        // field of the CertReq DER).
        let last = csr_der.len() - 1;
        csr_der[last] ^= 0xff;
        assert!(
            MlDsaCa::verify_csr_pop(&csr_der).is_err(),
            "tampered PoP signature must be rejected"
        );
    }

    #[test]
    fn verify_csr_pop_rejects_mismatched_key() {
        // Build a CSR whose SPKI is key A but whose signature is over an info
        // signed by key B — a proof-of-possession mismatch.
        let (pk_a, _sk_a) = ml_dsa_87::try_keygen().expect("keygen a");
        let (_pk_b, sk_b) = ml_dsa_87::try_keygen().expect("keygen b");
        let pk_a_bytes = pk_a.into_bytes();

        let spki = SubjectPublicKeyInfoOwned {
            algorithm: id_ml_dsa_87(),
            subject_public_key: BitString::from_bytes(&pk_a_bytes).expect("bitstring"),
        };
        let info = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: build_dn("mismatch", "Org").expect("dn"),
            public_key: spki,
            attributes: Default::default(),
        };
        let info_der = info.to_der().expect("info der");
        // Sign with the WRONG key (sk_b) — does not match SPKI (pk_a).
        let sig = sk_b.try_sign(&info_der, &[]).expect("sign");
        let csr = CertReq {
            info,
            algorithm: id_ml_dsa_87(),
            signature: BitString::from_bytes(&sig).expect("sig"),
        };
        let csr_der = csr.to_der().expect("csr der");

        assert!(
            MlDsaCa::verify_csr_pop(&csr_der).is_err(),
            "mismatched-key CSR must be rejected"
        );
    }

    #[test]
    fn crl_round_trip_independently_verifies() {
        let ca = rustgate_test_utils::mldsa::generate_mldsa_ca("CRL CA");
        let signer = MlDsaCa::from_der(ca.cert_der, ca.secret_key).expect("construct MlDsaCa");

        let now = SystemTime::now();
        let next = now + Duration::from_secs(7 * 24 * 60 * 60);
        let revoked = [
            MlDsaRevokedCert {
                serial: vec![0x12, 0x34, 0x56],
                revocation_time: now,
                reason: Some(CrlReason::KeyCompromise),
            },
            MlDsaRevokedCert {
                serial: vec![0xab, 0xcd],
                revocation_time: now,
                reason: None,
            },
        ];

        let crl_der = signer
            .issue_crl(&revoked, now, next, 42)
            .expect("issue crl");

        // Re-parse with x509-parser and pin structural facts.
        let (_, crl) = x509_parser::parse_x509_crl(&crl_der).expect("parse crl");
        assert_eq!(
            crl.iter_revoked_certificates().count(),
            2,
            "both revoked entries must be present"
        );
        assert_eq!(
            crl.signature_algorithm.algorithm.to_string(),
            ML_DSA_87_OID_STR
        );

        // Independently verify the CRL signature against the CA public key.
        // Re-encode the parsed CertificateList to recover the exact TBS bytes.
        let list = CertificateList::from_der(&crl_der).expect("re-decode crl");
        let tbs_der = list.tbs_cert_list.to_der().expect("tbs der");
        let sig_bytes = list.signature.as_bytes().expect("crl signature bytes");
        assert_eq!(sig_bytes.len(), ml_dsa_87::SIG_LEN);
        let mut sig_arr = [0u8; ml_dsa_87::SIG_LEN];
        sig_arr.copy_from_slice(sig_bytes);
        let ca_pk = public_key_from_bytes(&ca.public_key);
        assert!(
            ca_pk.verify(&tbs_der, &sig_arr, &[]),
            "independent fips204 verification of the CRL signature must pass"
        );
    }

    #[test]
    fn crl_number_is_monotonic_in_output() {
        let ca = rustgate_test_utils::mldsa::generate_mldsa_ca("Monotonic CA");
        let signer = MlDsaCa::from_der(ca.cert_der, ca.secret_key).expect("construct MlDsaCa");
        let now = SystemTime::now();
        let next = now + Duration::from_secs(3600);

        let crl_low = signer.issue_crl(&[], now, next, 7).expect("crl 7");
        let crl_high = signer.issue_crl(&[], now, next, 8).expect("crl 8");

        let (_, low) = x509_parser::parse_x509_crl(&crl_low).expect("parse low");
        let (_, high) = x509_parser::parse_x509_crl(&crl_high).expect("parse high");

        let low_num = low.crl_number().expect("low CRL must carry a crlNumber");
        let high_num = high.crl_number().expect("high CRL must carry a crlNumber");
        assert!(
            high_num > low_num,
            "crlNumber must be monotonic across issued CRLs: {low_num} then {high_num}"
        );
    }

    #[test]
    fn from_der_rejects_wrong_secret_key_length() {
        let ca = rustgate_test_utils::mldsa::generate_mldsa_ca("Reject CA");
        let err = MlDsaCa::from_der(ca.cert_der, vec![0u8; 10])
            .expect_err("short secret key must be rejected");
        assert!(matches!(err, EnrollmentError::Config(_)));
    }
}
