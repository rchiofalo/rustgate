// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Self-signed ML-DSA-87 CA generation for tests.
//!
//! Produces a pure ML-DSA-87 (RFC 9881) self-signed CA certificate plus the
//! `fips204` key material, so tests exercising
//! `rustgate_enrollment::mldsa::MlDsaCa` (and the ML-DSA TLS-verify path,
//! #501) can drive real issuance without a live CA.
//!
//! This mirrors — deliberately independently of — the production assembly in
//! `rustgate-enrollment`, since `rustgate-test-utils` cannot depend on the
//! enrollment crate (that would be a dependency cycle).

use der::asn1::{BitString, GeneralizedTime, OctetString, SetOfVec, UtcTime, Utf8StringRef};
use der::oid::{AssociatedOid, ObjectIdentifier};
use der::{Any, Encode};
use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

const OID_ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_EKU_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const OID_EKU_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// A self-signed ML-DSA-87 test CA: certificate DER and raw `fips204` key
/// material.
#[derive(Debug, Clone)]
pub struct MlDsaTestCa {
    /// The self-signed CA certificate, DER-encoded.
    pub cert_der: Vec<u8>,
    /// The serialized `fips204` ML-DSA-87 secret key (`SK_LEN` bytes).
    pub secret_key: Vec<u8>,
    /// The serialized `fips204` ML-DSA-87 public key (`PK_LEN` bytes).
    pub public_key: Vec<u8>,
}

/// Generate a self-signed ML-DSA-87 CA certificate with the given Common Name.
///
/// # Panics
///
/// Panics on any key-generation or DER-encoding failure — appropriate for a
/// test helper.
#[must_use]
pub fn generate_mldsa_ca(cn: &str) -> MlDsaTestCa {
    let (pk, sk) = ml_dsa_87::try_keygen().expect("ML-DSA-87 keygen");
    let pk_bytes = pk.into_bytes();

    let alg = || AlgorithmIdentifierOwned {
        oid: OID_ML_DSA_87,
        parameters: None,
    };

    let name = self_signed_name(cn);

    let spki = SubjectPublicKeyInfoOwned {
        algorithm: alg(),
        subject_public_key: BitString::from_bytes(&pk_bytes).expect("pk bitstring"),
    };

    let now = std::time::SystemTime::now();
    let validity = Validity {
        not_before: to_time(now - std::time::Duration::from_secs(300)),
        not_after: to_time(now + std::time::Duration::from_secs(3650 * 24 * 60 * 60)),
    };

    let extensions = vec![
        extension(
            &BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
            true,
        ),
        extension(&KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign), true),
    ];

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[0x01]).expect("serial"),
        signature: alg(),
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    let tbs_der = tbs.to_der().expect("tbs der");
    let sig = sk.try_sign(&tbs_der, &[]).expect("self-sign CA");

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: alg(),
        signature: BitString::from_bytes(&sig).expect("sig bitstring"),
    };

    MlDsaTestCa {
        cert_der: cert.to_der().expect("cert der"),
        secret_key: sk.into_bytes().to_vec(),
        public_key: pk_bytes.to_vec(),
    }
}

/// Issue an end-entity certificate signed by an [`MlDsaTestCa`], carrying a
/// caller-supplied `SubjectPublicKeyInfo`.
///
/// The SPKI is passed through verbatim, so the leaf's own key may be *any*
/// algorithm — in particular a classical ECDSA key. That combination
/// (ML-DSA-87 issuer, classical leaf) is the one the ML-DSA TLS
/// certificate-verification path (#501) needs to exercise, and it is the
/// realistic CNSA 2.0 migration shape: a long-lived post-quantum root signing
/// short-lived classical leaves.
///
/// Deliberately not available on `rustgate_enrollment::mldsa::MlDsaCa`, whose
/// `issue_leaf` hardcodes an ML-DSA-87 SPKI on purpose — this is a test-only
/// affordance and must not widen the production issuance API.
///
/// `spki_der` must be a DER-encoded `SubjectPublicKeyInfo` (the exact bytes
/// `rcgen`'s `PublicKeyData::subject_public_key_info` or an X.509 parser
/// yields).
///
/// # Panics
///
/// Panics on malformed SPKI DER or any encoding failure — appropriate for a
/// test helper.
#[must_use]
pub fn issue_leaf_with_spki(ca: &MlDsaTestCa, spki_der: &[u8], cn: &str) -> Vec<u8> {
    use der::Decode;

    let sk = ml_dsa_87::PrivateKey::try_from_bytes(
        ca.secret_key
            .clone()
            .try_into()
            .expect("CA secret key length"),
    )
    .expect("CA secret key");

    let alg = || AlgorithmIdentifierOwned {
        oid: OID_ML_DSA_87,
        parameters: None,
    };

    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der).expect("leaf spki der");

    // Issuer must match the CA's subject byte-for-byte or path building fails.
    let issuer = Certificate::from_der(&ca.cert_der)
        .expect("ca cert der")
        .tbs_certificate
        .subject;

    let now = std::time::SystemTime::now();
    let validity = Validity {
        not_before: to_time(now - std::time::Duration::from_secs(300)),
        not_after: to_time(now + std::time::Duration::from_secs(365 * 24 * 60 * 60)),
    };

    let extensions = vec![
        extension(
            &BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
            true,
        ),
        extension(
            &KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment),
            true,
        ),
        extension(
            &ExtendedKeyUsage(vec![OID_EKU_CLIENT_AUTH, OID_EKU_SERVER_AUTH]),
            false,
        ),
    ];

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[0x02]).expect("serial"),
        // The algorithm the ISSUER signs with — ML-DSA-87 — independent of the
        // leaf's own key algorithm carried in `subject_public_key_info`.
        signature: alg(),
        issuer,
        validity,
        subject: self_signed_name(cn),
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    let tbs_der = tbs.to_der().expect("tbs der");
    let sig = sk.try_sign(&tbs_der, &[]).expect("CA signs leaf");

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: alg(),
        signature: BitString::from_bytes(&sig).expect("sig bitstring"),
    };

    cert.to_der().expect("cert der")
}

fn self_signed_name(cn: &str) -> Name {
    let attr = AttributeTypeAndValue {
        oid: OID_COMMON_NAME,
        value: Any::encode_from(&Utf8StringRef::new(cn).expect("cn utf8")).expect("cn any"),
    };
    let mut set = SetOfVec::new();
    set.insert(attr).expect("rdn set");
    RdnSequence(vec![RelativeDistinguishedName(set)])
}

fn extension<T>(value: &T, critical: bool) -> Extension
where
    T: Encode + AssociatedOid,
{
    Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(value.to_der().expect("ext der")).expect("ext octets"),
    }
}

fn to_time(t: std::time::SystemTime) -> Time {
    let gt = GeneralizedTime::from_system_time(t).expect("generalized time");
    let dt = gt.to_date_time();
    if dt.year() < 2050 {
        Time::UtcTime(UtcTime::from_date_time(dt).expect("utc time"))
    } else {
        Time::GeneralTime(gt)
    }
}
