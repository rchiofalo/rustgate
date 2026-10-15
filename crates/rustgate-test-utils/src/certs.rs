// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! X.509 certificate generation for tests.

use std::fmt;
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls_pki_types::pem::PemObject;
use time::{Duration as TimeDuration, OffsetDateTime};

/// Install a crypto provider once for the test process.
///
/// Uses `aws-lc-rs`, the workspace's only rustls provider. When FIPS mode is required, tests should call
/// `install_fips_provider()` from `rustgate-transport` *before*
/// creating any `TestCa` instances — the `let _ =` here silently
/// ignores the "already installed" error so FIPS tests work
/// correctly without conflict.
/// Global counter for CRL serial numbers, ensuring each generated CRL
/// receives a unique, incrementing serial number across all `TestCa` instances.
static CRL_SERIAL: AtomicU64 = AtomicU64::new(1);

static INIT_CRYPTO: Once = Once::new();
fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::aws_lc_rs::default_provider(),
        );
    });
}

/// Generate a fresh server key pair for use with
/// [`TestCa::issue_server_cert_with_key`].
///
/// Exposed so tests can model "same key, different certs" flows — in
/// particular the RFC 7469 SPKI-pinning regression test (issue #948),
/// where a reissued cert must still satisfy an existing pin.
pub fn generate_server_keypair() -> KeyPair {
    ensure_crypto_provider();
    KeyPair::generate().expect("failed to generate key pair")
}

/// Extract the serial number from a PEM-encoded certificate.
fn extract_serial_from_pem(pem: &str) -> SerialNumber {
    let cert_der = rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .expect("no certificate in PEM")
        .expect("failed to parse certificate PEM");

    let (_, cert) =
        x509_parser::parse_x509_certificate(cert_der.as_ref()).expect("failed to parse X.509");
    let serial_bytes = cert.tbs_certificate.serial.to_bytes_be();
    SerialNumber::from_slice(&serial_bytes)
}

/// A certificate authority for signing test certificates.
pub struct TestCa {
    pub cert_pem: String,
    pub key_pem: String,
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TestCa {
    /// Create a new test CA with the given common name.
    pub fn new(cn: &str) -> Self {
        ensure_crypto_provider();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let key_pem = key_pair.serialize_pem();
        let issuer = CertifiedIssuer::self_signed(params, key_pair).expect("failed to sign CA");

        Self {
            cert_pem: issuer.pem(),
            key_pem,
            issuer,
        }
    }

    /// Issue a server certificate with the given common name and SANs.
    pub fn issue_server_cert(&self, cn: &str, san_dns: &[&str]) -> TestCert {
        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        self.issue_server_cert_with_key(&key_pair, cn, san_dns)
    }

    /// Issue a server certificate reusing an existing key pair.
    ///
    /// Each call produces a cert with a fresh serial, validity window, and
    /// signature — the leaf DER bytes change — but the SPKI bytes stay
    /// identical because the public key comes from `key_pair`. This lets
    /// tests model the common DevOps pattern of annual cert rotation with
    /// long-lived key material, and is the cornerstone of the RFC 7469
    /// SPKI-pinning regression test (issue #948).
    pub fn issue_server_cert_with_key(
        &self,
        key_pair: &KeyPair,
        cn: &str,
        san_dns: &[&str],
    ) -> TestCert {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;

        params.subject_alt_names = san_dns
            .iter()
            .map(|s| rcgen::SanType::DnsName((*s).try_into().expect("invalid DNS name")))
            .collect();

        let cert = params
            .signed_by(key_pair, &self.issuer)
            .expect("failed to sign server cert");

        TestCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        }
    }

    /// Issue a client certificate with no CN — for testing error paths.
    pub fn issue_client_cert_no_cn(&self) -> TestCert {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);

        // Empty DN — no CN
        params.distinguished_name = DistinguishedName::new();

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .expect("failed to sign client cert");

        TestCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        }
    }

    /// Issue an already-expired client certificate for testing rejection paths.
    ///
    /// The certificate's validity window is entirely in the past (30 days ago
    /// to 1 day ago), so TLS handshake validation will reject it.
    pub fn issue_expired_client_cert(&self, cn: &str, groups: &[&str]) -> TestCert {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        if !groups.is_empty() {
            dn.push(DnType::OrganizationalUnitName, groups.join(","));
        }
        params.distinguished_name = dn;

        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::days(30);
        params.not_after = now - TimeDuration::days(1);

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .expect("failed to sign expired client cert");

        TestCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        }
    }

    /// Issue a server certificate that expires in `days_remaining` days.
    ///
    /// Useful for testing the "degraded" health check threshold (e.g. a cert
    /// expiring within 7 days should trigger a degraded status).
    pub fn issue_near_expiry_server_cert(
        &self,
        cn: &str,
        san_dns: &[&str],
        days_remaining: i64,
    ) -> TestCert {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;

        params.subject_alt_names = san_dns
            .iter()
            .map(|s| rcgen::SanType::DnsName((*s).try_into().expect("invalid DNS name")))
            .collect();

        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::days(1);
        params.not_after = now + TimeDuration::days(days_remaining);

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .expect("failed to sign near-expiry server cert");

        TestCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        }
    }

    /// Generate a Certificate Revocation List (CRL) revoking the given certificates.
    ///
    /// Parses each PEM to extract its serial number, builds a CRL signed by
    /// this CA, and returns the CRL in PEM format. The CRL is valid for 30 days.
    pub fn generate_crl(&self, revoked_cert_pems: &[&str]) -> String {
        let revoked_certs: Vec<RevokedCertParams> = revoked_cert_pems
            .iter()
            .map(|pem| {
                let serial = extract_serial_from_pem(pem);
                RevokedCertParams {
                    serial_number: serial,
                    revocation_time: OffsetDateTime::now_utc(),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                }
            })
            .collect();

        let now = OffsetDateTime::now_utc();
        let crl_params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + TimeDuration::days(30),
            crl_number: SerialNumber::from(CRL_SERIAL.fetch_add(1, Ordering::Relaxed)),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };

        let crl = crl_params
            .signed_by(&self.issuer)
            .expect("failed to sign CRL");
        crl.pem().expect("failed to encode CRL as PEM")
    }

    /// Issue a certificate with only `ServerAuth` EKU and no SANs.
    ///
    /// Useful for testing that a server-only certificate is rejected when
    /// presented as a client certificate during mTLS.
    pub fn issue_server_auth_only_cert(&self, cn: &str) -> TestCert {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .expect("failed to sign server-auth-only cert");

        TestCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        }
    }

    /// Generate an already-expired CRL for testing stale CRL detection.
    ///
    /// The CRL's `thisUpdate` and `nextUpdate` are both in the past,
    /// simulating a CRL that should have been refreshed.
    pub fn generate_expired_crl(&self, revoked_cert_pems: &[&str]) -> String {
        let revoked_certs: Vec<RevokedCertParams> = revoked_cert_pems
            .iter()
            .map(|pem| {
                let serial = extract_serial_from_pem(pem);
                RevokedCertParams {
                    serial_number: serial,
                    revocation_time: OffsetDateTime::now_utc() - TimeDuration::days(60),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                }
            })
            .collect();

        let now = OffsetDateTime::now_utc();
        let crl_params = CertificateRevocationListParams {
            this_update: now - TimeDuration::days(60),
            next_update: now - TimeDuration::days(30),
            crl_number: SerialNumber::from(CRL_SERIAL.fetch_add(1, Ordering::Relaxed)),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };

        let crl = crl_params
            .signed_by(&self.issuer)
            .expect("failed to sign expired CRL");
        crl.pem().expect("failed to encode expired CRL as PEM")
    }

    /// Issue a client certificate with rich subject and SAN fields for
    /// testing the ABAC attribute extraction pipeline.
    ///
    /// Populates:
    /// - Subject CN, OU (joined groups), O, and C (if `country` is set)
    /// - URI SANs (including a `spiffe://` entry when `spiffe_id` is set)
    /// - DNS SANs from `san_dns`
    /// - Email (RFC822) SANs from `san_email`
    #[allow(clippy::too_many_arguments)]
    pub fn issue_client_cert_with_attrs(
        &self,
        cn: &str,
        groups: &[&str],
        spiffe_id: Option<&str>,
        organization: Option<&str>,
        country: Option<&str>,
        san_dns: &[&str],
        san_email: &[&str],
    ) -> TestCert {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        if !groups.is_empty() {
            dn.push(DnType::OrganizationalUnitName, groups.join(","));
        }
        if let Some(org) = organization {
            dn.push(DnType::OrganizationName, org);
        }
        if let Some(c) = country {
            dn.push(DnType::CountryName, c);
        }
        params.distinguished_name = dn;

        let mut sans: Vec<rcgen::SanType> = Vec::new();
        if let Some(spiffe) = spiffe_id {
            sans.push(rcgen::SanType::URI(
                spiffe.try_into().expect("invalid spiffe URI"),
            ));
        }
        for dns in san_dns {
            sans.push(rcgen::SanType::DnsName(
                (*dns).try_into().expect("invalid DNS name"),
            ));
        }
        for email in san_email {
            sans.push(rcgen::SanType::Rfc822Name(
                (*email).try_into().expect("invalid email SAN"),
            ));
        }
        params.subject_alt_names = sans;

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .expect("failed to sign client cert");

        TestCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        }
    }

    /// Issue a client certificate that expires `seconds_remaining` seconds
    /// from now.
    ///
    /// Useful for negative integration tests that need to drive a real
    /// mTLS handshake with a cert that will expire mid-session, so the
    /// test can pin whatever the current expiry-mid-session policy is
    /// (fail-closed via cert-reloader, or grandfathered until handshake
    /// renegotiation, or anywhere in between). Refs #789 / F-134.
    pub fn issue_near_expiry_client_cert(
        &self,
        cn: &str,
        groups: &[&str],
        seconds_remaining: i64,
    ) -> TestCert {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        if !groups.is_empty() {
            dn.push(DnType::OrganizationalUnitName, groups.join(","));
        }
        params.distinguished_name = dn;

        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::minutes(1);
        params.not_after = now + TimeDuration::seconds(seconds_remaining);

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .expect("failed to sign near-expiry client cert");

        TestCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        }
    }

    /// Issue a client certificate with the given CN and OU fields.
    ///
    /// CN becomes the user identity, OU fields become group memberships.
    /// Groups are stored as comma-separated values in a single OU field
    /// due to rcgen limitations with multiple OU entries.
    pub fn issue_client_cert(&self, cn: &str, groups: &[&str]) -> TestCert {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        if !groups.is_empty() {
            // Join groups with comma since rcgen doesn't support multiple OU entries
            dn.push(DnType::OrganizationalUnitName, groups.join(","));
        }
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .expect("failed to sign client cert");

        TestCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        }
    }
}

impl fmt::Debug for TestCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestCa")
            .field("cert_pem", &"<certificate>")
            .field("key_pem", &"<private key>")
            .finish()
    }
}

/// A generated certificate with its private key.
#[derive(Debug)]
pub struct TestCert {
    pub cert_pem: String,
    pub key_pem: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn successive_crls_get_different_serial_numbers() {
        let ca = TestCa::new("test-crl-serial-ca");
        let client = ca.issue_client_cert("user1", &[]);

        let crl1 = ca.generate_crl(&[&client.cert_pem]);
        let crl2 = ca.generate_crl(&[&client.cert_pem]);

        // The DER encoding includes the CRL number, so different serial
        // numbers produce different DER (and thus PEM) output.
        let crl1_der = pem_to_der(&crl1);
        let crl2_der = pem_to_der(&crl2);
        assert_ne!(
            crl1_der, crl2_der,
            "successive CRLs must differ (different serial numbers)"
        );
    }

    /// Decode PEM-encoded CRL to DER bytes.
    fn pem_to_der(pem: &str) -> Vec<u8> {
        rustls_pki_types::CertificateRevocationListDer::pem_slice_iter(pem.as_bytes())
            .next()
            .expect("no CRL in PEM")
            .expect("failed to parse CRL PEM")
            .to_vec()
    }
}
