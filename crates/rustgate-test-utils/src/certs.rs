//! X.509 certificate generation for tests.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::fmt;

/// A certificate authority for signing test certificates.
pub struct TestCa {
    pub cert_pem: String,
    pub key_pem: String,
    cert: Certificate,
    key_pair: KeyPair,
}

impl TestCa {
    /// Create a new test CA with the given common name.
    pub fn new(cn: &str) -> Self {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let cert = params.self_signed(&key_pair).expect("failed to sign CA");

        Self {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            cert,
            key_pair,
        }
    }

    /// Issue a server certificate with the given common name and SANs.
    pub fn issue_server_cert(&self, cn: &str, san_dns: &[&str]) -> TestCert {
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

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let cert = params
            .signed_by(&key_pair, &self.cert, &self.key_pair)
            .expect("failed to sign server cert");

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
            .signed_by(&key_pair, &self.cert, &self.key_pair)
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
