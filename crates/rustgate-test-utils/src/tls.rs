// Copyright © 2026 Roberto Chiofalo.

//! Shared TLS helpers for integration tests.
//!
//! Provides PEM parsing and `rustls::ClientConfig` construction so that
//! individual test crates do not each re-implement the same boilerplate.

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;

/// Parse PEM-encoded certificates into DER form.
pub fn parse_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse certs")
}

/// Parse a PEM-encoded private key into DER form.
pub fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).expect("parse key")
}

/// Build a `rustls::ClientConfig` for mTLS with the given client cert/key
/// and a CA certificate to trust.
pub fn build_client_tls_config(
    cert_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> rustls::ClientConfig {
    let certs = parse_certs(cert_pem);
    let key = parse_key(key_pem);
    let mut root_store = RootCertStore::empty();
    for cert in parse_certs(ca_pem) {
        root_store.add(cert).expect("add CA cert");
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("client config")
}
