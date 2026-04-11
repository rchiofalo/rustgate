// Copyright © 2026 Roberto Chiofalo.

//! Shared PEM parsing utilities for certificates, private keys, and CA stores.
//!
//! These functions consolidate duplicated PEM parsing logic used across
//! the transport and federation crates. They return [`RustgateError`] so
//! both direct users and anyhow-based callers can consume them via `?`.

use rustgate_core::error::{ConfigError, Result, RustgateError};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;

/// Parse PEM-encoded certificates into DER form.
///
/// Returns an error if the PEM data is invalid or contains no certificates.
pub fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            RustgateError::from(ConfigError::PemParse {
                kind: "certificate".to_string(),
                reason: e.to_string(),
            })
        })?;

    if certs.is_empty() {
        return Err(ConfigError::EmptyPem {
            kind: "certificates".to_string(),
        }
        .into());
    }

    Ok(certs)
}

/// Parse a PEM-encoded private key into DER form.
///
/// Accepts PKCS#8, PKCS#1 (RSA), and SEC1 (EC) key formats.
pub fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| {
        RustgateError::from(ConfigError::PemParse {
            kind: "private key".to_string(),
            reason: e.to_string(),
        })
    })
}

/// Parse PEM-encoded CA certificates and build a [`RootCertStore`].
///
/// Returns an error if the PEM data is invalid, contains no certificates,
/// or if any certificate cannot be added to the store.
pub fn parse_ca_store(pem: &str) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            RustgateError::from(ConfigError::PemParse {
                kind: "CA certificate".to_string(),
                reason: e.to_string(),
            })
        })?;

    if certs.is_empty() {
        return Err(ConfigError::EmptyPem {
            kind: "CA certificates".to_string(),
        }
        .into());
    }

    for cert in certs {
        store.add(cert).map_err(|e| {
            RustgateError::from(ConfigError::Other(format!(
                "failed to add CA certificate: {e}"
            )))
        })?;
    }

    Ok(store)
}
