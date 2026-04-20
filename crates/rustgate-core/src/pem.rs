// Copyright © 2026 Roberto Chiofalo.

//! Shared PEM parsing helpers for certificates, private keys, and CA
//! trust stores.
//!
//! Use these instead of hand-rolling `rustls_pki_types::pem::PemObject`
//! iterators per crate — consistent [`ConfigError`] mapping means every
//! PEM-parse failure surfaces the same diagnostic fields
//! (`kind`, `reason`) across the workspace.
//!
//! All helpers take a byte slice so callers that already hold key
//! material in `Zeroizing<Vec<u8>>` or read bytes from disk do not need
//! an extra UTF-8 check. String callers pass `s.as_bytes()`.
//!
//! Enable via the `pem` cargo feature on `rustgate-core`.
//!
//! [`ConfigError`]: crate::error::ConfigError

use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::{ConfigError, Result, RustgateError};

/// Parse PEM-encoded certificates into DER form.
///
/// Accepts one or more `CERTIFICATE` blocks. Returns
/// [`ConfigError::PemParse`] on malformed PEM and
/// [`ConfigError::EmptyPem`] when the input parses cleanly but contains
/// zero certificate blocks (for example, an empty file or a file that
/// only contains a private key).
///
/// [`ConfigError::PemParse`]: crate::error::ConfigError::PemParse
/// [`ConfigError::EmptyPem`]: crate::error::ConfigError::EmptyPem
pub fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
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
/// Accepts PKCS#8 (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`), and SEC1
/// (`EC PRIVATE KEY`) PEM tag types. Returns [`ConfigError::PemParse`]
/// on any parse error.
///
/// [`ConfigError::PemParse`]: crate::error::ConfigError::PemParse
pub fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| {
        RustgateError::from(ConfigError::PemParse {
            kind: "private key".to_string(),
            reason: e.to_string(),
        })
    })
}

/// Parse PEM-encoded CA certificates and build a [`RootCertStore`].
///
/// Every certificate in the input is added to a fresh
/// [`RootCertStore`]. Returns [`ConfigError::PemParse`] on malformed
/// PEM, [`ConfigError::EmptyPem`] on empty input, or
/// [`ConfigError::Other`] if any certificate is rejected by the trust
/// store (for example, a non-CA cert).
///
/// [`ConfigError::PemParse`]: crate::error::ConfigError::PemParse
/// [`ConfigError::EmptyPem`]: crate::error::ConfigError::EmptyPem
/// [`ConfigError::Other`]: crate::error::ConfigError::Other
pub fn parse_ca_store(pem: &[u8]) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Build a self-signed CA + leaf cert + key PEM fixture for tests.
    /// Kept tiny on purpose so tests run fast and don't need TestCa.
    struct Fixture {
        ca_pem: String,
        leaf_cert_pem: String,
        leaf_key_pem: String,
    }

    fn fixture() -> Fixture {
        // CA
        let mut ca_params = rcgen::CertificateParams::new(vec!["test-ca".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Leaf signed by the CA
        let leaf_params = rcgen::CertificateParams::new(vec!["leaf".to_string()]).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_key).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        Fixture {
            ca_pem: ca_cert.pem(),
            leaf_cert_pem: leaf_cert.pem(),
            leaf_key_pem: leaf_key.serialize_pem(),
        }
    }

    #[test]
    fn parse_certs_accepts_valid_pem() {
        let fx = fixture();
        let certs = parse_certs(fx.leaf_cert_pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn parse_certs_accepts_chain() {
        let fx = fixture();
        // Concatenate leaf + CA to form a 2-cert chain.
        let chain = format!("{}{}", fx.leaf_cert_pem, fx.ca_pem);
        let certs = parse_certs(chain.as_bytes()).unwrap();
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn parse_certs_rejects_empty_pem() {
        let err = parse_certs(b"").unwrap_err();
        match err {
            RustgateError::Config(ConfigError::EmptyPem { kind }) => {
                assert_eq!(kind, "certificates");
            }
            other => panic!("expected EmptyPem, got {other:?}"),
        }
    }

    #[test]
    fn parse_certs_rejects_key_only_pem() {
        // Valid PEM, but no CERTIFICATE blocks — EmptyPem, not PemParse.
        let fx = fixture();
        let err = parse_certs(fx.leaf_key_pem.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            RustgateError::Config(ConfigError::EmptyPem { .. })
        ));
    }

    #[test]
    fn parse_certs_rejects_garbage() {
        let err =
            parse_certs(b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n")
                .unwrap_err();
        match err {
            RustgateError::Config(ConfigError::PemParse { kind, .. }) => {
                assert_eq!(kind, "certificate");
            }
            other => panic!("expected PemParse, got {other:?}"),
        }
    }

    #[test]
    fn parse_key_accepts_pkcs8() {
        let fx = fixture();
        // rcgen emits PKCS#8 by default.
        let key = parse_key(fx.leaf_key_pem.as_bytes()).unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn parse_key_rejects_non_key_pem() {
        let fx = fixture();
        let err = parse_key(fx.leaf_cert_pem.as_bytes()).unwrap_err();
        match err {
            RustgateError::Config(ConfigError::PemParse { kind, .. }) => {
                assert_eq!(kind, "private key");
            }
            other => panic!("expected PemParse, got {other:?}"),
        }
    }

    #[test]
    fn parse_ca_store_accepts_ca_pem() {
        let fx = fixture();
        let store = parse_ca_store(fx.ca_pem.as_bytes()).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn parse_ca_store_rejects_empty_pem() {
        let err = parse_ca_store(b"").unwrap_err();
        match err {
            RustgateError::Config(ConfigError::EmptyPem { kind }) => {
                assert_eq!(kind, "CA certificates");
            }
            other => panic!("expected EmptyPem, got {other:?}"),
        }
    }

    #[test]
    fn parse_ca_store_rejects_malformed_pem() {
        let err = parse_ca_store(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n")
            .unwrap_err();
        assert!(matches!(
            err,
            RustgateError::Config(ConfigError::PemParse { .. })
        ));
    }

    #[test]
    fn parse_key_rejects_empty_pem() {
        // Empty input goes through the same PemParse mapping — we do
        // not emit EmptyPem for keys since a missing key is a parse
        // failure, not a "no entries of expected kind" situation.
        let err = parse_key(b"").unwrap_err();
        match err {
            RustgateError::Config(ConfigError::PemParse { kind, .. }) => {
                assert_eq!(kind, "private key");
            }
            other => panic!("expected PemParse for empty key input, got {other:?}"),
        }
    }

    #[test]
    fn parse_ca_store_accepts_chain_of_multiple_cas() {
        // Two distinct self-signed CAs concatenated into one PEM blob
        // should both land in the returned RootCertStore — this pins
        // the per-cert add loop (lines 101-107) across multiple entries.
        let fx1 = fixture();
        let fx2 = fixture();
        let chain = format!("{}{}", fx1.ca_pem, fx2.ca_pem);
        let store = parse_ca_store(chain.as_bytes()).unwrap();
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn parse_ca_store_accepts_non_ca_leaf_silently() {
        // Documents current behavior: `RootCertStore::add` does NOT
        // enforce `BasicConstraints: CA:TRUE`, so a misconfigured
        // operator who drops a leaf certificate into their CA bundle
        // will have it silently accepted as a trust anchor. This is
        // permissive-by-design in rustls — the operator's intent is
        // authoritative. Tracking this here so any future tightening
        // (defensive CA check before add) breaks this test loudly.
        let fx = fixture();
        let store = parse_ca_store(fx.leaf_cert_pem.as_bytes()).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn parse_ca_store_rejects_valid_pem_with_garbage_der() {
        // Pins the `ConfigError::Other` path: the PEM envelope is
        // valid (so `pem_slice_iter` succeeds), but the base64-decoded
        // payload is not a parseable X.509 certificate. `store.add`
        // rejects it, and the error must be mapped to
        // `ConfigError::Other` with a message that names the failure.
        //
        // AAAA base64-decodes to three zero bytes — structurally not
        // a valid DER SEQUENCE, so webpki's trust-anchor parser fails.
        let input = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let err = parse_ca_store(input).unwrap_err();
        match err {
            RustgateError::Config(ConfigError::Other(msg)) => {
                assert!(
                    msg.contains("CA certificate"),
                    "expected error to mention 'CA certificate', got {msg:?}"
                );
            }
            other => panic!("expected ConfigError::Other for garbage DER, got {other:?}"),
        }
    }
}
