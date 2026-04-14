// Copyright © 2026 Roberto Chiofalo.

//! Certificate pinning verifier for outbound TLS connections.
//!
//! Wraps the standard WebPKI verifier with an additional SHA-256 pin
//! check on the leaf certificate DER. This provides defense-in-depth
//! against CA compromise or mis-issuance — even if the certificate
//! chains to a trusted CA, it must also match a pre-configured pin.

use std::fmt;
use std::sync::Arc;

use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::error::HttpError;

/// A TLS certificate verifier that enforces SHA-256 certificate pins
/// in addition to standard WebPKI chain validation.
///
/// The inner verifier handles X.509 chain validation and revocation.
/// This wrapper adds a post-verification check that the leaf certificate's
/// DER-encoded SHA-256 hash matches at least one configured pin.
pub(crate) struct PinnedCertVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    /// SHA-256 hashes of acceptable leaf certificate DER encodings.
    pins: Vec<[u8; 32]>,
}

impl fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedCertVerifier")
            .field("pin_count", &self.pins.len())
            .finish_non_exhaustive()
    }
}

impl PinnedCertVerifier {
    /// Create a new pinning verifier wrapping the given inner verifier.
    pub(crate) fn new(inner: Arc<dyn ServerCertVerifier>, pins: Vec<[u8; 32]>) -> Self {
        Self { inner, pins }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // First: standard WebPKI chain validation
        let _ = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Second: SHA-256 pin check on the leaf certificate DER
        let cert_hash = Sha256::digest(end_entity.as_ref());
        let matches_pin = self
            .pins
            .iter()
            .any(|pin| pin.as_slice() == cert_hash.as_slice());

        if matches_pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "certificate pin mismatch: SHA-256 {} did not match any of {} configured pins",
                hex::encode(cert_hash),
                self.pins.len()
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Parse base64-encoded SHA-256 pins into raw 32-byte arrays.
pub(crate) fn parse_pins(pins: &[String]) -> Result<Vec<[u8; 32]>, HttpError> {
    let mut parsed = Vec::with_capacity(pins.len());
    for (i, pin) in pins.iter().enumerate() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(pin)
            .map_err(|e| HttpError::Config(format!("pin-sha256[{i}] is not valid base64: {e}")))?;
        let hash: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            HttpError::Config(format!(
                "pin-sha256[{i}] decoded to {} bytes, expected 32 (SHA-256)",
                v.len()
            ))
        })?;
        parsed.push(hash);
    }
    Ok(parsed)
}

/// Build a `rustls::RootCertStore` from PEM-encoded CA certificates.
pub(crate) fn build_root_store(ca_pem: &[u8]) -> Result<rustls::RootCertStore, HttpError> {
    let certs = parse_pem_certs(ca_pem);
    if certs.is_empty() {
        return Err(HttpError::Config(
            "no certificates found in CA PEM file".to_string(),
        ));
    }

    let mut store = rustls::RootCertStore::empty();
    for cert in certs {
        store.add(cert).map_err(|e| {
            HttpError::Config(format!("failed to add CA certificate to root store: {e}"))
        })?;
    }
    Ok(store)
}

/// Parse PEM-encoded certificates into DER `CertificateDer` values.
///
/// Handles multiple certificates in a single PEM file (certificate chains).
/// Returns an empty vec if no certificates are found.
pub(crate) fn parse_pem_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    let Ok(text) = std::str::from_utf8(pem) else {
        return Vec::new();
    };

    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64 = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64.clear();
        } else if trimmed == "-----END CERTIFICATE-----" {
            in_cert = false;
            if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&b64) {
                certs.push(CertificateDer::from(der));
            }
        } else if in_cert {
            b64.push_str(trimmed);
        }
    }
    certs
}

/// Parse a PEM-encoded private key into a `PrivateKeyDer`.
///
/// Supports RSA (PKCS#1), PKCS#8, and EC (SEC1) key formats.
pub(crate) fn parse_pem_private_key(
    pem: &[u8],
) -> Option<rustls::pki_types::PrivateKeyDer<'static>> {
    use zeroize::Zeroize;

    // Wrap text in Zeroizing — it contains the full PEM including key material
    let mut text = zeroize::Zeroizing::new(std::str::from_utf8(pem).ok()?.to_string());

    let markers: &[(&str, &str, &str)] = &[
        (
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            "rsa",
        ),
        (
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "pkcs8",
        ),
        (
            "-----BEGIN EC PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----",
            "ec",
        ),
    ];

    for &(begin_marker, end_marker, key_type) in markers {
        if let Some(start) = text.find(begin_marker) {
            let content = &text[start + begin_marker.len()..];
            if let Some(end_idx) = content.find(end_marker) {
                // Accumulate base64 in a zeroizable buffer
                let mut b64 = zeroize::Zeroizing::new(
                    content[..end_idx]
                        .lines()
                        .map(str::trim)
                        .collect::<String>(),
                );
                if let Ok(der_bytes) = base64::engine::general_purpose::STANDARD.decode(&*b64) {
                    // Wipe intermediate buffers immediately — don't wait for drop
                    b64.zeroize();
                    text.zeroize();

                    // Wrap decoded DER in Zeroizing, extract via take, convert
                    let mut der = zeroize::Zeroizing::new(der_bytes);
                    let raw = std::mem::take(&mut *der);
                    return Some(match key_type {
                        "rsa" => rustls::pki_types::PrivateKeyDer::Pkcs1(raw.into()),
                        "ec" => rustls::pki_types::PrivateKeyDer::Sec1(raw.into()),
                        _ => rustls::pki_types::PrivateKeyDer::Pkcs8(raw.into()),
                    });
                }
                b64.zeroize();
            }
        }
    }
    text.zeroize();
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parse_valid_base64_pins() {
        // Two valid 32-byte (SHA-256) pins
        let pin1 = base64::engine::general_purpose::STANDARD.encode([0xAA; 32]);
        let pin2 = base64::engine::general_purpose::STANDARD.encode([0xBB; 32]);
        let pins = parse_pins(&[pin1, pin2]).unwrap();
        assert_eq!(pins.len(), 2);
        assert_eq!(pins[0], [0xAA; 32]);
        assert_eq!(pins[1], [0xBB; 32]);
    }

    #[test]
    fn parse_pins_rejects_invalid_base64() {
        let err = parse_pins(&["not-valid!!!".to_string()]).unwrap_err();
        assert!(err.to_string().contains("not valid base64"), "got: {err}");
    }

    #[test]
    fn parse_pins_rejects_wrong_length() {
        // 16 bytes instead of 32
        let pin = base64::engine::general_purpose::STANDARD.encode([0xCC; 16]);
        let err = parse_pins(&[pin]).unwrap_err();
        assert!(err.to_string().contains("expected 32"), "got: {err}");
    }

    #[test]
    fn parse_pem_certs_extracts_certificate() {
        // Generate a self-signed cert using rustgate-test-utils would be ideal,
        // but for unit tests we just verify PEM parsing mechanics.
        let fake_der = [0x30, 0x82, 0x01, 0x00]; // Minimal ASN.1 SEQUENCE
        let b64 = base64::engine::general_purpose::STANDARD.encode(fake_der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        let certs = parse_pem_certs(pem.as_bytes());
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].as_ref(), &fake_der);
    }

    #[test]
    fn parse_pem_certs_handles_multiple() {
        let der1 = [0x01, 0x02, 0x03];
        let der2 = [0x04, 0x05, 0x06];
        let b64_1 = base64::engine::general_purpose::STANDARD.encode(der1);
        let b64_2 = base64::engine::general_purpose::STANDARD.encode(der2);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{b64_1}\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\n{b64_2}\n-----END CERTIFICATE-----\n"
        );
        let certs = parse_pem_certs(pem.as_bytes());
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn parse_pem_certs_empty_on_no_markers() {
        let certs = parse_pem_certs(b"no certificates here");
        assert!(certs.is_empty());
    }

    #[test]
    fn parse_pem_private_key_pkcs8() {
        let fake_der = [0x30, 0x82, 0x01, 0x00];
        let b64 = base64::engine::general_purpose::STANDARD.encode(fake_der);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");
        let key = parse_pem_private_key(pem.as_bytes());
        assert!(key.is_some());
        assert!(matches!(
            key.unwrap(),
            rustls::pki_types::PrivateKeyDer::Pkcs8(_)
        ));
    }

    #[test]
    fn parse_pem_private_key_rsa() {
        let fake_der = [0x30, 0x82, 0x01, 0x00];
        let b64 = base64::engine::general_purpose::STANDARD.encode(fake_der);
        let pem =
            format!("-----BEGIN RSA PRIVATE KEY-----\n{b64}\n-----END RSA PRIVATE KEY-----\n");
        let key = parse_pem_private_key(pem.as_bytes());
        assert!(key.is_some());
        assert!(matches!(
            key.unwrap(),
            rustls::pki_types::PrivateKeyDer::Pkcs1(_)
        ));
    }

    #[test]
    fn parse_pem_private_key_ec() {
        let fake_der = [0x30, 0x82, 0x01, 0x00];
        let b64 = base64::engine::general_purpose::STANDARD.encode(fake_der);
        let pem = format!("-----BEGIN EC PRIVATE KEY-----\n{b64}\n-----END EC PRIVATE KEY-----\n");
        let key = parse_pem_private_key(pem.as_bytes());
        assert!(key.is_some());
        assert!(matches!(
            key.unwrap(),
            rustls::pki_types::PrivateKeyDer::Sec1(_)
        ));
    }

    #[test]
    fn parse_pem_private_key_none_on_garbage() {
        assert!(parse_pem_private_key(b"not a key").is_none());
    }
}
