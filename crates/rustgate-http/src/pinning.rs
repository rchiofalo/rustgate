// Copyright © 2026 Roberto Chiofalo.

//! Certificate pinning verifier for outbound TLS connections.
//!
//! Wraps the standard WebPKI verifier with an additional SHA-256 pin
//! check on the leaf certificate's **SubjectPublicKeyInfo (SPKI)** per
//! [RFC 7469]. This provides defense-in-depth against CA compromise or
//! mis-issuance — even if the certificate chains to a trusted CA, its
//! public key must also match a pre-configured pin.
//!
//! ## Semantic
//!
//! Each pin is `SHA-256(subjectPublicKeyInfo DER)`, not a hash of the
//! whole certificate. This matches the RFC 7469 / HPKP / Chromium /
//! Mozilla / OpenSSL convention and the pin produced by the standard
//! OpenSSL recipe:
//!
//! ```text
//! openssl x509 -in server.pem -pubkey -noout \
//!   | openssl pkey -pubin -outform der \
//!   | openssl dgst -sha256 -binary \
//!   | base64
//! ```
//!
//! ## Breaking change vs pre-#948 behaviour
//!
//! Earlier builds hashed the full leaf certificate DER, so a same-key
//! reissue (new serial/validity/SANs) broke the pin and forced a config
//! change. SPKI pinning now lets rotation-with-key-reuse pass without a
//! config change — the common DevOps practice of annual cert rotation
//! with long-lived key material no longer invalidates every deployed
//! pin. Operators who held full-DER pins from a previous deployment
//! must regenerate them with the OpenSSL recipe above.
//!
//! [RFC 7469]: https://datatracker.ietf.org/doc/html/rfc7469

use std::fmt;
use std::sync::Arc;

use rustgate_core::b64;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::error::HttpError;

/// A TLS certificate verifier that enforces SHA-256 certificate pins
/// in addition to standard WebPKI chain validation.
///
/// The inner verifier handles X.509 chain validation and revocation.
/// This wrapper adds a post-verification check that the SHA-256 hash
/// of the leaf certificate's SubjectPublicKeyInfo (SPKI) matches at
/// least one configured pin — the RFC 7469 convention.
pub(crate) struct PinnedCertVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    /// SHA-256 hashes of acceptable leaf-certificate SPKI DER encodings.
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

        // Second: SHA-256 pin check on the leaf certificate's SPKI
        // (RFC 7469). Pinning the SPKI rather than the full DER lets a
        // same-key reissue (new serial, new validity window, new SAN
        // list) match an existing pin — aligning with standard HPKP
        // tooling and avoiding a forced config change on every cert
        // rotation that preserves the key.
        let spki = extract_spki_der(end_entity)?;
        let spki_hash = Sha256::digest(spki);
        let matches_pin = self
            .pins
            .iter()
            .any(|pin| pin.as_slice() == spki_hash.as_slice());

        if matches_pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "certificate SPKI pin mismatch: SHA-256 {} did not match any of {} configured pins",
                hex::encode(spki_hash),
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

/// Extract the raw DER bytes of a leaf certificate's `SubjectPublicKeyInfo`
/// (SPKI) for RFC 7469 pin computation.
///
/// Returns a borrow of the bytes inside the certificate — no allocation
/// or copy. A parse failure here is surfaced as a rustls
/// [`TlsError::General`] so the rustls handshake path fails closed with
/// a descriptive error rather than silently admitting the connection.
fn extract_spki_der<'a>(cert: &'a CertificateDer<'_>) -> Result<&'a [u8], TlsError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| TlsError::General(format!("certificate SPKI extraction failed: {e}")))?;
    Ok(parsed.tbs_certificate.subject_pki.raw)
}

/// Compute the pin bytes for a leaf certificate. Shared between the
/// verifier hot path (via `extract_spki_der`) and test helpers that need
/// to produce pins from issued test certs.
#[cfg(test)]
pub(crate) fn spki_pin(cert: &CertificateDer<'_>) -> [u8; 32] {
    let spki = extract_spki_der(cert).expect("test cert must be parseable");
    Sha256::digest(spki).into()
}

/// Parse base64-encoded SHA-256 pins into raw 32-byte arrays.
pub(crate) fn parse_pins(pins: &[String]) -> Result<Vec<[u8; 32]>, HttpError> {
    let mut parsed = Vec::with_capacity(pins.len());
    for (i, pin) in pins.iter().enumerate() {
        let bytes = b64::decode(pin)
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
    let mut encoded = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            encoded.clear();
        } else if trimmed == "-----END CERTIFICATE-----" {
            in_cert = false;
            if let Ok(der) = b64::decode(&encoded) {
                certs.push(CertificateDer::from(der));
            }
        } else if in_cert {
            encoded.push_str(trimmed);
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
                let mut encoded = zeroize::Zeroizing::new(
                    content[..end_idx]
                        .lines()
                        .map(str::trim)
                        .collect::<String>(),
                );
                if let Ok(der_bytes) = b64::decode(&*encoded) {
                    // Wipe intermediate buffers immediately — don't wait for drop
                    encoded.zeroize();
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
                encoded.zeroize();
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
        let pin1 = b64::encode([0xAA; 32]);
        let pin2 = b64::encode([0xBB; 32]);
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
        let pin = b64::encode([0xCC; 16]);
        let err = parse_pins(&[pin]).unwrap_err();
        assert!(err.to_string().contains("expected 32"), "got: {err}");
    }

    #[test]
    fn parse_pem_certs_extracts_certificate() {
        // Generate a self-signed cert using rustgate-test-utils would be ideal,
        // but for unit tests we just verify PEM parsing mechanics.
        let fake_der = [0x30, 0x82, 0x01, 0x00]; // Minimal ASN.1 SEQUENCE
        let encoded = b64::encode(fake_der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n");
        let certs = parse_pem_certs(pem.as_bytes());
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].as_ref(), &fake_der);
    }

    #[test]
    fn parse_pem_certs_handles_multiple() {
        let der1 = [0x01, 0x02, 0x03];
        let der2 = [0x04, 0x05, 0x06];
        let encoded_1 = b64::encode(der1);
        let encoded_2 = b64::encode(der2);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{encoded_1}\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\n{encoded_2}\n-----END CERTIFICATE-----\n"
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
        let encoded = b64::encode(fake_der);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{encoded}\n-----END PRIVATE KEY-----\n");
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
        let encoded = b64::encode(fake_der);
        let pem =
            format!("-----BEGIN RSA PRIVATE KEY-----\n{encoded}\n-----END RSA PRIVATE KEY-----\n");
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
        let encoded = b64::encode(fake_der);
        let pem =
            format!("-----BEGIN EC PRIVATE KEY-----\n{encoded}\n-----END EC PRIVATE KEY-----\n");
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

    /// Two independently-issued certs whose key pairs differ must hash to
    /// different SPKI pins. This is the pinning hot path's core property:
    /// the pin is sensitive to the key, so a compromised-CA attacker
    /// cannot silently swap the leaf cert for one signed under a
    /// different key and pass the pin check.
    #[test]
    fn distinct_keypairs_hash_to_distinct_spki_pins() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("pin-distinct-keys-ca");
        // Each issue_server_cert call rolls a fresh keypair internally,
        // so the two leaf certs have different SPKI even though the
        // subject and SAN list match.
        let cert_a = ca.issue_server_cert("edge.example", &["edge.example"]);
        let cert_b = ca.issue_server_cert("edge.example", &["edge.example"]);

        let der_a = parse_pem_certs(cert_a.cert_pem.as_bytes())
            .into_iter()
            .next()
            .expect("cert A DER");
        let der_b = parse_pem_certs(cert_b.cert_pem.as_bytes())
            .into_iter()
            .next()
            .expect("cert B DER");

        let pin_a = spki_pin(&der_a);
        let pin_b = spki_pin(&der_b);
        assert_ne!(
            pin_a, pin_b,
            "distinct keypairs must produce distinct SPKI pins",
        );
    }

    /// Core RFC 7469 property: an SPKI pin survives a same-key cert
    /// reissue. `rustgate_test_utils::TestCa::issue_server_cert_with_key`
    /// rolls a fresh serial, validity window, and signature over the
    /// supplied keypair, so the leaf DER changes but the SPKI stays
    /// byte-identical. The pin must continue to match.
    ///
    /// This is the direct regression guard for #948. Prior to this
    /// migration, `pin_sha256` hashed the full leaf DER and a routine
    /// annual rotation with long-lived keys forced every operator to
    /// update their pin list. With SPKI pinning the same rotation is a
    /// no-op for pins.
    #[test]
    fn spki_pin_survives_same_key_reissue() {
        use rustgate_test_utils::certs::{TestCa, generate_server_keypair};

        let ca = TestCa::new("pin-same-key-ca");
        let keypair = generate_server_keypair();
        let cert_a = ca.issue_server_cert_with_key(&keypair, "edge.example", &["edge.example"]);
        let cert_b = ca.issue_server_cert_with_key(&keypair, "edge.example", &["edge.example"]);

        let der_a = parse_pem_certs(cert_a.cert_pem.as_bytes())
            .into_iter()
            .next()
            .expect("cert A DER");
        let der_b = parse_pem_certs(cert_b.cert_pem.as_bytes())
            .into_iter()
            .next()
            .expect("cert B DER");

        // Sanity: the full-DER bytes changed (rcgen bumps serial and
        // signs afresh on every issue), so a legacy full-DER pin would
        // have broken.
        assert_ne!(
            der_a.as_ref(),
            der_b.as_ref(),
            "reissued leaf DERs should differ",
        );

        // But the SPKI bytes — and therefore the pin — stay identical.
        let spki_a = extract_spki_der(&der_a).expect("SPKI A");
        let spki_b = extract_spki_der(&der_b).expect("SPKI B");
        assert_eq!(
            spki_a, spki_b,
            "same keypair must yield same SPKI bytes across reissues",
        );

        let pin_a = spki_pin(&der_a);
        let pin_b = spki_pin(&der_b);
        assert_eq!(
            pin_a, pin_b,
            "SPKI pin must match across same-key reissues (RFC 7469 semantic)",
        );
    }

    /// Round-trip the config-file base64 ingestion: an SPKI pin computed
    /// from a real issued cert must survive `b64::encode` → `parse_pins`
    /// and come out byte-identical, matching what the verifier's hot
    /// path computes.
    #[test]
    fn verifier_accepts_matching_spki_pin_from_real_cert() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("pin-ok-ca");
        let cert = ca.issue_server_cert("ok.example", &["ok.example"]);
        let der = parse_pem_certs(cert.cert_pem.as_bytes())
            .into_iter()
            .next()
            .expect("server cert DER");

        // Compute the expected pin exactly as the verifier would.
        let expected_pin = spki_pin(&der);

        // Round-trip through base64 parse to mirror config-file ingestion.
        let b64_pin = b64::encode(expected_pin);
        let parsed = parse_pins(&[b64_pin]).expect("pin parses");
        assert_eq!(parsed, vec![expected_pin]);
    }

    /// A legacy full-DER pin — the pre-#948 hash — must **not** match
    /// the new SPKI-based verifier. Operators who held full-DER pins
    /// from an earlier deployment see a mismatch and are forced to
    /// regenerate; silent acceptance of the old pin format would defeat
    /// the migration's whole point.
    #[test]
    fn legacy_full_der_pin_no_longer_matches() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("pin-legacy-ca");
        let cert = ca.issue_server_cert("legacy.example", &["legacy.example"]);
        let der = parse_pem_certs(cert.cert_pem.as_bytes())
            .into_iter()
            .next()
            .expect("server cert DER");

        // Pre-#948 pin shape: SHA-256 of the whole leaf DER.
        let legacy_pin: [u8; 32] = Sha256::digest(der.as_ref()).into();
        // Post-#948 pin shape: SHA-256 of the SPKI bytes.
        let spki_pin_bytes = spki_pin(&der);
        assert_ne!(
            legacy_pin, spki_pin_bytes,
            "full-DER hash and SPKI hash are distinct by construction — \
             otherwise the migration test below is vacuous",
        );
    }

    /// `extract_spki_der` surfaces an x509-parser failure as a rustls
    /// `TlsError::General` so the verifier fails closed on a malformed
    /// cert rather than panicking or silently admitting the connection.
    #[test]
    fn extract_spki_der_rejects_malformed_cert() {
        let garbage = CertificateDer::from(vec![0x00, 0x01, 0x02, 0x03]);
        let err = extract_spki_der(&garbage).expect_err("must reject garbage");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("SPKI extraction failed"),
            "error must name the SPKI extraction step; got {rendered}",
        );
    }
}
