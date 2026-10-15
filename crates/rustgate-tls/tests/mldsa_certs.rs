// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! ML-DSA-87 (FIPS 204 / RFC 9881) TLS certificate-verification tests (#501).
//!
//! # What these tests must avoid proving by accident
//!
//! webpki does **not** verify a trust anchor's own signature — an anchor is
//! trusted by assertion, not by cryptography. So a test that presents a
//! self-signed ML-DSA CA as both the anchor *and* the end entity passes
//! happily while executing **zero** ML-DSA verification code. Every test here
//! therefore uses a chain where the leaf is genuinely *signed by* the anchor,
//! and [`provider_without_opt_in_rejects_mldsa_issued_chain`] is the mandatory negative
//! control: it runs the identical chain through the unmodified provider and
//! requires a failure. Without that control, none of the positive results mean
//! anything.
//!
//! # Why the leaf key is classical
//!
//! The leaf carries an ECDSA P-384 key, not an ML-DSA one. That is the
//! capability that actually works end-to-end today, and the realistic CNSA 2.0
//! migration shape: a long-lived post-quantum root signing short-lived
//! classical leaves. A *pure* ML-DSA leaf would have to produce an ML-DSA
//! `CertificateVerify`, which rustls cannot generate (its `any_supported_type`
//! handles RSA/ECDSA/EdDSA only) — so no live handshake can exercise it from
//! this side. That half is covered at the signature level by
//! [`verify_tls13_signature_accepts_fips204_signature`] instead.

#![cfg(feature = "mldsa-certs")]
#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use rustgate_core::constants::HANDSHAKE_TIMEOUT;
use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::mldsa::{MlDsaTestCa, generate_mldsa_ca, issue_leaf_with_spki};
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::{TlsConfig, TlsListener, mldsa_provider};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ------------------------------------------------------------------
// Fixtures
// ------------------------------------------------------------------

/// Install the ML-DSA-augmented provider as this process's default, once.
///
/// Required, not merely convenient: with `mldsa-certs` on, rustls has *both*
/// its `ring` and `aws_lc_rs` features enabled, so
/// `CryptoProvider::get_default_or_install_from_crate_features()` cannot pick
/// a backend and panics. Anything that builds a verifier without an explicit
/// provider — including `TlsConfig::build_server_config` — depends on this
/// having run first. (Production does the same thing at startup in
/// `rustgate-server`'s `main`.)
fn install_default_provider_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::CryptoProvider::install_default(mldsa_provider());
    });
}

fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// An ML-DSA-87 CA plus an ECDSA P-384 leaf that the CA actually signed.
struct MldsaIssuedChain {
    ca: MlDsaTestCa,
    leaf_der: Vec<u8>,
    leaf_key_pem: String,
}

fn mldsa_issued_chain(cn: &str) -> MldsaIssuedChain {
    use rcgen::PublicKeyData as _;

    let ca = generate_mldsa_ca("rustgate ML-DSA-87 Test CA");
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let leaf_der = issue_leaf_with_spki(&ca, &key_pair.subject_public_key_info(), cn);
    MldsaIssuedChain {
        ca,
        leaf_der,
        leaf_key_pem: key_pair.serialize_pem(),
    }
}

/// Build a [`rustls::DigitallySignedStruct`] from its wire encoding.
///
/// Its `new` is crate-private, but the type is `Codec`, and the encoding is
/// simply `scheme || u16 length || signature`.
fn digitally_signed(scheme: rustls::SignatureScheme, sig: &[u8]) -> rustls::DigitallySignedStruct {
    use rustls::internal::msgs::codec::{Codec, Reader};

    let mut wire = Vec::with_capacity(sig.len() + 4);
    wire.extend_from_slice(&scheme.to_array());
    wire.extend_from_slice(
        &u16::try_from(sig.len())
            .expect("signature fits u16")
            .to_be_bytes(),
    );
    wire.extend_from_slice(sig);

    let mut reader = Reader::init(&wire);
    rustls::DigitallySignedStruct::read(&mut reader).expect("well-formed DigitallySignedStruct")
}

fn root_store_with(ca_der: &[u8]) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .expect("ML-DSA CA is a usable trust anchor");
    Arc::new(roots)
}

// ------------------------------------------------------------------
// Chain verification — positive, and the mandatory negative control
// ------------------------------------------------------------------

/// The augmented provider must accept a leaf whose issuer signed it with
/// ML-DSA-87. This is the capability #501 asks for.
#[test]
fn augmented_provider_verifies_mldsa_issued_chain() {
    let chain = mldsa_issued_chain("MLDSA-CLIENT-1");

    let verifier =
        WebPkiClientVerifier::builder_with_provider(root_store_with(&chain.ca.cert_der), {
            Arc::new(mldsa_provider())
        })
        .build()
        .expect("verifier builds");

    let result = verifier.verify_client_cert(
        &CertificateDer::from(chain.leaf_der.clone()),
        &[],
        UnixTime::now(),
    );

    assert!(
        result.is_ok(),
        "augmented provider must verify an ML-DSA-87-issued chain, got {:?}",
        result.err(),
    );
}

/// **Mandatory negative control.** The identical chain must FAIL against
/// rustgate's aws-lc-rs provider without the ML-DSA opt-in.
///
/// If this ever passes, the positive test above is proving nothing — it would
/// mean the chain is being accepted without any ML-DSA signature actually
/// being checked (for example because the leaf was mistakenly self-signed). It
/// also pins that ML-DSA acceptance stays opt-in: since rustls 0.23.46 the
/// *stock* aws-lc-rs provider accepts this chain, and rustgate strips ML-DSA
/// from it unless `--mldsa-client-certs` is set.
#[test]
fn provider_without_opt_in_rejects_mldsa_issued_chain() {
    let chain = mldsa_issued_chain("MLDSA-CLIENT-2");

    let verifier =
        WebPkiClientVerifier::builder_with_provider(root_store_with(&chain.ca.cert_der), {
            Arc::new(rustgate_tls::aws_lc_rs_provider())
        })
        .build()
        .expect("verifier builds");

    let result = verifier.verify_client_cert(
        &CertificateDer::from(chain.leaf_der.clone()),
        &[],
        UnixTime::now(),
    );

    // Assert the *reason*, not merely that it failed: the rejection must name
    // the ML-DSA-87 algorithm identifier (OID 2.16.840.1.101.3.4.3.19, DER
    // `06 09 60 86 48 01 65 03 04 03 13`) as unsupported. A bare `is_err()`
    // would also be satisfied by an unrelated failure — a malformed leaf, a
    // bad issuer name — and would silently stop testing what it claims to.
    const ML_DSA_87_ALG_ID_DER: &[u8] = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
    ];

    match result {
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id,
                ..
            },
        )) => {
            assert_eq!(
                signature_algorithm_id, ML_DSA_87_ALG_ID_DER,
                "rejection must be about ML-DSA-87 specifically",
            );
        }
        other => panic!(
            "without the opt-in the chain must be rejected with UnsupportedSignatureAlgorithm \
             for ML-DSA-87 — if it is accepted, ML-DSA is no longer opt-in and the positive \
             test is vacuous. Got: {other:?}",
        ),
    }
}

// ------------------------------------------------------------------
// Live mTLS handshake
// ------------------------------------------------------------------

/// End-to-end proof: a real client completes a real mTLS handshake presenting
/// a certificate issued by an ML-DSA-87 CA, and the server extracts its
/// identity.
///
/// The server's own certificate stays classical (a separate `TestCa`), because
/// only the *client* trust path is under test here — that is where the
/// ML-DSA-87 issuer signature has to be verified.
#[tokio::test]
async fn live_mtls_handshake_with_mldsa_issued_client_cert() {
    install_default_provider_once();

    let chain = mldsa_issued_chain("MLDSA-OPERATOR-1");
    let server_ca = TestCa::new("rustgate ML-DSA Test Server CA");
    let server_cert = server_ca.issue_server_cert("localhost", &["localhost"]);

    // Client CA store = the ML-DSA-87 CA: the server will have to verify the
    // client's chain using an ML-DSA signature.
    let tls_config = TlsConfig::from_pem(
        &server_cert.cert_pem,
        &server_cert.key_pem,
        &der_to_pem(&chain.ca.cert_der, "CERTIFICATE"),
    )
    .expect("server TLS config builds with an ML-DSA-87 client CA");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("listener binds");
    let addr = listener.local_addr().expect("listener addr");

    let server_handle = tokio::spawn(async move {
        let session = tokio::time::timeout(HANDSHAKE_TIMEOUT, listener.accept())
            .await
            .expect("handshake completes within deadline")
            .expect("mTLS handshake against ML-DSA-87-issued client cert succeeds");

        assert_eq!(&*session.identity().cn, "MLDSA-OPERATOR-1");

        let (mut reader, mut writer) = session.split();
        let mut buf = [0u8; 5];
        let _ = reader.read_exact(&mut buf).await.expect("server reads");
        assert_eq!(&buf, b"hello");
        writer.write_all(b"world").await.expect("server writes");
        writer.flush().await.expect("server flushes");
    });

    let client_tls = build_client_tls_config(
        &der_to_pem(&chain.leaf_der, "CERTIFICATE"),
        &chain.leaf_key_pem,
        &server_ca.cert_pem,
    );
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let server_name: rustls_pki_types::ServerName<'static> = "localhost".try_into().unwrap();
    let mut stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .expect("client handshake within deadline")
        .expect("client handshake ok");

    stream.write_all(b"hello").await.expect("client writes");
    stream.flush().await.expect("client flushes");
    let mut reply = [0u8; 5];
    let _ = stream.read_exact(&mut reply).await.expect("client reads");
    assert_eq!(&reply, b"world");

    server_handle.await.expect("server task joins");
}

// ------------------------------------------------------------------
// TLS 1.3 CertificateVerify signature scheme (forward-compat interop)
// ------------------------------------------------------------------

/// A `CertificateVerify` produced by the pure-Rust `fips204` implementation
/// must verify through the augmented provider (which uses aws-lc-rs).
///
/// This covers the half that no live handshake can reach — rustls cannot
/// generate an ML-DSA signature — and doubles as a cross-implementation
/// agreement check between two independent ML-DSA-87 implementations.
#[test]
fn verify_tls13_signature_accepts_fips204_signature() {
    use fips204::ml_dsa_87;
    use fips204::traits::{SerDes, Signer};

    let ca = generate_mldsa_ca("rustgate ML-DSA-87 SigTest CA");
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(ca.secret_key.clone().try_into().unwrap())
        .expect("CA secret key");

    let message = b"rustgate ML-DSA-87 TLS 1.3 CertificateVerify transcript";
    // Empty context string, per RFC 9881's pure ML-DSA profile.
    let signature = sk.try_sign(message, &[]).expect("sign");

    let dss = digitally_signed(rustls::SignatureScheme::ML_DSA_87, &signature);

    let result = rustls::crypto::verify_tls13_signature(
        message,
        &CertificateDer::from(ca.cert_der.clone()),
        &dss,
        &mldsa_provider().signature_verification_algorithms,
    );

    assert!(
        result.is_ok(),
        "aws-lc-rs must accept a fips204-produced ML-DSA-87 signature, got {:?}",
        result.err(),
    );
}

/// A tampered ML-DSA-87 signature must be rejected — proves the positive test
/// above is checking the signature rather than short-circuiting on the scheme.
#[test]
fn verify_tls13_signature_rejects_tampered_signature() {
    use fips204::ml_dsa_87;
    use fips204::traits::{SerDes, Signer};

    let ca = generate_mldsa_ca("rustgate ML-DSA-87 Tamper CA");
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(ca.secret_key.clone().try_into().unwrap())
        .expect("CA secret key");

    let message = b"rustgate ML-DSA-87 TLS 1.3 CertificateVerify transcript";
    let mut signature = sk.try_sign(message, &[]).expect("sign").to_vec();
    signature[0] ^= 0xFF;

    let dss = digitally_signed(rustls::SignatureScheme::ML_DSA_87, &signature);

    let result = rustls::crypto::verify_tls13_signature(
        message,
        &CertificateDer::from(ca.cert_der.clone()),
        &dss,
        &mldsa_provider().signature_verification_algorithms,
    );

    assert!(result.is_err(), "a tampered ML-DSA-87 signature must fail");
}

// ------------------------------------------------------------------
// Advertisement
// ------------------------------------------------------------------

/// The server advertises its accepted schemes in the `CertificateRequest`.
/// ML-DSA-87 must be present but **last**: `mapping` order is preference
/// order, and promoting it would make dual-credential peers send a ~7 KB
/// ML-DSA credential where a ~100-byte ECDSA one would do.
#[test]
fn advertised_schemes_include_mldsa_last() {
    let schemes = mldsa_provider()
        .signature_verification_algorithms
        .supported_schemes();

    assert!(
        schemes.contains(&rustls::SignatureScheme::ML_DSA_87),
        "ML-DSA-87 must be advertised in supported_verify_schemes",
    );
    assert_eq!(
        schemes.last(),
        Some(&rustls::SignatureScheme::ML_DSA_87),
        "ML-DSA-87 must be advertised last, behind every classical scheme",
    );
    assert_eq!(
        schemes
            .iter()
            .filter(|s| **s == rustls::SignatureScheme::ML_DSA_87)
            .count(),
        1,
        "ML-DSA-87 must be advertised exactly once",
    );
    // The augmentation must not have displaced the classical schemes.
    for expected in [
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        rustls::SignatureScheme::ED25519,
    ] {
        assert!(
            schemes.contains(&expected),
            "classical scheme {expected:?} must still be advertised",
        );
    }
}
