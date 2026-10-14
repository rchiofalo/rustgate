// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]

//! Proptest coverage for [`CsrSigner::sign_csr`] (F-131, refs #789).
//!
//! [`CsrSigner::sign_csr`] is the hot path that every TAK client traverses
//! during certificate enrollment. It accepts an attacker-supplied PEM
//! string and a server-controlled username, parses the embedded
//! certification request, validates the public key, and emits a freshly
//! signed certificate. A panic anywhere in this pipeline turns a single
//! malformed enrollment request into a denial-of-service against every
//! concurrent enrollment — so the contract this module pins is "no input
//! produces a panic; the output is either `Ok` or a typed [`EnrollmentError`]
//! variant".
//!
//! Three families of inputs are covered:
//!
//! 1. **Random byte sequences** as the CSR PEM. Almost all of these are
//!    invalid, so the expected outcome is `Err(EnrollmentError::Csr(_))`
//!    or `Err(EnrollmentError::Signing(_))`. Any panic here is a bug.
//! 2. **Random Common Name lengths** up to the workspace-wide
//!    `MAX_CN_LENGTH = 256` cap (`rustgate_core::identity`). Each
//!    generated CN is fed to [`CsrSigner::sign_csr`] together with a
//!    valid CSR; the signed certificate's subject must round-trip back
//!    to the supplied CN.
//! 3. **Random SAN counts** up to the per-category cap of `32`
//!    (`MAX_SAN_ENTRIES_PER_CATEGORY` in
//!    `rustgate_tls::extract`). The CSR's caller-supplied SANs
//!    are stripped by `sign_csr`'s allowlist policy — the round-trip
//!    therefore asserts the *output* certificate carries no SAN
//!    entries regardless of how many the CSR claimed. That is the
//!    documented #794 hardening.

use proptest::prelude::*;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustgate_enrollment::EnrollmentError;
use rustgate_enrollment::signing::CsrSigner;
use rustgate_test_utils::certs::TestCa;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Workspace-wide cap from `rustgate_core::identity` (private to the
/// crate; mirrored here for the proptest's CN-length range bound).
const MAX_CN_LENGTH: usize = 256;

/// Workspace-wide per-category SAN cap from
/// `rustgate_tls::extract`. Mirrored locally because the constant
/// is crate-private.
const MAX_SAN_ENTRIES_PER_CATEGORY: usize = 32;

/// Build a fresh `CsrSigner` rooted at a freshly minted test CA.
fn build_signer() -> CsrSigner {
    let ca = TestCa::new("PropTest CA");
    CsrSigner::from_pem(&ca.cert_pem, &ca.key_pem, "TestOrg").expect("build signer")
}

/// Generate a valid CSR PEM with the supplied CN and an optional list
/// of DNS SAN entries. Returns the PEM string ready to feed into
/// `sign_csr`.
fn make_valid_csr(cn: &str, dns_sans: &[String]) -> String {
    let key = KeyPair::generate().expect("keypair");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.subject_alt_names = dns_sans
        .iter()
        .map(|d| rcgen::SanType::DnsName(d.clone().try_into().expect("dns name")))
        .collect();
    let csr = params.serialize_request(&key).expect("csr build");
    csr.pem().expect("csr pem")
}

/// CN strategy: ASCII letters + digits, lengths from 1 to
/// `MAX_CN_LENGTH`. The cn-character allowlist is intentionally narrow
/// so each generated CN is also a valid X.509 subject string —
/// otherwise rcgen rejects the CN with an unrelated error and the
/// round-trip assertion never fires.
fn cn_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::char::ranges(vec!['a'..='z', 'A'..='Z', '0'..='9'].into()),
        1..=MAX_CN_LENGTH,
    )
    .prop_map(|cs| cs.into_iter().collect::<String>())
}

/// DNS-name strategy used for SAN generation. Single-label names are
/// the simplest representation rcgen accepts; the test only cares
/// about *count*, not shape.
fn dns_label_strategy() -> impl Strategy<Value = String> {
    "[a-z]{1,16}".prop_map(|s| s.to_string())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Random bytes up to 8 KiB are fed in as the CSR PEM. Almost
    /// none will parse — the contract is "every result is either
    /// `Ok` or a typed `EnrollmentError`, never a panic". A panic
    /// would let a single hostile enrollment request halt every
    /// concurrent signing call sharing the worker.
    #[test]
    fn random_bytes_never_panic(input in proptest::collection::vec(any::<u8>(), 0..=8192)) {
        let signer = build_signer();
        let csr_pem = String::from_utf8_lossy(&input).into_owned();
        let result = signer.sign_csr(&csr_pem, "user");
        match result {
            Ok(_) => {} // astronomically unlikely, but acceptable.
            Err(EnrollmentError::Csr(_))
            | Err(EnrollmentError::Signing(_))
            | Err(EnrollmentError::Config(_)) => {}
            Err(other) => {
                prop_assert!(
                    false,
                    "random-byte CSR produced unexpected error variant: {other:?}"
                );
            }
        }
    }

    /// Random ASCII CNs up to `MAX_CN_LENGTH` round-trip through
    /// `sign_csr`. The CSR's CN is irrelevant — `sign_csr` enforces
    /// the supplied `username` parameter as the issued cert's CN
    /// (the documented #794 allowlist hardening). The round-trip
    /// therefore asserts the *username* parameter, not the CSR's CN,
    /// surfaces in the signed certificate's subject.
    #[test]
    fn cn_lengths_round_trip(cn in cn_strategy()) {
        let signer = build_signer();
        let csr_pem = make_valid_csr("ignored-cn", &[]);
        let signed = signer
            .sign_csr(&csr_pem, &cn)
            .expect("valid CSR + valid CN must sign");
        let (_, parsed) = X509Certificate::from_der(&signed).expect("parse signed cert");
        let subject = parsed.subject().to_string();
        prop_assert!(
            subject.contains(&format!("CN={cn}")),
            "issued cert subject must contain CN={cn}, got `{subject}`"
        );
    }

    /// Random DNS-SAN counts up to `MAX_SAN_ENTRIES_PER_CATEGORY`.
    /// The CSR carries N SAN entries; the signed cert must carry
    /// zero, since `sign_csr` strips every caller-supplied SAN by
    /// the allowlist construction. This pins the documented #794
    /// invariant: an attacker cannot smuggle SANs into a signed
    /// cert by stuffing them in their CSR.
    #[test]
    fn san_counts_round_trip(
        sans in proptest::collection::vec(dns_label_strategy(), 0..=MAX_SAN_ENTRIES_PER_CATEGORY)
    ) {
        let signer = build_signer();
        let csr_pem = make_valid_csr("san-test", &sans);
        let signed = signer
            .sign_csr(&csr_pem, "san-test")
            .expect("valid CSR must sign regardless of CSR-supplied SANs");
        let (_, parsed) = X509Certificate::from_der(&signed).expect("parse signed cert");
        // The signed cert must carry no SAN extension at all; the
        // allowlist clears the SAN list before signing.
        let san_ext = parsed
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME);
        prop_assert!(
            san_ext.is_none(),
            "signed cert must not carry a SAN extension regardless of CSR-supplied SAN count \
             (input had {} SANs)",
            sans.len()
        );
    }
}
