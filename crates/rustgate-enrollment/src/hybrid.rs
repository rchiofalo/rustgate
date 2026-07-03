// Copyright © 2026 Roberto Chiofalo.

//! Hybrid (composite classical + post-quantum) certificate scaffold.
//!
//! This module is the first, honest slice of hybrid-certificate issuance
//! (issue #503). It records the owner-decided direction — **composite ML-DSA**
//! (`draft-ietf-lamps-pq-composite-sigs`) as the primary path, with dual
//! certificate chains as the operationally-complex fallback — as typed code,
//! and it surfaces a clear "blocked upstream" error instead of shipping fake
//! crypto.
//!
//! # Why this is a scaffold, not an implementation
//!
//! A working composite-signature path cannot be built or compile-verified
//! against the current dependency stack:
//!
//! - `rcgen` (workspace pin) has **no** composite / ML-DSA signature
//!   construction API.
//! - `rustls` has **no** ML-DSA certificate-verification path yet (#501, open).
//! - ML-DSA "pure" issuance (#502) is not yet available.
//! - The governing IETF draft (`draft-ietf-lamps-pq-composite-sigs`) is still
//!   in "Revised I-D Needed" state, and the `aws-lc-rs` FIPS/ML-DSA mutual
//!   exclusion ([aws-lc-rs #964]) blocks the provider-side pieces.
//!
//! So [`sign_csr_hybrid`] deliberately returns
//! [`EnrollmentError::HybridUnsupported`] pointing at ADR 0019 and the
//! blocking issues. The [`HybridSignatureProfile`] enum and its descriptors
//! are the stable surface that #501/#502 and the eventual rcgen/aws-lc-rs
//! upstream work will fill in.
//!
//! See `docs/adr/0019-cnsa2-hybrid-mldsa.md` — the "#503 Hybrid Certificate
//! Issuance" section — for the full design and phased plan.
//!
//! [aws-lc-rs #964]: https://github.com/aws/aws-lc-rs/issues/964

use crate::error::EnrollmentError;
use crate::signing::CsrSigner;

/// A composite signature profile: one post-quantum ML-DSA algorithm paired
/// with a classical ECDSA algorithm at a matching NIST security level.
///
/// The classical half is the **fallback verifier** for peers that have not yet
/// adopted ML-DSA, and the **secondary verifier** for crypto-agility per
/// CNSA 2.0 § 4. See ADR 0019 for why composite (not pure ML-DSA) is the
/// migration-window direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HybridSignatureProfile {
    /// **CNSA 2.0 Level 5** — Composite ML-DSA-87 + ECDSA-P384.
    ///
    /// The target profile for DoD National Security Systems: ML-DSA-87 is the
    /// CNSA 2.0 digital-signature algorithm (NIST Level 5), and ECDSA-P384 is
    /// the CNSA 2.0 classical signature it composes with.
    Ml87EcdsaP384,

    /// **NIST Level 3** — Composite ML-DSA-65 + ECDSA-P256.
    ///
    /// A lower-tier profile for deployments where ML-DSA-87 is unavailable or
    /// oversized for the wire budget (some tactical radios). Not a CNSA 2.0
    /// Level 5 profile — use [`Self::Ml87EcdsaP384`] for NSS environments.
    Ml65EcdsaP256,
}

impl HybridSignatureProfile {
    /// The post-quantum (ML-DSA) half of the composite, e.g. `"ML-DSA-87"`.
    pub const fn pq_algorithm(self) -> &'static str {
        match self {
            Self::Ml87EcdsaP384 => "ML-DSA-87",
            Self::Ml65EcdsaP256 => "ML-DSA-65",
        }
    }

    /// The classical (ECDSA) half of the composite, e.g. `"ECDSA-P384"`.
    pub const fn classical_algorithm(self) -> &'static str {
        match self {
            Self::Ml87EcdsaP384 => "ECDSA-P384",
            Self::Ml65EcdsaP256 => "ECDSA-P256",
        }
    }

    /// The NIST post-quantum security level of the profile (5 or 3).
    pub const fn nist_level(self) -> u8 {
        match self {
            Self::Ml87EcdsaP384 => 5,
            Self::Ml65EcdsaP256 => 3,
        }
    }

    /// A human-readable descriptor of the composite pair, e.g.
    /// `"ML-DSA-87+ECDSA-P384"`.
    pub const fn descriptor(self) -> &'static str {
        match self {
            Self::Ml87EcdsaP384 => "ML-DSA-87+ECDSA-P384",
            Self::Ml65EcdsaP256 => "ML-DSA-65+ECDSA-P256",
        }
    }
}

/// Sign a PKCS#10 CSR into a hybrid (composite ML-DSA + ECDSA) certificate —
/// **not yet implementable**.
///
/// This is the stable entrypoint for hybrid issuance. It performs the same
/// input contract as [`CsrSigner::sign_csr`] (the CSR contributes only the
/// public key; the authenticated `username` is enforced as the CN), but a
/// composite signature cannot be produced against the current dependency
/// stack, so it always returns [`EnrollmentError::HybridUnsupported`].
///
/// The error message names the requested [`HybridSignatureProfile`], the
/// governing ADR, and the blocking upstream issues so operators and future
/// implementers get an actionable pointer rather than a silent failure or —
/// worse — an unstandardized wire format masquerading as a hybrid cert.
///
/// When #501 (rustls ML-DSA verify) and #502 (ML-DSA issuance) land, and once
/// rcgen exposes composite-signature construction, this function's body is
/// where the real composite issuance slots in behind the same signature.
///
/// See `docs/adr/0019-cnsa2-hybrid-mldsa.md` and [aws-lc-rs #964].
///
/// [aws-lc-rs #964]: https://github.com/aws/aws-lc-rs/issues/964
pub fn sign_csr_hybrid(
    _signer: &CsrSigner,
    _csr_pem: &str,
    _username: &str,
    profile: HybridSignatureProfile,
) -> Result<Vec<u8>, EnrollmentError> {
    Err(EnrollmentError::HybridUnsupported(format!(
        "composite {} certificate issuance is not yet available: rcgen has no \
         composite-signature construction API, rustls has no ML-DSA verify path \
         (#501), and ML-DSA issuance (#502) is not yet implemented. See \
         docs/adr/0019-cnsa2-hybrid-mldsa.md (#503 Hybrid Certificate Issuance) \
         and aws-lc-rs #964 for the upstream gates",
        profile.descriptor()
    )))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    fn test_signer() -> CsrSigner {
        let ca = rustgate_test_utils::certs::TestCa::new("Test CA");
        CsrSigner::from_pem(&ca.cert_pem, &ca.key_pem, "TestOrg").expect("signer")
    }

    fn generate_csr(cn: &str) -> String {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

        let key = KeyPair::generate().expect("keygen");
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        let csr = params.serialize_request(&key).expect("csr");
        csr.pem().expect("pem")
    }

    #[test]
    fn hybrid_signature_profile_variants_and_algorithms() {
        // L5 (CNSA 2.0) profile.
        let l5 = HybridSignatureProfile::Ml87EcdsaP384;
        assert_eq!(l5.pq_algorithm(), "ML-DSA-87");
        assert_eq!(l5.classical_algorithm(), "ECDSA-P384");
        assert_eq!(l5.nist_level(), 5);
        assert_eq!(l5.descriptor(), "ML-DSA-87+ECDSA-P384");

        // L3 profile.
        let l3 = HybridSignatureProfile::Ml65EcdsaP256;
        assert_eq!(l3.pq_algorithm(), "ML-DSA-65");
        assert_eq!(l3.classical_algorithm(), "ECDSA-P256");
        assert_eq!(l3.nist_level(), 3);
        assert_eq!(l3.descriptor(), "ML-DSA-65+ECDSA-P256");
    }

    #[test]
    fn sign_csr_hybrid_is_blocked_upstream() {
        let signer = test_signer();
        let csr_pem = generate_csr("hybrid-client");

        for profile in [
            HybridSignatureProfile::Ml87EcdsaP384,
            HybridSignatureProfile::Ml65EcdsaP256,
        ] {
            let result = sign_csr_hybrid(&signer, &csr_pem, "hybrid-client", profile);
            match result {
                Err(EnrollmentError::HybridUnsupported(msg)) => {
                    // The message must point at the ADR and blocking issues so
                    // the failure is actionable, not opaque.
                    assert!(
                        msg.contains("0019"),
                        "message must reference ADR 0019: {msg}"
                    );
                    assert!(
                        msg.contains("#503"),
                        "message must reference issue #503: {msg}"
                    );
                    assert!(
                        msg.contains(profile.descriptor()),
                        "message must name the requested profile {}: {msg}",
                        profile.descriptor()
                    );
                }
                other => panic!("expected HybridUnsupported, got {other:?}"),
            }
        }
    }
}
