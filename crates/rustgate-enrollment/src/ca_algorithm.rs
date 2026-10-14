// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! CA signature-algorithm selection for certificate/CRL issuance.
//!
//! Defines the [`CaAlgorithm`] enum — the set of signature algorithms the
//! enrollment CA can be asked to issue under. Today only the classical
//! variants ([`CaAlgorithm::EcdsaP256`], [`CaAlgorithm::Rsa2048`]) actually
//! produce certificates; the ML-DSA variants exist so the public surface,
//! config parsing, and the fail-closed guard in `signing.rs` can be written
//! and reviewed now, ahead of the upstream crypto landing.
//!
//! # Why the ML-DSA variants do not issue yet
//!
//! Per ADR 0019 (`docs/adr/0019-cnsa2-hybrid-mldsa.md`), rustgate's
//! CNSA 2.0 target is **Composite ML-DSA + ECDSA** hybrid certificates
//! (IETF LAMPS hybrid-signature draft / RFC 9655 draft), **not** pure
//! ML-DSA. Two upstream blockers stand in the way of issuance:
//!
//! 1. `rcgen`'s ML-DSA path is gated behind `aws_lc_rs_unstable` and is
//!    **mutually exclusive with `fips`** — enabling it would break every
//!    FIPS build in the workspace
//!    ([aws-lc-rs #964](https://github.com/aws/aws-lc-rs/issues/964)).
//! 2. Even with that feature on, `rcgen` emits **pure** ML-DSA certificates,
//!    which ADR 0019's Decision explicitly rejects for the 2026–2030
//!    transition window (legacy peers cannot verify them). The composite
//!    OIDs are not finalized until late 2026.
//!
//! Selecting an ML-DSA algorithm therefore fails closed with an actionable
//! error (see [`crate::signing`]) instead of silently issuing the wrong
//! certificate format.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Signature algorithm the enrollment CA issues certificates and CRLs under.
///
/// The classical variants issue today. The ML-DSA variants are scaffold for
/// the CNSA 2.0 Composite ML-DSA hybrid path (ADR 0019 Phase 3) and are
/// **rejected at issuance time** — see [`is_post_quantum`] and
/// [`is_composite_required`].
///
/// [`is_post_quantum`]: CaAlgorithm::is_post_quantum
/// [`is_composite_required`]: CaAlgorithm::is_composite_required
// Explicit per-variant `rename` (not `rename_all = "kebab-case"`): serde's
// kebab-case splits only on case boundaries, so it would render `Rsa2048` as
// `rsa2048` and `MlDsa44` as `ml-dsa44` — neither matches the canonical
// digit-separated CLI spelling in `as_str`/`FromStr`. Pinning each variant
// keeps the serde wire form byte-identical to the CLI/config spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CaAlgorithm {
    /// ECDSA over NIST P-256 (SHA-256). Classical, issues today. The default
    /// for existing deployments.
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256,
    /// RSA 2048-bit (SHA-256). Classical, issues today.
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    /// Composite ML-DSA-44 + ECDSA-P256 (NIST Level 2). Scaffold only —
    /// fails closed at issuance per ADR 0019.
    #[serde(rename = "ml-dsa-44")]
    MlDsa44,
    /// Composite ML-DSA-65 + ECDSA-P256 (NIST Level 3). Scaffold only —
    /// fails closed at issuance per ADR 0019.
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
    /// Composite ML-DSA-87 + ECDSA-P384 (NIST Level 5, the CNSA 2.0 target).
    /// Scaffold only — fails closed at issuance per ADR 0019.
    #[serde(rename = "ml-dsa-87")]
    MlDsa87,
}

impl CaAlgorithm {
    /// Whether this algorithm is a post-quantum (ML-DSA) variant.
    ///
    /// Returns `true` for the three `MlDsa*` variants, `false` for the
    /// classical ones. Callers use this to route to the fail-closed
    /// issuance guard rather than the classical signing path.
    #[must_use]
    pub const fn is_post_quantum(self) -> bool {
        matches!(self, Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87)
    }

    /// Whether this algorithm requires a Composite (hybrid) ML-DSA + ECDSA
    /// certificate per ADR 0019.
    ///
    /// Equivalent to [`is_post_quantum`](CaAlgorithm::is_post_quantum) today:
    /// every ML-DSA variant rustgate commits to is composite, never pure
    /// ML-DSA. Kept as a distinct predicate because a future ADR could
    /// supersede 0019 and permit pure ML-DSA once the federation has fully
    /// migrated — at which point these two would diverge.
    #[must_use]
    pub const fn is_composite_required(self) -> bool {
        self.is_post_quantum()
    }

    /// The canonical CLI/config spelling for this algorithm.
    ///
    /// Matches the `FromStr` accepted spelling and the serde wire form, so
    /// `parse` ∘ `as_str` round-trips.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::Rsa2048 => "rsa-2048",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }
}

impl Default for CaAlgorithm {
    /// The classical ECDSA P-256 path — the algorithm existing deployments
    /// issue under with no configuration change.
    fn default() -> Self {
        Self::EcdsaP256
    }
}

impl fmt::Display for CaAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CaAlgorithm {
    type Err = ParseCaAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ecdsa-p256" => Ok(Self::EcdsaP256),
            "rsa-2048" => Ok(Self::Rsa2048),
            "ml-dsa-44" => Ok(Self::MlDsa44),
            "ml-dsa-65" => Ok(Self::MlDsa65),
            "ml-dsa-87" => Ok(Self::MlDsa87),
            other => Err(ParseCaAlgorithmError {
                input: other.to_string(),
            }),
        }
    }
}

/// Error returned when a string does not name a known [`CaAlgorithm`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "unknown CA algorithm `{input}` (expected one of: ecdsa-p256, rsa-2048, ml-dsa-44, ml-dsa-65, ml-dsa-87)"
)]
pub struct ParseCaAlgorithmError {
    /// The unrecognized input string.
    input: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_results)]
mod tests {
    use super::*;

    const ALL: [CaAlgorithm; 5] = [
        CaAlgorithm::EcdsaP256,
        CaAlgorithm::Rsa2048,
        CaAlgorithm::MlDsa44,
        CaAlgorithm::MlDsa65,
        CaAlgorithm::MlDsa87,
    ];

    #[test]
    fn from_str_accepts_all_canonical_spellings() {
        assert_eq!(
            "ecdsa-p256".parse::<CaAlgorithm>().unwrap(),
            CaAlgorithm::EcdsaP256
        );
        assert_eq!(
            "rsa-2048".parse::<CaAlgorithm>().unwrap(),
            CaAlgorithm::Rsa2048
        );
        assert_eq!(
            "ml-dsa-44".parse::<CaAlgorithm>().unwrap(),
            CaAlgorithm::MlDsa44
        );
        assert_eq!(
            "ml-dsa-65".parse::<CaAlgorithm>().unwrap(),
            CaAlgorithm::MlDsa65
        );
        assert_eq!(
            "ml-dsa-87".parse::<CaAlgorithm>().unwrap(),
            CaAlgorithm::MlDsa87
        );
    }

    #[test]
    fn from_str_rejects_unknown_strings() {
        let err = "ml-dsa-99".parse::<CaAlgorithm>().unwrap_err();
        assert!(err.to_string().contains("ml-dsa-99"));
        assert!("".parse::<CaAlgorithm>().is_err());
        assert!(
            "ECDSA-P256".parse::<CaAlgorithm>().is_err(),
            "case-sensitive"
        );
        assert!("ecdsap256".parse::<CaAlgorithm>().is_err());
    }

    #[test]
    fn display_matches_cli_spelling_and_round_trips_through_from_str() {
        for alg in ALL {
            let rendered = alg.to_string();
            assert_eq!(rendered, alg.as_str());
            assert_eq!(
                rendered.parse::<CaAlgorithm>().unwrap(),
                alg,
                "Display ∘ FromStr must round-trip for {alg:?}"
            );
        }
    }

    #[test]
    fn is_post_quantum_is_true_only_for_mldsa_variants() {
        assert!(!CaAlgorithm::EcdsaP256.is_post_quantum());
        assert!(!CaAlgorithm::Rsa2048.is_post_quantum());
        assert!(CaAlgorithm::MlDsa44.is_post_quantum());
        assert!(CaAlgorithm::MlDsa65.is_post_quantum());
        assert!(CaAlgorithm::MlDsa87.is_post_quantum());
    }

    #[test]
    fn is_composite_required_tracks_post_quantum_today() {
        for alg in ALL {
            assert_eq!(
                alg.is_composite_required(),
                alg.is_post_quantum(),
                "ADR 0019 commits every ML-DSA variant to composite, never pure: {alg:?}"
            );
        }
    }

    #[test]
    fn serde_wire_form_matches_cli_spelling() {
        for alg in ALL {
            let json = serde_json::to_string(&alg).unwrap();
            // Explicit per-variant rename means the JSON string is byte-
            // identical to the CLI/config spelling (including the digit
            // separators kebab-case would drop).
            assert_eq!(json, format!("\"{}\"", alg.as_str()));
            let back: CaAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(back, alg);
        }
    }

    #[test]
    fn serde_rejects_unknown_variant() {
        let result = serde_json::from_str::<CaAlgorithm>("\"ml-dsa-99\"");
        assert!(result.is_err());
    }

    #[test]
    fn default_is_classical_ecdsa_p256() {
        assert_eq!(CaAlgorithm::default(), CaAlgorithm::EcdsaP256);
        assert!(!CaAlgorithm::default().is_post_quantum());
    }
}
