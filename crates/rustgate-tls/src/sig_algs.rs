// Copyright © 2026 Roberto Chiofalo.

//! Signature-verification policy for `aws-lc-rs`-backed providers.
//!
//! rustls 0.23.45 started listing ML-DSA-44/65/87 in the stock `aws-lc-rs`
//! provider's `signature_verification_algorithms`. Until then, accepting an
//! ML-DSA-signed certificate chain required the explicit augmentation in
//! [`mldsa_certs`](crate::mldsa_certs), and that augmentation is what
//! `--mldsa-client-certs` gates — including the audit event that records the
//! trust-policy widening.
//!
//! Left alone, the upstream change would turn that flag into a no-op: every
//! `post-quantum` or `mldsa-certs` build installs an `aws-lc-rs` provider, so
//! ML-DSA issuers would be accepted with the flag off, no audit event, and no
//! operator decision. [`without_mldsa_verification`] restores the pre-0.23.45
//! baseline by stripping every ML-DSA entry from the stock set; the
//! augmentation then adds ML-DSA-87 back on top of that baseline, so the two
//! are complementary and the flag remains the single point of decision.
//!
//! Filtering is by algorithm identifier and [`SignatureScheme`] rather than by
//! pointer identity against `webpki::aws_lc_rs::ML_DSA_*`, so this module
//! needs neither the `rustls-webpki` dependency nor the `mldsa-certs` feature
//! and works on a plain `post-quantum` build.

use std::sync::LazyLock;

use rustls::SignatureScheme;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls_pki_types::{AlgorithmIdentifier, SignatureVerificationAlgorithm, alg_id};

/// Every ML-DSA parameter set rustls can name, as X.509 signature algorithm
/// identifiers (RFC 9881 OIDs, parameters absent).
const ML_DSA_SIG_ALG_IDS: [AlgorithmIdentifier; 3] =
    [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87];

/// Every ML-DSA TLS signature scheme rustls can name.
const ML_DSA_SCHEMES: [SignatureScheme; 3] = [
    SignatureScheme::ML_DSA_44,
    SignatureScheme::ML_DSA_65,
    SignatureScheme::ML_DSA_87,
];

fn is_mldsa_alg(alg: &dyn SignatureVerificationAlgorithm) -> bool {
    ML_DSA_SIG_ALG_IDS.contains(&alg.signature_alg_id())
}

fn is_mldsa_scheme(scheme: SignatureScheme) -> bool {
    ML_DSA_SCHEMES.contains(&scheme)
}

/// The stock `aws-lc-rs` verification set with every ML-DSA entry removed —
/// exactly what the stock set was before rustls 0.23.45.
///
/// Derived from the upstream provider rather than hand-listed so that
/// classical algorithms rustls adds in future point releases are kept.
/// Leaked once via `LazyLock` for the same reason as
/// `mldsa_certs::MLDSA_SIG_ALGS`: `WebPkiSupportedAlgorithms` requires
/// `'static` slices, and the filtered set is only knowable at run time.
static STOCK_WITHOUT_MLDSA: LazyLock<WebPkiSupportedAlgorithms> = LazyLock::new(|| {
    let base = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;

    let all: Vec<&'static dyn SignatureVerificationAlgorithm> = base
        .all
        .iter()
        .copied()
        .filter(|alg| !is_mldsa_alg(*alg))
        .collect();

    let mapping: Vec<(
        SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    )> = base
        .mapping
        .iter()
        .copied()
        .filter(|(scheme, _)| !is_mldsa_scheme(*scheme))
        .collect();

    WebPkiSupportedAlgorithms {
        all: all.leak(),
        mapping: mapping.leak(),
    }
});

/// The stock `aws-lc-rs` verification set minus ML-DSA, for the augmentation
/// in `mldsa_certs` to build on so ML-DSA-87 is present exactly once.
#[cfg(any(feature = "mldsa-certs", test))]
pub(crate) fn stock_without_mldsa() -> WebPkiSupportedAlgorithms {
    *STOCK_WITHOUT_MLDSA
}

/// Remove ML-DSA certificate verification from an `aws-lc-rs`-backed
/// provider, leaving every other part of it untouched.
///
/// This is the default for every `aws-lc-rs` provider rustgate installs when
/// `--mldsa-client-certs` is **not** set. It exists because the stock set
/// gained ML-DSA upstream; without it the flag would no longer gate anything.
///
/// `base` must be an `aws-lc-rs`-backed provider: the replacement set is
/// derived from `aws-lc-rs`'s own algorithm list, so pairing it with a `ring`
/// provider would swap in algorithms `ring` cannot back.
#[must_use]
pub fn without_mldsa_verification(base: CryptoProvider) -> CryptoProvider {
    CryptoProvider {
        signature_verification_algorithms: *STOCK_WITHOUT_MLDSA,
        ..base
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The stripped set must contain no ML-DSA entry in either `all` or
    /// `mapping`, and must keep every classical entry in its original order.
    #[test]
    fn stripped_set_has_no_mldsa_and_keeps_classical_order() {
        let base = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
        let stripped = stock_without_mldsa();

        assert!(
            !stripped.all.iter().any(|alg| is_mldsa_alg(*alg)),
            "`all` must not contain any ML-DSA algorithm"
        );
        assert!(
            !stripped.mapping.iter().any(|(s, _)| is_mldsa_scheme(*s)),
            "`mapping` must not advertise any ML-DSA scheme"
        );

        let base_classical: Vec<_> = base
            .mapping
            .iter()
            .map(|(s, _)| *s)
            .filter(|s| !is_mldsa_scheme(*s))
            .collect();
        let stripped_schemes: Vec<_> = stripped.mapping.iter().map(|(s, _)| *s).collect();
        assert_eq!(
            stripped_schemes, base_classical,
            "classical schemes must survive, in their original order"
        );
    }

    /// Pin the reason this module exists: the stock set ships ML-DSA. If this
    /// ever fails, upstream dropped it again and the strip is a harmless
    /// no-op — but `mldsa_certs` should be re-checked, since its augmentation
    /// is once more the only route to ML-DSA-87.
    #[test]
    fn stock_provider_ships_mldsa_since_rustls_0_23_45() {
        let base = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
        assert!(
            base.mapping
                .iter()
                .any(|(s, _)| *s == SignatureScheme::ML_DSA_87),
            "stock aws-lc-rs set should list ML_DSA_87 — see module docs"
        );
    }

    /// `LazyLock` must hand back the same leaked slices every time.
    #[test]
    fn strip_does_not_leak_per_call() {
        let first = without_mldsa_verification(rustls::crypto::aws_lc_rs::default_provider())
            .signature_verification_algorithms;
        let second = without_mldsa_verification(rustls::crypto::aws_lc_rs::default_provider())
            .signature_verification_algorithms;
        assert!(std::ptr::eq(first.all, second.all));
        assert!(std::ptr::eq(first.mapping, second.mapping));
    }
}
