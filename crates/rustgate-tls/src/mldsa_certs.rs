// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! ML-DSA-87 (FIPS 204 / RFC 9881) TLS certificate verification.
//!
//! Extends the `aws-lc-rs` crypto provider's signature-verification set with
//! ML-DSA-87 so the server accepts client-certificate chains that use it. This
//! is the verification half of the post-quantum PKI story — [`crate`]'s sibling
//! `rustgate-enrollment` already *issues* pure ML-DSA-87 certificates (#502),
//! but nothing could authenticate a peer presenting one until now (#501).
//!
//! # Two distinct capabilities
//!
//! The augmentation adds ML-DSA-87 in two independent places, which deliver
//! very different things:
//!
//! - **ML-DSA issuer** (`all`) — a chain anchored at an ML-DSA-87 CA that
//!   signs *classical* (ECDSA/RSA) leaves. This works today against every
//!   existing client, unmodified, because no client-side ML-DSA signing is
//!   involved. It is also the CNSA 2.0 migration runway: the long-lived root
//!   is the credential with real harvest-now-forge-later exposure, while
//!   short-lived leaves can stay classical.
//! - **ML-DSA leaf** (`mapping`) — a peer whose *own key* is ML-DSA-87, which
//!   must produce an ML-DSA `CertificateVerify`. rustls cannot currently
//!   generate one (its `any_supported_type` handles RSA/ECDSA/EdDSA only), so
//!   this is forward-compatible interop surface for external stacks
//!   (OpenSSL 3.5+, BoringSSL), not something `rustgate-client` can drive.
//!
//! # Why a custom provider is required
//!
//! rustls reserves the `ML_DSA_87` [`SignatureScheme`] code point (0x0906) but
//! its stock `aws-lc-rs` provider does **not** list any ML-DSA algorithm in
//! `signature_verification_algorithms`. Enabling a Cargo feature alone
//! therefore changes nothing; the provider's algorithm set has to be rebuilt.
//! Everything downstream picks the augmentation up for free, because
//! `WebPkiClientVerifier::builder` resolves the process-default provider, and
//! [`DynamicCertVerifier`](crate::verifier::DynamicCertVerifier) already
//! delegates `verify_tls1{2,3}_signature` and `supported_verify_schemes` to it.
//!
//! # Deliberate constraints
//!
//! - **Not FIPS.** [`rustls::crypto::CryptoProvider::fips`] is an AND across
//!   every algorithm, and webpki marks ML-DSA `in_fips_submission: false`, so
//!   the augmented provider always reports `fips() == false`. `--fips-required`
//!   and ML-DSA verification are mutually exclusive by construction.
//! - **TLS 1.3 only, in practice.** TLS 1.2's `ClientCertificateType` registry
//!   has no ML-DSA entry, so a TLS 1.2 `CertificateRequest` cannot coherently
//!   ask for one. rustls exposes no per-version hook to suppress the
//!   advertisement.
//! - **Appended last.** `mapping` order is the advertised preference order and
//!   TLS 1.3 uses only the first entry per scheme, so ML-DSA is added at the
//!   end. Promoting it would make dual-credential peers send a ~7 KB ML-DSA
//!   credential where a ~100-byte ECDSA one would do.

// `rustls/fips` enables `webpki/aws-lc-rs-fips`, and webpki gates its ML-DSA
// statics on `not(aws-lc-rs-fips)` (aws-lc-rs independently gates its whole
// `unstable::signature` module on `not(fips)`). The two feature sets cannot
// coexist, so fail loudly here rather than with a bare "cannot find value
// `ML_DSA_87`" from a dependency.
#[cfg(all(feature = "mldsa-certs", feature = "fips"))]
compile_error!(
    "features `mldsa-certs` and `fips` are mutually exclusive: `rustls/fips` enables \
     `webpki/aws-lc-rs-fips`, which removes the `webpki::aws_lc_rs::ML_DSA_*` statics \
     (ML-DSA is not in the AWS-LC FIPS 3.0 submission). Build ML-DSA certificate \
     verification without `fips`, or drop `mldsa-certs`."
);

use std::sync::LazyLock;

use rustgate_core::error::{ConfigError, Result, RustgateError};
use rustls::SignatureScheme;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls_pki_types::SignatureVerificationAlgorithm;

/// The single ML-DSA-87 verification algorithm, as a `'static` slice so it can
/// be referenced from [`WebPkiSupportedAlgorithms::mapping`].
static ML_DSA_87_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[webpki::aws_lc_rs::ML_DSA_87];

/// The stock `aws-lc-rs` verification set plus ML-DSA-87.
///
/// Derived from the upstream provider rather than hand-listed so that
/// algorithms rustls adds in future point releases are picked up
/// automatically — a hand-copied list would silently drop them, and the only
/// symptom would be a classical client that mysteriously stops connecting.
static MLDSA_SIG_ALGS: LazyLock<WebPkiSupportedAlgorithms> = LazyLock::new(|| {
    let base = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;

    let mut all = base.all.to_vec();
    all.push(webpki::aws_lc_rs::ML_DSA_87);

    let mut mapping = base.mapping.to_vec();
    // Appended last: this is the advertised preference order (see module docs).
    mapping.push((SignatureScheme::ML_DSA_87, ML_DSA_87_ALGS));

    // `WebPkiSupportedAlgorithms` stores `&'static` slices, but the augmented
    // set is only knowable at run time (it is derived from the upstream
    // provider), so leaking is the only way to satisfy that contract. Bounded
    // and one-time: this closure runs at most once per process via `LazyLock`,
    // leaking on the order of a few hundred bytes. Never call `Vec::leak`
    // outside this initializer — a per-call leak would be unbounded, which
    // `provider_construction_does_not_leak_per_call` guards against.
    WebPkiSupportedAlgorithms {
        all: all.leak(),
        mapping: mapping.leak(),
    }
});

/// Build an `aws-lc-rs` [`CryptoProvider`] that also verifies ML-DSA-87
/// signatures in certificate chains.
///
/// This is the primary entry point. Prefer it over
/// [`install_mldsa_provider`] anywhere a provider can be passed explicitly
/// (for example `WebPkiClientVerifier::builder_with_provider`), because
/// installing a process-default is a one-shot, global operation that cannot be
/// undone — which makes it unusable in tests that share a process.
///
/// Key-exchange groups and cipher suites are left exactly as the `aws-lc-rs`
/// defaults, so this composes with the `post-quantum` feature's ML-KEM group
/// preference: that augments key exchange, this augments signature
/// verification.
#[must_use]
pub fn mldsa_provider() -> CryptoProvider {
    with_mldsa_verification(rustls::crypto::aws_lc_rs::default_provider())
}

/// Add ML-DSA-87 certificate verification to an existing provider, leaving
/// every other part of it untouched.
///
/// Use this to *compose* rather than replace. The `post-quantum` feature
/// customises `kx_groups` and this customises
/// `signature_verification_algorithms` — orthogonal fields of the same
/// provider — so a build with both must merge them into one value instead of
/// racing to call `install_default` twice (the second call always loses).
///
/// `base` must be an `aws-lc-rs`-backed provider: the ML-DSA algorithm is
/// implemented by aws-lc-rs, so pairing it with a `ring` provider would
/// produce a provider that advertises a scheme it cannot verify.
#[must_use]
pub fn with_mldsa_verification(base: CryptoProvider) -> CryptoProvider {
    CryptoProvider {
        signature_verification_algorithms: *MLDSA_SIG_ALGS,
        ..base
    }
}

/// Install [`mldsa_provider`] as the process-wide default crypto provider.
///
/// Must be called once, before any TLS operation. Every verifier built
/// afterwards — client and server, including federation and HTTP egress —
/// inherits the widened signature-verification set, so this is a
/// trust-policy change and should be gated behind an explicit operator opt-in.
///
/// # Errors
///
/// Returns an error if a crypto provider is already installed.
pub fn install_mldsa_provider() -> Result<()> {
    CryptoProvider::install_default(mldsa_provider()).map_err(|_| {
        RustgateError::from(ConfigError::Other(
            "crypto provider already installed".to_string(),
        ))
    })?;

    tracing::info!(
        scheme = "ML-DSA-87",
        fips = false,
        "ML-DSA certificate verification enabled — accepting ML-DSA-87 issuer signatures \
         in client-certificate chains (#501)"
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The augmented set must be a strict superset of the stock one: every
    /// classical algorithm still present, in its original relative order, with
    /// ML-DSA-87 appended last.
    #[test]
    fn augmented_set_is_stock_plus_mldsa_appended_last() {
        let base = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
        let augmented = *MLDSA_SIG_ALGS;

        assert_eq!(
            augmented.all.len(),
            base.all.len() + 1,
            "exactly one algorithm should be added to `all`"
        );
        assert_eq!(
            augmented.mapping.len(),
            base.mapping.len() + 1,
            "exactly one scheme should be added to `mapping`"
        );

        // Classical schemes keep their original order — this is the advertised
        // preference order, so a reordering would be a behaviour change.
        let base_schemes: Vec<_> = base.mapping.iter().map(|(s, _)| *s).collect();
        let augmented_schemes: Vec<_> = augmented.mapping.iter().map(|(s, _)| *s).collect();
        assert_eq!(
            &augmented_schemes[..base_schemes.len()],
            &base_schemes[..],
            "existing schemes must keep their relative order"
        );

        assert_eq!(
            augmented_schemes.last(),
            Some(&SignatureScheme::ML_DSA_87),
            "ML-DSA-87 must be last so it is not preferred over classical schemes"
        );
    }

    /// Pin the on-the-wire code point. rustls takes `ML_DSA_87 => 0x0906` from
    /// an IANA-registered draft, and it is what peers actually exchange in
    /// `signature_algorithms`; an upstream renumber would silently break
    /// interop with stacks that already shipped the registered value.
    ///
    /// (rustls also gates TLS 1.3 eligibility on these two bytes via a private
    /// denylist, which no public API exposes — that path is covered
    /// behaviourally by the `verify_tls13_signature` test in
    /// `tests/mldsa_certs.rs`.)
    #[test]
    fn mldsa_87_wire_code_point_is_0x0906() {
        assert_eq!(
            SignatureScheme::ML_DSA_87.to_array(),
            [0x09, 0x06],
            "ML-DSA-87 must keep its IANA-registered TLS code point"
        );
    }

    /// ML-DSA is not in the AWS-LC FIPS submission, and `CryptoProvider::fips`
    /// is an AND across every algorithm — so the augmented provider can never
    /// satisfy `--fips-required`. Pinned so it is a documented consequence
    /// rather than an operator surprise.
    #[test]
    fn augmented_provider_does_not_claim_fips() {
        assert!(
            !mldsa_provider().fips(),
            "augmented provider must not report FIPS mode"
        );
    }

    /// `LazyLock` must hand back the same leaked slices every time; a
    /// per-call `Vec::leak` would grow the heap without bound.
    #[test]
    fn provider_construction_does_not_leak_per_call() {
        let first = mldsa_provider().signature_verification_algorithms;
        let second = mldsa_provider().signature_verification_algorithms;
        assert!(
            std::ptr::eq(first.all, second.all),
            "`all` must be the same leaked allocation across calls"
        );
        assert!(
            std::ptr::eq(first.mapping, second.mapping),
            "`mapping` must be the same leaked allocation across calls"
        );
    }
}
