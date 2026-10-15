// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Process-wide rustls crypto provider fallback.
//!
//! `reqwest` is built without a provider of its own (ADR 0037), so building
//! a client panics if no process-wide default is installed. `rustgate-server`
//! installs one at startup; library callers and tests may not, so every
//! place that builds a `reqwest` client calls [`ensure_default`] first.

/// Install the aws-lc-rs provider as the process default if none is
/// installed yet.
///
/// An already-installed provider, such as the one `rustgate-server` builds
/// from `--kx-groups`, is left alone. Under `--features fips` the provider
/// installed here is the FIPS one, because `rustls/fips` changes what
/// `aws_lc_rs::default_provider()` returns.
pub fn ensure_default() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // A concurrent caller may win the race; either way a provider is
        // installed afterwards, which is all this function promises.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_a_provider_and_is_idempotent() {
        ensure_default();
        let first = rustls::crypto::CryptoProvider::get_default().map(std::sync::Arc::as_ptr);
        assert!(first.is_some());
        ensure_default();
        let second = rustls::crypto::CryptoProvider::get_default().map(std::sync::Arc::as_ptr);
        assert_eq!(first, second);
    }
}
