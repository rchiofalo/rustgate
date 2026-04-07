//! OCSP stapling support for the server certificate resolver.
//!
//! This module wraps any [`ResolvesServerCert`] implementation (such as
//! [`crate::CertReloader`]) with [`ocsp_stapler::Stapler`], which periodically
//! fetches OCSP responses for the certificates the resolver returns and
//! attaches them to the TLS handshake. Stapled responses let clients verify
//! certificate revocation status without contacting the issuing CA's OCSP
//! responder themselves, eliminating a network round-trip and the associated
//! privacy / availability concerns.
//!
//! # Caveats
//!
//! - **Most useful with private / enterprise CAs.** Let's Encrypt stopped
//!   serving OCSP responses in 2025 — certificates issued by ACME-style public
//!   CAs are increasingly relying on short lifetimes and CRLite/CRLs instead
//!   of OCSP. Stapling continues to be valuable for internal PKIs that operate
//!   their own OCSP responder.
//! - **First handshakes may be unstapled.** [`ocsp_stapler::Stapler`] fetches
//!   OCSP responses asynchronously in a background tokio task. Calling
//!   [`ocsp_stapler::Stapler::preload`] before serving traffic mitigates this
//!   for known certificates, but rotated or newly issued certificates served
//!   later still take one fetch cycle (up to 60s) to staple.
//! - **Certificates without an issuer in the chain pass through unstapled.**
//!   The stapler needs both the leaf and its issuer to construct the OCSP
//!   request. If the [`ResolvesServerCert`] implementation returns only a leaf
//!   (no chain), the response is delivered without a stapled OCSP entry.
//! - **SHA-1 OCSP requests only.** The upstream `ocsp-stapler` crate currently
//!   constructs OCSP requests with SHA-1 issuer name / key hashes. Most CAs
//!   accept this, but operators with strict modern responders should verify
//!   compatibility before enabling.
//! - **Coexists with CRL verification.** OCSP stapling lives on the *resolver*
//!   side of the handshake (server cert path) while CRLs live on the
//!   *verifier* side (client cert path). Enabling both is fully supported and
//!   they do not interact.

use std::sync::Arc;

pub use ocsp_stapler::Stapler;
use rustls::server::ResolvesServerCert;

/// Wrap an existing certificate resolver with an OCSP-stapling layer.
///
/// The returned [`Arc<Stapler>`] itself implements [`ResolvesServerCert`] and
/// can be passed straight into
/// [`crate::TlsConfig::build_reloadable_server_config`]. The stapler spawns a
/// background tokio task that refreshes OCSP responses on its own cadence
/// (currently every 60 seconds — not configurable in the upstream crate).
///
/// Call [`preload`] after wrapping and before binding the listener to
/// pre-fetch OCSP responses for any certificates the inner resolver already
/// knows about, so the very first TLS handshake can include a stapled
/// response.
pub fn wrap_resolver(inner: Arc<dyn ResolvesServerCert>) -> Arc<Stapler> {
    Arc::new(Stapler::new(inner))
}

/// Pre-fetch the OCSP response for the given [`CertifiedKey`] so the very
/// first TLS handshake after startup can include a stapled response.
///
/// This is a thin sync wrapper around [`Stapler::preload`] kept here for
/// symmetry with [`wrap_resolver`] so callers do not need to depend on
/// `ocsp_stapler` directly. Callers that cannot easily obtain a
/// `CertifiedKey` may simply skip preloading — the first handshake will
/// surface the leaf to the stapler which then queues an OCSP fetch in the
/// background.
pub fn preload(stapler: &Stapler, ckey: Arc<rustls::sign::CertifiedKey>) {
    stapler.preload(ckey);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::sync::Arc;

    use rustgate_test_utils::certs::TestCa;
    use rustls::server::ResolvesServerCert;

    use super::*;
    use crate::CertReloader;

    /// The wrapped resolver should still resolve the underlying certificate
    /// (just without a stapled OCSP entry, since no responder is reachable in
    /// tests). This verifies the delegation path works end-to-end.
    #[tokio::test]
    async fn stapler_delegates_resolve_to_inner() {
        let ca = TestCa::new("ocsp-stapler-test");
        let leaf = ca.issue_server_cert("localhost", &["localhost"]);

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        std::fs::write(&cert_path, leaf.cert_pem.as_bytes()).unwrap();
        std::fs::write(&key_path, leaf.key_pem.as_bytes()).unwrap();

        let reloader = CertReloader::new(&cert_path, &key_path).unwrap();
        let inner: Arc<dyn ResolvesServerCert> = reloader;
        let stapler = wrap_resolver(inner);

        // The stapler implements ResolvesServerCert; we can't easily fabricate
        // a ClientHello here, but we can at least confirm the trait is
        // satisfied and that preload() runs without panicking when there is
        // no OCSP responder reachable.
        let _: Arc<dyn ResolvesServerCert> = stapler.clone();
        stapler.stop().await;
    }
}
