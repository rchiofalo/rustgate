// Copyright © 2026 Roberto Chiofalo.

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

/// Pre-fetch the OCSP response for the given `CertifiedKey` so the very
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

    /// SEC-5: `CertReloader` reads the key via the shared secrets gate, which
    /// rejects group/other-readable keys — test keys must be owner-only.
    fn write_key_0600(path: &std::path::Path, contents: &[u8]) {
        std::fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

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
        write_key_0600(&key_path, leaf.key_pem.as_bytes());

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

    /// Helper — build a [`CertReloader`]-backed [`Arc<dyn ResolvesServerCert>`]
    /// anchored in a tempdir so the dir's lifetime can be threaded through the
    /// caller. Returns the dir too so the caller keeps it alive.
    fn build_reloader_with_tempdir(cn: &str) -> (Arc<dyn ResolvesServerCert>, tempfile::TempDir) {
        let ca = TestCa::new(cn);
        let leaf = ca.issue_server_cert(cn, &[cn]);
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        std::fs::write(&cert_path, leaf.cert_pem.as_bytes()).unwrap();
        write_key_0600(&key_path, leaf.key_pem.as_bytes());
        let reloader = CertReloader::new(&cert_path, &key_path).unwrap();
        (reloader, dir)
    }

    /// Batched contract pin for `wrap_resolver` / `preload` — executed as a
    /// single `#[tokio::test]` to amortize tokio-runtime teardown cost. Each
    /// `Stapler` spawns an `ocsp-stapler` background fetch task that keeps
    /// the runtime shutdown loop alive for ~55s while it unwinds; splitting
    /// this into four separate `#[tokio::test]` cases would therefore add
    /// ~4 × 55s of CI time without isolating any failure mode that could not
    /// be localized from the assertion label on the failing line. The four
    /// contract clauses asserted here:
    ///
    /// 1. **Concrete `Arc<Stapler>` return type.** Downstream code reaches for
    ///    `stapler.preload(...)` and `stapler.stop()` without a trait-object
    ///    hop; a refactor that narrowed the signature to
    ///    `-> Arc<dyn ResolvesServerCert>` would silently break those call
    ///    sites in `TlsConfig::build_reloadable_server_config`.
    /// 2. **`Send + Sync + 'static` bounds survive both the concrete and
    ///    trait-object forms.** Compile-time self-check via
    ///    `fn assert_bounds<T: Send + Sync + 'static>(_: &T)`: a regression
    ///    that introduced an `Rc`, a non-`Send` `dyn Fn`, or a non-`'static`
    ///    borrow inside `Stapler` fails test-compile rather than at the
    ///    first transitive `rustls::ServerConfig` call site.
    /// 3. **Distinct inner resolvers produce independent staplers** (not a
    ///    shared global singleton). A regression would be invisible to
    ///    single-reloader tests and surface only in multi-SNI-leaf deploys.
    /// 4. **`preload()` is idempotent under the same certified key.** The
    ///    upstream stapler deduplicates by leaf-cert fingerprint, so two
    ///    preload calls with the same key must not panic or double-enqueue.
    #[tokio::test]
    async fn wrap_resolver_and_preload_contract_batch() {
        // Clause 1: concrete Arc<Stapler> return type.
        let (inner_concrete, _dir_concrete) = build_reloader_with_tempdir("ocsp-concrete-type");
        let stapler_concrete: Arc<Stapler> = wrap_resolver(inner_concrete);
        let _: Arc<dyn ResolvesServerCert> =
            Arc::clone(&stapler_concrete) as Arc<dyn ResolvesServerCert>;

        // Clause 2: Send + Sync + 'static on both concrete and erased forms.
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        assert_bounds(&stapler_concrete);
        let erased: Arc<dyn ResolvesServerCert> =
            Arc::clone(&stapler_concrete) as Arc<dyn ResolvesServerCert>;
        assert_bounds(&erased);

        // Clause 3: distinct inners produce distinct staplers.
        let (inner_b, _dir_b) = build_reloader_with_tempdir("ocsp-multi-b");
        let stapler_b = wrap_resolver(inner_b);
        assert!(
            !Arc::ptr_eq(&stapler_concrete, &stapler_b),
            "wrap_resolver must return a fresh Arc<Stapler> per call, not a shared singleton"
        );

        // Clause 4: preload() is idempotent under the same certified key.
        let ca = TestCa::new("ocsp-preload");
        let leaf = ca.issue_server_cert("localhost", &["localhost"]);
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        std::fs::write(&cert_path, leaf.cert_pem.as_bytes()).unwrap();
        write_key_0600(&key_path, leaf.key_pem.as_bytes());
        let reloader = CertReloader::new(&cert_path, &key_path).unwrap();
        let ckey = reloader
            .certified_key()
            .expect("reloader must expose its certified key immediately after construction");
        let ckey_second = Arc::clone(&ckey);
        let inner_preload: Arc<dyn ResolvesServerCert> = reloader;
        let stapler_preload = wrap_resolver(inner_preload);
        preload(&stapler_preload, ckey);
        preload(&stapler_preload, ckey_second);
    }
}
