// Copyright © 2026 Roberto Chiofalo.

//! PEM parsing helpers — re-exported from [`rustgate_core::pem`].
//!
//! This module used to own the `parse_certs` / `parse_key` /
//! `parse_ca_store` helpers. They now live in [`rustgate_core::pem`] so
//! `rustgate-client`, `rustgate-federation`, and `rustgate-enrollment`
//! can share the same error mapping. This module stays as a thin facade
//! for backward compatibility with existing imports.
//!
//! New callers should import directly from `rustgate_core::pem`.

pub use rustgate_core::pem::{parse_ca_store, parse_certs, parse_key};

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    //! Facade coverage — the exhaustive parsing behaviour lives in
    //! `rustgate_core::pem`. Here we only pin the public re-export
    //! surface: a silent upstream rename or accidental removal of one
    //! of the three helpers must fail this build, not produce a stale
    //! import that breaks downstream crates (`rustgate-client` and
    //! integration tests still reach for `rustgate_transport::pem::…`).
    use rustgate_test_utils::certs::TestCa;
    use rustls_pki_types::PrivateKeyDer;

    use super::{parse_ca_store, parse_certs, parse_key};

    #[test]
    fn facade_parses_ca_cert_pem() {
        let ca = TestCa::new("facade-ca");
        let certs = parse_certs(ca.cert_pem.as_bytes()).expect("CA cert PEM must parse");
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn facade_parses_client_cert_and_key() {
        let ca = TestCa::new("facade-ca");
        let client = ca.issue_client_cert("facade-client", &["users"]);

        let certs = parse_certs(client.cert_pem.as_bytes()).expect("client cert PEM must parse");
        assert_eq!(certs.len(), 1);

        let key = parse_key(client.key_pem.as_bytes()).expect("client key PEM must parse");
        assert!(
            matches!(key, PrivateKeyDer::Pkcs8(_)),
            "rcgen emits PKCS#8; re-export must round-trip it"
        );
    }

    #[test]
    fn facade_builds_ca_store() {
        let ca = TestCa::new("facade-ca");
        let store = parse_ca_store(ca.cert_pem.as_bytes()).expect("CA PEM must build store");
        assert_eq!(store.len(), 1);
    }
}
