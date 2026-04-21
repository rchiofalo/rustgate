// Copyright © 2026 Roberto Chiofalo.

//! Enrollment-specific error types.

/// Errors that can occur during certificate enrollment.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("auth: {0}")]
    Auth(String),

    #[error("csr: {0}")]
    Csr(String),

    #[error("signing: {0}")]
    Signing(String),

    #[error("config: {0}")]
    Config(String),

    #[error("tls: {0}")]
    Tls(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    //! Display-shape and conversion tests for [`EnrollmentError`].
    //!
    //! `EnrollmentError` is the return type of every fallible path in
    //! `rustgate-enrollment` — auth, CSR decoding, signing, revocation,
    //! data-package serving, PKCS#12 building, EST endpoints, and the
    //! HTTP server glue. Each variant's Display prefix (`auth:`,
    //! `csr:`, `signing:`, `config:`, `tls:`, `io:`, `json:`) is the
    //! operator-facing grep token that distinguishes enrollment
    //! failures in the structured log trail and in the HTTP response
    //! body surfaced to the TAK client. A refactor that inlined the
    //! prefix out of the `thiserror` template (or flipped one variant
    //! to a different prefix) would silently change the runbook
    //! contract — SIEM filters and support scripts match on the raw
    //! `auth:` / `signing:` tokens, not on the variant name.
    //!
    //! The `#[from]` conversion paths (`io::Error`, `serde_json::Error`)
    //! are reached exclusively through `?` in every module that uses
    //! them — they're never constructed directly. Pinning these here
    //! catches a regression where the `#[from]` attribute is removed
    //! and callers silently stop auto-wrapping, routing raw I/O errors
    //! through an un-prefixed `anyhow`-style path instead.

    use std::error::Error as _;

    use super::*;

    #[test]
    fn auth_variant_displays_with_auth_prefix() {
        // The `auth:` prefix is the grep token for authentication
        // failures. `rustgate-enrollment` uses this on every invalid-
        // credentials reject; operators grep the audit stream for
        // `auth:` to count brute-force attempts across a sliding
        // window.
        let err = EnrollmentError::Auth("invalid credentials".into());
        let rendered = err.to_string();
        assert_eq!(
            rendered, "auth: invalid credentials",
            "auth variant Display must carry the exact `auth:` grep prefix"
        );
    }

    #[test]
    fn csr_variant_displays_with_csr_prefix() {
        // `csr:` is the triage token for certificate-signing-request
        // decoding and validation failures (bad PEM, tampered
        // signature, subject mismatches). Operators who see an
        // enrollment failure separate `csr:` from `signing:` to
        // distinguish "client sent garbage" from "our CA had a
        // problem."
        let err = EnrollmentError::Csr("bad PEM header".into());
        let rendered = err.to_string();
        assert_eq!(rendered, "csr: bad PEM header");
    }

    #[test]
    fn signing_variant_displays_with_signing_prefix() {
        // `signing:` identifies CA-side failures — rcgen internal
        // errors, private-key-load issues, or server-side policy
        // rejects inside `CsrSigner`. Distinguishing this from `csr:`
        // is the first-order triage signal in the enrollment runbook.
        let err = EnrollmentError::Signing("rcgen build error".into());
        let rendered = err.to_string();
        assert_eq!(rendered, "signing: rcgen build error");
    }

    #[test]
    fn config_variant_displays_with_config_prefix() {
        // `config:` covers startup-time configuration errors (missing
        // files, invalid TOML, incompatible options). Almost always
        // fatal — the server fails to start rather than surfacing
        // this at request time.
        let err = EnrollmentError::Config("missing ca_cert path".into());
        let rendered = err.to_string();
        assert_eq!(rendered, "config: missing ca_cert path");
    }

    #[test]
    fn tls_variant_displays_with_tls_prefix() {
        // `tls:` covers the enrollment server's own TLS setup
        // failures (rustls cert/key mismatches, cipher configuration
        // errors). Not to be confused with the *client* TLS handshake
        // failures audit — those go through `rustgate_core::audit`.
        let err = EnrollmentError::Tls("cert/key mismatch".into());
        let rendered = err.to_string();
        assert_eq!(rendered, "tls: cert/key mismatch");
    }

    #[test]
    fn io_variant_from_std_io_error_via_from_impl() {
        // `EnrollmentError::Io` is reached exclusively through the
        // `#[from] std::io::Error` conversion. Pinning the `?`-driven
        // path catches a regression where the `#[from]` attribute is
        // removed — the `?` fails to compile at every call site, but
        // if a helper masked that with a manual conversion we'd lose
        // the `io:` prefix token operators grep for.
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let err: EnrollmentError = source.into();
        match err {
            EnrollmentError::Io(_) => {}
            other => panic!("expected Io variant, got {other:?}"),
        }
    }

    #[test]
    fn io_variant_preserves_source_chain() {
        // `Error::source()` must walk to the original `io::Error` so
        // `tracing::error!` field formatting and `anyhow`-style
        // downcasts work downstream. Without the `#[source]` / `#[from]`
        // wiring, the chain would break at `EnrollmentError::Io` and
        // the underlying kind would be invisible in the log trail.
        let source = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: EnrollmentError = source.into();
        let chained = err
            .source()
            .expect("Io must expose its std::io::Error as source");
        let io_err = chained
            .downcast_ref::<std::io::Error>()
            .expect("source must downcast to std::io::Error");
        assert_eq!(io_err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn io_variant_display_prefixes_io_token() {
        // The Io variant's Display is `io: <inner>`. Pin the prefix so
        // a refactor that changed the template to drop the `io:`
        // sigil fails here — SIEM rules match on the literal `io:`
        // at the start of the line.
        let source = std::io::Error::other("disk full");
        let err: EnrollmentError = source.into();
        let rendered = err.to_string();
        assert!(
            rendered.starts_with("io:"),
            "Io Display must start with `io:` grep token: {rendered}"
        );
        assert!(
            rendered.contains("disk full"),
            "inner io::Error message must survive: {rendered}"
        );
    }

    #[test]
    fn json_variant_from_serde_error_via_from_impl() {
        // `EnrollmentError::Json` is reached through the
        // `#[from] serde_json::Error` blanket conversion, exercised
        // by the data-package manifest loader and the EST JSON
        // endpoints. Same rationale as the Io test.
        let source = serde_json::from_str::<serde_json::Value>("not json").expect_err("must fail");
        let err: EnrollmentError = source.into();
        match err {
            EnrollmentError::Json(_) => {}
            other => panic!("expected Json variant, got {other:?}"),
        }
    }

    #[test]
    fn json_variant_display_prefixes_json_token() {
        // Mirror of the Io Display-prefix test. `json:` is the SIEM
        // token operators use to count "malformed manifest" events
        // separately from transport-level I/O errors.
        let source =
            serde_json::from_str::<serde_json::Value>("{ not json").expect_err("must fail");
        let err: EnrollmentError = source.into();
        let rendered = err.to_string();
        assert!(
            rendered.starts_with("json:"),
            "Json Display must start with `json:` grep token: {rendered}"
        );
    }

    #[test]
    fn json_variant_preserves_source_chain() {
        // Keep the serde_json::Error reachable through `source()` so
        // downstream tracing layers can render the full line/column
        // detail serde produces. A regression that removed `#[from]`
        // (or wrapped the error in a stringified `Json(String)` like
        // the other variants) would break the chain and we'd ship
        // "json: invalid syntax" with no location information.
        let source = serde_json::from_str::<serde_json::Value>("not json").expect_err("must fail");
        let err: EnrollmentError = source.into();
        let chained = err
            .source()
            .expect("Json must expose its serde_json::Error as source");
        assert!(
            chained.downcast_ref::<serde_json::Error>().is_some(),
            "source must downcast to serde_json::Error"
        );
    }

    #[test]
    fn string_variants_do_not_expose_chainable_source() {
        // `Auth`, `Csr`, `Signing`, `Config`, `Tls` all wrap a plain
        // `String` — `std::error::Error::source` should return `None`
        // for each. This is the flip side of the Io/Json source-chain
        // tests: a refactor that "fixed" these variants to wrap a
        // typed error with `#[source]` would unexpectedly start
        // producing error chains, which changes the audit output
        // shape. Pin the current contract so that change is
        // deliberate rather than accidental.
        for err in [
            EnrollmentError::Auth("x".into()),
            EnrollmentError::Csr("x".into()),
            EnrollmentError::Signing("x".into()),
            EnrollmentError::Config("x".into()),
            EnrollmentError::Tls("x".into()),
        ] {
            assert!(
                err.source().is_none(),
                "{err:?} must not expose a source chain"
            );
        }
    }

    #[test]
    fn enrollment_error_is_send_and_sync() {
        // `EnrollmentError` flows through `axum` handlers, `tokio::
        // spawn` calls in the enrollment server, and `anyhow::Error`
        // conversions in the server binary. A future variant holding
        // a `!Send`/`!Sync` field would fail to compile in those
        // contexts; this assertion makes the failure local.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EnrollmentError>();
    }
}
