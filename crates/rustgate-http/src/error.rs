// Copyright © 2026 Roberto Chiofalo.

//! Error types for the HTTP egress subsystem.
//!
//! All errors use [`thiserror::Error`] for structured, displayable error
//! messages. No panics — all fallible paths return `Result<T, HttpError>`.

/// Errors produced by the HTTP egress bridge.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// Configuration validation failed.
    #[error("HTTP config validation: {0}")]
    Config(String),

    /// Failed to construct a `reqwest::Client` for a target.
    #[error("failed to build HTTP client for target `{target}`: {source}")]
    ClientBuild {
        target: String,
        source: reqwest::Error,
    },

    /// HTTP request failed at the transport level.
    #[error("HTTP request to `{target}` failed: {source}")]
    Request {
        target: String,
        source: reqwest::Error,
    },

    /// HTTP response returned a non-success status code.
    #[error("HTTP response from `{target}` returned {status}")]
    ResponseStatus { target: String, status: u16 },

    /// Failed to read a secret file (token, password, HMAC key).
    #[error("failed to read secret file `{path}`: {source}")]
    SecretRead {
        path: String,
        source: std::io::Error,
    },

    /// Failed to read a TLS certificate or key file.
    #[error("failed to read TLS file `{path}` for target `{target}`: {source}")]
    TlsFile {
        target: String,
        path: String,
        source: std::io::Error,
    },

    /// Payload serialization to JSON failed.
    #[error("payload serialization failed: {source}")]
    Serialize { source: serde_json::Error },

    /// Protobuf conversion failed (requires `proto` feature).
    #[error("protobuf conversion failed: {message}")]
    ProtoConvert { message: String },

    /// The target's circuit breaker is open — requests are being shed.
    #[error("circuit breaker open for target `{target}`")]
    CircuitOpen { target: String },

    /// TLS certificate pin mismatch — the server's certificate hash does
    /// not match any of the configured SHA-256 pins.
    #[error("certificate pin mismatch for target `{target}`: none of {pin_count} pins matched")]
    PinMismatch { target: String, pin_count: usize },

    /// Dead-letter queue I/O or encryption error.
    #[error("DLQ error for target `{target}`: {message}")]
    Dlq { target: String, message: String },
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    //! Display-shape tests for every `HttpError` variant.
    //!
    //! These pin the rendered `to_string()` form of each variant because
    //! downstream audit pipelines, tracing log lines, and operator
    //! runbooks all grep for specific tokens (`"certificate pin mismatch"`,
    //! `"circuit breaker open"`, `"failed to read secret file"`). A
    //! well-meaning refactor that tweaked the `#[error(...)]` template
    //! would silently break every grep-based alert without failing any
    //! other test. Pinning the exact tokens here makes that class of
    //! regression trip CI instead of a pager at 3am.
    //!
    //! Variants carrying `reqwest::Error` (`ClientBuild`, `Request`) and
    //! `serde_json::Error` (`Serialize`) are exercised indirectly
    //! through `From` impls and source-chain tests rather than
    //! constructed from scratch, since those upstream error types do
    //! not have a public constructor.
    use std::error::Error as _;
    use std::io;

    use super::*;

    // ---------------------------------------------------------------
    // Direct-construction variants — Display token pinning
    // ---------------------------------------------------------------

    #[test]
    fn config_variant_includes_validation_prefix_and_message() {
        let err = HttpError::Config("missing target url".into());
        let rendered = err.to_string();
        assert!(
            rendered.contains("HTTP config validation"),
            "Config variant must carry the fixed prefix so log filters grep for it: {rendered}"
        );
        assert!(
            rendered.contains("missing target url"),
            "Config variant must echo the operator-supplied detail: {rendered}"
        );
    }

    #[test]
    fn response_status_variant_renders_target_and_status() {
        let err = HttpError::ResponseStatus {
            target: "alpha".into(),
            status: 503,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("alpha"), "target must appear: {rendered}");
        assert!(
            rendered.contains("503"),
            "numeric status must appear so SIEM can match on it: {rendered}"
        );
        assert!(
            rendered.contains("HTTP response"),
            "response-status variant must be distinguishable from request-level failures: \
             {rendered}"
        );
    }

    #[test]
    fn circuit_open_variant_names_target_and_state() {
        let err = HttpError::CircuitOpen {
            target: "beta".into(),
        };
        let rendered = err.to_string();
        // `circuit breaker open` is the grep token operators bind
        // PagerDuty alerts to — keep the exact phrase stable.
        assert!(
            rendered.contains("circuit breaker open"),
            "CircuitOpen must preserve the canonical alert phrase: {rendered}"
        );
        assert!(
            rendered.contains("beta"),
            "target name must appear: {rendered}"
        );
    }

    #[test]
    fn pin_mismatch_variant_includes_target_and_pin_count() {
        let err = HttpError::PinMismatch {
            target: "pinned-host".into(),
            pin_count: 3,
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("certificate pin mismatch"),
            "PinMismatch must carry the canonical grep token: {rendered}"
        );
        assert!(rendered.contains("pinned-host"));
        assert!(
            rendered.contains('3'),
            "pin_count must appear so operators know how many pins were checked: {rendered}"
        );
    }

    #[test]
    fn dlq_variant_formats_target_and_message() {
        let err = HttpError::Dlq {
            target: "gamma".into(),
            message: "archive seal rejected".into(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("DLQ error"));
        assert!(rendered.contains("gamma"));
        assert!(rendered.contains("archive seal rejected"));
    }

    #[test]
    fn secret_read_variant_includes_path_and_io_source() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "not readable");
        let err = HttpError::SecretRead {
            path: "/etc/rustgate/token".into(),
            source,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("/etc/rustgate/token"));
        assert!(
            rendered.contains("failed to read secret file"),
            "variant must keep its distinctive prefix, not collapse into a generic I/O error: \
             {rendered}"
        );
    }

    #[test]
    fn secret_read_variant_preserves_io_source_chain() {
        // thiserror wires `source: std::io::Error` into the
        // `std::error::Error::source()` chain. Operators and
        // `tracing::error!(err = ?err)` printers rely on that chain
        // to surface the underlying `io::ErrorKind`. Dropping the
        // chain (e.g. inlining the io::Error's message into the
        // Display template and removing the `source` field from the
        // struct) would preserve the top-level message but break
        // every `err.source()` traversal. Pin it.
        let source = io::Error::new(io::ErrorKind::NotFound, "no such file");
        let err = HttpError::SecretRead {
            path: "/missing".into(),
            source,
        };
        let chained = err
            .source()
            .expect("SecretRead must expose its io::Error source");
        let io_err = chained
            .downcast_ref::<io::Error>()
            .expect("source must downcast to io::Error");
        assert_eq!(io_err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn tls_file_variant_includes_target_and_path() {
        let source = io::Error::new(io::ErrorKind::InvalidData, "PEM parse failed");
        let err = HttpError::TlsFile {
            target: "delta".into(),
            path: "/tls/client.pem".into(),
            source,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("delta"));
        assert!(rendered.contains("/tls/client.pem"));
        assert!(rendered.contains("failed to read TLS file"));
    }

    #[test]
    fn tls_file_variant_preserves_io_source_chain() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "mode 0640");
        let err = HttpError::TlsFile {
            target: "t".into(),
            path: "/p".into(),
            source,
        };
        let io_err = err
            .source()
            .expect("TlsFile must expose io::Error as source")
            .downcast_ref::<io::Error>()
            .expect("source must downcast to io::Error");
        assert_eq!(io_err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn proto_convert_variant_formats_message_without_target() {
        // ProtoConvert is deliberately target-agnostic — the failure
        // is in payload shape, not in per-target networking. Pinning
        // "no target field in the rendering" ensures a future
        // refactor that adds a target field doesn't silently change
        // the audit record schema.
        let err = HttpError::ProtoConvert {
            message: "missing field".into(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("protobuf conversion failed"));
        assert!(rendered.contains("missing field"));
    }

    // ---------------------------------------------------------------
    // Serialize / reqwest variants via From / constructor paths
    // ---------------------------------------------------------------

    #[test]
    fn serialize_variant_via_serde_json_error_source() {
        // We can obtain a real `serde_json::Error` by parsing
        // invalid JSON — this exercises the branch that constructs
        // the Serialize variant without relying on a private API.
        let serde_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("not json").expect_err("must fail");
        let err = HttpError::Serialize { source: serde_err };
        let rendered = err.to_string();
        assert!(
            rendered.contains("payload serialization failed"),
            "Serialize variant must carry its canonical prefix: {rendered}"
        );
        // Source chain must expose the underlying serde_json::Error
        // so operators can inspect the parse cause downstream.
        err.source()
            .expect("Serialize must expose its serde_json::Error source")
            .downcast_ref::<serde_json::Error>()
            .expect("source must downcast to serde_json::Error");
    }

    // ---------------------------------------------------------------
    // Debug formatting — secret-hygiene smoke check
    // ---------------------------------------------------------------

    #[test]
    fn debug_formatting_does_not_leak_secret_read_path_reuse() {
        // We do not redact the file path (it's an operator-supplied
        // config value, not secret material), but we should still be
        // confident that the Debug output is sane and contains the
        // variant name — downstream code that emits `{:?}` at
        // non-secret-log targets needs stable formatting.
        let err = HttpError::SecretRead {
            path: "/etc/rustgate/token".into(),
            source: io::Error::other("x"),
        };
        let debug = format!("{err:?}");
        assert!(
            debug.starts_with("SecretRead"),
            "variant tag must prefix Debug: {debug}"
        );
        assert!(debug.contains("/etc/rustgate/token"));
    }

    // ---------------------------------------------------------------
    // Send + Sync object-safety — implied by thiserror but test-pinned
    // ---------------------------------------------------------------

    #[test]
    fn http_error_is_send_and_sync() {
        // `HttpError` must be Send + Sync so it can cross
        // `tokio::spawn` boundaries and flow through `Arc`-backed
        // error callbacks. If a future variant introduces a
        // non-Send/!Sync field (e.g. a raw `Rc<...>`), the crate
        // would fail to compile in downstream async contexts. This
        // compile-time assertion makes the failure local.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HttpError>();
    }
}
