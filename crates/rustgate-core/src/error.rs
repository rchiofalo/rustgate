// Copyright © 2026 Roberto Chiofalo.

//! Error types for rustgate.
//!
//! Provides structured error enums for transport and configuration failures,
//! replacing stringly-typed error variants with machine-matchable sub-errors.

/// Transport-layer errors.
///
/// Covers failures during socket binding, TLS handshake, certificate
/// validation, and identity extraction from X.509 certificates.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Failed to bind a listener to the specified address.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        /// The address that could not be bound.
        addr: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// TLS handshake did not complete successfully.
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    /// Peer did not present a client certificate during mTLS.
    #[error("no client certificate presented")]
    NoCertificate,

    /// Peer presented a certificate chain with zero entries.
    #[error("empty client certificate chain")]
    EmptyCertChain,

    /// Certificate subject is missing a Common Name (CN) field.
    #[error("certificate missing Common Name")]
    MissingCommonName,

    /// Certificate is missing a required Extended Key Usage extension.
    #[error("certificate missing required Extended Key Usage: {expected}")]
    MissingKeyUsage {
        /// The EKU purpose that was expected (e.g. `ClientAuth`).
        expected: String,
    },

    /// Catch-all for transport errors that do not yet have a dedicated variant.
    #[error("{0}")]
    Other(String),
}

/// Configuration-layer errors.
///
/// Covers failures when parsing PEM data, building TLS configurations,
/// and validating configuration values.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to parse PEM-encoded data (certificates, keys, CRLs).
    #[error("failed to parse {kind} PEM: {reason}")]
    PemParse {
        /// What was being parsed (e.g. `"certificate"`, `"CRL"`, `"private key"`).
        kind: String,
        /// The underlying parse error message.
        reason: String,
    },

    /// PEM data was valid but contained zero items of the expected kind.
    #[error("no {kind} found in PEM data")]
    EmptyPem {
        /// What was expected (e.g. `"certificates"`, `"CRLs"`).
        kind: String,
    },

    /// An unsupported TLS protocol version was requested.
    #[error("unsupported TLS version '{version}': expected '1.2' or '1.3'")]
    TlsVersion {
        /// The version string that was rejected.
        version: String,
    },

    /// Catch-all for configuration errors that do not yet have a dedicated variant.
    #[error("{0}")]
    Other(String),
}

/// Top-level error type for the rustgate crate.
#[derive(Debug, thiserror::Error)]
pub enum RustgateError {
    /// A transport-layer error (socket, TLS, certificate).
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// A configuration-layer error (PEM parsing, TLS config).
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// A raw I/O error not covered by the transport layer.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias used throughout the workspace.
pub type Result<T> = std::result::Result<T, RustgateError>;

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::error::Error as _;
    use std::io;

    use super::*;

    // ---- TransportError Display ----

    #[test]
    fn transport_bind_display_includes_addr_and_source() {
        let io_err = io::Error::new(io::ErrorKind::AddrInUse, "address already in use");
        let err = TransportError::Bind {
            addr: "127.0.0.1:4443".into(),
            source: io_err,
        };
        let msg = err.to_string();
        assert!(msg.contains("127.0.0.1:4443"), "addr missing: {msg}");
        assert!(
            msg.contains("address already in use"),
            "source missing: {msg}"
        );
        assert!(msg.starts_with("failed to bind"), "prefix wrong: {msg}");
    }

    #[test]
    fn transport_bind_exposes_source_via_error_trait() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "nope");
        let err = TransportError::Bind {
            addr: "0.0.0.0:80".into(),
            source: io_err,
        };
        // thiserror wires #[source] on the field named `source` automatically.
        let src = err.source().expect("Bind must expose its io::Error source");
        assert!(
            src.downcast_ref::<io::Error>().is_some(),
            "source should be io::Error"
        );
    }

    #[test]
    fn transport_tls_handshake_display_contains_reason() {
        let err = TransportError::TlsHandshake("cert expired".into());
        assert_eq!(err.to_string(), "TLS handshake failed: cert expired");
    }

    #[test]
    fn transport_no_certificate_display_is_static() {
        assert_eq!(
            TransportError::NoCertificate.to_string(),
            "no client certificate presented"
        );
    }

    #[test]
    fn transport_empty_cert_chain_display_is_static() {
        assert_eq!(
            TransportError::EmptyCertChain.to_string(),
            "empty client certificate chain"
        );
    }

    #[test]
    fn transport_missing_common_name_display_is_static() {
        assert_eq!(
            TransportError::MissingCommonName.to_string(),
            "certificate missing Common Name"
        );
    }

    #[test]
    fn transport_missing_key_usage_display_includes_expected() {
        let err = TransportError::MissingKeyUsage {
            expected: "ClientAuth".into(),
        };
        assert_eq!(
            err.to_string(),
            "certificate missing required Extended Key Usage: ClientAuth"
        );
    }

    #[test]
    fn transport_other_display_is_passthrough() {
        // `#[error("{0}")]` means Other wraps a free-form string verbatim.
        let err = TransportError::Other("weird thing".into());
        assert_eq!(err.to_string(), "weird thing");
    }

    #[test]
    fn transport_other_empty_string_is_empty_display() {
        let err = TransportError::Other(String::new());
        assert_eq!(err.to_string(), "");
    }

    #[test]
    fn transport_variants_without_source_return_none_source() {
        // None of the static variants wrap an #[source] field, so Error::source
        // must return None.
        assert!(TransportError::NoCertificate.source().is_none());
        assert!(TransportError::EmptyCertChain.source().is_none());
        assert!(TransportError::MissingCommonName.source().is_none());
        assert!(TransportError::TlsHandshake("x".into()).source().is_none());
        assert!(
            TransportError::MissingKeyUsage {
                expected: "x".into()
            }
            .source()
            .is_none()
        );
        assert!(TransportError::Other("x".into()).source().is_none());
    }

    #[test]
    fn transport_debug_contains_variant_name() {
        // Debug is derived; pin that the variant name is present so logs can
        // identify the kind without needing Display.
        let err = TransportError::NoCertificate;
        assert!(
            format!("{err:?}").contains("NoCertificate"),
            "debug repr missing variant name"
        );
    }

    // ---- ConfigError Display ----

    #[test]
    fn config_pem_parse_display_includes_kind_and_reason() {
        let err = ConfigError::PemParse {
            kind: "certificate".into(),
            reason: "unexpected header".into(),
        };
        assert_eq!(
            err.to_string(),
            "failed to parse certificate PEM: unexpected header"
        );
    }

    #[test]
    fn config_empty_pem_display_includes_kind() {
        let err = ConfigError::EmptyPem {
            kind: "CRLs".into(),
        };
        assert_eq!(err.to_string(), "no CRLs found in PEM data");
    }

    #[test]
    fn config_tls_version_display_matches_expected_text() {
        // This variant's message is operator-facing guidance — pin the exact
        // text so we notice if a rewrite drops the allowed-values hint.
        let err = ConfigError::TlsVersion {
            version: "1.1".into(),
        };
        assert_eq!(
            err.to_string(),
            "unsupported TLS version '1.1': expected '1.2' or '1.3'"
        );
    }

    #[test]
    fn config_other_display_is_passthrough() {
        let err = ConfigError::Other("legacy message".into());
        assert_eq!(err.to_string(), "legacy message");
    }

    #[test]
    fn config_variants_have_no_source() {
        assert!(
            ConfigError::PemParse {
                kind: "k".into(),
                reason: "r".into()
            }
            .source()
            .is_none()
        );
        assert!(
            ConfigError::EmptyPem { kind: "k".into() }
                .source()
                .is_none()
        );
        assert!(
            ConfigError::TlsVersion {
                version: "v".into()
            }
            .source()
            .is_none()
        );
        assert!(ConfigError::Other("x".into()).source().is_none());
    }

    // ---- RustgateError From / transparent ----

    #[test]
    fn rustgate_from_transport_is_transparent_display() {
        // #[error(transparent)] on Transport: Display must equal the inner
        // error's Display exactly, not something like "transport: …".
        let inner = TransportError::NoCertificate;
        let expected = inner.to_string();
        let wrapped: RustgateError = inner.into();
        assert_eq!(wrapped.to_string(), expected);
    }

    #[test]
    fn rustgate_from_config_is_transparent_display() {
        let inner = ConfigError::EmptyPem {
            kind: "certificates".into(),
        };
        let expected = inner.to_string();
        let wrapped: RustgateError = inner.into();
        assert_eq!(wrapped.to_string(), expected);
    }

    #[test]
    fn rustgate_from_io_error_prefixes_with_io() {
        // #[error("io: {0}")] — the Io variant is NOT transparent; it prefixes.
        let io_err = io::Error::new(io::ErrorKind::NotFound, "missing file");
        let err: RustgateError = io_err.into();
        assert_eq!(err.to_string(), "io: missing file");
    }

    #[test]
    fn rustgate_transparent_forwards_source_to_inner_chain() {
        // `#[error(transparent)]` forwards source() to the inner's source(),
        // it does NOT return the inner itself as the source. So for a
        // TransportError::Bind (which has an io::Error #[source]), the
        // top-level RustgateError::source() must bottom out at the io::Error.
        let io_err = io::Error::new(io::ErrorKind::AddrInUse, "already bound");
        let inner = TransportError::Bind {
            addr: "127.0.0.1:0".into(),
            source: io_err,
        };
        let wrapped: RustgateError = inner.into();
        let src = wrapped
            .source()
            .expect("transparent should forward to inner's io::Error source");
        assert!(
            src.downcast_ref::<io::Error>().is_some(),
            "forwarded source should be the io::Error"
        );
        assert_eq!(src.to_string(), "already bound");
    }

    #[test]
    fn rustgate_transparent_returns_none_when_inner_has_no_source() {
        // Pin the other half of the transparent contract: when the wrapped
        // variant has no #[source] (e.g. TlsHandshake holds just a String),
        // source() returns None all the way up — not Some(inner).
        let wrapped: RustgateError = TransportError::TlsHandshake("boom".into()).into();
        assert!(
            wrapped.source().is_none(),
            "transparent should return None, not wrap the inner"
        );

        let wrapped: RustgateError = ConfigError::Other("x".into()).into();
        assert!(
            wrapped.source().is_none(),
            "transparent Config with no inner #[source] must also return None"
        );
    }

    #[test]
    fn rustgate_from_io_exposes_io_error_as_source() {
        // #[from] on the Io variant still wires Error::source to the inner.
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe gone");
        let err: RustgateError = io_err.into();
        let src = err.source().expect("Io variant should expose source");
        assert!(
            src.downcast_ref::<io::Error>().is_some(),
            "Io source should be downcastable to io::Error"
        );
    }

    #[test]
    fn rustgate_question_mark_propagates_transport_error() {
        // Verify `?` works by constructing a Result<_, RustgateError> via
        // From<TransportError> and matching on the wrapped variant.
        fn inner() -> std::result::Result<(), TransportError> {
            Err(TransportError::MissingCommonName)
        }
        fn outer() -> Result<()> {
            inner()?;
            Ok(())
        }
        match outer() {
            Err(RustgateError::Transport(TransportError::MissingCommonName)) => {}
            other => panic!("expected Transport(MissingCommonName), got {other:?}"),
        }
    }

    #[test]
    fn rustgate_question_mark_propagates_config_error() {
        fn inner() -> std::result::Result<(), ConfigError> {
            Err(ConfigError::TlsVersion {
                version: "0".into(),
            })
        }
        fn outer() -> Result<()> {
            inner()?;
            Ok(())
        }
        match outer() {
            Err(RustgateError::Config(ConfigError::TlsVersion { version })) => {
                assert_eq!(version, "0");
            }
            other => panic!("expected Config(TlsVersion), got {other:?}"),
        }
    }

    #[test]
    fn rustgate_question_mark_propagates_io_error() {
        fn inner() -> std::result::Result<(), io::Error> {
            Err(io::Error::other("bang"))
        }
        fn outer() -> Result<()> {
            inner()?;
            Ok(())
        }
        match outer() {
            Err(RustgateError::Io(e)) => {
                assert_eq!(e.to_string(), "bang");
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn rustgate_debug_contains_variant_name() {
        let err: RustgateError = TransportError::EmptyCertChain.into();
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Transport"), "Debug missing variant: {dbg}");
    }

    #[test]
    fn result_alias_round_trip() {
        // Pin that `Result<T>` really is `std::result::Result<T, RustgateError>`
        // by passing a RustgateError through it.
        fn make_ok() -> Result<u32> {
            Ok(42)
        }
        fn make_err() -> Result<u32> {
            Err(TransportError::NoCertificate.into())
        }
        assert_eq!(make_ok().unwrap(), 42);
        match make_err() {
            Err(RustgateError::Transport(TransportError::NoCertificate)) => {}
            other => panic!("expected Transport(NoCertificate), got {other:?}"),
        }
    }
}
