// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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

    #[test]
    fn all_error_enums_satisfy_error_send_sync_static_bound() {
        // Compile-time bound pin: every enum must satisfy the workspace-wide
        // `Box<dyn Error + Send + Sync + 'static>` contract that all spawned
        // tasks' Result returns and every `anyhow::Error::from(err)` call
        // site depend on. A refactor that embedded a non-`Send` field (e.g.
        // a raw `Rc`, `RefCell`, or a `&'a str` in a new variant) or a
        // non-`'static` borrow would break every downstream spawn site and
        // `thiserror`'s own blanket impls would silently stop compiling at
        // far-away call sites — the test traps the regression locally at
        // the bound-helper call rather than at the first `tokio::spawn`.
        fn assert_bounds<T: std::error::Error + Send + Sync + 'static>() {}
        assert_bounds::<TransportError>();
        assert_bounds::<ConfigError>();
        assert_bounds::<RustgateError>();
    }

    #[test]
    fn errors_coerce_to_dyn_error_trait_object() {
        // The trait-object coercion path is what every `tracing::error!(err
        // = %err, …)` macro invocation uses under the hood, and what
        // `anyhow::Error` relies on for its source-chain rendering. Pin the
        // coercion explicitly so a regression that narrowed one of the
        // error enums to not impl `std::error::Error` (e.g. by mistakenly
        // removing the `thiserror::Error` derive during a refactor) trips
        // here at a compile-failure on the coercion rather than at every
        // log call site in the binary.
        let t: TransportError = TransportError::NoCertificate;
        let c: ConfigError = ConfigError::Other("x".into());
        let r: RustgateError = TransportError::EmptyCertChain.into();
        let _as_dyn_t: &dyn std::error::Error = &t;
        let _as_dyn_c: &dyn std::error::Error = &c;
        let _as_dyn_r: &dyn std::error::Error = &r;
    }

    #[test]
    fn io_error_converts_to_rustgate_io_variant_not_transport_bind() {
        // `impl From<io::Error> for RustgateError` wires `?` at the top
        // level directly to `RustgateError::Io`, NOT to
        // `TransportError::Bind`. This is load-bearing: `TransportError::Bind`
        // carries the extra `addr: String` context that a bare `io::Error`
        // cannot supply, so auto-converting a top-level I/O error into
        // `Bind` would silently emit an empty-addr audit log at every
        // startup-time config-read failure. A refactor that "helpfully"
        // added `#[from] io::Error` to `TransportError::Bind` would break
        // this discrimination and bury the mistake until a deploy
        // reproduced the error path — pin it here.
        let io_err = io::Error::new(io::ErrorKind::NotFound, "missing file");
        let converted: RustgateError = io_err.into();
        match converted {
            RustgateError::Io(_) => {}
            other => panic!("expected RustgateError::Io, got {other:?}"),
        }
    }

    #[test]
    fn rustgate_error_source_chain_terminates_at_io_error_depth_two() {
        // `RustgateError::Transport(Bind { source: io })` has a two-hop
        // chain: the transparent top-level forwards to Bind's source
        // (the `io::Error`), which itself has no further source. A
        // regression that accidentally box-wrapped the io::Error inside
        // an extra layer would extend the chain to 3 and silently change
        // `anyhow::Error`'s default rendering (and break any downstream
        // matcher that walks the chain by count). Pin depth exactly.
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let inner = TransportError::Bind {
            addr: "0.0.0.0:0".into(),
            source: io_err,
        };
        let top: RustgateError = inner.into();
        let depth1 = top
            .source()
            .expect("Transport(Bind) must expose the io::Error source");
        let depth2 = depth1.source();
        assert!(
            depth2.is_none(),
            "chain must terminate after io::Error, got another layer: {depth2:?}"
        );
    }

    #[test]
    fn rustgate_io_preserves_io_error_kind_through_downcast() {
        // The `#[error("io: {0}")]` on `RustgateError::Io(#[from] io::Error)`
        // pins the Display prefix, but downstream consumers (store-forward
        // retry loop, CRL reloader backoff decision) match on the
        // underlying `io::ErrorKind` via `err.source().and_then(|e|
        // e.downcast_ref::<io::Error>()).map(|e| e.kind())`. Pin that the
        // kind round-trips: a regression that wrapped the io::Error in a
        // new error type (even one that preserved Display) would lose the
        // downcast and silently degrade every kind-specific retry
        // decision to the generic fallback.
        let io_err = io::Error::new(io::ErrorKind::WouldBlock, "try again");
        let wrapped: RustgateError = io_err.into();
        let src = wrapped.source().expect("Io must expose source");
        let downcast = src
            .downcast_ref::<io::Error>()
            .expect("source must downcast to io::Error");
        assert_eq!(downcast.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn transport_error_exhaustive_variant_match_pins_current_seven_variant_set() {
        // No-wildcard match through every current TransportError variant.
        // Adding a variant without updating downstream handlers would be
        // a silent drift (e.g. a new `TransportError::CertRevoked`
        // variant would slip through every existing `match transport_err`
        // site via a buried `_ =>` arm); this test forces the adder to
        // touch a spot where the reviewer is primed to audit the
        // corresponding audit-log-emitter / retry-classifier / operator-
        // facing-message-table updates.
        let variants = [
            TransportError::Bind {
                addr: "x".into(),
                source: io::Error::other("_"),
            },
            TransportError::TlsHandshake("_".into()),
            TransportError::NoCertificate,
            TransportError::EmptyCertChain,
            TransportError::MissingCommonName,
            TransportError::MissingKeyUsage {
                expected: "_".into(),
            },
            TransportError::Other("_".into()),
        ];
        for v in variants {
            let kind = match v {
                TransportError::Bind { .. } => "bind",
                TransportError::TlsHandshake(_) => "tls",
                TransportError::NoCertificate => "no-cert",
                TransportError::EmptyCertChain => "empty-chain",
                TransportError::MissingCommonName => "missing-cn",
                TransportError::MissingKeyUsage { .. } => "missing-eku",
                TransportError::Other(_) => "other",
            };
            assert!(!kind.is_empty(), "every variant must be handled");
        }
    }

    #[test]
    fn config_error_exhaustive_variant_match_pins_current_four_variant_set() {
        // Same shape as the TransportError exhaustive-match pin — pins
        // the closed-enum contract for the four ConfigError variants so
        // a new variant forces a compile failure here rather than slip
        // through a `_ =>` wildcard in the config-loader error handler.
        let variants = [
            ConfigError::PemParse {
                kind: "_".into(),
                reason: "_".into(),
            },
            ConfigError::EmptyPem { kind: "_".into() },
            ConfigError::TlsVersion {
                version: "_".into(),
            },
            ConfigError::Other("_".into()),
        ];
        for v in variants {
            let kind = match v {
                ConfigError::PemParse { .. } => "pem",
                ConfigError::EmptyPem { .. } => "empty",
                ConfigError::TlsVersion { .. } => "tls",
                ConfigError::Other(_) => "other",
            };
            assert!(!kind.is_empty(), "every variant must be handled");
        }
    }

    #[test]
    fn rustgate_error_exhaustive_variant_match_pins_current_three_variant_set() {
        // Same shape — pins the three-variant RustgateError closed-enum
        // contract. A new top-level variant (e.g. `Authz`) would slip
        // through every existing matcher via a buried `_ =>` arm; force
        // the adder to touch this spot where the reviewer is primed to
        // audit the top-level Display / From-conversion / audit-log-kind
        // updates.
        let variants = [
            RustgateError::Transport(TransportError::NoCertificate),
            RustgateError::Config(ConfigError::Other("_".into())),
            RustgateError::Io(io::Error::other("_")),
        ];
        for v in variants {
            let kind = match v {
                RustgateError::Transport(_) => "transport",
                RustgateError::Config(_) => "config",
                RustgateError::Io(_) => "io",
            };
            assert!(!kind.is_empty(), "every top-level variant must be handled");
        }
    }

    #[test]
    fn rustgate_from_transport_bind_preserves_addr_context() {
        // Pins that the transparent wrap through `From<TransportError>`
        // preserves the inner variant's field contents bit-for-bit
        // (specifically the `addr: String`). A refactor that
        // "normalized" the inner variant during the transparent wrap
        // (e.g. stripped a port for log-noise reduction) would break
        // the audit-log invariant that the bind-failure event carries
        // the exact addr the operator configured. The assertion
        // matches on the wrapped variant AND compares the addr string
        // verbatim.
        let inner = TransportError::Bind {
            addr: "192.0.2.1:4443".into(),
            source: io::Error::other("probe"),
        };
        let top: RustgateError = inner.into();
        match top {
            RustgateError::Transport(TransportError::Bind { addr, .. }) => {
                assert_eq!(
                    addr, "192.0.2.1:4443",
                    "addr must be preserved verbatim through From<TransportError>"
                );
            }
            other => panic!("expected Transport(Bind), got {other:?}"),
        }
    }

    #[test]
    fn result_alias_is_identical_to_std_result_with_rustgate_error() {
        // `pub type Result<T> = std::result::Result<T, RustgateError>` is
        // a type alias, not a newtype — the two spellings must be
        // interchangeable at every call site. Pin by assigning a value
        // of one spelling to a binding of the other WITHOUT any
        // conversion. A regression that changed the alias to a
        // wrapper struct would fail this compile-free assignment.
        let via_alias: Result<u32> = Ok(7);
        let via_std: std::result::Result<u32, RustgateError> = via_alias;
        match via_std {
            Ok(n) => assert_eq!(n, 7),
            Err(_) => panic!("expected Ok(7)"),
        }
        // And the reverse direction.
        let via_std: std::result::Result<u32, RustgateError> = Ok(9);
        let via_alias: Result<u32> = via_std;
        match via_alias {
            Ok(n) => assert_eq!(n, 9),
            Err(_) => panic!("expected Ok(9)"),
        }
    }
}
