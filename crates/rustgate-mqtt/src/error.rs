// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! MQTT-specific error types with protocol reason code mapping.

/// Errors that can occur during MQTT session handling.
#[derive(Debug, thiserror::Error)]
pub enum MqttError {
    /// The client sent an unsupported protocol version.
    #[error("unsupported protocol version: {0}")]
    UnsupportedProtocol(u8),

    /// The client requested persistent sessions (clean_session=false).
    #[error("persistent sessions are not supported")]
    PersistentSessionUnsupported,

    /// The will message specified an unauthorized topic.
    ///
    /// Per MQTT 5.0 §3.1.2.5 the will payload is published by the broker on
    /// behalf of the client when the connection ends ungracefully — so the
    /// will must pass the same authorization gate as a live `PUBLISH`. A
    /// will targeting a group the client is not a member of is rejected at
    /// CONNECT time before the session is admitted.
    #[error("will message rejected: {0}")]
    WillRejected(String),

    /// The client attempted QoS 2, which is not supported in v1.
    #[error("QoS 2 (exactly-once) is not supported")]
    Qos2Unsupported,

    /// The client is not authorized for the requested topic/action.
    #[error("not authorized for topic: {0}")]
    NotAuthorized(String),

    /// The topic failed validation (wildcards, invalid characters, etc.).
    #[error("invalid topic: {0}")]
    InvalidTopic(String),

    /// A packet exceeded the maximum allowed size.
    #[error("packet too large: {size} bytes exceeds {max} byte limit")]
    PacketTooLarge { size: usize, max: usize },

    /// The client sent a v5 PUBLISH with a Topic Alias outside the
    /// `[1, advertised_max]` range, or referenced an alias that has
    /// not yet been established. MQTT 5.0 §3.3.2.3.4: this is a
    /// Protocol Error and the broker MUST send DISCONNECT with reason
    /// code 0x94 (TopicAliasInvalid) before closing the connection.
    /// `alias=0` is the spec-reserved value and always triggers this
    /// variant. Surfaced from the read loop so the session-end handler
    /// can emit the matching v5 DISCONNECT before tearing down the
    /// stream.
    #[error("topic alias {alias} invalid (max {max})")]
    TopicAliasInvalid { alias: u16, max: u16 },

    /// The client sent a malformed packet.
    #[error("malformed packet: {0}")]
    Malformed(String),

    /// The CONNECT packet was not the first packet on the connection.
    #[error("expected CONNECT as first packet")]
    ConnectExpected,

    /// The MQTT client ID is already in use by a different mTLS identity.
    #[error("client ID `{0}` is already in use by another identity")]
    ClientIdInUse(String),

    /// The keep-alive timer expired without receiving any packet.
    #[error("keep-alive timeout ({0}s)")]
    KeepAliveTimeout(u16),

    /// An I/O error on the underlying TLS stream.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::io;

    use super::*;

    // -----------------------------------------------------------------
    // Display messages — pin the operator-facing text for every variant
    // so a thiserror refactor cannot silently change log / diagnostic
    // output. Every MQTT session error is rendered into either a
    // disconnect reason code or an audit/tracing field, so the exact
    // string shape matters.
    // -----------------------------------------------------------------

    #[test]
    fn display_unsupported_protocol_includes_version_byte() {
        assert_eq!(
            MqttError::UnsupportedProtocol(3).to_string(),
            "unsupported protocol version: 3",
        );
    }

    #[test]
    fn display_persistent_session_unsupported_is_stable() {
        assert_eq!(
            MqttError::PersistentSessionUnsupported.to_string(),
            "persistent sessions are not supported",
        );
    }

    #[test]
    fn display_will_rejected_quotes_reason() {
        assert_eq!(
            MqttError::WillRejected("not authorized for topic 'bravo'".to_string()).to_string(),
            "will message rejected: not authorized for topic 'bravo'",
        );
    }

    #[test]
    fn display_qos2_unsupported_is_stable() {
        assert_eq!(
            MqttError::Qos2Unsupported.to_string(),
            "QoS 2 (exactly-once) is not supported",
        );
    }

    #[test]
    fn display_not_authorized_quotes_topic() {
        assert_eq!(
            MqttError::NotAuthorized("fleet/alpha".to_string()).to_string(),
            "not authorized for topic: fleet/alpha",
        );
    }

    #[test]
    fn display_invalid_topic_quotes_topic() {
        assert_eq!(
            MqttError::InvalidTopic("bad/#/topic".to_string()).to_string(),
            "invalid topic: bad/#/topic",
        );
    }

    #[test]
    fn display_packet_too_large_includes_size_and_max() {
        assert_eq!(
            MqttError::PacketTooLarge {
                size: 20_000_000,
                max: 16_777_216,
            }
            .to_string(),
            "packet too large: 20000000 bytes exceeds 16777216 byte limit",
        );
    }

    #[test]
    fn display_malformed_packet_includes_reason() {
        assert_eq!(
            MqttError::Malformed("truncated variable header".to_string()).to_string(),
            "malformed packet: truncated variable header",
        );
    }

    #[test]
    fn display_connect_expected_is_stable() {
        assert_eq!(
            MqttError::ConnectExpected.to_string(),
            "expected CONNECT as first packet",
        );
    }

    #[test]
    fn display_client_id_in_use_quotes_id() {
        // The back-tick wrapping is important: it makes the ID visually
        // distinct in logs when the ID contains spaces or unusual
        // characters, which reduces operator confusion when diagnosing
        // a takeover attempt.
        assert_eq!(
            MqttError::ClientIdInUse("tak-client-42".to_string()).to_string(),
            "client ID `tak-client-42` is already in use by another identity",
        );
    }

    #[test]
    fn display_keep_alive_timeout_includes_seconds() {
        assert_eq!(
            MqttError::KeepAliveTimeout(90).to_string(),
            "keep-alive timeout (90s)",
        );
    }

    #[test]
    fn display_io_includes_inner_message() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "peer went away");
        let err = MqttError::from(io_err);
        // The inner Display of `io::Error` is appended as `{0}`.
        assert_eq!(err.to_string(), "I/O error: peer went away");
    }

    // -----------------------------------------------------------------
    // Conversions & trait bounds
    // -----------------------------------------------------------------

    #[test]
    fn from_io_error_maps_to_io_variant() {
        // The `#[from]` attribute on `Io(#[from] std::io::Error)` means
        // any `io::Error` should lift into `MqttError::Io` transparently
        // (used on the session hot path via `?`).
        let io_err = io::Error::from(io::ErrorKind::TimedOut);
        let err: MqttError = io_err.into();
        match err {
            MqttError::Io(inner) => assert_eq!(inner.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected MqttError::Io, got {other:?}"),
        }
    }

    #[test]
    fn mqtt_error_implements_std_error() {
        // Pin the trait bound so downstream `Box<dyn std::error::Error>`
        // boxing (used by the session layer when funnelling errors into
        // `anyhow` contexts) keeps compiling.
        fn assert_std_error<E: std::error::Error>() {}
        assert_std_error::<MqttError>();
    }

    #[test]
    fn mqtt_error_is_send_sync() {
        // Errors are routed across task boundaries when the session's
        // `tokio::spawn`-ed read/write halves converge on a shutdown;
        // losing Send/Sync would silently break that compile-time
        // invariant.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MqttError>();
    }

    #[test]
    fn debug_impl_renders_variant_name() {
        // `Debug` ends up in `tracing::error!(?err, …)` emissions —
        // stabilise that the variant name is present so log-grepping
        // for `ClientIdInUse` finds the relevant records.
        let err = MqttError::ClientIdInUse("abc".to_string());
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("ClientIdInUse"),
            "Debug should name the variant; got {rendered}",
        );
    }

    // -----------------------------------------------------------------
    // Error::source() contract — pins `#[from]`-driven chaining so
    // downstream `anyhow::Context::context()` chains render inner IO
    // errors in operator-facing output. The non-Io variants must
    // return `None` so the log chain stops there, rather than
    // accidentally inheriting a misleading cause.
    // -----------------------------------------------------------------

    #[test]
    fn io_variant_source_returns_inner_io_error() {
        use std::error::Error as _;
        // `#[error("I/O error: {0}")]` + `Io(#[from] std::io::Error)`
        // is the only variant that should chain through `source()`.
        // A regression that dropped the `#[source]` behaviour of
        // `#[from]` (or swapped the template to `{source}` without
        // the `#[source]` marker) would silently break the chain,
        // and every `anyhow::context`-wrapped caller would lose the
        // inner io::Error from its Display chain.
        let io_err = io::Error::new(io::ErrorKind::ConnectionAborted, "reset by peer");
        let wrapped: MqttError = io_err.into();
        let src = wrapped
            .source()
            .expect("Io variant must chain to its inner io::Error");
        // The source is the io::Error; its Display should match the
        // original message.
        assert!(
            src.to_string().contains("reset by peer"),
            "source() must delegate to inner io::Error's Display: {}",
            src
        );
    }

    #[test]
    fn non_io_variants_return_none_from_source() {
        use std::error::Error as _;
        // Every variant other than `Io` is self-contained (no
        // `#[source]` / `#[from]` field), so `Error::source()` must
        // return `None`. A regression that added `#[source]` to a
        // non-Io variant (for example, bolting an inner cause onto
        // `Malformed` without updating this test) would silently
        // extend every operator-facing error chain.
        let cases = [
            MqttError::UnsupportedProtocol(3),
            MqttError::PersistentSessionUnsupported,
            MqttError::WillRejected("t".into()),
            MqttError::Qos2Unsupported,
            MqttError::NotAuthorized("t".into()),
            MqttError::InvalidTopic("t".into()),
            MqttError::PacketTooLarge { size: 1, max: 2 },
            MqttError::Malformed("m".into()),
            MqttError::ConnectExpected,
            MqttError::ClientIdInUse("i".into()),
            MqttError::KeepAliveTimeout(30),
        ];
        for err in &cases {
            assert!(
                err.source().is_none(),
                "variant {err:?} must NOT chain a source (got {:?})",
                err.source()
            );
        }
    }

    #[test]
    fn mqtt_error_is_static_bound() {
        // The enum has no lifetime parameters and carries only owned
        // data (`u8`, `u16`, `usize`, `String`, `io::Error`), so it
        // must satisfy the `'static` bound. Downstream callers box
        // `MqttError` as `Box<dyn std::error::Error + Send + Sync +
        // 'static>` (the shape `anyhow::Error::new` wants) and a
        // regression that introduced a borrowed field (e.g. `&str`
        // instead of `String` on `Malformed`) would fail here with a
        // pointed error rather than at the far-away boxing site.
        fn assert_static<T: 'static>() {}
        assert_static::<MqttError>();
    }

    // -----------------------------------------------------------------
    // Full-variant Debug sweep — the existing single-variant test
    // pins `ClientIdInUse`, but every variant ends up in
    // `tracing::error!(?err, …)` at least one call site. Operators
    // grep on variant names to filter log streams, so a
    // `thiserror::Debug` regression that elided a variant would
    // silently break alerting without breaking anything else.
    // -----------------------------------------------------------------

    #[test]
    fn debug_names_every_variant_when_present_in_log_stream() {
        let cases: [(MqttError, &str); 12] = [
            (MqttError::UnsupportedProtocol(3), "UnsupportedProtocol"),
            (
                MqttError::PersistentSessionUnsupported,
                "PersistentSessionUnsupported",
            ),
            (MqttError::WillRejected("t".into()), "WillRejected"),
            (MqttError::Qos2Unsupported, "Qos2Unsupported"),
            (MqttError::NotAuthorized("t".into()), "NotAuthorized"),
            (MqttError::InvalidTopic("t".into()), "InvalidTopic"),
            (
                MqttError::PacketTooLarge { size: 1, max: 2 },
                "PacketTooLarge",
            ),
            (MqttError::Malformed("m".into()), "Malformed"),
            (MqttError::ConnectExpected, "ConnectExpected"),
            (MqttError::ClientIdInUse("i".into()), "ClientIdInUse"),
            (MqttError::KeepAliveTimeout(30), "KeepAliveTimeout"),
            (MqttError::Io(io::Error::from(io::ErrorKind::Other)), "Io"),
        ];
        for (err, expected) in &cases {
            let rendered = format!("{err:?}");
            assert!(
                rendered.contains(expected),
                "Debug for {err:?} must contain variant name {expected:?}: {rendered}"
            );
        }
    }

    // -----------------------------------------------------------------
    // Boundary-value rendering — pins that Display templates do not
    // panic or truncate at the integer type boundaries. `u8::MAX` in
    // `UnsupportedProtocol`, `u16::MAX` in `KeepAliveTimeout`, and
    // `usize::MAX` in both fields of `PacketTooLarge` are the inputs
    // an adversary can actually produce on a hostile connection.
    // -----------------------------------------------------------------

    #[test]
    fn unsupported_protocol_zero_and_max_render_exactly() {
        // `0` is what a truncated / empty CONNECT packet might produce
        // once parsed into a u8; `255` is the signed-byte boundary.
        // A regression that used a template like `{0:02}` (zero-pad)
        // or `{0:x}` (hex) would silently change operator-facing text
        // and break SIEM regex rules.
        assert_eq!(
            MqttError::UnsupportedProtocol(0).to_string(),
            "unsupported protocol version: 0",
        );
        assert_eq!(
            MqttError::UnsupportedProtocol(u8::MAX).to_string(),
            "unsupported protocol version: 255",
        );
    }

    #[test]
    fn keep_alive_timeout_at_u16_max_renders_exactly() {
        // A hostile or buggy client can advertise `u16::MAX` seconds
        // (just over 18 hours) and the render must survive that
        // without allocating a garbage truncated string.
        assert_eq!(
            MqttError::KeepAliveTimeout(u16::MAX).to_string(),
            "keep-alive timeout (65535s)",
        );
    }

    #[test]
    fn packet_too_large_at_usize_max_renders_exactly() {
        // On a 64-bit host `usize::MAX` is 20 digits (18_446_744_073_
        // 709_551_615). Rendering this in the size / max fields must
        // succeed without allocating a doubled / truncated string —
        // a refactor that switched to `fmt::LowerHex` or used
        // arithmetic (e.g. a human-readable "GiB" renderer) on the
        // size field would change the log shape and break SIEM rules.
        let err = MqttError::PacketTooLarge {
            size: usize::MAX,
            max: usize::MAX,
        };
        let rendered = err.to_string();
        // Assert the exact digit form for both fields.
        assert!(
            rendered.contains(&usize::MAX.to_string()),
            "Display must render usize::MAX literal: {rendered}"
        );
        assert!(rendered.starts_with("packet too large: "));
        assert!(rendered.ends_with(" byte limit"));
    }

    // -----------------------------------------------------------------
    // Empty-payload Display defence — `String`-carrying variants must
    // still render without producing garbage when the payload is
    // empty (e.g. an adversary-supplied CONNECT with a zero-length
    // Malformed reason, or a topic filter that normalises to empty).
    // -----------------------------------------------------------------

    #[test]
    fn string_variants_tolerate_empty_payload_without_panicking() {
        // Each variant's template appends `{0}` after a trailing
        // separator. With an empty payload the trailing character
        // stays in place (no silent trimming). Pin that every
        // string-carrying Display template survives the empty-string
        // input and renders the static prefix verbatim.
        assert_eq!(
            MqttError::NotAuthorized(String::new()).to_string(),
            "not authorized for topic: ",
        );
        assert_eq!(
            MqttError::InvalidTopic(String::new()).to_string(),
            "invalid topic: ",
        );
        assert_eq!(
            MqttError::Malformed(String::new()).to_string(),
            "malformed packet: ",
        );
        assert_eq!(
            MqttError::ClientIdInUse(String::new()).to_string(),
            "client ID `` is already in use by another identity",
        );
    }

    // -----------------------------------------------------------------
    // Exhaustiveness pin — the enum is deliberately NOT
    // `#[non_exhaustive]`, so the reason-code mapper in
    // `crate::session` can `match` on every variant without a
    // wildcard arm and rely on the compiler to flag a missed variant
    // when a future variant is added. An exhaustive match here
    // compiles iff the enum carries the same 12 variants as the
    // mapper sees, guarding against a variant added to the enum but
    // not to the mapper (or vice-versa).
    // -----------------------------------------------------------------

    #[test]
    fn error_enum_exhaustive_match_compiles_with_no_wildcard() {
        // The match is purely for its compile-time exhaustiveness
        // check — the runtime assertion is tautological. A future
        // variant added to `MqttError` without `#[non_exhaustive]`
        // would force the new variant to be handled here, directing
        // the maintainer to the downstream reason-code mapper.
        fn classify(err: &MqttError) -> &'static str {
            match err {
                MqttError::UnsupportedProtocol(_) => "unsupported_protocol",
                MqttError::PersistentSessionUnsupported => "persistent_session",
                MqttError::WillRejected(_) => "will_rejected",
                MqttError::Qos2Unsupported => "qos2",
                MqttError::NotAuthorized(_) => "not_authorized",
                MqttError::InvalidTopic(_) => "invalid_topic",
                MqttError::PacketTooLarge { .. } => "packet_too_large",
                MqttError::TopicAliasInvalid { .. } => "topic_alias_invalid",
                MqttError::Malformed(_) => "malformed",
                MqttError::ConnectExpected => "connect_expected",
                MqttError::ClientIdInUse(_) => "client_id_in_use",
                MqttError::KeepAliveTimeout(_) => "keepalive_timeout",
                MqttError::Io(_) => "io",
            }
        }
        assert_eq!(
            classify(&MqttError::ConnectExpected),
            "connect_expected",
            "sanity check that the mapping executes at all"
        );
    }

    // -----------------------------------------------------------------
    // Io round-trip — pins that the `ErrorKind` survives the `From`
    // conversion intact. A regression that remapped the inner
    // io::Error's kind (e.g. collapsing every kind to `Other`) would
    // silently break every upstream `if err.kind() ==
    // ConnectionReset`-style branch that funnels MQTT session drops
    // into the appropriate audit event.
    // -----------------------------------------------------------------

    #[test]
    fn io_variant_preserves_error_kind_through_from_conversion() {
        let kinds = [
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::WouldBlock,
        ];
        for kind in kinds {
            let err: MqttError = io::Error::from(kind).into();
            match err {
                MqttError::Io(inner) => assert_eq!(
                    inner.kind(),
                    kind,
                    "kind must survive From<io::Error> conversion unchanged"
                ),
                other => panic!("expected MqttError::Io for kind {kind:?}, got {other:?}"),
            }
        }
    }
}
