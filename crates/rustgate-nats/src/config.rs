// Copyright © 2026 Roberto Chiofalo.

//! NATS connection configuration.

use std::hash::{BuildHasher, Hasher};
use std::path::PathBuf;
use std::process;

/// TLS configuration for mTLS connections to the NATS broker.
#[derive(Debug, Clone, Default)]
pub struct NatsTlsConfig {
    /// Path to the client certificate PEM file.
    pub client_cert: Option<PathBuf>,

    /// Path to the client private key PEM file.
    pub client_key: Option<PathBuf>,

    /// Path to the CA certificate PEM file for verifying the NATS server.
    pub ca_cert: Option<PathBuf>,

    /// When true, TLS is required for the NATS connection.
    /// If set but no certificates are provided, connection will fail.
    pub required: bool,
}

impl NatsTlsConfig {
    /// Returns true if client certificate and key are both configured.
    pub fn has_client_auth(&self) -> bool {
        self.client_cert.is_some() && self.client_key.is_some()
    }

    /// Validate that the TLS configuration is consistent.
    ///
    /// Returns an error if TLS is required but no certificates are provided,
    /// or if only one of cert/key is specified without the other.
    pub fn validate(&self) -> Result<(), NatsTlsConfigError> {
        // If cert is provided, key must also be provided (and vice versa)
        if self.client_cert.is_some() != self.client_key.is_some() {
            return Err(NatsTlsConfigError::IncompleteClientAuth);
        }

        // If TLS is required, at least CA or client certs should be configured
        if self.required && self.ca_cert.is_none() && !self.has_client_auth() {
            return Err(NatsTlsConfigError::RequiredButNoCerts);
        }

        Ok(())
    }
}

/// Errors from validating NATS TLS configuration.
#[derive(Debug, thiserror::Error)]
pub enum NatsTlsConfigError {
    /// TLS is required but no certificates were provided.
    #[error(
        "NATS TLS is required but no certificates were provided (set RUSTGATE_NATS_TLS_CERT, RUSTGATE_NATS_TLS_KEY, and/or RUSTGATE_NATS_TLS_CA)"
    )]
    RequiredButNoCerts,

    /// Only one of client cert or key was provided.
    #[error("both RUSTGATE_NATS_TLS_CERT and RUSTGATE_NATS_TLS_KEY must be provided together")]
    IncompleteClientAuth,
}

/// Configuration for the NATS adapter.
#[derive(Debug, Clone)]
pub struct NatsConfig {
    /// NATS server URL (e.g., "nats://localhost:4222").
    pub url: String,

    /// Optional NATS credentials file path for JWT/NKey auth.
    pub credentials_file: Option<String>,

    /// TLS/mTLS configuration for the NATS broker connection.
    pub tls: NatsTlsConfig,

    /// Subject prefix for point updates (default: "points").
    pub subject_prefix: String,

    /// JetStream stream name for history replay (default: "TRACKS_HISTORY").
    pub jetstream_stream: String,

    /// JetStream subject prefix for history (default: "TRACKS.HISTORY").
    pub jetstream_subject_prefix: String,

    /// Default group name when identity has no groups (default: "__ANON__").
    pub default_group: String,

    /// Maximum NATS message payload size to deserialize (default: 256 KB).
    /// Messages larger than this are dropped as a defense-in-depth measure
    /// against resource exhaustion. NATS servers enforce their own max_payload
    /// (default 1 MB), but this provides an additional application-level guard.
    pub max_payload_bytes: usize,

    /// Maximum number of messages to replay from JetStream on startup.
    /// Limits memory consumption during SA bootstrap. 0 = unlimited.
    pub max_replay_count: usize,

    /// Instance ID for echo prevention. Auto-generated if not set.
    pub instance_id: String,

    /// Internal buffer capacity for each NATS subscription.
    ///
    /// Controls how many messages can be buffered before the subscriber
    /// exerts backpressure on the NATS server. When the buffer is full,
    /// the NATS client triggers a slow consumer event. Default: 1024.
    pub subscription_capacity: usize,

    /// JetStream stream name for live updates (default: "RUSTGATE_LIVE").
    ///
    /// The subscriber creates this stream (if it doesn't already exist) to
    /// capture messages on `{subject_prefix}.>` via a durable pull consumer,
    /// providing real backpressure instead of buffered push subscriptions.
    pub live_stream: String,

    /// Maximum number of unacknowledged messages for the pull consumer
    /// (default: 1000).
    ///
    /// Controls concurrency: the server will not deliver more than this
    /// many messages until earlier ones are acknowledged.
    pub max_ack_pending: i64,

    /// Maximum number of JetStream delivery attempts for any single
    /// message before the consumer gives up and advances past it
    /// (default: `5` — the workspace poison-message handling standard).
    ///
    /// Defense-in-depth against poison messages: if processing panics
    /// mid-handler or the task is cancelled between receive and ACK, the
    /// message would otherwise redeliver indefinitely. A positive value
    /// caps that redelivery loop so a single bad message cannot wedge
    /// the consumer. Operators can watch for the
    /// `$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES.*.*` advisory subject
    /// (emitted by the NATS server on each give-up) if they want an
    /// alerting signal — this crate does not subscribe to it here.
    ///
    /// **Behaviour change.** Pre-#883-sub3 the default was `0`, which
    /// JetStream interprets as "use the server default of unlimited
    /// redelivery". Operators upgrading from a pre-#883 build now see
    /// the consumer give up after five attempts on a persistently-
    /// failing message; the audit event `nats.poison_dlq` fires on the
    /// give-up so SIEM tooling can alert. Set explicitly to `0` (or
    /// any non-positive value) to opt back into the legacy unlimited-
    /// redelivery semantics — useful for legacy migrations where a
    /// JetStream stream contains records the operator wants to keep
    /// retrying indefinitely while they fix the upstream producer.
    ///
    /// Five attempts is the workspace poison-message standard: large
    /// enough to survive a transient pod restart, small enough that a
    /// persistently-failing message drops within a few seconds of re-
    /// delivery intervals.
    pub max_deliver: i64,

    /// Optional path for JetStream replay checkpoint file.
    /// When set, stores the last processed sequence number so
    /// subsequent restarts resume from the checkpoint.
    pub checkpoint_path: Option<PathBuf>,

    /// Optional subject on which to run a NATS request/reply responder.
    ///
    /// When set to `Some(subject)`, callers that build a
    /// [`crate::request::NatsRequestResponder`] via
    /// [`crate::NatsAdapter::request_responder`] will subscribe here and
    /// dispatch incoming requests to the supplied handler. When `None`,
    /// no responder is wired and `request_responder` returns `None`.
    ///
    /// The subject is validated like [`subject_prefix`] — multi-level
    /// subjects (`rustgate.ops.status`) are allowed, but wildcards
    /// (`*`, `>`) are rejected because a responder subscribes to one
    /// concrete subject. Operators who want multiple endpoints should
    /// configure several responders, each with its own subject.
    ///
    /// [`subject_prefix`]: Self::subject_prefix
    pub request_subject: Option<String>,

    /// Optional subject to republish poison messages before they are ACKed.
    ///
    /// When a subscriber receives a message it cannot process locally — the
    /// payload is oversized, the JSON is unparseable, the position is the
    /// CoT "unknown" sentinel, or the identity fails validation — it must
    /// still ACK so the pull consumer can advance past the stuck sequence.
    /// Silently swallowing those bytes is the current behaviour, which means
    /// operators have no way to inspect what the upstream producer sent.
    ///
    /// When this field is `Some(subject)`, the subscriber publishes the
    /// original payload to that subject (with diagnostic headers: reason,
    /// original subject, millis-since-epoch timestamp) before ACKing the
    /// poison message. The payload is forwarded unchanged — whatever
    /// garbage arrived is exactly what operators will see on the DLQ.
    ///
    /// **Best-effort.** A failed DLQ publish is logged at `warn` but does
    /// NOT block the ACK of the original message — blocking would defeat
    /// the whole point of giving up on the stuck sequence and could wedge
    /// the consumer on transient NATS publish errors.
    ///
    /// **Loop prevention.** The DLQ subject MUST NOT start with
    /// `{subject_prefix}.`. The live stream captures that entire namespace
    /// with a `{subject_prefix}.>` wildcard; a DLQ subject inside that
    /// namespace would be recaptured, redelivered, re-classified as poison,
    /// republished to DLQ, and so on indefinitely. Operators who want the
    /// DLQ archived into a JetStream stream should configure a second
    /// stream on a disjoint subject (e.g. `rustgate.dlq`).
    ///
    /// Wildcards (`*`, `>`) are rejected for the same reason as
    /// `subject_prefix` — the publisher writes to one concrete subject.
    pub dead_letter_subject: Option<String>,

    /// Optional narrow-subscribe filters for the JetStream pull consumer.
    ///
    /// When empty (default), the consumer subscribes to the full
    /// `{subject_prefix}.>` wildcard — every message the stream captures
    /// is delivered to this instance, even if it will be shed downstream
    /// by group-based ACL filtering. That's fine for low-volume or
    /// single-tenant deployments, but in high-volume fleets where a
    /// given subscriber only cares about a subset of groups or message
    /// kinds, the server-side work of matching every subject against
    /// the consumer is wasted.
    ///
    /// When non-empty, each entry is passed directly to JetStream as a
    /// `filter_subject` / `filter_subjects` (one vs many). NATS wildcards
    /// (`*` single-token, `>` tail) are supported — e.g. `points.ALPHA.>`
    /// or `points.*.position` — which is why these patterns bypass the
    /// "no wildcards" rule that applies to `subject_prefix` itself.
    ///
    /// **Safety rail:** every entry must start with `{subject_prefix}.`
    /// so a filter cannot silently escape the stream's subject space
    /// and produce an always-empty consumer. Validation also rejects
    /// empty strings, control characters, whitespace, and non-ASCII
    /// bytes — the same hardening that protects `subject_prefix`.
    ///
    /// Requires NATS server 2.10 or newer for the multi-pattern form
    /// (`filter_subjects`). The single-pattern form (`filter_subject`)
    /// works on older servers too, but the `async-nats` crate is built
    /// with `server_2_10` enabled workspace-wide so both wires are
    /// available unconditionally here.
    pub subject_filters: Vec<String>,
}

impl NatsConfig {
    /// Validate the NATS configuration.
    ///
    /// Checks that `subject_prefix`, `jetstream_subject_prefix`, and
    /// `default_group` do not contain NATS wildcards (`*`, `>`) or
    /// control characters that could cause subject injection.
    pub fn validate(&self) -> Result<(), NatsConfigError> {
        validate_nats_subject_prefix(&self.subject_prefix, "subject_prefix")?;
        validate_nats_subject_prefix(&self.jetstream_subject_prefix, "jetstream_subject_prefix")?;
        validate_nats_subject_token(&self.default_group, "default_group")?;
        // Optional: request/reply responder subject (issue #907b). When
        // unset, no responder is wired. When set, the same rules apply
        // as for `subject_prefix`: dots allowed for multi-level
        // subjects, wildcards rejected because the responder subscribes
        // to one concrete subject.
        if let Some(ref subject) = self.request_subject {
            validate_nats_subject_prefix(subject, "request_subject")?;
        }
        if let Some(ref dlq) = self.dead_letter_subject {
            validate_nats_subject_prefix(dlq, "dead_letter_subject")?;
            // Loop-prevention safety rail: the live stream captures
            // `{subject_prefix}.>`. If the DLQ subject lives inside that
            // namespace, every DLQ publish is immediately recaptured,
            // redelivered, re-classified as poison, and republished —
            // producing an unbounded feedback loop that wedges the
            // consumer on one poisoned payload. Reject at validate() time
            // rather than discover this in production.
            let stream_prefix = format!("{}.", self.subject_prefix);
            if dlq.starts_with(&stream_prefix) {
                return Err(NatsConfigError::InvalidSubject {
                    field: "dead_letter_subject".to_string(),
                    reason: format!(
                        "`{dlq}` is inside the live-stream subject space `{stream_prefix}>` — \
                         DLQ traffic would be recaptured and redelivered, producing an infinite \
                         loop. Choose a subject outside the `{stream_prefix}` namespace."
                    ),
                });
            }
        }
        validate_subject_filters(&self.subject_filters, &self.subject_prefix)?;
        self.tls.validate().map_err(NatsConfigError::Tls)?;
        Ok(())
    }
}

/// Validate `NatsConfig::subject_filters`.
///
/// Unlike [`validate_nats_subject_prefix`], wildcards (`*`, `>`) are
/// permitted — they are the whole point of a filter. Each pattern must
/// still be ASCII-printable, non-empty, and scoped to `{subject_prefix}.`
/// so the consumer cannot silently bind to subjects the stream does
/// not capture.
fn validate_subject_filters(filters: &[String], prefix: &str) -> Result<(), NatsConfigError> {
    if filters.is_empty() {
        return Ok(());
    }
    // Match the exact byte sequence that `ensure_stream` asks JetStream
    // to capture — any filter that escapes this prefix would bind to an
    // always-empty subject set and silently drop all traffic.
    let required_prefix = format!("{prefix}.");
    for (idx, pattern) in filters.iter().enumerate() {
        if pattern.is_empty() {
            return Err(NatsConfigError::InvalidSubject {
                field: format!("subject_filters[{idx}]"),
                reason: "must not be empty".to_string(),
            });
        }
        for b in pattern.bytes() {
            // Reject control chars, whitespace, DEL (0x7F), and non-ASCII.
            // `*` and `>` are allowed so NATS wildcards can be expressed.
            if b <= 0x20 || b >= 0x7F {
                return Err(NatsConfigError::InvalidSubject {
                    field: format!("subject_filters[{idx}]"),
                    reason: format!(
                        "contains invalid byte 0x{b:02X}; control characters, \
                         whitespace, and non-ASCII are not allowed"
                    ),
                });
            }
        }
        if !pattern.starts_with(&required_prefix) {
            return Err(NatsConfigError::InvalidSubject {
                field: format!("subject_filters[{idx}]"),
                reason: format!(
                    "`{pattern}` must start with `{required_prefix}` so the \
                     filter stays within the stream's subject space"
                ),
            });
        }
    }
    Ok(())
}

/// Validate a NATS subject prefix (may contain `.` level separators).
///
/// Rejects wildcards (`*`, `>`), control characters, spaces, and
/// non-ASCII bytes. The `.` separator is allowed since prefixes like
/// `"TRACKS.HISTORY"` are valid multi-level subjects.
fn validate_nats_subject_prefix(s: &str, field: &str) -> Result<(), NatsConfigError> {
    if s.is_empty() {
        return Err(NatsConfigError::InvalidSubject {
            field: field.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    for b in s.bytes() {
        if b <= 0x20 || b >= 0x7F || matches!(b, b'>' | b'*') {
            return Err(NatsConfigError::InvalidSubject {
                field: field.to_string(),
                reason: format!(
                    "contains invalid byte 0x{b:02X}; wildcards (*, >), \
                     control characters, and non-ASCII are not allowed"
                ),
            });
        }
    }
    Ok(())
}

/// Validate a single NATS subject token (no `.` separators allowed).
fn validate_nats_subject_token(s: &str, field: &str) -> Result<(), NatsConfigError> {
    if s.is_empty() {
        return Err(NatsConfigError::InvalidSubject {
            field: field.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    for b in s.bytes() {
        if b <= 0x20 || b >= 0x7F || matches!(b, b'.' | b'>' | b'*') {
            return Err(NatsConfigError::InvalidSubject {
                field: field.to_string(),
                reason: format!(
                    "contains invalid byte 0x{b:02X}; wildcards (*, >), dots, \
                     control characters, and non-ASCII are not allowed"
                ),
            });
        }
    }
    Ok(())
}

/// Errors from validating NATS configuration.
#[derive(Debug, thiserror::Error)]
pub enum NatsConfigError {
    /// A subject prefix or token contains invalid characters.
    #[error("NATS config `{field}`: {reason}")]
    InvalidSubject { field: String, reason: String },
    /// TLS configuration error.
    #[error(transparent)]
    Tls(#[from] NatsTlsConfigError),
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: "nats://localhost:4222".to_string(),
            credentials_file: None,
            tls: NatsTlsConfig::default(),
            subject_prefix: "points".to_string(),
            jetstream_stream: "TRACKS_HISTORY".to_string(),
            jetstream_subject_prefix: "TRACKS.HISTORY".to_string(),
            default_group: "__ANON__".to_string(),
            max_payload_bytes: 256 * 1024,
            max_replay_count: 0,
            instance_id: generate_instance_id(),
            subscription_capacity: 1024,
            live_stream: "RUSTGATE_LIVE".to_string(),
            max_ack_pending: 1000,
            // Default: five attempts is the workspace poison-message
            // standard. Operators who want the pre-#883-sub3 unlimited-
            // redelivery semantics back must set this to `0` (or any
            // non-positive value) explicitly. Refs #883 sub-item 3.
            max_deliver: 5,
            checkpoint_path: None,
            request_subject: None,
            dead_letter_subject: None,
            subject_filters: Vec::new(),
        }
    }
}

/// Generate a unique instance ID using OS-seeded randomness.
///
/// Uses `RandomState` (backed by OS entropy) combined with PID and
/// nanosecond timestamp to produce a collision-resistant identifier.
fn generate_instance_id() -> String {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(process::id() as u64);
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    format!("rustgate-{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn tls_config_default_validates() {
        let config = NatsTlsConfig::default();
        config.validate().unwrap();
    }

    #[test]
    fn tls_config_with_all_certs_validates() {
        let config = NatsTlsConfig {
            client_cert: Some(PathBuf::from("/tmp/cert.pem")),
            client_key: Some(PathBuf::from("/tmp/key.pem")),
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            required: true,
        };
        config.validate().unwrap();
    }

    #[test]
    fn tls_config_ca_only_validates() {
        let config = NatsTlsConfig {
            client_cert: None,
            client_key: None,
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            required: true,
        };
        config.validate().unwrap();
    }

    #[test]
    fn tls_config_cert_without_key_fails() {
        let config = NatsTlsConfig {
            client_cert: Some(PathBuf::from("/tmp/cert.pem")),
            client_key: None,
            ca_cert: None,
            required: false,
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, NatsTlsConfigError::IncompleteClientAuth),
            "expected IncompleteClientAuth, got: {err}"
        );
    }

    #[test]
    fn tls_config_key_without_cert_fails() {
        let config = NatsTlsConfig {
            client_cert: None,
            client_key: Some(PathBuf::from("/tmp/key.pem")),
            ca_cert: None,
            required: false,
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, NatsTlsConfigError::IncompleteClientAuth));
    }

    #[test]
    fn tls_config_required_without_certs_fails() {
        let config = NatsTlsConfig {
            client_cert: None,
            client_key: None,
            ca_cert: None,
            required: true,
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, NatsTlsConfigError::RequiredButNoCerts));
    }

    #[test]
    fn tls_config_not_required_without_certs_ok() {
        let config = NatsTlsConfig {
            client_cert: None,
            client_key: None,
            ca_cert: None,
            required: false,
        };
        config.validate().unwrap();
    }

    #[test]
    fn has_client_auth_both_present() {
        let config = NatsTlsConfig {
            client_cert: Some(PathBuf::from("cert.pem")),
            client_key: Some(PathBuf::from("key.pem")),
            ca_cert: None,
            required: false,
        };
        assert!(config.has_client_auth());
    }

    #[test]
    fn has_client_auth_none() {
        let config = NatsTlsConfig::default();
        assert!(!config.has_client_auth());
    }

    #[test]
    fn default_config_validates() {
        NatsConfig::default().validate().unwrap();
    }

    #[test]
    fn wildcard_in_subject_prefix_rejected() {
        let config = NatsConfig {
            subject_prefix: "points.>".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, NatsConfigError::InvalidSubject { ref field, .. } if field == "subject_prefix"),
            "expected InvalidSubject for subject_prefix, got: {err}"
        );
    }

    #[test]
    fn asterisk_in_subject_prefix_rejected() {
        let config = NatsConfig {
            subject_prefix: "points.*".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn wildcard_in_jetstream_prefix_rejected() {
        let config = NatsConfig {
            jetstream_subject_prefix: "TRACKS.>".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, NatsConfigError::InvalidSubject { ref field, .. } if field == "jetstream_subject_prefix"),
        );
    }

    #[test]
    fn dot_in_subject_prefix_allowed() {
        let config = NatsConfig {
            subject_prefix: "my.prefix".to_string(),
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn dot_in_default_group_rejected() {
        let config = NatsConfig {
            default_group: "group.sub".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_subject_prefix_rejected() {
        let config = NatsConfig {
            subject_prefix: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn control_char_in_subject_prefix_rejected() {
        let config = NatsConfig {
            subject_prefix: "points\x01bad".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn del_in_subject_prefix_rejected() {
        let config = NatsConfig {
            subject_prefix: "points\x7Fbad".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn space_in_subject_prefix_rejected() {
        let config = NatsConfig {
            subject_prefix: "points bad".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn non_ascii_in_subject_prefix_rejected() {
        let config = NatsConfig {
            subject_prefix: "caf\u{00e9}".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn tab_in_default_group_rejected() {
        let config = NatsConfig {
            default_group: "group\tname".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn default_request_subject_is_none() {
        // Responder is strictly opt-in. A default of `None` means
        // clients that do not configure request/reply never subscribe
        // to anything extra — critical for deployments that only want
        // the streaming bridge (the vast majority today).
        let config = NatsConfig::default();
        assert!(config.request_subject.is_none());
    }

    #[test]
    fn request_subject_valid_multi_level_accepted() {
        let config = NatsConfig {
            request_subject: Some("rustgate.ops.status".to_string()),
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn request_subject_single_token_accepted() {
        let config = NatsConfig {
            request_subject: Some("ping".to_string()),
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn wildcard_in_request_subject_rejected() {
        // Responders subscribe to one concrete subject; `>`/`*` would
        // require the handler to switch on subject at runtime, which is
        // out of scope for the initial cut.
        let config = NatsConfig {
            request_subject: Some("rustgate.ops.>".to_string()),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, NatsConfigError::InvalidSubject { ref field, .. } if field == "request_subject"),
            "expected InvalidSubject for request_subject, got: {err}"
        );
    }

    #[test]
    fn asterisk_in_request_subject_rejected() {
        let config = NatsConfig {
            request_subject: Some("rustgate.*.status".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_request_subject_rejected() {
        // `Some("")` is semantically invalid — callers who want to
        // disable request/reply must pass `None`. The empty-string case
        // is a common misconfiguration (e.g. unset env var rendered as
        // empty string by a shell) and we should fail it loudly at
        // validate() rather than subscribe to "".
        let config = NatsConfig {
            request_subject: Some(String::new()),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, NatsConfigError::InvalidSubject { ref field, .. } if field == "request_subject"),
        );
    }

    #[test]
    fn control_char_in_request_subject_rejected() {
        let config = NatsConfig {
            request_subject: Some("rustgate\x01ops".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn space_in_request_subject_rejected() {
        let config = NatsConfig {
            request_subject: Some("rustgate ops".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn non_ascii_in_request_subject_rejected() {
        let config = NatsConfig {
            request_subject: Some("caf\u{00e9}".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn nats_config_validate_propagates_tls_error() {
        let config = NatsConfig {
            tls: NatsTlsConfig {
                client_cert: Some(PathBuf::from("cert.pem")),
                client_key: None,
                ca_cert: None,
                required: false,
            },
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, NatsConfigError::Tls(_)));
    }

    #[test]
    fn default_subscription_capacity() {
        let config = NatsConfig::default();
        assert_eq!(config.subscription_capacity, 1024);
    }

    #[test]
    fn custom_subscription_capacity() {
        let config = NatsConfig {
            subscription_capacity: 256,
            ..Default::default()
        };
        assert_eq!(config.subscription_capacity, 256);
    }

    #[test]
    fn default_max_deliver_is_five_for_poison_handling() {
        // Default `5` is the workspace poison-message handling standard
        // (refs #883 sub-item 3). Pre-#883-sub3 the default was `0`
        // (JetStream's "unlimited" sentinel), which let a poisonous
        // message redeliver indefinitely and silently. The new default
        // bounds the redelivery loop and triggers the
        // `nats.poison_dlq` audit event on the final give-up.
        // Operators who need the legacy semantics back must set this
        // explicitly to `0` (or any non-positive value).
        let config = NatsConfig::default();
        assert_eq!(config.max_deliver, 5);
    }

    #[test]
    fn explicit_zero_max_deliver_opts_into_legacy_unlimited() {
        // The escape hatch documented in the field's rustdoc: setting
        // `max_deliver = 0` explicitly tells the JetStream server to
        // use its own default (unlimited redelivery), preserving the
        // pre-#883 behaviour for operators who need it. Validation
        // must accept the value — we never want to refuse a legitimate
        // legacy-compat opt-in.
        let config = NatsConfig {
            max_deliver: 0,
            ..Default::default()
        };
        config.validate().unwrap();
        assert_eq!(config.max_deliver, 0);
    }

    #[test]
    fn custom_max_deliver_round_trips() {
        let config = NatsConfig {
            max_deliver: 5,
            ..Default::default()
        };
        assert_eq!(config.max_deliver, 5);
    }

    #[test]
    fn default_subject_filters_is_empty() {
        // Back-compat posture: an upgraded config that doesn't set
        // `subject_filters` must produce the same `{prefix}.>` wildcard
        // subscription as before. The emptiness is the signal to the
        // subscriber that it should keep the wildcard.
        let config = NatsConfig::default();
        assert!(config.subject_filters.is_empty());
    }

    #[test]
    fn subject_filters_single_pattern_validates() {
        let config = NatsConfig {
            subject_filters: vec!["points.ALPHA.>".to_string()],
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn subject_filters_multiple_patterns_validate() {
        let config = NatsConfig {
            subject_filters: vec![
                "points.ALPHA.>".to_string(),
                "points.BRAVO.position".to_string(),
                "points.*.update.v2".to_string(),
            ],
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn subject_filters_wildcards_allowed() {
        // The point of a filter is wildcard matching — `*` (one token) and
        // `>` (tail) must pass validation even though they're forbidden in
        // `subject_prefix`.
        for pat in ["points.*.update", "points.ALPHA.>", "points.>"] {
            let config = NatsConfig {
                subject_filters: vec![pat.to_string()],
                ..Default::default()
            };
            config.validate().unwrap_or_else(|e| panic!("{pat}: {e}"));
        }
    }

    #[test]
    fn subject_filter_outside_prefix_rejected() {
        // A filter that doesn't start with `{subject_prefix}.` would bind
        // the consumer to a subject set the stream never captures — silent
        // zero-traffic failure mode. Validation catches it.
        let config = NatsConfig {
            subject_prefix: "points".to_string(),
            subject_filters: vec!["other.ALPHA.>".to_string()],
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, NatsConfigError::InvalidSubject { ref field, .. } if field == "subject_filters[0]"),
            "expected InvalidSubject on subject_filters[0], got: {err}"
        );
    }

    #[test]
    fn subject_filter_matching_prefix_exactly_rejected() {
        // The required prefix is `"{prefix}."` — an entry equal to just
        // the prefix (no trailing dot) would match the prefix itself as a
        // token but not the `.something` sub-subjects the stream captures.
        let config = NatsConfig {
            subject_prefix: "points".to_string(),
            subject_filters: vec!["points".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_filter_entry_rejected() {
        let config = NatsConfig {
            subject_filters: vec!["points.ALPHA.>".to_string(), String::new()],
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, NatsConfigError::InvalidSubject { ref field, .. } if field == "subject_filters[1]"),
        );
    }

    #[test]
    fn control_char_in_filter_rejected() {
        let config = NatsConfig {
            subject_filters: vec!["points.ALPHA\x01.>".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn space_in_filter_rejected() {
        let config = NatsConfig {
            subject_filters: vec!["points.ALPHA BRAVO.>".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn non_ascii_in_filter_rejected() {
        let config = NatsConfig {
            subject_filters: vec!["points.caf\u{00e9}.>".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn del_byte_in_filter_rejected() {
        let config = NatsConfig {
            subject_filters: vec!["points.ALPHA\x7F.>".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn subject_filter_validation_independent_of_prefix_validation() {
        // If subject_prefix is bad, that error surfaces first. Establishes
        // field-ordering: callers should treat the first returned error as
        // authoritative and not assume filter validation ran.
        let config = NatsConfig {
            subject_prefix: "points bad".to_string(),
            subject_filters: vec!["points bad.x".to_string()],
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, NatsConfigError::InvalidSubject { ref field, .. } if field == "subject_prefix"),
            "expected prefix error first, got: {err}"
        );
    }

    // --- dead_letter_subject ---

    #[test]
    fn default_dead_letter_subject_is_none() {
        // DLQ is strictly opt-in: existing deployments that never set
        // `dead_letter_subject` keep the current silent-drop behaviour.
        // Any non-None default would silently start republishing poison
        // messages to an unexpected subject on upgrade.
        let config = NatsConfig::default();
        assert!(config.dead_letter_subject.is_none());
    }

    #[test]
    fn dead_letter_subject_multi_level_accepted() {
        let config = NatsConfig {
            dead_letter_subject: Some("rustgate.dlq".to_string()),
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn dead_letter_subject_single_token_accepted() {
        let config = NatsConfig {
            dead_letter_subject: Some("deadletter".to_string()),
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn wildcard_in_dead_letter_subject_rejected() {
        // The subscriber publishes to one concrete subject; `>` and `*`
        // have no meaning on the publish path and almost certainly
        // indicate operator confusion between DLQ and subject_filters.
        let config = NatsConfig {
            dead_letter_subject: Some("rustgate.dlq.>".to_string()),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, NatsConfigError::InvalidSubject { ref field, .. } if field == "dead_letter_subject"),
            "expected InvalidSubject on dead_letter_subject, got: {err}"
        );
    }

    #[test]
    fn asterisk_in_dead_letter_subject_rejected() {
        let config = NatsConfig {
            dead_letter_subject: Some("rustgate.*.dlq".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_dead_letter_subject_rejected() {
        // `Some("")` is a classic env-var-rendered-as-empty-string
        // misconfiguration. Operators who want to disable DLQ must
        // pass `None`.
        let config = NatsConfig {
            dead_letter_subject: Some(String::new()),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, NatsConfigError::InvalidSubject { ref field, .. } if field == "dead_letter_subject"),
        );
    }

    #[test]
    fn control_char_in_dead_letter_subject_rejected() {
        let config = NatsConfig {
            dead_letter_subject: Some("rustgate\x01dlq".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn non_ascii_in_dead_letter_subject_rejected() {
        let config = NatsConfig {
            dead_letter_subject: Some("caf\u{00e9}.dlq".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn dead_letter_subject_inside_live_stream_prefix_rejected() {
        // The whole point of the loop-prevention rule: if the DLQ is
        // captured by the live stream wildcard, DLQ traffic becomes new
        // poison traffic, forever.
        let config = NatsConfig {
            subject_prefix: "points".to_string(),
            dead_letter_subject: Some("points.dlq".to_string()),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        let message = err.to_string();
        assert!(
            matches!(err, NatsConfigError::InvalidSubject { ref field, .. } if field == "dead_letter_subject"),
            "expected InvalidSubject on dead_letter_subject, got: {err}"
        );
        // Error message should explicitly mention the loop hazard so a
        // confused operator can understand why the config was rejected
        // without consulting the docs.
        assert!(
            message.contains("loop"),
            "error message should explain the loop hazard, got: {message}"
        );
    }

    #[test]
    fn dead_letter_subject_equal_to_prefix_accepted() {
        // Edge case: the rule rejects `{prefix}.xxx`, not `{prefix}`
        // itself — the live stream doesn't capture the bare prefix
        // (it captures `{prefix}.>`), so `{prefix}` alone is safe.
        // This is a deliberate choice: the pattern-match is prefix +
        // trailing dot, and the bare prefix is not inside that namespace.
        let config = NatsConfig {
            subject_prefix: "points".to_string(),
            dead_letter_subject: Some("points".to_string()),
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn dead_letter_subject_unrelated_prefix_accepted() {
        // The canonical deployment pattern: DLQ in a sibling namespace
        // captured by a separate JetStream stream (e.g. `rustgate.dlq`
        // while the live stream is `points.>`).
        let config = NatsConfig {
            subject_prefix: "points".to_string(),
            dead_letter_subject: Some("rustgate.dlq".to_string()),
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn dead_letter_subject_round_trips() {
        let config = NatsConfig {
            dead_letter_subject: Some("rustgate.dlq".to_string()),
            ..Default::default()
        };
        assert_eq!(config.dead_letter_subject.as_deref(), Some("rustgate.dlq"));
    }

    #[test]
    fn max_deliver_does_not_affect_validation() {
        // `max_deliver` has no syntactic constraints (positive caps redeliveries,
        // 0 means unlimited, negative values would be rejected by the NATS
        // server at consumer-create time). The config validator should not
        // guess at semantics — just round-trip.
        let positive = NatsConfig {
            max_deliver: 100,
            ..Default::default()
        };
        positive.validate().unwrap();

        let zero = NatsConfig {
            max_deliver: 0,
            ..Default::default()
        };
        zero.validate().unwrap();
    }
}
