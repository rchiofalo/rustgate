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

    /// Optional path for JetStream replay checkpoint file.
    /// When set, stores the last processed sequence number so
    /// subsequent restarts resume from the checkpoint.
    pub checkpoint_path: Option<PathBuf>,
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
        self.tls.validate().map_err(NatsConfigError::Tls)?;
        Ok(())
    }
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
            checkpoint_path: None,
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
}
