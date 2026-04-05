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
