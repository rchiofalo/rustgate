// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed error hierarchy for the federation crate.
//!
//! This module replaces the previous `anyhow::Error` plumbing with a
//! discriminated [`FederationError`] enum so callers can match on
//! specific failure modes (e.g. distinguish a TLS handshake failure
//! from a peer-not-found lookup) without parsing Display strings.
//!
//! The Display output of every variant is kept verbatim with the
//! pre-migration `anyhow!` / `bail!` text so log greps and operator
//! runbooks continue to work unchanged. Callers that only ever
//! formatted the error chain through `tracing::warn!(error = %e, …)`
//! do not need to change.

use std::net::AddrParseError;
use std::time::Duration;

use thiserror::Error;

/// Errors returned by the federation crate.
///
/// Variants are grouped by the subsystem that emits them (config,
/// connector, discovery, store, manager, IO). The grouping is
/// load-bearing: handler code in `rustgate-server` matches on
/// `FederationError::PeerNotFound` to surface a 404 in the REST API,
/// for example, so renaming a variant is a wire-shape change.
#[derive(Debug, Error)]
pub enum FederationError {
    // ── Configuration ──────────────────────────────────────────────
    /// Unknown federation protocol token (only `v1` and `v2` are accepted).
    #[error("unknown federation protocol: {0}")]
    UnknownProtocol(String),

    /// Invalid socket address supplied for a peer.
    #[error("invalid peer address '{address}': {source}")]
    InvalidPeerAddress {
        /// The malformed address string as configured.
        address: String,
        /// The underlying `AddrParseError` from `std::net`.
        #[source]
        source: AddrParseError,
    },

    // ── Connector / TLS ────────────────────────────────────────────
    /// Underlying I/O error (file read, socket I/O).
    #[error("{context}: {source}")]
    Io {
        /// Human-readable context for which I/O operation failed
        /// (e.g. "reading federation cert from /etc/ssl/cert.pem").
        context: String,
        /// The underlying `std::io::Error`.
        #[source]
        source: std::io::Error,
    },

    /// A long-running TCP/TLS operation exceeded its deadline.
    #[error("{operation} timed out after {timeout:?}")]
    Timeout {
        /// Description of what timed out (e.g. "TCP connect to 10.0.0.1:9001").
        operation: String,
        /// The timeout duration that was exceeded.
        timeout: Duration,
    },

    /// Invalid TLS server name supplied to the connector.
    #[error("invalid server name: {0}")]
    InvalidServerName(String),

    /// rustls / certificate error during handshake or config build.
    #[error("{context}: {source}")]
    Tls {
        /// Human-readable context (e.g. "TLS handshake with 10.0.0.1:9001",
        /// "invalid client certificate").
        context: String,
        /// The underlying `rustls::Error`.
        #[source]
        source: rustls::Error,
    },

    /// Failure to extract identity material from a peer's certificate.
    #[error("identity extraction failed: {0}")]
    IdentityExtraction(String),

    /// PEM parsing or validation failure.
    #[error("{context}: {source}")]
    Pem {
        /// Human-readable context for which PEM operation failed.
        context: String,
        /// The underlying core error.
        #[source]
        source: rustgate_core::error::RustgateError,
    },

    /// X.509 parsing failure on a stored certificate.
    #[error("failed to parse X.509 certificate: {0}")]
    X509(String),

    // ── Locking ────────────────────────────────────────────────────
    /// A `std::sync::Mutex` / `RwLock` was poisoned by a panicking holder.
    ///
    /// The variant carries the locking site so the operator log identifies
    /// which subsystem entered an inconsistent state.
    #[error("{context}: {detail}")]
    Lock {
        /// The locking site (e.g. "trust store lock poisoned",
        /// "DynamicPeerConnector lock poisoned").
        context: String,
        /// The Display rendering of the original `PoisonError`.
        detail: String,
    },

    // ── Discovery ──────────────────────────────────────────────────
    /// Failure inside a peer-discovery backend (Consul / etcd / DNS-SD).
    #[error("{0}")]
    Discovery(String),

    // ── Store / Persistence ────────────────────────────────────────
    /// Lookup against the federate store missed.
    #[error("federate not found: {0}")]
    PeerNotFound(String),

    /// Serialization / deserialization error against the federate store.
    #[error("{context}: {source}")]
    Serde {
        /// Human-readable context for the serde operation that failed.
        context: String,
        /// The underlying `serde_json::Error`.
        #[source]
        source: serde_json::Error,
    },

    /// Backing-store I/O error (NATS KV connect, JetStream bucket create).
    #[error("{0}")]
    Storage(String),

    // ── Manager / lifecycle ────────────────────────────────────────
    /// `FederationManager::start` was called twice on the same instance.
    #[error("federation manager is already running")]
    AlreadyRunning,

    /// `FederationManager::start` has not been called yet — caller cannot
    /// invoke a method that requires the live subsystem.
    #[error("{0}")]
    NotInitialized(&'static str),

    /// HA claim manager required but not configured.
    #[error("HA claim manager not initialized")]
    HaClaimManagerMissing,

    /// V2 TLS config required but not built (V2 disabled or misconfigured).
    #[error("v2_tls_config not set")]
    V2TlsConfigMissing,

    /// Adoption requested for a peer that has no enabled outbound config.
    #[error("no enabled outbound peer config found for '{0}'")]
    NoOutboundPeerConfig(String),

    /// HA NATS connect failed.
    #[error("HA NATS connect to {url}: {detail}")]
    HaNatsConnect {
        /// The NATS URL we attempted to connect to.
        url: String,
        /// Human-readable rendering of the underlying NATS error.
        detail: String,
    },

    /// Generic catch-all for human-readable errors that do not yet have
    /// a dedicated variant.
    ///
    /// Existing call sites that constructed `anyhow::anyhow!("{message}")`
    /// migrate to this variant verbatim; new call sites should prefer a
    /// dedicated variant so callers can match on structured failure
    /// modes.
    #[error("{0}")]
    Other(String),
}

impl From<rustgate_core::error::RustgateError> for FederationError {
    fn from(err: rustgate_core::error::RustgateError) -> Self {
        // Wrap the structured `RustgateError` chain as a Pem variant so
        // the source-chain remains reachable via `std::error::Error::source`.
        // The "rustgate-core" prefix gives operators a clear breadcrumb when
        // a federation log line points back into a shared core helper.
        Self::Pem {
            context: "rustgate-core".into(),
            source: err,
        }
    }
}

impl From<std::io::Error> for FederationError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            context: "I/O error".into(),
            source: err,
        }
    }
}

impl FederationError {
    /// Build an [`Io`](Self::Io) variant from a context string and an
    /// underlying `std::io::Error`.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Build a [`Timeout`](Self::Timeout) variant.
    pub fn timeout(operation: impl Into<String>, timeout: Duration) -> Self {
        Self::Timeout {
            operation: operation.into(),
            timeout,
        }
    }

    /// Build a [`Tls`](Self::Tls) variant.
    pub fn tls(context: impl Into<String>, source: rustls::Error) -> Self {
        Self::Tls {
            context: context.into(),
            source,
        }
    }

    /// Build a [`Pem`](Self::Pem) variant from a [`RustgateError`].
    ///
    /// [`RustgateError`]: rustgate_core::error::RustgateError
    pub fn pem(context: impl Into<String>, source: rustgate_core::error::RustgateError) -> Self {
        Self::Pem {
            context: context.into(),
            source,
        }
    }

    /// Build a [`Lock`](Self::Lock) variant from a context string and a
    /// rendering of the underlying `PoisonError`.
    pub fn lock(context: impl Into<String>, detail: impl std::fmt::Display) -> Self {
        Self::Lock {
            context: context.into(),
            detail: detail.to_string(),
        }
    }

    /// Build a [`Discovery`](Self::Discovery) variant.
    pub fn discovery(message: impl Into<String>) -> Self {
        Self::Discovery(message.into())
    }

    /// Build a [`Storage`](Self::Storage) variant.
    pub fn storage(message: impl Into<String>) -> Self {
        Self::Storage(message.into())
    }

    /// Build a [`Serde`](Self::Serde) variant.
    pub fn serde(context: impl Into<String>, source: serde_json::Error) -> Self {
        Self::Serde {
            context: context.into(),
            source,
        }
    }

    /// Build an [`Other`](Self::Other) variant from any `Display` value.
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }
}

/// Convenience alias used throughout the federation crate.
pub type Result<T> = std::result::Result<T, FederationError>;

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn unknown_protocol_displays_input() {
        let e = FederationError::UnknownProtocol("v9".into());
        assert_eq!(e.to_string(), "unknown federation protocol: v9");
    }

    #[test]
    fn peer_not_found_preserves_id() {
        let e = FederationError::PeerNotFound("alpha".into());
        assert_eq!(e.to_string(), "federate not found: alpha");
    }

    #[test]
    fn already_running_message_matches_original() {
        let e = FederationError::AlreadyRunning;
        assert_eq!(e.to_string(), "federation manager is already running");
    }

    #[test]
    fn timeout_renders_operation_and_duration() {
        let e = FederationError::timeout("TCP connect to 10.0.0.1:9001", Duration::from_secs(10));
        let rendered = e.to_string();
        assert!(rendered.contains("TCP connect to 10.0.0.1:9001"));
        assert!(rendered.contains("10s"));
    }

    #[test]
    fn invalid_server_name_displays_supplied_value() {
        let e = FederationError::InvalidServerName("not a hostname".into());
        assert_eq!(e.to_string(), "invalid server name: not a hostname");
    }

    #[test]
    fn invalid_peer_address_chains_source() {
        let parse_err: AddrParseError = "garbage".parse::<std::net::SocketAddr>().unwrap_err();
        let e = FederationError::InvalidPeerAddress {
            address: "garbage".into(),
            source: parse_err,
        };
        let rendered = e.to_string();
        assert!(rendered.starts_with("invalid peer address 'garbage'"));
        // `#[source]` chain is reachable via `std::error::Error::source`.
        let source = std::error::Error::source(&e);
        assert!(source.is_some(), "AddrParseError should be in source chain");
    }

    #[test]
    fn ha_claim_manager_missing_static_message() {
        let e = FederationError::HaClaimManagerMissing;
        assert_eq!(e.to_string(), "HA claim manager not initialized");
    }

    #[test]
    fn v2_tls_config_missing_static_message() {
        let e = FederationError::V2TlsConfigMissing;
        assert_eq!(e.to_string(), "v2_tls_config not set");
    }

    #[test]
    fn lock_helper_preserves_context_and_poison_detail() {
        let e = FederationError::lock("trust store lock poisoned", "PoisonError(..)");
        assert_eq!(e.to_string(), "trust store lock poisoned: PoisonError(..)");
    }

    #[test]
    fn other_helper_carries_arbitrary_message() {
        let e = FederationError::other("simulated discovery failure");
        assert_eq!(e.to_string(), "simulated discovery failure");
    }

    #[test]
    fn no_outbound_peer_config_displays_id() {
        let e = FederationError::NoOutboundPeerConfig("peer-7".into());
        assert_eq!(
            e.to_string(),
            "no enabled outbound peer config found for 'peer-7'",
        );
    }

    #[test]
    fn ha_nats_connect_renders_url_and_detail() {
        let e = FederationError::HaNatsConnect {
            url: "nats://10.0.0.1:4222".into(),
            detail: "connection refused".into(),
        };
        assert_eq!(
            e.to_string(),
            "HA NATS connect to nats://10.0.0.1:4222: connection refused",
        );
    }

    #[test]
    fn not_initialized_uses_static_str_message() {
        let e = FederationError::NotInitialized("connector not initialized (call start() first)");
        assert_eq!(
            e.to_string(),
            "connector not initialized (call start() first)",
        );
    }

    #[test]
    fn variants_implement_send_sync_static() {
        // FederationError must remain Send + Sync + 'static so it can
        // travel through `tokio::spawn` boundaries and `anyhow::Error`
        // wrappers in callers.
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<FederationError>();
    }

    #[test]
    fn implements_std_error() {
        // Crate consumers route this error through `anyhow::Error::from`
        // at the binary boundary; that requires the std::error::Error
        // bound to compile.
        fn assert_error<T: std::error::Error + 'static>() {}
        assert_error::<FederationError>();
    }
}
