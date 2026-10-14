// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Error types for the Lattice bridge.

/// Convenience alias for fallible operations in this crate.
pub type Result<T> = std::result::Result<T, LatticeError>;

/// Top-level error enum for the Lattice bridge.
///
/// Variants carry context fields rather than opaque strings so that
/// audit / metrics callers can match on the failure mode without
/// parsing a `Display` form.
#[derive(Debug, thiserror::Error)]
pub enum LatticeError {
    /// The bridge backend is not connected to a Lattice endpoint.
    #[error("lattice bridge not connected (backend `{backend}`)")]
    NotConnected {
        /// Symbolic name of the backend that refused the call (e.g. `"mock"`,
        /// `"real-grpc"`). Useful for routing audit events when multiple
        /// bridges are stacked behind a fallback.
        backend: &'static str,
    },

    /// The configured `[lattice.auth]` paths are missing or unreadable.
    ///
    /// The `path` field is the operator-supplied path that failed
    /// validation. The `kind` field distinguishes mTLS material from
    /// the JWT secret to make audit triage cheap.
    #[error("lattice auth material unreadable at `{path}` (kind `{kind}`): {source}")]
    AuthMaterial {
        /// Symbolic kind of credential that failed to load:
        /// `"mtls-cert" | "mtls-key" | "jwt-secret"`.
        kind: &'static str,
        /// The operator-configured filesystem path.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// `publish_entity` failed at the bridge backend.
    ///
    /// The `entity_id` is preserved so a follow-up retry path can
    /// correlate the failed publish with the offending entity. The
    /// backend label distinguishes mock from real-SDK reports.
    #[error("lattice publish failed for entity `{entity_id}` on backend `{backend}`: {reason}")]
    PublishFailed {
        /// Backend symbolic name.
        backend: &'static str,
        /// The entity ID that failed to publish.
        entity_id: String,
        /// Reason from the backend (mock-channel-closed, gRPC status, etc.).
        reason: String,
    },

    /// The inbound subscription stream terminated unexpectedly.
    #[error("lattice subscription stream closed (backend `{backend}`): {reason}")]
    SubscriptionClosed {
        /// Backend symbolic name.
        backend: &'static str,
        /// Reason from the backend.
        reason: String,
    },

    /// Health-report submission failed.
    #[error("lattice health report failed (backend `{backend}`): {reason}")]
    HealthReportFailed {
        /// Backend symbolic name.
        backend: &'static str,
        /// Reason from the backend.
        reason: String,
    },

    /// Configuration validation rejected a `[lattice]` block.
    ///
    /// Holds the human-readable reason — emitted at startup so the
    /// operator can correct `rustgate.toml` and retry; never raised
    /// on the hot path.
    #[error("invalid lattice configuration: {reason}")]
    InvalidConfig {
        /// Human-readable description of the validation failure.
        reason: String,
    },
}
