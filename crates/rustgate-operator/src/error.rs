// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Error types for the rustgate Kubernetes operator.

use std::fmt;

/// Top-level error returned by the operator's render and reconcile paths.
#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    /// CRD validation failed before rendering — caller should surface this
    /// as a `Conditions[type=Ready,status=False,reason=InvalidSpec]` on the
    /// owning `RustgateCluster` and skip the apply step.
    #[error("invalid RustgateCluster spec: {message}")]
    InvalidSpec { message: String },

    /// YAML serialization failed during manifest rendering. This should not
    /// happen for any spec that passes validation; if it does, the operator
    /// has a bug.
    #[error("manifest serialization failed: {0}")]
    Serialize(String),

    /// JSON serialization failed during manifest construction. Same caveat
    /// as `Serialize` — a passing-validation spec should not trip this.
    #[error("manifest construction failed: {0}")]
    Construct(String),

    /// Server-side apply rejected a manifest. The variant carries the
    /// object kind and name so the controller can surface a focused
    /// Kubernetes Event and the right metric label. Field name is
    /// `reason` rather than `source` so thiserror doesn't try to look
    /// up a `std::error::Error` impl on the contained `String`.
    #[cfg(feature = "controller")]
    #[error("apply {kind}/{name} failed: {reason}")]
    Apply {
        kind: String,
        name: String,
        reason: String,
    },

    /// Status patch back to the parent `RustgateCluster` failed. The
    /// reconcile is treated as successful (children are applied) but the
    /// status field will be stale until the next pass.
    #[cfg(feature = "controller")]
    #[error("status patch failed: {0}")]
    StatusPatch(String),

    /// Leader election layer reported a transient error. The reconcile
    /// path treats this as a hint to back off — it never proceeds
    /// without holding the lease.
    #[cfg(feature = "controller")]
    #[error("leader election error: {0}")]
    Leader(String),

    /// Kubernetes client construction or API call failed at a layer the
    /// controller doesn't expect to be partially-recoverable. Surfaces
    /// as a `Warning` Event and is requeued on the standard backoff.
    #[cfg(feature = "controller")]
    #[error("Kubernetes API error: {0}")]
    Kube(String),
}

impl OperatorError {
    /// Construct an [`OperatorError::InvalidSpec`] from any displayable.
    pub fn invalid_spec(message: impl fmt::Display) -> Self {
        Self::InvalidSpec {
            message: message.to_string(),
        }
    }
}

impl From<serde_yaml::Error> for OperatorError {
    fn from(err: serde_yaml::Error) -> Self {
        Self::Serialize(err.to_string())
    }
}

impl From<serde_json::Error> for OperatorError {
    fn from(err: serde_json::Error) -> Self {
        Self::Construct(err.to_string())
    }
}

/// Result alias for operator-facing fallible operations.
pub type Result<T> = std::result::Result<T, OperatorError>;
