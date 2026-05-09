// Copyright © 2026 Roberto Chiofalo.

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
