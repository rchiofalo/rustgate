//! Error types for the authz crate.

use thiserror::Error;

/// Errors produced while parsing, validating, or compiling a policy.
#[derive(Debug, Error)]
pub enum AuthzError {
    /// The input bytes were not valid JSON.
    #[error("invalid policy JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Policy failed a validation check.
    #[error("policy validation failed at {stage}: {message}")]
    Validation {
        /// Short identifier of the pipeline stage that rejected the policy.
        stage: &'static str,
        /// Human-readable explanation.
        message: String,
    },
}

impl AuthzError {
    /// Construct a validation error.
    pub fn validation(stage: &'static str, message: impl Into<String>) -> Self {
        Self::Validation {
            stage,
            message: message.into(),
        }
    }
}
