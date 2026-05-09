// Copyright © 2026 Roberto Chiofalo.

//! Error type returned by the inference pipeline.
//!
//! Each variant carries enough context (model name, attribute name,
//! path, status code) to debug a misconfigured pipeline without
//! needing to enable trace logging. The router-side callback
//! ([`crate::wiring::router_callback`]) downgrades these to
//! `tracing::debug` so a model that rejects a payload does not poison
//! the routing critical path.

use std::path::PathBuf;

/// Unified error type for the inference pipeline.
#[derive(Debug, thiserror::Error)]
pub enum InferenceError {
    /// Loading a model file from disk failed (I/O error, format
    /// mismatch, missing metadata).
    #[error("model `{name}` failed to load from {path}: {reason}")]
    ModelLoadFailed {
        /// Logical model name as registered in the pipeline config.
        name: String,
        /// On-disk path attempted.
        path: PathBuf,
        /// Backend-specific reason string.
        reason: String,
    },

    /// Forward-pass on a loaded model failed.
    #[error("model `{name}` inference failed: {reason}")]
    InferenceFailed {
        /// Logical model name.
        name: String,
        /// Backend-specific reason string.
        reason: String,
    },

    /// A required entity attribute was missing for the model's input
    /// projection. The pipeline does NOT synthesize defaults — a
    /// missing attribute is the callsite's bug, not a runtime
    /// soft-error.
    #[error("model `{name}` requires attribute `{attribute}` on entity `{uid}`")]
    MissingAttribute {
        /// Logical model name.
        name: String,
        /// Missing attribute key (e.g. `"position.altitude_m"`).
        attribute: String,
        /// Entity UID for diagnostics.
        uid: String,
    },

    /// The model produced an output tensor or label vector that the
    /// pipeline could not decode into an [`crate::InferenceResult`].
    #[error("model `{name}` output decode failed: {reason}")]
    OutputDecode {
        /// Logical model name.
        name: String,
        /// Backend-specific reason string.
        reason: String,
    },

    /// The supplied [`crate::InferenceConfig`] was internally
    /// inconsistent (duplicate model names, threshold out of range,
    /// missing referenced model file).
    #[error("inference config invalid: {reason}")]
    ConfigInvalid {
        /// Description of the inconsistency.
        reason: String,
    },
}
