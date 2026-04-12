// Copyright © 2026 Roberto Chiofalo.

//! Error types for the HTTP egress subsystem.
//!
//! All errors use [`thiserror::Error`] for structured, displayable error
//! messages. No panics — all fallible paths return `Result<T, HttpError>`.

/// Errors produced by the HTTP egress bridge.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// Configuration validation failed.
    #[error("HTTP config validation: {0}")]
    Config(String),

    /// Failed to construct a `reqwest::Client` for a target.
    #[error("failed to build HTTP client for target `{target}`: {source}")]
    ClientBuild {
        target: String,
        source: reqwest::Error,
    },

    /// HTTP request failed at the transport level.
    #[error("HTTP request to `{target}` failed: {source}")]
    Request {
        target: String,
        source: reqwest::Error,
    },

    /// HTTP response returned a non-success status code.
    #[error("HTTP response from `{target}` returned {status}")]
    ResponseStatus { target: String, status: u16 },

    /// Failed to read a secret file (token, password, HMAC key).
    #[error("failed to read secret file `{path}`: {source}")]
    SecretRead {
        path: String,
        source: std::io::Error,
    },

    /// Payload serialization to JSON failed.
    #[error("payload serialization failed: {source}")]
    Serialize { source: serde_json::Error },

    /// The target's circuit breaker is open — requests are being shed.
    #[error("circuit breaker open for target `{target}`")]
    CircuitOpen { target: String },
}
