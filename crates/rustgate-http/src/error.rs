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

    /// Failed to read a TLS certificate or key file.
    #[error("failed to read TLS file `{path}` for target `{target}`: {source}")]
    TlsFile {
        target: String,
        path: String,
        source: std::io::Error,
    },

    /// Payload serialization to JSON failed.
    #[error("payload serialization failed: {source}")]
    Serialize { source: serde_json::Error },

    /// Protobuf conversion failed (requires `proto` feature).
    #[error("protobuf conversion failed: {message}")]
    ProtoConvert { message: String },

    /// The target's circuit breaker is open — requests are being shed.
    #[error("circuit breaker open for target `{target}`")]
    CircuitOpen { target: String },

    /// TLS certificate pin mismatch — the server's certificate hash does
    /// not match any of the configured SHA-256 pins.
    #[error("certificate pin mismatch for target `{target}`: none of {pin_count} pins matched")]
    PinMismatch { target: String, pin_count: usize },

    /// Dead-letter queue I/O or encryption error.
    #[error("DLQ error for target `{target}`: {message}")]
    Dlq { target: String, message: String },
}
