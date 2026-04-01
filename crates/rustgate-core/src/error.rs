//! Error types for rustgate.
//!
//! Provides structured error enums for transport and configuration failures,
//! replacing stringly-typed error variants with machine-matchable sub-errors.

/// Transport-layer errors.
///
/// Covers failures during socket binding, TLS handshake, certificate
/// validation, and identity extraction from X.509 certificates.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Failed to bind a listener to the specified address.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        /// The address that could not be bound.
        addr: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// TLS handshake did not complete successfully.
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    /// Peer did not present a client certificate during mTLS.
    #[error("no client certificate presented")]
    NoCertificate,

    /// Peer presented a certificate chain with zero entries.
    #[error("empty client certificate chain")]
    EmptyCertChain,

    /// Certificate subject is missing a Common Name (CN) field.
    #[error("certificate missing Common Name")]
    MissingCommonName,

    /// Certificate is missing a required Extended Key Usage extension.
    #[error("certificate missing required Extended Key Usage: {expected}")]
    MissingKeyUsage {
        /// The EKU purpose that was expected (e.g. `ClientAuth`).
        expected: String,
    },

    /// Catch-all for transport errors that do not yet have a dedicated variant.
    #[error("{0}")]
    Other(String),
}

/// Configuration-layer errors.
///
/// Covers failures when parsing PEM data, building TLS configurations,
/// and validating configuration values.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to parse PEM-encoded data (certificates, keys, CRLs).
    #[error("failed to parse {kind} PEM: {reason}")]
    PemParse {
        /// What was being parsed (e.g. `"certificate"`, `"CRL"`, `"private key"`).
        kind: String,
        /// The underlying parse error message.
        reason: String,
    },

    /// PEM data was valid but contained zero items of the expected kind.
    #[error("no {kind} found in PEM data")]
    EmptyPem {
        /// What was expected (e.g. `"certificates"`, `"CRLs"`).
        kind: String,
    },

    /// An unsupported TLS protocol version was requested.
    #[error("unsupported TLS version '{version}': expected '1.2' or '1.3'")]
    TlsVersion {
        /// The version string that was rejected.
        version: String,
    },

    /// Catch-all for configuration errors that do not yet have a dedicated variant.
    #[error("{0}")]
    Other(String),
}

/// Top-level error type for the rustgate crate.
#[derive(Debug, thiserror::Error)]
pub enum RustgateError {
    /// A transport-layer error (socket, TLS, certificate).
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// A configuration-layer error (PEM parsing, TLS config).
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// A raw I/O error not covered by the transport layer.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias used throughout the workspace.
pub type Result<T> = std::result::Result<T, RustgateError>;
