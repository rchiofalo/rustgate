// Copyright © 2026 Roberto Chiofalo.

//! Enrollment-specific error types.

/// Errors that can occur during certificate enrollment.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("auth: {0}")]
    Auth(String),

    #[error("csr: {0}")]
    Csr(String),

    #[error("signing: {0}")]
    Signing(String),

    #[error("config: {0}")]
    Config(String),

    #[error("tls: {0}")]
    Tls(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
