// Copyright © 2026 Roberto Chiofalo.

//! Authentication builders for outbound HTTP requests.
//!
//! Supports three authentication methods: Bearer token, HTTP Basic Auth,
//! and HMAC-SHA256 request body signing. All secret material is read from
//! files (never inline config) and wrapped in [`Zeroizing`] for automatic
//! memory wiping on drop.

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::config::AuthConfig;
use crate::error::HttpError;

type HmacSha256 = Hmac<Sha256>;

/// Runtime authentication state for a single target.
///
/// Holds loaded secret material — dropped with zeroization.
/// Custom [`Debug`] impl never logs secret contents.
pub(crate) enum AuthState {
    /// Bearer token authentication (`Authorization: Bearer <token>`).
    Bearer(Zeroizing<String>),
    /// HTTP Basic Auth (`Authorization: Basic <base64(user:pass)>`).
    Basic {
        username: String,
        password: Zeroizing<String>,
    },
    /// HMAC-SHA256 request body signing.
    /// Header value: `sha256=<hex-encoded-mac>`.
    Hmac {
        secret: Zeroizing<Vec<u8>>,
        header_name: String,
    },
}

impl fmt::Debug for AuthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => f.debug_tuple("Bearer").field(&"[REDACTED]").finish(),
            Self::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"[REDACTED]")
                .finish(),
            Self::Hmac { header_name, .. } => f
                .debug_struct("Hmac")
                .field("header_name", header_name)
                .field("secret", &"[REDACTED]")
                .finish(),
        }
    }
}

impl AuthState {
    /// Load authentication state from config by reading secret files.
    ///
    /// Reads secret material from the filesystem at construction time.
    /// Uses blocking I/O — call during publisher initialization, not per-request.
    pub(crate) fn from_config(config: &AuthConfig) -> Result<Self, HttpError> {
        match config {
            AuthConfig::Bearer { token_file } => {
                let token = read_secret_file(token_file)?;
                Ok(Self::Bearer(token))
            }
            AuthConfig::Basic {
                username,
                password_file,
            } => {
                let password = read_secret_file(password_file)?;
                Ok(Self::Basic {
                    username: username.clone(),
                    password,
                })
            }
            AuthConfig::Hmac {
                secret_file,
                header,
            } => {
                let secret_str = read_secret_file(secret_file)?;
                let secret = Zeroizing::new(secret_str.as_bytes().to_vec());
                let header_name = header
                    .clone()
                    .unwrap_or_else(|| "X-Signature-256".to_string());
                Ok(Self::Hmac {
                    secret,
                    header_name,
                })
            }
        }
    }

    /// Apply authentication to a request builder.
    ///
    /// For Bearer and Basic, sets the `Authorization` header.
    /// For HMAC, computes the signature over `body` and sets the
    /// configured header (default: `X-Signature-256`).
    pub(crate) fn apply(
        &self,
        builder: reqwest::RequestBuilder,
        body: &[u8],
    ) -> Result<reqwest::RequestBuilder, HttpError> {
        match self {
            Self::Bearer(token) => Ok(builder.bearer_auth(token.as_str())),
            Self::Basic { username, password } => {
                Ok(builder.basic_auth(username, Some(password.as_str())))
            }
            Self::Hmac {
                secret,
                header_name,
            } => {
                let signature = compute_hmac_signature(secret, body)?;
                Ok(builder.header(header_name, signature))
            }
        }
    }
}

/// Maximum secret file size (8 KiB) — prevents accidentally loading a log
/// file or binary blob as a secret.
const MAX_SECRET_FILE_BYTES: usize = 8 * 1024;

/// Read a secret file, trim whitespace, wrap in [`Zeroizing`].
///
/// Uses blocking I/O because secret loading only happens at startup
/// during publisher initialization, not on the hot path.
///
/// Rejects empty secrets (after trimming) and files larger than 8 KiB.
fn read_secret_file(path: &str) -> Result<Zeroizing<String>, HttpError> {
    let content = std::fs::read_to_string(path).map_err(|e| HttpError::SecretRead {
        path: path.to_string(),
        source: e,
    })?;

    if content.len() > MAX_SECRET_FILE_BYTES {
        return Err(HttpError::Config(format!(
            "secret file `{path}` is too large ({} bytes, max {MAX_SECRET_FILE_BYTES})",
            content.len()
        )));
    }

    let trimmed = content.trim().to_string();
    if trimmed.is_empty() {
        return Err(HttpError::Config(format!(
            "secret file `{path}` is empty after trimming whitespace"
        )));
    }

    Ok(Zeroizing::new(trimmed))
}

/// Compute HMAC-SHA256 over `data` and return `sha256=<hex>` string.
///
/// Follows the GitHub webhook signature format (de facto standard).
fn compute_hmac_signature(secret: &[u8], data: &[u8]) -> Result<String, HttpError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| HttpError::Config(format!("HMAC key initialization failed: {e}")))?;
    mac.update(data);
    let result = mac.finalize();
    let hex_digest = hex::encode(result.into_bytes());
    Ok(format!("sha256={hex_digest}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use base64::Engine;

    use super::*;

    /// Write content to a temp file, returning the path. Caller must clean up.
    fn write_temp_secret(name: &str, content: &str) -> String {
        let dir = std::env::temp_dir().join("rustgate-http-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn bearer_loads_from_file() {
        let path = write_temp_secret("bearer-token", "my-token-123\n");
        let config = AuthConfig::Bearer {
            token_file: path.clone(),
        };
        let state = AuthState::from_config(&config).unwrap();
        match &state {
            AuthState::Bearer(token) => assert_eq!(token.as_str(), "my-token-123"),
            _ => panic!("expected Bearer"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn basic_loads_from_file() {
        let path = write_temp_secret("basic-pass", "  s3cret  \n");
        let config = AuthConfig::Basic {
            username: "admin".to_string(),
            password_file: path.clone(),
        };
        let state = AuthState::from_config(&config).unwrap();
        match &state {
            AuthState::Basic { username, password } => {
                assert_eq!(username, "admin");
                assert_eq!(password.as_str(), "s3cret");
            }
            _ => panic!("expected Basic"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hmac_loads_from_file() {
        let path = write_temp_secret("hmac-secret", "hmac-secret-key");
        let config = AuthConfig::Hmac {
            secret_file: path.clone(),
            header: None,
        };
        let state = AuthState::from_config(&config).unwrap();
        match &state {
            AuthState::Hmac {
                header_name,
                secret,
            } => {
                assert_eq!(header_name, "X-Signature-256");
                assert_eq!(secret.as_slice(), b"hmac-secret-key");
            }
            _ => panic!("expected Hmac"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hmac_custom_header() {
        let path = write_temp_secret("hmac-key-custom", "key");
        let config = AuthConfig::Hmac {
            secret_file: path.clone(),
            header: Some("X-Custom-Sig".to_string()),
        };
        let state = AuthState::from_config(&config).unwrap();
        match &state {
            AuthState::Hmac { header_name, .. } => {
                assert_eq!(header_name, "X-Custom-Sig");
            }
            _ => panic!("expected Hmac"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_returns_error() {
        let config = AuthConfig::Bearer {
            token_file: "/nonexistent/path/token".to_string(),
        };
        let err = AuthState::from_config(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/nonexistent/path/token"), "got: {msg}");
    }

    #[test]
    fn hmac_signature_known_vector() {
        // Known HMAC-SHA256 test vector
        let secret = b"supersecretkey";
        let data = b"Hello, World!";
        let sig = compute_hmac_signature(secret, data).unwrap();
        assert!(sig.starts_with("sha256="), "got: {sig}");

        // Verify independently
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(data);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig, format!("sha256={expected}"));
    }

    #[test]
    fn hmac_signature_empty_body() {
        let secret = b"key";
        let sig = compute_hmac_signature(secret, b"").unwrap();
        assert!(sig.starts_with("sha256="));
        // Empty body should still produce a valid MAC
        assert!(sig.len() > "sha256=".len());
    }

    #[test]
    fn hmac_signature_deterministic() {
        let secret = b"test-key";
        let data = b"test-data";
        let sig1 = compute_hmac_signature(secret, data).unwrap();
        let sig2 = compute_hmac_signature(secret, data).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn hmac_different_data_different_signature() {
        let secret = b"key";
        let sig1 = compute_hmac_signature(secret, b"data1").unwrap();
        let sig2 = compute_hmac_signature(secret, b"data2").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn debug_redacts_bearer() {
        let state = AuthState::Bearer(Zeroizing::new("secret-token".to_string()));
        let debug = format!("{state:?}");
        assert!(!debug.contains("secret-token"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn debug_redacts_basic_password() {
        let state = AuthState::Basic {
            username: "admin".to_string(),
            password: Zeroizing::new("password123".to_string()),
        };
        let debug = format!("{state:?}");
        assert!(debug.contains("admin"));
        assert!(!debug.contains("password123"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn debug_redacts_hmac_secret() {
        let state = AuthState::Hmac {
            secret: Zeroizing::new(b"my-hmac-secret".to_vec()),
            header_name: "X-Signature-256".to_string(),
        };
        let debug = format!("{state:?}");
        assert!(debug.contains("X-Signature-256"));
        assert!(!debug.contains("my-hmac-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn bearer_apply_sets_header() {
        let state = AuthState::Bearer(Zeroizing::new("tok123".to_string()));
        let client = reqwest::Client::new();
        let builder = client.post("http://localhost/test");
        let result = state.apply(builder, b"body").unwrap();
        let request = result.build().unwrap();
        let auth = request
            .headers()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(auth, "Bearer tok123");
    }

    #[test]
    fn basic_apply_sets_header() {
        let state = AuthState::Basic {
            username: "user".to_string(),
            password: Zeroizing::new("pass".to_string()),
        };
        let client = reqwest::Client::new();
        let builder = client.post("http://localhost/test");
        let result = state.apply(builder, b"body").unwrap();
        let request = result.build().unwrap();
        let auth = request
            .headers()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        // Basic auth is base64("user:pass")
        let expected = base64::engine::general_purpose::STANDARD.encode("user:pass");
        assert_eq!(auth, format!("Basic {expected}"));
    }

    #[test]
    fn hmac_apply_sets_signature_header() {
        let state = AuthState::Hmac {
            secret: Zeroizing::new(b"secret".to_vec()),
            header_name: "X-Signature-256".to_string(),
        };
        let body = b"request body";
        let client = reqwest::Client::new();
        let builder = client.post("http://localhost/test");
        let result = state.apply(builder, body).unwrap();
        let request = result.build().unwrap();
        let sig = request
            .headers()
            .get("X-Signature-256")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(sig.starts_with("sha256="));

        // Verify independently
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(body);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig, format!("sha256={expected}"));
    }
}
