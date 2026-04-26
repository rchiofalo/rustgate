// Copyright © 2026 Roberto Chiofalo.

//! Authentication builders for outbound HTTP requests.
//!
//! Supports three authentication methods: Bearer token, HTTP Basic Auth,
//! and HMAC-SHA256 request body signing. All secret material is read from
//! files (never inline config) and wrapped in [`Zeroizing`] for automatic
//! memory wiping on drop.

use std::fmt;

use hmac::{Hmac, Mac};
use rustgate_core::secrets::{SecretFileOpts, read_secret_file as core_read_secret_file};
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
                let mut secret_str = read_secret_file(secret_file)?;
                let secret = Zeroizing::new(secret_str.as_bytes().to_vec());
                // Wipe the string form now that we have the byte copy
                zeroize::Zeroize::zeroize(&mut *secret_str);
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
                // Include a timestamp in the signed payload to enable replay
                // prevention on the receiver side. The receiver reconstructs
                // the signed payload as "<timestamp>.<body>" and rejects
                // signatures older than an acceptable window.
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let signature = compute_hmac_signature(secret, body, timestamp)?;
                Ok(builder
                    .header("X-Rustgate-Timestamp", timestamp.to_string())
                    .header(header_name, signature))
            }
        }
    }
}

/// Read a secret file via the shared
/// [`rustgate_core::secrets::read_secret_file`] helper.
///
/// Uses the strict default policy — 8 KiB cap, mode 0o077 permissions
/// gate, empty-file rejection, trailing-whitespace trim — and additionally
/// binds the file's owner UID to the running process's effective UID so
/// a "secret dropped by `root`, service running as `rustgate`" misconfig
/// surfaces as a hard error rather than a silent read.
///
/// Uses blocking I/O because secret loading only happens at startup
/// during publisher initialization, not on the hot path.
fn read_secret_file(path: &str) -> Result<Zeroizing<String>, HttpError> {
    let mut opts = SecretFileOpts::default();
    #[cfg(unix)]
    {
        opts.require_owner_uid = Some(rustix::process::geteuid().as_raw());
    }
    Ok(core_read_secret_file(path, &opts)?)
}

/// Compute HMAC-SHA256 over `"<timestamp>.<data>"` and return `sha256=<hex>`.
///
/// The timestamp is bound into the signed payload so that captured
/// signatures cannot be replayed at a later time. Receivers verify by
/// reconstructing the same `"<timestamp>.<body>"` payload and checking
/// that the timestamp falls within an acceptable freshness window.
fn compute_hmac_signature(secret: &[u8], data: &[u8], timestamp: u64) -> Result<String, HttpError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| HttpError::Config(format!("HMAC key initialization failed: {e}")))?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(data);
    let result = mac.finalize();
    let hex_digest = hex::encode(result.into_bytes());
    Ok(format!("sha256={hex_digest}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use rustgate_core::b64;

    use super::*;

    /// Write content to a temp file with owner-only permissions, returning the path.
    fn write_temp_secret(name: &str, content: &str) -> String {
        let dir = std::env::temp_dir().join("rustgate-http-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
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
        let secret = b"supersecretkey";
        let data = b"Hello, World!";
        let timestamp = 1700000000u64;
        let sig = compute_hmac_signature(secret, data, timestamp).unwrap();
        assert!(sig.starts_with("sha256="), "got: {sig}");

        // Verify independently: signed payload is "<timestamp>.<body>"
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(data);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig, format!("sha256={expected}"));
    }

    #[test]
    fn hmac_signature_empty_body() {
        let secret = b"key";
        let sig = compute_hmac_signature(secret, b"", 1700000000).unwrap();
        assert!(sig.starts_with("sha256="));
        assert!(sig.len() > "sha256=".len());
    }

    #[test]
    fn hmac_signature_deterministic() {
        let secret = b"test-key";
        let data = b"test-data";
        let timestamp = 1700000000u64;
        let sig1 = compute_hmac_signature(secret, data, timestamp).unwrap();
        let sig2 = compute_hmac_signature(secret, data, timestamp).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn hmac_different_data_different_signature() {
        let secret = b"key";
        let timestamp = 1700000000u64;
        let sig1 = compute_hmac_signature(secret, b"data1", timestamp).unwrap();
        let sig2 = compute_hmac_signature(secret, b"data2", timestamp).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn hmac_different_timestamp_different_signature() {
        let secret = b"key";
        let data = b"same-data";
        let sig1 = compute_hmac_signature(secret, data, 1000).unwrap();
        let sig2 = compute_hmac_signature(secret, data, 2000).unwrap();
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
    fn rejects_oversized_secret_file() {
        let dir = std::env::temp_dir().join("rustgate-http-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oversized-secret");
        // Write 9 KiB (over 8 KiB limit)
        let content = "x".repeat(9 * 1024);
        std::fs::write(&path, &content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = read_secret_file(path.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_secret_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join("rustgate-http-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("insecure-secret");
        std::fs::write(&path, "secret-value").unwrap();
        // Set world-readable permissions (0644)
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_secret_file(path.to_str().unwrap()).unwrap_err();
        // The shared helper renders "overly-permissive Unix mode <octal>";
        // both that phrase and the literal mode bits are part of the
        // operator-facing contract that downstream alerts grep for.
        let rendered = err.to_string();
        assert!(
            rendered.contains("overly-permissive Unix mode"),
            "expected unified perm-check phrasing, got: {rendered}"
        );
        assert!(
            rendered.contains("0o644"),
            "expected actual mode in error, got: {rendered}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_empty_secret_file() {
        let path = write_temp_secret("empty-secret", "   \n\t  ");
        let err = read_secret_file(&path).unwrap_err();
        // The shared helper's `Empty` variant renders "is empty (after
        // optional newline trim)" — pin the canonical phrase so a
        // future tweak to the helper's Display string trips this test.
        assert!(err.to_string().contains("is empty"), "got: {err}");
        let _ = std::fs::remove_file(&path);
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
        let expected = b64::encode("user:pass");
        assert_eq!(auth, format!("Basic {expected}"));
    }

    #[test]
    fn hmac_apply_sets_signature_and_timestamp() {
        let state = AuthState::Hmac {
            secret: Zeroizing::new(b"secret".to_vec()),
            header_name: "X-Signature-256".to_string(),
        };
        let body = b"request body";
        let client = reqwest::Client::new();
        let builder = client.post("http://localhost/test");
        let result = state.apply(builder, body).unwrap();
        let request = result.build().unwrap();

        // Signature header present with sha256= prefix
        let sig = request
            .headers()
            .get("X-Signature-256")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(sig.starts_with("sha256="));

        // Timestamp header present and is a valid unix timestamp
        let ts_str = request
            .headers()
            .get("X-Rustgate-Timestamp")
            .unwrap()
            .to_str()
            .unwrap();
        let ts: u64 = ts_str.parse().unwrap();
        assert!(ts > 0);

        // Verify signature independently using the timestamp
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(ts_str.as_bytes());
        mac.update(b".");
        mac.update(body);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig, format!("sha256={expected}"));
    }
}
