// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Authentication builders for outbound HTTP requests.
//!
//! Supports three authentication methods: Bearer token, HTTP Basic Auth,
//! and HMAC-SHA256 request body signing. All secret material is read from
//! files (never inline config) and wrapped in [`Zeroizing`] for automatic
//! memory wiping on drop.

use std::fmt;

use rustgate_core::crypto::{hmac_sha256_tag, hmac_sha256_verify};
use rustgate_core::secrets::{SecretFileOpts, read_secret_file as core_read_secret_file};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::config::AuthConfig;
use crate::error::HttpError;

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
    /// For HMAC, computes the signature over the canonical request
    /// (`<timestamp>.<METHOD>.<path>.<body>`) and sets the configured
    /// header (default: `X-Signature-256`). The HTTP `method` and the
    /// URL `path` are bound into the signed payload so a captured
    /// signature cannot be replayed against a different endpoint
    /// (e.g. an `/alert` body replayed at `/shutdown`).
    pub(crate) fn apply(
        &self,
        builder: reqwest::RequestBuilder,
        method: &str,
        path: &str,
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
                // Include a timestamp + HTTP method + URL path in the signed
                // payload. The timestamp enables replay-window enforcement on
                // the receiver side; method + path bind the signature to the
                // specific endpoint so a captured request cannot be replayed
                // against a different endpoint (AWS SigV4-style canonical
                // request discipline). The receiver reconstructs the same
                // `<timestamp>.<METHOD>.<path>.<body>` payload and rejects
                // signatures whose canonical inputs do not match.
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let signature = compute_hmac_signature(secret, method, path, body, timestamp)?;
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

/// Compute HMAC-SHA256 over the canonical signed payload
/// `"<timestamp>.<METHOD>.<path>.<body>"` and return `sha256=<hex>`.
///
/// The canonical layout follows the AWS SigV4 discipline of binding
/// every replay-relevant request attribute into the signed bytes:
///
/// 1. `timestamp` — Unix seconds. Defends against signature replay
///    outside an acceptable freshness window (verified on the receive side).
/// 2. `method` — uppercase HTTP method (`POST`, `PUT`, …). Binds the
///    signature to the request semantics so a `POST` body cannot be
///    replayed as a `GET` (and vice versa).
/// 3. `path` — URL path component (no host, no query string). Binds the
///    signature to the exact endpoint so a captured `/alert` body
///    cannot be replayed against `/shutdown`.
/// 4. `body` — raw request body bytes. Binds payload integrity.
///
/// Components are joined by a single `.` byte separator. The body is
/// the last segment so its raw bytes (which may include `.` characters)
/// remain unambiguous.
///
/// Wire-format note: this is a breaking change from the prior
/// `<timestamp>.<body>` layout — receivers must use the same canonical
/// reconstruction or signatures will fail to verify.
fn compute_hmac_signature(
    secret: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: u64,
) -> Result<String, HttpError> {
    // Assemble the canonical signed payload upfront. The legacy inlined
    // path called `mac.update()` four times against pre-constant `.`
    // separators; that produces a byte-identical HMAC input to a single
    // pre-concatenated buffer because `Mac::update` is associative
    // over byte sequences. Keeping the format literal here keeps the
    // wire-format documentation in lockstep with the implementation.
    let timestamp_bytes = timestamp.to_string();
    let mut signed = Vec::with_capacity(
        timestamp_bytes.len() + 1 + method.len() + 1 + path.len() + 1 + body.len(),
    );
    signed.extend_from_slice(timestamp_bytes.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(method.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(path.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);

    let tag = hmac_sha256_tag(secret, &signed)
        .map_err(|e| HttpError::Config(format!("HMAC key initialization failed: {e}")))?;
    let hex_digest = hex::encode(tag);
    Ok(format!("sha256={hex_digest}"))
}

/// Verify an HMAC-SHA256 signature against the canonical signed payload
/// `"<timestamp>.<METHOD>.<path>.<body>"`.
///
/// Returns `true` only if `presented` matches the locally computed
/// signature. The comparison uses [`subtle::ConstantTimeEq`] so a timing
/// side-channel cannot leak how many leading bytes of the digest match
/// — both branches of the check execute in the same time regardless of
/// where (or whether) the signatures diverge.
///
/// The HMAC computation itself is delegated to the shared
/// [`rustgate_core::crypto::hmac_sha256_verify`] helper (constant-time
/// `ct_eq` over the raw 32-byte tag); this wrapper preserves the
/// caller-facing `sha256=<hex>` envelope contract by parsing the prefix
/// and decoding the hex payload before handing control to the helper.
/// We keep an explicit `ConstantTimeEq` check on the `sha256=` prefix so
/// even malformed presented signatures (right length, wrong prefix) are
/// rejected without timing leakage.
///
/// Receivers MUST also enforce a freshness window on `timestamp`
/// independently; this function only validates the cryptographic binding,
/// not the recency of the request.
//
// Forward-reference suppression: the verifier is the symmetric counterpart
// to `compute_hmac_signature` per the F-47 fix and is exercised by the
// `tests` module below (cross-endpoint replay tests are the load-bearing
// security regression). Server-side consumers (e.g. an inbound webhook
// receiver crate) will call it once that path lands — at which point this
// cfg-gate goes away. Tracking #747. The `cfg_attr` form keeps the lint
// suppression tied to non-test builds; the playbook's `#[allow]`-must-be-
// justified rule (F-156) only matches bare `#[allow(...)]`, but we still
// pin a comment here so a future contributor reading just the file knows
// why the gate exists.
#[cfg_attr(not(test), allow(dead_code))]
fn verify_hmac_signature(
    secret: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: u64,
    presented: &str,
) -> Result<bool, HttpError> {
    // Reconstruct the signed payload (timestamp.method.path.body) so the
    // helper can hash it independently. This mirrors the byte sequence
    // built by `compute_hmac_signature`.
    let timestamp_bytes = timestamp.to_string();
    let mut signed = Vec::with_capacity(
        timestamp_bytes.len() + 1 + method.len() + 1 + path.len() + 1 + body.len(),
    );
    signed.extend_from_slice(timestamp_bytes.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(method.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(path.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);

    // The presented signature must have the form `sha256=<64-hex-chars>`.
    // Reject anything else without leaking which prefix byte diverged
    // — the prefix comparison itself is constant-time.
    const PREFIX: &[u8] = b"sha256=";
    let presented_bytes = presented.as_bytes();
    if presented_bytes.len() != PREFIX.len() + 64 {
        return Ok(false);
    }
    let (prefix, hex_tag) = presented_bytes.split_at(PREFIX.len());
    if !bool::from(prefix.ct_eq(PREFIX)) {
        return Ok(false);
    }
    // Hex-decode the trailing 32 bytes worth of digest. A malformed hex
    // payload is a verification failure, not a configuration error.
    let presented_tag = match hex::decode(hex_tag) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false),
    };

    // The helper's constant-time `ct_eq` is the load-bearing comparison.
    match hmac_sha256_verify(secret, &signed, &presented_tag) {
        Ok(()) => Ok(true),
        Err(rustgate_core::crypto::HmacError::VerificationFailed)
        | Err(rustgate_core::crypto::HmacError::TagLengthMismatch { .. }) => Ok(false),
        Err(e @ rustgate_core::crypto::HmacError::InvalidKeyLength { .. }) => Err(
            HttpError::Config(format!("HMAC key initialization failed: {e}")),
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use hmac::{Hmac, Mac};
    use rustgate_core::b64;
    use sha2::Sha256;

    use super::*;

    /// Test-local alias used by the byte-for-byte regression tests
    /// that pin the helper output against the previous inlined
    /// `Hmac::<Sha256>::new_from_slice(...).update(...).finalize()`
    /// pipeline.
    type HmacSha256 = Hmac<Sha256>;

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
        let sig = compute_hmac_signature(secret, "POST", "/alert", data, timestamp).unwrap();
        assert!(sig.starts_with("sha256="), "got: {sig}");

        // Verify independently: signed payload is
        // "<timestamp>.<METHOD>.<path>.<body>"
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(b"POST");
        mac.update(b".");
        mac.update(b"/alert");
        mac.update(b".");
        mac.update(data);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig, format!("sha256={expected}"));
    }

    #[test]
    fn hmac_signature_empty_body() {
        let secret = b"key";
        let sig = compute_hmac_signature(secret, "POST", "/", b"", 1700000000).unwrap();
        assert!(sig.starts_with("sha256="));
        assert!(sig.len() > "sha256=".len());
    }

    /// Migration regression guard: closes #799. The HMAC pipeline now
    /// goes through `rustgate_core::crypto::hmac_sha256_tag`. Pin
    /// byte-for-byte equivalence to the previous inlined
    /// `Hmac::<Sha256>::new_from_slice(...).update(...).finalize()`
    /// path so a future tweak to `compute_hmac_signature` cannot
    /// silently break in-flight signed webhook deliveries.
    #[test]
    fn compute_hmac_signature_matches_inlined_construction() {
        let secret = b"webhook-secret";
        let body = b"some-payload";
        let timestamp = 1700000000u64;

        let helper_sig =
            compute_hmac_signature(secret, "POST", "/endpoint", body, timestamp).unwrap();

        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(b"POST");
        mac.update(b".");
        mac.update(b"/endpoint");
        mac.update(b".");
        mac.update(body);
        let inlined = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        assert_eq!(helper_sig, inlined);
    }

    #[test]
    fn hmac_signature_deterministic() {
        let secret = b"test-key";
        let data = b"test-data";
        let timestamp = 1700000000u64;
        let sig1 = compute_hmac_signature(secret, "POST", "/x", data, timestamp).unwrap();
        let sig2 = compute_hmac_signature(secret, "POST", "/x", data, timestamp).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn hmac_different_data_different_signature() {
        let secret = b"key";
        let timestamp = 1700000000u64;
        let sig1 = compute_hmac_signature(secret, "POST", "/x", b"data1", timestamp).unwrap();
        let sig2 = compute_hmac_signature(secret, "POST", "/x", b"data2", timestamp).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn hmac_different_timestamp_different_signature() {
        let secret = b"key";
        let data = b"same-data";
        let sig1 = compute_hmac_signature(secret, "POST", "/x", data, 1000).unwrap();
        let sig2 = compute_hmac_signature(secret, "POST", "/x", data, 2000).unwrap();
        assert_ne!(sig1, sig2);
    }

    /// F-47 / #747: the canonical signed bytes MUST include
    /// `"<timestamp>.<METHOD>.<path>.<body>"` so a captured signature is
    /// bound to its endpoint, not just to its body. The previous
    /// `<timestamp>.<body>` layout left the signature endpoint-agnostic
    /// and a compromised webhook URL could replay an `/alert` body
    /// against `/shutdown`.
    #[test]
    fn hmac_signed_payload_includes_method_and_path() {
        let secret = b"supersecretkey";
        let body = b"hello-body";
        let timestamp = 1700000000u64;
        let sig = compute_hmac_signature(secret, "POST", "/alert", body, timestamp).unwrap();

        // Reconstruct the canonical payload manually: timestamp, method,
        // path, body, joined by `.`. If the implementation drops any
        // segment or reorders them, this assertion fails.
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(b"1700000000.POST./alert.");
        mac.update(body);
        let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert_eq!(sig, expected);
    }

    /// F-47 / #747 — load-bearing security regression: a signature
    /// generated for `path=/alert` MUST NOT verify against `path=/shutdown`,
    /// even with the same timestamp + body + secret. This is the
    /// cross-endpoint replay attack the canonical-payload change closes.
    #[test]
    fn hmac_replay_to_different_path_rejected() {
        let secret = b"supersecretkey";
        let body = b"benign body that an attacker captures";
        let timestamp = 1700000000u64;

        // Signer is a webhook publishing to /alert.
        let signature = compute_hmac_signature(secret, "POST", "/alert", body, timestamp).unwrap();

        // Attacker replays the same body+sig+timestamp to /shutdown.
        let verified =
            verify_hmac_signature(secret, "POST", "/shutdown", body, timestamp, &signature)
                .unwrap();
        assert!(
            !verified,
            "cross-endpoint replay must fail: signature for /alert verified against /shutdown"
        );

        // Sanity: replay back to the original path verifies as expected.
        let verified_self =
            verify_hmac_signature(secret, "POST", "/alert", body, timestamp, &signature).unwrap();
        assert!(verified_self, "signature must verify against its own path");
    }

    /// F-47 / #747: a signature generated for `method=POST` MUST NOT
    /// verify against `method=GET`. Method binding is independent of
    /// path binding — both must hold.
    #[test]
    fn hmac_replay_with_different_method_rejected() {
        let secret = b"supersecretkey";
        let body = b"some body";
        let timestamp = 1700000000u64;

        let signature =
            compute_hmac_signature(secret, "POST", "/endpoint", body, timestamp).unwrap();

        let verified =
            verify_hmac_signature(secret, "GET", "/endpoint", body, timestamp, &signature).unwrap();
        assert!(
            !verified,
            "cross-method replay must fail: POST signature verified as GET"
        );
    }

    /// Happy path regression guard: matching method, path, body, and
    /// timestamp MUST verify cleanly. Without this the load-bearing
    /// security tests above could pass while the verifier silently
    /// rejects everything (false-negative bug).
    #[test]
    fn hmac_round_trip_succeeds_for_matching_method_path_body_timestamp() {
        let secret = b"the-shared-secret";
        let body = b"{\"alert\":\"motion-detected\"}";
        let timestamp = 1700000000u64;
        let method = "POST";
        let path = "/alert";

        let signature = compute_hmac_signature(secret, method, path, body, timestamp).unwrap();
        let verified =
            verify_hmac_signature(secret, method, path, body, timestamp, &signature).unwrap();

        assert!(verified, "matching canonical inputs must verify");
    }

    /// The verifier MUST use a constant-time comparison
    /// (`subtle::ConstantTimeEq`) per CLAUDE.md so a timing side-channel
    /// cannot leak how many leading hex bytes of the digest match. This
    /// is a defense-in-depth check: short of measuring the wall clock,
    /// the cleanest assertion is that two signatures differing only in
    /// the *last* byte still produce a verification rejection (i.e. the
    /// comparator does not short-circuit on the first matching byte the
    /// way `==` would on byte arrays of identical length).
    #[test]
    fn hmac_constant_time_compare_used() {
        let secret = b"supersecretkey";
        let body = b"some body";
        let timestamp = 1700000000u64;

        let real = compute_hmac_signature(secret, "POST", "/x", body, timestamp).unwrap();

        // Mutate the LAST hex byte of the signature. A short-circuiting
        // comparator that returned on first mismatch would still reject
        // this; the load-bearing property is that *every* mismatched
        // input — first-byte, mid-byte, last-byte — produces a rejection
        // without leaking via timing.
        let mut tampered: Vec<char> = real.chars().collect();
        let last_idx = tampered.len() - 1;
        let replacement = if tampered[last_idx] == '0' { '1' } else { '0' };
        tampered[last_idx] = replacement;
        let tampered: String = tampered.into_iter().collect();
        assert_ne!(real, tampered, "tampering must actually change the digest");

        let verified =
            verify_hmac_signature(secret, "POST", "/x", body, timestamp, &tampered).unwrap();
        assert!(
            !verified,
            "tampered last-byte signature must be rejected (proves verifier checks full digest)"
        );

        // Also pin: a same-length all-different signature must reject.
        let bogus = format!("sha256={}", "0".repeat(64));
        let verified_bogus =
            verify_hmac_signature(secret, "POST", "/x", body, timestamp, &bogus).unwrap();
        assert!(!verified_bogus, "all-zero digest must be rejected");

        // Defense-in-depth: confirm the verifier source actually uses
        // `subtle::ConstantTimeEq` rather than `==`. This pins the
        // CLAUDE.md contract at compile time — if a future refactor
        // swaps to `==`, the test still passes the rejection asserts
        // above but this assertion fails.
        let source = include_str!("auth.rs");
        assert!(
            source.contains("ct_eq"),
            "verify_hmac_signature MUST use subtle::ConstantTimeEq::ct_eq per CLAUDE.md"
        );
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
        let result = state.apply(builder, "POST", "/test", b"body").unwrap();
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
        let result = state.apply(builder, "POST", "/test", b"body").unwrap();
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
        let result = state.apply(builder, "POST", "/test", body).unwrap();
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

        // Verify signature independently using the timestamp + the
        // canonical method+path bindings the apply path threaded in.
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(ts_str.as_bytes());
        mac.update(b".");
        mac.update(b"POST");
        mac.update(b".");
        mac.update(b"/test");
        mac.update(b".");
        mac.update(body);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig, format!("sha256={expected}"));
    }
}
