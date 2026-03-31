//! JWT token authentication for federation connections.
//!
//! Provides HMAC-SHA256 signed JWT tokens as an alternative to
//! certificate-only federation authentication. Tokens carry peer
//! identity, group claims, and expiration.
//!
//! This is an opt-in layer — mTLS remains the default transport
//! security. JWT adds per-connection authorization claims that can
//! be rotated without re-issuing certificates.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Minimum secret length in bytes for HMAC-SHA256 security.
const MIN_SECRET_LENGTH: usize = 32;

/// Default maximum number of revoked JTIs tracked.
const DEFAULT_REVOCATION_CAPACITY: usize = 10_000;

/// Warn when revocation cache reaches this fraction of capacity.
const REVOCATION_WARN_THRESHOLD: f64 = 0.8;

/// JWT claims for federation peer authentication.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FederationClaims {
    /// Subject — the peer's federation ID.
    pub sub: String,
    /// Issuer — the server that created the token.
    pub iss: String,
    /// Expiration time (seconds since Unix epoch).
    pub exp: u64,
    /// Issued-at time (seconds since Unix epoch).
    pub iat: u64,
    /// Unique token identifier (for revocation).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jti: String,
    /// Groups the peer is authorized for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// Manages JWT issuance, validation, and revocation for federation.
pub struct JwtAuthority {
    /// HMAC-SHA256 signing key.
    secret: Vec<u8>,
    /// Issuer name stamped into tokens.
    issuer: String,
    /// Default token lifetime.
    default_expiry: Duration,
    /// Revoked token IDs mapped to their expiration time (Unix seconds).
    /// Entries are auto-expired during `revoke()` when the token's `exp` has passed.
    revoked: Mutex<HashMap<String, u64>>,
    /// Maximum number of entries in the revocation cache.
    revocation_capacity: usize,
}

impl std::fmt::Debug for JwtAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtAuthority")
            .field("issuer", &self.issuer)
            .field("default_expiry", &self.default_expiry)
            .finish_non_exhaustive()
    }
}

impl JwtAuthority {
    /// Create a new JWT authority with the given signing secret.
    ///
    /// The secret must be at least [`MIN_SECRET_LENGTH`] bytes (32) to
    /// provide full HMAC-SHA256 security.
    pub fn new(secret: impl Into<Vec<u8>>, issuer: impl Into<String>) -> Result<Self, JwtError> {
        let secret = secret.into();
        if secret.len() < MIN_SECRET_LENGTH {
            return Err(JwtError::SecretTooShort {
                min: MIN_SECRET_LENGTH,
                actual: secret.len(),
            });
        }
        Ok(Self {
            secret,
            issuer: issuer.into(),
            default_expiry: Duration::from_secs(3600),
            revoked: Mutex::new(HashMap::new()),
            revocation_capacity: DEFAULT_REVOCATION_CAPACITY,
        })
    }

    /// Set the default token lifetime.
    pub fn with_expiry(mut self, expiry: Duration) -> Self {
        self.default_expiry = expiry;
        self
    }

    /// Set the maximum number of entries in the revocation cache.
    pub fn with_revocation_capacity(mut self, capacity: usize) -> Self {
        self.revocation_capacity = capacity;
        self
    }

    /// Issue a signed JWT for a federation peer.
    pub fn issue(&self, peer_id: &str, groups: Vec<String>) -> Result<String, JwtError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtError::ClockError)?;

        let jti = generate_jti(peer_id, now.as_secs());

        let claims = FederationClaims {
            sub: peer_id.to_string(),
            iss: self.issuer.clone(),
            exp: now.as_secs() + self.default_expiry.as_secs(),
            iat: now.as_secs(),
            jti,
            groups,
        };

        encode(&self.secret, &claims)
    }

    /// Issue a token with a custom expiration duration.
    pub fn issue_with_expiry(
        &self,
        peer_id: &str,
        groups: Vec<String>,
        expiry: Duration,
    ) -> Result<String, JwtError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtError::ClockError)?;

        let jti = generate_jti(peer_id, now.as_secs());

        let claims = FederationClaims {
            sub: peer_id.to_string(),
            iss: self.issuer.clone(),
            exp: now.as_secs() + expiry.as_secs(),
            iat: now.as_secs(),
            jti,
            groups,
        };

        encode(&self.secret, &claims)
    }

    /// Validate a JWT token and return the claims if valid.
    pub fn validate(&self, token: &str) -> Result<FederationClaims, JwtError> {
        let claims = decode(&self.secret, token)?;

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtError::ClockError)?;

        if claims.exp <= now.as_secs() {
            return Err(JwtError::Expired);
        }

        // Check issuer
        if claims.iss != self.issuer {
            return Err(JwtError::InvalidIssuer);
        }

        // Check revocation
        if !claims.jti.is_empty() {
            let revoked = match self.revoked.lock() {
                Ok(r) => r,
                Err(poisoned) => poisoned.into_inner(),
            };
            if revoked.contains_key(&claims.jti) {
                return Err(JwtError::Revoked);
            }
        }

        Ok(claims)
    }

    /// Revoke a token by its JTI (unique identifier).
    ///
    /// The `exp` parameter is the token's expiration time (Unix seconds).
    /// Once that time passes, the entry is automatically purged during
    /// subsequent `revoke()` calls.
    ///
    /// If the cache is at capacity after purging expired entries, the
    /// oldest entry (by expiration time) is evicted.
    pub fn revoke(&self, jti: &str, exp: u64) {
        let mut revoked = match self.revoked.lock() {
            Ok(r) => r,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Purge expired entries first.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        revoked.retain(|_, &mut entry_exp| entry_exp > now);

        // Evict the oldest entry if still at capacity.
        if revoked.len() >= self.revocation_capacity
            && let Some(oldest_jti) = revoked
                .iter()
                .min_by_key(|(_, exp)| *exp)
                .map(|(jti, _)| jti.clone())
        {
            let _ = revoked.remove(&oldest_jti);
        }

        let size = revoked.len() + 1;
        let _ = revoked.insert(jti.to_string(), exp);

        let threshold = (self.revocation_capacity as f64 * REVOCATION_WARN_THRESHOLD) as usize;
        if size >= threshold {
            tracing::warn!(
                size,
                capacity = self.revocation_capacity,
                "JWT revocation cache at {:.0}% capacity",
                (size as f64 / self.revocation_capacity as f64) * 100.0,
            );
        }
    }

    /// Number of revoked tokens tracked.
    pub fn revoked_count(&self) -> usize {
        match self.revoked.lock() {
            Ok(r) => r.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }
}

/// JWT encoding/validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    /// Token has expired.
    Expired,
    /// Token signature is invalid.
    InvalidSignature,
    /// Token format is malformed.
    Malformed,
    /// Token issuer does not match.
    InvalidIssuer,
    /// Token has been revoked.
    Revoked,
    /// System clock error.
    ClockError,
    /// JSON serialization/deserialization error.
    SerializationError(String),
    /// Signing secret is too short.
    SecretTooShort {
        /// Minimum required length in bytes.
        min: usize,
        /// Actual length provided.
        actual: usize,
    },
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Expired => write!(f, "token expired"),
            JwtError::InvalidSignature => write!(f, "invalid signature"),
            JwtError::Malformed => write!(f, "malformed token"),
            JwtError::InvalidIssuer => write!(f, "invalid issuer"),
            JwtError::Revoked => write!(f, "token revoked"),
            JwtError::ClockError => write!(f, "system clock error"),
            JwtError::SerializationError(msg) => write!(f, "serialization error: {msg}"),
            JwtError::SecretTooShort { min, actual } => {
                write!(f, "secret too short: need {min} bytes, got {actual}")
            }
        }
    }
}

impl std::error::Error for JwtError {}

// ── JWT encoding/decoding ───────────────────────────────────────────

/// Encode claims into a signed JWT string.
fn encode(secret: &[u8], claims: &FederationClaims) -> Result<String, JwtError> {
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let header_b64 = base64url_encode(header.as_bytes());

    let payload_json =
        serde_json::to_string(claims).map_err(|e| JwtError::SerializationError(e.to_string()))?;
    let payload_b64 = base64url_encode(payload_json.as_bytes());

    let signing_input = format!("{header_b64}.{payload_b64}");

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| JwtError::InvalidSignature)?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = base64url_encode(&signature);

    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Decode and verify a JWT token, returning the claims.
fn decode(secret: &[u8], token: &str) -> Result<FederationClaims, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::Malformed);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let actual_sig = base64url_decode(parts[2]).map_err(|_| JwtError::Malformed)?;

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| JwtError::InvalidSignature)?;
    mac.update(signing_input.as_bytes());
    // Constant-time verification via the hmac crate.
    mac.verify_slice(&actual_sig)
        .map_err(|_| JwtError::InvalidSignature)?;

    let payload_bytes = base64url_decode(parts[1]).map_err(|_| JwtError::Malformed)?;
    let claims: FederationClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| JwtError::SerializationError(e.to_string()))?;

    Ok(claims)
}

// ── Base64url encoding/decoding ─────────────────────────────────────

const B64URL_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(B64URL_ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(B64URL_ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(B64URL_ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(B64URL_ALPHABET[(triple & 0x3F) as usize] as char);
        }
    }

    result
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, ()> {
    let mut buf = Vec::with_capacity(input.len() * 3 / 4);
    let bytes = input.as_bytes();
    let chunks = bytes.chunks(4);

    for chunk in chunks {
        let mut sextet = [0u32; 4];
        let mut pad = 0;

        for (i, &b) in chunk.iter().enumerate() {
            sextet[i] = b64url_char_to_val(b)?;
        }
        for s in sextet.iter_mut().skip(chunk.len()) {
            *s = 0;
            pad += 1;
        }

        let triple = (sextet[0] << 18) | (sextet[1] << 12) | (sextet[2] << 6) | sextet[3];

        buf.push(((triple >> 16) & 0xFF) as u8);
        if pad < 2 {
            buf.push(((triple >> 8) & 0xFF) as u8);
        }
        if pad < 1 {
            buf.push((triple & 0xFF) as u8);
        }
    }

    Ok(buf)
}

fn b64url_char_to_val(c: u8) -> Result<u32, ()> {
    match c {
        b'A'..=b'Z' => Ok((c - b'A') as u32),
        b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
        b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(()),
    }
}

/// Generate a unique token identifier from peer ID and timestamp.
fn generate_jti(peer_id: &str, timestamp: u64) -> String {
    let mut h = Sha256::new();
    h.update(peer_id.as_bytes());
    h.update(timestamp.to_le_bytes());
    let hash = h.finalize();
    // Use first 16 bytes as hex for a short unique ID
    hash[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_authority() -> JwtAuthority {
        JwtAuthority::new(
            b"test-secret-key-for-jwt-testing!!".to_vec(),
            "rustgate-test",
        )
        .expect("valid secret")
    }

    #[test]
    fn issue_and_validate() {
        let auth = make_authority();
        let token = auth
            .issue("peer-1", vec!["Alpha".into()])
            .expect("issue should succeed");

        let claims = auth.validate(&token).expect("validate should succeed");
        assert_eq!(claims.sub, "peer-1");
        assert_eq!(claims.iss, "rustgate-test");
        assert_eq!(claims.groups, vec!["Alpha"]);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn expired_token_rejected() {
        let auth = JwtAuthority::new(b"test-secret-key-for-jwt-testing!!".to_vec(), "test")
            .expect("valid secret")
            .with_expiry(Duration::from_secs(0));

        let token = auth.issue("peer-1", vec![]).expect("issue");

        // Token expires immediately (exp == iat)
        let result = auth.validate(&token);
        assert_eq!(result, Err(JwtError::Expired));
    }

    #[test]
    fn wrong_secret_rejected() {
        let auth1 = JwtAuthority::new(b"test-secret-key-for-jwt-wrong-1!!".to_vec(), "test")
            .expect("valid secret");
        let auth2 = JwtAuthority::new(b"test-secret-key-for-jwt-wrong-2!!".to_vec(), "test")
            .expect("valid secret");

        let token = auth1.issue("peer-1", vec![]).expect("issue");
        let result = auth2.validate(&token);
        assert_eq!(result, Err(JwtError::InvalidSignature));
    }

    #[test]
    fn wrong_issuer_rejected() {
        let auth1 = JwtAuthority::new(b"test-secret-key-for-jwt-testing!!".to_vec(), "issuer-1")
            .expect("valid secret");
        let auth2 = JwtAuthority::new(b"test-secret-key-for-jwt-testing!!".to_vec(), "issuer-2")
            .expect("valid secret");

        let token = auth1.issue("peer-1", vec![]).expect("issue");
        let result = auth2.validate(&token);
        assert_eq!(result, Err(JwtError::InvalidIssuer));
    }

    #[test]
    fn revoked_token_rejected() {
        let auth = make_authority();
        let token = auth.issue("peer-1", vec![]).expect("issue");

        let claims = auth.validate(&token).expect("valid before revocation");
        auth.revoke(&claims.jti, claims.exp);

        let result = auth.validate(&token);
        assert_eq!(result, Err(JwtError::Revoked));
    }

    #[test]
    fn malformed_token_rejected() {
        let auth = make_authority();
        assert_eq!(auth.validate("not-a-jwt"), Err(JwtError::Malformed));
        assert_eq!(auth.validate("a.b"), Err(JwtError::Malformed));
        assert_eq!(auth.validate(""), Err(JwtError::Malformed));
    }

    #[test]
    fn tampered_payload_rejected() {
        let auth = make_authority();
        let token = auth.issue("peer-1", vec![]).expect("issue");

        // Tamper with the payload section
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{}.dGFtcGVyZWQ.{}", parts[0], parts[2]);
        assert_eq!(auth.validate(&tampered), Err(JwtError::InvalidSignature));
    }

    #[test]
    fn custom_expiry() {
        let auth = make_authority();
        let token = auth
            .issue_with_expiry("peer-1", vec![], Duration::from_secs(7200))
            .expect("issue");

        let claims = auth.validate(&token).expect("valid");
        assert!(claims.exp - claims.iat >= 7200);
    }

    #[test]
    fn revoked_count() {
        let auth = make_authority();
        assert_eq!(auth.revoked_count(), 0);
        auth.revoke("jti-1", u64::MAX);
        auth.revoke("jti-2", u64::MAX);
        assert_eq!(auth.revoked_count(), 2);
    }

    #[test]
    fn expired_revocations_are_purged() {
        let auth = make_authority();
        // Revoke with an expiration in the past — should be purged on next revoke.
        auth.revoke("old-jti", 1);
        assert_eq!(auth.revoked_count(), 1);

        // Inserting another entry triggers purge of expired ones.
        auth.revoke("new-jti", u64::MAX);
        assert_eq!(
            auth.revoked_count(),
            1,
            "expired entry should have been purged"
        );
    }

    #[test]
    fn revocation_cache_respects_capacity() {
        let auth = JwtAuthority::new(b"test-secret-key-for-jwt-testing!!".to_vec(), "test")
            .expect("valid secret")
            .with_revocation_capacity(3);

        auth.revoke("jti-1", u64::MAX);
        auth.revoke("jti-2", u64::MAX);
        auth.revoke("jti-3", u64::MAX);
        assert_eq!(auth.revoked_count(), 3);

        // Fourth revocation should evict the oldest.
        auth.revoke("jti-4", u64::MAX);
        assert_eq!(auth.revoked_count(), 3, "should not exceed capacity");
    }

    #[test]
    fn base64url_roundtrip() {
        let data = b"Hello, Federation JWT!";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).expect("decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 Test Case 2 — verify the hmac crate produces the expected output.
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        let mut mac = HmacSha256::new_from_slice(key).expect("valid key");
        mac.update(data);
        let result = mac.finalize().into_bytes();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn short_secret_rejected() {
        let result = JwtAuthority::new(b"too-short".to_vec(), "test");
        assert_eq!(
            result.expect_err("should fail with short secret"),
            JwtError::SecretTooShort { min: 32, actual: 9 }
        );
    }

    #[test]
    fn exact_minimum_secret_accepted() {
        let secret = vec![0xABu8; MIN_SECRET_LENGTH];
        let auth = JwtAuthority::new(secret, "test");
        assert!(auth.is_ok());
    }

    #[test]
    fn jwt_error_display() {
        assert_eq!(JwtError::Expired.to_string(), "token expired");
        assert_eq!(JwtError::InvalidSignature.to_string(), "invalid signature");
        assert_eq!(JwtError::Revoked.to_string(), "token revoked");
    }
}
