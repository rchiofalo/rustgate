// Copyright © 2026 Roberto Chiofalo.

//! JWT token authentication for federation connections.
//!
//! Provides HMAC-SHA256 signed JWT tokens as an alternative to
//! certificate-only federation authentication. Tokens carry peer
//! identity, group claims, and expiration.
//!
//! This is an opt-in layer — mTLS remains the default transport
//! security. JWT adds per-connection authorization claims that can
//! be rotated without re-issuing certificates.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use lru::LruCache;
use rustgate_core::b64;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Minimum secret length in bytes for HMAC-SHA256 security.
const MIN_SECRET_LENGTH: usize = 32;

/// Default maximum number of revoked JTIs tracked.
const DEFAULT_REVOCATION_CAPACITY: usize = 10_000;

/// How often to amortise the expired-entry sweep, measured in `revoke()`
/// calls. At the default of 128, a cache at the 10k-entry capacity
/// triggers at most 1 full O(n) scan per 128 revocations — bounding
/// the amortised cost at O(n / 128) per call while still reclaiming
/// space proactively before the LRU-based eviction kicks in.
const EXPIRY_SWEEP_INTERVAL: u64 = 128;

/// Maximum clock skew tolerance in seconds for `iat` validation.
/// Tokens issued slightly in the future (within this window) are accepted
/// to account for clock drift between federation peers.
const MAX_CLOCK_SKEW_SECS: u64 = 60;

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
    /// HMAC-SHA256 signing key. Wrapped in [`Zeroizing`] so the key
    /// material is wiped from memory when the authority is dropped.
    secret: Zeroizing<Vec<u8>>,
    /// Issuer name stamped into tokens.
    issuer: String,
    /// Default token lifetime.
    default_expiry: Duration,
    /// Revoked token IDs mapped to their expiration time (Unix seconds).
    ///
    /// Backed by [`LruCache`] for O(1) insertion, lookup, and capacity
    /// eviction. Expired entries are proactively reclaimed on an
    /// amortised sweep ([`EXPIRY_SWEEP_INTERVAL`]); anything not yet
    /// swept is naturally evicted by the LRU when capacity is reached.
    revoked: Mutex<RevocationState>,
    /// Maximum number of entries in the revocation cache.
    revocation_capacity: NonZeroUsize,
}

/// Lock-protected revocation cache state. Keeping the sweep counter
/// inside the mutex guarantees the "every N revokes" accounting is
/// race-free across concurrent `revoke()` callers.
struct RevocationState {
    entries: LruCache<String, u64>,
    /// Number of `revoke()` calls since the last expired-entry sweep.
    sweep_counter: u64,
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
    /// The secret must be at least 32 bytes (`MIN_SECRET_LENGTH`) to
    /// provide full HMAC-SHA256 security.
    pub fn new(secret: impl Into<Vec<u8>>, issuer: impl Into<String>) -> Result<Self, JwtError> {
        let secret = Zeroizing::new(secret.into());
        if secret.len() < MIN_SECRET_LENGTH {
            return Err(JwtError::SecretTooShort {
                min: MIN_SECRET_LENGTH,
                actual: secret.len(),
            });
        }
        let capacity = NonZeroUsize::new(DEFAULT_REVOCATION_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        Ok(Self {
            secret,
            issuer: issuer.into(),
            default_expiry: Duration::from_secs(3600),
            revoked: Mutex::new(RevocationState {
                entries: LruCache::new(capacity),
                sweep_counter: 0,
            }),
            revocation_capacity: capacity,
        })
    }

    /// Set the default token lifetime.
    pub fn with_expiry(mut self, expiry: Duration) -> Self {
        self.default_expiry = expiry;
        self
    }

    /// Set the maximum number of entries in the revocation cache.
    ///
    /// A value of `0` is coerced to `1`; zero-capacity would make the
    /// cache immediately evict every insertion, silently defeating
    /// revocation. Existing entries are dropped on resize.
    pub fn with_revocation_capacity(mut self, capacity: usize) -> Self {
        let nz = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN);
        self.revocation_capacity = nz;
        // Replace the cache rather than calling resize so the old entries
        // are dropped deterministically — avoids growth / shrink ambiguity
        // across LruCache versions.
        let mut guard = match self.revoked.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.entries = LruCache::new(nz);
        guard.sweep_counter = 0;
        drop(guard);
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

        // Check issued-at: reject tokens with iat in the future (beyond clock skew)
        if claims.iat > now.as_secs() + MAX_CLOCK_SKEW_SECS {
            return Err(JwtError::IssuedInFuture);
        }

        // Check issuer
        if claims.iss != self.issuer {
            return Err(JwtError::InvalidIssuer);
        }

        // Check revocation (non-promoting: `peek` does not touch LRU order
        // so a flood of validations cannot keep a revoked token anchored
        // at the MRU end indefinitely).
        if !claims.jti.is_empty() {
            let revoked = match self.revoked.lock() {
                Ok(r) => r,
                Err(poisoned) => poisoned.into_inner(),
            };
            if revoked.entries.peek(&claims.jti).is_some() {
                return Err(JwtError::Revoked);
            }
        }

        Ok(claims)
    }

    /// Revoke a token by its JTI (unique identifier).
    ///
    /// The `exp` parameter is the token's expiration time (Unix seconds).
    /// Insertion is O(1); capacity eviction is O(1) (least-recently-used
    /// JTI is dropped). Expired entries are reclaimed on an amortised
    /// sweep every `EXPIRY_SWEEP_INTERVAL` `revoke()` calls — bounding
    /// the per-call cost while still freeing space proactively.
    pub fn revoke(&self, jti: &str, exp: u64) {
        let mut state = match self.revoked.lock() {
            Ok(r) => r,
            Err(poisoned) => poisoned.into_inner(),
        };

        state.sweep_counter = state.sweep_counter.wrapping_add(1);
        if state.sweep_counter % EXPIRY_SWEEP_INTERVAL == 0 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            // LruCache has no `retain`; collect first to avoid mutating
            // while iterating.
            let expired: Vec<String> = state
                .entries
                .iter()
                .filter(|&(_, &v)| v <= now)
                .map(|(k, _)| k.clone())
                .collect();
            for k in &expired {
                let _ = state.entries.pop(k);
            }
        }

        // O(1) insert; O(1) LRU eviction when at capacity.
        let _ = state.entries.put(jti.to_string(), exp);

        let size = state.entries.len();
        let capacity = self.revocation_capacity.get();
        let threshold = (capacity as f64 * REVOCATION_WARN_THRESHOLD) as usize;
        if size >= threshold {
            tracing::warn!(
                size,
                capacity,
                "JWT revocation cache at {:.0}% capacity",
                (size as f64 / capacity as f64) * 100.0,
            );
        }
    }

    /// Number of revoked tokens tracked.
    pub fn revoked_count(&self) -> usize {
        match self.revoked.lock() {
            Ok(r) => r.entries.len(),
            Err(poisoned) => poisoned.into_inner().entries.len(),
        }
    }
}

/// JWT encoding/validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    /// Token has expired.
    Expired,
    /// Token `iat` (issued-at) is in the future beyond clock skew tolerance.
    IssuedInFuture,
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
            JwtError::IssuedInFuture => write!(f, "token issued in the future"),
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
    let header_b64 = b64::encode_url_safe(header.as_bytes());

    let payload_json =
        serde_json::to_string(claims).map_err(|e| JwtError::SerializationError(e.to_string()))?;
    let payload_b64 = b64::encode_url_safe(payload_json.as_bytes());

    let signing_input = format!("{header_b64}.{payload_b64}");

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| JwtError::InvalidSignature)?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = b64::encode_url_safe(signature);

    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Decode and verify a JWT token, returning the claims.
fn decode(secret: &[u8], token: &str) -> Result<FederationClaims, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::Malformed);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let actual_sig = b64::decode_url_safe(parts[2]).map_err(|_| JwtError::Malformed)?;

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| JwtError::InvalidSignature)?;
    mac.update(signing_input.as_bytes());
    // Constant-time verification via the hmac crate.
    mac.verify_slice(&actual_sig)
        .map_err(|_| JwtError::InvalidSignature)?;

    let payload_bytes = b64::decode_url_safe(parts[1]).map_err(|_| JwtError::Malformed)?;
    let claims: FederationClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| JwtError::SerializationError(e.to_string()))?;

    Ok(claims)
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
    fn future_iat_rejected() {
        let auth = make_authority();

        // Manually create a token with iat far in the future
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time");
        let future_iat = now.as_secs() + MAX_CLOCK_SKEW_SECS + 600;

        let claims = FederationClaims {
            sub: "peer-1".to_string(),
            iss: "rustgate-test".to_string(),
            exp: future_iat + 3600,
            iat: future_iat,
            jti: "test-jti".to_string(),
            groups: vec![],
        };

        let token = encode(&auth.secret, &claims).expect("encode");
        let result = auth.validate(&token);
        assert_eq!(result, Err(JwtError::IssuedInFuture));
    }

    #[test]
    fn iat_within_skew_accepted() {
        let auth = make_authority();

        // iat slightly in the future but within skew tolerance
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time");
        let future_iat = now.as_secs() + MAX_CLOCK_SKEW_SECS - 5;

        let claims = FederationClaims {
            sub: "peer-1".to_string(),
            iss: "rustgate-test".to_string(),
            exp: future_iat + 3600,
            iat: future_iat,
            jti: "test-jti".to_string(),
            groups: vec![],
        };

        let token = encode(&auth.secret, &claims).expect("encode");
        let result = auth.validate(&token);
        assert!(result.is_ok(), "iat within skew should be accepted");
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
        // Sweeps are amortised every EXPIRY_SWEEP_INTERVAL revokes —
        // the expired entry should be reclaimed once the counter wraps
        // past the interval, not on the next revoke.
        let auth = make_authority();
        auth.revoke("old-jti", 1);
        assert_eq!(auth.revoked_count(), 1);

        // One extra insert short of the interval: still not swept.
        for i in 0..(EXPIRY_SWEEP_INTERVAL - 2) {
            auth.revoke(&format!("filler-{i}"), u64::MAX);
        }
        // Drive one more revoke so the counter hits the sweep modulus.
        auth.revoke("new-jti", u64::MAX);

        // Now the sweep has run: `old-jti` (exp=1) is reclaimed.
        // The count is exactly the number of still-valid fillers + new-jti.
        let count = auth.revoked_count();
        assert!(
            count < (EXPIRY_SWEEP_INTERVAL as usize),
            "expected sweep to drop `old-jti`, got count={count}"
        );
        // And the specific JTI should no longer validate as revoked.
        let revoked = match auth.revoked.lock() {
            Ok(r) => r,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert!(
            revoked.entries.peek("old-jti").is_none(),
            "old-jti should be purged"
        );
    }

    #[test]
    fn sweep_does_not_evict_unexpired_entries() {
        let auth = make_authority();
        let future_exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(u64::MAX, |d| d.as_secs() + 3600);

        // Force a sweep to run without anything to reclaim.
        for i in 0..EXPIRY_SWEEP_INTERVAL {
            auth.revoke(&format!("jti-{i}"), future_exp);
        }

        // Every entry was unexpired, so the sweep must not have pruned any.
        assert_eq!(
            auth.revoked_count(),
            EXPIRY_SWEEP_INTERVAL as usize,
            "amortised sweep must not drop unexpired entries"
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

        // Fourth revocation should evict the least-recently-used entry.
        auth.revoke("jti-4", u64::MAX);
        assert_eq!(auth.revoked_count(), 3, "should not exceed capacity");
    }

    #[test]
    fn eviction_drops_least_recently_inserted_at_capacity() {
        // Regression for #761: capacity eviction must be O(1) and
        // deterministically target the least-recently-used entry, not a
        // linear scan. This test pins down the LRU ordering: `jti-1` was
        // inserted first and is the LRU victim when capacity is hit.
        let auth = JwtAuthority::new(b"test-secret-key-for-jwt-testing!!".to_vec(), "test")
            .expect("valid secret")
            .with_revocation_capacity(3);

        auth.revoke("jti-1", u64::MAX);
        auth.revoke("jti-2", u64::MAX);
        auth.revoke("jti-3", u64::MAX);
        auth.revoke("jti-4", u64::MAX);

        let guard = match auth.revoked.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert!(
            guard.entries.peek("jti-1").is_none(),
            "LRU entry jti-1 must be evicted"
        );
        for jti in ["jti-2", "jti-3", "jti-4"] {
            assert!(
                guard.entries.peek(jti).is_some(),
                "{jti} must survive eviction"
            );
        }
    }

    #[test]
    fn validation_peek_does_not_promote_revoked_jti() {
        // Guards against a degenerate case where a high-volume validator
        // hammering a revoked JTI could anchor it at the MRU end, starving
        // genuine new revocations during a revocation burst. `validate()`
        // uses `peek` precisely to prevent this.
        let auth = JwtAuthority::new(b"test-secret-key-for-jwt-testing!!".to_vec(), "test")
            .expect("valid secret")
            .with_revocation_capacity(2);

        // Insert: order is [jti-A, jti-B]  (A = LRU)
        auth.revoke("jti-A", u64::MAX);
        auth.revoke("jti-B", u64::MAX);

        // Simulate validation attempts that would "look up" jti-A many times.
        // If `peek` weren't used, this would promote jti-A to MRU.
        {
            let guard = match auth.revoked.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            for _ in 0..10 {
                assert!(guard.entries.peek("jti-A").is_some());
            }
        }

        // A third revocation must still evict jti-A, because peek did not
        // promote it away from the LRU slot.
        auth.revoke("jti-C", u64::MAX);
        let guard = match auth.revoked.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert!(
            guard.entries.peek("jti-A").is_none(),
            "peek must not promote; jti-A should have been evicted"
        );
    }

    #[test]
    fn zero_capacity_coerced_to_min_one() {
        // Regression guard: `with_revocation_capacity(0)` must not silently
        // produce a cache that evicts every insertion.
        let auth = JwtAuthority::new(b"test-secret-key-for-jwt-testing!!".to_vec(), "test")
            .expect("valid secret")
            .with_revocation_capacity(0);

        auth.revoke("jti-1", u64::MAX);
        assert_eq!(
            auth.revoked_count(),
            1,
            "capacity=0 must coerce to 1 and retain at least one entry"
        );
    }

    #[test]
    fn base64url_roundtrip() {
        let data = b"Hello, Federation JWT!";
        let encoded = b64::encode_url_safe(data);
        let decoded = b64::decode_url_safe(&encoded).expect("decode");
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
