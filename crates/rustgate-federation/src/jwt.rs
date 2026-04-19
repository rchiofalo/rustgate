// Copyright © 2026 Roberto Chiofalo.

//! JWT token authentication for federation connections.
//!
//! Supports HMAC-SHA256 (HS256) and ECDSA P-256 SHA-256 (ES256, RFC 7518)
//! signed tokens. Tokens carry peer identity, group claims, and
//! expiration.
//!
//! This is an opt-in layer — mTLS remains the default transport
//! security. JWT adds per-connection authorization claims that can
//! be rotated without re-issuing certificates.
//!
//! # Algorithm selection
//!
//! - [`JwtAuthority::new`] creates an HS256 authority. The same secret
//!   signs and verifies tokens. Every verifier holds the ability to
//!   forge tokens, so a compromised peer leaks the issuing key for the
//!   entire federation.
//! - [`JwtAuthority::new_es256`] creates an ES256 authority. Signing uses
//!   the operator-supplied private key; verification uses per-peer public
//!   keys registered via [`JwtAuthority::with_es256_verifier`]. A
//!   compromised verifier cannot forge tokens. Tokens carry a `kid`
//!   header that routes verification to the right public key, so
//!   operators can stage key rotation by pre-distributing the next
//!   `kid`'s public key before flipping the issuer.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use lru::LruCache;
use ring::signature::{self as ring_sig, KeyPair};
use rustgate_core::b64;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Minimum secret length in bytes for HMAC-SHA256 security.
const MIN_SECRET_LENGTH: usize = 32;

/// Maximum permitted length for a `kid` (key identifier) header field.
/// Keeps header JSON bounded and guards against hostile peers trying to
/// inflate tokens via pathological identifiers.
const MAX_KID_LENGTH: usize = 64;

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

/// JWT signing/verification algorithm per RFC 7518.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC-SHA256 — symmetric, a single secret signs and verifies.
    Hs256,
    /// ECDSA P-256 with SHA-256 — asymmetric, fixed 64-byte signature
    /// `(r || s)` per RFC 7518 §3.4.
    Es256,
}

impl Algorithm {
    fn as_str(self) -> &'static str {
        match self {
            Algorithm::Hs256 => "HS256",
            Algorithm::Es256 => "ES256",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "HS256" => Some(Algorithm::Hs256),
            "ES256" => Some(Algorithm::Es256),
            _ => None,
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Active signing key used to issue tokens.
///
/// The `Es256` variant boxes the [`ring_sig::EcdsaKeyPair`] because it
/// is ~264 bytes (vs ~48 bytes for the HS256 variant), and we don't
/// want every `SigningKey` value to pay that cost when the authority
/// is HS256. The clippy `large_enum_variant` lint flags the disparity.
enum SigningKey {
    Hs256 {
        secret: Zeroizing<Vec<u8>>,
        kid: Option<String>,
    },
    Es256 {
        key_pair: Box<ring_sig::EcdsaKeyPair>,
        kid: String,
    },
}

impl SigningKey {
    fn algorithm(&self) -> Algorithm {
        match self {
            SigningKey::Hs256 { .. } => Algorithm::Hs256,
            SigningKey::Es256 { .. } => Algorithm::Es256,
        }
    }

    fn kid(&self) -> Option<&str> {
        match self {
            SigningKey::Hs256 { kid, .. } => kid.as_deref(),
            SigningKey::Es256 { kid, .. } => Some(kid.as_str()),
        }
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, JwtError> {
        match self {
            SigningKey::Hs256 { secret, .. } => {
                let mut mac =
                    HmacSha256::new_from_slice(secret).map_err(|_| JwtError::InvalidSignature)?;
                mac.update(signing_input);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            SigningKey::Es256 { key_pair, .. } => {
                // A fresh SystemRandom is effectively free — ring keeps the
                // per-thread entropy handle internally.
                let rng = ring::rand::SystemRandom::new();
                let sig = key_pair
                    .sign(&rng, signing_input)
                    .map_err(|_| JwtError::InvalidSignature)?;
                Ok(sig.as_ref().to_vec())
            }
        }
    }
}

/// Public verifier key for validating received tokens.
///
/// Verifiers are indexed by `kid` inside [`JwtAuthority`] so a single
/// authority can validate tokens from many peers, each with its own
/// key material, without a shared secret.
enum VerificationKey {
    Hs256(Zeroizing<Vec<u8>>),
    /// ECDSA P-256 public key in SEC1 uncompressed form
    /// (`0x04 || x(32) || y(32)` = 65 bytes).
    Es256(Vec<u8>),
}

impl VerificationKey {
    fn algorithm(&self) -> Algorithm {
        match self {
            VerificationKey::Hs256(_) => Algorithm::Hs256,
            VerificationKey::Es256(_) => Algorithm::Es256,
        }
    }

    fn verify(&self, signing_input: &[u8], sig: &[u8]) -> Result<(), JwtError> {
        match self {
            VerificationKey::Hs256(secret) => {
                let mut mac =
                    HmacSha256::new_from_slice(secret).map_err(|_| JwtError::InvalidSignature)?;
                mac.update(signing_input);
                // Constant-time verification via the hmac crate.
                mac.verify_slice(sig)
                    .map_err(|_| JwtError::InvalidSignature)
            }
            VerificationKey::Es256(pub_key) => {
                ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P256_SHA256_FIXED, pub_key)
                    .verify(signing_input, sig)
                    .map_err(|_| JwtError::InvalidSignature)
            }
        }
    }
}

/// Manages JWT issuance, validation, and revocation for federation.
pub struct JwtAuthority {
    /// Active signing key — used by `issue()` / `issue_with_expiry()`.
    signing: SigningKey,
    /// Per-peer verifier keys, indexed by the JWT header `kid` field.
    /// Incoming tokens route verification here. An ES256 authority
    /// pre-populates this with its own local public key (so it can
    /// verify tokens it issued itself).
    verifiers: HashMap<String, VerificationKey>,
    /// Fallback verifier for tokens whose header has no `kid`.
    /// Present only when [`JwtAuthority::new`] (HS256) was used, so
    /// legacy tokens without a `kid` header still validate. ES256
    /// authorities always emit a `kid`, so no fallback is needed.
    legacy_verifier: Option<VerificationKey>,
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
    /// Create a new HS256 JWT authority.
    ///
    /// The secret must be at least 32 bytes (`MIN_SECRET_LENGTH`) to
    /// provide full HMAC-SHA256 security. Tokens issued by this
    /// authority omit the `kid` header (backward compatible with
    /// earlier versions of this crate). A matching HS256 verifier is
    /// installed as the `legacy_verifier` so the same authority can
    /// validate tokens it issued itself.
    pub fn new(secret: impl Into<Vec<u8>>, issuer: impl Into<String>) -> Result<Self, JwtError> {
        let secret = Zeroizing::new(secret.into());
        if secret.len() < MIN_SECRET_LENGTH {
            return Err(JwtError::SecretTooShort {
                min: MIN_SECRET_LENGTH,
                actual: secret.len(),
            });
        }
        // Dedicated copy for the verifier side — dropped when the
        // authority is dropped (so both wipes fire deterministically).
        let legacy = Zeroizing::new(secret.to_vec());
        let capacity = NonZeroUsize::new(DEFAULT_REVOCATION_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        Ok(Self {
            signing: SigningKey::Hs256 { secret, kid: None },
            verifiers: HashMap::new(),
            legacy_verifier: Some(VerificationKey::Hs256(legacy)),
            issuer: issuer.into(),
            default_expiry: Duration::from_secs(3600),
            revoked: Mutex::new(RevocationState {
                entries: LruCache::new(capacity),
                sweep_counter: 0,
            }),
            revocation_capacity: capacity,
        })
    }

    /// Create a new ES256 JWT authority.
    ///
    /// `pkcs8_der` must be a PKCS#8 v1 DER-encoded ECDSA P-256 private
    /// key. `kid` uniquely identifies this signing key; every issued
    /// token carries it in the header so remote verifiers can route to
    /// the correct public key.
    ///
    /// The local public key is registered as a verifier under the same
    /// `kid`, so this authority can validate tokens it issued itself.
    pub fn new_es256(
        pkcs8_der: impl AsRef<[u8]>,
        kid: impl Into<String>,
        issuer: impl Into<String>,
    ) -> Result<Self, JwtError> {
        let kid = validate_kid(kid.into())?;
        let rng = ring::rand::SystemRandom::new();
        let key_pair = ring_sig::EcdsaKeyPair::from_pkcs8(
            &ring_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8_der.as_ref(),
            &rng,
        )
        .map_err(|_| JwtError::InvalidKey)?;
        let local_public_key = key_pair.public_key().as_ref().to_vec();

        let mut verifiers = HashMap::new();
        let _ = verifiers.insert(kid.clone(), VerificationKey::Es256(local_public_key));

        let capacity = NonZeroUsize::new(DEFAULT_REVOCATION_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        Ok(Self {
            signing: SigningKey::Es256 {
                key_pair: Box::new(key_pair),
                kid,
            },
            verifiers,
            legacy_verifier: None,
            issuer: issuer.into(),
            default_expiry: Duration::from_secs(3600),
            revoked: Mutex::new(RevocationState {
                entries: LruCache::new(capacity),
                sweep_counter: 0,
            }),
            revocation_capacity: capacity,
        })
    }

    /// The algorithm this authority uses to sign issued tokens.
    pub fn signing_algorithm(&self) -> Algorithm {
        self.signing.algorithm()
    }

    /// The `kid` this authority stamps on issued tokens, if any.
    /// [`Self::new`] (HS256) returns `None`; [`Self::new_es256`]
    /// always returns `Some`.
    pub fn signing_kid(&self) -> Option<&str> {
        self.signing.kid()
    }

    /// Register an HS256 verifier key for a peer identified by `kid`.
    ///
    /// The secret must be at least 32 bytes (`MIN_SECRET_LENGTH`). Used to
    /// validate tokens issued by a remote HS256 peer; bootstraps the
    /// verifier registry alongside or instead of the fallback
    /// `legacy_verifier`.
    pub fn with_hs256_verifier(
        mut self,
        kid: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Result<Self, JwtError> {
        let kid = validate_kid(kid.into())?;
        let secret = Zeroizing::new(secret.into());
        if secret.len() < MIN_SECRET_LENGTH {
            return Err(JwtError::SecretTooShort {
                min: MIN_SECRET_LENGTH,
                actual: secret.len(),
            });
        }
        let _ = self.verifiers.insert(kid, VerificationKey::Hs256(secret));
        Ok(self)
    }

    /// Register an ES256 verifier key for a peer identified by `kid`.
    ///
    /// `public_key_sec1` must be a raw ECDSA P-256 uncompressed public
    /// key in SEC1 form: `0x04 || x(32) || y(32)`, 65 bytes total.
    /// No PEM or SPKI wrapping — unwrap at the call site. Extract
    /// directly from a `ring::signature::EcdsaKeyPair::public_key()` or
    /// from the raw `x`/`y` fields of a JWK.
    pub fn with_es256_verifier(
        mut self,
        kid: impl Into<String>,
        public_key_sec1: impl Into<Vec<u8>>,
    ) -> Result<Self, JwtError> {
        let kid = validate_kid(kid.into())?;
        let public_key = public_key_sec1.into();
        // SEC1 uncompressed P-256: leading 0x04 + 32 bytes X + 32 bytes Y.
        if public_key.len() != 65 || public_key.first() != Some(&0x04) {
            return Err(JwtError::InvalidKey);
        }
        let _ = self
            .verifiers
            .insert(kid, VerificationKey::Es256(public_key));
        Ok(self)
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

        encode(&self.signing, &claims)
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

        encode(&self.signing, &claims)
    }

    /// Validate a JWT token and return the claims if valid.
    ///
    /// Verification selects a key by inspecting the token's header:
    /// - If a `kid` field is present, looks it up in the peer verifier
    ///   registry (populated by `with_*_verifier` or the ES256 local
    ///   self-verifier).
    /// - If no `kid`, falls back to the `legacy_verifier` (populated
    ///   only by HS256 authorities). ES256 authorities never fall back:
    ///   tokens without a `kid` are rejected as [`JwtError::UnknownKid`].
    /// - The header's `alg` must match the selected verifier's
    ///   algorithm, or [`JwtError::AlgorithmMismatch`] is returned.
    pub fn validate(&self, token: &str) -> Result<FederationClaims, JwtError> {
        let claims = decode(self, token)?;

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
    /// Provided key material (PKCS#8 DER private key or SEC1 public key)
    /// could not be parsed.
    InvalidKey,
    /// Token header advertises an algorithm this authority does not
    /// support (only `HS256` and `ES256` are recognised).
    UnsupportedAlgorithm(String),
    /// Token header carries a `kid` that is not in the verifier registry
    /// (or no `kid` was present and no legacy verifier is configured).
    UnknownKid(String),
    /// Token header's `alg` does not match the verifier's algorithm for
    /// the selected `kid`. This catches algorithm-confusion attacks
    /// (e.g. a signed-with-HS256 token presented with an `alg: ES256`
    /// header hoping a public-key verifier treats the public key as an
    /// HMAC secret).
    AlgorithmMismatch {
        /// Algorithm declared in the token header.
        header: Algorithm,
        /// Algorithm configured on the verifier selected by `kid`.
        key: Algorithm,
    },
    /// Provided `kid` is empty, exceeds 64 bytes (`MAX_KID_LENGTH`), or
    /// contains non-printable / control characters.
    InvalidKid,
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
            JwtError::InvalidKey => write!(f, "invalid key material"),
            JwtError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported algorithm: {alg}")
            }
            JwtError::UnknownKid(kid) => {
                if kid.is_empty() {
                    write!(f, "token has no kid and no legacy verifier is configured")
                } else {
                    write!(f, "unknown kid: {kid}")
                }
            }
            JwtError::AlgorithmMismatch { header, key } => {
                write!(
                    f,
                    "token alg {header} does not match key alg {key} for selected kid"
                )
            }
            JwtError::InvalidKid => write!(
                f,
                "kid must be non-empty, <= {MAX_KID_LENGTH} bytes, and printable ASCII"
            ),
        }
    }
}

impl std::error::Error for JwtError {}

// ── JWT encoding/decoding ───────────────────────────────────────────

/// JOSE header serialised into the first segment of every JWT.
///
/// `kid` is omitted when the signer has no key identifier (HS256 path
/// used by [`JwtAuthority::new`]) so the on-wire format is identical
/// to what older versions of this crate produced.
#[derive(serde::Serialize)]
struct EncodedHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

/// JOSE header as parsed from an incoming token.
#[derive(serde::Deserialize)]
struct DecodedHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    // `typ` is not validated — RFC 7519 allows it to be absent and
    // many issuers omit it.
}

/// Encode claims into a signed JWT string.
fn encode(signing: &SigningKey, claims: &FederationClaims) -> Result<String, JwtError> {
    let header = EncodedHeader {
        alg: signing.algorithm().as_str(),
        typ: "JWT",
        kid: signing.kid(),
    };
    let header_json =
        serde_json::to_string(&header).map_err(|e| JwtError::SerializationError(e.to_string()))?;
    let header_b64 = b64::encode_url_safe(header_json.as_bytes());

    let payload_json =
        serde_json::to_string(claims).map_err(|e| JwtError::SerializationError(e.to_string()))?;
    let payload_b64 = b64::encode_url_safe(payload_json.as_bytes());

    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing.sign(signing_input.as_bytes())?;
    let signature_b64 = b64::encode_url_safe(signature);

    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Decode and verify a JWT token, returning the claims.
///
/// The verifier is selected by the header's `kid` (with fallback to
/// the authority's `legacy_verifier` when `kid` is absent). The
/// header's `alg` must match the verifier's algorithm — this is the
/// defence against the classic "`alg: HS256` + RSA public key as HMAC
/// secret" algorithm-confusion attack.
fn decode(auth: &JwtAuthority, token: &str) -> Result<FederationClaims, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::Malformed);
    }

    let header_bytes = b64::decode_url_safe(parts[0]).map_err(|_| JwtError::Malformed)?;
    let header: DecodedHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::Malformed)?;

    let alg = Algorithm::parse(&header.alg)
        .ok_or_else(|| JwtError::UnsupportedAlgorithm(header.alg.clone()))?;

    let verifier: &VerificationKey = match header.kid.as_deref() {
        Some(kid) => auth
            .verifiers
            .get(kid)
            .ok_or_else(|| JwtError::UnknownKid(kid.to_string()))?,
        None => auth
            .legacy_verifier
            .as_ref()
            .ok_or_else(|| JwtError::UnknownKid(String::new()))?,
    };

    if verifier.algorithm() != alg {
        return Err(JwtError::AlgorithmMismatch {
            header: alg,
            key: verifier.algorithm(),
        });
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let actual_sig = b64::decode_url_safe(parts[2]).map_err(|_| JwtError::Malformed)?;
    verifier.verify(signing_input.as_bytes(), &actual_sig)?;

    let payload_bytes = b64::decode_url_safe(parts[1]).map_err(|_| JwtError::Malformed)?;
    let claims: FederationClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| JwtError::SerializationError(e.to_string()))?;

    Ok(claims)
}

/// Validate a `kid` string. Rejects empty values, anything longer than
/// [`MAX_KID_LENGTH`], and anything that isn't printable ASCII. The
/// latter catches control-character injection that would corrupt the
/// header JSON even through serde escaping (e.g. an attacker trying
/// to smuggle a second JSON field via a quoted string).
fn validate_kid(kid: String) -> Result<String, JwtError> {
    if kid.is_empty() || kid.len() > MAX_KID_LENGTH {
        return Err(JwtError::InvalidKid);
    }
    if !kid.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err(JwtError::InvalidKid);
    }
    Ok(kid)
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

        let token = encode(&auth.signing, &claims).expect("encode");
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

        let token = encode(&auth.signing, &claims).expect("encode");
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

    // ── ES256 / multi-key tests (#760) ──────────────────────────────

    /// Generate a fresh ECDSA P-256 key pair. Returns (pkcs8 DER, SEC1 public key).
    fn es256_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring_sig::EcdsaKeyPair::generate_pkcs8(
            &ring_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("keygen");
        let key_pair = ring_sig::EcdsaKeyPair::from_pkcs8(
            &ring_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .expect("parse pkcs8");
        let public_key = key_pair.public_key().as_ref().to_vec();
        (pkcs8.as_ref().to_vec(), public_key)
    }

    #[test]
    fn es256_issue_and_validate_round_trip() {
        let (pkcs8, _pub) = es256_test_keypair();
        let auth = JwtAuthority::new_es256(pkcs8, "peer-alpha", "rustgate-test").expect("es256");

        assert_eq!(auth.signing_algorithm(), Algorithm::Es256);
        assert_eq!(auth.signing_kid(), Some("peer-alpha"));

        let token = auth
            .issue("peer-alpha", vec!["Alpha".into()])
            .expect("issue");
        let claims = auth.validate(&token).expect("validate");
        assert_eq!(claims.sub, "peer-alpha");
        assert_eq!(claims.groups, vec!["Alpha"]);
    }

    #[test]
    fn es256_cross_authority_validate_via_registered_verifier() {
        // Authority A issues with a private key it holds.
        let (pkcs8_a, pub_a) = es256_test_keypair();
        let authority_a =
            JwtAuthority::new_es256(pkcs8_a, "peer-a", "rustgate-test").expect("es256 a");

        // Authority B holds a DIFFERENT signing key but carries A's
        // public key as a verifier. This is the whole asymmetric-crypto
        // rationale from #760: B never sees A's signing key yet can
        // still verify tokens A issued.
        let (pkcs8_b, _pub_b) = es256_test_keypair();
        let authority_b = JwtAuthority::new_es256(pkcs8_b, "peer-b", "rustgate-test")
            .expect("es256 b")
            .with_es256_verifier("peer-a", pub_a)
            .expect("register a's public key");

        let token = authority_a.issue("peer-a", vec![]).expect("issue");
        let claims = authority_b.validate(&token).expect("validate");
        assert_eq!(claims.sub, "peer-a");
    }

    #[test]
    fn es256_emits_alg_and_kid_in_header() {
        let (pkcs8, _) = es256_test_keypair();
        let auth = JwtAuthority::new_es256(pkcs8, "peer-kid-xyz", "rustgate-test").expect("es256");
        let token = auth.issue("peer-kid-xyz", vec![]).expect("issue");

        let header_b64 = token.split('.').next().expect("has header");
        let header_bytes = b64::decode_url_safe(header_b64).expect("decode header");
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("json");
        assert_eq!(header.get("alg").and_then(|v| v.as_str()), Some("ES256"));
        assert_eq!(
            header.get("kid").and_then(|v| v.as_str()),
            Some("peer-kid-xyz")
        );
        assert_eq!(header.get("typ").and_then(|v| v.as_str()), Some("JWT"));
    }

    #[test]
    fn hs256_authority_omits_kid_from_header_for_backward_compat() {
        // Regression: HS256 authority built via `new()` must continue to
        // emit the legacy `{"alg":"HS256","typ":"JWT"}` header shape
        // with no `kid` field, so tokens verify against older peers.
        let auth = make_authority();
        let token = auth.issue("peer-1", vec![]).expect("issue");
        let header_b64 = token.split('.').next().expect("has header");
        let header_bytes = b64::decode_url_safe(header_b64).expect("decode header");
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("json");
        assert_eq!(header.get("alg").and_then(|v| v.as_str()), Some("HS256"));
        assert!(
            header.get("kid").is_none(),
            "legacy HS256 header must omit kid"
        );
    }

    #[test]
    fn es256_unknown_kid_rejected() {
        let (pkcs8_a, _) = es256_test_keypair();
        let authority_a =
            JwtAuthority::new_es256(pkcs8_a, "peer-a", "rustgate-test").expect("es256 a");

        // Authority B has no record of peer-a's public key.
        let (pkcs8_b, _) = es256_test_keypair();
        let authority_b =
            JwtAuthority::new_es256(pkcs8_b, "peer-b", "rustgate-test").expect("es256 b");

        let token = authority_a.issue("peer-a", vec![]).expect("issue");
        let err = authority_b
            .validate(&token)
            .expect_err("should reject unknown kid");
        assert!(matches!(err, JwtError::UnknownKid(ref k) if k == "peer-a"));
    }

    #[test]
    fn es256_authority_rejects_token_without_kid() {
        // An ES256 authority has `legacy_verifier: None`, so a token
        // whose header has no `kid` cannot fall back — it's rejected.
        let (pkcs8, _) = es256_test_keypair();
        let auth = JwtAuthority::new_es256(pkcs8, "peer-a", "rustgate-test").expect("es256");

        // Craft a no-kid token by signing with a separate HS256 authority.
        let hs_auth = make_authority();
        let token = hs_auth.issue("peer-1", vec![]).expect("issue hs");

        let err = auth.validate(&token).expect_err("must reject");
        assert!(matches!(err, JwtError::UnknownKid(ref k) if k.is_empty()));
    }

    #[test]
    fn algorithm_mismatch_header_vs_key_rejected() {
        // Security defence: an attacker crafts a token header claiming
        // `alg: HS256` but presents a `kid` that points to an ES256
        // verifier. A naive implementation might treat the ES256 public
        // key bytes as an HS256 secret — classic alg-confusion. We
        // reject with AlgorithmMismatch before any signature check.

        let (pkcs8, pub_a) = es256_test_keypair();
        let _authority_a =
            JwtAuthority::new_es256(pkcs8, "peer-a", "rustgate-test").expect("es256 a");

        let hs_secret = b"test-secret-key-for-jwt-testing!!".to_vec();
        let authority_b = JwtAuthority::new(hs_secret.clone(), "rustgate-test")
            .expect("hs256")
            .with_es256_verifier("peer-a", pub_a)
            .expect("register es256 verifier");

        // Build a token signed with HS256 under authority_b's key, but
        // stamp peer-a's kid into the header so the verifier selects the
        // ES256 entry. This simulates an attacker's crafted token.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let claims = FederationClaims {
            sub: "peer-a".to_string(),
            iss: "rustgate-test".to_string(),
            exp: now + 3600,
            iat: now,
            jti: "attack".to_string(),
            groups: vec![],
        };
        // Uses HS256 with a kid so the verifier routes to the ES256 entry.
        let forged_signing = SigningKey::Hs256 {
            secret: Zeroizing::new(hs_secret),
            kid: Some("peer-a".to_string()),
        };
        let forged_token = encode(&forged_signing, &claims).expect("encode");

        let err = authority_b
            .validate(&forged_token)
            .expect_err("must reject");
        assert!(
            matches!(
                err,
                JwtError::AlgorithmMismatch {
                    header: Algorithm::Hs256,
                    key: Algorithm::Es256,
                }
            ),
            "expected AlgorithmMismatch, got {err:?}"
        );
    }

    #[test]
    fn es256_tampered_signature_rejected() {
        let (pkcs8, _) = es256_test_keypair();
        let auth = JwtAuthority::new_es256(pkcs8, "peer-a", "rustgate-test").expect("es256");
        let token = auth.issue("peer-a", vec![]).expect("issue");

        let parts: Vec<&str> = token.split('.').collect();
        // Corrupt the signature by swapping in 64 zero bytes (valid length
        // for ES256 fixed format, but won't satisfy verification).
        let bad_sig = b64::encode_url_safe([0u8; 64]);
        let tampered = format!("{}.{}.{}", parts[0], parts[1], bad_sig);
        assert_eq!(auth.validate(&tampered), Err(JwtError::InvalidSignature));
    }

    #[test]
    fn new_es256_rejects_malformed_pkcs8() {
        // 64 bytes of 0xFF is not a valid PKCS#8 DER blob.
        let garbage = vec![0xFFu8; 64];
        let err =
            JwtAuthority::new_es256(garbage, "peer-a", "rustgate-test").expect_err("must reject");
        assert_eq!(err, JwtError::InvalidKey);
    }

    #[test]
    fn with_es256_verifier_rejects_malformed_public_key() {
        let (pkcs8, _) = es256_test_keypair();
        let auth = JwtAuthority::new_es256(pkcs8, "peer-a", "rustgate-test").expect("es256");

        // Too short (SEC1 uncompressed P-256 requires exactly 65 bytes).
        let short = vec![0x04u8; 32];
        let err = auth
            .with_es256_verifier("peer-b", short)
            .expect_err("must reject");
        assert_eq!(err, JwtError::InvalidKey);
    }

    #[test]
    fn with_es256_verifier_rejects_wrong_sec1_tag() {
        let (pkcs8, _) = es256_test_keypair();
        let auth = JwtAuthority::new_es256(pkcs8, "peer-a", "rustgate-test").expect("es256");

        // 65 bytes but leading byte is 0x05 instead of 0x04 (uncompressed).
        let wrong_tag: Vec<u8> = std::iter::once(0x05u8)
            .chain(std::iter::repeat_n(0, 64))
            .collect();
        let err = auth
            .with_es256_verifier("peer-b", wrong_tag)
            .expect_err("must reject");
        assert_eq!(err, JwtError::InvalidKey);
    }

    #[test]
    fn invalid_kid_rejected_on_builders() {
        let (pkcs8, _) = es256_test_keypair();
        // Empty kid.
        let err = JwtAuthority::new_es256(&pkcs8[..], "", "rustgate-test").expect_err("empty kid");
        assert_eq!(err, JwtError::InvalidKid);

        // Oversized kid.
        let long_kid = "a".repeat(MAX_KID_LENGTH + 1);
        let err = JwtAuthority::new_es256(&pkcs8[..], long_kid, "rustgate-test")
            .expect_err("oversized kid");
        assert_eq!(err, JwtError::InvalidKid);

        // Control character.
        let err = JwtAuthority::new_es256(&pkcs8[..], "peer\x07a", "rustgate-test")
            .expect_err("control char kid");
        assert_eq!(err, JwtError::InvalidKid);

        // Non-ASCII.
        let err = JwtAuthority::new_es256(&pkcs8[..], "peer-α", "rustgate-test")
            .expect_err("non-ascii kid");
        assert_eq!(err, JwtError::InvalidKid);
    }

    #[test]
    fn with_hs256_verifier_validates_remote_peer_token() {
        // Two HS256 authorities with different secrets. A registers B's
        // secret under B's kid and can validate tokens B issues when
        // those tokens carry B's kid in the header.
        let secret_a = b"test-secret-key-for-jwt-peer-a!!".to_vec();
        let secret_b = b"test-secret-key-for-jwt-peer-b!!".to_vec();

        // Peer B signs tokens with a kid (built manually since `new` doesn't set one).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let claims = FederationClaims {
            sub: "peer-b".to_string(),
            iss: "rustgate-test".to_string(),
            exp: now + 3600,
            iat: now,
            jti: "b-jti".to_string(),
            groups: vec![],
        };
        let signing_b = SigningKey::Hs256 {
            secret: Zeroizing::new(secret_b.clone()),
            kid: Some("peer-b".to_string()),
        };
        let token = encode(&signing_b, &claims).expect("encode");

        let authority_a = JwtAuthority::new(secret_a, "rustgate-test")
            .expect("hs256 a")
            .with_hs256_verifier("peer-b", secret_b)
            .expect("register peer-b verifier");

        let claims = authority_a.validate(&token).expect("validate");
        assert_eq!(claims.sub, "peer-b");
    }

    #[test]
    fn with_hs256_verifier_rejects_short_secret() {
        let auth = make_authority();
        let err = auth
            .with_hs256_verifier("peer-b", b"too-short".to_vec())
            .expect_err("must reject short");
        assert!(matches!(err, JwtError::SecretTooShort { .. }));
    }
}
