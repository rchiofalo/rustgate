// Copyright © 2026 Roberto Chiofalo.

//! JWT token authentication for federation connections.
//!
//! Supports HMAC-SHA256 (HS256), ECDSA P-256 SHA-256 (ES256, RFC 7518),
//! and Ed25519 (EdDSA, RFC 8037) signed tokens. Tokens carry peer
//! identity, group claims, and expiration.
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
//! - [`JwtAuthority::new_ed25519`] creates an EdDSA (Ed25519) authority.
//!   Same asymmetric security model as ES256 — private signing key,
//!   per-peer public verifier keys registered via
//!   [`JwtAuthority::with_ed25519_verifier`] — but with smaller on-wire
//!   keys (32-byte raw public keys vs 65-byte SEC1), constant-time
//!   arithmetic by construction, and no signature malleability. Prefer
//!   this over ES256 for new deployments.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use lru::LruCache;
use ring::signature::{self as ring_sig, KeyPair};
use rustgate_core::b64;
use rustgate_core::crypto::{HmacError, hmac_sha256_tag, hmac_sha256_verify};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Map an [`HmacError`] from the shared crypto helper into the
/// federation crate's [`JwtError`]. HS256 sign/verify failures are
/// uniformly reported as [`JwtError::InvalidSignature`] — the helper's
/// fail-closed empty-key path collapses into the same caller-visible
/// outcome as a true tag mismatch (the JWT layer never legitimately
/// passes an empty secret because `JwtAuthority::new` enforces a
/// 32-byte minimum).
fn map_hmac_error(_err: HmacError) -> JwtError {
    JwtError::InvalidSignature
}

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
///
/// Sized to exceed [`rustgate_core::constants::FEDERATION_HEARTBEAT_TIMEOUT`]
/// (90 s) so NTP drift that still keeps heartbeats flowing cannot
/// simultaneously reject freshly-issued JWTs. Prior to #764 this was 60 s
/// which produced a flapping regime under 60–90 s clock drift: heartbeats
/// declared the peer alive, but every token refresh failed with
/// [`JwtError::IssuedInFuture`] and triggered a
/// `peer_connected` → `token_rejected` loop.
///
/// The compile-time assertion below pins the invariant so a future tweak
/// to either constant cannot silently reintroduce the flap. 120 s gives
/// a 30 s safety margin over the heartbeat timeout — enough to absorb
/// typical stateless jitter without noticeably widening the replay
/// surface. Operators who need to tolerate larger drift should also bump
/// heartbeat timeouts, not just this value.
const MAX_CLOCK_SKEW_SECS: u64 = 120;

// Guard the heartbeat vs clock-skew invariant at compile time. If someone
// lowers `MAX_CLOCK_SKEW_SECS` below `FEDERATION_HEARTBEAT_TIMEOUT` or
// raises the heartbeat timeout past the clock skew, the build breaks
// here instead of reintroducing the #764 flapping regime in production.
const _: () = assert!(
    MAX_CLOCK_SKEW_SECS >= rustgate_core::constants::FEDERATION_HEARTBEAT_TIMEOUT.as_secs(),
    "MAX_CLOCK_SKEW_SECS must be >= FEDERATION_HEARTBEAT_TIMEOUT to avoid \
     JWT iat flapping under NTP drift — see issue #764",
);

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

/// JWT signing/verification algorithm per RFC 7518 / RFC 8037.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC-SHA256 — symmetric, a single secret signs and verifies.
    Hs256,
    /// ECDSA P-256 with SHA-256 — asymmetric, fixed 64-byte signature
    /// `(r || s)` per RFC 7518 §3.4.
    Es256,
    /// Ed25519 (EdDSA) — asymmetric, fixed 64-byte signature per
    /// RFC 8037 §3.1. Serialised in the JWT header as `"EdDSA"` (not
    /// `"Ed25519"`), matching RFC 8037's `"alg"` value table.
    EdDsa,
}

impl Algorithm {
    fn as_str(self) -> &'static str {
        match self {
            Algorithm::Hs256 => "HS256",
            Algorithm::Es256 => "ES256",
            Algorithm::EdDsa => "EdDSA",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "HS256" => Some(Algorithm::Hs256),
            "ES256" => Some(Algorithm::Es256),
            "EdDSA" => Some(Algorithm::EdDsa),
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
/// The `Es256` and `EdDsa` variants box their ring key pairs because
/// they're larger than the HS256 variant (~264 B for `EcdsaKeyPair`,
/// ~128 B for `Ed25519KeyPair` vs ~48 B for HS256), and we don't want
/// every `SigningKey` value to pay that cost when the authority is
/// HS256. The clippy `large_enum_variant` lint flags the disparity.
enum SigningKey {
    Hs256 {
        secret: Zeroizing<Vec<u8>>,
        kid: Option<String>,
    },
    Es256 {
        key_pair: Box<ring_sig::EcdsaKeyPair>,
        kid: String,
    },
    EdDsa {
        key_pair: Box<ring_sig::Ed25519KeyPair>,
        kid: String,
    },
}

impl SigningKey {
    fn algorithm(&self) -> Algorithm {
        match self {
            SigningKey::Hs256 { .. } => Algorithm::Hs256,
            SigningKey::Es256 { .. } => Algorithm::Es256,
            SigningKey::EdDsa { .. } => Algorithm::EdDsa,
        }
    }

    fn kid(&self) -> Option<&str> {
        match self {
            SigningKey::Hs256 { kid, .. } => kid.as_deref(),
            SigningKey::Es256 { kid, .. } => Some(kid.as_str()),
            SigningKey::EdDsa { kid, .. } => Some(kid.as_str()),
        }
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, JwtError> {
        match self {
            SigningKey::Hs256 { secret, .. } => {
                hmac_sha256_tag(secret, signing_input).map_err(map_hmac_error)
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
            SigningKey::EdDsa { key_pair, .. } => {
                // Ed25519 is deterministic (RFC 8032 §5.1.6) so no RNG
                // is required; ring's `sign` never fails for this algo
                // because the key material was validated at construction.
                let sig = key_pair.sign(signing_input);
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
    /// Ed25519 public key in raw form per RFC 8032 §5.1.5 — exactly
    /// 32 bytes, no framing, no SPKI wrapping. Callers that have an
    /// SPKI-wrapped key must strip the wrapper before registering.
    EdDsa(Vec<u8>),
}

/// Read-only view of a verifier key, exposed for JWKS serialization.
///
/// The HS256 variant carries no payload — the symmetric secret never
/// leaves [`JwtAuthority`] for any purpose, including JWKS publication.
/// Callers that walk the verifier registry through [`JwtAuthority::verifier_views`]
/// can still see that an HS256 entry exists (so they may surface a
/// configuration warning) but they cannot read the secret bytes.
#[derive(Debug)]
pub enum VerificationKeyView<'a> {
    /// Symmetric HS256 verifier — secret intentionally hidden.
    Hs256,
    /// ECDSA P-256 SEC1 uncompressed point (65 bytes).
    Es256(&'a [u8]),
    /// Raw Ed25519 public key (32 bytes).
    EdDsa(&'a [u8]),
}

impl<'a> VerificationKeyView<'a> {
    /// Re-borrow this view at its original lifetime — useful when an
    /// `Iterator::map` collects views into a `Vec` and then needs to
    /// hand them out to `build_jwk_set` without consuming the vector.
    pub fn borrow(&self) -> VerificationKeyView<'a> {
        match self {
            VerificationKeyView::Hs256 => VerificationKeyView::Hs256,
            VerificationKeyView::Es256(b) => VerificationKeyView::Es256(b),
            VerificationKeyView::EdDsa(b) => VerificationKeyView::EdDsa(b),
        }
    }
}

impl VerificationKey {
    fn algorithm(&self) -> Algorithm {
        match self {
            VerificationKey::Hs256(_) => Algorithm::Hs256,
            VerificationKey::Es256(_) => Algorithm::Es256,
            VerificationKey::EdDsa(_) => Algorithm::EdDsa,
        }
    }

    fn verify(&self, signing_input: &[u8], sig: &[u8]) -> Result<(), JwtError> {
        match self {
            VerificationKey::Hs256(secret) => {
                // Constant-time verification (`subtle::ConstantTimeEq::ct_eq`)
                // is enforced inside the shared
                // `rustgate_core::crypto::hmac_sha256_verify` helper.
                hmac_sha256_verify(secret, signing_input, sig).map_err(map_hmac_error)
            }
            VerificationKey::Es256(pub_key) => {
                ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P256_SHA256_FIXED, pub_key)
                    .verify(signing_input, sig)
                    .map_err(|_| JwtError::InvalidSignature)
            }
            VerificationKey::EdDsa(pub_key) => {
                ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, pub_key)
                    .verify(signing_input, sig)
                    .map_err(|_| JwtError::InvalidSignature)
            }
        }
    }
}

/// Externally-sourced verifier key, materialised from a JWKS document.
///
/// This is the public mirror of the crate-private `VerificationKey`:
/// the JWKS client constructs values of this type from each
/// `kty`/`alg`-validated JWK entry and hands them to
/// [`JwtAuthority::install_external_verifiers`] in a `HashMap` keyed by
/// `kid`. The receiver translates these into the internal
/// representation atomically.
///
/// `ExternalVerifier::Hs256` is intentionally available so operators
/// who explicitly opt in (`allow_hs256: true`) can ship symmetric
/// secrets through JWKS — but it is fail-closed by default at the
/// JWKS-client layer.
#[derive(Debug, Clone)]
pub enum ExternalVerifier {
    /// Symmetric HMAC-SHA256 secret. Wrapped in
    /// [`Zeroizing`] so the bytes are wiped on drop. Length must be
    /// at least `MIN_SECRET_LENGTH` — checked at install time.
    Hs256(Zeroizing<Vec<u8>>),
    /// ECDSA P-256 public key in SEC1 uncompressed form
    /// (`0x04 || x(32) || y(32)` = 65 bytes).
    Es256(Vec<u8>),
    /// Raw Ed25519 public key (32 bytes per RFC 8032 §5.1.5).
    EdDsa(Vec<u8>),
}

impl ExternalVerifier {
    /// Materialise the public-facing variant into the crate-private
    /// `VerificationKey`. The shape is one-to-one but each branch
    /// either takes ownership (Hs256) or copies a small Vec (Es256,
    /// EdDsa) so the resulting registry can live behind an `ArcSwap`
    /// without a lifetime hanging off the caller's input map.
    fn into_verification_key(self) -> VerificationKey {
        match self {
            ExternalVerifier::Hs256(secret) => VerificationKey::Hs256(secret),
            ExternalVerifier::Es256(b) => VerificationKey::Es256(b),
            ExternalVerifier::EdDsa(b) => VerificationKey::EdDsa(b),
        }
    }

    /// Algorithm advertised by this verifier — used by the JWKS client
    /// for diff logging without breaking the encapsulation of the
    /// crate-private `VerificationKey`.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            ExternalVerifier::Hs256(_) => Algorithm::Hs256,
            ExternalVerifier::Es256(_) => Algorithm::Es256,
            ExternalVerifier::EdDsa(_) => Algorithm::EdDsa,
        }
    }
}

/// Initial value for the [`JwtAuthority::external_verifiers`] field.
/// An empty `HashMap` behind an `ArcSwap` so the validation hot path
/// always sees a non-`None` snapshot — no `Option` unwrap on each
/// token validation.
fn empty_external_verifiers() -> ArcSwap<HashMap<String, VerificationKey>> {
    ArcSwap::from_pointee(HashMap::new())
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
    /// Hot-reloadable verifier registry sourced from a remote JWKS
    /// endpoint (refs #952). Populated and atomically swapped by
    /// `JwksClient`; consulted by [`decode`]
    /// after the static `verifiers` map has been searched. The
    /// `ArcSwap<Arc<HashMap<...>>>` shape mirrors the ACL/authz
    /// hot-reload pattern in `transport::router` — readers get a
    /// lock-free snapshot via [`ArcSwap::load`] and the JWKS refresh
    /// task swaps a fresh map in via [`ArcSwap::store`] without
    /// blocking validation.
    external_verifiers: ArcSwap<HashMap<String, VerificationKey>>,
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
            external_verifiers: empty_external_verifiers(),
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
            external_verifiers: empty_external_verifiers(),
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

    /// Create a new EdDSA (Ed25519) JWT authority.
    ///
    /// `pkcs8_der` must be a PKCS#8 v2 DER-encoded Ed25519 private key
    /// (RFC 5958 / RFC 8410). `kid` uniquely identifies this signing
    /// key; every issued token carries it in the header so remote
    /// verifiers can route to the correct public key.
    ///
    /// The local public key is registered as a verifier under the same
    /// `kid`, so this authority can validate tokens it issued itself.
    ///
    /// Compared to [`Self::new_es256`], Ed25519 offers smaller public
    /// keys (32 bytes raw vs 65 bytes SEC1), constant-time arithmetic
    /// by construction, and no signature malleability — prefer it for
    /// new federation deployments.
    pub fn new_ed25519(
        pkcs8_der: impl AsRef<[u8]>,
        kid: impl Into<String>,
        issuer: impl Into<String>,
    ) -> Result<Self, JwtError> {
        let kid = validate_kid(kid.into())?;
        let key_pair = ring_sig::Ed25519KeyPair::from_pkcs8(pkcs8_der.as_ref())
            .map_err(|_| JwtError::InvalidKey)?;
        let local_public_key = key_pair.public_key().as_ref().to_vec();

        let mut verifiers = HashMap::new();
        let _ = verifiers.insert(kid.clone(), VerificationKey::EdDsa(local_public_key));

        let capacity = NonZeroUsize::new(DEFAULT_REVOCATION_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        Ok(Self {
            signing: SigningKey::EdDsa {
                key_pair: Box::new(key_pair),
                kid,
            },
            verifiers,
            external_verifiers: empty_external_verifiers(),
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

    /// Register an EdDSA (Ed25519) verifier key for a peer identified
    /// by `kid`.
    ///
    /// `public_key_raw` must be exactly 32 bytes — the raw Ed25519
    /// public key encoding per RFC 8032 §5.1.5. No PEM, no SPKI, no
    /// JWK — unwrap at the call site. Extract directly from a
    /// [`ring::signature::Ed25519KeyPair::public_key`] or from the
    /// base64url `x` field of a `kty=OKP, crv=Ed25519` JWK.
    pub fn with_ed25519_verifier(
        mut self,
        kid: impl Into<String>,
        public_key_raw: impl Into<Vec<u8>>,
    ) -> Result<Self, JwtError> {
        let kid = validate_kid(kid.into())?;
        let public_key = public_key_raw.into();
        // Raw Ed25519 public keys are exactly 32 bytes per RFC 8032 §5.1.5.
        if public_key.len() != 32 {
            return Err(JwtError::InvalidKey);
        }
        let _ = self
            .verifiers
            .insert(kid, VerificationKey::EdDsa(public_key));
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
    ///
    /// Accepts any string-like reference (e.g. `&str`, `&PeerId`) so
    /// callers holding a typed [`rustgate_core::PeerId`] do not have to
    /// reach for `.as_str()`. The wire-format `sub` claim still stores
    /// the bare string exactly as provided.
    pub fn issue(&self, peer_id: impl AsRef<str>, groups: Vec<String>) -> Result<String, JwtError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtError::ClockError)?;

        let peer_id = peer_id.as_ref();
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
    ///
    /// See [`issue`](Self::issue) for the typed-`peer_id` contract.
    pub fn issue_with_expiry(
        &self,
        peer_id: impl AsRef<str>,
        groups: Vec<String>,
        expiry: Duration,
    ) -> Result<String, JwtError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtError::ClockError)?;

        let peer_id = peer_id.as_ref();
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

    /// Walk the per-`kid` verifier registry as read-only views suitable
    /// for JWKS serialization. The HS256 secret bytes are deliberately
    /// hidden in [`VerificationKeyView::Hs256`] — symmetric secrets are
    /// never exposed outside the authority.
    ///
    /// The returned vector owns the kid `String` keys; the views borrow
    /// from `self` and remain valid as long as the authority does. The
    /// `legacy_verifier` (if present) is omitted because it has no
    /// `kid` to publish in JWKS, and HS256 secrets are filtered at the
    /// JWKS-build step regardless.
    pub fn verifier_views(&self) -> Vec<(String, VerificationKeyView<'_>)> {
        self.verifiers
            .iter()
            .map(|(kid, key)| {
                let view = match key {
                    VerificationKey::Hs256(_) => VerificationKeyView::Hs256,
                    VerificationKey::Es256(b) => VerificationKeyView::Es256(b),
                    VerificationKey::EdDsa(b) => VerificationKeyView::EdDsa(b),
                };
                (kid.clone(), view)
            })
            .collect()
    }

    /// Look up the verifier-side algorithm for a given `kid`. Returns
    /// `None` when the kid is not registered. Used by the JWKS module's
    /// state-machine integration tests to assert that a kid maps to the
    /// expected algorithm before any signature work.
    pub fn verifier_algorithm(&self, kid: &str) -> Option<Algorithm> {
        self.verifiers.get(kid).map(|k| k.algorithm()).or_else(|| {
            let guard = self.external_verifiers.load();
            guard.get(kid).map(|k| k.algorithm())
        })
    }

    /// Atomically replace the external verifier registry with a fresh
    /// snapshot. Used by `JwksClient` (refs #952)
    /// after a successful JWKS refresh — readers see the new map on
    /// their next call to [`Self::validate`] without any locking on the
    /// hot path.
    ///
    /// External verifiers are consulted only after the static
    /// `verifiers` map (the one populated by `with_*_verifier` builders
    /// and the local self-verifier) has been searched, so an operator
    /// can override a JWKS-supplied entry by registering the same kid
    /// inline at startup.
    pub fn install_external_verifiers(&self, verifiers: HashMap<String, ExternalVerifier>) {
        let materialised: HashMap<String, VerificationKey> = verifiers
            .into_iter()
            .map(|(kid, v)| (kid, v.into_verification_key()))
            .collect();
        self.external_verifiers.store(Arc::new(materialised));
    }

    /// Return the set of `kid`s currently published by the external
    /// (JWKS-sourced) verifier registry. Stable ordering is not
    /// guaranteed — callers that need a deterministic ordering must
    /// sort.
    pub fn external_verifier_kids(&self) -> Vec<String> {
        self.external_verifiers.load().keys().cloned().collect()
    }

    /// Test-only helper: forge an HS256-signed token with a custom
    /// `kid` header, used by the algorithm-confusion attack pin in
    /// `crate::jwks::tests`.
    ///
    /// Production code does not need this — `issue()` always derives
    /// the kid from the authority's signing key. The helper exists so
    /// the JWKS test module can construct an attacker-shaped token
    /// without re-importing the crate-private `SigningKey` enum.
    #[cfg(test)]
    pub(crate) fn test_only_forge_hs256_with_kid(
        secret: &[u8],
        kid: &str,
        claims: &FederationClaims,
    ) -> String {
        let signing = SigningKey::Hs256 {
            secret: Zeroizing::new(secret.to_vec()),
            kid: Some(kid.to_string()),
        };
        encode(&signing, claims).expect("test-only forging path")
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

// Why this `Display` is not migrated to `#[derive(thiserror::Error)]`:
//
// The `UnknownKid(String)` variant renders two distinct messages
// depending on whether the kid is empty (the "no kid header at all"
// path constructs `UnknownKid(String::new())` from `decode()`) or
// non-empty (a real kid that did not resolve in the verifier
// registry). thiserror's `#[error("...")]` attribute is a single
// format string per variant — there is no template form that can
// branch on field content, and operator log-correlation tooling
// already greps for both literal strings, so byte-stable output
// rules out a single "unknown kid: {kid}" template (it would render
// "unknown kid: " with a trailing space for the empty case).
//
// Splitting into `MissingKid` + `UnknownKid(String)` would let
// thiserror handle this cleanly, but that is a breaking change to
// this crate's public error variants and is intentionally out of
// scope for the Display-impl migration. The manual `Display` and
// `Error` impls below are documented and pinned by `Display` tests
// in the in-file test module.
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

    // Hold the external-verifier guard for the lifetime of this call.
    // `ArcSwap::load` is `Guard<Arc<HashMap<...>>>` — dropping it
    // releases the read snapshot, so we must keep it on the stack for
    // as long as `verifier` borrows out of it.
    let external_guard = auth.external_verifiers.load();

    // Verifier resolution order (kid present):
    //   1. Static `verifiers` map (with_*_verifier + self-verifier)
    //   2. External JWKS-sourced map (refs #952)
    // An operator-provided static entry therefore overrides a JWKS
    // entry under the same kid, which is the conservative posture for
    // a misconfigured remote.
    let verifier: &VerificationKey = match header.kid.as_deref() {
        Some(kid) => match auth.verifiers.get(kid) {
            Some(v) => v,
            None => external_guard
                .get(kid)
                .ok_or_else(|| JwtError::UnknownKid(kid.to_string()))?,
        },
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

    drop(external_guard);
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
    #![allow(clippy::panic, clippy::unwrap_used)]

    use hmac::{Hmac, Mac};

    use super::*;

    /// Test-local alias used by the byte-for-byte regression tests
    /// that pin the helper output against the previous inlined
    /// `Hmac::<Sha256>::new_from_slice(...).update(...).finalize()`
    /// pipeline.
    type HmacSha256 = Hmac<Sha256>;

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

    /// Regression test for issue #764. A federated peer whose clock is
    /// `FEDERATION_HEARTBEAT_TIMEOUT` seconds ahead of the verifier must
    /// still be able to present a freshly-issued token. Prior to the
    /// fix, `MAX_CLOCK_SKEW_SECS = 60` would reject tokens from any
    /// peer drifting past 60 s even though heartbeats were still
    /// flowing — producing a `peer_connected` / `token_rejected` flap.
    #[test]
    fn iat_at_heartbeat_timeout_drift_accepted() {
        use rustgate_core::constants::FEDERATION_HEARTBEAT_TIMEOUT;

        let auth = make_authority();

        // Peer's clock is ahead by the full heartbeat timeout — the
        // worst case where heartbeats still keep the link declared
        // alive. Clock skew tolerance must cover this (plus a small
        // safety margin).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time");
        let drift = FEDERATION_HEARTBEAT_TIMEOUT.as_secs();
        let future_iat = now.as_secs() + drift;

        let claims = FederationClaims {
            sub: "peer-1".to_string(),
            iss: "rustgate-test".to_string(),
            exp: future_iat + 3600,
            iat: future_iat,
            jti: "test-jti-764".to_string(),
            groups: vec![],
        };

        let token = encode(&auth.signing, &claims).expect("encode");
        let result = auth.validate(&token);
        assert!(
            result.is_ok(),
            "token issued from peer drifting at heartbeat-timeout bound \
             must be accepted — otherwise liveness and auth disagree \
             (issue #764): got {result:?}"
        );
    }

    /// Runtime check mirroring the compile-time assertion on
    /// `MAX_CLOCK_SKEW_SECS >= FEDERATION_HEARTBEAT_TIMEOUT`. The
    /// `const _: () = assert!(…)` in the module header is the primary
    /// guard; this test documents the invariant in the failing-test
    /// output if somebody disables the compile-time assertion.
    #[test]
    fn clock_skew_exceeds_heartbeat_timeout() {
        use rustgate_core::constants::FEDERATION_HEARTBEAT_TIMEOUT;

        assert!(
            MAX_CLOCK_SKEW_SECS >= FEDERATION_HEARTBEAT_TIMEOUT.as_secs(),
            "MAX_CLOCK_SKEW_SECS ({}) must be >= FEDERATION_HEARTBEAT_TIMEOUT ({:?}) \
             to avoid JWT iat flapping under NTP drift (issue #764)",
            MAX_CLOCK_SKEW_SECS,
            FEDERATION_HEARTBEAT_TIMEOUT
        );
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

    /// Migration regression guard: closes #799. The HS256 sign/verify
    /// pipeline now goes through `rustgate_core::crypto::hmac_sha256_*`.
    /// Pin byte-for-byte equivalence to the previous inlined pipeline
    /// so any future tweak to `SigningKey::sign` / `VerificationKey::verify`
    /// cannot silently invalidate previously-issued JWT tokens
    /// (which would manifest as a federation peer outage on rollout).
    #[test]
    fn hs256_sign_matches_inlined_construction() {
        let secret = b"a-shared-secret-of-thirty-two-bytes!!".to_vec();
        let signing_input = b"jwt.header.payload";
        let signing_key = SigningKey::Hs256 {
            secret: Zeroizing::new(secret.clone()),
            kid: None,
        };
        let helper_sig = signing_key.sign(signing_input).unwrap();

        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(signing_input);
        let inlined: Vec<u8> = mac.finalize().into_bytes().to_vec();

        assert_eq!(helper_sig, inlined);
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

    // ── EdDSA (Ed25519) tests (#952 part 1) ─────────────────────────

    /// Generate a fresh Ed25519 key pair. Returns (pkcs8 DER, raw 32-byte public key).
    fn ed25519_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring_sig::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        let key_pair = ring_sig::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse pkcs8");
        let public_key = key_pair.public_key().as_ref().to_vec();
        (pkcs8.as_ref().to_vec(), public_key)
    }

    #[test]
    fn ed25519_issue_and_validate_round_trip() {
        let (pkcs8, _pub) = ed25519_test_keypair();
        let auth =
            JwtAuthority::new_ed25519(pkcs8, "peer-alpha", "rustgate-test").expect("ed25519");

        assert_eq!(auth.signing_algorithm(), Algorithm::EdDsa);
        assert_eq!(auth.signing_kid(), Some("peer-alpha"));

        let token = auth
            .issue("peer-alpha", vec!["Alpha".into()])
            .expect("issue");
        let claims = auth.validate(&token).expect("validate");
        assert_eq!(claims.sub, "peer-alpha");
        assert_eq!(claims.groups, vec!["Alpha"]);
    }

    #[test]
    fn ed25519_cross_authority_validate_via_registered_verifier() {
        // Authority A issues with a private key it holds.
        let (pkcs8_a, pub_a) = ed25519_test_keypair();
        let authority_a =
            JwtAuthority::new_ed25519(pkcs8_a, "peer-a", "rustgate-test").expect("ed25519 a");

        // Authority B holds a DIFFERENT signing key but carries A's
        // public key as a verifier — same asymmetric rationale as the
        // ES256 path. B never sees A's signing key yet can still
        // verify tokens A issued.
        let (pkcs8_b, _pub_b) = ed25519_test_keypair();
        let authority_b = JwtAuthority::new_ed25519(pkcs8_b, "peer-b", "rustgate-test")
            .expect("ed25519 b")
            .with_ed25519_verifier("peer-a", pub_a)
            .expect("register a's public key");

        let token = authority_a.issue("peer-a", vec![]).expect("issue");
        let claims = authority_b.validate(&token).expect("validate");
        assert_eq!(claims.sub, "peer-a");
    }

    #[test]
    fn ed25519_emits_alg_and_kid_in_header() {
        let (pkcs8, _) = ed25519_test_keypair();
        let auth =
            JwtAuthority::new_ed25519(pkcs8, "peer-kid-ed25519", "rustgate-test").expect("ed25519");
        let token = auth.issue("peer-kid-ed25519", vec![]).expect("issue");

        let header_b64 = token.split('.').next().expect("has header");
        let header_bytes = b64::decode_url_safe(header_b64).expect("decode header");
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("json");
        // Per RFC 8037 the alg value is exactly "EdDSA" (not "Ed25519").
        assert_eq!(header.get("alg").and_then(|v| v.as_str()), Some("EdDSA"));
        assert_eq!(
            header.get("kid").and_then(|v| v.as_str()),
            Some("peer-kid-ed25519")
        );
        assert_eq!(header.get("typ").and_then(|v| v.as_str()), Some("JWT"));
    }

    #[test]
    fn ed25519_unknown_kid_rejected() {
        let (pkcs8_a, _) = ed25519_test_keypair();
        let authority_a =
            JwtAuthority::new_ed25519(pkcs8_a, "peer-a", "rustgate-test").expect("ed25519 a");

        // Authority B has no record of peer-a's public key.
        let (pkcs8_b, _) = ed25519_test_keypair();
        let authority_b =
            JwtAuthority::new_ed25519(pkcs8_b, "peer-b", "rustgate-test").expect("ed25519 b");

        let token = authority_a.issue("peer-a", vec![]).expect("issue");
        let err = authority_b
            .validate(&token)
            .expect_err("should reject unknown kid");
        assert!(matches!(err, JwtError::UnknownKid(ref k) if k == "peer-a"));
    }

    #[test]
    fn ed25519_authority_rejects_token_without_kid() {
        // An EdDSA authority has `legacy_verifier: None`, so a token
        // whose header has no `kid` cannot fall back — it's rejected.
        let (pkcs8, _) = ed25519_test_keypair();
        let auth = JwtAuthority::new_ed25519(pkcs8, "peer-a", "rustgate-test").expect("ed25519");

        // Craft a no-kid token by signing with a separate HS256 authority.
        let hs_auth = make_authority();
        let token = hs_auth.issue("peer-1", vec![]).expect("issue hs");

        let err = auth.validate(&token).expect_err("must reject");
        assert!(matches!(err, JwtError::UnknownKid(ref k) if k.is_empty()));
    }

    #[test]
    fn ed25519_algorithm_mismatch_header_vs_key_rejected() {
        // Security defence mirroring the ES256 alg-confusion guard:
        // an attacker crafts a token header claiming `alg: HS256` but
        // presents a `kid` that points to an Ed25519 verifier. The
        // verifier must refuse before any signature check rather than
        // feed the 32-byte Ed25519 public key into HMAC as if it were
        // a shared secret.

        let (pkcs8, pub_a) = ed25519_test_keypair();
        let _authority_a =
            JwtAuthority::new_ed25519(pkcs8, "peer-a", "rustgate-test").expect("ed25519 a");

        let hs_secret = b"test-secret-key-for-jwt-testing!!".to_vec();
        let authority_b = JwtAuthority::new(hs_secret.clone(), "rustgate-test")
            .expect("hs256")
            .with_ed25519_verifier("peer-a", pub_a)
            .expect("register ed25519 verifier");

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
        // Sign with HS256 but stamp peer-a's kid so the verifier routes
        // to the Ed25519 entry.
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
                    key: Algorithm::EdDsa,
                }
            ),
            "expected AlgorithmMismatch, got {err:?}"
        );
    }

    #[test]
    fn ed25519_tampered_signature_rejected() {
        let (pkcs8, _) = ed25519_test_keypair();
        let auth = JwtAuthority::new_ed25519(pkcs8, "peer-a", "rustgate-test").expect("ed25519");
        let token = auth.issue("peer-a", vec![]).expect("issue");

        let parts: Vec<&str> = token.split('.').collect();
        // Ed25519 signatures are exactly 64 bytes (RFC 8032 §5.1.6);
        // 64 zero bytes keeps the length valid but the signature cannot
        // verify against any real public key.
        let bad_sig = b64::encode_url_safe([0u8; 64]);
        let tampered = format!("{}.{}.{}", parts[0], parts[1], bad_sig);
        assert_eq!(auth.validate(&tampered), Err(JwtError::InvalidSignature));
    }

    #[test]
    fn ed25519_tampered_payload_rejected() {
        // Distinct from the ES256 tampered-sig test: flip a bit in the
        // payload segment so the signature-over-input no longer matches.
        let (pkcs8, _) = ed25519_test_keypair();
        let auth = JwtAuthority::new_ed25519(pkcs8, "peer-a", "rustgate-test").expect("ed25519");
        let token = auth.issue("peer-a", vec![]).expect("issue");

        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{}.dGFtcGVyZWQ.{}", parts[0], parts[2]);
        assert_eq!(auth.validate(&tampered), Err(JwtError::InvalidSignature));
    }

    #[test]
    fn new_ed25519_rejects_malformed_pkcs8() {
        // 64 bytes of 0xFF is not a valid PKCS#8 v2 DER blob.
        let garbage = vec![0xFFu8; 64];
        let err =
            JwtAuthority::new_ed25519(garbage, "peer-a", "rustgate-test").expect_err("must reject");
        assert_eq!(err, JwtError::InvalidKey);
    }

    #[test]
    fn new_ed25519_rejects_ecdsa_pkcs8() {
        // An ECDSA P-256 PKCS#8 blob is well-formed DER but the wrong
        // algorithm — ring must refuse it rather than silently accept.
        let (ecdsa_pkcs8, _) = es256_test_keypair();
        let err = JwtAuthority::new_ed25519(ecdsa_pkcs8, "peer-a", "rustgate-test")
            .expect_err("must reject cross-algorithm PKCS#8");
        assert_eq!(err, JwtError::InvalidKey);
    }

    #[test]
    fn with_ed25519_verifier_rejects_wrong_length_public_key() {
        let (pkcs8, _) = ed25519_test_keypair();
        let auth = JwtAuthority::new_ed25519(pkcs8, "peer-a", "rustgate-test").expect("ed25519");

        // Too short.
        let short = vec![0u8; 31];
        let err = auth
            .with_ed25519_verifier("peer-b", short)
            .expect_err("must reject 31-byte key");
        assert_eq!(err, JwtError::InvalidKey);

        // Too long (33 bytes — e.g. an SEC1 point prefix mistakenly
        // included).
        let (pkcs8, _) = ed25519_test_keypair();
        let auth = JwtAuthority::new_ed25519(pkcs8, "peer-a", "rustgate-test").expect("ed25519");
        let long = vec![0u8; 33];
        let err = auth
            .with_ed25519_verifier("peer-b", long)
            .expect_err("must reject 33-byte key");
        assert_eq!(err, JwtError::InvalidKey);
    }

    #[test]
    fn ed25519_invalid_kid_rejected_on_builders() {
        let (pkcs8, _) = ed25519_test_keypair();
        // Empty kid.
        let err =
            JwtAuthority::new_ed25519(&pkcs8[..], "", "rustgate-test").expect_err("empty kid");
        assert_eq!(err, JwtError::InvalidKid);

        // Oversized kid.
        let long_kid = "a".repeat(MAX_KID_LENGTH + 1);
        let err = JwtAuthority::new_ed25519(&pkcs8[..], long_kid, "rustgate-test")
            .expect_err("oversized kid");
        assert_eq!(err, JwtError::InvalidKid);

        // Control character.
        let err = JwtAuthority::new_ed25519(&pkcs8[..], "peer\x07a", "rustgate-test")
            .expect_err("control char kid");
        assert_eq!(err, JwtError::InvalidKid);

        // Non-ASCII.
        let err = JwtAuthority::new_ed25519(&pkcs8[..], "peer-α", "rustgate-test")
            .expect_err("non-ascii kid");
        assert_eq!(err, JwtError::InvalidKid);
    }

    #[test]
    fn ed25519_signature_is_deterministic() {
        // RFC 8032 §5.1.6: Ed25519 signatures are deterministic — the
        // same (key, message) pair must always produce the same
        // signature. This is a deliberate property (no nonce-reuse
        // footgun) and differs from ES256 where randomness is required.
        let (pkcs8, _) = ed25519_test_keypair();
        let auth = JwtAuthority::new_ed25519(pkcs8, "peer-det", "rustgate-test").expect("ed25519");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let claims = FederationClaims {
            sub: "peer-det".to_string(),
            iss: "rustgate-test".to_string(),
            exp: now + 3600,
            iat: now,
            jti: "fixed-jti".to_string(),
            groups: vec![],
        };
        let token1 = encode(&auth.signing, &claims).expect("encode 1");
        let token2 = encode(&auth.signing, &claims).expect("encode 2");
        assert_eq!(
            token1, token2,
            "Ed25519 must produce identical output for identical input"
        );
    }

    #[test]
    fn ed25519_verifier_cross_algorithm_rejects_ecdsa_pubkey() {
        // Registering a 32-byte key that happens to be drawn from ECDSA
        // material must still be rejected on length only if it's not
        // 32 bytes — but a 32-byte blob is always accepted as raw
        // Ed25519 bytes (there is no way to tell ed25519 from random
        // bytes at this layer). The meaningful cross-algorithm check is
        // that verification itself fails: a token signed with Ed25519
        // cannot verify against a mismatched "Ed25519" verifier built
        // from unrelated bytes.
        let (pkcs8_a, _pub_a) = ed25519_test_keypair();
        let authority_a =
            JwtAuthority::new_ed25519(pkcs8_a, "peer-a", "rustgate-test").expect("ed25519 a");

        // Authority B registers the wrong 32-byte public key under
        // peer-a's kid.
        let (pkcs8_b, _pub_b) = ed25519_test_keypair();
        let wrong_key = vec![0xABu8; 32];
        let authority_b = JwtAuthority::new_ed25519(pkcs8_b, "peer-b", "rustgate-test")
            .expect("ed25519 b")
            .with_ed25519_verifier("peer-a", wrong_key)
            .expect("register wrong key");

        let token = authority_a.issue("peer-a", vec![]).expect("issue");
        let err = authority_b
            .validate(&token)
            .expect_err("wrong Ed25519 public key must fail verification");
        assert_eq!(err, JwtError::InvalidSignature);
    }

    // ── Back to the HS256 verifier tests ────────────────────────────

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

    // --- JwtError Display tests ---
    //
    // JwtError keeps a manual `impl Display` because `UnknownKid(String)`
    // renders two distinct messages depending on whether the inner kid
    // is empty (no `kid` header at all) or non-empty (a real kid that
    // did not resolve in the verifier registry). thiserror's
    // `#[error("...")]` attribute is one format string per variant,
    // with no template form that branches on field content. Splitting
    // the variant into `MissingKid` + `UnknownKid(String)` would let
    // thiserror handle this cleanly, but is a breaking change to the
    // public error API and intentionally out of scope here. These
    // tests pin every variant's output so any future refactor of the
    // manual Display fails loudly rather than silently breaking
    // operator log-correlation tooling.
    //
    // See `impl Display for JwtError` for the rationale doc-comment.

    #[test]
    fn jwt_error_simple_variants_display_byte_stable() {
        assert_eq!(JwtError::Expired.to_string(), "token expired");
        assert_eq!(
            JwtError::IssuedInFuture.to_string(),
            "token issued in the future"
        );
        assert_eq!(JwtError::InvalidSignature.to_string(), "invalid signature");
        assert_eq!(JwtError::Malformed.to_string(), "malformed token");
        assert_eq!(JwtError::InvalidIssuer.to_string(), "invalid issuer");
        assert_eq!(JwtError::Revoked.to_string(), "token revoked");
        assert_eq!(JwtError::ClockError.to_string(), "system clock error");
        assert_eq!(JwtError::InvalidKey.to_string(), "invalid key material");
    }

    #[test]
    fn jwt_error_serialization_error_display_includes_msg() {
        let err = JwtError::SerializationError("bad json at line 1".to_string());
        assert_eq!(err.to_string(), "serialization error: bad json at line 1");
    }

    #[test]
    fn jwt_error_secret_too_short_display_includes_min_and_actual() {
        let err = JwtError::SecretTooShort { min: 32, actual: 8 };
        assert_eq!(err.to_string(), "secret too short: need 32 bytes, got 8");
    }

    #[test]
    fn jwt_error_unsupported_algorithm_display_includes_alg() {
        let err = JwtError::UnsupportedAlgorithm("RS256".to_string());
        assert_eq!(err.to_string(), "unsupported algorithm: RS256");
    }

    #[test]
    fn jwt_error_unknown_kid_display_branches_on_emptiness() {
        // Empty kid → "no kid header at all" path.
        let err = JwtError::UnknownKid(String::new());
        assert_eq!(
            err.to_string(),
            "token has no kid and no legacy verifier is configured"
        );
        // Non-empty kid → "kid did not resolve in registry" path. This
        // branching is exactly why JwtError keeps a manual Display.
        let err = JwtError::UnknownKid("peer-a".to_string());
        assert_eq!(err.to_string(), "unknown kid: peer-a");
    }

    #[test]
    fn jwt_error_algorithm_mismatch_display_names_both_algorithms() {
        let err = JwtError::AlgorithmMismatch {
            header: Algorithm::Hs256,
            key: Algorithm::Es256,
        };
        assert_eq!(
            err.to_string(),
            "token alg HS256 does not match key alg ES256 for selected kid"
        );
    }

    #[test]
    fn jwt_error_invalid_kid_display_embeds_max_length() {
        // The literal `MAX_KID_LENGTH` is interpolated into the
        // message — pin the rendered text against the constant rather
        // than a hard-coded number so a deliberate cap change updates
        // both sides together.
        let err = JwtError::InvalidKid;
        assert_eq!(
            err.to_string(),
            format!("kid must be non-empty, <= {MAX_KID_LENGTH} bytes, and printable ASCII")
        );
    }
}
