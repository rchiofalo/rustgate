// Copyright © 2026 Roberto Chiofalo.

//! JSON Web Key Set (JWKS, RFC 7517) representation, key-rotation state
//! machine, and PEM key loading for federation JWT authentication.
//!
//! Closes #760. Federation V2 JWT auth uses asymmetric algorithms
//! (ES256 / EdDSA) for cross-peer trust where a compromised verifier
//! must not leak the issuing key. This module wraps the per-`kid`
//! verifier registry that lives inside [`crate::jwt::JwtAuthority`]
//! with two operator-facing concepts:
//!
//! 1. **JWKS serialization (RFC 7517)** — the verifier set serializes
//!    into the standard `{"keys": [...]}` envelope with one
//!    [`Jwk`] per public key. Operators expose this at
//!    `/.well-known/jwks.json` so remote peers can discover the public
//!    keys this server is currently willing to verify against. Only
//!    asymmetric public keys appear in the JWKS — HS256 secrets must
//!    never leave the issuing host and are filtered out at serialization
//!    time. Tokens issued by this server's signing key carry the same
//!    `kid` in their JOSE header so verifiers can match the JWT to the
//!    right entry.
//!
//! 2. **Key-rotation state machine** — every JWKS entry carries a
//!    [`KeyState`] (`Active`, `VerifyOnly`, `Removed`). The intended
//!    operator workflow is:
//!
//!    - Stage a new key as `Active`. The signer flips to it; verifiers
//!      list both old and new in JWKS so in-flight tokens still verify.
//!    - Demote the previous key to `VerifyOnly`. Signing stops on the
//!      old key, but tokens it already minted continue to verify until
//!      they expire.
//!    - Once the old key's longest-lived issued token has expired
//!      (operator waits one token-TTL beyond the demotion), mark it
//!      `Removed`. JWKS no longer advertises it and validation rejects
//!      any token that still references its `kid`.
//!
//! 3. **PEM key loading** — operators stage signing/verifying material
//!    on disk as PEM. [`load_es256_pkcs8_pem`] / [`load_ed25519_pkcs8_pem`]
//!    funnel through [`rustgate_core::secrets::read_secret_file`] so
//!    permission, size, and ownership checks match the rest of the
//!    workspace (see #1188 for the unification rationale). Public-key
//!    PEM is unwrapped by [`load_es256_public_pem`] /
//!    [`load_ed25519_public_pem`] which strip the SPKI/SubjectPublicKeyInfo
//!    framing and return the raw key material that
//!    [`crate::jwt::JwtAuthority::with_es256_verifier`] /
//!    [`crate::jwt::JwtAuthority::with_ed25519_verifier`] expect.
//!
//! ## Algorithm-confusion defense
//!
//! The key-rotation state machine does not weaken the algorithm-mismatch
//! check in [`crate::jwt::JwtAuthority::validate`]. A JWKS entry's
//! advertised `alg` is only a hint to remote peers; the verifier on
//! this side enforces `header.alg == verifier.algorithm()` before any
//! signature work, so a token whose header claims `alg=HS256` cannot
//! recycle a JWKS-published P-256 public key as an HMAC secret. This
//! defense is exercised by `algorithm_confusion_attack_rejected` in
//! the in-file test module.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustgate_core::b64;
use rustgate_core::secrets::{SecretFileError, SecretFileOpts, read_secret_file};
use zeroize::Zeroizing;

use crate::jwt::{Algorithm, VerificationKeyView};

/// Permitted PEM size for a private signing key on disk. ES256 PKCS#8
/// PEMs run ~250 B, Ed25519 ~120 B, RSA up to ~3 KiB; 16 KiB leaves
/// headroom without inviting a multi-megabyte file abuse path.
const MAX_PEM_KEY_BYTES: u64 = 16 * 1024;

/// Maximum PEM size we will attempt to parse for a public key file.
/// SPKI-wrapped public keys are at most a few hundred bytes; we
/// keep the same 16 KiB cap as private keys for symmetry with
/// [`MAX_PEM_KEY_BYTES`] and to allow the same `SecretFileOpts` profile.
const MAX_PUBLIC_PEM_BYTES: u64 = 16 * 1024;

/// Lifecycle state of a JWKS entry.
///
/// The transitions are deliberately one-way (`Active → VerifyOnly →
/// Removed`) so an operator script that promotes a key by mistake
/// cannot silently roll back to a state where the demoted key starts
/// signing again. A misconfigured rollback must instead introduce a
/// new entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyState {
    /// Currently signs new JWTs and verifies incoming ones. There is at
    /// most one `Active` key per algorithm at a time — a key rotation
    /// stages the new key as `Active` and demotes the old one to
    /// `VerifyOnly` in the same operator action so the JWKS never has
    /// two `Active` ES256 keys simultaneously.
    Active,
    /// Stops signing, still verifies. This is the drain window for the
    /// previous `Active` key while in-flight tokens it issued naturally
    /// expire.
    VerifyOnly,
    /// No longer advertised in JWKS and rejected by the verifier with
    /// [`crate::jwt::JwtError::UnknownKid`]. Operators set this state
    /// only after the longest-lived issued token under this `kid` has
    /// expired (typically `default_expiry` after the `Active →
    /// VerifyOnly` demotion).
    Removed,
}

impl KeyState {
    /// True when verification is allowed. `Removed` is the only
    /// state where verification is rejected.
    pub fn allows_verification(self) -> bool {
        matches!(self, KeyState::Active | KeyState::VerifyOnly)
    }

    /// True when signing is allowed. Only `Active` keys may sign;
    /// `VerifyOnly` and `Removed` reject signing attempts.
    pub fn allows_signing(self) -> bool {
        matches!(self, KeyState::Active)
    }
}

/// A single JWK entry per RFC 7517 §4.
///
/// Field ordering is canonical (`alphabetical via BTreeMap` at
/// serialization time) so two servers serving the same key set produce
/// byte-identical JWKS responses, which simplifies caching and
/// shareable JWKS fixtures in CI.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Jwk {
    /// Key type. `EC` for ES256 (RFC 7518 §6.2), `OKP` for EdDSA
    /// (RFC 8037 §2).
    pub kty: String,
    /// Key identifier matching the JWT header `kid`.
    pub kid: String,
    /// Algorithm — `ES256` or `EdDSA`.
    pub alg: String,
    /// Permitted use, always `"sig"` for our JWTs (RFC 7517 §4.2).
    #[serde(rename = "use")]
    pub r#use: String,
    /// EC curve name for ES256 (`"P-256"`) — present on `kty=EC`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// Base64url-encoded x coordinate (ES256) or full public key (EdDSA).
    /// RFC 7518 §6.2.1 / RFC 8037 §2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Base64url-encoded y coordinate (ES256 only). RFC 7518 §6.2.1.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// JWKS document per RFC 7517 §5.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JwkSet {
    /// Public keys this server is willing to verify against.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Locate a JWK by its `kid`.
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// Construct a JWK from a verifier-side view of a public key. Returns
/// `None` for HS256 (symmetric secrets must never leave the issuing
/// host).
fn jwk_from_view(kid: &str, view: &VerificationKeyView<'_>) -> Option<Jwk> {
    match view {
        // HS256 secrets are not part of any public JWKS — return None
        // so the caller filters them out at serialization.
        VerificationKeyView::Hs256 => None,
        VerificationKeyView::Es256(sec1) => {
            // SEC1 uncompressed: 0x04 || x(32) || y(32) — 65 bytes.
            // The discriminator must already be 0x04 because
            // `with_es256_verifier` enforces it; treat anything else
            // as a programming error in the verifier registry.
            if sec1.len() != 65 || sec1.first() != Some(&0x04) {
                return None;
            }
            let x = b64::encode_url_safe(&sec1[1..33]);
            let y = b64::encode_url_safe(&sec1[33..65]);
            Some(Jwk {
                kty: "EC".to_string(),
                kid: kid.to_string(),
                alg: Algorithm::Es256.to_string(),
                r#use: "sig".to_string(),
                crv: Some("P-256".to_string()),
                x: Some(x),
                y: Some(y),
            })
        }
        VerificationKeyView::EdDsa(raw) => {
            // RFC 8037 §2: kty=OKP, crv=Ed25519, x = raw 32-byte public
            // key, no y coordinate. The 32-byte length is enforced at
            // verifier registration; reject silently if the registry
            // is in an unexpected shape.
            if raw.len() != 32 {
                return None;
            }
            Some(Jwk {
                kty: "OKP".to_string(),
                kid: kid.to_string(),
                alg: Algorithm::EdDsa.to_string(),
                r#use: "sig".to_string(),
                crv: Some("Ed25519".to_string()),
                x: Some(b64::encode_url_safe(raw)),
                y: None,
            })
        }
    }
}

/// Build a JWKS from an iterator of `(kid, view, state)` triples.
///
/// Entries in [`KeyState::Removed`] state are excluded — JWKS only
/// advertises keys that are still verifying. HS256 entries are also
/// excluded because publishing a symmetric secret would defeat the
/// security boundary JWKS exists to provide.
pub fn build_jwk_set<'a, I>(entries: I) -> JwkSet
where
    I: IntoIterator<Item = (&'a str, VerificationKeyView<'a>, KeyState)>,
{
    let mut keys = Vec::new();
    for (kid, view, state) in entries {
        if !state.allows_verification() {
            continue;
        }
        if let Some(jwk) = jwk_from_view(kid, &view) {
            keys.push(jwk);
        }
    }
    // Sort by kid for deterministic byte output. RFC 7517 does not
    // mandate ordering, but byte-stable JWKS responses cache better
    // and make test pinning trivial.
    keys.sort_by(|a, b| a.kid.cmp(&b.kid));
    JwkSet { keys }
}

/// Hot-reloadable view over a per-`kid` lifecycle state map. The
/// federation HTTP layer consumes this via [`KeyStateRegistry::snapshot`]
/// and the JWT verifier consults it via [`KeyStateRegistry::state_of`]
/// to short-circuit `Removed` keys before any signature work.
///
/// The interior `ArcSwap<BTreeMap>` is the same hot-reload discipline
/// used by ACL / authz / CRL elsewhere in the workspace — see
/// `transport::router` for the canonical example.
#[derive(Debug, Default)]
pub struct KeyStateRegistry {
    inner: ArcSwap<BTreeMap<String, KeyState>>,
}

impl KeyStateRegistry {
    /// Construct an empty registry. Any kid not present in the registry
    /// is treated as `Active` — registries are an explicit demotion
    /// surface, not a default-deny gate.
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(BTreeMap::new()),
        }
    }

    /// Look up the lifecycle state of a `kid`. Returns
    /// [`KeyState::Active`] when the kid is not explicitly demoted —
    /// new keys default to `Active` until the operator marks them
    /// otherwise.
    pub fn state_of(&self, kid: &str) -> KeyState {
        self.inner
            .load()
            .get(kid)
            .copied()
            .unwrap_or(KeyState::Active)
    }

    /// Replace the current state map atomically.
    pub fn replace(&self, states: BTreeMap<String, KeyState>) {
        self.inner.store(Arc::new(states));
    }

    /// Snapshot the current lifecycle map for serialization or
    /// diagnostics.
    pub fn snapshot(&self) -> BTreeMap<String, KeyState> {
        self.inner.load().as_ref().clone()
    }

    /// Demote a key from `Active` to `VerifyOnly`. No-op for a kid
    /// that is already `VerifyOnly` or `Removed`. This is the second
    /// step of the rotation workflow — the operator typically calls
    /// it after promoting a replacement to `Active`.
    pub fn demote_to_verify_only(&self, kid: &str) {
        let mut next = self.snapshot();
        let entry = next.entry(kid.to_string()).or_insert(KeyState::Active);
        if matches!(entry, KeyState::Active) {
            *entry = KeyState::VerifyOnly;
        }
        self.replace(next);
    }

    /// Mark a key as `Removed` (no longer advertised in JWKS, no longer
    /// accepted by the verifier). One-way: once `Removed`, the entry
    /// stays `Removed`. The operator must introduce a new `kid` to
    /// restore service for that peer.
    pub fn remove(&self, kid: &str) {
        let mut next = self.snapshot();
        let _ = next.insert(kid.to_string(), KeyState::Removed);
        self.replace(next);
    }
}

// ── PEM key loading ─────────────────────────────────────────────────

/// Errors returned by the PEM loaders in this module.
#[derive(Debug, thiserror::Error)]
pub enum PemKeyError {
    /// The file could not be read, was too large, or had insecure
    /// permissions. The wrapped [`SecretFileError`] preserves the
    /// underlying classification (`PermissionsTooOpen`, `TooLarge`,
    /// `OwnerMismatch`, `NotReadable`, `Empty`).
    #[error("pem secret file error: {0}")]
    SecretFile(#[from] SecretFileError),
    /// The PEM tag did not match the expected key kind, or the body
    /// was not parseable DER.
    #[error("pem parse error: {0}")]
    Parse(String),
    /// The DER body parsed but was the wrong shape for the requested
    /// key (e.g. an RSA PKCS#8 file passed to the ES256 loader).
    #[error("key material rejected: {0}")]
    Invalid(String),
}

/// Strip a single `-----BEGIN xxx----- / -----END xxx-----` envelope
/// and decode the base64 body.
fn parse_pem_block(pem: &str, expected_tag: &str) -> Result<Vec<u8>, PemKeyError> {
    let begin = format!("-----BEGIN {expected_tag}-----");
    let end = format!("-----END {expected_tag}-----");
    let begin_idx = pem
        .find(&begin)
        .ok_or_else(|| PemKeyError::Parse(format!("missing {begin}")))?;
    let after_begin = begin_idx + begin.len();
    let end_idx = pem[after_begin..]
        .find(&end)
        .ok_or_else(|| PemKeyError::Parse(format!("missing {end}")))?;
    let body = &pem[after_begin..after_begin + end_idx];
    // RFC 7468 allows whitespace inside the base64 body — strip it
    // before decoding.
    let stripped: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes =
        b64::decode(stripped.as_bytes()).map_err(|e| PemKeyError::Parse(format!("base64: {e}")))?;
    Ok(bytes)
}

/// Load an ES256 (ECDSA P-256) PKCS#8 private key from a PEM file.
/// Returns the DER bytes ready to feed to
/// [`crate::jwt::JwtAuthority::new_es256`]. The bytes are wiped on drop
/// because they hold private signing material.
pub fn load_es256_pkcs8_pem(path: impl AsRef<Path>) -> Result<Zeroizing<Vec<u8>>, PemKeyError> {
    let opts = SecretFileOpts::with_max_bytes(MAX_PEM_KEY_BYTES);
    let raw = read_secret_file(path, &opts)?;
    let der = parse_pem_block(&raw, "PRIVATE KEY")?;
    Ok(Zeroizing::new(der))
}

/// Load an Ed25519 PKCS#8 private key from a PEM file. Same contract as
/// [`load_es256_pkcs8_pem`].
pub fn load_ed25519_pkcs8_pem(path: impl AsRef<Path>) -> Result<Zeroizing<Vec<u8>>, PemKeyError> {
    let opts = SecretFileOpts::with_max_bytes(MAX_PEM_KEY_BYTES);
    let raw = read_secret_file(path, &opts)?;
    let der = parse_pem_block(&raw, "PRIVATE KEY")?;
    Ok(Zeroizing::new(der))
}

/// Load an ES256 SPKI public-key PEM and unwrap to the raw 65-byte
/// SEC1 uncompressed point. The caller hands this to
/// [`crate::jwt::JwtAuthority::with_es256_verifier`].
///
/// The SPKI structure for `id-ecPublicKey` + `secp256r1` always ends
/// with the BIT STRING containing the uncompressed point, so we locate
/// the `0x04` discriminator and copy the trailing 65 bytes. This avoids
/// pulling in a full ASN.1 dependency for what is a deterministic suffix.
pub fn load_es256_public_pem(path: impl AsRef<Path>) -> Result<Vec<u8>, PemKeyError> {
    let opts = SecretFileOpts::with_max_bytes(MAX_PUBLIC_PEM_BYTES);
    let raw = read_secret_file(path, &opts)?;
    let spki = parse_pem_block(&raw, "PUBLIC KEY")?;
    extract_sec1_from_es256_spki(&spki)
}

/// Load an Ed25519 SPKI public-key PEM and unwrap to the raw 32-byte
/// public key per RFC 8410 §4. Hand to
/// [`crate::jwt::JwtAuthority::with_ed25519_verifier`].
pub fn load_ed25519_public_pem(path: impl AsRef<Path>) -> Result<Vec<u8>, PemKeyError> {
    let opts = SecretFileOpts::with_max_bytes(MAX_PUBLIC_PEM_BYTES);
    let raw = read_secret_file(path, &opts)?;
    let spki = parse_pem_block(&raw, "PUBLIC KEY")?;
    extract_raw_from_ed25519_spki(&spki)
}

/// Strip the SPKI/AlgorithmIdentifier framing and return the trailing
/// 65-byte SEC1 point. Errors out if the input is not the well-known
/// shape produced by `openssl ec -pubout` for an `id-ecPublicKey` +
/// `secp256r1` key (91 bytes total, with the SEC1 point in the last 65).
fn extract_sec1_from_es256_spki(spki: &[u8]) -> Result<Vec<u8>, PemKeyError> {
    // The standard ES256 SPKI is 91 bytes; the uncompressed point lives
    // in the trailing 65 bytes after a fixed AlgorithmIdentifier prefix.
    // Anything else is either a different curve, a malformed key, or a
    // future format we don't recognise — refuse explicitly.
    if spki.len() != 91 {
        return Err(PemKeyError::Invalid(format!(
            "ES256 SPKI must be 91 bytes (got {})",
            spki.len()
        )));
    }
    let point = &spki[spki.len() - 65..];
    if point.first() != Some(&0x04) {
        return Err(PemKeyError::Invalid(
            "ES256 SPKI tail must be SEC1 uncompressed (0x04)".to_string(),
        ));
    }
    Ok(point.to_vec())
}

/// Strip the SPKI/AlgorithmIdentifier framing and return the trailing
/// 32-byte raw Ed25519 public key. Mirrors
/// [`extract_sec1_from_es256_spki`] but for `id-Ed25519`.
fn extract_raw_from_ed25519_spki(spki: &[u8]) -> Result<Vec<u8>, PemKeyError> {
    // The standard Ed25519 SPKI is 44 bytes (12-byte AlgorithmIdentifier
    // wrapper + BIT STRING header + 32-byte key). Refuse anything else.
    if spki.len() != 44 {
        return Err(PemKeyError::Invalid(format!(
            "Ed25519 SPKI must be 44 bytes (got {})",
            spki.len()
        )));
    }
    Ok(spki[12..44].to_vec())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use ring::signature::{self as ring_sig, KeyPair};

    use super::*;
    use crate::jwt::{FederationClaims, JwtAuthority, JwtError};

    fn es256_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = ring_sig::EcdsaKeyPair::generate_pkcs8(
            &ring_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .expect("keygen");
        let key_pair = ring_sig::EcdsaKeyPair::from_pkcs8(
            &ring_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
            rng.as_ref(),
            &ring::rand::SystemRandom::new(),
        )
        .expect("parse pkcs8");
        let public_key = key_pair.public_key().as_ref().to_vec();
        (rng.as_ref().to_vec(), public_key)
    }

    fn ed25519_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring_sig::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        let key_pair = ring_sig::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse pkcs8");
        let public_key = key_pair.public_key().as_ref().to_vec();
        (pkcs8.as_ref().to_vec(), public_key)
    }

    // ── KeyState basics ─────────────────────────────────────────────

    #[test]
    fn key_state_active_allows_signing_and_verification() {
        assert!(KeyState::Active.allows_signing());
        assert!(KeyState::Active.allows_verification());
    }

    #[test]
    fn key_state_verify_only_blocks_signing_but_allows_verification() {
        assert!(!KeyState::VerifyOnly.allows_signing());
        assert!(KeyState::VerifyOnly.allows_verification());
    }

    #[test]
    fn key_state_removed_blocks_everything() {
        assert!(!KeyState::Removed.allows_signing());
        assert!(!KeyState::Removed.allows_verification());
    }

    #[test]
    fn registry_default_state_is_active() {
        let reg = KeyStateRegistry::new();
        assert_eq!(reg.state_of("anything"), KeyState::Active);
    }

    #[test]
    fn registry_demote_to_verify_only_persists_across_loads() {
        let reg = KeyStateRegistry::new();
        reg.demote_to_verify_only("k1");
        assert_eq!(reg.state_of("k1"), KeyState::VerifyOnly);
    }

    #[test]
    fn registry_remove_persists_and_blocks_demotion_back() {
        let reg = KeyStateRegistry::new();
        reg.remove("k1");
        assert_eq!(reg.state_of("k1"), KeyState::Removed);

        // Demote attempt does not flip Removed back to VerifyOnly —
        // demote_to_verify_only only acts on Active entries.
        reg.demote_to_verify_only("k1");
        assert_eq!(reg.state_of("k1"), KeyState::Removed);
    }

    #[test]
    fn registry_replace_swaps_atomic_snapshot() {
        let reg = KeyStateRegistry::new();
        let mut next = BTreeMap::new();
        let _ = next.insert("a".to_string(), KeyState::Active);
        let _ = next.insert("b".to_string(), KeyState::VerifyOnly);
        reg.replace(next);
        assert_eq!(reg.state_of("a"), KeyState::Active);
        assert_eq!(reg.state_of("b"), KeyState::VerifyOnly);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2);
    }

    // ── JWKS serialization ──────────────────────────────────────────

    #[test]
    fn jwks_endpoint_returns_currently_trusted_keys() {
        // Build a small federation with one ES256 verifier and one EdDSA
        // verifier. Serialize the registry to JSON, parse the JSON, and
        // assert kid + alg + kty across both entries.
        let (pkcs8_es, pub_es) = es256_test_keypair();
        let (_pkcs8_ed, pub_ed) = ed25519_test_keypair();
        let auth = JwtAuthority::new_es256(pkcs8_es, "k-es", "rustgate-test")
            .expect("es256")
            .with_ed25519_verifier("k-ed", pub_ed.clone())
            .expect("ed25519 verifier");

        let registry = KeyStateRegistry::new();
        let entries = auth
            .verifier_views()
            .into_iter()
            .map(|(kid, view)| {
                let state = registry.state_of(&kid);
                (kid, view, state)
            })
            .collect::<Vec<_>>();
        // Re-borrow as &str + view + state for build_jwk_set.
        let triples = entries
            .iter()
            .map(|(k, v, s)| (k.as_str(), v.borrow(), *s))
            .collect::<Vec<_>>();
        let jwks = build_jwk_set(triples);

        let json = serde_json::to_vec(&jwks).expect("serialize");
        let round: JwkSet = serde_json::from_slice(&json).expect("parse");
        assert_eq!(round.keys.len(), 2);

        let es = round.find("k-es").expect("k-es present");
        assert_eq!(es.kty, "EC");
        assert_eq!(es.alg, "ES256");
        assert_eq!(es.crv.as_deref(), Some("P-256"));
        assert!(es.x.is_some());
        assert!(es.y.is_some());

        let ed = round.find("k-ed").expect("k-ed present");
        assert_eq!(ed.kty, "OKP");
        assert_eq!(ed.alg, "EdDSA");
        assert_eq!(ed.crv.as_deref(), Some("Ed25519"));
        assert!(ed.x.is_some());
        assert!(ed.y.is_none(), "EdDSA JWK must not carry y");

        // Decoded x for EdDSA must equal the registered raw public key.
        let decoded_x = b64::decode_url_safe(ed.x.as_deref().unwrap()).expect("decode");
        assert_eq!(decoded_x, pub_ed);

        // Decoded SEC1 reconstruction for ES256 must equal the registered
        // public key (which is itself SEC1 from `with_es256_verifier`).
        let mut reconstructed = vec![0x04];
        reconstructed.extend_from_slice(&b64::decode_url_safe(es.x.as_deref().unwrap()).unwrap());
        reconstructed.extend_from_slice(&b64::decode_url_safe(es.y.as_deref().unwrap()).unwrap());
        assert_eq!(reconstructed, pub_es);
    }

    #[test]
    fn verifier_picks_key_by_kid_from_jwks() {
        // Multi-key JWKS scenario: authority A signs with k-foo, B
        // signs with k-bar. C carries both verifiers under their kids
        // and must route each token to the right entry.
        let (pkcs8_a, pub_a) = es256_test_keypair();
        let (pkcs8_b, pub_b) = es256_test_keypair();
        let (pkcs8_c, _) = es256_test_keypair();

        let auth_a = JwtAuthority::new_es256(pkcs8_a, "k-foo", "rustgate-test").expect("a");
        let auth_b = JwtAuthority::new_es256(pkcs8_b, "k-bar", "rustgate-test").expect("b");
        let auth_c = JwtAuthority::new_es256(pkcs8_c, "k-c", "rustgate-test")
            .expect("c")
            .with_es256_verifier("k-foo", pub_a)
            .expect("register foo")
            .with_es256_verifier("k-bar", pub_b)
            .expect("register bar");

        let token_a = auth_a.issue("peer-a", vec![]).expect("issue a");
        let token_b = auth_b.issue("peer-b", vec![]).expect("issue b");

        let claims_a = auth_c.validate(&token_a).expect("validate a via foo");
        assert_eq!(claims_a.sub, "peer-a");
        let claims_b = auth_c.validate(&token_b).expect("validate b via bar");
        assert_eq!(claims_b.sub, "peer-b");
    }

    #[test]
    fn jwks_excludes_hs256_secrets() {
        // HS256 secrets must never appear in JWKS — that's the whole
        // point of asymmetric trust. Build an HS256 authority with one
        // peer verifier, serialize, and confirm the keys array is empty.
        let auth = JwtAuthority::new(
            b"test-secret-key-for-jwt-testing!!".to_vec(),
            "rustgate-test",
        )
        .expect("hs256")
        .with_hs256_verifier("k-symmetric", b"another-secret-of-32-bytes-min!!".to_vec())
        .expect("register hs verifier");

        let registry = KeyStateRegistry::new();
        let entries = auth
            .verifier_views()
            .into_iter()
            .map(|(kid, view)| (kid, view, registry.state_of("anything")))
            .collect::<Vec<_>>();
        let triples = entries
            .iter()
            .map(|(k, v, s)| (k.as_str(), v.borrow(), *s))
            .collect::<Vec<_>>();
        let jwks = build_jwk_set(triples);
        assert!(jwks.keys.is_empty(), "HS256 must never leak into JWKS");
    }

    #[test]
    fn jwks_excludes_removed_keys() {
        let (pkcs8, _) = es256_test_keypair();
        let auth = JwtAuthority::new_es256(pkcs8, "k-old", "rustgate-test").expect("es256");

        let registry = KeyStateRegistry::new();
        registry.remove("k-old");

        let entries = auth
            .verifier_views()
            .into_iter()
            .map(|(kid, view)| {
                let state = registry.state_of(&kid);
                (kid, view, state)
            })
            .collect::<Vec<_>>();
        let triples = entries
            .iter()
            .map(|(k, v, s)| (k.as_str(), v.borrow(), *s))
            .collect::<Vec<_>>();
        let jwks = build_jwk_set(triples);
        assert!(jwks.keys.is_empty(), "Removed keys must not appear in JWKS");
    }

    #[test]
    fn jwks_includes_verify_only_keys() {
        // Drain window: a key in VerifyOnly state still verifies
        // in-flight tokens, so it MUST still appear in JWKS.
        let (pkcs8, _) = es256_test_keypair();
        let auth = JwtAuthority::new_es256(pkcs8, "k-draining", "rustgate-test").expect("es256");

        let registry = KeyStateRegistry::new();
        registry.demote_to_verify_only("k-draining");

        let entries = auth
            .verifier_views()
            .into_iter()
            .map(|(kid, view)| {
                let state = registry.state_of(&kid);
                (kid, view, state)
            })
            .collect::<Vec<_>>();
        let triples = entries
            .iter()
            .map(|(k, v, s)| (k.as_str(), v.borrow(), *s))
            .collect::<Vec<_>>();
        let jwks = build_jwk_set(triples);
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, "k-draining");
    }

    // ── Round-trip against ES256 / EdDSA authorities ────────────────

    #[test]
    fn es256_signs_and_verifies_round_trip() {
        let (pkcs8, _) = es256_test_keypair();
        let auth = JwtAuthority::new_es256(pkcs8, "k-rt-es", "rustgate-test").expect("es256");
        let token = auth.issue("peer-rt", vec!["A".into()]).expect("issue");
        let claims = auth.validate(&token).expect("validate");
        assert_eq!(claims.sub, "peer-rt");
        assert_eq!(claims.groups, vec!["A"]);
    }

    #[test]
    fn eddsa_signs_and_verifies_round_trip() {
        let (pkcs8, _) = ed25519_test_keypair();
        let auth = JwtAuthority::new_ed25519(pkcs8, "k-rt-ed", "rustgate-test").expect("ed25519");
        let token = auth.issue("peer-rt", vec!["B".into()]).expect("issue");
        let claims = auth.validate(&token).expect("validate");
        assert_eq!(claims.sub, "peer-rt");
        assert_eq!(claims.groups, vec!["B"]);
    }

    // ── Algorithm-confusion / cross-algorithm rejection ─────────────

    #[test]
    fn verifier_rejects_jwt_signed_with_wrong_alg() {
        // ES256-only verifier presented with an HS256-signed token →
        // reject. The token has no kid, so the ES256 authority
        // (which has `legacy_verifier: None`) hits UnknownKid before
        // any signature work.
        let (pkcs8, _) = es256_test_keypair();
        let es_auth = JwtAuthority::new_es256(pkcs8, "k-es", "rustgate-test").expect("es256");

        let hs_auth = JwtAuthority::new(
            b"test-secret-key-for-jwt-testing!!".to_vec(),
            "rustgate-test",
        )
        .expect("hs");
        let hs_token = hs_auth.issue("peer-1", vec![]).expect("issue hs");

        let err = es_auth.validate(&hs_token).expect_err("must reject");
        assert!(matches!(err, JwtError::UnknownKid(_)));
    }

    #[test]
    fn algorithm_confusion_attack_rejected() {
        // Classic JWT vulnerability: attacker takes the ES256 public
        // key (published in JWKS), uses it as the HMAC secret, and
        // crafts a token with `alg=HS256` + `kid=peer-a` so a naive
        // verifier picks the ES256 entry but treats the public bytes as
        // HMAC material. The typed Algorithm enum on each verifier
        // entry rejects this with `AlgorithmMismatch` before any
        // signature work.
        let (pkcs8, pub_a) = es256_test_keypair();
        let _ = JwtAuthority::new_es256(pkcs8, "peer-a", "rustgate-test").expect("es256 a");

        let attacker_secret = pub_a.clone();
        let target_authority = JwtAuthority::new(
            b"target-secret-for-jwt-testing!!1".to_vec(),
            "rustgate-test",
        )
        .expect("target hs256")
        .with_es256_verifier("peer-a", pub_a)
        .expect("register peer-a verifier");

        // Craft an HS256 token using the public key bytes as the secret
        // and stamping peer-a's kid. The attack is "verifier picks
        // peer-a's ES256 entry but feeds it through HMAC as if the
        // header's HS256 declaration was authoritative".
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
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
        // Use crate-internal helper exposed for the test.
        let forged =
            JwtAuthority::test_only_forge_hs256_with_kid(&attacker_secret, "peer-a", &claims);

        let err = target_authority.validate(&forged).expect_err("must reject");
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

    // ── State-machine pin tests ─────────────────────────────────────

    #[test]
    fn verify_only_key_rejects_signing_attempt() {
        // The state-machine pin: a key marked VerifyOnly does not allow
        // signing. The `KeyState::allows_signing` predicate is the
        // authoritative check that callers (e.g. signer factories) use
        // to refuse signing, so pinning it here documents the contract.
        let reg = KeyStateRegistry::new();
        reg.demote_to_verify_only("k-old");
        let state = reg.state_of("k-old");
        assert!(
            !state.allows_signing(),
            "VerifyOnly must not permit signing"
        );
        assert!(
            state.allows_verification(),
            "VerifyOnly must still permit verification"
        );
    }

    #[test]
    fn removed_key_rejects_verification() {
        let reg = KeyStateRegistry::new();
        reg.remove("k-gone");
        let state = reg.state_of("k-gone");
        assert!(!state.allows_signing());
        assert!(
            !state.allows_verification(),
            "Removed must reject verification"
        );
    }

    #[test]
    fn rotation_workflow_active_to_verify_only_to_removed() {
        // End-to-end pin of the operator workflow described in the
        // module docs: stage Active → demote to VerifyOnly → eventually
        // mark Removed.
        let reg = KeyStateRegistry::new();
        // Day 0: kid is Active by default.
        assert_eq!(reg.state_of("k-rotating"), KeyState::Active);

        // Day 1: operator demotes after promoting a replacement.
        reg.demote_to_verify_only("k-rotating");
        assert_eq!(reg.state_of("k-rotating"), KeyState::VerifyOnly);

        // Day N (after TTL drains): operator removes.
        reg.remove("k-rotating");
        assert_eq!(reg.state_of("k-rotating"), KeyState::Removed);
    }

    // ── PEM loaders ─────────────────────────────────────────────────

    #[test]
    fn pem_block_round_trip() {
        let pem = "-----BEGIN PRIVATE KEY-----\n\
                   AAECAwQFBgcICQoLDA0ODw==\n\
                   -----END PRIVATE KEY-----\n";
        let bytes = parse_pem_block(pem, "PRIVATE KEY").expect("parse");
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn pem_block_missing_begin_rejected() {
        let pem = "AAECAwQFBgcICQoLDA0ODw==";
        let err = parse_pem_block(pem, "PRIVATE KEY").expect_err("must reject");
        assert!(matches!(err, PemKeyError::Parse(_)));
    }

    #[test]
    fn pem_block_missing_end_rejected() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAECAwQFBgcICQoLDA0ODw==\n";
        let err = parse_pem_block(pem, "PRIVATE KEY").expect_err("must reject");
        assert!(matches!(err, PemKeyError::Parse(_)));
    }

    #[test]
    fn extract_sec1_from_es256_spki_rejects_wrong_length() {
        let too_short = vec![0u8; 50];
        let err = extract_sec1_from_es256_spki(&too_short).expect_err("must reject");
        assert!(matches!(err, PemKeyError::Invalid(_)));
    }

    #[test]
    fn extract_sec1_from_es256_spki_rejects_wrong_tag() {
        let mut spki = vec![0u8; 91];
        spki[91 - 65] = 0x02; // not 0x04
        let err = extract_sec1_from_es256_spki(&spki).expect_err("must reject");
        assert!(matches!(err, PemKeyError::Invalid(_)));
    }

    #[test]
    fn extract_raw_from_ed25519_spki_rejects_wrong_length() {
        let too_short = vec![0u8; 30];
        let err = extract_raw_from_ed25519_spki(&too_short).expect_err("must reject");
        assert!(matches!(err, PemKeyError::Invalid(_)));
    }

    #[test]
    fn load_es256_pkcs8_pem_round_trip() {
        use std::io::Write;
        // Generate a fresh ES256 key and write it as PEM, then load
        // and use to instantiate a JwtAuthority.
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring_sig::EcdsaKeyPair::generate_pkcs8(
            &ring_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("keygen");
        let pem_body = b64::encode(pkcs8.as_ref());
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{pem_body}\n-----END PRIVATE KEY-----\n");

        let f = tempfile::NamedTempFile::new().expect("tempfile");
        f.as_file().write_all(pem.as_bytes()).expect("write");
        // Apply 0o600 so the strict permission gate passes.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }

        let der = load_es256_pkcs8_pem(f.path()).expect("load");
        let auth = JwtAuthority::new_es256(der.as_slice(), "k-loaded", "rustgate-test")
            .expect("auth from loaded key");
        assert_eq!(auth.signing_kid(), Some("k-loaded"));
    }

    #[test]
    fn load_ed25519_pkcs8_pem_round_trip() {
        use std::io::Write;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring_sig::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        let pem_body = b64::encode(pkcs8.as_ref());
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{pem_body}\n-----END PRIVATE KEY-----\n");

        let f = tempfile::NamedTempFile::new().expect("tempfile");
        f.as_file().write_all(pem.as_bytes()).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }

        let der = load_ed25519_pkcs8_pem(f.path()).expect("load");
        let auth = JwtAuthority::new_ed25519(der.as_slice(), "k-loaded-ed", "rustgate-test")
            .expect("auth from loaded key");
        assert_eq!(auth.signing_kid(), Some("k-loaded-ed"));
    }

    #[test]
    fn load_pkcs8_pem_rejects_world_readable() {
        // The strict SecretFileOpts default forbids any group/other
        // permission bits — this is the path that defends against an
        // operator dropping the key into a shared volume by mistake.
        // We verify the rejection surfaces as PemKeyError::SecretFile.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::PermissionsExt;

            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = ring_sig::EcdsaKeyPair::generate_pkcs8(
                &ring_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )
            .expect("keygen");
            let pem_body = b64::encode(pkcs8.as_ref());
            let pem =
                format!("-----BEGIN PRIVATE KEY-----\n{pem_body}\n-----END PRIVATE KEY-----\n");

            let f = tempfile::NamedTempFile::new().expect("tempfile");
            f.as_file().write_all(pem.as_bytes()).expect("write");
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o644))
                .expect("chmod");

            let err = load_es256_pkcs8_pem(f.path()).expect_err("must reject world-readable");
            assert!(matches!(err, PemKeyError::SecretFile(_)));
        }
    }
}
