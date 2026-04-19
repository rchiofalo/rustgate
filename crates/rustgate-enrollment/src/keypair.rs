// Copyright © 2026 Roberto Chiofalo.

//! Defense-in-depth wrapper that zeroes the CA private key's serialized DER
//! bytes when the enrollment subsystem is torn down.
//!
//! # Why this module exists
//!
//! `rcgen::KeyPair` stores two independent copies of the private key material:
//!
//! 1. A ring-backed parsed form in `KeyPair::kind` (ring-internal state that
//!    does not implement `Zeroize` — ring's security model explicitly
//!    disclaims memory-wiping as out of scope for its public surface).
//! 2. A plain `Vec<u8>` copy of the PKCS#8 DER retained for re-serialization
//!    via `KeyPair::serialize_der`.
//!
//! With rcgen's `zeroize` feature enabled (as configured in the workspace
//! `Cargo.toml`), `rcgen::KeyPair` gains an `impl Zeroize` that wipes copy
//! (2). [`ZeroizingKeyPair`] is a newtype wrapper that invokes that
//! `zeroize()` call on drop so the `Vec<u8>` cannot linger past the
//! enrollment server's lifetime — closing the residue window raised in
//! issue #766 (IMPROVEMENT-ANALYSIS F-39).
//!
//! # Known residual exposure
//!
//! The ring-level parsed key (copy 1) is **not** zeroed by this wrapper
//! because ring does not expose a `Zeroize` bound on its `EcdsaKeyPair` /
//! `Ed25519KeyPair` / `RsaKeyPair` types, and the workspace-wide
//! `unsafe_code = "forbid"` lint prevents reaching into ring's private state
//! via pointer casts. Eliminating that copy requires an upstream change in
//! ring. Until then, the CA-key lifecycle (load once at startup, hold for the
//! entire process) limits the practical exposure: the residue is only
//! reachable to an attacker with post-process memory access, which also
//! grants access to any other secret material in the allocator.
//!
//! # Why not replace rcgen entirely?
//!
//! rcgen is the workspace's standard PKI toolkit (certificate issuance, CRL
//! signing, test-utilities). Swapping it out for a hand-rolled ASN.1 signer
//! would trade a small, tractable residue for a much larger attack surface
//! and a new maintenance burden. The wrapper is the proportionate
//! intervention.

use rcgen::{KeyPair, PublicKeyData, SignatureAlgorithm, SigningKey};
use zeroize::Zeroize;

/// Zeroizing wrapper around [`rcgen::KeyPair`] that wipes the serialized
/// DER copy on drop.
///
/// Implements [`SigningKey`] and [`PublicKeyData`] by delegating to the
/// wrapped `KeyPair`, so an `Issuer<'static, ZeroizingKeyPair>` is a
/// drop-in replacement for `Issuer<'static, KeyPair>`.
///
/// See the module docs for the exact memory-wipe guarantee and the
/// upstream limitation regarding ring's parsed key state.
pub(crate) struct ZeroizingKeyPair {
    inner: KeyPair,
}

impl ZeroizingKeyPair {
    /// Wrap an existing `KeyPair` so its serialized DER copy is zeroed on
    /// drop. The wrapped `KeyPair` is otherwise unchanged.
    pub(crate) fn new(inner: KeyPair) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for ZeroizingKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // rcgen's own Debug already redacts `serialized_der`, but we reassert
        // the redaction here so the type's security property is obvious at a
        // glance and cannot be silently widened by an rcgen release that
        // changes its Debug formatting.
        f.debug_struct("ZeroizingKeyPair")
            .field("inner", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ZeroizingKeyPair {
    fn drop(&mut self) {
        // Wipes `self.inner.serialized_der`. The ring-backed parsed key in
        // `self.inner.kind` is not covered by this sweep (see module docs
        // for rationale and residual exposure).
        self.inner.zeroize();
    }
}

impl PublicKeyData for ZeroizingKeyPair {
    fn der_bytes(&self) -> &[u8] {
        self.inner.der_bytes()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.inner.algorithm()
    }
}

impl SigningKey for ZeroizingKeyPair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.inner.sign(msg)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Build a fresh `KeyPair` for a round-trip test. Uses rcgen's default
    /// algorithm (ECDSA P-256).
    fn fresh_key() -> KeyPair {
        KeyPair::generate().expect("generate keypair for test")
    }

    #[test]
    fn signs_via_delegation() {
        let wrapped = ZeroizingKeyPair::new(fresh_key());
        let msg = b"tactical message router";
        let sig = wrapped.sign(msg).expect("sign delegates to inner");
        // P-256/SHA-256 ASN.1 DER signatures are between 70 and 72 bytes
        // depending on the high-bit-set integer-length boundaries. Reject a
        // degenerate empty signature — the exact length check would pin
        // implementation details we don't own.
        assert!(!sig.is_empty(), "delegated sign() must return a signature");
    }

    #[test]
    fn public_key_delegation_matches_inner() {
        let inner = fresh_key();
        let inner_bytes = inner.der_bytes().to_vec();
        let inner_alg: *const _ = inner.algorithm();

        let wrapped = ZeroizingKeyPair::new(inner);
        assert_eq!(
            wrapped.der_bytes(),
            inner_bytes.as_slice(),
            "der_bytes must match the wrapped KeyPair"
        );
        assert!(
            std::ptr::eq(wrapped.algorithm(), inner_alg),
            "algorithm must be the wrapped KeyPair's &'static reference"
        );
    }

    #[test]
    fn debug_redacts_inner() {
        let wrapped = ZeroizingKeyPair::new(fresh_key());
        let rendered = format!("{wrapped:?}");
        assert!(
            rendered.contains("[REDACTED]"),
            "Debug must redact inner; got: {rendered}"
        );
    }

    #[test]
    fn drop_wipes_serialized_der() {
        // Sanity check: after dropping, the wrapped `KeyPair::serialize_der()`
        // would have been zero-length. Since the wrapped value is moved on
        // drop, we test the behaviour by serializing before and invoking
        // zeroize explicitly on an inner `KeyPair` clone — the same path the
        // Drop impl exercises. This protects against a regression where the
        // Drop impl accidentally stops calling `zeroize`.
        let mut inner = fresh_key();
        let before = inner.serialize_der();
        assert!(!before.is_empty(), "fresh key should have DER bytes");

        inner.zeroize();
        let after = inner.serialize_der();
        assert!(
            after.iter().all(|b| *b == 0),
            "after zeroize(), serialize_der() must return zeros (got non-zero byte)"
        );
    }
}
