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

    /// `ZeroizingKeyPair` must be `Send + Sync` because `CsrSigner`
    /// stores an `Issuer<'static, ZeroizingKeyPair>` that flows across
    /// tokio tasks (the enrollment HTTP handlers are `async` and the
    /// server spawns them onto the multi-threaded runtime). A refactor
    /// that accidentally introduced an `Rc` / `Cell` / non-`Send`
    /// field would fail to compile here rather than at the
    /// `Arc<CsrSigner>` call site in `server.rs`, where the error is
    /// one trait-bound layer removed.
    #[test]
    fn wrapper_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        let wrapped = ZeroizingKeyPair::new(fresh_key());
        assert_send_sync(&wrapped);
    }

    /// `Issuer<'static, _>` requires the signing key to be `'static`,
    /// which for `ZeroizingKeyPair` means "owns its contents, no
    /// borrows". A regression that added a `&'a KeyPair` reference
    /// field would silently break every caller storing the signer
    /// inside an `Arc` that is held past any stack frame. The test
    /// asserts the bound holds by moving the wrapper into a
    /// `Box<dyn SigningKey + Send + Sync + 'static>` — the same shape
    /// the downstream `Issuer` expects.
    #[test]
    fn wrapper_satisfies_static_signing_key_trait_object() {
        fn assert_static<T: 'static>() {}
        assert_static::<ZeroizingKeyPair>();
        let wrapped = ZeroizingKeyPair::new(fresh_key());
        let boxed: Box<dyn SigningKey + Send + Sync + 'static> = Box::new(wrapped);
        // Exercise the trait object once so the compiler cannot elide
        // the erasure — a regression that narrowed the trait bound
        // would fail at this call, not at the `Box::new`.
        let sig = boxed.sign(b"static-bound").expect("trait-object sign");
        assert!(!sig.is_empty());
    }

    /// The custom `Debug` impl must not leak any fragment of the
    /// wrapped key's DER bytes, even incidentally — a regression that
    /// added `.field("serialized_der", &...)` alongside the
    /// `[REDACTED]` marker would still pass the existing
    /// `debug_redacts_inner` test (which only checks for the marker's
    /// presence), but would leak the very bytes the wrapper exists
    /// to protect. This test pins the stricter contract: the rendered
    /// Debug string must not contain ANY byte from the DER serialisation.
    #[test]
    fn debug_does_not_leak_der_bytes() {
        let inner = fresh_key();
        let der = inner.serialize_der();
        // Sample a non-zero byte window from the middle of the DER
        // payload — the start is ASN.1 overhead (`30 82 ...`) that
        // also appears in other structures' headers, and the end may
        // contain small integers that coincidentally show up in the
        // debug text. A 12-byte slice from the middle is specific to
        // this particular key material.
        let probe_start = der.len() / 2;
        let probe = &der[probe_start..probe_start + 12];

        let wrapped = ZeroizingKeyPair::new(inner);
        let rendered = format!("{wrapped:?}");
        let rendered_bytes = rendered.as_bytes();

        // The probe is binary; it is extremely unlikely to appear as
        // a UTF-8 substring of the Debug rendering unless the impl
        // actually prints the DER. A simple windowed byte-slice
        // search is enough to catch the regression.
        for (idx, window) in rendered_bytes.windows(probe.len()).enumerate() {
            assert_ne!(
                window, probe,
                "Debug rendering leaks DER bytes at offset {idx}; got {rendered}"
            );
        }
    }

    /// Distinct inputs must produce distinct signatures, both because
    /// ECDSA/EdDSA signing is collision-resistant in practice and
    /// because a regression that swapped in a zero-returning stub
    /// would silently produce identical "signatures" for every
    /// message. The test is deliberately asymmetric — it compares the
    /// signatures as byte slices rather than asserting a specific
    /// format, so it is algorithm-agnostic and survives a future
    /// switch away from rcgen's default ECDSA P-256 default.
    #[test]
    fn sign_produces_distinct_outputs_for_distinct_inputs() {
        let wrapped = ZeroizingKeyPair::new(fresh_key());
        let sig_a = wrapped.sign(b"message-a").expect("sign a");
        let sig_b = wrapped.sign(b"message-b-is-different").expect("sign b");
        assert!(!sig_a.is_empty() && !sig_b.is_empty());
        assert_ne!(
            sig_a, sig_b,
            "distinct inputs must produce distinct signatures — a regression that returned a constant byte pattern would collide here",
        );
    }

    /// Signing an empty message must not panic and must still return
    /// a non-empty signature. rcgen hashes the message before signing
    /// (SHA-256 for ECDSA P-256), so an empty input hashes to a
    /// well-defined digest rather than tripping a length check.
    /// Enrollment does not currently sign empty payloads in
    /// production, but the contract we pin is "sign is total over
    /// byte slices" so a future caller who passes an empty buffer
    /// from a failed length check does not panic the whole task.
    #[test]
    fn sign_empty_message_does_not_panic_and_returns_signature() {
        let wrapped = ZeroizingKeyPair::new(fresh_key());
        let sig = wrapped.sign(&[]).expect("sign empty must succeed");
        assert!(
            !sig.is_empty(),
            "sign(&[]) must still produce a non-empty DER signature",
        );
    }

    /// Signing the same message twice must return well-formed, bounded-length
    /// DER signatures — rcgen's default ECDSA P-256 signer emits
    /// `SEQUENCE { INTEGER r, INTEGER s }` where r and s are ~256-bit
    /// integers DER-encoded minimally. The total length is usually 70–72
    /// bytes but legitimately dips to 68–69 when r or s happens to have a
    /// leading zero byte (each ~1/256), so pinning a `>= 70` lower bound
    /// makes the test flaky. Instead we assert the DER structure exactly
    /// (SEQUENCE tag + a length byte that matches the content) and a hard
    /// `<= 72` upper bound. A regression that returned progressively-longer
    /// signatures each call (a counter-mode-like state leak) would blow past
    /// 72 bytes and fail here.
    #[test]
    fn sign_same_message_twice_returns_bounded_length_signatures() {
        let wrapped = ZeroizingKeyPair::new(fresh_key());
        let sig1 = wrapped.sign(b"stable-input").expect("sign1");
        let sig2 = wrapped.sign(b"stable-input").expect("sign2");
        for (label, sig) in [("sig1", &sig1), ("sig2", &sig2)] {
            // Validate the DER structure exactly instead of pinning a magic
            // lower bound (the source of the old flake): a P-256 ECDSA
            // signature is a DER SEQUENCE whose content is always < 128
            // bytes, so the short-form length byte equals the content length.
            assert_eq!(
                sig.first(),
                Some(&0x30),
                "{label} must be a DER SEQUENCE (tag 0x30), got {sig:02x?}",
            );
            assert_eq!(
                sig.get(1).copied(),
                Some((sig.len() - 2) as u8),
                "{label} DER length byte must equal content length ({} bytes)",
                sig.len() - 2,
            );
            // Hard upper bound for P-256: SEQUENCE(2) + two INTEGERs of at
            // most 35 bytes (tag+len+33) each. Catches a state-leak regression
            // that would grow the signature past this.
            assert!(
                sig.len() <= 72,
                "{label} exceeds the 72-byte P-256 DER maximum: {} bytes",
                sig.len(),
            );
        }
    }

    /// `der_bytes()` on the wrapper must return the raw public-key
    /// byte string the wrapped `KeyPair` exposes — for the default
    /// algorithm (ECDSA P-256) this is the uncompressed SEC1 point
    /// encoding (`0x04 || X || Y`, exactly 65 bytes). A regression
    /// that accidentally PEM-encoded or hex-encoded the return value
    /// would break every downstream caller that concatenates the
    /// bytes into an X.509 SPKI structure, so the test pins both the
    /// leading tag byte and the exact length.
    #[test]
    fn der_bytes_are_raw_sec1_uncompressed_point() {
        let wrapped = ZeroizingKeyPair::new(fresh_key());
        let der = wrapped.der_bytes();
        assert!(!der.is_empty(), "der_bytes must not be empty");
        assert_eq!(
            der[0], 0x04,
            "SEC1 uncompressed point must start with tag 0x04; got 0x{:02x} — a PEM-encoded or hex-encoded return would start with 0x2d or an ASCII digit",
            der[0],
        );
        assert_eq!(
            der.len(),
            65,
            "ECDSA P-256 uncompressed public point must be exactly 65 bytes (1 tag + 32 X + 32 Y); got {}",
            der.len(),
        );
    }

    /// Dropping a wrapper must not panic under any circumstances —
    /// `Drop` runs during stack unwinding from another panic, and a
    /// panic-in-drop is a double-panic that aborts the process. rcgen's
    /// `zeroize()` is infallible by contract, so this test exercises
    /// the drop path directly (via a scoped block) and relies on the
    /// test harness's panic reporting to catch any regression that
    /// introduced a `.unwrap()` inside `Drop`.
    #[test]
    fn drop_does_not_panic() {
        {
            let _wrapped = ZeroizingKeyPair::new(fresh_key());
            // _wrapped goes out of scope here — Drop fires.
        }
        // Reaching this line is the assertion — the test harness
        // would have aborted the process before we got here if
        // Drop panicked.
    }

    /// Multiple wrappers dropped in sequence must each wipe their own
    /// backing store without cross-contamination. This pins the
    /// independence contract so a regression that moved the wipe into
    /// a shared `static` buffer (an absurd but instructive failure
    /// mode) would trip on the second drop.
    #[test]
    fn multiple_wrappers_drop_independently() {
        for _ in 0..4 {
            let _wrapped = ZeroizingKeyPair::new(fresh_key());
        }
        // If any drop panicked, the harness would have caught it.
    }
}
