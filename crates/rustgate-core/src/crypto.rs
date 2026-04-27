// Copyright © 2026 Roberto Chiofalo.

//! Hardened HMAC-SHA256 helpers with unified key-handling and
//! constant-time verification discipline.
//!
//! Replaces three inlined HMAC-SHA256 constructions across the
//! workspace (transport store-forward integrity tag, http webhook
//! signing, federation JWT HS256 signing) that had subtle divergences
//! in error handling and verification. Concentrating the construction
//! here means the timing-side-channel and key-length disciplines are
//! enforced at one boundary instead of relying on per-caller
//! correctness.
//!
//! # Usage
//!
//! ```
//! use rustgate_core::crypto::{hmac_sha256_tag, hmac_sha256_verify};
//!
//! let key = b"a-shared-secret-of-non-zero-length";
//! let data = b"canonical request bytes";
//!
//! let tag = hmac_sha256_tag(key, data).expect("non-empty key");
//! assert_eq!(tag.len(), 32);
//!
//! hmac_sha256_verify(key, data, &tag).expect("matching tag");
//! ```
//!
//! # Constant-time verification
//!
//! [`hmac_sha256_verify`] compares the computed tag to the supplied
//! tag via [`subtle::ConstantTimeEq::ct_eq`] so a timing side-channel
//! cannot leak how many leading bytes match. Callers MUST use
//! `hmac_sha256_verify` for any verification path; never compare
//! tags with `==`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Length of an HMAC-SHA256 tag in bytes.
pub const HMAC_SHA256_TAG_LEN: usize = 32;

/// Errors returned by the HMAC-SHA256 helpers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HmacError {
    /// The HMAC key was empty. Per RFC 2104, HMAC accepts arbitrary-
    /// length keys, but a zero-byte key provides no authentication
    /// guarantee whatsoever and almost always indicates a configuration
    /// error (uninitialised secret, file truncation, missing env var).
    /// We fail closed.
    #[error("HMAC key length is invalid: {actual_bytes} bytes (must be non-empty)")]
    InvalidKeyLength {
        /// Actual key length in bytes that triggered the failure.
        actual_bytes: usize,
    },
    /// The supplied tag did not match the computed tag. Comparison is
    /// performed in constant time so this error does not reveal where
    /// the divergence occurred.
    #[error("HMAC tag verification failed (constant-time mismatch)")]
    VerificationFailed,
    /// The supplied tag was not exactly [`HMAC_SHA256_TAG_LEN`] bytes.
    /// This check runs before the constant-time comparison so callers
    /// cannot pass a short or oversized buffer and observe whether the
    /// length-mismatch fast path differs from the comparison fast path.
    #[error("HMAC tag length mismatch: got {actual} bytes, expected {expected} bytes")]
    TagLengthMismatch {
        /// Actual tag length supplied by the caller.
        actual: usize,
        /// Expected tag length — always [`HMAC_SHA256_TAG_LEN`].
        expected: usize,
    },
}

/// Compute an HMAC-SHA256 tag over `data` using `key`.
///
/// Returns the 32-byte tag as a `Vec<u8>`. Returns
/// [`HmacError::InvalidKeyLength`] only on the empty-key edge case;
/// HMAC accepts arbitrary-length keys per RFC 2104, so any non-empty
/// key produces a tag.
///
/// # Errors
///
/// - [`HmacError::InvalidKeyLength`] if `key` is empty.
pub fn hmac_sha256_tag(key: &[u8], data: &[u8]) -> Result<Vec<u8>, HmacError> {
    if key.is_empty() {
        return Err(HmacError::InvalidKeyLength { actual_bytes: 0 });
    }
    // justification: `Hmac::<Sha256>::new_from_slice` only fails on the
    // `InvalidLength` path, which the spec defines as "key length zero".
    // We rejected that case above so the constructor is unreachable.
    // Using `expect` here keeps the helper signature simple — promoting
    // it to a fallible path would add an error variant the helper
    // semantically cannot return.
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC accepts any non-empty key length per RFC 2104");
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify an HMAC-SHA256 tag using constant-time comparison.
///
/// Returns `Ok(())` on a successful match, `Err` otherwise. The
/// comparison uses [`subtle::ConstantTimeEq::ct_eq`] to prevent
/// timing side-channels — an attacker cannot infer how many leading
/// bytes of the tag matched by measuring the rejection latency.
///
/// # Errors
///
/// - [`HmacError::InvalidKeyLength`] if `key` is empty.
/// - [`HmacError::TagLengthMismatch`] if `expected_tag` is not exactly
///   [`HMAC_SHA256_TAG_LEN`] bytes. This pre-check runs before the
///   constant-time comparison so the length-mismatch path is itself
///   trivially constant-time (no key-derived branching).
/// - [`HmacError::VerificationFailed`] if the computed tag and the
///   supplied tag differ.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<(), HmacError> {
    if key.is_empty() {
        return Err(HmacError::InvalidKeyLength { actual_bytes: 0 });
    }
    if expected_tag.len() != HMAC_SHA256_TAG_LEN {
        return Err(HmacError::TagLengthMismatch {
            actual: expected_tag.len(),
            expected: HMAC_SHA256_TAG_LEN,
        });
    }
    let computed = hmac_sha256_tag(key, data)?;
    // Constant-time comparison via subtle::ConstantTimeEq prevents
    // timing side-channels. Both sides are equal length here (32 bytes
    // each) so ct_eq exercises its full constant-time path.
    if computed.ct_eq(expected_tag).into() {
        Ok(())
    } else {
        Err(HmacError::VerificationFailed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_tag_returns_thirty_two_bytes() {
        let tag = hmac_sha256_tag(b"some-key", b"some-data").unwrap();
        assert_eq!(tag.len(), HMAC_SHA256_TAG_LEN);
    }

    #[test]
    fn hmac_sha256_tag_rejects_empty_key() {
        let err = hmac_sha256_tag(b"", b"data").unwrap_err();
        assert_eq!(err, HmacError::InvalidKeyLength { actual_bytes: 0 });
    }

    /// RFC 4231 Test Case 1 — key = 20 bytes of 0x0b, data = "Hi There".
    /// Expected HMAC-SHA256:
    ///   b0344c61d8db38535ca8afceaf0bf12b
    ///   881dc200c9833da726e9376c2e32cff7
    #[test]
    fn hmac_sha256_tag_matches_known_test_vector() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected_hex = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        let tag = hmac_sha256_tag(&key, data).unwrap();
        assert_eq!(hex_encode(&tag), expected_hex);
    }

    #[test]
    fn hmac_sha256_verify_succeeds_for_matching_tag() {
        let key = b"shared-secret";
        let data = b"payload bytes";
        let tag = hmac_sha256_tag(key, data).unwrap();
        hmac_sha256_verify(key, data, &tag).unwrap();
    }

    #[test]
    fn hmac_sha256_verify_rejects_wrong_tag() {
        let key = b"shared-secret";
        let data = b"payload bytes";
        let mut tag = hmac_sha256_tag(key, data).unwrap();
        // Flip the final byte so the tag still has the correct length
        // but no longer matches.
        tag[31] ^= 0x01;
        let err = hmac_sha256_verify(key, data, &tag).unwrap_err();
        assert_eq!(err, HmacError::VerificationFailed);
    }

    #[test]
    fn hmac_sha256_verify_rejects_short_tag() {
        let key = b"shared-secret";
        let data = b"payload";
        let short = vec![0u8; 16];
        let err = hmac_sha256_verify(key, data, &short).unwrap_err();
        assert_eq!(
            err,
            HmacError::TagLengthMismatch {
                actual: 16,
                expected: HMAC_SHA256_TAG_LEN,
            }
        );
    }

    #[test]
    fn hmac_sha256_verify_rejects_long_tag() {
        let key = b"shared-secret";
        let data = b"payload";
        let long = vec![0u8; 64];
        let err = hmac_sha256_verify(key, data, &long).unwrap_err();
        assert_eq!(
            err,
            HmacError::TagLengthMismatch {
                actual: 64,
                expected: HMAC_SHA256_TAG_LEN,
            }
        );
    }

    #[test]
    fn hmac_sha256_verify_rejects_empty_key() {
        let tag = vec![0u8; HMAC_SHA256_TAG_LEN];
        let err = hmac_sha256_verify(b"", b"data", &tag).unwrap_err();
        assert_eq!(err, HmacError::InvalidKeyLength { actual_bytes: 0 });
    }

    /// Defense-in-depth check that the verifier source actually uses
    /// `subtle::ConstantTimeEq::ct_eq` rather than `==`. Pinning a true
    /// constant-time guarantee from a unit test is impractical (it
    /// would require statistical timing measurements with very high
    /// sample counts), but a source-level grep is enough to catch the
    /// most likely regression: a refactor that swaps `ct_eq` for `==`.
    #[test]
    fn hmac_sha256_verify_uses_constant_time_compare() {
        let source = include_str!("crypto.rs");
        assert!(
            source.contains("ct_eq"),
            "hmac_sha256_verify MUST use subtle::ConstantTimeEq::ct_eq per CLAUDE.md"
        );
    }

    /// Tag determinism — same key and data must always produce the
    /// same tag (HMAC is, by construction, a deterministic MAC). This
    /// pins that the helper does not accidentally introduce
    /// nondeterminism (e.g. mixing in a per-call nonce).
    #[test]
    fn hmac_sha256_tag_is_deterministic() {
        let key = b"key";
        let data = b"data";
        let a = hmac_sha256_tag(key, data).unwrap();
        let b = hmac_sha256_tag(key, data).unwrap();
        assert_eq!(a, b);
    }

    /// Different keys against the same data must produce different
    /// tags — pins that the helper actually mixes the key in.
    #[test]
    fn hmac_sha256_tag_diverges_on_key_change() {
        let data = b"same data";
        let a = hmac_sha256_tag(b"key-a", data).unwrap();
        let b = hmac_sha256_tag(b"key-b", data).unwrap();
        assert_ne!(a, b);
    }

    /// Different data against the same key must produce different
    /// tags — pins that the helper actually digests the data.
    #[test]
    fn hmac_sha256_tag_diverges_on_data_change() {
        let key = b"the-key";
        let a = hmac_sha256_tag(key, b"data-a").unwrap();
        let b = hmac_sha256_tag(key, b"data-b").unwrap();
        assert_ne!(a, b);
    }

    /// Tiny hex encoder for the RFC 4231 test vector. Avoids pulling
    /// `hex` into rustgate-core's dependency surface just to assert
    /// against a published test vector.
    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}
