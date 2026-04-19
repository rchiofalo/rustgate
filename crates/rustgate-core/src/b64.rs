// Copyright © 2026 Roberto Chiofalo.

//! Workspace-wide base64 engines and encode/decode helpers.
//!
//! Before this module existed the workspace reached for `base64` directly
//! from 17 files with inconsistent styles — `base64::engine::general_purpose::STANDARD`,
//! `base64::Engine::encode(&STANDARD, …)`, `use base64::Engine as _; STANDARD.encode(…)`,
//! plus a URL-safe variant for JWT. Callers had to match the engine to the
//! spec they were implementing (RFC 4648 §4 for general use, §5 URL-safe
//! for JWT), and it was easy to paste the wrong call shape.
//!
//! This module gives every caller one import path and four functions:
//!
//! ```ignore
//! use rustgate_core::b64;
//! let s = b64::encode(payload);                 // RFC 4648 §4 with padding
//! let bytes = b64::decode(&s)?;                 // mirror of `encode`
//! let jwt_part = b64::encode_url_safe(header);  // RFC 4648 §5 without padding
//! let raw = b64::decode_url_safe(jwt_part)?;    // mirror for JWT
//! ```
//!
//! The engines are re-exported so callers that need the lower-level
//! `base64::Engine` trait (e.g. for streaming decoders) do not have to
//! also depend on `base64` directly.

pub use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
pub use base64::{DecodeError, Engine};

/// Encode `data` with standard base64 (RFC 4648 §4), producing a padded
/// ASCII string.
///
/// Use this for anything that shows up in HTTP Basic auth headers,
/// certificate payloads, HMAC digests exchanged as strings, or JSON
/// wire formats that carry binary blobs.
pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
    STANDARD.encode(data)
}

/// Decode standard base64 (RFC 4648 §4). Accepts both padded and
/// unpadded input strictly — matches the default [`base64`] crate
/// behaviour of the `STANDARD` engine.
pub fn decode<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>, DecodeError> {
    STANDARD.decode(data)
}

/// Encode `data` with URL-safe base64 without padding (RFC 4648 §5).
///
/// Use this for JWT components, OAuth tokens, or any context where the
/// encoded bytes appear in a URL or HTTP header that would otherwise
/// collide with `+`, `/`, or `=`.
pub fn encode_url_safe<T: AsRef<[u8]>>(data: T) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode URL-safe base64 without padding (RFC 4648 §5).
pub fn decode_url_safe<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_round_trip() {
        let raw = b"hello world";
        let encoded = encode(raw);
        assert_eq!(encoded, "aGVsbG8gd29ybGQ=");
        assert_eq!(decode(&encoded).expect("decode"), raw);
    }

    #[test]
    fn url_safe_round_trip() {
        // Input that would produce `+` and `/` under standard alphabet —
        // URL-safe must use `-` and `_` instead and drop padding.
        let raw = [0xff, 0xfb, 0xef, 0xbf];
        let encoded = encode_url_safe(raw);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
        assert_eq!(decode_url_safe(&encoded).expect("decode"), raw);
    }

    #[test]
    fn standard_rejects_url_safe_alphabet() {
        // A URL-safe blob should not decode under the standard engine —
        // the `-`/`_` characters are invalid in the §4 alphabet.
        let url_safe = encode_url_safe([0xff, 0xfb]);
        assert!(decode(&url_safe).is_err());
    }

    #[test]
    fn engines_reexported() {
        // Smoke test that the engine constants are usable via the
        // re-export path for callers that need the trait directly.
        let raw = b"x";
        assert_eq!(STANDARD.encode(raw), "eA==");
        assert_eq!(URL_SAFE_NO_PAD.encode(raw), "eA");
    }
}
