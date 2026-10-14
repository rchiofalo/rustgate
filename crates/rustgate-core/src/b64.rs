// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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

    #[test]
    fn empty_input_round_trips_on_standard_engine() {
        // An empty input must encode to an empty string and decode back to
        // an empty Vec. Silent emission of stray bytes here would poison
        // HMAC digests and JSON envelopes whose payload happens to be empty.
        let empty: &[u8] = &[];
        let encoded = encode(empty);
        assert_eq!(encoded, "", "empty input must encode to empty string");
        assert_eq!(
            decode(&encoded).expect("decode empty"),
            Vec::<u8>::new(),
            "empty input must decode to empty Vec",
        );
    }

    #[test]
    fn empty_input_round_trips_on_url_safe_engine() {
        // Mirror of the standard-engine empty-input contract for the JWT
        // / OAuth path. `URL_SAFE_NO_PAD` must produce no padding characters
        // even when the input length is zero.
        let empty: &[u8] = &[];
        let encoded = encode_url_safe(empty);
        assert_eq!(
            encoded, "",
            "url-safe empty input must encode to empty string"
        );
        assert_eq!(
            decode_url_safe(&encoded).expect("decode empty"),
            Vec::<u8>::new(),
            "url-safe empty input must decode to empty Vec",
        );
    }

    #[test]
    fn decode_rejects_non_alphabet_bytes_with_decode_error() {
        // `DecodeError` must be reachable via this module's public surface —
        // callers propagate it with `?` through their own error enums.
        let err = decode("!!!!").expect_err("non-alphabet bytes must fail");
        // The variant is deliberately not asserted by name — it's the
        // `base64::DecodeError` type that's part of the API contract. The
        // test binds `_err` to `DecodeError` to prove the re-export path.
        let _err: DecodeError = err;
    }

    #[test]
    fn decode_url_safe_rejects_standard_padded_output() {
        // Reverse of `standard_rejects_url_safe_alphabet`: URL_SAFE_NO_PAD
        // must refuse canonical padded blobs. This pins that the engine
        // pair is strictly mirrored — a caller cannot accidentally feed a
        // padded JSON blob into the JWT path and have it silently succeed.
        let padded = encode(b"x"); // "eA=="
        assert!(
            decode_url_safe(&padded).is_err(),
            "url-safe engine must reject standard padding",
        );
    }

    #[test]
    fn url_safe_rejects_plus_and_slash_alphabet() {
        // Bytes that would produce `+` or `/` under §4 are illegal on the
        // URL-safe decoder — the alphabet contract is `-`/`_` only. Pin
        // the rejection so a refactor that swaps engines can't silently
        // decode the wrong alphabet.
        let with_plus = STANDARD.encode([0xff, 0xfb, 0xef, 0xbf]); // contains `+` or `/`
        assert!(
            with_plus.contains('+') || with_plus.contains('/'),
            "fixture must exercise the §4-only characters",
        );
        assert!(
            decode_url_safe(&with_plus).is_err(),
            "url-safe engine must reject §4-alphabet bytes",
        );
    }

    #[test]
    fn encode_accepts_all_as_ref_byteslike_types() {
        // The generic `T: AsRef<[u8]>` bound must work for every call shape
        // actually used across the 17 downstream crates — slices, arrays,
        // owned vectors, and `&str`. This protects against a future refactor
        // that narrows the bound to (for example) just `&[u8]`.
        let slice: &[u8] = b"abc";
        let array: [u8; 3] = *b"abc";
        let owned: Vec<u8> = b"abc".to_vec();
        let string: String = String::from("abc");
        let str_slice: &str = "abc";

        assert_eq!(encode(slice), "YWJj");
        assert_eq!(encode(array), "YWJj");
        assert_eq!(encode(&owned), "YWJj");
        assert_eq!(encode(&string), "YWJj");
        assert_eq!(encode(str_slice), "YWJj");
    }

    #[test]
    fn large_binary_round_trips_across_chunk_boundaries() {
        // 3 KiB of deterministic binary crosses the §4 3-byte group boundary
        // many times and exceeds the typical stack buffer size — a chunking
        // regression in either engine shows up here but not in the tiny
        // happy-path round-trip tests above.
        let raw: Vec<u8> = (0..3072).map(|i| (i % 256) as u8).collect();

        let std_encoded = encode(&raw);
        assert_eq!(
            decode(&std_encoded).expect("standard decode"),
            raw,
            "standard engine must round-trip 3 KiB binary cleanly",
        );

        let url_encoded = encode_url_safe(&raw);
        assert_eq!(
            decode_url_safe(&url_encoded).expect("url-safe decode"),
            raw,
            "url-safe engine must round-trip 3 KiB binary cleanly",
        );
    }

    #[test]
    fn standard_engine_produces_padded_output_with_equals() {
        // Pin the padding contract — callers writing fixtures or snapshot
        // tests rely on `encode` emitting canonical `=` padding. Inputs of
        // length 1 produce `==` padding; length 2 produces `=`; length 3
        // produces none. All three boundary cases exercised.
        assert!(encode(b"x").ends_with("=="), "1-byte input → 2 pad chars");
        assert!(encode(b"xx").ends_with("="), "2-byte input → 1 pad char");
        assert!(!encode(b"xxx").ends_with("="), "3-byte input → no padding");
    }

    #[test]
    fn url_safe_engine_never_emits_padding() {
        // The NO_PAD variant's defining property — verify across the three
        // boundary input lengths. Regression test against accidental engine
        // swap (e.g. someone re-exports URL_SAFE with padding by mistake).
        assert!(!encode_url_safe(b"x").contains('='));
        assert!(!encode_url_safe(b"xx").contains('='));
        assert!(!encode_url_safe(b"xxx").contains('='));
    }
}
