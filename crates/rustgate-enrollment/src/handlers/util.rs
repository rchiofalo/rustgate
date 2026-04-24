// Copyright © 2026 Roberto Chiofalo.

//! Shared utilities for building HTTP responses and parsing query parameters.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};

/// Build an HTTP response with the given status, content type, and body.
pub(crate) fn build_response(
    status: StatusCode,
    content_type: &str,
    body: Bytes,
) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(status);
    if !content_type.is_empty() {
        builder = builder.header("Content-Type", content_type);
    }
    builder
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("internal error"))))
}

/// Extract a named parameter from a URL query string.
pub(crate) fn extract_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            Some(percent_decode(v))
        } else {
            None
        }
    })
}

/// Decode percent-encoded (URL-encoded) strings.
///
/// Handles `%XX` hex pairs and `+` as space, passing through all other
/// bytes unchanged.
pub(crate) fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let hi = bytes.next().unwrap_or(b'0');
                let lo = bytes.next().unwrap_or(b'0');
                result.push(decode_hex_pair(hi, lo) as char);
            }
            b'+' => result.push(' '),
            _ => result.push(b as char),
        }
    }
    result
}

fn decode_hex_pair(hi: u8, lo: u8) -> u8 {
    (hex_nibble(hi) << 4) | hex_nibble(lo)
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_space() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
    }

    #[test]
    fn percent_decode_plus_as_space() {
        assert_eq!(percent_decode("hello+world"), "hello world");
    }

    #[test]
    fn percent_decode_slash() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
    }

    #[test]
    fn percent_decode_passthrough() {
        assert_eq!(percent_decode("plain-text_123"), "plain-text_123");
    }

    #[test]
    fn extract_param_decodes_encoded_values() {
        let query = "clientUID=alpha%20bravo&name=test%2Fuser";
        assert_eq!(
            extract_param(query, "clientUID"),
            Some("alpha bravo".to_string())
        );
        assert_eq!(extract_param(query, "name"), Some("test/user".to_string()));
    }

    #[test]
    fn extract_param_returns_none_for_missing_key() {
        assert_eq!(extract_param("a=1&b=2", "c"), None);
    }

    /// Pin `build_response`'s end-to-end shape: the status, Content-Type
    /// header, and body bytes must all round-trip exactly as given, with
    /// no transformations applied. `build_response` is called from every
    /// enrollment handler (`handle_tls_config`, `handle_sign_client_v1`,
    /// `handle_sign_client_v2`, `handle_revoke`, CRL + EST endpoints) so
    /// a silent regression — say, defaulting the Content-Type when the
    /// caller passed one, or wrapping the body in additional framing —
    /// would break every API response at once. We assert all three
    /// contract points explicitly.
    #[tokio::test]
    async fn build_response_sets_status_content_type_and_body_exactly() {
        use http_body_util::BodyExt;
        let body_bytes = Bytes::from_static(b"hello-world");
        let resp = build_response(
            StatusCode::IM_A_TEAPOT,
            "application/json",
            body_bytes.clone(),
        );
        assert_eq!(
            resp.status(),
            StatusCode::IM_A_TEAPOT,
            "status code must round-trip verbatim — a regression that remapped status would break 4xx/5xx signalling"
        );
        assert_eq!(
            resp.headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "Content-Type header must carry the caller's value unchanged"
        );
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            collected, body_bytes,
            "body bytes must round-trip — no transformation"
        );
    }

    /// Pin the `content_type.is_empty()` early-skip branch in the
    /// builder. The helper deliberately omits the Content-Type header
    /// when the caller passes `""` so PKCS#12 / binary content-negotiated
    /// responses (where the caller sets Content-Type elsewhere, or wants
    /// hyper's default) do not get a spurious empty header slammed on.
    /// A regression that dropped the guard would produce
    /// `Content-Type: ` in every such response and fail downstream
    /// strict-header-parsing clients.
    #[test]
    fn build_response_with_empty_content_type_omits_header() {
        let resp = build_response(
            StatusCode::OK,
            "",
            Bytes::from_static(b"raw-bytes-no-content-type"),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("Content-Type").is_none(),
            "empty content_type must skip the header — got {:?}",
            resp.headers().get("Content-Type")
        );
    }

    /// Pin that percent-decoding is case-insensitive for hex nibbles —
    /// `%2F`, `%2f`, `%aB`, and `%Ab` must all decode identically. RFC
    /// 3986 §2.1 recommends producers use uppercase, but real-world CoT
    /// clients (ATAK, iTAK, Wintak) emit a mix, so a regression that
    /// narrowed `hex_nibble` to only one case would silently corrupt
    /// every `clientUID=...` query parameter from the mis-cased half of
    /// the fleet. Note: the helper uses `byte as char`, so any byte
    /// ≥ 0x80 becomes a Latin-1 code point and gets UTF-8-encoded to
    /// two bytes when pushed onto the `String` — this is a known
    /// quirk of the implementation and we pin it both to prevent
    /// silent drift and to document it.
    #[test]
    fn percent_decode_hex_nibbles_are_case_insensitive() {
        assert_eq!(
            percent_decode("%2F"),
            percent_decode("%2f"),
            "%2F (uppercase) and %2f (lowercase) must decode identically"
        );
        assert_eq!(percent_decode("%2F"), "/");
        assert_eq!(
            percent_decode("%aB"),
            percent_decode("%Ab"),
            "mixed case %aB and %Ab must decode identically"
        );
        // 0xAB as char = U+00AB, UTF-8-encoded as [0xC2, 0xAB] when
        // pushed onto the result String. Pin both the identity check
        // and the exact byte sequence.
        assert_eq!(percent_decode("%aB").as_bytes(), &[0xC2, 0xAB]);
    }

    /// Pin the `_ => 0` fallthrough in `hex_nibble`: an invalid hex
    /// character decodes as `0`, so `%GG` → `0x00`. This is a
    /// deliberate defensive choice (never panic on user-supplied
    /// input, never allocate a large error-path buffer) but the
    /// semantics matter — a regression that changed the fallback to
    /// a larger value would start producing distorted `clientUID`s on
    /// malformed query strings. The input `%ZZ` is a plausible
    /// copy-paste-from-logs artefact.
    #[test]
    fn percent_decode_invalid_hex_produces_null_byte() {
        // %ZZ → both nibbles fall through to 0 → (0 << 4) | 0 = 0x00
        assert_eq!(
            percent_decode("%ZZ").as_bytes(),
            &[0x00],
            "invalid hex must decode as 0x00 via the hex_nibble fallback"
        );
        // Mixed valid + invalid — only the invalid nibble falls through
        assert_eq!(
            percent_decode("%4Z").as_bytes(),
            &[0x40],
            "%4Z = (4 << 4) | 0 = 0x40 — the valid high nibble is preserved"
        );
    }

    /// Pin `%00 → 0x00`. A NUL byte in decoded output is allowed by
    /// `String::push(char)` (char 0 is valid UTF-8), and the helper
    /// does not filter it — input validation is the caller's job.
    /// This is exercised explicitly so a future "sanitize during
    /// decode" refactor that silently strips NULs fails here, forcing
    /// the refactor to go through deliberate review.
    #[test]
    fn percent_decode_null_byte_passes_through() {
        let out = percent_decode("%00");
        assert_eq!(out.as_bytes(), &[0x00]);
        assert_eq!(out.len(), 1);
    }

    /// Pin the truncated-escape defensive branch: a `%` with no
    /// following byte (`"foo%"`) or only one following byte
    /// (`"foo%A"`) must not panic and must not consume random memory.
    /// `bytes.next().unwrap_or(b'0')` supplies `'0'` for each missing
    /// nibble, so `%` alone decodes as `(0<<4)|0 = 0x00` and `%A`
    /// decodes as `(0xA<<4)|0 = 0xA0`. A regression that replaced
    /// `.unwrap_or(b'0')` with `.unwrap()` would panic on adversarial
    /// `clientUID=foo%` queries and crash the enrollment HTTP worker —
    /// this test pins the no-panic contract AND the specific
    /// fallback values (noting that the `byte as char` push encodes
    /// 0xA0 as the two-byte UTF-8 sequence [0xC2, 0xA0]), so drifting
    /// either one surfaces here.
    #[test]
    fn percent_decode_truncated_escape_uses_zero_fallback() {
        // Bare `%` at end: both nibbles default to '0' → 0x00
        assert_eq!(
            percent_decode("prefix%").as_bytes(),
            b"prefix\x00",
            "trailing bare %% must decode as 0x00, not panic"
        );
        // `%A` — one hex digit, low nibble defaults to '0' → 0xA0 →
        // U+00A0 → UTF-8 encoded as [0xC2, 0xA0]
        assert_eq!(
            percent_decode("%A").as_bytes(),
            &[0xC2, 0xA0],
            "single-digit %A must decode as 0xA0 (UTF-8: 0xC2 0xA0), not panic"
        );
    }

    /// Pin `extract_param` on a malformed query pair with no `=`:
    /// the `split_once('=')?` returns `None`, so the pair is silently
    /// skipped rather than matching on just the key name. The
    /// critical property is that a bare `"clientUID"` token (no
    /// equals, no value) does NOT match a `key = "clientUID"` lookup
    /// and silently return `Some("")` — that would let an
    /// unauthenticated client lie about their UID without actually
    /// transmitting it. The test both exercises the standalone
    /// malformed-query case and the mixed-with-valid case to pin
    /// that one malformed pair does not poison the iterator and
    /// prevent later valid pairs from being found.
    #[test]
    fn extract_param_skips_malformed_pair_without_equals() {
        assert_eq!(
            extract_param("clientUID", "clientUID"),
            None,
            "bare key with no = must not match — security contract"
        );
        assert_eq!(
            extract_param("clientUID&name=alice", "name"),
            Some("alice".to_string()),
            "malformed pair must be skipped, not halt iteration"
        );
    }

    /// Pin `extract_param`'s first-match semantics for duplicate
    /// keys. `find_map` returns on the first `Some(_)` so
    /// `"a=1&a=2"` yields `Some("1")`. The contract is neutral on
    /// whether last-wins or first-wins semantics are "correct" for
    /// HTTP (the spec is silent), but pinning the current behaviour
    /// keeps the semantics stable across refactors so operators
    /// never get surprised by a silent flip — two identical
    /// `clientUID` fields from a buggy client must always resolve
    /// the same way.
    #[test]
    fn extract_param_returns_first_match_on_duplicate_keys() {
        assert_eq!(
            extract_param("clientUID=first&clientUID=second", "clientUID"),
            Some("first".to_string()),
            "duplicate keys must resolve to first occurrence — pin the find_map contract"
        );
    }

    /// Pin that `extract_param` key matching is exact, not a prefix
    /// or substring match — `"clientUID"` must NOT match a lookup
    /// for `"client"`, and `"clientUIDExtended"` must NOT match a
    /// lookup for `"clientUID"`. The implementation uses `k == key`
    /// which is strict string equality; a regression to
    /// `k.starts_with(key)` or `k.contains(key)` would turn every
    /// query parameter into an attacker-controlled prefix and let a
    /// spoofed `clientUIDFake=…` value satisfy a `clientUID` probe.
    #[test]
    fn extract_param_requires_exact_key_match_not_prefix_or_substring() {
        // Lookup for "client" must not match "clientUID=…"
        assert_eq!(
            extract_param("clientUID=xyz", "client"),
            None,
            "prefix of real key must not match"
        );
        // Lookup for "clientUID" must not match "clientUIDExtended=…"
        assert_eq!(
            extract_param("clientUIDExtended=evil", "clientUID"),
            None,
            "extended-name key must not satisfy exact lookup"
        );
        // Lookup for "UID" must not match "clientUID=…"
        assert_eq!(
            extract_param("clientUID=xyz", "UID"),
            None,
            "suffix of real key must not match"
        );
    }

    /// Pin the empty-query and empty-key defensive edges:
    /// - `""` yields a single empty pair, which fails `split_once('=')`
    ///   and is skipped → `None`.
    /// - `"=value"` yields key=`""`, value=`"value"` — a lookup for
    ///   `""` matches and returns `Some("value")`. This is an edge
    ///   that could surprise callers but pinning it keeps the
    ///   behaviour stable.
    #[test]
    fn extract_param_handles_empty_query_and_empty_key() {
        assert_eq!(
            extract_param("", "anything"),
            None,
            "empty query must return None for any key"
        );
        assert_eq!(
            extract_param("=orphan", ""),
            Some("orphan".to_string()),
            "empty key matches an orphan `=value` pair — pin the current edge"
        );
    }
}
