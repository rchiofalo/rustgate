// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! JSON response helpers and URL decoding utilities.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::Serialize;

use super::types::{ErrorResponse, SuccessResponse};

/// Build a 500 Internal Server Error response with a plain-text body.
pub(crate) fn internal_error_response() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from("internal server error")));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

/// Build a 200 OK JSON response wrapping `data` in a `{"data": ...}` envelope.
pub(crate) fn json_ok<T: Serialize>(data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&SuccessResponse { data }).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Build a 201 Created JSON response wrapping `data` in a `{"data": ...}` envelope.
pub(crate) fn json_created<T: Serialize>(data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&SuccessResponse { data }).unwrap_or_default();
    Response::builder()
        .status(StatusCode::CREATED)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Build a JSON error response with the given status code and message.
pub(crate) fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&ErrorResponse {
        error: message.to_string(),
    })
    .unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Simple percent-decoding for URL path segments.
pub(crate) fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let decoded = hex_byte(hi, lo);
            result.push(decoded as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

pub(crate) fn hex_byte(hi: u8, lo: u8) -> u8 {
    (hex_nibble(hi) << 4) | hex_nibble(lo)
}

pub(crate) fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    //! Unit tests for the federation REST API response builders and the
    //! URL-segment percent-decoder.
    //!
    //! These helpers produce the JSON envelopes every
    //! `rustgate_federation::api::handlers::*` endpoint returns, so
    //! any drift in the status code, content-type, or envelope shape
    //! is an API contract change that must be deliberate. The tests
    //! pin:
    //!
    //! * the exact HTTP status code on each builder (200 / 201 / 500 /
    //!   caller-supplied for `json_error`) — the management API has no
    //!   richer error taxonomy than status-code-plus-`{"error": …}`,
    //!   so a regression that dropped the status field or swapped 201
    //!   for 200 would silently redirect clients that rely on the code
    //!   to distinguish "already existed" from "newly created";
    //! * the `content-type: application/json` header on every JSON
    //!   builder — absent it, browsers and middleware treat the body
    //!   as `text/plain` and stop pretty-printing, and content-sniffing
    //!   security rules (`X-Content-Type-Options: nosniff`) start
    //!   refusing the response;
    //! * the canonical envelope keys (`"data"` for success, `"error"`
    //!   for failure) — downstream clients parse these keys verbatim,
    //!   so switching to `"result"` or `"message"` would break every
    //!   caller in one shot;
    //! * the `percent_decode` / `hex_byte` / `hex_nibble` trio — the
    //!   decoder is a hand-rolled implementation (not `percent-encoding`
    //!   crate) because it's used only on short path segments; pinning
    //!   the character map here catches a regression that flipped
    //!   upper-vs-lower hex handling, dropped the `+` → space mapping,
    //!   or introduced a panic on malformed `%` escapes (the existing
    //!   code silently falls back to `0` on bad nibbles — that's a
    //!   contract operators rely on when they call the API with
    //!   literally-encoded ids).
    //!
    //! The helper functions are `pub(crate)`, so these tests live
    //! inline rather than in `tests/` to keep the visibility boundary
    //! tight. The enclosing `api` module is already feature-gated on
    //! `api`, so no extra `#[cfg(feature = "api")]` is needed here.

    use http_body_util::BodyExt;
    use serde_json::Value;

    use super::*;

    async fn body_bytes(resp: Response<Full<Bytes>>) -> Bytes {
        resp.into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes()
    }

    fn status_of(resp: &Response<Full<Bytes>>) -> StatusCode {
        resp.status()
    }

    fn content_type_of(resp: &Response<Full<Bytes>>) -> Option<String> {
        resp.headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    // ------------------------------------------------------------------
    // internal_error_response — 500 plain-text fallback.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn internal_error_response_is_500_with_plain_text_body() {
        // This is the fallback every other builder drops to when the
        // `Response::builder().body(...)` call somehow fails — pin the
        // status + body so a regression that "fixed" it to return a
        // JSON body with status 200 would fail here. A JSON body with
        // `{"error":"internal server error"}` would be a *nicer*
        // shape, but it would also stop distinguishing builder-path
        // failures from actual server-logic errors that already
        // produce that envelope via `json_error`.
        let resp = internal_error_response();
        assert_eq!(status_of(&resp), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_bytes(resp).await;
        assert_eq!(
            body.as_ref(),
            b"internal server error",
            "fallback body must remain plain text so it's distinguishable from json_error outputs"
        );
    }

    // ------------------------------------------------------------------
    // json_ok — 200 with `{"data": ...}` envelope.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn json_ok_returns_200_with_data_envelope() {
        let resp = json_ok(&serde_json::json!({"hello": "world"}));
        assert_eq!(status_of(&resp), StatusCode::OK);
        assert_eq!(
            content_type_of(&resp).as_deref(),
            Some("application/json"),
            "json_ok must set content-type so middleware doesn't sniff"
        );
        let body = body_bytes(resp).await;
        let parsed: Value =
            serde_json::from_slice(&body).expect("json_ok must emit valid UTF-8 JSON");
        // The envelope key is the API contract — downstream callers
        // parse `.data` directly. A refactor that flattened the
        // envelope would break every client without warning.
        assert_eq!(parsed["data"]["hello"], "world");
    }

    #[tokio::test]
    async fn json_ok_serializes_empty_slice_as_empty_array_in_data() {
        // `handle_list_federates` returns `&Vec<_>` — an empty list is
        // a valid, common result (no federates configured yet). The
        // envelope must still be `{"data": []}`, not omit the key.
        let empty: Vec<u32> = Vec::new();
        let resp = json_ok(&empty);
        assert_eq!(status_of(&resp), StatusCode::OK);
        let parsed: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert!(
            parsed["data"].is_array() && parsed["data"].as_array().unwrap().is_empty(),
            "empty list must serialise as empty array under .data, got {parsed}"
        );
    }

    // ------------------------------------------------------------------
    // json_created — 201 with the same envelope as json_ok.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn json_created_returns_201_with_data_envelope() {
        // 201 Created vs 200 OK is the signal clients use to tell
        // "newly created" from "already existed and was returned as-is."
        // Pin the 201 so a mass rename from `json_created` to `json_ok`
        // (or a refactor that collapsed them) would fail here.
        let resp = json_created(&serde_json::json!({"id": "new"}));
        assert_eq!(status_of(&resp), StatusCode::CREATED);
        assert_eq!(content_type_of(&resp).as_deref(), Some("application/json"));
        let parsed: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(parsed["data"]["id"], "new");
    }

    #[tokio::test]
    async fn json_created_uses_same_envelope_key_as_json_ok() {
        // Both success envelopes share the `{"data": …}` shape — the
        // only thing that differs is the status code. Pin this so
        // json_created can never drift to `{"created": …}` or similar
        // without a conscious schema change.
        let ok = json_ok(&"a");
        let created = json_created(&"a");
        let ok_parsed: Value = serde_json::from_slice(&body_bytes(ok).await).unwrap();
        let created_parsed: Value = serde_json::from_slice(&body_bytes(created).await).unwrap();
        assert_eq!(ok_parsed, created_parsed);
    }

    // ------------------------------------------------------------------
    // json_error — caller-supplied status with `{"error": ...}` envelope.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn json_error_preserves_caller_supplied_status() {
        // `handle_*` builders pass four different statuses through
        // json_error in practice: 400 (bad JSON), 404 (not found), 409
        // (conflict), 500 (store lock poisoned). Pin three of them so
        // a regression that hard-coded any single status would fail.
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let resp = json_error(status, "boom");
            assert_eq!(
                status_of(&resp),
                status,
                "json_error must pass {status} through unchanged"
            );
        }
    }

    #[tokio::test]
    async fn json_error_emits_error_envelope_with_message() {
        let resp = json_error(StatusCode::BAD_REQUEST, "invalid JSON: missing id");
        assert_eq!(
            content_type_of(&resp).as_deref(),
            Some("application/json"),
            "error responses must still be JSON so clients can parse uniformly"
        );
        let parsed: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(parsed["error"], "invalid JSON: missing id");
        // The success envelope key must NOT appear in an error body —
        // a regression that used `{"data": "...", "error": "..."}`
        // would confuse every client's branch logic.
        assert!(
            parsed.get("data").is_none(),
            "error envelope must not carry a data key, got {parsed}"
        );
    }

    #[tokio::test]
    async fn json_error_preserves_special_characters_in_message() {
        // Error messages often include user-supplied strings (e.g.
        // "unknown field `bogus`" from serde). The JSON encoder must
        // escape quotes / backslashes properly — pin a round-trip so
        // a regression that swapped to hand-rolled JSON formatting
        // (and forgot escaping) would fail with a parse error here.
        let resp = json_error(StatusCode::BAD_REQUEST, r#"bad quote: ""  and \ too"#);
        let parsed: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(parsed["error"], r#"bad quote: ""  and \ too"#);
    }

    // ------------------------------------------------------------------
    // percent_decode / hex_byte / hex_nibble — hand-rolled URL decoder.
    // ------------------------------------------------------------------

    #[test]
    fn percent_decode_leaves_unreserved_characters_untouched() {
        // Alphanumerics, dash, dot, underscore, tilde — the RFC 3986
        // unreserved set. The decoder must not mangle them.
        assert_eq!(percent_decode("abc-123.xyz_~"), "abc-123.xyz_~");
    }

    #[test]
    fn percent_decode_plus_becomes_space() {
        // `application/x-www-form-urlencoded` encodes space as `+`.
        // The federation API accepts both `%20` and `+` in path
        // segments (operators copy-paste URLs from dashboards that
        // encode spaces either way). Pin `+` handling so a refactor
        // that narrowed the decoder to RFC 3986 (which uses only
        // `%20`) doesn't silently break those operators.
        assert_eq!(percent_decode("a+b+c"), "a b c");
    }

    #[test]
    fn percent_decode_decodes_valid_percent_escape() {
        // %20 → ' ', %2F → '/', %3A → ':'. Case-insensitive on the
        // hex digits because some clients upper-case them.
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("host%3A9001"), "host:9001");
    }

    #[test]
    fn percent_decode_uppercase_and_lowercase_hex_agree() {
        // Operators paste URLs with either case; the decoder must
        // produce identical bytes for either. This catches a
        // regression that restricted `hex_nibble` to only lowercase.
        assert_eq!(percent_decode("%2f"), percent_decode("%2F"));
        assert_eq!(percent_decode("%ab"), percent_decode("%AB"));
    }

    #[test]
    fn percent_decode_handles_truncated_percent_escape_without_panic() {
        // The current implementation falls back to `0` for missing
        // hex nibbles via `unwrap_or(b'0')`. That's the contract —
        // an ill-formed tail like `"abc%2"` yields `"abc "` (0x20)
        // rather than panicking. Any refactor to proper error
        // handling should be a deliberate choice; pin the lenient
        // behaviour so it's not changed silently.
        // Truncated at the end: `%2` — only one nibble available.
        let out = percent_decode("abc%2");
        // `%` + `2` + (nothing → b'0') → 0x20 → space
        assert_eq!(
            out, "abc ",
            "truncated escape must decode via the 0-nibble fallback, got {out:?}"
        );
    }

    #[test]
    fn percent_decode_handles_non_hex_after_percent_via_zero_fallback() {
        // `%GG` is not valid hex. `hex_nibble` returns 0 for any
        // non-hex byte, so `%GG` → 0x00 → NUL. Pin this so a refactor
        // to stricter behaviour is an explicit decision.
        let out = percent_decode("%GG");
        assert_eq!(out.as_bytes(), &[0x00]);
    }

    #[test]
    fn hex_nibble_handles_every_digit_letter_case() {
        // Exhaustive table: every valid hex character must map to
        // its numeric value, upper and lower case, plus 0 for any
        // byte outside the hex ranges.
        for (b, expected) in [
            (b'0', 0),
            (b'5', 5),
            (b'9', 9),
            (b'a', 10),
            (b'c', 12),
            (b'f', 15),
            (b'A', 10),
            (b'C', 12),
            (b'F', 15),
        ] {
            assert_eq!(
                hex_nibble(b),
                expected,
                "hex_nibble({b:#x}) expected {expected}"
            );
        }

        // Out-of-range bytes all map to 0 (the silent-fallback
        // contract percent_decode relies on).
        for b in [b'g', b'G', b'@', b'/', b' ', 0x00_u8, 0xff_u8] {
            assert_eq!(hex_nibble(b), 0, "non-hex byte {b:#x} must map to 0");
        }
    }

    #[test]
    fn hex_byte_combines_nibbles_in_big_endian_order() {
        // `%2A` → hi=0x02, lo=0x0a → 0x2a. Pin the high-nibble-first
        // ordering so a refactor that accidentally flipped to
        // little-endian (`(lo << 4) | hi`) would fail here and then
        // surface in percent_decode round-trips.
        assert_eq!(hex_byte(b'2', b'A'), 0x2A);
        assert_eq!(hex_byte(b'0', b'0'), 0x00);
        assert_eq!(hex_byte(b'F', b'F'), 0xFF);
        assert_eq!(hex_byte(b'7', b'f'), 0x7F);
    }
}
