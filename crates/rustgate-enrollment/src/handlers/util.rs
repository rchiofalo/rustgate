// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared utilities for building HTTP responses and parsing query parameters.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};

/// Redact absolute filesystem paths from a client-facing error string.
///
/// Enrollment errors can embed filesystem paths verbatim (an `io::Error`
/// from a failed DB read/rename carries the path, and `serde_json::Error`
/// can carry file context), which would leak deployment topology to any
/// client that can trigger the error (F-149, #1526). This replaces every
/// run that looks like an absolute path — a leading `/` or a Windows
/// `C:\`-style drive prefix followed by non-whitespace path characters —
/// with the literal token `<path>`.
///
/// **Split-surface policy:** apply this only at the client-facing HTTP
/// response boundary. Server-side `tracing` log lines keep the full,
/// unredacted error so operators retain the path for triage.
pub(crate) fn redact_paths(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // A path segment starts at a `/` (Unix) or a `<drive>:\` prefix
        // (Windows). We only treat `/` as a path start when it is at the
        // beginning of a token (preceded by whitespace, a quote, or the
        // string start) so ordinary prose slashes (e.g. "and/or") are not
        // clobbered.
        let prev_is_boundary = i == 0
            || matches!(
                bytes[i - 1],
                b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'(' | b'[' | b'`'
            );
        let unix_path = bytes[i] == b'/' && prev_is_boundary;
        let win_path = prev_is_boundary
            && bytes[i].is_ascii_alphabetic()
            && i + 2 < bytes.len()
            && bytes[i + 1] == b':'
            && (bytes[i + 2] == b'\\' || bytes[i + 2] == b'/');

        if unix_path || win_path {
            out.push_str("<path>");
            // Consume the whole path run: any non-whitespace, non-quote
            // character is treated as part of the path.
            while i < bytes.len()
                && !matches!(
                    bytes[i],
                    b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b')' | b']' | b'`'
                )
            {
                i += 1;
            }
        } else {
            // Push the current UTF-8 character intact. `input` is valid
            // UTF-8, so advance by the full code point width.
            let ch_len = utf8_char_len(bytes[i]);
            let end = (i + ch_len).min(bytes.len());
            out.push_str(&input[i..end]);
            i = end;
        }
    }
    out
}

/// Byte-length of the UTF-8 code point whose leading byte is `b`.
fn utf8_char_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        // Continuation or invalid leading byte — advance one to make
        // progress; `input` being valid UTF-8 means this arm is only hit
        // defensively.
        1
    }
}

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

    /// A Unix absolute path embedded in an error string is replaced by
    /// `<path>` and no `/`-rooted fragment survives (F-149, #1526). This
    /// is the core split-surface contract: the client-facing copy must
    /// never carry deployment topology.
    #[test]
    fn redact_paths_replaces_unix_absolute_path() {
        let msg = "failed to rename /var/lib/rustgate/revocations.tmp";
        let out = redact_paths(msg);
        assert_eq!(out, "failed to rename <path>");
        assert!(
            !out.contains('/'),
            "no path separator may survive redaction: {out}"
        );
    }

    /// The path token that opens a quoted or parenthesised context is
    /// redacted but the surrounding punctuation is preserved, so
    /// `(os error 2)`-style trailers stay intact.
    #[test]
    fn redact_paths_preserves_trailing_punctuation() {
        let msg = "No such file or directory (/etc/rustgate/db.json) (os error 2)";
        let out = redact_paths(msg);
        assert_eq!(out, "No such file or directory (<path>) (os error 2)");
        assert!(!out.contains('/'), "no `/` may remain: {out}");
    }

    /// A Windows drive-letter path is redacted too — the helper must not
    /// be Unix-only, since operators may run on either platform.
    #[test]
    fn redact_paths_replaces_windows_drive_path() {
        let msg = r"cannot open C:\ProgramData\rustgate\db.json for writing";
        let out = redact_paths(msg);
        assert_eq!(out, "cannot open <path> for writing");
        assert!(!out.contains('\\'), "no backslash may remain: {out}");
    }

    /// A prose slash mid-word (e.g. "and/or", "key/value") is NOT a path
    /// and must be left untouched — only token-initial `/` runs are
    /// redacted. Over-redacting benign text would garble error messages.
    #[test]
    fn redact_paths_leaves_prose_slashes_intact() {
        let msg = "expected key/value pair and/or a trailing comma";
        assert_eq!(redact_paths(msg), msg);
    }

    /// Multi-byte UTF-8 in the surrounding text round-trips intact — the
    /// helper walks code points, not bytes, so it must not corrupt
    /// non-ASCII characters while redacting an embedded path.
    #[test]
    fn redact_paths_preserves_multibyte_utf8() {
        let msg = "erreur en écrivant /srv/données/db.json — réessayez";
        let out = redact_paths(msg);
        assert_eq!(out, "erreur en écrivant <path> — réessayez");
        assert!(!out.contains('/'));
    }

    /// A string with no path is returned unchanged.
    #[test]
    fn redact_paths_noop_on_pathless_input() {
        let msg = "serial must be hex characters only";
        assert_eq!(redact_paths(msg), msg);
    }

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
