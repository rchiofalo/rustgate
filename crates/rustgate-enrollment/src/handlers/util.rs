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
}
