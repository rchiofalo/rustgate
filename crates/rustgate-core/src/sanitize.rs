// Copyright © 2026 Roberto Chiofalo.

//! Input sanitization utilities for untrusted data.
//!
//! Provides functions that make user-controlled strings safe for
//! inclusion in structured log fields and other output formats.

/// Sanitize a string for safe inclusion in structured log fields.
///
/// Replaces control characters (including newlines, carriage returns,
/// and other C0/C1 codes) with the Unicode replacement character
/// (`U+FFFD`). Printable characters and non-control Unicode are
/// preserved unchanged.
///
/// This prevents log-forging attacks where a malicious certificate CN
/// or OU could inject newlines or ANSI escape sequences into log output.
pub fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || c == '\n' || c == '\r' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_strings_unchanged() {
        assert_eq!(sanitize_for_log("alice"), "alice");
        assert_eq!(sanitize_for_log("Bob Smith"), "Bob Smith");
        assert_eq!(sanitize_for_log("org-unit-123"), "org-unit-123");
    }

    #[test]
    fn newlines_replaced() {
        assert_eq!(sanitize_for_log("line1\nline2"), "line1\u{FFFD}line2");
        assert_eq!(
            sanitize_for_log("line1\r\nline2"),
            "line1\u{FFFD}\u{FFFD}line2"
        );
    }

    #[test]
    fn control_characters_replaced() {
        assert_eq!(sanitize_for_log("a\x00b"), "a\u{FFFD}b");
        assert_eq!(sanitize_for_log("a\x01b"), "a\u{FFFD}b");
        assert_eq!(sanitize_for_log("a\x1Bb"), "a\u{FFFD}b"); // ESC
        assert_eq!(sanitize_for_log("a\tb"), "a\u{FFFD}b"); // TAB
    }

    #[test]
    fn unicode_preserved() {
        assert_eq!(sanitize_for_log("caf\u{00e9}"), "caf\u{00e9}");
        assert_eq!(sanitize_for_log("\u{1F600}"), "\u{1F600}");
        assert_eq!(sanitize_for_log("\u{4e16}\u{754c}"), "\u{4e16}\u{754c}");
    }

    #[test]
    fn empty_string_unchanged() {
        assert_eq!(sanitize_for_log(""), "");
    }
}
