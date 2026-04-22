// Copyright © 2026 Roberto Chiofalo.

//! Input sanitization utilities for untrusted data.
//!
//! Provides functions that make user-controlled strings safe for
//! inclusion in structured log fields and other output formats.

/// Sanitize a string for safe inclusion in structured log fields.
///
/// Replaces control characters (C0/C1, newlines, carriage returns) with
/// the Unicode replacement character (`U+FFFD`). When a CSI introducer
/// is seen — either `ESC [` (C0) or `\u{9B}` (C1) — the full CSI
/// sequence body (parameter/intermediate bytes in `0x20..=0x3F`,
/// terminated by a final byte in `0x40..=0x7E`) is consumed so that
/// parameters like `[31m` do not leak into the log as printable bytes.
/// Printable characters and non-control Unicode are preserved.
///
/// This prevents log-forging attacks where a malicious certificate CN
/// or OU could inject newlines or ANSI escape sequences into log output,
/// and it prevents partial CSI payloads (the tail of an escape sequence)
/// from surviving when only the introducer byte is replaced.
pub fn sanitize_for_log(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // C0 CSI introducer: `ESC [ … final`. Replace ESC and drop
            // the bracket + body so that SGR payloads like `[31m` do not
            // survive as printable characters.
            '\u{1B}' => {
                out.push('\u{FFFD}');
                if chars.peek() == Some(&'[') {
                    let _ = chars.next();
                    consume_csi_body(&mut chars);
                }
            }
            // C1 CSI introducer: single `\u{9B}` byte followed by body.
            '\u{9B}' => {
                out.push('\u{FFFD}');
                consume_csi_body(&mut chars);
            }
            c if c.is_control() => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

/// Consume a CSI sequence body per ECMA-48 §5.4: zero or more parameter
/// and intermediate bytes in `0x20..=0x3F`, followed by a single final
/// byte in `0x40..=0x7E`. Stops on any byte outside those ranges (which
/// also covers EOF and already-replaced bytes).
fn consume_csi_body(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&next) = chars.peek() {
        match next as u32 {
            0x20..=0x3F => {
                let _ = chars.next();
            }
            0x40..=0x7E => {
                let _ = chars.next();
                break;
            }
            _ => break,
        }
    }
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

    #[test]
    fn ansi_csi_fully_consumed() {
        // Red SGR around "RED" — introducer + params + final must all go.
        assert_eq!(
            sanitize_for_log("\x1b[31mRED\x1b[0m"),
            "\u{FFFD}RED\u{FFFD}"
        );
        // Reset-only SGR with no params.
        assert_eq!(sanitize_for_log("\x1b[m"), "\u{FFFD}");
        // Multiple params separated by `;`.
        assert_eq!(sanitize_for_log("\x1b[1;31;40mX"), "\u{FFFD}X");
    }

    #[test]
    fn c1_csi_fully_consumed() {
        // 8-bit single-byte CSI introducer `\u{9B}` followed by SGR body.
        assert_eq!(
            sanitize_for_log("\u{9B}31mRED\u{9B}0m"),
            "\u{FFFD}RED\u{FFFD}"
        );
        // C1 CSI with intermediate + final bytes.
        assert_eq!(sanitize_for_log("\u{9B}?25l"), "\u{FFFD}");
    }

    #[test]
    fn esc_without_bracket_only_replaces_introducer() {
        // `ESC b` is not CSI — only ESC must be replaced, `b` survives.
        assert_eq!(sanitize_for_log("a\x1bbc"), "a\u{FFFD}bc");
        // Trailing ESC at end-of-string must not panic.
        assert_eq!(sanitize_for_log("tail\x1b"), "tail\u{FFFD}");
    }

    #[test]
    fn truncated_csi_does_not_leak_body() {
        // Unterminated CSI at end of string: all remaining param bytes are
        // consumed, so nothing leaks.
        assert_eq!(sanitize_for_log("\x1b[31"), "\u{FFFD}");
        assert_eq!(sanitize_for_log("\u{9B}1;2;3"), "\u{FFFD}");
    }

    #[test]
    fn csi_terminated_by_invalid_byte_stops_cleanly() {
        // A newline breaks the CSI body — newline is still sanitized, and
        // any subsequent characters remain intact.
        assert_eq!(sanitize_for_log("\x1b[31\nafter"), "\u{FFFD}\u{FFFD}after");
    }

    #[test]
    fn log_forging_with_ansi_sequence_cannot_inject_styled_tail() {
        // Attacker-controlled CN: inject bold+red around a fake log line.
        // Before the fix, `[1;31m` would leak through as printable chars;
        // after the fix, the introducer replacement is the only artifact.
        let malicious = "alice\x1b[1;31mFAKE ENTRY\x1b[0m";
        assert_eq!(
            sanitize_for_log(malicious),
            "alice\u{FFFD}FAKE ENTRY\u{FFFD}"
        );
    }
}
