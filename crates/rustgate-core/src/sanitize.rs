// Copyright © 2026 Roberto Chiofalo.

//! Input sanitization utilities for untrusted data.
//!
//! Provides functions that make user-controlled strings safe for
//! inclusion in structured log fields and other output formats.
//!
//! # Sanitization Helper Matrix
//!
//! Several sanitization helpers exist across the workspace. They share a
//! common design pressure — *make untrusted input safe for one specific
//! destination* — but each destination imposes its own constraints, so
//! the helpers cannot share a single implementation core. This matrix
//! documents the divergences explicitly so a future change to one
//! helper triggers a deliberate decision rather than silent drift.
//!
//! | Helper | Crate | Destination | Control chars | Non-ASCII | NFC | Length cap | Returns | Trust model |
//! |---|---|---|---|---|---|---|---|---|
//! | [`sanitize_for_log`] | `rustgate-core` | log field | replace with `U+FFFD` (incl. CSI body) | preserved as-is | no | none | `String` | untrusted |
//! | `sanitize_nats_token` | `rustgate-nats` | NATS subject token | strip (drop) | strip | yes | 256 bytes | `Option<Cow<str>>` | untrusted |
//! | `sanitize_filename` | `rustgate-federation` | filesystem path component | replace with `_` | replace with `_` | no | none | `String` | untrusted |
//! | `validate_publish_topic` / `validate_subscribe_filter` | `rustgate-mqtt` | MQTT topic / topic filter | reject (error) | reject (error) | no | 255 bytes | `Result<(), MqttError>` | untrusted |
//!
//! ## Why the helpers diverge
//!
//! - **`sanitize_for_log`** replaces with `U+FFFD` rather than stripping
//!   so the position of every removed byte is still visible in logs —
//!   important for forensic correlation. It preserves arbitrary
//!   non-control Unicode because legitimate certificate CNs may contain
//!   non-Latin scripts. It does **not** NFC-normalize because the log
//!   line is consumed by humans and pipelines that handle Unicode-
//!   equivalent forms identically; normalizing would only mask that the
//!   raw bytes on the wire were unusual.
//! - **`sanitize_nats_token`** must produce a string that satisfies NATS
//!   subject syntax (printable ASCII, no `.`, no `*`, no `>`). It
//!   *strips* rather than replaces because every output character must
//!   be a valid token character — `U+FFFD` is non-ASCII and NATS would
//!   reject it. NFC normalization closes a Unicode-equivalence spoofing
//!   gap (see `shared-infrastructure.md`'s "Unicode Normalization
//!   Defense") before ASCII filtering, so NFC variants of a
//!   confusable character collapse to the same post-strip output.
//! - **`sanitize_filename`** must produce a string that the OS will
//!   accept as a path component, but the rules vary across filesystems.
//!   The conservative choice is `[A-Za-z0-9._-]` and replace everything
//!   else with `_`. It does not NFC-normalize because the input has
//!   already been audited (it comes from a parsed certificate CN, not
//!   a free-form network field).
//! - **MQTT topic validators** reject rather than transform because MQTT
//!   topic syntax is part of the wire protocol — if a client publishes
//!   with an invalid topic, the right answer is `MALFORMED_PACKET`, not
//!   silent munging of the topic. The validator is a *validator*, not a
//!   *sanitizer*; it appears here only so callers know which family it
//!   belongs to.
//!
//! ## Untrusted vs operator-controlled input
//!
//! All four helpers operate on **untrusted** input — values that came in
//! from a network peer (a TLS certificate CN, a publish topic, a NATS
//! group hint) and must be neutralized before being passed to a
//! destination that interprets the bytes (a log line, a NATS subject,
//! a filesystem path, the MQTT wire codec). For operator-controlled
//! values (CLI flags, config fields parsed from the operator's TOML),
//! validation at parse time is preferred and these runtime sanitizers
//! should not appear on the hot path.
//!
//! ## Byte-stability guarantee
//!
//! Each helper is pinned by `*_byte_stable_for_known_inputs` regression
//! tests in its home crate so that any change to the output for a
//! captured input fails CI. This guarantee means downstream pipelines
//! (log parsers, NATS subscribers, file scanners) can rely on the
//! output bytes being stable across rustgate releases.

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

    // -- defensive-invariant coverage -----------------------------------

    #[test]
    fn all_c0_control_chars_replaced_including_del() {
        // Sweep every C0 control (0x00..=0x1F) AND 0x7F (DEL). ESC (0x1B)
        // is the CSI introducer — when not followed by `[`, the docstring
        // says ESC alone is replaced — so ESC is still in the expected
        // output. A regression that carved an exception for e.g. `\t`
        // (tab, 0x09) or `\x7F` (DEL) would start passing raw control
        // bytes through into log fields and enable a class of forging
        // attacks the function exists to prevent.
        for byte in 0x00u8..=0x1F {
            let c = char::from(byte);
            let input = format!("x{c}y");
            let output = sanitize_for_log(&input);
            assert_eq!(
                output, "x\u{FFFD}y",
                "C0 control byte {byte:#04x} must be replaced with U+FFFD"
            );
        }
        // DEL (0x7F) is also Cc category; must be treated the same way.
        let input = "a\u{007F}b";
        assert_eq!(
            sanitize_for_log(input),
            "a\u{FFFD}b",
            "DEL must be replaced"
        );
    }

    #[test]
    fn all_c1_control_chars_except_0x9b_csi_introducer_are_replaced() {
        // Sweep C1 control range 0x80..=0x9F. 0x9B is the CSI introducer
        // and handled separately (introducer replaced + body consumed);
        // every other byte in the range must be replaced.
        for code in 0x80u32..=0x9F {
            if code == 0x9B {
                continue;
            }
            let c = char::from_u32(code).expect("C1 code points are valid chars");
            let input = format!("x{c}y");
            let output = sanitize_for_log(&input);
            assert_eq!(
                output, "x\u{FFFD}y",
                "C1 control codepoint U+{code:04X} must be replaced with U+FFFD"
            );
        }
    }

    #[test]
    fn csi_consumed_when_only_intermediate_bytes_present_and_no_final_at_eof() {
        // Truncated CSI sequence with parameter + intermediate bytes but
        // no final byte at EOF. Per ECMA-48 §5.4, parameter bytes are
        // 0x30-0x3F and intermediate bytes 0x20-0x2F; both ranges are in
        // our consumed 0x20..=0x3F window. A regression that required a
        // final byte before consuming would let `12;34` leak into the log
        // stream as printable characters.
        assert_eq!(sanitize_for_log("\x1b[12;34"), "\u{FFFD}");
        // Same pattern with C1 introducer.
        assert_eq!(sanitize_for_log("\u{9B}12;34"), "\u{FFFD}");
        // Intermediate-only body (no parameter bytes, just 0x20-0x2F).
        assert_eq!(sanitize_for_log("\x1b[!\"#$"), "\u{FFFD}");
    }

    #[test]
    fn csi_with_final_byte_immediately_after_bracket_with_no_parameters() {
        // `\x1B[Xhello` — `X` is 0x58, in 0x40..=0x7E (final byte range),
        // so consumed immediately; the trailing "hello" survives. Pins the
        // zero-parameter path of `consume_csi_body` — a regression that
        // required at least one parameter byte before accepting a final
        // would loop forever or fail to consume the final here.
        assert_eq!(sanitize_for_log("\x1b[Xhello"), "\u{FFFD}hello");
        assert_eq!(sanitize_for_log("\u{9B}Xworld"), "\u{FFFD}world");
        // Final byte at end of input — no trailing text.
        assert_eq!(sanitize_for_log("\x1b[m"), "\u{FFFD}");
    }

    #[test]
    fn consecutive_esc_introducers_each_produce_independent_replacements() {
        // `\x1B\x1B\x1B` — three consecutive ESC characters. Each is its
        // own introducer; none is followed by `[`, so each contributes
        // exactly one U+FFFD and nothing is consumed beyond the introducer
        // itself. A regression that treated the first ESC as opening a
        // CSI body would silently swallow the next two ESCs.
        assert_eq!(sanitize_for_log("\x1b\x1b\x1b"), "\u{FFFD}\u{FFFD}\u{FFFD}");
        // Mixed: ESC then proper CSI then ESC alone.
        assert_eq!(
            sanitize_for_log("\x1b\x1b[31mred\x1b"),
            "\u{FFFD}\u{FFFD}red\u{FFFD}"
        );
    }

    #[test]
    fn lone_c1_csi_introducer_at_eof_produces_exactly_one_replacement() {
        // `\u{9B}` alone with nothing after — the C1 CSI path enters
        // `consume_csi_body` which finds EOF and breaks cleanly. A
        // regression that assumed the body always had at least one byte
        // (e.g. via unchecked `chars.next().unwrap()`) would panic here.
        assert_eq!(sanitize_for_log("\u{9B}"), "\u{FFFD}");
        assert_eq!(sanitize_for_log("prefix\u{9B}"), "prefix\u{FFFD}");
    }

    #[test]
    fn unicode_format_and_bidi_override_characters_pass_through_by_design() {
        // `char::is_control()` covers only General_Category = Cc (C0 +
        // C1). Format characters (Cf) like U+202E RIGHT-TO-LEFT OVERRIDE
        // and U+FEFF BYTE ORDER MARK are intentionally NOT replaced —
        // they are legal in UTF-8 identifiers and may legitimately appear
        // in CNs for non-Latin scripts. Pin this as the documented
        // scope-limit so a future "stronger sanitizer" refactor is a
        // conscious decision, not an accident.
        assert_eq!(sanitize_for_log("a\u{202E}b"), "a\u{202E}b");
        assert_eq!(sanitize_for_log("\u{FEFF}start"), "\u{FEFF}start");
        assert_eq!(sanitize_for_log("\u{200E}\u{200F}"), "\u{200E}\u{200F}");
    }

    #[test]
    fn sanitize_is_idempotent_on_arbitrary_input() {
        // U+FFFD is not a control character and not a CSI introducer, so
        // feeding `sanitize_for_log`'s output back through it must be a
        // no-op. Operational importance: log pipelines that re-sanitize
        // at a downstream stage must not mutate an already-clean string
        // (e.g. by doubling the replacement marker).
        let corpus = [
            "plain text",
            "line1\nline2",
            "\x1b[31mRED\x1b[0m",
            "\u{9B}31mX",
            "\x00\x1b\x7F",
            "",
            "caf\u{00e9} \u{1F600}",
        ];
        for s in corpus {
            let once = sanitize_for_log(s);
            let twice = sanitize_for_log(&once);
            assert_eq!(once, twice, "sanitize must be idempotent for input {s:?}");
        }
    }

    #[test]
    fn log_forging_with_newline_and_csi_is_fully_neutralized() {
        // Worst-case attacker-controlled CN: attempt to forge a complete
        // log entry by injecting a newline followed by a styled-and-
        // fabricated "authorized=true" line. A regression that left
        // either the newline or the CSI introducer in place would
        // re-enable the injection.
        let malicious = "user\n\x1b[32m2024-01-01T00:00:00Z authorized=true\x1b[0m";
        let out = sanitize_for_log(malicious);
        assert_eq!(
            out,
            "user\u{FFFD}\u{FFFD}2024-01-01T00:00:00Z authorized=true\u{FFFD}"
        );
        // Defence-in-depth: the raw control bytes and CSI introducers must
        // be absent from the output.
        assert!(!out.contains('\n'), "newline leaked: {out:?}");
        assert!(!out.contains('\x1b'), "ESC leaked: {out:?}");
    }

    #[test]
    fn sanitize_for_log_byte_stable_for_known_inputs() {
        // Pins the exact output bytes for a corpus of inputs spanning
        // every documented behavior class. A regression on any line of
        // this table indicates a wire-visible behavior change — the
        // matrix in the module docs claims byte-stable output, and the
        // log pipelines downstream depend on it.
        let cases: &[(&str, &str)] = &[
            ("plain", "plain"),
            ("alice\nbob", "alice\u{FFFD}bob"),
            ("a\tb", "a\u{FFFD}b"),
            ("\x1b[31mRED\x1b[0m", "\u{FFFD}RED\u{FFFD}"),
            ("\u{9B}1;31m", "\u{FFFD}"),
            ("caf\u{00e9}", "caf\u{00e9}"),
            ("caf\u{0065}\u{0301}", "caf\u{0065}\u{0301}"),
            ("\u{1F600}smile", "\u{1F600}smile"),
            ("a.b.c", "a.b.c"),
            ("group*", "group*"),
            ("group>tail", "group>tail"),
            ("a/b", "a/b"),
            ("\u{202E}rtl", "\u{202E}rtl"),
            ("", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_for_log(input),
                *expected,
                "byte-stable output regression for input {input:?}"
            );
        }
    }

    #[test]
    fn matrix_invariant_sanitize_for_log_does_not_nfc_normalize() {
        // Pinned axis from the module-doc matrix: `sanitize_for_log` does
        // NOT NFC-normalize. NFD "café" (e + combining acute) must come
        // out byte-identical. If a future change accidentally adds NFC
        // normalization here, the NATS helper's "we do NFC, the log
        // helper does not" promise in the matrix becomes false.
        let nfd = "caf\u{0065}\u{0301}";
        let nfc = "caf\u{00e9}";
        assert_ne!(nfd, nfc, "NFD and NFC of 'café' must differ at byte level");
        assert_eq!(
            sanitize_for_log(nfd),
            nfd,
            "sanitize_for_log must preserve NFD bytes"
        );
        assert_eq!(
            sanitize_for_log(nfc),
            nfc,
            "sanitize_for_log must preserve NFC bytes"
        );
    }

    #[test]
    fn matrix_invariant_sanitize_for_log_preserves_non_ascii() {
        // Pinned axis from the module-doc matrix: `sanitize_for_log`
        // preserves non-ASCII (in contrast to `sanitize_nats_token` which
        // strips it). A regression would re-introduce data loss for
        // non-Latin CNs.
        assert_eq!(sanitize_for_log("\u{4e16}\u{754c}"), "\u{4e16}\u{754c}");
        assert_eq!(sanitize_for_log("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn sanitized_output_contains_no_raw_control_introducers() {
        // Cross-cutting invariant: whatever the input, the output must
        // never contain `\x1B` (C0 CSI introducer), `\u{9B}` (C1 CSI
        // introducer), `\n`, `\r`, `\0`, or `\t`. This is a stronger
        // black-box contract than per-variant checks — a regression that
        // added a new bypass path (e.g. dropping the `is_control()` arm)
        // would fail here across the whole corpus at once.
        let corpus = [
            "\x1b[31mred\x1b[0m",
            "\u{9B}1;2;3m",
            "line1\r\nline2",
            "bell\x07here",
            "vt\x0bff\x0c",
            "control\x00null",
            "tab\there",
            "\x1b\x1b\x1b\x7F",
        ];
        for input in corpus {
            let out = sanitize_for_log(input);
            for forbidden in &['\x1B', '\u{9B}', '\n', '\r', '\0', '\t', '\x07'] {
                assert!(
                    !out.contains(*forbidden),
                    "forbidden char {forbidden:?} leaked through input {input:?} → {out:?}"
                );
            }
        }
    }
}
