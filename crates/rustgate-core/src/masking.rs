// Copyright © 2026 Roberto Chiofalo.

//! Sensitive data masking utilities for log output.
//!
//! Provides functions to partially redact certificate serials, IP addresses,
//! and credentials before they appear in structured log fields. This prevents
//! full sensitive values from persisting in log storage while retaining enough
//! information for correlation and debugging.

/// Mask a certificate serial number, showing only the first 4 and last 4 characters.
///
/// Returns the original string unchanged if it is 10 characters or fewer
/// (not enough to meaningfully redact). For longer serials the middle is
/// replaced with `"..."`.
///
/// # Examples
///
/// ```
/// # use rustgate_core::masking::mask_cert_serial;
/// assert_eq!(mask_cert_serial("A1B2C3D4E5F6Y3Z4"), "A1B2...Y3Z4");
/// assert_eq!(mask_cert_serial("SHORT"), "SHORT");
/// ```
pub fn mask_cert_serial(serial: &str) -> String {
    if serial.len() <= 10 {
        return serial.to_string();
    }
    let prefix = &serial[..4];
    let suffix = &serial[serial.len() - 4..];
    format!("{prefix}...{suffix}")
}

/// Mask the last octet (or group) of an IP address.
///
/// For IPv4, replaces the last octet with `"***"`.
/// For IPv6 (contains `":"`), replaces the last group with `"***"`.
/// If the address includes a port (e.g. `"192.168.1.5:8080"`), the port is
/// preserved and only the address portion is masked.
///
/// # Examples
///
/// ```
/// # use rustgate_core::masking::mask_ip;
/// assert_eq!(mask_ip("192.168.1.5"), "192.168.1.***");
/// assert_eq!(mask_ip("10.0.0.1:8080"), "10.0.0.***:8080");
/// ```
pub fn mask_ip(ip: &str) -> String {
    // Handle IPv6 addresses (with optional bracket-port like [::1]:443)
    if ip.contains(':') && !ip.starts_with('[') && ip.matches(':').count() > 1 {
        // Plain IPv6 — mask last group
        if let Some(pos) = ip.rfind(':') {
            return format!("{}:***", &ip[..pos]);
        }
    }

    // Handle bracketed IPv6 with port, e.g. [::1]:443
    if ip.starts_with('[') {
        if let Some(bracket_end) = ip.find(']') {
            let addr = &ip[1..bracket_end];
            let after_bracket = &ip[bracket_end + 1..]; // ":443" or ""
            if let Some(pos) = addr.rfind(':') {
                return format!("[{}:***]{after_bracket}", &addr[..pos]);
            }
        }
        return ip.to_string();
    }

    // IPv4 — optionally with port (single colon)
    // Separate address and port first
    let (addr, port_suffix) = if let Some(colon) = ip.rfind(':') {
        // Only treat as port if the part before the colon looks like an IPv4 address
        let before = &ip[..colon];
        if before.contains('.') {
            (before, Some(&ip[colon..]))
        } else {
            (ip, None)
        }
    } else {
        (ip, None)
    };

    if let Some(dot) = addr.rfind('.') {
        let masked_addr = format!("{}.***", &addr[..dot]);
        match port_suffix {
            Some(port) => format!("{masked_addr}{port}"),
            None => masked_addr,
        }
    } else {
        ip.to_string()
    }
}

/// Hash a client CN to a stable opaque token for PII-safe logging.
///
/// Uses SHA-256 truncated to the first 12 hex chars (48 bits). This is a
/// correlation token, not a cryptographic identifier — the truncation
/// collision risk is acceptable for an audit trail, and the token remains
/// stable so operators can follow a single identity across log events
/// without the raw CN ever appearing in log storage.
///
/// Use this for the access-log target and any other structured log field
/// that would otherwise carry a raw client identity.
///
/// # Examples
///
/// ```
/// # use rustgate_core::masking::hash_cn;
/// let h = hash_cn("alice");
/// assert_eq!(h.len(), 12);
/// assert_eq!(hash_cn("alice"), h);        // stable across calls
/// assert_ne!(hash_cn("alice"), hash_cn("bob"));
/// ```
pub fn hash_cn(cn: &str) -> String {
    use std::fmt::Write;

    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cn.as_bytes());
    let mut out = String::with_capacity(12);
    for b in &digest[..6] {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Mask a credential string, showing only the first 2 characters.
///
/// The remainder is replaced with `"********"`. Strings shorter than 3
/// characters are fully replaced with `"********"` to avoid leaking
/// near-complete values.
///
/// # Examples
///
/// ```
/// # use rustgate_core::masking::mask_credential;
/// assert_eq!(mask_credential("password123"), "pa********");
/// assert_eq!(mask_credential("ab"), "********");
/// ```
pub fn mask_credential(s: &str) -> String {
    if s.len() < 3 {
        return "********".to_string();
    }
    format!("{}********", &s[..2])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── mask_cert_serial ────────────────────────────────────────────

    #[test]
    fn serial_long_is_masked() {
        assert_eq!(mask_cert_serial("A1B2C3D4E5F6Y3Z4"), "A1B2...Y3Z4");
    }

    #[test]
    fn serial_exactly_ten_is_not_masked() {
        assert_eq!(mask_cert_serial("1234567890"), "1234567890");
    }

    #[test]
    fn serial_short_is_not_masked() {
        assert_eq!(mask_cert_serial("ABC"), "ABC");
    }

    #[test]
    fn serial_empty() {
        assert_eq!(mask_cert_serial(""), "");
    }

    #[test]
    fn serial_eleven_chars_is_masked() {
        assert_eq!(mask_cert_serial("12345678901"), "1234...8901");
    }

    // ── mask_ip ─────────────────────────────────────────────────────

    #[test]
    fn ipv4_last_octet_masked() {
        assert_eq!(mask_ip("192.168.1.5"), "192.168.1.***");
    }

    #[test]
    fn ipv4_with_port() {
        assert_eq!(mask_ip("10.0.0.1:8080"), "10.0.0.***:8080");
    }

    #[test]
    fn ipv6_last_group_masked() {
        assert_eq!(mask_ip("2001:db8::1"), "2001:db8::***");
    }

    #[test]
    fn ipv6_mapped_ipv4_masked() {
        assert_eq!(mask_ip("::ffff:192.168.1.1"), "::ffff:***");
    }

    #[test]
    fn bracketed_ipv6_with_port() {
        assert_eq!(mask_ip("[::1]:443"), "[::***]:443");
    }

    #[test]
    fn empty_string() {
        assert_eq!(mask_ip(""), "");
    }

    // ── mask_credential ─────────────────────────────────────────────

    #[test]
    fn credential_normal() {
        assert_eq!(mask_credential("password123"), "pa********");
    }

    #[test]
    fn credential_short() {
        assert_eq!(mask_credential("ab"), "********");
    }

    #[test]
    fn credential_empty() {
        assert_eq!(mask_credential(""), "********");
    }

    #[test]
    fn credential_exactly_three() {
        assert_eq!(mask_credential("abc"), "ab********");
    }

    #[test]
    fn credential_single_char() {
        assert_eq!(mask_credential("x"), "********");
    }

    // ── hash_cn ─────────────────────────────────────────────────────

    #[test]
    fn hash_cn_is_stable_and_truncated() {
        let h = hash_cn("alice");
        assert_eq!(h.len(), 12);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hash_cn("alice"), h);
        assert_ne!(hash_cn("alice"), hash_cn("bob"));
    }

    #[test]
    fn hash_cn_empty_input() {
        // Empty string still hashes to a valid 12-char token.
        let h = hash_cn("");
        assert_eq!(h.len(), 12);
    }

    // ── defensive-invariant coverage ────────────────────────────────

    #[test]
    fn mask_cert_serial_output_is_always_eleven_chars_for_input_longer_than_ten_bytes() {
        // The masked shape is `{4 prefix}...{4 suffix}` — exactly 4 + 3 + 4
        // = 11 characters, regardless of input length. Pin this so a
        // regression that e.g. widened the prefix/suffix to 6 each (making
        // correlation easier at the cost of disclosing more of the serial)
        // trips here rather than silently leaking more bytes into logs.
        for input in [
            "12345678901",                      // 11 chars (just over boundary)
            "A1B2C3D4E5F6",                     // 12
            "0123456789ABCDEF0123456789ABCDEF", // 32
            &"x".repeat(1024),                  // pathological long
        ] {
            let out = mask_cert_serial(input);
            assert_eq!(
                out.len(),
                11,
                "mask_cert_serial output must be exactly 11 chars for input of len {}, got {out:?}",
                input.len()
            );
            assert!(
                out.contains("..."),
                "masked output must contain separator: {out:?}"
            );
        }
    }

    #[test]
    fn mask_cert_serial_non_ascii_short_input_returns_verbatim_without_panic() {
        // Short non-ASCII input (under 10 BYTES, not chars) takes the
        // verbatim early-return path and must not panic on byte-slice
        // operations. Pins that the `<= 10` guard uses `len()` (bytes) and
        // that no byte-slice indexing occurs on short inputs. A regression
        // that re-ordered the guard after byte slicing would panic on any
        // non-ASCII input at byte boundaries inside a UTF-8 continuation.
        assert_eq!(mask_cert_serial("café"), "café"); // 5 bytes, short path
        assert_eq!(mask_cert_serial("日本"), "日本"); // 6 bytes, short path
        assert_eq!(mask_cert_serial("🔒"), "🔒"); // 4 bytes, short path
    }

    #[test]
    fn mask_ip_bracketed_ipv6_without_port_preserves_brackets_and_masks_last_group() {
        // Pin the `after_bracket = ""` branch — bracketed IPv6 with no
        // trailing port. Before this test, `bracketed_ipv6_with_port`
        // covered the `[::1]:443` case but not the no-port variant, so a
        // regression that mis-indexed `&ip[bracket_end + 1..]` past len on
        // empty-suffix input would only surface at a live rejection.
        assert_eq!(mask_ip("[::1]"), "[::***]");
        assert_eq!(mask_ip("[2001:db8::1]"), "[2001:db8::***]");
    }

    #[test]
    fn mask_ip_invalid_non_ip_input_returns_verbatim() {
        // A hostname or non-IP string with no colon and no dot falls
        // through every masking branch and is returned unchanged. Pins
        // that `mask_ip` is a best-effort helper (won't panic on bad
        // input, won't silently truncate a short hostname fragment).
        assert_eq!(mask_ip("hostname"), "hostname");
        assert_eq!(mask_ip("localhost"), "localhost");
        assert_eq!(mask_ip("x"), "x");
    }

    #[test]
    fn mask_ip_single_colon_non_ip_returns_verbatim() {
        // `"x:y"` — one colon, no dot, not bracketed. The IPv6 branch
        // requires `matches(':').count() > 1`, and the IPv4-with-port
        // branch requires `before.contains('.')` — neither fires, so the
        // string is returned verbatim. Pins the "ambiguous single-colon
        // input" path is handled safely rather than mis-classified as a
        // mangled IPv4:port.
        assert_eq!(mask_ip("x:y"), "x:y");
        assert_eq!(mask_ip("no-port:just-text"), "no-port:just-text");
    }

    #[test]
    fn mask_credential_output_for_long_input_is_exactly_ten_chars() {
        // `{2 prefix}********` — exactly 2 + 8 = 10 characters, regardless
        // of input length. Pins the output-length invariant so a regression
        // that varied the asterisk count (e.g. scaled with input length,
        // re-enabling length disclosure) trips here. Operationally
        // important for log column alignment that downstream tools (grep
        // /awk dashboards) assume.
        for input in [
            "abc",                      // exactly 3
            "password123",              // medium
            &"x".repeat(1024),          // long
            "VeryLongSecret!@#$%^&*()", // special chars
        ] {
            let out = mask_credential(input);
            assert_eq!(
                out.len(),
                10,
                "mask_credential output for input of len {} must be 10 chars, got {out:?}",
                input.len()
            );
            assert!(
                out.ends_with("********"),
                "masked output must end with 8 asterisks: {out:?}"
            );
        }
    }

    #[test]
    fn mask_credential_output_for_short_input_is_exactly_eight_chars() {
        // Short inputs (len < 3) are fully replaced with `"********"` —
        // exactly 8 characters. Pins the short-path invariant so a
        // regression that padded differently (e.g. to 10 chars for column
        // alignment) trips here rather than silently disclosing a length
        // signal through the output shape.
        for input in ["", "a", "ab"] {
            let out = mask_credential(input);
            assert_eq!(
                out, "********",
                "short-input mask must be exactly 8 asterisks for input {input:?}, got {out:?}"
            );
            assert_eq!(out.len(), 8);
        }
    }

    #[test]
    fn hash_cn_output_is_always_lowercase_ascii_hex() {
        // The `{b:02x}` format specifier emits lowercase hex; pin this as
        // the contract. A regression to `{b:02X}` (uppercase) would break
        // any downstream log pipeline doing case-sensitive correlation
        // (e.g. grep -F "abcd12" vs grep -F "ABCD12"). The existing
        // `is_ascii_hexdigit` check allows EITHER case — this test closes
        // that gap.
        for cn in [
            "alice",
            "bob",
            "\u{4e16}\u{754c}",
            "",
            "🔒",
            &"x".repeat(256),
        ] {
            let h = hash_cn(cn);
            assert_eq!(h.len(), 12);
            assert!(
                h.chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "hash_cn output must be lowercase hex only: {h:?} for input {cn:?}"
            );
        }
    }

    #[test]
    fn hash_cn_matches_sha256_first_six_byte_truncation_spec() {
        // Cross-check the implementation against the documented
        // algorithmic contract — "SHA-256(cn), first 6 bytes, lowercase
        // hex". An independent recomputation via the raw sha2 primitives
        // must agree byte-for-byte with the module's output. A regression
        // that swapped to a different hash (e.g. SHA-1, MD5) or changed
        // the truncation length (first 4 bytes = 8 chars) would fail here.
        use sha2::{Digest, Sha256};
        for cn in [
            "",
            "alice",
            "bob",
            "\u{4e16}\u{754c}",
            "very-long-cn-with-dashes",
        ] {
            let digest = Sha256::digest(cn.as_bytes());
            let expected = format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
            );
            assert_eq!(
                hash_cn(cn),
                expected,
                "hash_cn({cn:?}) must equal SHA-256(cn)[..6] as lowercase hex"
            );
        }
    }

    #[test]
    fn hash_cn_distinguishes_case_and_whitespace_variants() {
        // Near-identical inputs must produce distinct hashes — operators
        // rely on the correlation token to separate "alice" from "Alice"
        // from "alice " (trailing space, common CN-normalisation footgun)
        // from "ALICE". A regression that lowercased / trimmed the input
        // before hashing would merge these into one and let a typoed CN
        // silently co-mingle with the legitimate identity's audit trail.
        let hashes = [
            hash_cn("alice"),
            hash_cn("Alice"),
            hash_cn("ALICE"),
            hash_cn("alice "),
            hash_cn(" alice"),
            hash_cn("alic"),
            hash_cn("alicee"),
        ];
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(
            unique.len(),
            hashes.len(),
            "near-identical CNs must produce distinct hashes, got collision in {hashes:?}"
        );
    }

    // ── F-94 (#802) public-API contract regression coverage ──────────
    //
    // The following four tests pin the *public* hash-correlation contract
    // expected by other crates that have migrated from the formerly-private
    // `rustgate_transport::router::hash_cn` to the shared
    // `rustgate_core::masking::hash_cn`. They are deliberately named with the
    // F-94 spelling so a future reorg / rename catches the migration
    // breakage at the test level (the names are quoted in the issue body).

    #[test]
    fn hash_identity_returns_hex_with_documented_length() {
        // 48 bits of SHA-256 truncation = 12 hex chars. Pin the documented
        // length so a regression that widened (more disclosure) or
        // narrowed (more collisions) the truncation trips here.
        let h = hash_cn("alice");
        assert_eq!(h.len(), 12);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_identity_is_deterministic() {
        // Same input must always produce the same correlation token — the
        // whole point of hashing for log correlation.
        assert_eq!(hash_cn("alice"), hash_cn("alice"));
        assert_eq!(hash_cn(""), hash_cn(""));
        let long = "x".repeat(4096);
        assert_eq!(hash_cn(&long), hash_cn(&long));
    }

    #[test]
    fn hash_identity_distinguishes_different_inputs() {
        // Distinct CNs must produce distinct correlation tokens (modulo the
        // 48-bit collision risk, which is acceptable for an audit trail).
        // A regression to a fixed-output fold (e.g. `cn.len() % 256`) would
        // collapse alice/bob into the same hash.
        assert_ne!(hash_cn("alice"), hash_cn("bob"));
        assert_ne!(hash_cn("a"), hash_cn("aa"));
    }

    #[test]
    fn hash_identity_handles_pathological_inputs() {
        // Empty, very long, and control-char-laden inputs must all produce
        // a 12-char hex token without panicking. CNs come from
        // attacker-controlled X.509 subjects (extracted by the cert
        // parser) so the sanitizer-of-last-resort must not be the place
        // that crashes the process.
        let pathological = [
            "".to_string(),
            "x".repeat(1_048_576), // 1 MiB
            "\0\0\0\0".to_string(),
            "\r\n\r\n\u{007f}\u{0001}\u{0008}".to_string(),
            "evil\nlog\rinjection\x00attempt".to_string(),
            "\u{4e16}\u{754c}\u{0001}\u{007f}".to_string(),
        ];
        for cn in &pathological {
            let h = hash_cn(cn);
            assert_eq!(
                h.len(),
                12,
                "pathological input must still produce 12-char hex, got {h:?} for input of len {}",
                cn.len()
            );
            assert!(
                h.chars().all(|c| c.is_ascii_hexdigit()),
                "pathological input must produce hex-only output, got {h:?} for input of len {}",
                cn.len()
            );
        }
    }

    #[test]
    fn hash_cn_handles_large_inputs_above_sha256_block_boundary_without_panic() {
        // SHA-256 processes 64-byte blocks internally. Test inputs well
        // above that boundary (and into the multi-block range) to pin
        // that the function doesn't panic on large inputs and still
        // produces a valid 12-char hex token. A regression that added a
        // stack-allocated bounded buffer would fail on the large inputs.
        for size in [64, 1024, 65_536, 1_048_576] {
            let cn = "x".repeat(size);
            let h = hash_cn(&cn);
            assert_eq!(
                h.len(),
                12,
                "hash_cn output len must be 12 for input size {size}, got {h:?}"
            );
            assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn masking_functions_all_return_owned_string_type() {
        // Compile-time pin that every public masking function returns an
        // owned `String`, not `&str` or `Cow<'_, str>`. A regression to a
        // borrowed return type would tie the output's lifetime to the
        // input and break every structured-log call site that stores the
        // masked value into a longer-lived span field. `let _: String = …`
        // enforces this at monomorphisation time — if the return type
        // narrowed, the test would fail to compile here.
        let _: String = mask_cert_serial("A1B2C3D4E5F6Y3Z4");
        let _: String = mask_ip("10.0.0.1");
        let _: String = mask_credential("password");
        let _: String = hash_cn("alice");
    }

    // ── F-30 (#773) log-field cardinality cap ────────────────────────
    //
    // The following tests pin the contract that `hash_cn` is the
    // cardinality-cap primitive for operational `info!`/`debug!`/`trace!`
    // log fields carrying user-controlled CNs or peer ids. The
    // boundary discipline is documented in the call sites: error/warn
    // logs keep the raw value for forensic correlation (already
    // sanitized at the audit boundary per #1197); operational logs at
    // info/debug pass the value through `hash_cn` before it reaches a
    // structured field. This caps the SIEM index cardinality at the
    // bounded fleet-CN count rather than the unbounded
    // attacker-controlled value count.

    #[test]
    fn hash_identity_idempotent_through_log_field() {
        // The same CN, hashed at multiple log-emission sites in the
        // same process, must produce the same correlation token. This
        // is the property a SIEM relies on when grouping events by
        // `cn` field — every emission of identity X must collapse to
        // a single index entry, otherwise the cardinality cap is
        // defeated. The previous `hash_cn_is_stable_and_truncated`
        // test pins this for two adjacent calls; this test pins the
        // contract across many calls and many distinct identities,
        // matching the realistic operator query "find all log events
        // for this hashed CN" pattern.
        for cn in [
            "alice",
            "bob@example.test",
            "device-007.uas.fleet",
            "tenant-a/group-b/cn-c",
            "",
            "🔒",
            "very-long-cn-".repeat(32).as_str(),
        ] {
            let first = hash_cn(cn);
            // Hash 50 more times, including with different `&str`
            // bindings (owned vs borrowed) — the public contract
            // accepts `&str` so all of these must resolve to the same
            // 12-char hex token regardless of binding source.
            for _ in 0..50 {
                assert_eq!(
                    hash_cn(cn),
                    first,
                    "hash_cn({cn:?}) must be idempotent across repeated calls"
                );
                let owned = cn.to_string();
                assert_eq!(
                    hash_cn(&owned),
                    first,
                    "hash_cn for {cn:?} must agree between owned and borrowed bindings"
                );
            }
        }
    }

    #[test]
    fn hash_identity_collision_resistance_smoke() {
        // 1000 distinct CNs must produce 1000 distinct hashes in the
        // smoke-test set. This is a smoke check for the 48-bit
        // truncation collision risk: by the birthday bound the
        // expected first collision is around 2^24 ≈ 16 million inputs
        // (so 1000 inputs is safely below the threshold), and a
        // regression to a much shorter truncation (e.g. first 8 bits)
        // would collapse the smoke set into ~256 buckets and trip
        // here. Pins the operational contract that an attacker
        // churning a few thousand CNs will not collapse the SIEM
        // index by accident — they would have to mount a deliberate
        // 48-bit preimage attack.
        use std::collections::HashSet;
        let hashes: HashSet<String> = (0..1000)
            .map(|i| hash_cn(&format!("client-{i:04}@fleet.example.test")))
            .collect();
        assert_eq!(
            hashes.len(),
            1000,
            "1000 distinct CNs must produce 1000 distinct hashes; \
             got {} unique buckets — the truncation may have narrowed",
            hashes.len()
        );
    }
}
