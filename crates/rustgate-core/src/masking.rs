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
}
