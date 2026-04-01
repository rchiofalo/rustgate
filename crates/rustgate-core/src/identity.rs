//! Client identity types and validation.
//!
//! Every authenticated connection has an associated `Identity` containing
//! the certificate Common Name (CN), SHA-256 fingerprint, and group
//! memberships. Constructors validate the CN to prevent empty, oversized,
//! or control-character–laden values from propagating through the system.

use std::collections::BTreeSet;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

/// Unique group identifier.
pub type GroupId = String;

/// Certificate fingerprint (SHA-256 hex).
pub type CertFingerprint = String;

/// Maximum allowed length for a certificate Common Name.
///
/// X.509 limits CN to 64 characters (RFC 5280 Appendix A), but we allow
/// up to 256 to accommodate compound names that include socket addresses
/// (e.g., `udp-anonymous-127.0.0.1:5600`).
const MAX_CN_LENGTH: usize = 256;

/// Errors that can occur during identity construction.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The Common Name (CN) is empty.
    #[error("identity CN must not be empty")]
    EmptyCn,

    /// The CN exceeds the maximum allowed length.
    #[error("identity CN too long ({len} chars, max {MAX_CN_LENGTH})")]
    CnTooLong {
        /// Actual length of the CN.
        len: usize,
    },

    /// The CN contains control characters (null, newline, tab, ESC, etc.).
    #[error("identity CN contains control characters")]
    CnContainsControlChars,

    /// The fingerprint is empty when a TLS session requires one.
    #[error("identity fingerprint must not be empty for TLS sessions")]
    EmptyFingerprint,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Identity {
    pub cn: String,
    pub fingerprint: CertFingerprint,
    pub groups: BTreeSet<GroupId>,
}

impl Identity {
    /// Create a validated identity for a TLS-authenticated session.
    ///
    /// Validates that:
    /// - `cn` is non-empty, within length limits, and free of control characters
    /// - `fingerprint` is non-empty (TLS sessions always have a cert fingerprint)
    pub fn new(
        cn: String,
        fingerprint: CertFingerprint,
        groups: BTreeSet<GroupId>,
    ) -> Result<Self, IdentityError> {
        validate_cn(&cn)?;

        if fingerprint.is_empty() {
            return Err(IdentityError::EmptyFingerprint);
        }

        Ok(Self {
            cn,
            fingerprint,
            groups,
        })
    }

    /// Create a validated identity for a plaintext (non-TLS) session.
    ///
    /// Plaintext sessions (UDP, plaintext TCP, federation inbound, NATS bridge)
    /// have no certificate and therefore no fingerprint. The fingerprint is set
    /// to an empty string.
    pub fn plaintext(cn: String, groups: BTreeSet<GroupId>) -> Result<Self, IdentityError> {
        validate_cn(&cn)?;

        Ok(Self {
            cn,
            fingerprint: String::new(),
            groups,
        })
    }

    pub fn is_member_of(&self, group: &str) -> bool {
        self.groups.contains(group)
    }
}

/// Validate a Common Name string.
fn validate_cn(cn: &str) -> Result<(), IdentityError> {
    if cn.is_empty() {
        return Err(IdentityError::EmptyCn);
    }

    if cn.len() > MAX_CN_LENGTH {
        return Err(IdentityError::CnTooLong { len: cn.len() });
    }

    if cn.chars().any(|c| c.is_control()) {
        return Err(IdentityError::CnContainsControlChars);
    }

    Ok(())
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for Identity {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate a valid CN: non-empty, no control chars, max 256 chars.
        // Use printable ASCII to avoid control characters.
        let cn_len = u.int_in_range(1..=64)?;
        let cn: String = (0..cn_len)
            .map(|_| {
                // Printable ASCII range: 0x20 (space) to 0x7E (~)
                u.int_in_range(0x20u8..=0x7E).map(|b| b as char)
            })
            .collect::<arbitrary::Result<_>>()?;

        // Generate a hex fingerprint like "aa:bb:cc:dd"
        let fp_bytes: [u8; 8] = u.arbitrary()?;
        let fingerprint: String = fp_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");

        let num_groups: usize = u.int_in_range(0..=4)?;
        let mut groups = BTreeSet::new();
        for _ in 0..num_groups {
            let glen = u.int_in_range(1..=16)?;
            let group: String = (0..glen)
                .map(|_| u.int_in_range(b'a'..=b'z').map(|b| b as char))
                .collect::<arbitrary::Result<_>>()?;
            let _ = groups.insert(group);
        }

        Ok(Self {
            cn,
            fingerprint,
            groups,
        })
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cn)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_valid_identity() {
        let id = Identity::new("alice".to_string(), "aa:bb:cc".to_string(), BTreeSet::new());
        assert!(id.is_ok());
        let id = id.unwrap();
        assert_eq!(id.cn, "alice");
        assert_eq!(id.fingerprint, "aa:bb:cc");
    }

    #[test]
    fn new_with_groups() {
        let mut groups = BTreeSet::new();
        let _ = groups.insert("Alpha".to_string());
        let _ = groups.insert("Bravo".to_string());
        let id = Identity::new("bob".to_string(), "ff:ee".to_string(), groups).unwrap();
        assert!(id.is_member_of("Alpha"));
        assert!(id.is_member_of("Bravo"));
        assert!(!id.is_member_of("Charlie"));
    }

    #[test]
    fn new_rejects_empty_cn() {
        let result = Identity::new(String::new(), "aa:bb".to_string(), BTreeSet::new());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, IdentityError::EmptyCn));
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn new_rejects_empty_fingerprint() {
        let result = Identity::new("alice".to_string(), String::new(), BTreeSet::new());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::EmptyFingerprint
        ));
    }

    #[test]
    fn new_rejects_cn_too_long() {
        let long_cn = "a".repeat(MAX_CN_LENGTH + 1);
        let result = Identity::new(long_cn, "fp".to_string(), BTreeSet::new());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, IdentityError::CnTooLong { .. }));
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn new_accepts_max_length_cn() {
        let cn = "a".repeat(MAX_CN_LENGTH);
        let result = Identity::new(cn, "fp".to_string(), BTreeSet::new());
        assert!(result.is_ok());
    }

    #[test]
    fn new_rejects_cn_with_null() {
        let result = Identity::new(
            "alice\x00bob".to_string(),
            "fp".to_string(),
            BTreeSet::new(),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::CnContainsControlChars
        ));
    }

    #[test]
    fn new_rejects_cn_with_newline() {
        let result = Identity::new("alice\nbob".to_string(), "fp".to_string(), BTreeSet::new());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::CnContainsControlChars
        ));
    }

    #[test]
    fn new_rejects_cn_with_tab() {
        let result = Identity::new("alice\tbob".to_string(), "fp".to_string(), BTreeSet::new());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::CnContainsControlChars
        ));
    }

    #[test]
    fn new_rejects_cn_with_escape() {
        let result = Identity::new(
            "alice\x1Bbob".to_string(),
            "fp".to_string(),
            BTreeSet::new(),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::CnContainsControlChars
        ));
    }

    #[test]
    fn new_accepts_unicode_cn() {
        let result = Identity::new("caf\u{00e9}".to_string(), "fp".to_string(), BTreeSet::new());
        assert!(result.is_ok());
    }

    #[test]
    fn new_accepts_cn_with_special_chars() {
        // Typical CN patterns: dots, dashes, underscores, spaces, colons
        let result = Identity::new(
            "user.name-host_1:8080 (test)".to_string(),
            "fp".to_string(),
            BTreeSet::new(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn plaintext_valid() {
        let id = Identity::plaintext("udp-anon".to_string(), BTreeSet::new());
        assert!(id.is_ok());
        let id = id.unwrap();
        assert_eq!(id.fingerprint, "");
    }

    #[test]
    fn plaintext_rejects_empty_cn() {
        let result = Identity::plaintext(String::new(), BTreeSet::new());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IdentityError::EmptyCn));
    }

    #[test]
    fn plaintext_rejects_control_chars() {
        let result = Identity::plaintext("bad\x00name".to_string(), BTreeSet::new());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::CnContainsControlChars
        ));
    }

    #[test]
    fn display_shows_cn() {
        let id = Identity::new("alice".to_string(), "fp".to_string(), BTreeSet::new()).unwrap();
        assert_eq!(format!("{id}"), "alice");
    }
}
