// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared revocation vocabulary for the mid-session revocation sweep
//! (ADR 0025, piece 3).
//!
//! The TLS layer builds a [`RevokedSet`] from each loaded CRL generation and
//! the router's sweeper matches live sessions against it. Both sides must
//! encode the `(issuer, serial)` key identically, so the encoding lives here
//! in one place: [`serial_hex`] for serials and [`canonical_issuer`] for
//! issuer names. The session side reads the same encoding back out of the
//! [`Identity`] attribute bag ([`ATTR_ISSUER_CN`], [`ATTR_CERT_SERIAL`]).

use std::collections::HashSet;

use crate::identity::{AttrValue, Identity};
use crate::sanitize::sanitize_for_log;

/// Identity attribute holding the certificate issuer's CN, in
/// [`canonical_issuer`] form.
pub const ATTR_ISSUER_CN: &str = "issuer_cn";
/// Identity attribute holding the certificate serial, in [`serial_hex`] form.
pub const ATTR_CERT_SERIAL: &str = "cert_serial";
/// Identity attribute holding the certificate `notAfter` as Unix seconds.
pub const ATTR_CERT_NOT_AFTER: &str = "cert_not_after";
/// Identity attribute (a set) holding one [`chain_key`] per intermediate CA
/// certificate the client presented, so revoking an intermediate also
/// matches the sessions of the leaves it issued.
pub const ATTR_CHAIN_REVOCATION_KEYS: &str = "chain_revocation_keys";

/// Separates issuer and serial in a [`chain_key`]. A control character, so
/// it can never appear in a [`canonical_issuer`] string.
const CHAIN_KEY_SEP: char = '\u{1f}';

/// Encode one `(issuer, serial)` pair for [`ATTR_CHAIN_REVOCATION_KEYS`].
/// Both arguments must already be canonical ([`canonical_issuer`],
/// [`serial_hex`]).
#[must_use]
pub fn chain_key(issuer_canonical: &str, serial_hex: &str) -> String {
    format!("{issuer_canonical}{CHAIN_KEY_SEP}{serial_hex}")
}

/// Encode a certificate serial as lowercase hex, two characters per byte of
/// its big-endian representation, with no `0x` prefix and no trimming.
///
/// Callers must pass the same byte form on both sides (the minimal
/// big-endian magnitude, e.g. x509-parser's `BigUint::to_bytes_be`), so a
/// serial with its high bit set (DER-padded with a leading `0x00` on the
/// wire) encodes the same for a certificate and for a CRL entry.
#[must_use]
pub fn serial_hex(serial_be: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(serial_be.len() * 2);
    for b in serial_be {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Canonical form of an issuer CN for revocation matching.
///
/// This is the form stored in the [`ATTR_ISSUER_CN`] identity attribute, so
/// a CRL issuer passed through this function compares equal to it.
#[must_use]
pub fn canonical_issuer(issuer_cn: &str) -> String {
    sanitize_for_log(issuer_cn)
}

/// The set of revoked `(issuer CN, serial)` pairs across all loaded CRLs.
///
/// Matching is issuer-scoped: X.509 serials are unique only per issuer, so a
/// serial revoked by one CA never matches a certificate from another.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevokedSet {
    entries: HashSet<(String, String)>,
}

impl RevokedSet {
    /// An empty set (nothing revoked).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a revoked certificate. `issuer_cn` and `serial_be` are encoded
    /// with [`canonical_issuer`] and [`serial_hex`].
    pub fn insert(&mut self, issuer_cn: &str, serial_be: &[u8]) {
        let _ = self
            .entries
            .insert((canonical_issuer(issuer_cn), serial_hex(serial_be)));
    }

    /// Whether `(issuer CN, serial hex)` is revoked. Both arguments must
    /// already be in canonical form, as stored on an [`Identity`].
    #[must_use]
    pub fn contains_canonical(&self, issuer_cn: &str, serial_hex: &str) -> bool {
        self.entries
            .contains(&(issuer_cn.to_owned(), serial_hex.to_owned()))
    }

    /// Whether the certificate behind `identity`, or any intermediate CA
    /// certificate in the chain the client presented, is revoked. Returns
    /// `false` when the identity carries no issuer or serial (e.g. plaintext
    /// or anonymous sessions), which never match a CRL.
    #[must_use]
    pub fn is_revoked(&self, identity: &Identity) -> bool {
        if let (Some(issuer), Some(serial)) = (
            str_attr(identity, ATTR_ISSUER_CN),
            str_attr(identity, ATTR_CERT_SERIAL),
        ) && self.contains_canonical(issuer, serial)
        {
            return true;
        }
        match identity.attributes.get(ATTR_CHAIN_REVOCATION_KEYS) {
            Some(AttrValue::Set(keys)) => keys.iter().any(|key| {
                key.split_once(CHAIN_KEY_SEP)
                    .is_some_and(|(issuer, serial)| self.contains_canonical(issuer, serial))
            }),
            _ => false,
        }
    }

    /// Number of revoked entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The certificate `notAfter` recorded on `identity`, as Unix seconds.
#[must_use]
pub fn cert_not_after(identity: &Identity) -> Option<i64> {
    match identity.attributes.get(ATTR_CERT_NOT_AFTER) {
        Some(AttrValue::Int(t)) => Some(*t),
        _ => None,
    }
}

fn str_attr<'a>(identity: &'a Identity, key: &str) -> Option<&'a str> {
    match identity.attributes.get(key) {
        Some(AttrValue::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn identity_with(issuer: Option<&str>, serial: Option<&str>) -> Identity {
        let mut attrs = std::collections::BTreeMap::new();
        if let Some(i) = issuer {
            let _ = attrs.insert(ATTR_ISSUER_CN.into(), AttrValue::Str(i.into()));
        }
        if let Some(s) = serial {
            let _ = attrs.insert(ATTR_CERT_SERIAL.into(), AttrValue::Str(s.into()));
        }
        Identity::new("client".into(), "fp".into(), BTreeSet::new())
            .expect("valid identity")
            .with_attributes(attrs)
    }

    #[test]
    fn serial_hex_keeps_every_byte() {
        assert_eq!(serial_hex(&[0x01]), "01");
        assert_eq!(serial_hex(&[0x00, 0xff]), "00ff");
        assert_eq!(serial_hex(&[0x8a, 0x0b]), "8a0b");
        assert_eq!(serial_hex(&[]), "");
    }

    #[test]
    fn matching_is_issuer_scoped() {
        let mut set = RevokedSet::new();
        set.insert("CA One", &[0x8a, 0x0b]);
        assert!(set.is_revoked(&identity_with(Some("CA One"), Some("8a0b"))));
        // Same serial under a different CA is not revoked.
        assert!(!set.is_revoked(&identity_with(Some("CA Two"), Some("8a0b"))));
        assert!(!set.is_revoked(&identity_with(Some("CA One"), Some("8a0c"))));
    }

    #[test]
    fn identities_without_issuer_or_serial_never_match() {
        let mut set = RevokedSet::new();
        set.insert("CA One", &[0x01]);
        assert!(!set.is_revoked(&identity_with(None, Some("01"))));
        assert!(!set.is_revoked(&identity_with(Some("CA One"), None)));
    }

    #[test]
    fn issuer_is_canonicalized_like_the_identity_attribute() {
        // The identity attribute is stored sanitized; a CRL issuer with the
        // same control characters must canonicalize to the same string.
        let mut set = RevokedSet::new();
        set.insert("Bad\nCA", &[0x02]);
        let stored = canonical_issuer("Bad\nCA");
        assert!(set.is_revoked(&identity_with(Some(&stored), Some("02"))));
    }

    #[test]
    fn a_revoked_intermediate_matches_its_leaves() {
        let mut set = RevokedSet::new();
        set.insert("Root CA", &[0x07]);
        let mut attrs = std::collections::BTreeMap::new();
        let _ = attrs.insert(ATTR_ISSUER_CN.into(), AttrValue::Str("Issuing CA".into()));
        let _ = attrs.insert(ATTR_CERT_SERIAL.into(), AttrValue::Str("01".into()));
        let _ = attrs.insert(
            ATTR_CHAIN_REVOCATION_KEYS.into(),
            AttrValue::Set(vec![chain_key("Root CA", "07")]),
        );
        let leaf = Identity::new("client".into(), "fp".into(), BTreeSet::new())
            .expect("valid identity")
            .with_attributes(attrs.clone());
        assert!(set.is_revoked(&leaf));

        // A different intermediate serial under the same root does not match.
        let _ = attrs.insert(
            ATTR_CHAIN_REVOCATION_KEYS.into(),
            AttrValue::Set(vec![chain_key("Root CA", "08")]),
        );
        let other = Identity::new("client".into(), "fp".into(), BTreeSet::new())
            .expect("valid identity")
            .with_attributes(attrs);
        assert!(!set.is_revoked(&other));
    }

    #[test]
    fn cert_not_after_reads_int_attribute() {
        assert_eq!(cert_not_after(&identity_with(None, None)), None);
        let mut attrs = std::collections::BTreeMap::new();
        let _ = attrs.insert(ATTR_CERT_NOT_AFTER.into(), AttrValue::Int(1_900_000_000));
        let id = Identity::new("client".into(), "fp".into(), BTreeSet::new())
            .expect("valid identity")
            .with_attributes(attrs);
        assert_eq!(cert_not_after(&id), Some(1_900_000_000));
    }
}
