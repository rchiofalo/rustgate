// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Pseudonymizes audit events that tie a person to classified traffic
//! before they leave for the SIEM.
//!
//! A SIEM may be cleared below the traffic it watches. Two events would
//! otherwise tell it who handled which classification and with whom:
//! `classification.denied` (source and destination CNs, message uid, full
//! marking) and `guard.rejected` for `unauthorized_classification` (the
//! CN behind an attempted spill). Withholding them would hide the
//! attempted-spill signal a SOC most needs, so by default they are
//! forwarded with:
//!
//! - identity fields replaced by a keyed pseudonym, HMAC-SHA256 under a
//!   random key drawn once per process. Tokens are stable for the life of
//!   the process, so the SIEM can still count repeat offenders, but cannot
//!   be reversed by hashing a list of candidate CNs. `hash_cn` is not used
//!   for this: it is unkeyed, which is fine for correlation in our own
//!   logs but not against a reader who knows the roster. The authoritative
//!   `--audit-log` keeps the real values.
//! - the message `uid` removed.
//! - the marking cut to its classification level (`SECRET//SI//NOFORN`
//!   becomes `SECRET`): the level is not sensitive, but compartment and
//!   control names can be.
//!
//! `--siem-include-classified` turns this off and forwards these events,
//! and `authz.classified_delivery`, unchanged.

use std::fmt::Write as _;

use super::layer::AuditRecord;

/// Fields replaced by a pseudonym, per event.
const IDENTITY_FIELDS: &[(&str, &[&str])] = &[
    ("classification.denied", &["source", "dest"]),
    ("guard.rejected", &["cn"]),
];
/// Fields removed, per event.
const DROPPED_FIELDS: &[(&str, &[&str])] = &[("classification.denied", &["uid"])];
/// Fields cut to their classification level, per event.
const MARKING_FIELDS: &[(&str, &[&str])] = &[("classification.denied", &["marking"])];

/// Hex characters kept from each pseudonym (64 bits).
const TOKEN_HEX_LEN: usize = 16;

/// Keyed pseudonymizer for classification-linked audit events.
pub(crate) struct Redactor {
    key: zeroize::Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Redactor {
    /// A redactor with a fresh random key from the installed crypto
    /// provider's secure RNG.
    ///
    /// # Errors
    ///
    /// Fails when no crypto provider is installed or its RNG fails.
    pub(crate) fn new() -> anyhow::Result<Self> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| anyhow::anyhow!("no crypto provider installed for SIEM pseudonyms"))?;
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        provider
            .secure_random
            .fill(key.as_mut())
            .map_err(|_| anyhow::anyhow!("secure RNG failed generating the SIEM pseudonym key"))?;
        Ok(Self { key })
    }

    #[cfg(test)]
    pub(crate) fn with_key(key: [u8; 32]) -> Self {
        Self {
            key: zeroize::Zeroizing::new(key),
        }
    }

    /// Whether `record` ties a person to classified traffic.
    fn applies(record: &AuditRecord) -> bool {
        match record.event_type.as_str() {
            "classification.denied" => true,
            "guard.rejected" => record.field("reason") == Some("unauthorized_classification"),
            _ => false,
        }
    }

    /// `record` with identities pseudonymized, the uid dropped and the
    /// marking cut to its level, when it is a classification-linked event;
    /// otherwise unchanged.
    pub(crate) fn redact(&self, mut record: AuditRecord) -> AuditRecord {
        if !Self::applies(&record) {
            return record;
        }
        let event = record.event_type.clone();
        let listed = |table: &[(&str, &[&str])], field: &str| {
            table
                .iter()
                .any(|(e, fields)| *e == event && fields.contains(&field))
        };
        record
            .fields
            .retain(|(field, _)| !listed(DROPPED_FIELDS, field));
        for (field, value) in &mut record.fields {
            if listed(IDENTITY_FIELDS, field) {
                *value = self.pseudonym(value);
            } else if listed(MARKING_FIELDS, field) {
                *value = classification_level(value);
            }
        }
        record
    }

    /// `p:` plus the first [`TOKEN_HEX_LEN`] hex characters of
    /// HMAC-SHA256(key, value).
    fn pseudonym(&self, value: &str) -> String {
        let mut token = String::with_capacity(2 + TOKEN_HEX_LEN);
        token.push_str("p:");
        // The key is 32 non-zero-length bytes, the only case the helper
        // rejects is an empty key; fall back to a constant marker rather
        // than ever forwarding the raw value.
        let Ok(tag) = rustgate_core::crypto::hmac_sha256_tag(self.key.as_ref(), value.as_bytes())
        else {
            token.push_str("unavailable");
            return token;
        };
        for byte in tag.iter().take(TOKEN_HEX_LEN / 2) {
            let _ = write!(token, "{byte:02x}");
        }
        token
    }
}

/// The classification level of a CAPCO-style marking: the part before the
/// first `//`, trimmed (`SECRET//SI//NOFORN` → `SECRET`). `-` when empty.
fn classification_level(marking: &str) -> String {
    let level = marking.split("//").next().unwrap_or_default().trim();
    if level.is_empty() {
        "-".to_owned()
    } else {
        level.to_owned()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn record(event_type: &str, fields: &[(&str, &str)]) -> AuditRecord {
        AuditRecord {
            at: time::OffsetDateTime::UNIX_EPOCH,
            event_type: event_type.to_owned(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    fn denied() -> AuditRecord {
        record(
            "classification.denied",
            &[
                ("source", "alice"),
                ("dest", "bob"),
                ("uid", "msg-42"),
                ("marking", "SECRET//SI//NOFORN"),
                ("group", "blue"),
                ("action", "egress"),
                ("result", "denied"),
            ],
        )
    }

    #[test]
    fn classification_denied_is_pseudonymized_and_trimmed() {
        let redactor = Redactor::with_key([7; 32]);
        let out = redactor.redact(denied());
        let source = out.field("source").unwrap();
        let dest = out.field("dest").unwrap();
        assert!(
            source.starts_with("p:") && source.len() == 2 + TOKEN_HEX_LEN,
            "{source}"
        );
        assert_ne!(source, dest);
        assert!(out.fields.iter().all(|(_, v)| v != "alice" && v != "bob"));
        assert_eq!(out.field("uid"), None);
        assert_eq!(out.field("marking"), Some("SECRET"));
        // Non-identifying fields survive for alerting.
        assert_eq!(out.field("group"), Some("blue"));
        assert_eq!(out.field("result"), Some("denied"));
    }

    #[test]
    fn pseudonyms_are_stable_per_key_and_differ_across_keys() {
        let a = Redactor::with_key([1; 32]);
        let b = Redactor::with_key([2; 32]);
        assert_eq!(a.pseudonym("alice"), a.pseudonym("alice"));
        assert_ne!(a.pseudonym("alice"), a.pseudonym("bob"));
        assert_ne!(a.pseudonym("alice"), b.pseudonym("alice"));
        // Not the unkeyed hash_cn token, which anyone can recompute.
        let unkeyed = rustgate_core::masking::hash_cn("alice");
        assert!(!a.pseudonym("alice").contains(&unkeyed));
    }

    #[test]
    fn guard_rejections_are_pseudonymized_only_for_classification() {
        let redactor = Redactor::with_key([3; 32]);
        let spill = record(
            "guard.rejected",
            &[("cn", "alice"), ("reason", "unauthorized_classification")],
        );
        assert!(
            redactor
                .redact(spill)
                .field("cn")
                .unwrap()
                .starts_with("p:")
        );
        let throttled = record(
            "guard.rejected",
            &[("cn", "alice"), ("reason", "rate_limit")],
        );
        assert_eq!(redactor.redact(throttled).field("cn"), Some("alice"));
    }

    #[test]
    fn other_events_pass_through_unchanged() {
        let redactor = Redactor::with_key([4; 32]);
        let connected = record("client.connected", &[("cn", "alice")]);
        assert_eq!(redactor.redact(connected.clone()), connected);
    }

    #[test]
    fn marking_level_handles_odd_input() {
        assert_eq!(classification_level("TOP SECRET//SCI"), "TOP SECRET");
        assert_eq!(classification_level("UNCLASSIFIED"), "UNCLASSIFIED");
        assert_eq!(classification_level(" //X"), "-");
        assert_eq!(classification_level(""), "-");
    }

    #[test]
    fn debug_does_not_print_the_key() {
        let shown = format!("{:?}", Redactor::with_key([9; 32]));
        assert!(
            shown.contains("[REDACTED]") && !shown.contains('9'),
            "{shown}"
        );
    }
}
