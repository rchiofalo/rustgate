// Copyright © 2026 Roberto Chiofalo.

//! Client identity types and validation.
//!
//! Every authenticated connection has an associated `Identity` containing
//! the certificate Common Name (CN), SHA-256 fingerprint, and group
//! memberships. Constructors validate the CN to prevent empty, oversized,
//! or control-character–laden values from propagating through the system.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};

/// A single attribute value attached to an [`Identity`].
///
/// The `AttrValue` enum is the unit of authorization context used by the
/// upcoming RBAC/ABAC engine. Values are derived from mTLS certificate
/// fields (SANs, subject, issuer, serial) and, in later work, from external
/// attribute providers.
///
/// `Set` is deliberately a `Vec<String>` rather than a `BTreeSet` to give
/// callers deterministic JSON serialization order. Callers that need set
/// semantics should sort and de-duplicate before construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum AttrValue {
    /// A single string value (e.g. `org`, `country`, `spiffe_id`).
    Str(String),
    /// A signed 64-bit integer value.
    Int(i64),
    /// A boolean value.
    Bool(bool),
    /// An ordered collection of string values (e.g. `san_dns`, `san_email`).
    ///
    /// Contract: callers should pre-sort and de-duplicate so that two
    /// equivalent sets compare equal and serialize identically.
    Set(Vec<String>),
}

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
    /// Certificate Common Name (or synthetic CN for plaintext sessions).
    pub cn: String,
    /// SHA-256 fingerprint of the presented certificate, or empty for plaintext.
    pub fingerprint: CertFingerprint,
    /// Group memberships derived from OU fields.
    pub groups: BTreeSet<GroupId>,
    /// Tenant identifier extracted from the certificate Organization (O) field.
    ///
    /// Used by the per-tenant quota tracker to enforce connection and
    /// rate limits per organization. Defaults to `None` on plaintext and
    /// test constructors.
    pub tenant: Option<String>,
    /// SPIFFE ID extracted from a URI SAN (`spiffe://...`), if present.
    ///
    /// Foundation for SPIFFE/SPIRE workload identity routing. Defaults to
    /// `None` on every existing constructor so there is no behavior change
    /// for callers that have not been updated.
    pub spiffe_id: Option<String>,
    /// Extensible attribute bag used by the RBAC/ABAC authorization engine.
    ///
    /// Shared via `Arc` so clones are cheap on the hot path. Populated by
    /// the transport layer from cert SANs (URI/DNS/email), subject fields
    /// (O, C), issuer CN, and cert serial. Defaults to an empty map on
    /// every existing constructor.
    pub attributes: Arc<BTreeMap<String, AttrValue>>,
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
            tenant: None,
            spiffe_id: None,
            attributes: Arc::new(BTreeMap::new()),
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
            tenant: None,
            spiffe_id: None,
            attributes: Arc::new(BTreeMap::new()),
        })
    }

    /// Return whether this identity is a member of the given group.
    pub fn is_member_of(&self, group: &str) -> bool {
        self.groups.contains(group)
    }

    /// Builder: attach an attribute bag to this identity.
    ///
    /// Intended for use at extraction time (e.g. TLS handshake) to seed
    /// the attribute map from certificate fields. Existing call sites do
    /// not need to use this — attributes default to empty.
    #[must_use]
    pub fn with_attributes(mut self, attributes: BTreeMap<String, AttrValue>) -> Self {
        self.attributes = Arc::new(attributes);
        self
    }

    /// Builder: attach a tenant identifier to this identity.
    ///
    /// The tenant is typically the Organization (O) field from the
    /// certificate subject, used by the per-tenant quota tracker.
    #[must_use]
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Builder: attach a SPIFFE ID to this identity.
    ///
    /// The SPIFFE ID is expected to be a URI of the form `spiffe://<trust-domain>/<path>`
    /// sourced from a URI SAN in the presented certificate.
    #[must_use]
    pub fn with_spiffe_id(mut self, spiffe_id: impl Into<String>) -> Self {
        self.spiffe_id = Some(spiffe_id.into());
        self
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
            tenant: None,
            spiffe_id: None,
            attributes: Arc::new(BTreeMap::new()),
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

    #[test]
    fn identity_attrvalue_and_identity_error_are_send_sync_static() {
        // Compile-time bound pin: every type in this module flows across
        // task boundaries (Identity is cloned into per-session router
        // tasks, AttrValue is embedded in the authz cache shards, and
        // IdentityError is propagated through `Result<_, RustgateError>`
        // in TLS-handshake spawn sites). A refactor that embedded a
        // non-`Send` field (raw pointer, `Rc`, `RefCell`) or a borrowed
        // reference would break every downstream spawn site, and this
        // test traps the regression locally.
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<Identity>();
        assert_bounds::<AttrValue>();
        assert_bounds::<IdentityError>();
    }

    #[test]
    fn attrvalue_exhaustive_match_pins_current_four_variant_set() {
        // No-wildcard match through every current AttrValue variant.
        // The authz engine's policy-evaluation path (Cedar backend,
        // in-process RBAC matcher) dispatches on the variant, and a new
        // variant added without updating the evaluator would slip
        // through a buried `_ =>` arm and silently degrade every policy
        // decision to the fallback. Pin the closed-enum contract.
        let variants = [
            AttrValue::Str("x".into()),
            AttrValue::Int(42),
            AttrValue::Bool(true),
            AttrValue::Set(vec!["a".into(), "b".into()]),
        ];
        for v in variants {
            let kind = match v {
                AttrValue::Str(_) => "str",
                AttrValue::Int(_) => "int",
                AttrValue::Bool(_) => "bool",
                AttrValue::Set(_) => "set",
            };
            assert!(!kind.is_empty(), "every variant must be handled");
        }
    }

    #[test]
    fn attrvalue_serde_wire_format_is_tagged_snake_case() {
        // `#[serde(tag = "type", content = "value", rename_all = "snake_case")]`
        // pins the JSON wire shape for every attribute crossing a
        // boundary — upstream attribute providers, Cedar policy
        // evaluation, the authz cache's serialized-decision key. A
        // refactor that changed the discriminator key from `"type"` /
        // `"value"` to the default serde adjacent or untagged layout
        // would silently break every consumer's matcher. Pin the exact
        // JSON shape for each variant.
        let s = serde_json::to_string(&AttrValue::Str("hi".into())).unwrap();
        assert_eq!(s, r#"{"type":"str","value":"hi"}"#);
        let i = serde_json::to_string(&AttrValue::Int(-7)).unwrap();
        assert_eq!(i, r#"{"type":"int","value":-7}"#);
        let b = serde_json::to_string(&AttrValue::Bool(true)).unwrap();
        assert_eq!(b, r#"{"type":"bool","value":true}"#);
        let set = serde_json::to_string(&AttrValue::Set(vec!["a".into(), "b".into()])).unwrap();
        assert_eq!(set, r#"{"type":"set","value":["a","b"]}"#);

        // Round-trip each variant to pin the reverse direction.
        let parsed: AttrValue = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, AttrValue::Str("hi".into()));
        let parsed: AttrValue = serde_json::from_str(&i).unwrap();
        assert_eq!(parsed, AttrValue::Int(-7));
        let parsed: AttrValue = serde_json::from_str(&b).unwrap();
        assert_eq!(parsed, AttrValue::Bool(true));
        let parsed: AttrValue = serde_json::from_str(&set).unwrap();
        assert_eq!(parsed, AttrValue::Set(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn attrvalue_set_preserves_caller_supplied_order_and_duplicates() {
        // The module doc is explicit: `Set` is a `Vec<String>` (not a
        // `BTreeSet`) so callers get deterministic serialization order
        // AND are responsible for sort+dedup themselves. A well-meaning
        // refactor that added `.sort() + .dedup()` inside the variant
        // constructor (or that changed the underlying type to
        // `BTreeSet<String>`) would silently change the serialized
        // order AND collapse duplicates — breaking every caller that
        // uses Set for ordered-list semantics (e.g. SAN DNS entries
        // where order carries SNI-preference signal).
        let v = AttrValue::Set(vec![
            "bravo".into(),
            "alpha".into(),
            "bravo".into(),
            "charlie".into(),
        ]);
        match v {
            AttrValue::Set(items) => {
                assert_eq!(items, vec!["bravo", "alpha", "bravo", "charlie"]);
            }
            _ => panic!("expected Set variant"),
        }
    }

    #[test]
    fn identity_error_exhaustive_match_pins_current_four_variant_set() {
        // No-wildcard match through every current IdentityError
        // variant. Construction-time validation failures are surfaced
        // to operators through this enum; a new variant (e.g. a
        // hypothetical `CnDisallowedCharacter { ch }`) added without
        // updating the operator-facing error-message table would slip
        // through via a buried `_ =>` arm. Pin the closed-enum
        // contract so the adder is forced to touch a reviewer-primed
        // site.
        let variants = [
            IdentityError::EmptyCn,
            IdentityError::CnTooLong { len: 999 },
            IdentityError::CnContainsControlChars,
            IdentityError::EmptyFingerprint,
        ];
        for v in variants {
            let kind = match v {
                IdentityError::EmptyCn => "empty-cn",
                IdentityError::CnTooLong { .. } => "too-long",
                IdentityError::CnContainsControlChars => "control",
                IdentityError::EmptyFingerprint => "empty-fp",
            };
            assert!(!kind.is_empty(), "every variant must be handled");
        }
    }

    #[test]
    fn identity_error_cn_too_long_display_includes_actual_len_and_max() {
        // The CnTooLong Display is the message operators see in
        // TLS-handshake audit logs when a client presents an
        // overlong CN. It must carry both the actual length AND the
        // MAX_CN_LENGTH constant so the operator can compare
        // directly — a bare "CN too long" message without the
        // numbers would leave the operator guessing whether to raise
        // the cap or reject the client. Pin the exact text shape.
        let err = IdentityError::CnTooLong { len: 999 };
        let msg = err.to_string();
        assert!(msg.contains("999"), "actual len missing: {msg}");
        assert!(
            msg.contains(&MAX_CN_LENGTH.to_string()),
            "MAX_CN_LENGTH missing: {msg}"
        );
        assert!(msg.starts_with("identity CN too long"), "prefix: {msg}");
    }

    #[test]
    fn max_cn_length_constant_is_256_as_documented() {
        // The module constant MAX_CN_LENGTH = 256 is explicitly chosen
        // above RFC 5280's 64-char limit to accommodate compound
        // plaintext-CN patterns like `udp-anonymous-127.0.0.1:5600`.
        // A regression that "tightened" the cap to 64 for RFC parity
        // would reject every plaintext CN the transport crate
        // synthesises for UDP/plaintext-TCP sessions — and the failure
        // would manifest as silent connection-rejection storms on
        // production deployments. Pin the literal value.
        assert_eq!(
            MAX_CN_LENGTH, 256,
            "MAX_CN_LENGTH must be 256 to accommodate compound plaintext CNs"
        );
    }

    #[test]
    fn plaintext_rejects_cn_too_long() {
        // `validate_cn` is shared between `new` and `plaintext`;
        // the existing suite pins CnTooLong rejection only via `new`.
        // A refactor that split validation (e.g. applied the length
        // cap only in `new` on the premise that plaintext sessions
        // "don't go through TLS so the 64-char X.509 limit doesn't
        // apply") would let plaintext CNs grow unbounded and breach
        // every log-size assumption downstream. Pin that plaintext
        // also enforces the cap.
        let long_cn = "x".repeat(MAX_CN_LENGTH + 1);
        let result = Identity::plaintext(long_cn, BTreeSet::new());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::CnTooLong { .. }
        ));
    }

    #[test]
    fn identity_builder_chain_preserves_prior_fields() {
        // The three builders — `with_tenant`, `with_spiffe_id`,
        // `with_attributes` — are each `-> Self` (consuming), so
        // chaining them must preserve every field that was set on
        // the prior builder step. A refactor that "rebuilt" Self
        // inside a builder (e.g. to gain a `Default` impl for a new
        // field) would silently reset prior builder outputs. Pin
        // that `.with_tenant("t").with_spiffe_id("s").with_attributes(m)`
        // yields an Identity that carries all three overrides AND
        // the original cn / fingerprint / groups from `new()`.
        let mut groups = BTreeSet::new();
        let _ = groups.insert("team".to_string());
        let mut attrs = BTreeMap::new();
        let _ = attrs.insert("k".to_string(), AttrValue::Str("v".into()));
        let id = Identity::new("alice".into(), "fp".into(), groups.clone())
            .unwrap()
            .with_tenant("acme-corp")
            .with_spiffe_id("spiffe://example/alice")
            .with_attributes(attrs.clone());
        // Original constructor fields preserved.
        assert_eq!(id.cn, "alice");
        assert_eq!(id.fingerprint, "fp");
        assert_eq!(id.groups, groups);
        // Each builder's effect present.
        assert_eq!(id.tenant.as_deref(), Some("acme-corp"));
        assert_eq!(id.spiffe_id.as_deref(), Some("spiffe://example/alice"));
        assert_eq!(id.attributes.get("k"), Some(&AttrValue::Str("v".into())));
    }

    #[test]
    fn identity_attributes_arc_is_shared_not_copied_on_clone() {
        // Identity carries `attributes: Arc<BTreeMap<String, AttrValue>>`.
        // The authz cache stores millions of per-subject decisions
        // keyed by identity clone; a refactor that changed the field
        // to `BTreeMap<String, AttrValue>` (bare) would silently
        // deep-copy the map on every clone and 10×-100× the memory
        // cost of the cache hot path. Pin the Arc-sharing contract
        // by asserting `Arc::ptr_eq` between an original and its
        // clone, AND that `Arc::strong_count` reflects the shared
        // ownership.
        let mut attrs = BTreeMap::new();
        let _ = attrs.insert("a".to_string(), AttrValue::Int(1));
        let id = Identity::new("alice".into(), "fp".into(), BTreeSet::new())
            .unwrap()
            .with_attributes(attrs);
        let cloned = id.clone();
        assert!(
            Arc::ptr_eq(&id.attributes, &cloned.attributes),
            "Identity::clone must share the attributes Arc, not re-allocate"
        );
        assert_eq!(
            Arc::strong_count(&id.attributes),
            2,
            "strong count must reflect the shared ownership after one clone"
        );
    }

    #[test]
    fn identity_with_different_fingerprint_is_not_equal() {
        // `#[derive(PartialEq, Eq)]` on Identity means equality is
        // structural — same cn, fingerprint, groups, tenant,
        // spiffe_id, attributes. For the HashMap<Identity, _> path
        // used by dedup/authz-cache, the fingerprint is the
        // discriminator that tells two cert-rotation-separated
        // sessions from the same CN apart. A regression that made
        // Identity equality CN-only (a plausible "simplification"
        // refactor) would silently merge two distinct sessions'
        // cache entries and leak authorization decisions across
        // cert rotations. Pin that fingerprint participates in Eq.
        let a = Identity::new("alice".into(), "fp-A".into(), BTreeSet::new()).unwrap();
        let b = Identity::new("alice".into(), "fp-B".into(), BTreeSet::new()).unwrap();
        assert_ne!(
            a, b,
            "identities differing only in fingerprint must not be equal"
        );
    }

    #[test]
    fn identity_equal_instances_produce_equal_hash() {
        // `#[derive(Hash, PartialEq, Eq)]` on Identity implies the
        // Rust contract `a == b` => `hash(a) == hash(b)`. The
        // HashMap<Identity, _> hot path (authz cache shards, dedup
        // index) relies on this invariant. A regression that
        // hand-rolled `Hash` while keeping the derived `PartialEq`
        // (or vice versa) would silently break every cache lookup —
        // keys inserted but never found again. Pin via an explicit
        // DefaultHasher round-trip on two equal-by-construction
        // identities.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut groups = BTreeSet::new();
        let _ = groups.insert("team".to_string());
        let a = Identity::new("alice".into(), "fp".into(), groups.clone()).unwrap();
        let b = Identity::new("alice".into(), "fp".into(), groups).unwrap();
        assert_eq!(a, b);
        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }
}
