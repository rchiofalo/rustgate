// Copyright © 2026 Roberto Chiofalo.

//! Runtime model types for authorization decisions.
//!
//! These types describe the inputs and outputs of policy evaluation. They are
//! kept deliberately small and allocation-free on the hot path: [`Subject`]
//! and [`Resource`] borrow from caller-owned data, and [`DecisionOutcome`]
//! only allocates when an obligation list is actually produced.

use std::collections::{BTreeMap, BTreeSet};

use rustgate_core::AttrValue;
use rustgate_core::identity::Identity;
use serde::{Deserialize, Serialize};

/// Snapshot of decision-cache effectiveness counters.
///
/// Lifted to [`crate::PolicyEngine`] as an optional trait method so backends
/// without a cache can still report `None`. The hot-path [`crate::NativeEngine`]
/// populates both counters on every evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheStats {
    /// Number of evaluations that returned a cached outcome.
    pub hits: u64,
    /// Number of evaluations that ran the full scan and populated the cache.
    pub misses: u64,
}

/// The action a subject is attempting to perform on a resource.
///
/// `#[non_exhaustive]` so that adding new actions (e.g. a future
/// `Manage` or `Admin`) does not break downstream match statements.
/// Consumers must include a wildcard `_` arm when matching on this enum
/// from outside the defining crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Action {
    /// Send a message to a specific target or group.
    Send,
    /// Receive a message routed toward the subject.
    Receive,
    /// Send a message to a federated peer server.
    Federate,
    /// Publish to a NATS subject.
    Publish,
    /// Subscribe to a NATS subject.
    Subscribe,
}

/// The core allow/deny verdict.
///
/// `#[non_exhaustive]` preserves future-proofing if the verdict space
/// grows to include additional outcomes (e.g. `NotApplicable` for
/// federated evaluation). Downstream matches must use a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Decision {
    /// Action is permitted.
    Allow,
    /// Action is denied.
    Deny,
}

/// Side-effects that the dataplane must apply alongside an allow decision.
///
/// `#[non_exhaustive]` — new obligations are added over time (e.g. more
/// masking flavours or audit tiers). Downstream matches must include a
/// wildcard arm so the obligation set can grow without breaking the API.
///
/// # Canonical chaining order (refs #882)
///
/// When multiple obligations apply to a single message (e.g. Send-PEP
/// attaches `MaskPoint` and Receive-PEP attaches `TagClassified`) they
/// MUST compose in a defined order so the same input produces the same
/// post-PEP byte output regardless of which code path encountered the
/// obligations or in which sequence the policy engine emitted them. The
/// canonical order is:
///
/// 1. **Group 1 — Redactors** (`priority = 0`). Variants that REMOVE
///    information from the payload. Run first so subsequent groups
///    operate on the redacted form rather than seeing pre-redaction
///    bytes. Members today: [`Obligation::MaskPoint`],
///    [`Obligation::MaskPayload`].
/// 2. **Group 2 — Classifiers / Taggers** (`priority = 1`). Variants
///    that ATTACH new fields, headers, or labels to the (already
///    redacted) message. Members today: [`Obligation::TagClassified`].
/// 3. **Group 3 — Auditors** (`priority = 2`). Variants that EMIT
///    audit events without changing the message bytes. Run last so the
///    audit record reflects the final post-redact-post-tag state.
///    Members today: [`Obligation::AuditExtended`]. Future
///    `#[non_exhaustive]` variants without an explicit group fall here
///    by default — auditing the final state is the safest fallback for
///    a transport build older than the policy engine.
///
/// Within each group ordering is alphabetical by `Debug` repr — a
/// deterministic, byte-stable rule that does not require per-variant
/// configuration. The application path applies a **stable sort** by
/// [`Obligation::chain_sort_key`] before actuation, so two permutations
/// of the same obligation set produce byte-identical post-PEP output.
///
/// **Adding a new variant**: assign it to a group via
/// [`Obligation::priority`] in the same edit that introduces the
/// variant, and document the assignment in the variant's docstring.
/// New variants without an explicit assignment default to Group 3
/// (Auditors) — see [`Obligation::priority`] for the default-group
/// rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Obligation {
    /// Zero the CoT `<point>` coordinates (`lat`, `lon`, `hae`) in the
    /// outbound message. The name intentionally reflects the scope: only
    /// the `<point>` element is touched, not `<detail>` children, not
    /// envelope metadata, and not free-form geographic references inside
    /// the payload. Non-CoT payloads pass through unmodified — masking
    /// is a best-effort leak-prevention obligation, not a hard gate.
    ///
    /// **Chaining group**: 1 (Redactor). Removes coordinate bytes from
    /// the payload; runs before classifiers and auditors so they see
    /// the redacted form.
    MaskPoint,
    /// Strip the payload body, leaving only envelope metadata.
    ///
    /// **Chaining group**: 1 (Redactor). Empties the payload and
    /// coerces the message type to `Other("masked")`; supersedes any
    /// prior [`Obligation::MaskPoint`] by replacing the body entirely.
    MaskPayload,
    /// Tag the outbound message as classified.
    ///
    /// **Chaining group**: 2 (Classifier/Tagger). Attaches the
    /// classified marker to the (already redacted) outbound message;
    /// data-plane is a no-op today, the audit record is emitted at the
    /// PEP call site.
    TagClassified,
    /// Emit an extended audit record for this decision.
    ///
    /// **Chaining group**: 3 (Auditor). Pure audit emission, no
    /// payload mutation; runs last so the audit record reflects the
    /// final post-redact-post-tag state.
    AuditExtended,
}

impl Obligation {
    /// Return the canonical chaining group this obligation belongs to
    /// (refs #882). `0` = Redactors, `1` = Classifiers/Taggers, `2` =
    /// Auditors.
    ///
    /// The application path sorts by `(priority, debug_repr)` with a
    /// **stable sort** so two permutations of the same obligation set
    /// produce byte-identical post-PEP output. Within a group the
    /// ordering is alphabetical by `Debug` repr — deterministic, no
    /// per-variant configuration.
    ///
    /// # Default for unknown variants
    ///
    /// `Obligation` is `#[non_exhaustive]`. A future variant landing
    /// in a transport build that pre-dates the authz upgrade will
    /// match the wildcard arm and receive `priority = 2` (Auditors).
    /// This is the safest fallback: an unknown variant the data plane
    /// cannot actuate is most likely a new audit/classification flavour
    /// the policy author added, and forcing it last lets every known
    /// redactor and tagger run first. The
    /// [`crate::Obligation`]-actuation site
    /// (`rustgate_transport::obligations::apply_obligations`) still
    /// fail-closes on unknown variants under the default
    /// `UnknownObligationPolicy::FailClosed` after the sort runs, so
    /// the priority assignment matters only when the operator opted
    /// into `SkipAndContinue` for a rolling-upgrade window.
    pub fn priority(&self) -> u8 {
        // justification: the wildcard arm is reachable only when a
        // future `#[non_exhaustive]` variant is added to this enum
        // without a corresponding match arm. Inside the defining
        // crate the compiler proves the wildcard is currently
        // unreachable, but removing it would silently regress the
        // forward-compat fallback the docstring promises — a future
        // variant landing without an explicit arm would then be a
        // compile failure here rather than a documented group-3
        // default. The `#[allow(unreachable_patterns)]` is the
        // narrowest annotation that preserves the safety net.
        #[allow(unreachable_patterns)]
        match self {
            // Group 1 — Redactors.
            Obligation::MaskPoint | Obligation::MaskPayload => 0,
            // Group 2 — Classifiers / Taggers.
            Obligation::TagClassified => 1,
            // Group 3 — Auditors. Unknown variants land here by
            // default (see docstring above).
            Obligation::AuditExtended => 2,
            // `#[non_exhaustive]` fallback: future variants assigned
            // to Group 3 by default. Add an explicit arm above when
            // landing the variant.
            _ => 2,
        }
    }

    /// Composite sort key used by the stable-sort step before
    /// obligation actuation (refs #882).
    ///
    /// Returns `(priority, debug_repr)` — the primary key is the
    /// chaining group from [`Obligation::priority`] and the secondary
    /// key is the `Debug` rendering, giving alphabetical disambiguation
    /// within each group. Stable-sort + this key guarantees the same
    /// obligation set produces byte-identical post-PEP output across
    /// any input permutation.
    ///
    /// The `String` allocation is intentional: variants may grow
    /// payload-bearing forms (e.g. a future `Obligation::TagWith(label)`)
    /// and bucketing by the full `Debug` repr keeps the sort
    /// deterministic across those without introducing a parallel
    /// per-variant tie-breaker constant.
    pub fn chain_sort_key(&self) -> (u8, String) {
        (self.priority(), format!("{self:?}"))
    }
}

/// The result of evaluating a policy against a subject/resource/action tuple.
#[derive(Debug, Clone)]
pub struct DecisionOutcome {
    /// The verdict.
    pub decision: Decision,
    /// Identifier of the rule that produced the decision, if any.
    pub rule_id: Option<smol_str::SmolStr>,
    /// Obligations to apply when `decision` is `Allow`.
    pub obligations: Vec<Obligation>,
}

impl DecisionOutcome {
    /// Shorthand for an unconditional allow outcome with no obligations.
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            rule_id: None,
            obligations: Vec::new(),
        }
    }

    /// Shorthand for an unconditional deny outcome with no obligations.
    pub fn deny() -> Self {
        Self {
            decision: Decision::Deny,
            rule_id: None,
            obligations: Vec::new(),
        }
    }

    /// Return true when the outcome is `Allow`.
    pub fn is_allow(&self) -> bool {
        matches!(self.decision, Decision::Allow)
    }
}

/// A 128-bit subject fingerprint produced by hashing the policy-relevant
/// identity fields with two independent seeds.
///
/// The decision cache key is composed on a per-session `SubjectHash` rather
/// than a single `u64`. Two independent 64-bit hashes make an adversarial
/// collision infeasible: the birthday bound for 128 bits is ~2^64, so even
/// an attacker who controls certificate CNs/SANs through enrollment cannot
/// pre-image a distinct identity that lands on the same cache entry as a
/// privileged principal.
///
/// Both component hashes are deterministic for the lifetime of a process:
/// they use `ahash` with fixed per-seed keys so the same identity always
/// produces the same fingerprint. The cache is per-process so we only need
/// stability within a single run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubjectHash {
    /// Primary 64-bit hash mixed from the first seed.
    pub primary: u64,
    /// Secondary 64-bit hash mixed from a distinct seed. Together with
    /// [`SubjectHash::primary`] this gives 128 bits of disambiguation.
    pub secondary: u64,
}

// Deterministic, process-stable ahash seeds. Derived from nothing-up-my-
// sleeve constants (first/second blocks of the Blowfish π table) so they
// are not attacker-controlled. The values are arbitrary but fixed — any
// two distinct quadruples would be equally correct; the only requirement
// is that the primary and secondary seeds differ.
const SUBJECT_SEED_PRIMARY: (u64, u64, u64, u64) = (
    0x243f_6a88_85a3_08d3,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
);
const SUBJECT_SEED_SECONDARY: (u64, u64, u64, u64) = (
    0x4528_21e6_38d0_1377,
    0xbe54_66cf_34e9_0c6c,
    0xc0ac_29b7_c97c_50dd,
    0x3f84_d5b5_b547_0917,
);

impl SubjectHash {
    /// Compute a 128-bit deterministic hash of the policy-relevant
    /// fields of `id`.
    ///
    /// The hash mixes `cn`, the sorted group set, the sorted attribute
    /// map (with length prefixes to prevent reinterpretation attacks),
    /// and the canonical SPIFFE ID. Length prefixes guarantee that no
    /// two distinct identities can produce the same write sequence on
    /// the underlying hasher.
    pub fn compute(id: &Identity) -> Self {
        use std::hash::BuildHasher;
        let rs_primary = ahash::RandomState::with_seeds(
            SUBJECT_SEED_PRIMARY.0,
            SUBJECT_SEED_PRIMARY.1,
            SUBJECT_SEED_PRIMARY.2,
            SUBJECT_SEED_PRIMARY.3,
        );
        let rs_secondary = ahash::RandomState::with_seeds(
            SUBJECT_SEED_SECONDARY.0,
            SUBJECT_SEED_SECONDARY.1,
            SUBJECT_SEED_SECONDARY.2,
            SUBJECT_SEED_SECONDARY.3,
        );
        let mut h1 = rs_primary.build_hasher();
        let mut h2 = rs_secondary.build_hasher();
        hash_identity_into(id, &mut h1);
        hash_identity_into(id, &mut h2);
        use std::hash::Hasher;
        Self {
            primary: h1.finish(),
            secondary: h2.finish(),
        }
    }
}

/// Mix all policy-relevant fields of `id` into `h` in a canonical,
/// length-delimited order. Used by both [`SubjectHash::compute`]
/// hashers so that only the seed differs between the two outputs.
fn hash_identity_into<H: std::hash::Hasher>(id: &Identity, h: &mut H) {
    use std::hash::Hash;
    // CN — length-prefixed via str::hash which writes a trailing
    // separator byte.
    id.cn.hash(h);

    // Groups: write the count first so that an empty group set
    // cannot be confused with an attribute-bag prefix, and each
    // group's bytes remain unambiguously delimited.
    (id.groups.len() as u64).hash(h);
    for g in &id.groups {
        g.hash(h);
    }

    // Attribute bag: count-prefixed, then each (key, value) pair.
    let attrs = id.attributes.as_ref();
    (attrs.len() as u64).hash(h);
    for (k, v) in attrs {
        k.hash(h);
        hash_attr(v, h);
    }

    // SPIFFE ID: tag its presence with a single discriminant byte so
    // `Some("")` and `None` hash distinctly.
    match id.spiffe_id.as_deref() {
        Some(s) => {
            1u8.hash(h);
            s.hash(h);
        }
        None => {
            0u8.hash(h);
        }
    }
}

/// Borrowed view of an authenticated identity for policy evaluation.
#[derive(Debug)]
pub struct Subject<'a> {
    /// Certificate Common Name.
    pub cn: &'a str,
    /// SPIFFE ID from a URI SAN, if any.
    pub spiffe_id: Option<&'a str>,
    /// Group memberships from OU fields or other sources.
    pub groups: &'a BTreeSet<String>,
    /// Extensible attribute bag from SANs, subject fields, and providers.
    pub attributes: &'a BTreeMap<String, AttrValue>,
    /// SHA-256 certificate fingerprint, empty for plaintext sessions.
    pub fingerprint: &'a str,
    /// 128-bit subject fingerprint used as the per-session component of
    /// the decision cache key.
    ///
    /// Callers on the hot path should precompute this once per session
    /// (see [`SubjectHash::compute`]) and reuse it via
    /// [`Subject::with_hash`] rather than paying the hashing cost on
    /// every evaluation.
    pub subject_hash: SubjectHash,
}

impl<'a> Subject<'a> {
    /// Borrow an [`Identity`] as a [`Subject`], computing `subject_hash`
    /// inline. Convenient for test/cold paths; the hot path should use
    /// [`Subject::with_hash`] and a session-cached hash.
    pub fn from_identity(id: &'a Identity) -> Self {
        let subject_hash = SubjectHash::compute(id);
        Self::with_hash(id, subject_hash)
    }

    /// Borrow an [`Identity`] as a [`Subject`] using a caller-provided,
    /// precomputed hash. Zero-work per call on the dataplane hot path.
    pub fn with_hash(id: &'a Identity, subject_hash: SubjectHash) -> Self {
        Self {
            // `id.cn` is now `Arc<str>`; deref coercion via `&*` yields
            // the borrowed `&str` Subject expects without paying for a
            // clone or (unstable) `Arc::as_str` call. Closes #784.
            cn: &id.cn,
            spiffe_id: id.spiffe_id.as_deref(),
            groups: &id.groups,
            attributes: id.attributes.as_ref(),
            fingerprint: id.fingerprint.as_str(),
            subject_hash,
        }
    }

    /// Compatibility wrapper for the previous single-`u64` API used in
    /// benches and tests. Prefer [`SubjectHash::compute`] in new code.
    pub fn compute_hash(id: &Identity) -> SubjectHash {
        SubjectHash::compute(id)
    }
}

fn hash_attr<H: std::hash::Hasher>(v: &AttrValue, h: &mut H) {
    use std::hash::Hash;
    match v {
        AttrValue::Str(s) => {
            0u8.hash(h);
            s.hash(h);
        }
        AttrValue::Int(i) => {
            1u8.hash(h);
            i.hash(h);
        }
        AttrValue::Bool(b) => {
            2u8.hash(h);
            b.hash(h);
        }
        AttrValue::Set(items) => {
            // Write the discriminant and the element count BEFORE the
            // items themselves. Without the count prefix, two distinct
            // Sets could produce the same hasher write sequence by
            // shifting bytes across element boundaries.
            3u8.hash(h);
            (items.len() as u64).hash(h);
            for item in items {
                item.hash(h);
            }
        }
    }
}

/// The resource a subject is acting on.
///
/// `#[non_exhaustive]` keeps the door open for additional resource
/// kinds (e.g. a future `Enrollment` or `Admin` variant) without
/// breaking downstream match statements. External consumers must
/// include a wildcard arm.
#[derive(Debug)]
#[non_exhaustive]
pub enum Resource<'a> {
    /// A direct unicast send to a specific CN.
    Direct {
        /// Target certificate CN.
        target_cn: &'a str,
    },
    /// A group-scoped send.
    Group {
        /// Group name.
        group: &'a str,
    },
    /// A broadcast to all connected peers.
    Broadcast,
    /// A federation link to another server.
    Federation {
        /// Peer server identifier.
        peer_id: &'a str,
    },
    /// A NATS subject (publish or subscribe target).
    NatsSubject {
        /// NATS subject string.
        subject: &'a str,
    },
}

impl<'a> Resource<'a> {
    /// Numeric tag used when bucketing compiled rules by resource kind.
    pub(crate) fn kind_tag(&self) -> u8 {
        match self {
            Resource::Direct { .. } => 0,
            Resource::Group { .. } => 1,
            Resource::Broadcast => 2,
            Resource::Federation { .. } => 3,
            Resource::NatsSubject { .. } => 4,
        }
    }
}

#[cfg(test)]
mod subject_hash_tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeMap;

    use super::*;

    fn identity(
        cn: &str,
        groups: &[&str],
        attrs: BTreeMap<String, AttrValue>,
        spiffe: Option<&str>,
    ) -> Identity {
        let groups: BTreeSet<String> = groups.iter().map(|g| (*g).to_string()).collect();
        let mut id = Identity::new(cn.to_string(), format!("{cn}-fp"), groups)
            .expect("valid identity")
            .with_attributes(attrs);
        if let Some(s) = spiffe {
            id = id.with_spiffe_id(s);
        }
        id
    }

    #[test]
    fn hash_is_deterministic_across_calls() {
        let id = identity("alice", &["ops"], BTreeMap::new(), None);
        let a = SubjectHash::compute(&id);
        let b = SubjectHash::compute(&id);
        assert_eq!(a, b, "same identity must hash identically");
    }

    #[test]
    fn primary_and_secondary_differ_for_same_identity() {
        // The two hashes are seeded independently, so for any
        // non-pathological identity they should produce distinct
        // 64-bit outputs. This is a cheap smoke-test that the
        // secondary seed is actually wired in.
        let id = identity("alice", &["ops"], BTreeMap::new(), None);
        let h = SubjectHash::compute(&id);
        assert_ne!(
            h.primary, h.secondary,
            "primary and secondary hashes should differ"
        );
    }

    #[test]
    fn distinct_identities_produce_distinct_128_bit_hashes() {
        let a = identity("alice", &["ops"], BTreeMap::new(), None);
        let b = identity("bob", &["ops"], BTreeMap::new(), None);
        assert_ne!(SubjectHash::compute(&a), SubjectHash::compute(&b));
    }

    #[test]
    fn groups_count_prefix_prevents_empty_vs_attr_confusion() {
        // With no length prefix on the group loop, an empty group set
        // + an attribute key that starts with byte 0 could in theory
        // collide with a single-element group whose name was the same
        // prefix. The length prefix eliminates that class of confusion.
        let a = identity("alice", &[], BTreeMap::new(), None);
        let mut attrs = BTreeMap::new();
        let _ = attrs.insert("x".to_string(), AttrValue::Str("y".to_string()));
        let b = identity("alice", &[], attrs, None);
        assert_ne!(SubjectHash::compute(&a), SubjectHash::compute(&b));
    }

    #[test]
    fn attr_set_length_prefix_disambiguates_elements() {
        // `Set(["ab"])` vs `Set(["a", "b"])` — without the length
        // prefix, both would write the same byte stream into the
        // hasher (modulo the per-string separator from `str::hash`).
        // With the prefix, the counts differ so the hashes differ.
        let mut attrs_one = BTreeMap::new();
        let _ = attrs_one.insert("k".to_string(), AttrValue::Set(vec!["ab".to_string()]));
        let mut attrs_two = BTreeMap::new();
        let _ = attrs_two.insert(
            "k".to_string(),
            AttrValue::Set(vec!["a".to_string(), "b".to_string()]),
        );
        let a = identity("alice", &[], attrs_one, None);
        let b = identity("alice", &[], attrs_two, None);
        assert_ne!(
            SubjectHash::compute(&a),
            SubjectHash::compute(&b),
            "length prefix must disambiguate same-byte-sum Set contents"
        );
    }

    #[test]
    fn attr_set_empty_vs_single_empty_string_differ() {
        let mut attrs_empty = BTreeMap::new();
        let _ = attrs_empty.insert("k".to_string(), AttrValue::Set(vec![]));
        let mut attrs_single_empty = BTreeMap::new();
        let _ = attrs_single_empty.insert("k".to_string(), AttrValue::Set(vec![String::new()]));
        let a = identity("alice", &[], attrs_empty, None);
        let b = identity("alice", &[], attrs_single_empty, None);
        assert_ne!(SubjectHash::compute(&a), SubjectHash::compute(&b));
    }

    #[test]
    fn spiffe_some_empty_vs_none_differ() {
        // `None` writes the 0 discriminant; `Some("")` writes the 1
        // discriminant then an empty string. Without the discriminant
        // they would collide.
        let a = identity("alice", &[], BTreeMap::new(), None);
        let b = identity("alice", &[], BTreeMap::new(), Some(""));
        assert_ne!(SubjectHash::compute(&a), SubjectHash::compute(&b));
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod model_tests {
    //! Defensive pins on the small surrounding model types
    //! (`DecisionOutcome` helpers, `Resource::kind_tag`, `Action` and
    //! `Obligation` serde contract, `CacheStats` derives, and the
    //! `Subject` borrow adapters). These types are small but each one
    //! has load-bearing invariants that the existing
    //! `subject_hash_tests` suite does not cover.

    use std::collections::BTreeSet;

    use super::*;

    // ── DecisionOutcome helpers ────────────────────────────────────

    #[test]
    fn decision_outcome_allow_is_allow_with_no_rule_no_obligations() {
        // The `allow()` shorthand is the canonical "policy allows with
        // no side-effects" return from group-ACL / Cedar backends that
        // don't emit obligations. Pin that it yields precisely
        // `Decision::Allow` with both optional fields in their empty
        // state — if a refactor flipped the defaults (e.g. seeded a
        // bogus `rule_id`), downstream cache code would key decisions
        // on synthetic rule identifiers that never existed.
        let o = DecisionOutcome::allow();
        assert_eq!(o.decision, Decision::Allow);
        assert!(o.rule_id.is_none());
        assert!(o.obligations.is_empty());
        assert!(o.is_allow());
    }

    #[test]
    fn decision_outcome_deny_is_deny_with_no_rule_no_obligations() {
        // Mirror of the allow test — pin the deny shape. `is_allow()`
        // must return false on a deny outcome; a bug there would let
        // denied traffic pass at every call site that short-circuits on
        // `if outcome.is_allow()`.
        let o = DecisionOutcome::deny();
        assert_eq!(o.decision, Decision::Deny);
        assert!(o.rule_id.is_none());
        assert!(o.obligations.is_empty());
        assert!(!o.is_allow());
    }

    #[test]
    fn decision_outcome_is_allow_ignores_rule_id_and_obligations() {
        // `is_allow()` must inspect only the verdict, not the
        // obligations or `rule_id`. If the helper ever incorporated
        // obligation emptiness into the check (e.g. `|| obligations.is_empty()`),
        // an explicit allow with `MaskPoint` would stop counting as an
        // allow — masking would silently fall back to "deny" semantics
        // in every call site.
        let allow_with_rule = DecisionOutcome {
            decision: Decision::Allow,
            rule_id: Some("rule-7".into()),
            obligations: vec![Obligation::MaskPoint, Obligation::AuditExtended],
        };
        assert!(allow_with_rule.is_allow());
        let deny_with_rule = DecisionOutcome {
            decision: Decision::Deny,
            rule_id: Some("rule-8".into()),
            obligations: vec![Obligation::TagClassified],
        };
        assert!(!deny_with_rule.is_allow());
    }

    // ── Resource::kind_tag ─────────────────────────────────────────

    #[test]
    fn resource_kind_tag_matches_documented_wire_values() {
        // `kind_tag` is the discriminant that compiled policies use to
        // bucket rules by resource kind. The mapping Direct=0, Group=1,
        // Broadcast=2, Federation=3, NatsSubject=4 is load-bearing — a
        // silent reshuffle would place rules into wrong buckets and
        // cause wholesale allow/deny flips in production without any
        // compile failure. Pin each mapping concretely.
        assert_eq!(Resource::Direct { target_cn: "alice" }.kind_tag(), 0);
        assert_eq!(Resource::Group { group: "ops" }.kind_tag(), 1);
        assert_eq!(Resource::Broadcast.kind_tag(), 2);
        assert_eq!(Resource::Federation { peer_id: "peer1" }.kind_tag(), 3);
        assert_eq!(Resource::NatsSubject { subject: "a.b.c" }.kind_tag(), 4);
    }

    #[test]
    fn resource_kind_tags_are_all_distinct() {
        // Stronger invariant: the five kind tags must be pairwise
        // distinct. If two Resource variants were accidentally assigned
        // the same tag (e.g. via a refactor that reordered and lost an
        // increment), rules for one kind would fire on the other's
        // traffic. Computed distinctness-via-set.
        let tags: BTreeSet<u8> = [
            Resource::Direct { target_cn: "x" }.kind_tag(),
            Resource::Group { group: "x" }.kind_tag(),
            Resource::Broadcast.kind_tag(),
            Resource::Federation { peer_id: "x" }.kind_tag(),
            Resource::NatsSubject { subject: "x" }.kind_tag(),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            tags.len(),
            5,
            "all five kind tags must be distinct: {tags:?}"
        );
    }

    #[test]
    fn resource_kind_tag_is_independent_of_inner_fields() {
        // `kind_tag` keys only on the enum discriminant. Different
        // `target_cn` or `group` values must not shift the tag — if
        // they ever did, compiled rule bucketing would leak bucket
        // identity into subject/group lookups.
        assert_eq!(
            Resource::Direct { target_cn: "alice" }.kind_tag(),
            Resource::Direct { target_cn: "bob" }.kind_tag()
        );
        assert_eq!(
            Resource::Group { group: "ops" }.kind_tag(),
            Resource::Group { group: "admins" }.kind_tag()
        );
    }

    // ── Action + Obligation serde contract ──────────────────────────

    #[test]
    fn action_serde_round_trips_via_snake_case_wire_names() {
        // `rename_all = "snake_case"` is a wire contract with stored
        // policy JSON files: `send`, `receive`, `federate`, `publish`,
        // `subscribe`. A regression to `PascalCase` or `kebab-case`
        // would make every stored policy fail to parse. Pin both the
        // serialize and deserialize direction for all five variants.
        for (action, wire) in [
            (Action::Send, "\"send\""),
            (Action::Receive, "\"receive\""),
            (Action::Federate, "\"federate\""),
            (Action::Publish, "\"publish\""),
            (Action::Subscribe, "\"subscribe\""),
        ] {
            let ser = serde_json::to_string(&action).expect("serialize action");
            assert_eq!(ser, wire, "{action:?}");
            let de: Action = serde_json::from_str(wire).expect("deserialize action");
            assert_eq!(de, action);
        }
    }

    #[test]
    fn obligation_serde_round_trips_via_snake_case_wire_names() {
        // Same invariant as actions: obligation serialization is part
        // of the policy wire format. `MaskPoint` maps to `mask_point`,
        // etc. Pin the full mapping so a rename of the Rust variant
        // doesn't silently desynchronise from the policy files.
        for (obl, wire) in [
            (Obligation::MaskPoint, "\"mask_point\""),
            (Obligation::MaskPayload, "\"mask_payload\""),
            (Obligation::TagClassified, "\"tag_classified\""),
            (Obligation::AuditExtended, "\"audit_extended\""),
        ] {
            let ser = serde_json::to_string(&obl).expect("serialize obligation");
            assert_eq!(ser, wire, "{obl:?}");
            let de: Obligation = serde_json::from_str(wire).expect("deserialize obligation");
            assert_eq!(de, obl);
        }
    }

    #[test]
    fn action_rejects_unknown_wire_tag() {
        // A malformed policy file with an unknown action name must
        // fail deserialization — not silently coerce to a default.
        // Pin that `serde_json::from_str` returns `Err` for unknown
        // tags so `#[non_exhaustive]` growth remains a visible change.
        let res: Result<Action, _> = serde_json::from_str("\"admin\"");
        assert!(res.is_err(), "unknown action tag must be rejected");
    }

    #[test]
    fn obligation_rejects_unknown_wire_tag() {
        // Same as actions — unknown obligation tags must error rather
        // than fall back silently.
        let res: Result<Obligation, _> = serde_json::from_str("\"encrypt_body\"");
        assert!(res.is_err(), "unknown obligation tag must be rejected");
    }

    #[test]
    fn action_and_obligation_are_copy_and_hash() {
        // Compile-time pin: both types are `Copy + Hash + Eq` so they
        // can key HashMaps/HashSets and be moved freely on the
        // evaluation hot path without clone cost. A regression that
        // removed either bound (e.g. added a non-Copy field) would
        // fail this generic-function assertion.
        fn assert_copy_hash_eq<T: Copy + std::hash::Hash + Eq>() {}
        assert_copy_hash_eq::<Action>();
        assert_copy_hash_eq::<Obligation>();
        assert_copy_hash_eq::<Decision>();
    }

    // ── CacheStats ─────────────────────────────────────────────────

    #[test]
    fn cache_stats_default_is_zeros_and_copy_and_eq() {
        // `CacheStats` is returned from `PolicyEngine::cache_stats`
        // across crate boundaries. Its `Default`, `Copy`, and `Eq`
        // derives are the lightweight plumbing that lets callers
        // compare snapshots without borrowing. Pin the zero-initialised
        // shape and the derive set.
        let a = CacheStats::default();
        assert_eq!(a.hits, 0);
        assert_eq!(a.misses, 0);
        // Copy semantics: move and compare.
        let b = a;
        let c = a;
        assert_eq!(b, c);
        // Inequality when fields differ.
        let d = CacheStats { hits: 1, misses: 0 };
        assert_ne!(a, d);
    }

    // ── Subject borrow adapters ─────────────────────────────────────

    fn plaintext_identity_for_subject() -> Identity {
        let mut groups = BTreeSet::new();
        let _ = groups.insert("ops".to_string());
        Identity::plaintext("cn-alice".to_string(), groups).expect("valid plaintext")
    }

    #[test]
    fn subject_from_identity_borrows_every_field_verbatim() {
        // `Subject::from_identity` is the cold-path adapter used in
        // tests and one-shot evaluators. Pin that each field on the
        // resulting `Subject` points at the source `Identity`'s bytes
        // (CN, groups, attributes, fingerprint, SPIFFE). A regression
        // that swapped in a dropped `to_string()` would allocate on
        // every call — or worse, lose the tie-back for borrow-checked
        // slices on the hot path.
        let id = plaintext_identity_for_subject();
        let subj = Subject::from_identity(&id);
        // `id.cn` is `Arc<str>`; deref to the inner `str` slice and
        // compare addresses. Subject::from_identity stores `&id.cn`
        // (deref-coerced to `&str`), pointing at the same byte slice.
        assert!(std::ptr::eq(subj.cn, &*id.cn));
        assert!(std::ptr::eq(subj.groups, &id.groups));
        assert!(std::ptr::eq(subj.attributes, id.attributes.as_ref()));
        assert!(std::ptr::eq(subj.fingerprint, id.fingerprint.as_str()));
        assert!(subj.spiffe_id.is_none());
    }

    #[test]
    fn subject_with_hash_uses_provided_hash_verbatim() {
        // The hot path precomputes `SubjectHash` once per session and
        // reuses it. Pin that `with_hash` installs the caller-supplied
        // value without recomputing — a silent recompute would
        // reintroduce per-evaluation hashing cost.
        let id = plaintext_identity_for_subject();
        let sentinel = SubjectHash {
            primary: 0xDEAD_BEEF,
            secondary: 0xCAFE_F00D,
        };
        let subj = Subject::with_hash(&id, sentinel);
        assert_eq!(subj.subject_hash.primary, 0xDEAD_BEEF);
        assert_eq!(subj.subject_hash.secondary, 0xCAFE_F00D);
    }

    #[test]
    fn subject_compute_hash_matches_subject_hash_compute() {
        // `Subject::compute_hash` is the compatibility wrapper for
        // older bench code. It must delegate to `SubjectHash::compute`
        // rather than reimplement the hashing — otherwise the two
        // paths could drift and benches would measure different code
        // than production.
        let id = plaintext_identity_for_subject();
        assert_eq!(Subject::compute_hash(&id), SubjectHash::compute(&id));
    }

    #[test]
    fn subject_fingerprint_is_empty_for_plaintext_identity() {
        // Plaintext sessions carry an empty fingerprint. The Subject
        // adapter must pass that through verbatim — router code uses
        // `subject.fingerprint.is_empty()` to distinguish TLS from
        // non-TLS when emitting audit events. This is the symmetry
        // point with `plaintext.rs::session_identity_fingerprint_*`.
        let id = plaintext_identity_for_subject();
        let subj = Subject::from_identity(&id);
        assert!(subj.fingerprint.is_empty());
    }

    #[test]
    fn subject_hash_is_copy_and_eq_for_cache_keying() {
        // `SubjectHash` is copied into every `DecisionKey` in the
        // authz cache. Pin `Copy + Eq + Hash` so the cache can key
        // on the hash without clone cost.
        fn assert_bounds<T: Copy + Eq + std::hash::Hash>() {}
        assert_bounds::<SubjectHash>();
    }

    // ── Refs #882: canonical obligation chaining order ──────────────
    //
    // `Obligation::priority` and `Obligation::chain_sort_key` are the
    // load-bearing primitives the dispatcher uses to enforce the
    // documented 3-group ordering (Redactors → Classifiers/Taggers →
    // Auditors, alphabetical within each group). The tests below pin
    // the per-variant priority assignment, the alphabetical
    // tie-breaking, and the `(priority, debug_repr)` composition —
    // so a regression that demoted MaskPoint into group 2, or that
    // swapped the sort-key tuple ordering, fails here at the model
    // layer rather than only at the dispatcher integration site.

    /// Pin every known variant's group assignment. Group 1
    /// (Redactors) gets priority 0, Group 2 (Classifiers/Taggers)
    /// gets 1, Group 3 (Auditors) gets 2. A regression that
    /// reshuffled these would invert the canonical chaining order
    /// and silently reroute Receive-side classification before
    /// Send-side redaction.
    #[test]
    fn obligation_priority_pins_canonical_group_assignment() {
        assert_eq!(
            Obligation::MaskPoint.priority(),
            0,
            "MaskPoint must be Redactor (group 0)"
        );
        assert_eq!(
            Obligation::MaskPayload.priority(),
            0,
            "MaskPayload must be Redactor (group 0)"
        );
        assert_eq!(
            Obligation::TagClassified.priority(),
            1,
            "TagClassified must be Classifier/Tagger (group 1)"
        );
        assert_eq!(
            Obligation::AuditExtended.priority(),
            2,
            "AuditExtended must be Auditor (group 2)"
        );
    }

    /// `chain_sort_key` is `(priority, Debug-repr)` — primary key is
    /// the group, secondary is alphabetical. Pin the tuple shape so
    /// a regression that swapped the order (alphabetical first,
    /// group second) lands here. That regression would let
    /// `AuditExtended` outrank `MaskPoint` on the alphabetical
    /// component (`A` < `M`) and break the canonical chaining
    /// contract.
    #[test]
    fn obligation_chain_sort_key_is_priority_then_debug_repr() {
        let (mp_pri, mp_name) = Obligation::MaskPoint.chain_sort_key();
        assert_eq!(mp_pri, 0);
        assert_eq!(mp_name, "MaskPoint");

        let (mpl_pri, mpl_name) = Obligation::MaskPayload.chain_sort_key();
        assert_eq!(mpl_pri, 0);
        assert_eq!(mpl_name, "MaskPayload");

        let (tc_pri, tc_name) = Obligation::TagClassified.chain_sort_key();
        assert_eq!(tc_pri, 1);
        assert_eq!(tc_name, "TagClassified");

        let (ae_pri, ae_name) = Obligation::AuditExtended.chain_sort_key();
        assert_eq!(ae_pri, 2);
        assert_eq!(ae_name, "AuditExtended");
    }

    /// Within group 0 (Redactors) the sort key resolves
    /// alphabetically: `MaskPayload` < `MaskPoint` because
    /// `MaskP[a]…` precedes `MaskP[o]…`. A regression that ranked
    /// variants by enum-declaration order would swap these.
    #[test]
    fn obligation_chain_sort_key_orders_alphabetically_within_group() {
        // Group 0 alphabetical: MaskPayload < MaskPoint.
        assert!(
            Obligation::MaskPayload.chain_sort_key() < Obligation::MaskPoint.chain_sort_key(),
            "within group 0, MaskPayload must sort before MaskPoint (alphabetical)"
        );
        // Cross-group: every group-0 variant outranks every
        // group-1 / group-2 variant because priority dominates.
        assert!(
            Obligation::MaskPoint.chain_sort_key() < Obligation::TagClassified.chain_sort_key(),
            "group 0 (MaskPoint) must sort before group 1 (TagClassified)"
        );
        assert!(
            Obligation::TagClassified.chain_sort_key() < Obligation::AuditExtended.chain_sort_key(),
            "group 1 (TagClassified) must sort before group 2 (AuditExtended)"
        );
    }

    /// Stable sort on `chain_sort_key` reorders any input
    /// permutation into the canonical order. Pin the full
    /// permutation round-trip so a regression that returned an
    /// unstable / non-deterministic sort key surfaces here.
    #[test]
    fn obligation_chain_sort_key_canonicalizes_permutations() {
        let canonical = vec![
            Obligation::MaskPayload,   // group 0, alphabetically first
            Obligation::MaskPoint,     // group 0, alphabetically second
            Obligation::TagClassified, // group 1
            Obligation::AuditExtended, // group 2
        ];
        // Take a deliberately-scrambled permutation and run the
        // same stable sort the dispatcher uses.
        let mut scrambled = vec![
            Obligation::AuditExtended,
            Obligation::TagClassified,
            Obligation::MaskPoint,
            Obligation::MaskPayload,
        ];
        scrambled.sort_by_cached_key(Obligation::chain_sort_key);
        assert_eq!(scrambled, canonical);
    }
}
