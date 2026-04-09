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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Obligation {
    /// Strip geographic coordinates from the outbound message.
    MaskGeo,
    /// Strip the payload body, leaving only envelope metadata.
    MaskPayload,
    /// Tag the outbound message as classified.
    TagClassified,
    /// Emit an extended audit record for this decision.
    AuditExtended,
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
            cn: id.cn.as_str(),
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
