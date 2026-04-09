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
    /// Stable hash of `(cn, sorted groups, sorted attributes, spiffe_id)`.
    ///
    /// Callers on the hot path should precompute this once per session
    /// (see `Subject::compute_hash`) and reuse it via `Subject::with_hash`
    /// rather than paying the hashing cost on every evaluation.
    pub subject_hash: u64,
}

impl<'a> Subject<'a> {
    /// Borrow an [`Identity`] as a [`Subject`], computing `subject_hash`
    /// inline. Convenient for test/cold paths; the hot path should use
    /// `Subject::with_hash` and a session-cached hash.
    pub fn from_identity(id: &'a Identity) -> Self {
        let subject_hash = Self::compute_hash(id);
        Self::with_hash(id, subject_hash)
    }

    /// Borrow an [`Identity`] as a [`Subject`] using a caller-provided,
    /// precomputed hash. Zero-work per call on the dataplane hot path.
    pub fn with_hash(id: &'a Identity, subject_hash: u64) -> Self {
        Self {
            cn: id.cn.as_str(),
            spiffe_id: id.spiffe_id.as_deref(),
            groups: &id.groups,
            attributes: id.attributes.as_ref(),
            fingerprint: id.fingerprint.as_str(),
            subject_hash,
        }
    }

    /// Deterministic hash of the policy-relevant identity fields.
    ///
    /// Uses `ahash` seeded with fixed keys so the same identity yields
    /// the same hash for the lifetime of a process. The cache is
    /// per-process so we only need stability within a single run; a
    /// seeded construction avoids needing to store a `RandomState`
    /// alongside every cache.
    pub fn compute_hash(id: &Identity) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = ahash::AHasher::default();
        id.cn.hash(&mut h);
        // BTreeSet/BTreeMap already iterate in sorted order.
        for g in &id.groups {
            g.hash(&mut h);
        }
        for (k, v) in id.attributes.as_ref() {
            k.hash(&mut h);
            hash_attr(v, &mut h);
        }
        if let Some(s) = id.spiffe_id.as_deref() {
            s.hash(&mut h);
        }
        h.finish()
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
            3u8.hash(h);
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
