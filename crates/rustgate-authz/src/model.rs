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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Action is permitted.
    Allow,
    /// Action is denied.
    Deny,
}

/// Side-effects that the dataplane must apply alongside an allow decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
}

impl<'a> Subject<'a> {
    /// Borrow an [`Identity`] as a [`Subject`] without cloning.
    pub fn from_identity(id: &'a Identity) -> Self {
        Self {
            cn: id.cn.as_str(),
            spiffe_id: id.spiffe_id.as_deref(),
            groups: &id.groups,
            attributes: id.attributes.as_ref(),
            fingerprint: id.fingerprint.as_str(),
        }
    }
}

/// The resource a subject is acting on.
#[derive(Debug)]
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
