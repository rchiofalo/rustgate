//! Policy AST: `RuleSet`, `Rule`, and their matcher types.
//!
//! This module defines the serde-serializable surface of an authorization
//! policy. The AST is deliberately concrete and closed: adding a new matcher
//! variant requires a code change in the parser and compiler so that the
//! dataplane evaluator remains allocation-free.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::model::{Action, Obligation};

/// A set of rules plus default effect. The wire format has a `version` field
/// to allow forward-compatible evolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    /// Schema version, currently `1`.
    pub version: u32,
    /// Effect returned when no rule matches. Defaults to `Deny`.
    #[serde(default = "default_effect_deny")]
    pub default_effect: Effect,
    /// Ordered list of rules. Order is preserved through compilation so
    /// explicit-deny-before-allow semantics are authoring-friendly.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

fn default_effect_deny() -> Effect {
    Effect::Deny
}

/// Per-rule effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Permit the action when this rule matches.
    Allow,
    /// Forbid the action when this rule matches.
    Deny,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Stable identifier used in decision outcomes and audit records.
    pub id: SmolStr,
    /// Rule effect.
    pub effect: Effect,
    /// Action this rule governs.
    pub action: Action,
    /// Resource predicate.
    pub resource: ResourceMatcher,
    /// Subject predicate. An empty matcher matches any subject.
    pub subject: SubjectMatcher,
    /// Obligations to apply on allow outcomes.
    #[serde(default)]
    pub obligations: Vec<Obligation>,
}

/// Resource-side matcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceMatcher {
    /// Match a direct send. `target_cn = None` matches any target CN.
    Direct {
        /// Optional target CN to match exactly.
        #[serde(default)]
        target_cn: Option<String>,
    },
    /// Match a group send by group name.
    Group {
        /// Group name to match exactly.
        group: String,
    },
    /// Match a broadcast.
    Broadcast,
    /// Match a federation link. `peer_id = None` matches any peer.
    Federation {
        /// Optional peer ID to match exactly.
        #[serde(default)]
        peer_id: Option<String>,
    },
    /// Match a NATS subject. `subject_pattern` supports a trailing `*`
    /// wildcard (e.g. `cot.>` style prefixes would be written `cot.*`).
    NatsSubject {
        /// Subject pattern, literal or trailing-`*` wildcard.
        subject_pattern: String,
    },
    /// Match any resource kind.
    Any,
}

/// Subject-side matcher. All fields are AND-combined; an all-empty matcher
/// matches every subject.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectMatcher {
    /// Exact CN equality.
    #[serde(default)]
    pub cn_eq: Option<String>,
    /// Subject must be a member of at least one listed group.
    #[serde(default)]
    pub groups_any_of: Vec<String>,
    /// Subject must be a member of every listed group.
    #[serde(default)]
    pub groups_all_of: Vec<String>,
    /// SPIFFE ID must start with this literal prefix.
    #[serde(default)]
    pub spiffe_prefix: Option<String>,
    /// Every entry must match the subject's attribute of the same key.
    ///
    /// Accepted JSON value types:
    /// - string → compared against [`rustgate_core::AttrValue::Str`]
    /// - integer → compared against [`rustgate_core::AttrValue::Int`]
    /// - bool → compared against [`rustgate_core::AttrValue::Bool`]
    /// - array of strings → matches if every element is present in the
    ///   subject's corresponding [`rustgate_core::AttrValue::Set`]
    #[serde(default)]
    pub attribute_eq: BTreeMap<String, serde_json::Value>,
}
