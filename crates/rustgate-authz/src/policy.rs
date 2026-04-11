// Copyright © 2026 Roberto Chiofalo.

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
///
/// `deny_unknown_fields` is load-bearing: a misspelled top-level key in an
/// operator-authored policy (e.g. `"default_efect": "deny"`) must fail the
/// parse rather than silently falling back to the serde default. Without
/// it, a typo can silently grant full permissions because the surrounding
/// rule array still parses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
///
/// `#[non_exhaustive]` — even though `allow`/`deny` is the standard
/// duality today, future additions such as `advise` or `indeterminate`
/// are possible. Requiring downstream matches to include a wildcard
/// arm keeps the wire-format open for backwards-compatible growth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Effect {
    /// Permit the action when this rule matches.
    Allow,
    /// Forbid the action when this rule matches.
    Deny,
}

/// A single policy rule.
///
/// `deny_unknown_fields` prevents typos like `subjeect` or `rsource` from
/// silently dropping the affected predicate and leaving a rule that
/// matches everything the author meant to restrict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
///
/// `deny_unknown_fields` guards against kind-tagged typos
/// (`target_ccn`, `peerr_id`, etc.) that would otherwise be accepted
/// as a no-op and silently widen the rule's reach.
///
/// `#[non_exhaustive]` mirrors [`crate::Resource`] — adding a new
/// resource kind should not break downstream match statements.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
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
///
/// `deny_unknown_fields` is critical: a rule like
/// `{"subject": {"groups_all_off": ["admin"]}}` (trailing `f`) would
/// otherwise parse into an empty predicate that matches *every*
/// subject, silently granting the rule to everyone. Same reasoning for
/// `cn_eeq`, `atribute_eq`, and every other field name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
