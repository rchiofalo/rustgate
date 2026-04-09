//! Compile a [`RuleSet`] into a bucketed decision table for fast evaluation.
//!
//! The compiled form groups rules by `(action, resource_kind)`. At evaluation
//! time the engine performs a single hash lookup and linearly scans the
//! resulting slice. All string allocations and JSON-value decoding happen
//! here, at compile time, so the hot path does no heap work.

use ahash::AHashMap;
use sha2::{Digest, Sha256};
use smol_str::SmolStr;

use crate::error::AuthzError;
use crate::model::{Action, Obligation, Resource, Subject};
use crate::parser::validate;
use crate::policy::{Effect, ResourceMatcher, Rule, RuleSet, SubjectMatcher};

/// Hash key used to bucket rules during compilation and lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct BucketKey {
    pub(crate) action: Action,
    pub(crate) resource_kind: u8,
}

/// Compiled attribute-equality predicate. Values are decoded once at
/// compile time to avoid per-evaluation JSON decoding.
#[derive(Debug, Clone)]
pub(crate) enum CompiledAttrValue {
    Str(String),
    Int(i64),
    Bool(bool),
    /// Every listed element must be present in the subject's `Set` attr.
    SubsetOfSet(Vec<String>),
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledSubjectPred {
    cn_eq: Option<String>,
    groups_any_of: Vec<String>,
    groups_all_of: Vec<String>,
    spiffe_prefix: Option<String>,
    attribute_eq: Vec<(String, CompiledAttrValue)>,
}

#[derive(Debug, Clone)]
pub(crate) enum CompiledResourcePred {
    DirectAny,
    DirectEq(String),
    GroupEq(String),
    Broadcast,
    FederationAny,
    FederationEq(String),
    NatsExact(String),
    NatsPrefix(String),
    Any,
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledRule {
    pub(crate) id: SmolStr,
    pub(crate) effect: Effect,
    pub(crate) resource_predicate: CompiledResourcePred,
    pub(crate) subject_predicate: CompiledSubjectPred,
    pub(crate) obligations: Vec<Obligation>,
}

/// A compiled, ready-to-evaluate policy.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub(crate) policy_id: SmolStr,
    #[allow(dead_code)]
    pub(crate) epoch: u32,
    pub(crate) default_effect: Effect,
    pub(crate) buckets: AHashMap<BucketKey, Vec<CompiledRule>>,
    /// Rules with `ResourceMatcher::Any` must be evaluated for every action
    /// the rule targets, regardless of resource kind — tracked separately.
    pub(crate) any_resource: AHashMap<Action, Vec<CompiledRule>>,
}

impl RuleSet {
    /// Validate and compile this rule set into a [`CompiledPolicy`].
    pub fn compile(&self) -> Result<CompiledPolicy, AuthzError> {
        validate(self)?;

        let policy_id = compute_policy_id(self)?;

        let mut buckets: AHashMap<BucketKey, Vec<CompiledRule>> = AHashMap::new();
        let mut any_resource: AHashMap<Action, Vec<CompiledRule>> = AHashMap::new();

        for rule in &self.rules {
            let compiled = compile_rule(rule)?;
            match &rule.resource {
                ResourceMatcher::Any => {
                    any_resource.entry(rule.action).or_default().push(compiled);
                }
                other => {
                    let key = BucketKey {
                        action: rule.action,
                        resource_kind: resource_kind_tag(other),
                    };
                    buckets.entry(key).or_default().push(compiled);
                }
            }
        }

        Ok(CompiledPolicy {
            policy_id,
            epoch: 0,
            default_effect: self.default_effect,
            buckets,
            any_resource,
        })
    }
}

fn resource_kind_tag(m: &ResourceMatcher) -> u8 {
    match m {
        ResourceMatcher::Direct { .. } => 0,
        ResourceMatcher::Group { .. } => 1,
        ResourceMatcher::Broadcast => 2,
        ResourceMatcher::Federation { .. } => 3,
        ResourceMatcher::NatsSubject { .. } => 4,
        ResourceMatcher::Any => u8::MAX,
    }
}

fn compile_rule(rule: &Rule) -> Result<CompiledRule, AuthzError> {
    let resource_predicate = match &rule.resource {
        ResourceMatcher::Direct { target_cn: None } => CompiledResourcePred::DirectAny,
        ResourceMatcher::Direct {
            target_cn: Some(cn),
        } => CompiledResourcePred::DirectEq(cn.clone()),
        ResourceMatcher::Group { group } => CompiledResourcePred::GroupEq(group.clone()),
        ResourceMatcher::Broadcast => CompiledResourcePred::Broadcast,
        ResourceMatcher::Federation { peer_id: None } => CompiledResourcePred::FederationAny,
        ResourceMatcher::Federation {
            peer_id: Some(peer),
        } => CompiledResourcePred::FederationEq(peer.clone()),
        ResourceMatcher::NatsSubject { subject_pattern } => {
            if let Some(prefix) = subject_pattern.strip_suffix('*') {
                CompiledResourcePred::NatsPrefix(prefix.to_string())
            } else {
                CompiledResourcePred::NatsExact(subject_pattern.clone())
            }
        }
        ResourceMatcher::Any => CompiledResourcePred::Any,
    };

    let subject_predicate = compile_subject(&rule.subject)?;

    Ok(CompiledRule {
        id: rule.id.clone(),
        effect: rule.effect,
        resource_predicate,
        subject_predicate,
        obligations: rule.obligations.clone(),
    })
}

fn compile_subject(s: &SubjectMatcher) -> Result<CompiledSubjectPred, AuthzError> {
    let mut attribute_eq = Vec::with_capacity(s.attribute_eq.len());
    for (k, v) in &s.attribute_eq {
        let compiled = match v {
            serde_json::Value::String(s) => CompiledAttrValue::Str(s.clone()),
            serde_json::Value::Bool(b) => CompiledAttrValue::Bool(*b),
            serde_json::Value::Number(n) => match n.as_i64() {
                Some(i) => CompiledAttrValue::Int(i),
                None => {
                    return Err(AuthzError::validation(
                        "subject.attribute_eq",
                        format!("attribute `{k}` must be an integer, got {n}"),
                    ));
                }
            },
            serde_json::Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        serde_json::Value::String(s) => out.push(s.clone()),
                        _ => {
                            return Err(AuthzError::validation(
                                "subject.attribute_eq",
                                format!("attribute `{k}` array entries must be strings"),
                            ));
                        }
                    }
                }
                CompiledAttrValue::SubsetOfSet(out)
            }
            other => {
                return Err(AuthzError::validation(
                    "subject.attribute_eq",
                    format!("attribute `{k}` has unsupported JSON type: {other}"),
                ));
            }
        };
        attribute_eq.push((k.clone(), compiled));
    }

    Ok(CompiledSubjectPred {
        cn_eq: s.cn_eq.clone(),
        groups_any_of: s.groups_any_of.clone(),
        groups_all_of: s.groups_all_of.clone(),
        spiffe_prefix: s.spiffe_prefix.clone(),
        attribute_eq,
    })
}

fn compute_policy_id(set: &RuleSet) -> Result<SmolStr, AuthzError> {
    // Canonicalize by serializing through serde_json with sorted keys.
    // `serde_json::to_vec` preserves BTreeMap order; all other fields are
    // positional, so this yields a stable byte representation.
    let bytes = serde_json::to_vec(set)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(SmolStr::new(hex))
}

impl CompiledResourcePred {
    pub(crate) fn matches(&self, resource: &Resource<'_>) -> bool {
        match (self, resource) {
            (CompiledResourcePred::Any, _) => true,
            (CompiledResourcePred::DirectAny, Resource::Direct { .. }) => true,
            (CompiledResourcePred::DirectEq(want), Resource::Direct { target_cn }) => {
                want == target_cn
            }
            (CompiledResourcePred::GroupEq(want), Resource::Group { group }) => want == group,
            (CompiledResourcePred::Broadcast, Resource::Broadcast) => true,
            (CompiledResourcePred::FederationAny, Resource::Federation { .. }) => true,
            (CompiledResourcePred::FederationEq(want), Resource::Federation { peer_id }) => {
                want == peer_id
            }
            (CompiledResourcePred::NatsExact(want), Resource::NatsSubject { subject }) => {
                want == subject
            }
            (CompiledResourcePred::NatsPrefix(prefix), Resource::NatsSubject { subject }) => {
                subject.starts_with(prefix.as_str())
            }
            _ => false,
        }
    }
}

impl CompiledSubjectPred {
    pub(crate) fn matches(&self, subject: &Subject<'_>) -> bool {
        if let Some(want) = &self.cn_eq
            && want != subject.cn
        {
            return false;
        }

        if !self.groups_any_of.is_empty()
            && !self
                .groups_any_of
                .iter()
                .any(|g| subject.groups.contains(g.as_str()))
        {
            return false;
        }

        if !self
            .groups_all_of
            .iter()
            .all(|g| subject.groups.contains(g.as_str()))
        {
            return false;
        }

        if let Some(prefix) = &self.spiffe_prefix {
            match subject.spiffe_id {
                Some(id) if id.starts_with(prefix.as_str()) => {}
                _ => return false,
            }
        }

        for (key, want) in &self.attribute_eq {
            let Some(have) = subject.attributes.get(key) else {
                return false;
            };
            if !attr_matches(want, have) {
                return false;
            }
        }

        true
    }
}

fn attr_matches(want: &CompiledAttrValue, have: &rustgate_core::AttrValue) -> bool {
    use rustgate_core::AttrValue;
    match (want, have) {
        (CompiledAttrValue::Str(w), AttrValue::Str(h)) => w == h,
        (CompiledAttrValue::Int(w), AttrValue::Int(h)) => w == h,
        (CompiledAttrValue::Bool(w), AttrValue::Bool(h)) => w == h,
        (CompiledAttrValue::SubsetOfSet(needles), AttrValue::Set(haystack)) => {
            needles.iter().all(|n| haystack.iter().any(|h| h == n))
        }
        _ => false,
    }
}
