//! Policy engine trait and native in-process implementation.

use crate::compile::{BucketKey, CompiledPolicy, CompiledRule};
use crate::error::AuthzError;
use crate::model::{Action, Decision, DecisionOutcome, Resource, Subject};
use crate::policy::{Effect, RuleSet};

/// A policy engine evaluates a `(subject, resource, action)` tuple.
///
/// Implementations must be `Send + Sync + 'static` so they can be shared
/// across the dataplane via `Arc`.
pub trait PolicyEngine: Send + Sync + 'static {
    /// Evaluate the policy and return a [`DecisionOutcome`].
    fn evaluate(
        &self,
        subject: &Subject<'_>,
        resource: &Resource<'_>,
        action: Action,
    ) -> DecisionOutcome;

    /// Stable policy identifier (sha256 hex of the canonical rule set).
    fn policy_id(&self) -> &str;
}

/// In-process policy engine backed by a [`CompiledPolicy`].
#[derive(Debug, Clone)]
pub struct NativeEngine {
    compiled: CompiledPolicy,
}

impl NativeEngine {
    /// Compile `rules` and build a new engine.
    pub fn new(rules: RuleSet) -> Result<Self, AuthzError> {
        let compiled = rules.compile()?;
        Ok(Self { compiled })
    }

    /// Construct an empty, deny-by-default engine. Useful for tests and as
    /// a safe fallback before the first policy is loaded.
    pub fn empty() -> Self {
        let rules = RuleSet {
            version: 1,
            default_effect: Effect::Deny,
            rules: Vec::new(),
        };
        // Compilation of a trivially-valid empty ruleset cannot fail; fall
        // back to a hand-constructed `CompiledPolicy` if it ever does so we
        // stay panic-free per workspace lint rules.
        match rules.compile() {
            Ok(compiled) => Self { compiled },
            Err(_) => Self {
                compiled: CompiledPolicy {
                    policy_id: smol_str::SmolStr::new(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ),
                    epoch: 0,
                    default_effect: Effect::Deny,
                    buckets: ahash::AHashMap::new(),
                    any_resource: ahash::AHashMap::new(),
                },
            },
        }
    }
}

impl PolicyEngine for NativeEngine {
    fn evaluate(
        &self,
        subject: &Subject<'_>,
        resource: &Resource<'_>,
        action: Action,
    ) -> DecisionOutcome {
        let key = BucketKey {
            action,
            resource_kind: resource.kind_tag(),
        };

        let mut allow_hit: Option<&CompiledRule> = None;

        // Scan kind-specific bucket first, then the resource-any bucket.
        if let Some(bucket) = self.compiled.buckets.get(&key) {
            match scan(bucket, subject, resource) {
                ScanResult::Deny(rule) => return deny_from(rule),
                ScanResult::Allow(rule) => allow_hit = Some(rule),
                ScanResult::None => {}
            }
        }

        if let Some(bucket) = self.compiled.any_resource.get(&action) {
            match scan(bucket, subject, resource) {
                ScanResult::Deny(rule) => return deny_from(rule),
                ScanResult::Allow(rule) => {
                    if allow_hit.is_none() {
                        allow_hit = Some(rule);
                    }
                }
                ScanResult::None => {}
            }
        }

        if let Some(rule) = allow_hit {
            return DecisionOutcome {
                decision: Decision::Allow,
                rule_id: Some(rule.id.clone()),
                obligations: rule.obligations.clone(),
            };
        }

        match self.compiled.default_effect {
            Effect::Allow => DecisionOutcome::allow(),
            Effect::Deny => DecisionOutcome::deny(),
        }
    }

    fn policy_id(&self) -> &str {
        self.compiled.policy_id.as_str()
    }
}

enum ScanResult<'a> {
    Allow(&'a CompiledRule),
    Deny(&'a CompiledRule),
    None,
}

fn scan<'a>(
    bucket: &'a [CompiledRule],
    subject: &Subject<'_>,
    resource: &Resource<'_>,
) -> ScanResult<'a> {
    let mut first_allow: Option<&CompiledRule> = None;
    for rule in bucket {
        if !rule.resource_predicate.matches(resource) {
            continue;
        }
        if !rule.subject_predicate.matches(subject) {
            continue;
        }
        match rule.effect {
            Effect::Deny => return ScanResult::Deny(rule),
            Effect::Allow => {
                if first_allow.is_none() {
                    first_allow = Some(rule);
                }
            }
        }
    }
    match first_allow {
        Some(r) => ScanResult::Allow(r),
        None => ScanResult::None,
    }
}

fn deny_from(rule: &CompiledRule) -> DecisionOutcome {
    DecisionOutcome {
        decision: Decision::Deny,
        rule_id: Some(rule.id.clone()),
        obligations: Vec::new(),
    }
}
