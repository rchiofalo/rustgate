//! Policy engine trait and native in-process implementation.

use smol_str::SmolStr;

use crate::cache::{DecisionCache, DecisionKey};
use crate::compile::{BucketKey, CompiledPolicy, CompiledRule};
use crate::error::AuthzError;
use crate::model::{Action, CacheStats, Decision, DecisionOutcome, Resource, Subject};
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

    /// Snapshot of the backend's decision-cache counters, if it has one.
    ///
    /// Backends without a cache (e.g. the optional Cedar backend) return
    /// `None`; [`NativeEngine`] returns `Some(CacheStats { .. })`.
    fn cache_stats(&self) -> Option<CacheStats> {
        None
    }
}

/// In-process policy engine backed by a [`CompiledPolicy`].
#[derive(Debug, Clone)]
pub struct NativeEngine {
    compiled: CompiledPolicy,
    cache: DecisionCache,
}

impl NativeEngine {
    /// Compile `rules` and build a new engine with the default decision cache.
    pub fn new(rules: RuleSet) -> Result<Self, AuthzError> {
        let compiled = rules.compile()?;
        Ok(Self {
            compiled,
            cache: DecisionCache::default(),
        })
    }

    /// Builder: override the decision cache sizing. `shards` is rounded
    /// up to a power of two.
    pub fn with_cache_capacity(mut self, shards: usize, per_shard: usize) -> Self {
        self.cache = DecisionCache::new(shards, per_shard);
        self
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
        let compiled = match rules.compile() {
            Ok(compiled) => compiled,
            Err(_) => CompiledPolicy {
                policy_id: smol_str::SmolStr::new(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ),
                epoch: 0,
                default_effect: Effect::Deny,
                buckets: ahash::AHashMap::new(),
                any_resource: ahash::AHashMap::new(),
                compile_warnings: Vec::new(),
            },
        };
        Self {
            compiled,
            cache: DecisionCache::default(),
        }
    }

    /// Warnings emitted during policy compilation.
    ///
    /// Returns messages about overly broad rules (e.g.
    /// `ResourceMatcher::Any` on an allow rule, or an empty subject
    /// matcher that matches all subjects). These are also emitted via
    /// `tracing::warn!` during compilation.
    pub fn compile_warnings(&self) -> &[SmolStr] {
        &self.compiled.compile_warnings
    }

    /// Snapshot of the decision cache hit/miss counters (inherent variant).
    ///
    /// Prefer the trait-object [`PolicyEngine::cache_stats`] entry point
    /// from callers holding an `Arc<dyn PolicyEngine>`; this inherent
    /// method exists so statically-typed callers (tests, benches) don't
    /// have to pay the `Option` unwrap.
    pub fn cache_stats_direct(&self) -> CacheStats {
        CacheStats {
            hits: self.cache.hits(),
            misses: self.cache.misses(),
        }
    }
}

fn resource_hash(resource: &Resource<'_>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = ahash::AHasher::default();
    resource.kind_tag().hash(&mut h);
    match resource {
        Resource::Direct { target_cn } => target_cn.hash(&mut h),
        Resource::Group { group } => group.hash(&mut h),
        Resource::Broadcast => {}
        Resource::Federation { peer_id } => peer_id.hash(&mut h),
        Resource::NatsSubject { subject } => subject.hash(&mut h),
    }
    h.finish()
}

impl PolicyEngine for NativeEngine {
    fn evaluate(
        &self,
        subject: &Subject<'_>,
        resource: &Resource<'_>,
        action: Action,
    ) -> DecisionOutcome {
        let cache_key = DecisionKey {
            subject_hash: subject.subject_hash,
            resource_hash: resource_hash(resource),
            action,
            policy_epoch: self.compiled.epoch,
        };
        if let Some(hit) = self.cache.get(&cache_key) {
            return hit;
        }

        let outcome = self.evaluate_uncached(subject, resource, action);
        self.cache.insert(cache_key, &outcome);
        outcome
    }

    fn policy_id(&self) -> &str {
        self.compiled.policy_id.as_str()
    }

    fn cache_stats(&self) -> Option<CacheStats> {
        Some(self.cache_stats_direct())
    }
}

impl NativeEngine {
    fn evaluate_uncached(
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
            let obligations = rule.obligations.clone();
            if !obligations.is_empty() {
                tracing::debug!(
                    rule_id = %rule.id,
                    obligation_count = obligations.len(),
                    obligations = ?obligations,
                    "allow decision carries obligations that the dataplane must enforce"
                );
            }
            return DecisionOutcome {
                decision: Decision::Allow,
                rule_id: Some(rule.id.clone()),
                obligations,
            };
        }

        match self.compiled.default_effect {
            Effect::Allow => DecisionOutcome::allow(),
            Effect::Deny => DecisionOutcome::deny(),
        }
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
