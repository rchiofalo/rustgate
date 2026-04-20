// Copyright © 2026 Roberto Chiofalo.

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

    /// Warnings emitted during policy compilation.
    ///
    /// Returns messages about overly broad rules (e.g. allow + resource
    /// `any`, or an empty subject matcher). Backends that do not track
    /// compile-time warnings return an empty slice.
    fn compile_warnings(&self) -> &[SmolStr] {
        &[]
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

    fn compile_warnings(&self) -> &[SmolStr] {
        &self.compiled.compile_warnings
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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    //! Evaluation-shape and decision-cache tests for [`NativeEngine`].
    //!
    //! The engine is the hot path for every routed message. The parser
    //! and compiler tests pin the *structural* correctness of the
    //! compiled form; the tests here pin the *evaluation* contract:
    //! deny-first semantics across kind-specific and resource-any
    //! buckets, default-effect fall-through, obligation propagation on
    //! allow, decision-cache hit/miss accounting, policy-id stability,
    //! and the trait-method surface that `router.rs` consumes via
    //! `Arc<dyn PolicyEngine>`. A regression in any of these would be
    //! indistinguishable at the type level from a correct refactor, so
    //! only end-to-end pins catch it.

    use std::collections::{BTreeMap, BTreeSet};

    use rustgate_core::identity::Identity;
    use smol_str::SmolStr;

    use super::*;
    use crate::model::{Decision, Obligation};
    use crate::policy::{Effect, ResourceMatcher, Rule, RuleSet, SubjectMatcher};

    /// Build an identity for a TLS-authenticated subject with the
    /// supplied CN and group memberships. Every test uses the same
    /// shape so that differences in outcomes come from the rule set,
    /// not from the identity surface.
    fn identity(cn: &str, groups: &[&str]) -> Identity {
        let groups: BTreeSet<String> = groups.iter().map(|g| (*g).to_string()).collect();
        Identity::new(cn.to_string(), format!("{cn}-fp"), groups).expect("valid identity")
    }

    /// Construct a bare `Rule` with a stable id, effect, action,
    /// resource matcher, and an empty subject matcher. Obligations
    /// default to empty; tests that care about obligations build the
    /// rule inline rather than going through this helper.
    fn rule(
        id: &str,
        effect: Effect,
        action: Action,
        resource: ResourceMatcher,
        subject: SubjectMatcher,
    ) -> Rule {
        Rule {
            id: SmolStr::new(id),
            effect,
            action,
            resource,
            subject,
            obligations: Vec::new(),
        }
    }

    /// A subject matcher that is deliberately not match-all so that
    /// the compiler's "empty subject on allow" warning does not fire.
    /// Any single constraint that the test identity satisfies is fine.
    fn subject_cn(cn: &str) -> SubjectMatcher {
        SubjectMatcher {
            cn_eq: Some(cn.to_string()),
            ..Default::default()
        }
    }

    fn ruleset(default_effect: Effect, rules: Vec<Rule>) -> RuleSet {
        RuleSet {
            version: 1,
            default_effect,
            rules,
        }
    }

    #[test]
    fn empty_engine_is_deny_by_default() {
        // The `empty()` constructor is the safe-fallback used before the
        // first policy is loaded and as a default for tests. Its single
        // security contract is "deny everything." A refactor that
        // flipped the default_effect or shipped an accidental allow rule
        // would silently open the service up during the pre-load window.
        let engine = NativeEngine::empty();
        let id = identity("alice", &["ops"]);
        let subject = Subject::from_identity(&id);
        let outcome = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(
            outcome.rule_id.is_none(),
            "default-effect deny has no rule_id"
        );
        assert!(outcome.obligations.is_empty());
    }

    #[test]
    fn empty_engine_policy_id_is_64_char_hex() {
        // The empty ruleset still produces a stable sha256 hex id (or
        // the hand-constructed zero id if compilation ever fails). Pin
        // the width so a future refactor that switched to a truncated
        // id or a non-hex encoding — breaking downstream log filters —
        // fails here instead of silently drifting.
        let engine = NativeEngine::empty();
        let id = engine.policy_id();
        assert_eq!(id.len(), 64, "policy_id must be 64-char sha256 hex: {id}");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn allow_rule_returns_allow_with_rule_id() {
        // A single allow rule that matches the evaluation tuple must
        // surface its id so audit records and `decision_summary`
        // tracing can attribute the outcome to the exact rule. A
        // refactor that returned `rule_id: None` on allow would break
        // the audit trail even though the decision is still "correct".
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-alice-broadcast",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Broadcast,
                subject_cn("alice"),
            )],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);
        let outcome = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.rule_id.as_deref(), Some("allow-alice-broadcast"));
    }

    #[test]
    fn deny_rule_wins_over_later_allow() {
        // The compiler preserves rule order and the scanner short-
        // circuits on the first deny. Pin that a deny placed *before*
        // an otherwise-matching allow in the same bucket wins — this
        // is the "explicit deny" pattern most operator-authored
        // policies rely on. A refactor that reordered the scan (e.g.
        // grouping by effect) would invert this contract.
        let rules = ruleset(
            Effect::Allow,
            vec![
                rule(
                    "deny-alice",
                    Effect::Deny,
                    Action::Send,
                    ResourceMatcher::Broadcast,
                    subject_cn("alice"),
                ),
                rule(
                    "allow-alice",
                    Effect::Allow,
                    Action::Send,
                    ResourceMatcher::Broadcast,
                    subject_cn("alice"),
                ),
            ],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);
        let outcome = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(outcome.decision, Decision::Deny);
        assert_eq!(outcome.rule_id.as_deref(), Some("deny-alice"));
    }

    #[test]
    fn default_effect_deny_returned_when_no_rule_matches() {
        // No rule matches this tuple — the outcome must fall through
        // to `default_effect`. The default-deny path has no rule_id by
        // contract (nothing matched), so pinning `None` here protects
        // against a refactor that started synthesising a sentinel id.
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-bob",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Broadcast,
                subject_cn("bob"),
            )],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);
        let outcome = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome.rule_id.is_none());
    }

    #[test]
    fn default_effect_allow_returned_when_no_rule_matches() {
        // Mirror of the deny case — with `default_effect = Allow` and
        // no matching rule, the outcome must be Allow with no rule_id
        // and no obligations. This is the fail-open policy the
        // `--authz-fail-open` CLI flag relies on; a refactor that
        // forgot to apply the default_effect would silently deny
        // everything instead.
        let rules = ruleset(Effect::Allow, vec![]);
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);
        let outcome = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(outcome.decision, Decision::Allow);
        assert!(outcome.rule_id.is_none());
        assert!(outcome.obligations.is_empty());
    }

    #[test]
    fn allow_rule_propagates_obligations() {
        // Obligations are the allow-time side-effects the dataplane
        // must apply (mask coordinates, strip payload, emit extended
        // audit). The engine is the *only* place they are attached to
        // a decision; if this wiring is lost, the dataplane silently
        // skips masking on allow and classified data leaks.
        let mut r = rule(
            "allow-with-obligations",
            Effect::Allow,
            Action::Send,
            ResourceMatcher::Broadcast,
            subject_cn("alice"),
        );
        r.obligations = vec![Obligation::MaskPoint, Obligation::AuditExtended];
        let rules = ruleset(Effect::Deny, vec![r]);
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);
        let outcome = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(
            outcome.obligations,
            vec![Obligation::MaskPoint, Obligation::AuditExtended]
        );
    }

    #[test]
    fn deny_decision_never_carries_obligations() {
        // The docstring on `Obligation` says they apply on allow. Pin
        // that a deny decision produced via an explicit deny rule
        // never carries obligations even if the rule was authored with
        // them (operators sometimes copy-paste rule bodies). A
        // refactor that propagated obligations on deny would cause the
        // dataplane to mask data it had already refused to send,
        // wasting cycles and obscuring the deny verdict downstream.
        let mut r = rule(
            "deny-with-stray-obligations",
            Effect::Deny,
            Action::Send,
            ResourceMatcher::Broadcast,
            subject_cn("alice"),
        );
        r.obligations = vec![Obligation::MaskPoint];
        let rules = ruleset(Effect::Allow, vec![r]);
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);
        let outcome = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(
            outcome.obligations.is_empty(),
            "deny outcomes never carry obligations"
        );
    }

    #[test]
    fn any_resource_rule_matches_every_resource_kind() {
        // `ResourceMatcher::Any` is the wildcard that lives in the
        // `any_resource` map rather than a kind-specific bucket. A
        // single allow-any rule must match Direct, Group, Broadcast,
        // Federation, and NatsSubject alike — a refactor that forgot
        // to consult the any_resource bucket would silently fall
        // through to default-deny for every resource kind.
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-any",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Any,
                subject_cn("alice"),
            )],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);

        for resource in [
            Resource::Direct { target_cn: "bob" },
            Resource::Group { group: "ops" },
            Resource::Broadcast,
            Resource::Federation { peer_id: "peer-1" },
            Resource::NatsSubject { subject: "cot.x" },
        ] {
            let outcome = engine.evaluate(&subject, &resource, Action::Send);
            assert_eq!(
                outcome.decision,
                Decision::Allow,
                "any-resource allow must match {resource:?}"
            );
            assert_eq!(outcome.rule_id.as_deref(), Some("allow-any"));
        }
    }

    #[test]
    fn any_resource_deny_overrides_kind_specific_allow() {
        // The scanner evaluates the kind-specific bucket first and
        // then the any_resource bucket. A deny in the any_resource
        // bucket must short-circuit even after an allow has already
        // been found in the kind-specific bucket — this is the
        // "global deny list" pattern: one any-deny rule shuts off
        // access to every resource kind regardless of per-kind
        // allow rules below. A refactor that returned the first
        // allow before checking the any_resource deny would silently
        // invert this contract.
        let rules = ruleset(
            Effect::Allow,
            vec![
                rule(
                    "allow-broadcast-alice",
                    Effect::Allow,
                    Action::Send,
                    ResourceMatcher::Broadcast,
                    subject_cn("alice"),
                ),
                rule(
                    "global-deny-alice",
                    Effect::Deny,
                    Action::Send,
                    ResourceMatcher::Any,
                    subject_cn("alice"),
                ),
            ],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);
        let outcome = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(outcome.decision, Decision::Deny);
        assert_eq!(outcome.rule_id.as_deref(), Some("global-deny-alice"));
    }

    #[test]
    fn first_allow_in_kind_bucket_wins_over_second() {
        // The scanner stops at the first matching allow *within* a
        // bucket. Pin that the attributed rule_id is the first one —
        // this matters for audit because an operator reading "why was
        // this allowed" expects the earliest-matching rule, not the
        // last-seen one.
        let rules = ruleset(
            Effect::Deny,
            vec![
                rule(
                    "allow-first",
                    Effect::Allow,
                    Action::Send,
                    ResourceMatcher::Broadcast,
                    subject_cn("alice"),
                ),
                rule(
                    "allow-second",
                    Effect::Allow,
                    Action::Send,
                    ResourceMatcher::Broadcast,
                    subject_cn("alice"),
                ),
            ],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);
        let outcome = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.rule_id.as_deref(), Some("allow-first"));
    }

    #[test]
    fn cache_miss_then_hit_updates_stats() {
        // First evaluation is a miss; second evaluation with the same
        // tuple must be a hit. The decision cache is not observable by
        // inspection — the only operator-facing signal is the
        // hit/miss counter exported via `cache_stats()`. A refactor
        // that broke the cache key (for instance, forgetting to hash
        // the policy_epoch) would turn every evaluation into a miss,
        // which only shows up in this pair of counters.
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-alice",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Broadcast,
                subject_cn("alice"),
            )],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);

        let before = engine.cache_stats_direct();
        assert_eq!(before.hits, 0);
        assert_eq!(before.misses, 0);

        let first = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(first.decision, Decision::Allow);
        let after_first = engine.cache_stats_direct();
        assert_eq!(after_first.misses, 1, "first eval must be a miss");
        assert_eq!(after_first.hits, 0);

        let second = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(second.decision, Decision::Allow);
        let after_second = engine.cache_stats_direct();
        assert_eq!(after_second.misses, 1, "second eval with same key is a hit");
        assert_eq!(after_second.hits, 1);
    }

    #[test]
    fn cache_distinguishes_resource_kinds() {
        // The cache key includes a resource hash that folds in the
        // kind tag. Two evaluations on different resource kinds for
        // the same subject/action must be two misses — otherwise a
        // single policy outcome would be memoised across kinds, which
        // is a correctness bug (Direct send to Bob ≠ Broadcast). This
        // test is a direct regression guard for the `kind_tag().hash`
        // call in `resource_hash`.
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-any",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Any,
                subject_cn("alice"),
            )],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);

        engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        engine.evaluate(
            &subject,
            &Resource::Direct { target_cn: "bob" },
            Action::Send,
        );
        let stats = engine.cache_stats_direct();
        assert_eq!(
            stats.misses, 2,
            "different resource kinds must be cache misses"
        );
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn cache_distinguishes_actions() {
        // Mirror of the resource-kind test for the action axis. Two
        // evaluations with the same subject and resource but different
        // actions must both miss — otherwise Allow-on-Send would
        // leak to Receive.
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-any",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Any,
                subject_cn("alice"),
            )],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);

        engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        engine.evaluate(&subject, &Resource::Broadcast, Action::Receive);
        let stats = engine.cache_stats_direct();
        assert_eq!(stats.misses, 2, "different actions must be cache misses");
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn trait_cache_stats_returns_some_for_native_engine() {
        // The `PolicyEngine::cache_stats` trait method defaults to
        // `None` so backends without a cache (e.g. Cedar) can opt out.
        // `NativeEngine` must override it to return `Some(..)` — the
        // router uses the presence of `Some` to decide whether to
        // export Prometheus hit/miss gauges. A refactor that removed
        // the override would cause the gauges to disappear silently.
        let engine = NativeEngine::empty();
        let stats = PolicyEngine::cache_stats(&engine);
        assert!(stats.is_some(), "NativeEngine must override cache_stats");
    }

    #[test]
    fn compile_warnings_surface_allow_plus_any_resource() {
        // The compiler emits a warning when an allow rule uses
        // `ResourceMatcher::Any` because that matches every resource
        // kind — usually an over-broad authorship mistake. The
        // warning is exposed via both the inherent `compile_warnings`
        // method and the trait-method with the same name. Operators
        // (and the authz-reloader tracing output) rely on this — a
        // refactor that stopped recording the warning would leave
        // the over-broad rule silently active.
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-any-federate",
                Effect::Allow,
                Action::Federate,
                ResourceMatcher::Any,
                subject_cn("alice"),
            )],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let inherent = engine.compile_warnings();
        let trait_side: &[SmolStr] = PolicyEngine::compile_warnings(&engine);
        assert_eq!(inherent, trait_side, "inherent and trait view must agree");
        assert!(
            inherent.iter().any(|w| w.contains("allow-any-federate")),
            "warning must name the offending rule: {inherent:?}"
        );
        assert!(
            inherent.iter().any(|w| w.contains("any")),
            "warning must mention the `any` resource kind: {inherent:?}"
        );
    }

    #[test]
    fn compile_warnings_surface_empty_subject_allow() {
        // The second compile-warning category: an allow rule with a
        // vacuously-empty subject matcher matches every subject, which
        // is almost always unintended (the author usually meant to
        // restrict the rule to a group or CN). Pin that the engine
        // surfaces this warning — see #622.
        let mut r = rule(
            "allow-everyone",
            Effect::Allow,
            Action::Send,
            ResourceMatcher::Broadcast,
            SubjectMatcher::default(),
        );
        r.obligations = Vec::new();
        let rules = ruleset(Effect::Deny, vec![r]);
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let warnings = engine.compile_warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("allow-everyone") && w.contains("subject")),
            "warning must name the rule and mention the subject footgun: {warnings:?}"
        );
    }

    #[test]
    fn policy_id_differs_between_distinct_rulesets() {
        // The policy_id is a SHA-256 over the canonical JSON of the
        // rule set — it is the identifier that audit records and
        // authz-reload tracing use to correlate a decision with the
        // exact policy that produced it. Two distinct rule sets must
        // produce distinct ids; a refactor that keyed the id only on
        // `version` (or used a non-collision-resistant hash) would
        // silently collapse distinct policies into the same
        // correlation bucket.
        let a = ruleset(Effect::Deny, vec![]);
        let b = ruleset(
            Effect::Deny,
            vec![rule(
                "r1",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Broadcast,
                subject_cn("alice"),
            )],
        );
        let engine_a = NativeEngine::new(a).expect("valid ruleset compiles");
        let engine_b = NativeEngine::new(b).expect("valid ruleset compiles");
        assert_ne!(
            engine_a.policy_id(),
            engine_b.policy_id(),
            "distinct rule sets must have distinct policy ids"
        );
    }

    #[test]
    fn policy_id_is_stable_across_engine_instances() {
        // Same canonical bytes → same id. This is the flip side of
        // the distinct-rulesets test and it's what lets an operator
        // confirm via logs that two rustgate processes are running
        // the same policy.
        let rules = || {
            ruleset(
                Effect::Deny,
                vec![rule(
                    "r1",
                    Effect::Allow,
                    Action::Send,
                    ResourceMatcher::Broadcast,
                    subject_cn("alice"),
                )],
            )
        };
        let engine_a = NativeEngine::new(rules()).expect("valid ruleset compiles");
        let engine_b = NativeEngine::new(rules()).expect("valid ruleset compiles");
        assert_eq!(
            engine_a.policy_id(),
            engine_b.policy_id(),
            "identical rule sets must have identical policy ids"
        );
    }

    #[test]
    fn with_cache_capacity_is_chainable_and_evaluates() {
        // `with_cache_capacity` is the one builder method on
        // `NativeEngine`. It takes `self` and returns `Self` so tests
        // and benches can chain it after `new`. Pin that the chained
        // engine still evaluates correctly — a refactor that forgot
        // to carry `self.compiled` through would break every chained
        // construction.
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-alice",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Broadcast,
                subject_cn("alice"),
            )],
        );
        let engine = NativeEngine::new(rules)
            .expect("valid ruleset compiles")
            .with_cache_capacity(4, 8);
        let id = identity("alice", &[]);
        let subject = Subject::from_identity(&id);
        let outcome = engine.evaluate(&subject, &Resource::Broadcast, Action::Send);
        assert_eq!(outcome.decision, Decision::Allow);
    }

    #[test]
    fn policy_engine_is_object_safe_and_send_sync() {
        // `PolicyEngine` is consumed through `Arc<dyn PolicyEngine>`
        // in `rustgate-transport::router`. The trait must therefore
        // be object-safe AND Send + Sync + 'static. A future refactor
        // that added a non-object-safe method (e.g. one taking
        // `Self: Sized` generics) would fail to compile here rather
        // than much further downstream at the router call site where
        // the error message is much harder to diagnose.
        fn assert_dyn_send_sync<T: Send + Sync + ?Sized>() {}
        assert_dyn_send_sync::<dyn PolicyEngine>();
        let _boxed: Box<dyn PolicyEngine> = Box::new(NativeEngine::empty());
    }

    #[test]
    fn subject_hash_drives_cache_separation_between_identities() {
        // The cache key's subject component is the 128-bit
        // `SubjectHash`, not the raw CN. Two distinct identities
        // evaluated against the same rule must both miss because
        // their subject hashes differ. This is indirect evidence
        // that the cache keying actually uses the subject hash and
        // not (say) the `Subject::cn` pointer.
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-ops-group",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Broadcast,
                SubjectMatcher {
                    groups_any_of: vec!["ops".to_string()],
                    ..Default::default()
                },
            )],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        let alice = identity("alice", &["ops"]);
        let bob = identity("bob", &["ops"]);
        let s_alice = Subject::from_identity(&alice);
        let s_bob = Subject::from_identity(&bob);

        engine.evaluate(&s_alice, &Resource::Broadcast, Action::Send);
        engine.evaluate(&s_bob, &Resource::Broadcast, Action::Send);
        let stats = engine.cache_stats_direct();
        assert_eq!(
            stats.misses, 2,
            "distinct identities must be distinct cache keys"
        );
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn compile_warnings_empty_for_narrow_policy() {
        // Flip side of the two compile-warning tests: a well-scoped
        // policy emits no warnings. Pin that a clean policy returns
        // an empty slice so a refactor that started emitting spurious
        // warnings (polluting operator logs with false positives)
        // fails here.
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-alice-broadcast",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Broadcast,
                subject_cn("alice"),
            )],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");
        assert!(
            engine.compile_warnings().is_empty(),
            "narrow policy must produce no compile warnings"
        );
    }

    #[test]
    fn evaluate_uses_attribute_predicates_via_subject_matcher() {
        // The attribute_eq path on SubjectMatcher lives in the
        // compiled form and the runtime matcher in `compile.rs`; the
        // engine consumes it transparently. Pin that a rule gated on
        // an attribute fires only for subjects carrying that
        // attribute — evidence that the engine wires
        // `Subject::attributes` through to the compiled predicate.
        let mut attr_eq = BTreeMap::new();
        attr_eq.insert(
            "clearance".to_string(),
            serde_json::Value::String("secret".to_string()),
        );
        let rules = ruleset(
            Effect::Deny,
            vec![rule(
                "allow-cleared",
                Effect::Allow,
                Action::Send,
                ResourceMatcher::Broadcast,
                SubjectMatcher {
                    attribute_eq: attr_eq,
                    ..Default::default()
                },
            )],
        );
        let engine = NativeEngine::new(rules).expect("valid ruleset compiles");

        let mut cleared = identity("alice", &[]);
        let mut attrs: BTreeMap<String, rustgate_core::AttrValue> = BTreeMap::new();
        attrs.insert(
            "clearance".to_string(),
            rustgate_core::AttrValue::Str("secret".to_string()),
        );
        cleared = cleared.with_attributes(attrs);
        let uncleared = identity("bob", &[]);

        let s_cleared = Subject::from_identity(&cleared);
        let s_uncleared = Subject::from_identity(&uncleared);

        let cleared_outcome = engine.evaluate(&s_cleared, &Resource::Broadcast, Action::Send);
        let uncleared_outcome = engine.evaluate(&s_uncleared, &Resource::Broadcast, Action::Send);
        assert_eq!(cleared_outcome.decision, Decision::Allow);
        assert_eq!(uncleared_outcome.decision, Decision::Deny);
    }
}
