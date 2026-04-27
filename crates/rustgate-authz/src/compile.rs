// Copyright © 2026 Roberto Chiofalo.

//! Compile a [`RuleSet`] into a bucketed decision table for fast evaluation.
//!
//! The compiled form groups rules by `(action, resource_kind)`. At evaluation
//! time the engine performs a single hash lookup and linearly scans the
//! resulting slice. All string allocations and JSON-value decoding happen
//! here, at compile time, so the hot path does no heap work.

use std::sync::atomic::{AtomicU32, Ordering};

use ahash::AHashMap;
use sha2::{Digest, Sha256};
use smol_str::SmolStr;

/// Process-global monotonic counter: every compiled policy receives a
/// fresh epoch so decision caches keyed on the epoch automatically
/// invalidate on policy swap without any explicit clear.
static POLICY_EPOCH_COUNTER: AtomicU32 = AtomicU32::new(1);

fn next_policy_epoch() -> u32 {
    POLICY_EPOCH_COUNTER.fetch_add(1, Ordering::Relaxed)
}

use tracing::warn;

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
    spiffe_prefix: Option<SpiffePrefix>,
    attribute_eq: Vec<(String, CompiledAttrValue)>,
}

/// Segment-anchored SPIFFE prefix. `exact` is the trust-domain-or-path
/// form with any trailing slash trimmed, `with_slash` is the same
/// string with a mandatory `/` terminator. A SPIFFE ID matches if it
/// equals `exact` or starts with `with_slash`, which means
/// `spiffe://td/ops` will match itself and `spiffe://td/ops/api` but
/// not `spiffe://td/operator-evil`.
#[derive(Debug, Clone)]
pub(crate) struct SpiffePrefix {
    exact: String,
    with_slash: String,
}

impl SpiffePrefix {
    /// Return `true` if `id` is a segment-anchored extension of this
    /// prefix, or equals the prefix exactly.
    pub(crate) fn matches(&self, id: &str) -> bool {
        id == self.exact || id.starts_with(self.with_slash.as_str())
    }
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
    pub(crate) epoch: u32,
    pub(crate) default_effect: Effect,
    pub(crate) buckets: AHashMap<BucketKey, Vec<CompiledRule>>,
    /// Rules with `ResourceMatcher::Any` must be evaluated for every action
    /// the rule targets, regardless of resource kind — tracked separately.
    pub(crate) any_resource: AHashMap<Action, Vec<CompiledRule>>,
    /// Warnings emitted during compilation. Surfaced via
    /// [`crate::NativeEngine::compile_warnings`] so operators (and tests)
    /// can inspect them without capturing tracing output.
    pub(crate) compile_warnings: Vec<SmolStr>,
}

impl RuleSet {
    /// Validate and compile this rule set into a [`CompiledPolicy`].
    pub fn compile(&self) -> Result<CompiledPolicy, AuthzError> {
        validate(self)?;

        let policy_id = compute_policy_id(self)?;

        let mut buckets: AHashMap<BucketKey, Vec<CompiledRule>> = AHashMap::new();
        let mut any_resource: AHashMap<Action, Vec<CompiledRule>> = AHashMap::new();
        let mut compile_warnings: Vec<SmolStr> = Vec::new();

        for rule in &self.rules {
            let compiled = compile_rule(rule)?;

            // #621: ResourceMatcher::Any in allow rules matches every
            // resource kind, which is almost always broader than intended.
            // Warn so operators can confirm this is deliberate.
            if matches!(rule.resource, ResourceMatcher::Any) && rule.effect == Effect::Allow {
                let msg = SmolStr::new(format!(
                    "rule `{}`: allow + resource `any` matches all resource types; \
                     consider restricting to a specific resource kind",
                    rule.id,
                ));
                warn!(rule_id = %rule.id, "{msg}");
                compile_warnings.push(msg);
            }

            // #622: An empty SubjectMatcher vacuously matches every
            // subject. On an allow rule this silently grants access to
            // everyone, which is rarely intended. Deny rules with an
            // empty subject are fine (they block everyone by design).
            if rule.effect == Effect::Allow && compiled.subject_predicate.is_match_all() {
                let msg = SmolStr::new(format!(
                    "rule `{}`: allow rule with empty subject matcher matches all subjects; \
                     consider adding explicit subject constraints",
                    rule.id,
                ));
                warn!(rule_id = %rule.id, "{msg}");
                compile_warnings.push(msg);
            }

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
            epoch: next_policy_epoch(),
            default_effect: self.default_effect,
            buckets,
            any_resource,
            compile_warnings,
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
            // Reject obviously pathological patterns at compile time so
            // a typo cannot quietly become a match-everything rule:
            //
            //   - `""`        → would match every NATS subject via
            //                   `starts_with("")` after strip_suffix,
            //                   and is never what an operator means.
            //   - `"*"`       → strip_suffix('*') yields `""`, same
            //                   hazard. A rule author who wants "all
            //                   subjects" should use `{"kind": "any"}`
            //                   explicitly.
            //   - `">"`, `".>"`, etc. — NATS wildcards that this engine
            //                   does not implement. Silently treating
            //                   them as a literal match would surprise
            //                   any NATS-literate operator.
            if subject_pattern.is_empty() {
                return Err(AuthzError::validation(
                    "resource.subject_pattern",
                    "NATS subject_pattern must not be empty; use `kind: any` for match-all",
                ));
            }
            if subject_pattern == "*" {
                return Err(AuthzError::validation(
                    "resource.subject_pattern",
                    "NATS subject_pattern `*` alone is ambiguous; use `kind: any` for match-all",
                ));
            }
            if subject_pattern.contains('>') {
                return Err(AuthzError::validation(
                    "resource.subject_pattern",
                    "NATS `>` wildcard is not supported; use a trailing `.*` prefix match instead",
                ));
            }
            if let Some(prefix) = subject_pattern.strip_suffix('*') {
                if prefix.is_empty() {
                    // Defence-in-depth: the `== "*"` check above already
                    // catches this, but stripping a standalone `*` must
                    // never produce an empty prefix either way.
                    return Err(AuthzError::validation(
                        "resource.subject_pattern",
                        "NATS subject_pattern stripped to empty prefix; use `kind: any` instead",
                    ));
                }
                if prefix.contains('*') {
                    // Patterns like `cot.*.*` mix an interior `*` with
                    // the supported trailing wildcard. The engine only
                    // understands a single trailing `*`, so without
                    // this guard the rule would silently compile to a
                    // prefix-match against the literal `cot.*.`
                    // segment — which is never what the author
                    // intended. Reject at compile time so the operator
                    // can rewrite the rule rather than discovering the
                    // silent mismatch at runtime.
                    return Err(AuthzError::validation(
                        "resource.subject_pattern",
                        "NATS subject_pattern may contain at most one `*`, and only as a trailing wildcard",
                    ));
                }
                CompiledResourcePred::NatsPrefix(prefix.to_string())
            } else if subject_pattern.contains('*') {
                // Patterns like `cot.*.broadcast` contain an interior
                // `*` with no trailing wildcard. `strip_suffix('*')`
                // returns `None`, so without this guard the compiler
                // would accept the pattern as a literal exact match
                // against the string `cot.*.broadcast` — which never
                // fires because real NATS subjects never contain `*`.
                // That is the footgun the policy spec documents; catch
                // it at compile time with an explicit error rather
                // than shipping a silently-dead rule.
                return Err(AuthzError::validation(
                    "resource.subject_pattern",
                    "NATS subject_pattern interior `*` is not supported; only a trailing `*` wildcard is allowed",
                ));
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
    // Normalise `spiffe_prefix` so it always terminates on a path
    // segment boundary. Without this, `spiffe_prefix = "spiffe://td/ops"`
    // silently matches `spiffe://td/operator-evil` via raw `starts_with`,
    // which is exactly the footgun the SPIFFE spec warns against: the
    // trust domain is a path-segment authority and must be matched as
    // segments, not as bytes.
    //
    // The rule we enforce is simple and operator-visible:
    //
    //   - The prefix must start with `spiffe://`.
    //   - The prefix must contain a trust domain (at least one char
    //     after the scheme).
    //   - Either the prefix ends with `/` (explicit trust-domain or
    //     segment terminator), or we silently append `/` so the
    //     equivalent check uses segment semantics at match time.
    //
    // A prefix that is exactly `spiffe://td` (no trailing slash) is
    // rewritten to `spiffe://td/`, and the matcher is taught to accept
    // either the exact trust-domain-only ID `spiffe://td` OR any path
    // under it via `starts_with(spiffe://td/)`.
    let spiffe_prefix = match &s.spiffe_prefix {
        None => None,
        Some(raw) => Some(normalize_spiffe_prefix(raw)?),
    };

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
        spiffe_prefix,
        attribute_eq,
    })
}

/// Normalise a `spiffe_prefix` rule so matching is segment-anchored.
///
/// Returns a [`SpiffePrefix`] that remembers both the raw trust-domain
/// form (for exact match) and the segment-anchored form (for
/// `starts_with` matching of any path under the trust domain).
///
/// Rejects malformed prefixes at compile time with a clear
/// [`AuthzError::validation`].
fn normalize_spiffe_prefix(raw: &str) -> Result<SpiffePrefix, AuthzError> {
    const SCHEME: &str = "spiffe://";
    if !raw.starts_with(SCHEME) {
        return Err(AuthzError::validation(
            "subject.spiffe_prefix",
            format!("spiffe_prefix must start with `spiffe://`, got `{raw}`"),
        ));
    }
    let rest = &raw[SCHEME.len()..];
    if rest.is_empty() {
        return Err(AuthzError::validation(
            "subject.spiffe_prefix",
            "spiffe_prefix must include a trust domain",
        ));
    }
    // Split trust domain / path. If the authority itself is empty
    // (`spiffe:///foo`), reject — the canonicalizer on the extract
    // side would drop such an ID anyway.
    let authority_end = rest.find('/').unwrap_or(rest.len());
    if authority_end == 0 {
        return Err(AuthzError::validation(
            "subject.spiffe_prefix",
            "spiffe_prefix trust domain must not be empty",
        ));
    }
    // Build the segment-anchored form. Rules fall into two cases:
    //
    //   - `spiffe://td`          → exact = "spiffe://td",
    //                              with_slash = "spiffe://td/"
    //   - `spiffe://td/ops`      → exact = "spiffe://td/ops",
    //                              with_slash = "spiffe://td/ops/"
    //   - `spiffe://td/ops/`     → exact = "spiffe://td/ops" (trimmed),
    //                              with_slash = "spiffe://td/ops/"
    //
    // Matching then accepts either an exact string match (so
    // `spiffe://td/ops` matches itself) OR any path extension beginning
    // with `/` (so `spiffe://td/ops/api` matches but
    // `spiffe://td/operator-evil` does not).
    let without_trailing_slash = raw.strip_suffix('/').unwrap_or(raw);
    let exact = without_trailing_slash.to_string();
    let with_slash = if exact.ends_with('/') {
        exact.clone()
    } else {
        format!("{exact}/")
    };
    Ok(SpiffePrefix { exact, with_slash })
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
    /// Returns `true` when every field is `None` / empty, meaning the
    /// predicate vacuously matches all subjects.
    pub(crate) fn is_match_all(&self) -> bool {
        self.cn_eq.is_none()
            && self.groups_any_of.is_empty()
            && self.groups_all_of.is_empty()
            && self.spiffe_prefix.is_none()
            && self.attribute_eq.is_empty()
    }

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
                Some(id) if prefix.matches(id) => {}
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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use smol_str::SmolStr;

    use super::*;
    use crate::parser::POLICY_SCHEMA_VERSION;
    use crate::policy::{Effect, ResourceMatcher, Rule, RuleSet, SubjectMatcher};

    /// Exhaustive destructuring guard: adding a field to `CompiledSubjectPred`
    /// will cause a compile error here, reminding the developer to update
    /// `is_match_all()` and the per-field tests below.
    #[test]
    fn is_match_all_covers_all_fields() {
        let pred = CompiledSubjectPred {
            cn_eq: None,
            groups_any_of: vec![],
            groups_all_of: vec![],
            spiffe_prefix: None,
            attribute_eq: vec![],
        };
        assert!(pred.is_match_all(), "all-empty pred should match all");
    }

    #[test]
    fn is_match_all_false_when_cn_eq_set() {
        let pred = CompiledSubjectPred {
            cn_eq: Some("alice".to_string()),
            groups_any_of: vec![],
            groups_all_of: vec![],
            spiffe_prefix: None,
            attribute_eq: vec![],
        };
        assert!(!pred.is_match_all(), "cn_eq present should not match all");
    }

    #[test]
    fn is_match_all_false_when_groups_any_of_set() {
        let pred = CompiledSubjectPred {
            cn_eq: None,
            groups_any_of: vec!["ops".to_string()],
            groups_all_of: vec![],
            spiffe_prefix: None,
            attribute_eq: vec![],
        };
        assert!(
            !pred.is_match_all(),
            "groups_any_of present should not match all"
        );
    }

    #[test]
    fn is_match_all_false_when_groups_all_of_set() {
        let pred = CompiledSubjectPred {
            cn_eq: None,
            groups_any_of: vec![],
            groups_all_of: vec!["admins".to_string()],
            spiffe_prefix: None,
            attribute_eq: vec![],
        };
        assert!(
            !pred.is_match_all(),
            "groups_all_of present should not match all"
        );
    }

    #[test]
    fn is_match_all_false_when_spiffe_prefix_set() {
        let pred = CompiledSubjectPred {
            cn_eq: None,
            groups_any_of: vec![],
            groups_all_of: vec![],
            spiffe_prefix: Some(SpiffePrefix {
                exact: "spiffe://example.org".to_string(),
                with_slash: "spiffe://example.org/".to_string(),
            }),
            attribute_eq: vec![],
        };
        assert!(
            !pred.is_match_all(),
            "spiffe_prefix present should not match all"
        );
    }

    #[test]
    fn is_match_all_false_when_attribute_eq_set() {
        let pred = CompiledSubjectPred {
            cn_eq: None,
            groups_any_of: vec![],
            groups_all_of: vec![],
            spiffe_prefix: None,
            attribute_eq: vec![(
                "role".to_string(),
                CompiledAttrValue::Str("admin".to_string()),
            )],
        };
        assert!(
            !pred.is_match_all(),
            "attribute_eq present should not match all"
        );
    }

    // ------------------------------------------------------------------
    // Helpers — keep test bodies focused on what they pin. Every test
    // below constructs a policy programmatically via these helpers
    // rather than going through `parse_json` so a regression in the
    // serde layer does not smear into the compile-layer signal.
    // ------------------------------------------------------------------

    fn empty_ruleset() -> RuleSet {
        RuleSet {
            version: POLICY_SCHEMA_VERSION,
            default_effect: Effect::Deny,
            rules: Vec::new(),
        }
    }

    fn rule(id: &str, effect: Effect, resource: ResourceMatcher) -> Rule {
        Rule {
            id: SmolStr::new(id),
            effect,
            action: Action::Send,
            resource,
            subject: SubjectMatcher::default(),
            obligations: Vec::new(),
        }
    }

    // ------------------------------------------------------------------
    // `SpiffePrefix::matches` — segment-anchored match semantics. The
    // whole reason for the normalise step on compile is that a raw
    // `starts_with` on `spiffe://td/ops` matches `spiffe://td/operator-
    // evil`, which is the specific footgun SPIFFE spec authors call
    // out. Pin each leg of the documented "exact OR segment-extension"
    // contract.
    // ------------------------------------------------------------------

    /// Exact-equal match: the prefix `spiffe://td/ops` admits the
    /// SPIFFE ID `spiffe://td/ops` verbatim. A regression that required
    /// a trailing slash to match would silently break every "I want
    /// exactly this service" rule.
    #[test]
    fn spiffe_prefix_matches_exact_trust_domain_or_path() {
        let p = SpiffePrefix {
            exact: "spiffe://td/ops".to_string(),
            with_slash: "spiffe://td/ops/".to_string(),
        };
        assert!(p.matches("spiffe://td/ops"));
    }

    /// Segment-extension match: a path under the prefix — here
    /// `spiffe://td/ops/api` under prefix `spiffe://td/ops` — admits
    /// via the `starts_with(with_slash)` branch.
    #[test]
    fn spiffe_prefix_matches_segment_anchored_subpath() {
        let p = SpiffePrefix {
            exact: "spiffe://td/ops".to_string(),
            with_slash: "spiffe://td/ops/".to_string(),
        };
        assert!(p.matches("spiffe://td/ops/api"));
        assert!(p.matches("spiffe://td/ops/api/v1"));
    }

    /// The security-critical rejection: a SPIFFE ID that shares the
    /// prefix bytes but crosses a path segment inside the authority
    /// must NOT match. `spiffe://td/operator-evil` starts with the
    /// bytes of `spiffe://td/ops` but is a different segment — it
    /// must fail the segment-anchored check. A regression that dropped
    /// the `with_slash` branch and reverted to raw `starts_with` would
    /// silently grant `operator-evil` every permission the rule
    /// intended for `ops`.
    #[test]
    fn spiffe_prefix_rejects_byte_prefix_segment_impostor() {
        let p = SpiffePrefix {
            exact: "spiffe://td/ops".to_string(),
            with_slash: "spiffe://td/ops/".to_string(),
        };
        assert!(
            !p.matches("spiffe://td/operator-evil"),
            "segment-impostor must be rejected — this is the documented SPIFFE footgun"
        );
        assert!(!p.matches("spiffe://td/ops-readonly"));
    }

    // ------------------------------------------------------------------
    // `resource_kind_tag` — the numeric bucket discriminator. Pinning
    // both the specific values (0..=4 + MAX for Any) and their pairwise
    // distinctness so a refactor that accidentally collapsed two tags
    // (which would cause rules for one resource kind to fire on
    // another's traffic) fails here.
    // ------------------------------------------------------------------

    #[test]
    fn resource_kind_tag_maps_every_variant_distinctly() {
        use std::collections::BTreeSet;

        let tags: Vec<u8> = vec![
            resource_kind_tag(&ResourceMatcher::Direct { target_cn: None }),
            resource_kind_tag(&ResourceMatcher::Group {
                group: "g".to_string(),
            }),
            resource_kind_tag(&ResourceMatcher::Broadcast),
            resource_kind_tag(&ResourceMatcher::Federation { peer_id: None }),
            resource_kind_tag(&ResourceMatcher::NatsSubject {
                subject_pattern: "cot.*".to_string(),
            }),
            resource_kind_tag(&ResourceMatcher::Any),
        ];
        assert_eq!(
            tags,
            vec![0u8, 1, 2, 3, 4, u8::MAX],
            "compile-side tags must match the documented wire values — operators grep the source for these numbers"
        );

        let set: BTreeSet<u8> = tags.iter().copied().collect();
        assert_eq!(
            set.len(),
            tags.len(),
            "every matcher variant must bucket under a distinct tag — a duplicate would cross-fire rules between resource kinds"
        );
    }

    // ------------------------------------------------------------------
    // `compile_rule` NatsSubject validation — each rejection branch
    // exists to prevent a specific operator footgun. Pin every arm so
    // a regression that dropped one silently admits a match-everything
    // rule.
    // ------------------------------------------------------------------

    /// Empty pattern → ambiguous "everything" rule. Must reject so
    /// operators use `{"kind": "any"}` explicitly.
    #[test]
    fn compile_nats_subject_rejects_empty_pattern() {
        let mut set = empty_ruleset();
        set.rules.push(rule(
            "r",
            Effect::Allow,
            ResourceMatcher::NatsSubject {
                subject_pattern: "".to_string(),
            },
        ));
        let err = set.compile().expect_err("empty NATS pattern must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("subject_pattern"),
            "error must name the offending field for operator triage: {msg}"
        );
    }

    /// Standalone `*` compiles to an empty prefix, which would match
    /// every subject via `starts_with("")`. Must reject with a message
    /// that steers to `{"kind": "any"}`.
    #[test]
    fn compile_nats_subject_rejects_bare_star_pattern() {
        let mut set = empty_ruleset();
        set.rules.push(rule(
            "r",
            Effect::Allow,
            ResourceMatcher::NatsSubject {
                subject_pattern: "*".to_string(),
            },
        ));
        let err = set.compile().expect_err("bare `*` must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("ambiguous") || msg.contains("any"),
            "error must steer operators to `kind: any`: {msg}"
        );
    }

    /// NATS `>` wildcard semantics are not implemented — silently
    /// treating it as a literal character would produce a rule that
    /// never fires because real subjects never contain `>`. Must
    /// reject at compile so operators rewrite with a trailing `.*`
    /// prefix match.
    #[test]
    fn compile_nats_subject_rejects_greater_than_wildcard() {
        let mut set = empty_ruleset();
        set.rules.push(rule(
            "r",
            Effect::Allow,
            ResourceMatcher::NatsSubject {
                subject_pattern: "cot.>".to_string(),
            },
        ));
        let err = set.compile().expect_err("`>` wildcard must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains('>') || msg.contains("not supported"),
            "error must call out the unsupported wildcard: {msg}"
        );
    }

    /// Trailing `*` is the one supported wildcard — must compile to
    /// `NatsPrefix(prefix-without-star)`. Pin both the success path
    /// and the resulting runtime match behaviour.
    #[test]
    fn compile_nats_subject_trailing_star_produces_prefix_predicate() {
        let mut set = empty_ruleset();
        set.rules.push(rule(
            "r",
            Effect::Allow,
            ResourceMatcher::NatsSubject {
                subject_pattern: "cot.*".to_string(),
            },
        ));
        let compiled = set.compile().expect("trailing `*` must compile");
        let bucket = compiled
            .buckets
            .get(&BucketKey {
                action: Action::Send,
                resource_kind: resource_kind_tag(&ResourceMatcher::NatsSubject {
                    subject_pattern: String::new(),
                }),
            })
            .expect("nats-subject bucket must exist");
        assert_eq!(bucket.len(), 1);
        let pred = &bucket[0].resource_predicate;
        match pred {
            CompiledResourcePred::NatsPrefix(p) => assert_eq!(p, "cot."),
            other => panic!("expected NatsPrefix, got {other:?}"),
        }
        // And the runtime match honours that prefix.
        assert!(pred.matches(&Resource::NatsSubject {
            subject: "cot.position.broadcast"
        }));
        assert!(!pred.matches(&Resource::NatsSubject { subject: "mav.alt" }));
    }

    /// Interior `*` with no trailing wildcard — e.g. `cot.*.broadcast`
    /// — would silently compile to an exact match against that literal
    /// string, which never fires because real subjects never contain
    /// `*`. Must reject at compile time.
    #[test]
    fn compile_nats_subject_rejects_interior_star_without_trailing_wildcard() {
        let mut set = empty_ruleset();
        set.rules.push(rule(
            "r",
            Effect::Allow,
            ResourceMatcher::NatsSubject {
                subject_pattern: "cot.*.broadcast".to_string(),
            },
        ));
        let err = set.compile().expect_err("interior `*` must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("interior") || msg.contains("trailing"),
            "error must describe the wildcard position constraint: {msg}"
        );
    }

    /// Two wildcards like `cot.*.*` — after `strip_suffix('*')` the
    /// prefix still contains `*`, which the engine cannot process.
    /// Must reject rather than silently prefix-matching against the
    /// literal `cot.*.` string.
    #[test]
    fn compile_nats_subject_rejects_multi_star_pattern() {
        let mut set = empty_ruleset();
        set.rules.push(rule(
            "r",
            Effect::Allow,
            ResourceMatcher::NatsSubject {
                subject_pattern: "cot.*.*".to_string(),
            },
        ));
        let err = set.compile().expect_err("multi-`*` must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("at most one") || msg.contains("trailing"),
            "error must steer to single trailing wildcard: {msg}"
        );
    }

    // ------------------------------------------------------------------
    // `normalize_spiffe_prefix` rejection & normalisation paths.
    // ------------------------------------------------------------------

    /// Missing scheme — every rejection branch exists to prevent a
    /// silent coercion of a non-SPIFFE string into the matcher. Pin
    /// the message so operators who typo `example.org/ops` instead of
    /// `spiffe://example.org/ops` see a usable error.
    #[test]
    fn normalize_spiffe_prefix_rejects_missing_scheme() {
        let err = normalize_spiffe_prefix("example.org/ops").expect_err("missing scheme must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("spiffe://"),
            "error must name the expected scheme: {msg}"
        );
    }

    /// Empty trust domain (`spiffe://`). Must reject so an operator
    /// does not ship a rule that matches every SPIFFE ID in existence.
    #[test]
    fn normalize_spiffe_prefix_rejects_empty_trust_domain() {
        let err = normalize_spiffe_prefix("spiffe://")
            .expect_err("`spiffe://` alone must fail — no trust domain");
        let msg = format!("{err}");
        assert!(
            msg.contains("trust domain"),
            "error must call out the missing authority: {msg}"
        );
    }

    /// Trailing slash is canonicalised away for `exact` but the
    /// `with_slash` form must always terminate with `/`. Pin both
    /// sides so matching stays segment-anchored regardless of whether
    /// the operator wrote the trailing slash.
    #[test]
    fn normalize_spiffe_prefix_trims_trailing_slash_for_exact_match() {
        let p_slash = normalize_spiffe_prefix("spiffe://td/ops/")
            .expect("trailing-slash form must normalise");
        assert_eq!(p_slash.exact, "spiffe://td/ops");
        assert_eq!(p_slash.with_slash, "spiffe://td/ops/");

        let p_bare = normalize_spiffe_prefix("spiffe://td/ops").expect("bare form must normalise");
        assert_eq!(p_bare.exact, "spiffe://td/ops");
        assert_eq!(p_bare.with_slash, "spiffe://td/ops/");

        // The two forms must produce observably-identical match state
        // so operator intent does not depend on a trailing slash.
        assert!(p_slash.matches("spiffe://td/ops"));
        assert!(p_bare.matches("spiffe://td/ops"));
        assert!(p_slash.matches("spiffe://td/ops/api"));
        assert!(p_bare.matches("spiffe://td/ops/api"));
    }

    /// Trust-domain-only prefix `spiffe://td` must match both the bare
    /// form and any path under it, and must reject unrelated trust
    /// domains. Pin the full trust-domain match semantic.
    #[test]
    fn normalize_spiffe_prefix_trust_domain_only_matches_td_and_subpaths() {
        let p = normalize_spiffe_prefix("spiffe://td").expect("trust-domain-only must normalise");
        assert!(p.matches("spiffe://td"));
        assert!(p.matches("spiffe://td/foo"));
        assert!(p.matches("spiffe://td/foo/bar"));
        assert!(!p.matches("spiffe://other"));
        assert!(!p.matches("spiffe://td-evil"));
    }

    // ------------------------------------------------------------------
    // `compute_policy_id` — stable, deterministic, sensitive to any
    // meaningful change in the rule set.
    // ------------------------------------------------------------------

    /// Same input → same SHA-256 hex. Pin determinism so caches keyed
    /// on `policy_id` dedupe across restarts.
    #[test]
    fn compute_policy_id_is_deterministic_across_calls() {
        let set = empty_ruleset();
        let a = compute_policy_id(&set).expect("policy id must compute");
        let b = compute_policy_id(&set).expect("policy id must compute");
        assert_eq!(a, b, "same input must produce the same 64-char SHA-256 hex");
        assert_eq!(
            a.len(),
            64,
            "SHA-256 hex is exactly 64 characters, got {}",
            a.len()
        );
    }

    /// Perturbing the rule set — even just flipping `default_effect` —
    /// must change the digest. If this ever returned the same digest,
    /// a policy reload that only flipped the default posture would
    /// silently leave cached decisions in the old epoch.
    #[test]
    fn compute_policy_id_differs_when_default_effect_changes() {
        let mut a = empty_ruleset();
        a.default_effect = Effect::Deny;
        let mut b = empty_ruleset();
        b.default_effect = Effect::Allow;

        let id_a = compute_policy_id(&a).expect("must compute");
        let id_b = compute_policy_id(&b).expect("must compute");
        assert_ne!(
            id_a, id_b,
            "changing default_effect must yield a different policy_id so cache invalidates"
        );
    }

    // ------------------------------------------------------------------
    // `next_policy_epoch` / compile epoch — every compile must produce
    // a fresh monotonic epoch so the decision cache's epoch-keyed
    // lookup invalidates on reload without an explicit clear.
    // ------------------------------------------------------------------

    /// Two successive compiles of logically-identical rule sets must
    /// still produce different epochs — the epoch is not a function
    /// of policy content, it is a process-global monotonic counter.
    /// A regression that tied the epoch to `policy_id` would defeat
    /// the cache invalidation story (two reloads of the same policy
    /// must still count as two distinct epochs in case the underlying
    /// attributes changed).
    #[test]
    fn compile_yields_monotonic_epoch_across_successive_compiles() {
        let set = empty_ruleset();
        let a = set.compile().expect("compile #1");
        let b = set.compile().expect("compile #2");
        assert!(
            b.epoch > a.epoch,
            "each compile must produce a strictly-greater epoch (got {} then {})",
            a.epoch,
            b.epoch
        );
    }

    // ------------------------------------------------------------------
    // Compile warnings — operator-visible guardrails for rules that
    // are almost certainly broader than intended. Pin both emission
    // AND non-emission so a regression that dropped the warning (or
    // started emitting one for deny rules) is caught.
    // ------------------------------------------------------------------

    /// #621 — allow rule with `resource: any` must emit a warning
    /// into `compile_warnings`, naming the rule id so the operator
    /// can grep their source for it.
    #[test]
    fn compile_emits_warning_for_allow_rule_with_any_resource() {
        let mut set = empty_ruleset();
        set.rules
            .push(rule("r621", Effect::Allow, ResourceMatcher::Any));
        let compiled = set.compile().expect("must compile");
        assert!(
            compiled.compile_warnings.iter().any(|w| w.contains("r621")),
            "warning must name the offending rule id, got {:?}",
            compiled.compile_warnings
        );
        assert!(
            compiled.compile_warnings.iter().any(|w| w.contains("any")),
            "warning must mention `any` so operators know what to fix"
        );
    }

    /// Deny rule with `resource: any` is a valid deny-everything
    /// posture and must NOT emit the #621 warning — operators
    /// deliberately author blanket-deny fallback rules.
    #[test]
    fn compile_does_not_warn_for_deny_rule_with_any_resource() {
        let mut set = empty_ruleset();
        set.rules
            .push(rule("r-deny-all", Effect::Deny, ResourceMatcher::Any));
        let compiled = set.compile().expect("must compile");
        assert!(
            !compiled
                .compile_warnings
                .iter()
                .any(|w| w.contains("r-deny-all")),
            "deny rules with `any` resource are a valid blanket-deny — must not warn, got {:?}",
            compiled.compile_warnings
        );
    }

    /// #622 — allow rule with empty subject matcher vacuously grants
    /// access to every subject. Must warn so operators see it.
    #[test]
    fn compile_emits_warning_for_allow_rule_with_empty_subject_matcher() {
        let mut set = empty_ruleset();
        set.rules.push(rule(
            "r622",
            Effect::Allow,
            ResourceMatcher::Group {
                group: "ops".to_string(),
            },
        )); // SubjectMatcher::default() is empty → match-all
        let compiled = set.compile().expect("must compile");
        assert!(
            compiled
                .compile_warnings
                .iter()
                .any(|w| w.contains("r622") && w.contains("subject")),
            "warning must name the rule id AND cite the subject matcher, got {:?}",
            compiled.compile_warnings
        );
    }

    /// Both #621 and #622 must fire for an allow rule that hits both
    /// — an allow with `any` resource AND empty subject. Pin that
    /// both warnings are emitted (not just the first one found).
    #[test]
    fn compile_emits_both_warnings_when_rule_hits_621_and_622() {
        let mut set = empty_ruleset();
        set.rules
            .push(rule("r-double", Effect::Allow, ResourceMatcher::Any));
        let compiled = set.compile().expect("must compile");
        let matching: Vec<_> = compiled
            .compile_warnings
            .iter()
            .filter(|w| w.contains("r-double"))
            .collect();
        assert_eq!(
            matching.len(),
            2,
            "an allow rule with both hazards must emit both warnings, got {:?}",
            compiled.compile_warnings
        );
    }

    // ------------------------------------------------------------------
    // `CompiledResourcePred::matches` — the per-pair dispatch table.
    // Pin the `Any` special case and the kind-mismatch negative arm.
    // ------------------------------------------------------------------

    /// `CompiledResourcePred::Any` matches every resource kind. This
    /// is the run-time counterpart to the `ResourceMatcher::Any` arm
    /// of `compile_rule`.
    #[test]
    fn compiled_resource_pred_any_matches_every_resource_kind() {
        let pred = CompiledResourcePred::Any;
        assert!(pred.matches(&Resource::Direct { target_cn: "a" }));
        assert!(pred.matches(&Resource::Group { group: "ops" }));
        assert!(pred.matches(&Resource::Broadcast));
        assert!(pred.matches(&Resource::Federation { peer_id: "p" }));
        assert!(pred.matches(&Resource::NatsSubject { subject: "cot.1" }));
    }

    /// Kind-mismatch must return `false` — a `DirectAny` predicate
    /// must NOT admit a `Broadcast` resource. Pin the catch-all `_ =>
    /// false` arm of the dispatch table by walking every wrong-kind
    /// combination the table enumerates.
    #[test]
    fn compiled_resource_pred_kind_mismatch_returns_false() {
        let direct = CompiledResourcePred::DirectAny;
        assert!(!direct.matches(&Resource::Group { group: "ops" }));
        assert!(!direct.matches(&Resource::Broadcast));
        assert!(!direct.matches(&Resource::Federation { peer_id: "p" }));
        assert!(!direct.matches(&Resource::NatsSubject { subject: "s" }));

        let broadcast = CompiledResourcePred::Broadcast;
        assert!(!broadcast.matches(&Resource::Direct { target_cn: "a" }));
        assert!(!broadcast.matches(&Resource::Group { group: "ops" }));

        let nats_exact = CompiledResourcePred::NatsExact("cot.a".to_string());
        assert!(!nats_exact.matches(&Resource::NatsSubject { subject: "cot.b" }));
        assert!(!nats_exact.matches(&Resource::Broadcast));
    }

    // ------------------------------------------------------------------
    // `attr_matches` — AttrValue dispatch across every compiled
    // variant. Any regression here would silently flip attribute-
    // based allow rules into either deny-all or allow-all.
    // ------------------------------------------------------------------

    /// Each scalar wants/haves pair — Str/Int/Bool — must match on
    /// equality and reject on mismatch.
    #[test]
    fn attr_matches_scalar_variants_use_equality() {
        use rustgate_core::AttrValue;

        assert!(attr_matches(
            &CompiledAttrValue::Str("admin".to_string()),
            &AttrValue::Str("admin".to_string())
        ));
        assert!(!attr_matches(
            &CompiledAttrValue::Str("admin".to_string()),
            &AttrValue::Str("guest".to_string())
        ));
        assert!(attr_matches(&CompiledAttrValue::Int(7), &AttrValue::Int(7)));
        assert!(!attr_matches(
            &CompiledAttrValue::Int(7),
            &AttrValue::Int(8)
        ));
        assert!(attr_matches(
            &CompiledAttrValue::Bool(true),
            &AttrValue::Bool(true)
        ));
        assert!(!attr_matches(
            &CompiledAttrValue::Bool(true),
            &AttrValue::Bool(false)
        ));
    }

    /// `SubsetOfSet` requires every listed needle to appear in the
    /// subject's set. Pin both the empty-needles vacuous true, the
    /// full-subset pass, and the partial-overlap reject — a regression
    /// that flipped `all` to `any` would silently widen every
    /// set-membership allow rule.
    #[test]
    fn attr_matches_subset_of_set_requires_every_needle() {
        use rustgate_core::AttrValue;

        let haystack: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let attr = AttrValue::Set(haystack);

        // Empty needles — vacuously true.
        assert!(attr_matches(&CompiledAttrValue::SubsetOfSet(vec![]), &attr));
        // Full subset — true.
        assert!(attr_matches(
            &CompiledAttrValue::SubsetOfSet(vec!["a".to_string(), "b".to_string()]),
            &attr
        ));
        // Any missing needle — false. Pins the `all` semantic over `any`.
        assert!(!attr_matches(
            &CompiledAttrValue::SubsetOfSet(vec!["a".to_string(), "z".to_string()]),
            &attr
        ));
    }

    /// Type-mismatch must fall through to `false` — a `Str` want
    /// against an `Int` have (and every other cross-type pair) must
    /// NOT match. A regression that removed the catch-all and
    /// compared via `==` on trait objects would silently panic.
    #[test]
    fn attr_matches_type_mismatch_returns_false() {
        use rustgate_core::AttrValue;

        // Str want vs Int have
        assert!(!attr_matches(
            &CompiledAttrValue::Str("7".to_string()),
            &AttrValue::Int(7)
        ));
        // Int want vs Bool have
        assert!(!attr_matches(
            &CompiledAttrValue::Int(1),
            &AttrValue::Bool(true)
        ));
        // Bool want vs Str have
        assert!(!attr_matches(
            &CompiledAttrValue::Bool(true),
            &AttrValue::Str("true".to_string())
        ));
        // SubsetOfSet want vs Str have — no set to inspect, must reject.
        assert!(!attr_matches(
            &CompiledAttrValue::SubsetOfSet(vec!["x".to_string()]),
            &AttrValue::Str("x".to_string())
        ));
    }

    // ------------------------------------------------------------------
    // `compile_subject` attribute_eq JSON value rejection. A JSON
    // type the compiler does not understand must not silently collapse
    // to "no constraint" — it must fail compile so the operator sees
    // the fault.
    // ------------------------------------------------------------------

    /// A non-integer `Number` (floating point) must be rejected —
    /// the compiler refuses to invent integer coercion silently.
    #[test]
    fn compile_subject_rejects_non_integer_number_attribute() {
        let mut subject = SubjectMatcher::default();
        subject.attribute_eq.insert(
            "clearance".to_string(),
            serde_json::Value::Number(
                serde_json::Number::from_f64(1.5).expect("finite float must wrap"),
            ),
        );
        let err = compile_subject(&subject).expect_err("non-integer attribute must fail compile");
        let msg = format!("{err}");
        assert!(
            msg.contains("clearance") && (msg.contains("integer") || msg.contains("1.5")),
            "error must name the attribute and the fault: {msg}"
        );
    }

    /// Array attributes must contain strings only. A mixed-type array
    /// (e.g. `[1, "foo"]`) must fail compile rather than silently
    /// dropping the non-string entries.
    #[test]
    fn compile_subject_rejects_non_string_in_array_attribute() {
        let mut subject = SubjectMatcher::default();
        subject.attribute_eq.insert(
            "roles".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("ops".to_string()),
                serde_json::Value::Number(7.into()),
            ]),
        );
        let err = compile_subject(&subject).expect_err("mixed array must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("roles") && msg.contains("string"),
            "error must name the attribute and the string constraint: {msg}"
        );
    }

    /// A JSON type the compiler does not understand (object, null)
    /// must be rejected with a message naming the attribute and the
    /// bad type — silently dropping the constraint would invert every
    /// rule's semantics.
    #[test]
    fn compile_subject_rejects_unsupported_json_type() {
        let mut subject = SubjectMatcher::default();
        subject.attribute_eq.insert(
            "nested".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
        let err = compile_subject(&subject).expect_err("object attribute must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("nested") && msg.contains("unsupported"),
            "error must name the attribute and the type class: {msg}"
        );

        subject.attribute_eq.clear();
        subject
            .attribute_eq
            .insert("null_attr".to_string(), serde_json::Value::Null);
        let err2 = compile_subject(&subject).expect_err("null attribute must fail");
        assert!(
            format!("{err2}").contains("null_attr"),
            "null must also reject and name the offending key"
        );
    }

    // ----------------------------------------------------------------
    // CN normalization audit invariants (closes #723).
    //
    // The authz Cedar / native engine layer performs BYTE-IDENTICAL
    // CN comparison — no NFC, no lowercase, no trim. This is the
    // deliberate divergence from the case-insensitive ACL layer
    // documented in `docs/identity-normalization.md`. The
    // AND-composition of "ACL allow" + "authz allow" is the security
    // boundary: if either layer denies, the request is rejected, so
    // the more restrictive of the two normalization rules always wins.
    //
    // These tests pin the byte-exact contract. A regression that
    // added `to_ascii_lowercase()` or `to_lowercase()` to either side
    // of the `subject.cn` comparison would silently change which
    // policies match across releases — there is no visible deprecation
    // surface for that behavior change, and every existing
    // deployment's policy meaning would shift.
    // ----------------------------------------------------------------

    /// Helper: build a `CompiledSubjectPred` with `cn_eq` only — no
    /// other constraints — so the test isolates the CN-comparison
    /// behavior from groups / spiffe_id / attribute matching.
    fn compiled_pred_cn_eq(cn: &str) -> CompiledSubjectPred {
        CompiledSubjectPred {
            cn_eq: Some(cn.to_string()),
            groups_any_of: vec![],
            groups_all_of: vec![],
            spiffe_prefix: None,
            attribute_eq: vec![],
        }
    }

    use std::collections::BTreeSet;

    #[test]
    fn compiled_subject_pred_cn_eq_is_case_sensitive() {
        // **Load-bearing security test for #723.** The compiled
        // subject predicate's `cn_eq` performs a byte-identical
        // comparison via `==`. A regression that added
        // `to_ascii_lowercase()` to either side would silently change
        // which policies match across releases — every existing
        // deployment's policy meaning would shift without a visible
        // deprecation surface.
        //
        // The deliberate divergence from the ACL layer's case-
        // insensitive matching is documented in
        // `docs/identity-normalization.md`: AND-composition of "ACL
        // allow" + "authz allow" means the more restrictive layer
        // wins, so a Cedar policy author who writes `cn_eq="alice"`
        // gets a STRICTER match than the ACL — exactly the
        // defense-in-depth shape #723 was filed to preserve.
        use rustgate_core::identity::Identity;
        let pred = compiled_pred_cn_eq("alice");
        let id_lower = Identity::new("alice".into(), "fp".into(), BTreeSet::new()).unwrap();
        let id_upper = Identity::new("Alice".into(), "fp".into(), BTreeSet::new()).unwrap();
        let id_caps = Identity::new("ALICE".into(), "fp".into(), BTreeSet::new()).unwrap();
        assert!(
            pred.matches(&Subject::from_identity(&id_lower)),
            "exact lowercase match — happy path"
        );
        assert!(
            !pred.matches(&Subject::from_identity(&id_upper)),
            "case-mismatched CN must NOT match — authz is byte-exact, NOT case-insensitive"
        );
        assert!(
            !pred.matches(&Subject::from_identity(&id_caps)),
            "all-uppercase CN must NOT match the lowercase policy — authz is byte-exact"
        );
    }

    #[test]
    fn compiled_subject_pred_cn_eq_does_not_fold_unicode_lookalikes() {
        // The Turkish dotless i (`ı`, U+0131) is visually similar to
        // ASCII `i` but is a different codepoint. The compiled
        // subject predicate compares bytes — neither side normalizes
        // — so the lookalike form must NOT match an ASCII allow
        // entry. This is the same security invariant pinned at the
        // Identity layer (`unicode_lookalike_does_not_match_legitimate_cn`)
        // and the ACL layer (`acl_does_not_fold_unicode_lookalikes`):
        // every layer must independently reject the lookalike so a
        // regression in any one layer cannot create a spoofing path.
        use rustgate_core::identity::Identity;
        let pred = compiled_pred_cn_eq("alice");
        let id = Identity::new("al\u{0131}ce".into(), "fp".into(), BTreeSet::new()).unwrap();
        assert!(
            !pred.matches(&Subject::from_identity(&id)),
            "Unicode lookalike `alıce` must NOT match ASCII `alice` in the authz engine"
        );
    }

    #[test]
    fn compiled_subject_pred_cn_eq_does_not_trim_or_normalize_input() {
        // The compiled subject predicate does NOT trim leading /
        // trailing whitespace and does NOT NFC-normalize. The
        // Identity layer is expected to deliver bytes consistent with
        // what the policy author registered. A regression that added
        // either step here would silently merge identities that the
        // ACL and Identity layers treat as distinct, breaking the
        // AND-composition discipline.
        use rustgate_core::identity::Identity;
        let pred = compiled_pred_cn_eq("alice");
        let id_lead = Identity::new(" alice".into(), "fp".into(), BTreeSet::new()).unwrap();
        assert!(
            !pred.matches(&Subject::from_identity(&id_lead)),
            "leading whitespace must NOT be trimmed at the authz engine"
        );
        let id_trail = Identity::new("alice ".into(), "fp".into(), BTreeSet::new()).unwrap();
        assert!(
            !pred.matches(&Subject::from_identity(&id_trail)),
            "trailing whitespace must NOT be trimmed at the authz engine"
        );

        // NFD `cafe\u{0301}` must NOT match an NFC `caf\u{00e9}`
        // policy — the authz engine compares bytes, not Unicode
        // canonical equivalence.
        let pred_nfc = compiled_pred_cn_eq("caf\u{00e9}");
        let id_nfd = Identity::new("cafe\u{0301}".into(), "fp".into(), BTreeSet::new()).unwrap();
        assert!(
            !pred_nfc.matches(&Subject::from_identity(&id_nfd)),
            "NFD subject must NOT match NFC policy — authz engine is byte-exact"
        );
    }

    #[test]
    fn compiled_subject_pred_already_normalized_input_consumes_without_re_normalization() {
        // Pin the contract that the authz engine doesn't double-
        // normalize. This is operationally additive but pins the
        // contract so a future Identity layer that DOES normalize at
        // construction can rely on the engine consuming the
        // already-normalized form bit-for-bit. A regression that
        // added a normalize-on-evaluate step here would silently
        // change the meaning of every deployed policy — the
        // additivity test traps that drift before review.
        use rustgate_core::identity::Identity;
        let pred = compiled_pred_cn_eq("alice");
        let id = Identity::new("alice".into(), "fp".into(), BTreeSet::new()).unwrap();
        assert!(
            pred.matches(&Subject::from_identity(&id)),
            "already-lowercase input must match the lowercase policy with no further transform"
        );
    }
}
