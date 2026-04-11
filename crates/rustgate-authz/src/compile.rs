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
mod tests {
    use super::*;

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
}
