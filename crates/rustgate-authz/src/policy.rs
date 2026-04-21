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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    //! Serde-shape tests for the policy AST. These target each type
    //! directly (not via [`crate::parser::parse_json`]) so a regression
    //! in, say, the `ResourceMatcher` kind tagger surfaces as a failure
    //! against `ResourceMatcher` instead of being smeared across the
    //! cross-type `parse_json` surface.

    use super::*;

    // ---------------------------------------------------------------
    // Effect — snake_case tag round-trip
    // ---------------------------------------------------------------

    #[test]
    fn effect_serializes_as_lowercase_allow() {
        // Wire stability: operator-authored JSON uses lowercase
        // `"allow"` / `"deny"`. A future refactor that forgot to keep
        // `rename_all = "snake_case"` on `Effect` would silently break
        // every policy on disk.
        let json = serde_json::to_string(&Effect::Allow).expect("Effect must serialize");
        assert_eq!(json, "\"allow\"");
    }

    #[test]
    fn effect_serializes_as_lowercase_deny() {
        let json = serde_json::to_string(&Effect::Deny).expect("Effect must serialize");
        assert_eq!(json, "\"deny\"");
    }

    #[test]
    fn effect_deserializes_from_lowercase() {
        let allow: Effect = serde_json::from_str("\"allow\"").expect("\"allow\" must parse");
        assert_eq!(allow, Effect::Allow);
        let deny: Effect = serde_json::from_str("\"deny\"").expect("\"deny\" must parse");
        assert_eq!(deny, Effect::Deny);
    }

    #[test]
    fn effect_rejects_titlecase() {
        // `rename_all = "snake_case"` is strict — `"Allow"` is not a
        // valid wire value. Pinning this catches a regression where a
        // future maintainer switches to `rename_all = "PascalCase"` or
        // drops the attribute entirely, which would silently admit both
        // shapes and create an ambiguous parse surface.
        assert!(serde_json::from_str::<Effect>("\"Allow\"").is_err());
        assert!(serde_json::from_str::<Effect>("\"DENY\"").is_err());
    }

    #[test]
    fn effect_rejects_unknown_variant() {
        let err = serde_json::from_str::<Effect>("\"maybe\"")
            .expect_err("unknown effect variant must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("maybe") || msg.contains("variant"),
            "error should name the bad variant or call out it's a variant error: {msg}"
        );
    }

    // ---------------------------------------------------------------
    // RuleSet defaults
    // ---------------------------------------------------------------

    #[test]
    fn rule_set_default_effect_resolves_to_deny_when_omitted() {
        // The `default_effect_deny` helper is load-bearing: a minimal
        // policy without a default_effect field must adopt a deny
        // posture, not Effect's `#[derive(Default)]` (which does not
        // exist here but could be added in a refactor and land as
        // Allow if the enum variants were reordered).
        let set: RuleSet = serde_json::from_str("{\"version\": 1}").expect("must parse");
        assert_eq!(set.default_effect, Effect::Deny);
    }

    #[test]
    fn rule_set_rules_field_defaults_to_empty_vec() {
        let set: RuleSet = serde_json::from_str("{\"version\": 1}").expect("must parse");
        assert!(
            set.rules.is_empty(),
            "missing rules field must default to an empty vec, not a null or error"
        );
    }

    #[test]
    fn rule_set_version_field_is_required() {
        // `version` has no `#[serde(default)]`; an omitted version
        // must be rejected at serde level before the custom validator
        // even sees the document. If this drifts to accepting the
        // default `u32 = 0`, `parser::validate` still refuses it, but
        // the failure mode would shift from "missing required field"
        // to "unsupported version 0" — a worse error message for
        // operators and a noisier audit record.
        let err =
            serde_json::from_str::<RuleSet>("{}").expect_err("missing version must fail parse");
        let msg = err.to_string();
        assert!(
            msg.contains("version"),
            "missing-field error should name `version`: {msg}"
        );
    }

    // ---------------------------------------------------------------
    // Rule — deny_unknown_fields inside a rule object
    // ---------------------------------------------------------------

    #[test]
    fn rule_rejects_unknown_field_inside_rule() {
        // `RuleSet` already has `deny_unknown_fields`, but a
        // per-rule typo (e.g. `efect` misspelled) lives in the
        // inner `Rule` object, so the inner struct must carry the
        // same attribute. Pinning this defends against a refactor
        // that removes `deny_unknown_fields` from `Rule` while
        // leaving `RuleSet`'s attribute in place — a regression that
        // would make every per-rule typo silently widen the rule.
        let json = r#"{
            "id": "r1",
            "effect": "allow",
            "action": "send",
            "resource": {"kind": "any"},
            "subject": {},
            "surprise_field": true
        }"#;
        assert!(
            serde_json::from_str::<Rule>(json).is_err(),
            "an unknown field inside a Rule must fail parse"
        );
    }

    #[test]
    fn rule_obligations_field_defaults_to_empty() {
        let json = r#"{
            "id": "r1",
            "effect": "allow",
            "action": "send",
            "resource": {"kind": "any"},
            "subject": {}
        }"#;
        let rule: Rule = serde_json::from_str(json).expect("rule without obligations must parse");
        assert!(rule.obligations.is_empty());
    }

    // ---------------------------------------------------------------
    // ResourceMatcher — tag = "kind" dispatch
    // ---------------------------------------------------------------

    #[test]
    fn resource_matcher_any_variant_parses() {
        let matcher: ResourceMatcher =
            serde_json::from_str(r#"{"kind": "any"}"#).expect("any kind must parse");
        assert!(matches!(matcher, ResourceMatcher::Any));
    }

    #[test]
    fn resource_matcher_broadcast_variant_parses() {
        let matcher: ResourceMatcher =
            serde_json::from_str(r#"{"kind": "broadcast"}"#).expect("broadcast kind must parse");
        assert!(matches!(matcher, ResourceMatcher::Broadcast));
    }

    #[test]
    fn resource_matcher_direct_with_target_cn() {
        let matcher: ResourceMatcher =
            serde_json::from_str(r#"{"kind": "direct", "target_cn": "alice"}"#)
                .expect("direct kind with target_cn must parse");
        match matcher {
            ResourceMatcher::Direct { target_cn } => {
                assert_eq!(target_cn.as_deref(), Some("alice"));
            }
            other => panic!("expected Direct, got {other:?}"),
        }
    }

    #[test]
    fn resource_matcher_direct_without_target_cn_matches_anyone() {
        // `target_cn = None` is documented as "match any target CN".
        // Pinning the parse-side default guarantees that behaviour.
        let matcher: ResourceMatcher = serde_json::from_str(r#"{"kind": "direct"}"#)
            .expect("direct kind without target_cn must parse");
        match matcher {
            ResourceMatcher::Direct { target_cn } => assert!(target_cn.is_none()),
            other => panic!("expected Direct, got {other:?}"),
        }
    }

    #[test]
    fn resource_matcher_group_requires_group_name() {
        let matcher: ResourceMatcher = serde_json::from_str(r#"{"kind": "group", "group": "ops"}"#)
            .expect("group kind with group name must parse");
        match matcher {
            ResourceMatcher::Group { group } => assert_eq!(group, "ops"),
            other => panic!("expected Group, got {other:?}"),
        }
    }

    #[test]
    fn resource_matcher_group_rejects_missing_group_name() {
        // `Group.group` has no `#[serde(default)]`, so a bare
        // `{"kind": "group"}` with no group name must fail. A future
        // refactor that added `#[serde(default)]` to smooth over
        // operator mistakes would turn every unqualified group-rule
        // into a match-everything, quietly inverting the rule.
        let err = serde_json::from_str::<ResourceMatcher>(r#"{"kind": "group"}"#)
            .expect_err("group kind without group field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("group"),
            "error must name the missing field: {msg}"
        );
    }

    #[test]
    fn resource_matcher_federation_without_peer_matches_any() {
        let matcher: ResourceMatcher = serde_json::from_str(r#"{"kind": "federation"}"#)
            .expect("federation without peer_id must parse");
        match matcher {
            ResourceMatcher::Federation { peer_id } => assert!(peer_id.is_none()),
            other => panic!("expected Federation, got {other:?}"),
        }
    }

    #[test]
    fn resource_matcher_federation_with_peer_id() {
        let matcher: ResourceMatcher =
            serde_json::from_str(r#"{"kind": "federation", "peer_id": "peer-a"}"#)
                .expect("federation with peer_id must parse");
        match matcher {
            ResourceMatcher::Federation { peer_id } => {
                assert_eq!(peer_id.as_deref(), Some("peer-a"));
            }
            other => panic!("expected Federation, got {other:?}"),
        }
    }

    #[test]
    fn resource_matcher_nats_subject_requires_pattern() {
        let matcher: ResourceMatcher =
            serde_json::from_str(r#"{"kind": "nats_subject", "subject_pattern": "cot.*"}"#)
                .expect("nats_subject with pattern must parse");
        match matcher {
            ResourceMatcher::NatsSubject { subject_pattern } => {
                assert_eq!(subject_pattern, "cot.*");
            }
            other => panic!("expected NatsSubject, got {other:?}"),
        }
    }

    #[test]
    fn resource_matcher_rejects_missing_kind_tag() {
        // `#[serde(tag = "kind")]` is load-bearing — without a kind
        // discriminator the parser has no way to dispatch, and the
        // safe behaviour is to reject.
        assert!(
            serde_json::from_str::<ResourceMatcher>("{}").is_err(),
            "a ResourceMatcher with no kind tag must not parse"
        );
    }

    #[test]
    fn resource_matcher_rejects_unknown_kind() {
        // An operator who misspells `"federation"` as `"federaton"`
        // must see a loud rejection, not a silent fall-through.
        assert!(
            serde_json::from_str::<ResourceMatcher>(r#"{"kind": "federaton"}"#).is_err(),
            "an unknown ResourceMatcher kind must fail parse"
        );
    }

    #[test]
    fn resource_matcher_rejects_titlecase_kind() {
        // `rename_all = "snake_case"` on the enum means the wire
        // shape is case-sensitive. Pinning this catches a regression
        // where a future refactor flips to `rename_all = "PascalCase"`
        // or drops the attribute.
        assert!(
            serde_json::from_str::<ResourceMatcher>(r#"{"kind": "Direct"}"#).is_err(),
            "capitalised kind must fail parse under snake_case rename"
        );
    }

    #[test]
    fn resource_matcher_rejects_unknown_field_inside_variant() {
        // `deny_unknown_fields` on the enum scope-propagates to each
        // variant, so `target_ccn` (typo) inside a direct variant is
        // an error — not a silent drop that leaves target_cn=None.
        assert!(
            serde_json::from_str::<ResourceMatcher>(r#"{"kind": "direct", "target_ccn": "alice"}"#)
                .is_err(),
            "misspelled field inside a variant must fail parse"
        );
    }

    // ---------------------------------------------------------------
    // SubjectMatcher — all-optional structural defaults
    // ---------------------------------------------------------------

    #[test]
    fn subject_matcher_empty_object_equals_default() {
        // The doc contract: "an all-empty matcher matches every
        // subject." `{}` must produce a `Default`-equivalent matcher
        // with no fields set. This is the foundation for the
        // "match-anyone" rule shape operators rely on.
        let matcher: SubjectMatcher = serde_json::from_str("{}").expect("empty matcher must parse");
        let default = SubjectMatcher::default();
        // Compare field-by-field since SubjectMatcher doesn't derive
        // PartialEq (serde_json::Value isn't comparable structurally
        // in our target version).
        assert_eq!(matcher.cn_eq, default.cn_eq);
        assert!(matcher.groups_any_of.is_empty());
        assert!(matcher.groups_all_of.is_empty());
        assert_eq!(matcher.spiffe_prefix, default.spiffe_prefix);
        assert!(matcher.attribute_eq.is_empty());
    }

    #[test]
    fn subject_matcher_cn_eq_field_parses() {
        let matcher: SubjectMatcher =
            serde_json::from_str(r#"{"cn_eq": "alice"}"#).expect("cn_eq-only matcher must parse");
        assert_eq!(matcher.cn_eq.as_deref(), Some("alice"));
    }

    #[test]
    fn subject_matcher_groups_any_of_field_parses() {
        let matcher: SubjectMatcher = serde_json::from_str(r#"{"groups_any_of": ["ops", "sre"]}"#)
            .expect("groups_any_of matcher must parse");
        assert_eq!(matcher.groups_any_of, vec!["ops", "sre"]);
    }

    #[test]
    fn subject_matcher_groups_all_of_field_parses() {
        let matcher: SubjectMatcher =
            serde_json::from_str(r#"{"groups_all_of": ["admin", "ops"]}"#)
                .expect("groups_all_of matcher must parse");
        assert_eq!(matcher.groups_all_of, vec!["admin", "ops"]);
    }

    #[test]
    fn subject_matcher_spiffe_prefix_field_parses() {
        let matcher: SubjectMatcher =
            serde_json::from_str(r#"{"spiffe_prefix": "spiffe://example.org/"}"#)
                .expect("spiffe_prefix matcher must parse");
        assert_eq!(
            matcher.spiffe_prefix.as_deref(),
            Some("spiffe://example.org/")
        );
    }

    #[test]
    fn subject_matcher_attribute_eq_accepts_heterogeneous_values() {
        // The doc comment advertises four supported JSON value
        // types (string, int, bool, array-of-string). The backing
        // `serde_json::Value` accepts any JSON shape at parse time;
        // type enforcement lives in the compile/evaluate stage.
        // Pinning "all four advertised shapes parse at this layer"
        // catches any future refactor that migrates to a typed
        // enum (e.g. `AttrLiteral`) without updating the doc.
        let matcher: SubjectMatcher = serde_json::from_str(
            r#"{
                "attribute_eq": {
                    "rank": "captain",
                    "clearance": 4,
                    "on_duty": true,
                    "roles": ["admin", "ops"]
                }
            }"#,
        )
        .expect("heterogeneous attribute_eq values must parse");
        assert_eq!(matcher.attribute_eq.len(), 4);
        assert!(matcher.attribute_eq["rank"].is_string());
        assert!(matcher.attribute_eq["clearance"].is_i64());
        assert!(matcher.attribute_eq["on_duty"].is_boolean());
        assert!(matcher.attribute_eq["roles"].is_array());
    }

    /// The canonical footgun that `deny_unknown_fields` on
    /// [`SubjectMatcher`] defends against, called out explicitly in
    /// the type's doc comment: `"groups_all_off"` (trailing `f`)
    /// without `deny_unknown_fields` would parse into a
    /// `Default` matcher — an all-match predicate that silently
    /// grants the surrounding rule to everyone. Pinning this at the
    /// matcher level (in addition to the parser-level test) catches
    /// a regression that removes the attribute from this type
    /// specifically while leaving it on `RuleSet`.
    #[test]
    fn subject_matcher_rejects_misspelled_groups_field() {
        let err = serde_json::from_str::<SubjectMatcher>(r#"{"groups_all_off": ["admin"]}"#)
            .expect_err("misspelled field must be rejected to avoid all-match fallthrough");
        let msg = err.to_string();
        assert!(
            msg.contains("groups_all_off") || msg.contains("unknown"),
            "error should name the offending field or call it unknown: {msg}"
        );
    }

    #[test]
    fn subject_matcher_rejects_unknown_top_level_field() {
        // Broader regression guard: any field name not in the struct
        // is rejected, not just the specific typo above.
        assert!(
            serde_json::from_str::<SubjectMatcher>(r#"{"totally_new": true}"#).is_err(),
            "any unknown field on SubjectMatcher must fail parse"
        );
    }

    // ---------------------------------------------------------------
    // Default impls
    // ---------------------------------------------------------------

    #[test]
    fn subject_matcher_default_is_fully_empty() {
        // `SubjectMatcher` derives `Default` — every field must fall
        // back to "no predicate". A future refactor that added a
        // required default-different field (e.g. a `require_mtls:
        // bool = true`) would silently change the meaning of every
        // in-memory matcher built via `SubjectMatcher::default()`.
        let def = SubjectMatcher::default();
        assert!(def.cn_eq.is_none());
        assert!(def.groups_any_of.is_empty());
        assert!(def.groups_all_of.is_empty());
        assert!(def.spiffe_prefix.is_none());
        assert!(def.attribute_eq.is_empty());
    }

    // ---------------------------------------------------------------
    // Full Rule round-trip — integration of the above
    // ---------------------------------------------------------------

    #[test]
    fn rule_full_shape_round_trips() {
        // A realistic rule exercising every sub-type. Round-trip
        // via JSON proves that Serialize and Deserialize agree on
        // the wire shape — a regression that diverged them (e.g.
        // adding a `Serialize`-only helper field) would land on
        // disk as a file that cannot be read back.
        let json = r#"{
            "id": "rule-alpha",
            "effect": "allow",
            "action": "send",
            "resource": {"kind": "group", "group": "ops"},
            "subject": {"cn_eq": "alice", "groups_any_of": ["ops", "sre"]},
            "obligations": []
        }"#;
        let rule: Rule = serde_json::from_str(json).expect("full rule must parse");
        assert_eq!(rule.id, "rule-alpha");
        assert_eq!(rule.effect, Effect::Allow);
        let round_tripped = serde_json::to_string(&rule).expect("rule must serialize");
        let rule2: Rule =
            serde_json::from_str(&round_tripped).expect("round-tripped JSON must parse back");
        assert_eq!(rule2.id, rule.id);
        assert_eq!(rule2.effect, rule.effect);
    }
}
