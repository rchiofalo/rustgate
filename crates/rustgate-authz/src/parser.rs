// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! JSON parser for [`RuleSet`] policies.

use std::collections::HashSet;

use crate::error::AuthzError;
use crate::policy::RuleSet;

/// Supported policy schema version.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Parse a JSON policy document into a validated [`RuleSet`].
///
/// Validation checks:
/// - `version` must equal `1`
/// - every rule id must be non-empty and unique across the set
pub fn parse_json(bytes: &[u8]) -> Result<RuleSet, AuthzError> {
    let rules: RuleSet = serde_json::from_slice(bytes)?;
    validate(&rules)?;
    Ok(rules)
}

/// Validate a [`RuleSet`] without parsing. Exposed for callers that
/// construct a `RuleSet` programmatically (e.g. tests, benches).
pub fn validate(set: &RuleSet) -> Result<(), AuthzError> {
    if set.version != POLICY_SCHEMA_VERSION {
        return Err(AuthzError::validation(
            "version",
            format!(
                "unsupported policy schema version {}, expected {POLICY_SCHEMA_VERSION}",
                set.version
            ),
        ));
    }

    let mut seen: HashSet<&str> = HashSet::with_capacity(set.rules.len());
    for rule in &set.rules {
        if rule.id.is_empty() {
            return Err(AuthzError::validation("rules", "rule id must not be empty"));
        }
        if !seen.insert(rule.id.as_str()) {
            return Err(AuthzError::validation(
                "rules",
                format!("duplicate rule id `{}`", rule.id),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use smol_str::SmolStr;

    use super::*;
    use crate::model::Action;
    use crate::policy::{Effect, ResourceMatcher, Rule, RuleSet, SubjectMatcher};

    /// Build a minimal [`Rule`] with the given `id`. Every other field is
    /// set to a trivially-matching default so tests that exercise the
    /// id-uniqueness logic stay focused on that one axis.
    fn rule_with_id(id: &str) -> Rule {
        Rule {
            id: SmolStr::new(id),
            effect: Effect::Allow,
            action: Action::Send,
            resource: ResourceMatcher::Any,
            subject: SubjectMatcher::default(),
            obligations: Vec::new(),
        }
    }

    /// A `RuleSet` at the currently-supported version. Callers mutate the
    /// returned value to inject the invariant they want to violate.
    fn valid_empty_set() -> RuleSet {
        RuleSet {
            version: POLICY_SCHEMA_VERSION,
            default_effect: Effect::Deny,
            rules: Vec::new(),
        }
    }

    // ---- schema-version invariant -----------------------------------------

    /// Pin the supported schema version. A bump is a deliberate wire-format
    /// change that every operator-authored policy must migrate to — the
    /// constant exists specifically so downstream callers (and this test)
    /// have one place to notice the change.
    #[test]
    fn schema_version_is_one() {
        assert_eq!(
            POLICY_SCHEMA_VERSION, 1,
            "bumping POLICY_SCHEMA_VERSION requires a coordinated migration path for every \
             operator-authored policy on disk; do not bump this constant without updating the \
             parser-side backwards-compatibility story"
        );
    }

    // ---- parse_json happy path --------------------------------------------

    #[test]
    fn parse_json_accepts_minimal_policy() {
        let json = br#"{"version": 1}"#;
        let set = parse_json(json).expect("minimal policy must parse");
        assert_eq!(set.version, POLICY_SCHEMA_VERSION);
        // Missing default_effect must default to Deny (defence-in-depth for
        // policies authored without an explicit fallback clause).
        assert_eq!(set.default_effect, Effect::Deny);
        assert!(set.rules.is_empty());
    }

    #[test]
    fn parse_json_accepts_default_effect_allow() {
        let json = br#"{"version": 1, "default_effect": "allow"}"#;
        let set = parse_json(json).expect("explicit default_effect must parse");
        assert_eq!(set.default_effect, Effect::Allow);
    }

    #[test]
    fn parse_json_accepts_rules_array() {
        let json = br#"{
            "version": 1,
            "rules": [
                {
                    "id": "r1",
                    "effect": "allow",
                    "action": "send",
                    "resource": {"kind": "any"},
                    "subject": {"cn_eq": "alice"}
                }
            ]
        }"#;
        let set = parse_json(json).expect("policy with one rule must parse");
        assert_eq!(set.rules.len(), 1);
        assert_eq!(set.rules[0].id, "r1");
        assert_eq!(set.rules[0].effect, Effect::Allow);
    }

    // ---- parse_json JSON-level errors -------------------------------------

    #[test]
    fn parse_json_rejects_empty_input() {
        let err = parse_json(b"").expect_err("empty input must fail");
        assert!(
            matches!(err, AuthzError::Json(_)),
            "empty input is a serde-level failure, not a validation-stage failure: got {err:?}"
        );
    }

    #[test]
    fn parse_json_rejects_malformed_json() {
        let err = parse_json(b"{not valid json").expect_err("malformed JSON must fail");
        assert!(matches!(err, AuthzError::Json(_)));
    }

    /// `RuleSet` carries `#[serde(deny_unknown_fields)]` — a typo in a
    /// top-level key (e.g. `default_efect`) must fail the parse rather
    /// than silently dropping to the `Deny` default, which would change
    /// an operator's intended `Allow` fallback into a `Deny` fallback
    /// under their nose. Pinning the behaviour at the parser entry point
    /// catches any future refactor that accidentally relaxes the
    /// attribute.
    #[test]
    fn parse_json_rejects_unknown_top_level_field() {
        let json = br#"{"version": 1, "default_efect": "allow"}"#;
        let err = parse_json(json).expect_err("misspelled top-level field must fail");
        assert!(
            matches!(err, AuthzError::Json(_)),
            "unknown-field rejection is surfaced by serde, not the custom validator: got {err:?}"
        );
    }

    // ---- parse_json version invariant -------------------------------------

    #[test]
    fn parse_json_rejects_version_zero() {
        let json = br#"{"version": 0}"#;
        let err = parse_json(json).expect_err("version 0 must be rejected");
        match err {
            AuthzError::Validation { stage, message } => {
                assert_eq!(
                    stage, "version",
                    "version rejection must tag stage=\"version\" so audit pipelines can \
                     distinguish schema drift from rule-level errors"
                );
                assert!(
                    message.contains('0') && message.contains('1'),
                    "message must name both the rejected version and the expected version for \
                     operator diagnosis, got: {message}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn parse_json_rejects_future_version() {
        // Forward-incompatible schema — a newer format an older parser
        // cannot be trusted to interpret correctly. Must be rejected
        // loudly, not silently parsed as v1.
        let json = br#"{"version": 2}"#;
        let err = parse_json(json).expect_err("future version must be rejected");
        match err {
            AuthzError::Validation { stage, message } => {
                assert_eq!(stage, "version");
                assert!(
                    message.contains('2'),
                    "message must echo the offending version, got: {message}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    // ---- parse_json rule-id invariants ------------------------------------

    #[test]
    fn parse_json_rejects_empty_rule_id() {
        let json = br#"{
            "version": 1,
            "rules": [
                {
                    "id": "",
                    "effect": "allow",
                    "action": "send",
                    "resource": {"kind": "any"},
                    "subject": {}
                }
            ]
        }"#;
        let err = parse_json(json).expect_err("empty rule id must be rejected");
        match err {
            AuthzError::Validation { stage, message } => {
                assert_eq!(
                    stage, "rules",
                    "rule-level validation must tag stage=\"rules\" to separate it from the \
                     top-level version check in audit pipelines"
                );
                assert!(
                    message.contains("empty"),
                    "message must describe why the id was rejected, got: {message}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    /// Duplicate ids are the silent-override failure mode this validator
    /// is most responsible for catching. Two rules with the same id would
    /// surface as one entry in every id-keyed audit record and decision
    /// cache lookup, silently masking the second rule's effect — in the
    /// worst case, a copy-paste `deny` shadowed by a later `allow` that
    /// the operator never reviewed as a pair.
    #[test]
    fn parse_json_rejects_duplicate_rule_id() {
        let json = br#"{
            "version": 1,
            "rules": [
                {
                    "id": "shared",
                    "effect": "deny",
                    "action": "send",
                    "resource": {"kind": "any"},
                    "subject": {}
                },
                {
                    "id": "shared",
                    "effect": "allow",
                    "action": "send",
                    "resource": {"kind": "any"},
                    "subject": {}
                }
            ]
        }"#;
        let err = parse_json(json).expect_err("duplicate rule id must be rejected");
        match err {
            AuthzError::Validation { stage, message } => {
                assert_eq!(stage, "rules");
                assert!(
                    message.contains("duplicate") && message.contains("shared"),
                    "message must name both the failure mode and the offending id so the \
                     operator can grep their source, got: {message}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    // ---- validate() direct-call surface -----------------------------------

    /// `validate` is exported separately from `parse_json` so programmatic
    /// constructors (tests, benches, future DSL → RuleSet pipelines) can
    /// run the same invariants without serialising to JSON first. Pin the
    /// happy path.
    #[test]
    fn validate_accepts_programmatically_built_valid_set() {
        let mut set = valid_empty_set();
        set.rules.push(rule_with_id("r1"));
        set.rules.push(rule_with_id("r2"));
        validate(&set).expect("distinct non-empty ids must validate");
    }

    #[test]
    fn validate_accepts_empty_rules_list() {
        let set = valid_empty_set();
        validate(&set).expect("a version-1 policy with no rules is a valid minimal policy");
    }

    #[test]
    fn validate_rejects_version_zero_directly() {
        let mut set = valid_empty_set();
        set.version = 0;
        let err = validate(&set).expect_err("version 0 must fail validation");
        match err {
            AuthzError::Validation { stage, .. } => assert_eq!(stage, "version"),
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_future_version_directly() {
        let mut set = valid_empty_set();
        set.version = u32::MAX;
        let err = validate(&set).expect_err("u32::MAX must not be silently parsed as v1");
        assert!(matches!(
            err,
            AuthzError::Validation {
                stage: "version",
                ..
            }
        ));
    }

    #[test]
    fn validate_rejects_empty_rule_id_directly() {
        let mut set = valid_empty_set();
        set.rules.push(rule_with_id(""));
        let err = validate(&set).expect_err("empty rule id must fail validation");
        assert!(matches!(err, AuthzError::Validation { stage: "rules", .. }));
    }

    #[test]
    fn validate_rejects_duplicate_rule_id_directly() {
        let mut set = valid_empty_set();
        set.rules.push(rule_with_id("dup"));
        set.rules.push(rule_with_id("dup"));
        let err = validate(&set).expect_err("duplicate rule ids must fail validation");
        match err {
            AuthzError::Validation { stage, message } => {
                assert_eq!(stage, "rules");
                assert!(
                    message.contains("dup"),
                    "message must echo offending id: {message}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    /// The order-sensitive invariant: the duplicate detector must flag the
    /// second occurrence of an id, regardless of whether the first was
    /// an allow or a deny. A bug that short-circuited on the first
    /// insert would let a second, later-winning rule slip through on the
    /// assumption that "the first one is fine".
    #[test]
    fn validate_flags_duplicate_regardless_of_effect() {
        let mut set = valid_empty_set();
        let mut allow = rule_with_id("r");
        allow.effect = Effect::Allow;
        let mut deny = rule_with_id("r");
        deny.effect = Effect::Deny;
        set.rules.push(allow);
        set.rules.push(deny);
        let err = validate(&set).expect_err("duplicate id must trip regardless of effect pairing");
        assert!(matches!(err, AuthzError::Validation { stage: "rules", .. }));
    }

    /// Three distinct ids must validate cleanly — a sanity check that the
    /// duplicate detector does not mistake structural similarity (all
    /// rules using the same effect/action) for id collision.
    #[test]
    fn validate_accepts_many_distinct_ids() {
        let mut set = valid_empty_set();
        for i in 0..10 {
            set.rules.push(rule_with_id(&format!("rule-{i}")));
        }
        validate(&set).expect("ten distinct ids must validate");
    }
}
