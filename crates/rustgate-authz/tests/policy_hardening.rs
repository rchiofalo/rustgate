#![allow(clippy::panic, clippy::unwrap_used)]

//! Regression tests for the policy-parse / compile hardening work:
//!
//! - `deny_unknown_fields` on the AST so typos like `groups_all_off`
//!   cannot silently degrade a matcher to "match every subject".
//! - `spiffe_prefix` normalised to segment-anchored matching so a
//!   prefix like `spiffe://td/ops` cannot match `spiffe://td/operator-evil`.
//! - `ResourceMatcher::NatsSubject { subject_pattern }` compile-time
//!   validation that rejects `""`, `"*"`, and any pattern containing
//!   the unsupported `>` wildcard, preventing accidental match-all
//!   rules.

use std::collections::{BTreeMap, BTreeSet};

use rustgate_authz::parser::parse_json;
use rustgate_authz::{Action, NativeEngine, PolicyEngine, Resource, Subject};
use rustgate_core::identity::Identity;

fn spiffe_subject(id: &str) -> Identity {
    let mut identity = Identity::new("svc".to_string(), "fp".to_string(), BTreeSet::new()).unwrap();
    identity = identity.with_attributes(BTreeMap::new());
    identity = identity.with_spiffe_id(id);
    identity
}

// ---------- H3: deny_unknown_fields on the policy AST ----------

#[test]
fn typo_in_subject_field_is_rejected() {
    // `groups_all_off` (trailing `f`) was silently accepted before.
    // Without `deny_unknown_fields` the rule parsed into an empty
    // matcher that matched every subject — a total policy bypass via
    // a one-character typo.
    let bad = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"send",
         "resource":{"kind":"any"},
         "subject":{"groups_all_off":["admin"]}}
    ]}"#;
    assert!(
        parse_json(bad).is_err(),
        "typo in subject field must fail the parse"
    );
}

#[test]
fn typo_in_ruleset_field_is_rejected() {
    let bad = br#"{"version":1,"default_efect":"allow","rules":[]}"#;
    assert!(
        parse_json(bad).is_err(),
        "typo in top-level field must fail the parse"
    );
}

#[test]
fn typo_in_rule_field_is_rejected() {
    let bad = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"send",
         "resource":{"kind":"any"},
         "subject":{},
         "obligaions":[]}
    ]}"#;
    assert!(
        parse_json(bad).is_err(),
        "typo in rule field must fail the parse"
    );
}

#[test]
fn typo_in_resource_matcher_is_rejected() {
    let bad = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"send",
         "resource":{"kind":"direct","target_ccn":"bob"},
         "subject":{}}
    ]}"#;
    assert!(
        parse_json(bad).is_err(),
        "typo in resource matcher field must fail the parse"
    );
}

// ---------- H1: spiffe_prefix segment anchoring ----------

#[test]
fn spiffe_prefix_does_not_match_sibling_segment() {
    // Policy grants access to anything under `spiffe://example.org/ns/prod`.
    // A sibling identity `spiffe://example.org/ns/production-evil`
    // must NOT match — before the fix, raw `starts_with` would have
    // accepted it.
    let json = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"publish",
         "resource":{"kind":"nats_subject","subject_pattern":"cot.*"},
         "subject":{"spiffe_prefix":"spiffe://example.org/ns/prod"}}
    ]}"#;
    let engine = NativeEngine::new(parse_json(json).unwrap()).unwrap();

    let legit = spiffe_subject("spiffe://example.org/ns/prod/sa/foo");
    let evil = spiffe_subject("spiffe://example.org/ns/production-evil/sa/bar");
    let exact = spiffe_subject("spiffe://example.org/ns/prod");

    let res = Resource::NatsSubject { subject: "cot.red" };

    assert!(
        engine
            .evaluate(&Subject::from_identity(&legit), &res, Action::Publish)
            .is_allow(),
        "legitimate descendant under spiffe://example.org/ns/prod/ must match"
    );
    assert!(
        !engine
            .evaluate(&Subject::from_identity(&evil), &res, Action::Publish)
            .is_allow(),
        "sibling segment ns/production-evil must NOT match spiffe_prefix ns/prod"
    );
    assert!(
        engine
            .evaluate(&Subject::from_identity(&exact), &res, Action::Publish)
            .is_allow(),
        "exact trust-domain+path match must still succeed"
    );
}

#[test]
fn spiffe_prefix_trust_domain_only_still_works() {
    // Prefix `spiffe://example.org` (no path) should match the
    // trust-domain-only ID and any path under the trust domain, but
    // not a different trust domain that happens to start with the
    // same letters.
    let json = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"send",
         "resource":{"kind":"any"},
         "subject":{"spiffe_prefix":"spiffe://example.org"}}
    ]}"#;
    let engine = NativeEngine::new(parse_json(json).unwrap()).unwrap();

    let same_td = spiffe_subject("spiffe://example.org/svc");
    let sibling_td = spiffe_subject("spiffe://example.org.evil/svc");
    let res = Resource::Direct { target_cn: "bob" };

    assert!(
        engine
            .evaluate(&Subject::from_identity(&same_td), &res, Action::Send)
            .is_allow()
    );
    assert!(
        !engine
            .evaluate(&Subject::from_identity(&sibling_td), &res, Action::Send)
            .is_allow(),
        "sibling trust domain must NOT match segment-anchored spiffe_prefix"
    );
}

#[test]
fn spiffe_prefix_malformed_rejected_at_compile() {
    let bad = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"send",
         "resource":{"kind":"any"},
         "subject":{"spiffe_prefix":"http://example.org/"}}
    ]}"#;
    // Parse is fine (it's just a string field), but compile must
    // reject the non-spiffe scheme.
    let rs = parse_json(bad).expect("parse succeeds");
    assert!(
        NativeEngine::new(rs).is_err(),
        "non-spiffe scheme must fail compile"
    );

    let empty_td = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"send",
         "resource":{"kind":"any"},
         "subject":{"spiffe_prefix":"spiffe:///foo"}}
    ]}"#;
    let rs = parse_json(empty_td).expect("parse succeeds");
    assert!(
        NativeEngine::new(rs).is_err(),
        "empty trust domain must fail compile"
    );
}

// ---------- M7: NatsSubject pattern validation ----------

#[test]
fn nats_subject_empty_pattern_rejected() {
    let bad = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"publish",
         "resource":{"kind":"nats_subject","subject_pattern":""},
         "subject":{}}
    ]}"#;
    let rs = parse_json(bad).expect("parse succeeds");
    assert!(
        NativeEngine::new(rs).is_err(),
        "empty NATS subject_pattern must fail compile"
    );
}

#[test]
fn nats_subject_lone_star_pattern_rejected() {
    // `*` alone would strip_suffix to `""` and match every subject via
    // `starts_with("")`. Operators who want match-all should use
    // `{"kind": "any"}` explicitly.
    let bad = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"publish",
         "resource":{"kind":"nats_subject","subject_pattern":"*"},
         "subject":{}}
    ]}"#;
    let rs = parse_json(bad).expect("parse succeeds");
    assert!(
        NativeEngine::new(rs).is_err(),
        "lone `*` NATS subject_pattern must fail compile"
    );
}

#[test]
fn nats_subject_gt_wildcard_rejected() {
    // NATS's native `>` multi-token wildcard is not implemented by
    // this engine. A rule author who writes `cot.>` expecting the
    // NATS semantics must be told at compile time, not silently get
    // an exact-match rule that never fires.
    let bad = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"publish",
         "resource":{"kind":"nats_subject","subject_pattern":"cot.>"},
         "subject":{}}
    ]}"#;
    let rs = parse_json(bad).expect("parse succeeds");
    assert!(
        NativeEngine::new(rs).is_err(),
        "`>` wildcard must fail compile"
    );
}

#[test]
fn nats_subject_interior_wildcard_without_trailing_rejected() {
    // `cot.*.broadcast` has an interior `*` and no trailing `*`. The
    // engine only supports a single trailing `*`, so without a guard
    // this would silently compile to a literal exact match against
    // the string "cot.*.broadcast" — a dead rule that never fires
    // because real NATS subjects cannot contain `*`. Catch the
    // mistake at compile time.
    let bad = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"publish",
         "resource":{"kind":"nats_subject","subject_pattern":"cot.*.broadcast"},
         "subject":{}}
    ]}"#;
    let rs = parse_json(bad).expect("parse succeeds");
    assert!(
        NativeEngine::new(rs).is_err(),
        "interior `*` with no trailing wildcard must fail compile"
    );
}

#[test]
fn nats_subject_interior_and_trailing_wildcard_rejected() {
    // `cot.*.*` mixes an interior `*` with the supported trailing
    // wildcard. `strip_suffix('*')` succeeds and yields the prefix
    // `cot.*.`, which still contains a `*` that the engine cannot
    // interpret. Reject so the operator rewrites the rule.
    let bad = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"publish",
         "resource":{"kind":"nats_subject","subject_pattern":"cot.*.*"},
         "subject":{}}
    ]}"#;
    let rs = parse_json(bad).expect("parse succeeds");
    assert!(
        NativeEngine::new(rs).is_err(),
        "interior `*` combined with trailing `*` must fail compile"
    );
}

#[test]
fn nats_subject_valid_patterns_still_compile() {
    // Sanity: the allowed forms continue to compile and evaluate.
    let ok = br#"{"version":1,"rules":[
        {"id":"exact","effect":"allow","action":"publish",
         "resource":{"kind":"nats_subject","subject_pattern":"cot.red"},
         "subject":{}},
        {"id":"prefix","effect":"allow","action":"publish",
         "resource":{"kind":"nats_subject","subject_pattern":"telemetry.*"},
         "subject":{}}
    ]}"#;
    let rs = parse_json(ok).expect("parse succeeds");
    let engine = NativeEngine::new(rs).expect("compile succeeds");

    let id = Identity::new("svc".to_string(), "fp".to_string(), BTreeSet::new()).unwrap();
    let subj = Subject::from_identity(&id);

    assert!(
        engine
            .evaluate(
                &subj,
                &Resource::NatsSubject { subject: "cot.red" },
                Action::Publish,
            )
            .is_allow()
    );
    assert!(
        engine
            .evaluate(
                &subj,
                &Resource::NatsSubject {
                    subject: "telemetry.metrics"
                },
                Action::Publish,
            )
            .is_allow()
    );
}
