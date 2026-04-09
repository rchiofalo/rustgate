#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use rustgate_authz::parser::parse_json;
use rustgate_authz::{Action, NativeEngine, PolicyEngine, Resource, RuleSet, Subject};
use rustgate_core::identity::Identity;

fn alice() -> Identity {
    Identity::new("alice".to_string(), "fp".to_string(), BTreeSet::new()).unwrap()
}

#[test]
fn empty_policy_denies_all() {
    let engine = NativeEngine::empty();
    let id = alice();
    let subject = Subject::from_identity(&id);
    let resource = Resource::Direct { target_cn: "bob" };
    let out = engine.evaluate(&subject, &resource, Action::Send);
    assert!(!out.is_allow());
}

#[test]
fn missing_rule_denies() {
    let json = br#"{"version":1,"default_effect":"deny","rules":[
        {"id":"r1","effect":"allow","action":"send",
         "resource":{"kind":"broadcast"},"subject":{}}
    ]}"#;
    let set = parse_json(json).unwrap();
    let engine = NativeEngine::new(set).unwrap();
    let id = alice();
    let subject = Subject::from_identity(&id);
    let out = engine.evaluate(
        &subject,
        &Resource::Direct { target_cn: "bob" },
        Action::Send,
    );
    assert!(!out.is_allow());
}

#[test]
fn bad_version_rejected() {
    let json = br#"{"version":2,"rules":[]}"#;
    assert!(parse_json(json).is_err());
}

#[test]
fn duplicate_rule_id_rejected() {
    let json = br#"{"version":1,"rules":[
        {"id":"r1","effect":"allow","action":"send","resource":{"kind":"broadcast"},"subject":{}},
        {"id":"r1","effect":"deny","action":"send","resource":{"kind":"broadcast"},"subject":{}}
    ]}"#;
    assert!(parse_json(json).is_err());
}

#[test]
fn policy_id_is_stable_hex() {
    let json = br#"{"version":1,"rules":[]}"#;
    let set: RuleSet = parse_json(json).unwrap();
    let engine = NativeEngine::new(set).unwrap();
    let id = engine.policy_id();
    assert_eq!(id.len(), 64);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
}
