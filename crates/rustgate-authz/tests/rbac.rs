#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use rustgate_authz::parser::parse_json;
use rustgate_authz::{Action, NativeEngine, PolicyEngine, Resource, Subject};
use rustgate_core::identity::Identity;

fn user_with_groups(groups: &[&str]) -> Identity {
    let set: BTreeSet<String> = groups.iter().map(|g| (*g).to_string()).collect();
    Identity::new("alice".to_string(), "fp".to_string(), set).unwrap()
}

#[test]
fn groups_any_of_allows() {
    let json = br#"{"version":1,"rules":[
        {"id":"ops-broadcast","effect":"allow","action":"send",
         "resource":{"kind":"broadcast"},
         "subject":{"groups_any_of":["ops","admin"]}}
    ]}"#;
    let engine = NativeEngine::new(parse_json(json).unwrap()).unwrap();
    let id = user_with_groups(&["ops"]);
    let s = Subject::from_identity(&id);
    assert!(
        engine
            .evaluate(&s, &Resource::Broadcast, Action::Send)
            .is_allow()
    );
}

#[test]
fn groups_all_of_requires_all() {
    let json = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"send",
         "resource":{"kind":"broadcast"},
         "subject":{"groups_all_of":["ops","oncall"]}}
    ]}"#;
    let engine = NativeEngine::new(parse_json(json).unwrap()).unwrap();
    let only_ops = user_with_groups(&["ops"]);
    let both = user_with_groups(&["ops", "oncall"]);
    assert!(
        !engine
            .evaluate(
                &Subject::from_identity(&only_ops),
                &Resource::Broadcast,
                Action::Send
            )
            .is_allow()
    );
    assert!(
        engine
            .evaluate(
                &Subject::from_identity(&both),
                &Resource::Broadcast,
                Action::Send
            )
            .is_allow()
    );
}

#[test]
fn explicit_deny_beats_allow() {
    let json = br#"{"version":1,"rules":[
        {"id":"allow-ops","effect":"allow","action":"send",
         "resource":{"kind":"broadcast"},
         "subject":{"groups_any_of":["ops"]}},
        {"id":"deny-quarantine","effect":"deny","action":"send",
         "resource":{"kind":"broadcast"},
         "subject":{"groups_any_of":["quarantine"]}}
    ]}"#;
    let engine = NativeEngine::new(parse_json(json).unwrap()).unwrap();
    let id = user_with_groups(&["ops", "quarantine"]);
    let out = engine.evaluate(
        &Subject::from_identity(&id),
        &Resource::Broadcast,
        Action::Send,
    );
    assert!(!out.is_allow());
    assert_eq!(out.rule_id.as_deref(), Some("deny-quarantine"));
}

#[test]
fn unrelated_action_denied() {
    let json = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"send",
         "resource":{"kind":"broadcast"},"subject":{}}
    ]}"#;
    let engine = NativeEngine::new(parse_json(json).unwrap()).unwrap();
    let id = user_with_groups(&[]);
    assert!(
        !engine
            .evaluate(
                &Subject::from_identity(&id),
                &Resource::Broadcast,
                Action::Receive
            )
            .is_allow()
    );
}
