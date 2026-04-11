// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use rustgate_authz::parser::parse_json;
use rustgate_authz::{Action, NativeEngine, PolicyEngine, Resource, Subject};
use rustgate_core::AttrValue;
use rustgate_core::identity::Identity;

fn id_with(spiffe: Option<&str>, attrs: BTreeMap<String, AttrValue>) -> Identity {
    let mut id = Identity::new("svc".to_string(), "fp".to_string(), BTreeSet::new()).unwrap();
    id = id.with_attributes(attrs);
    if let Some(s) = spiffe {
        id = id.with_spiffe_id(s);
    }
    id
}

#[test]
fn spiffe_prefix_matches() {
    let json = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"publish",
         "resource":{"kind":"nats_subject","subject_pattern":"cot.*"},
         "subject":{"spiffe_prefix":"spiffe://example.org/ns/prod/"}}
    ]}"#;
    let engine = NativeEngine::new(parse_json(json).unwrap()).unwrap();

    let good = id_with(Some("spiffe://example.org/ns/prod/sa/foo"), BTreeMap::new());
    let bad = id_with(Some("spiffe://example.org/ns/dev/sa/foo"), BTreeMap::new());
    let res = Resource::NatsSubject { subject: "cot.red" };

    assert!(
        engine
            .evaluate(&Subject::from_identity(&good), &res, Action::Publish)
            .is_allow()
    );
    assert!(
        !engine
            .evaluate(&Subject::from_identity(&bad), &res, Action::Publish)
            .is_allow()
    );
}

#[test]
fn attribute_eq_scalar_types() {
    let json = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"send",
         "resource":{"kind":"any"},
         "subject":{"attribute_eq":{"org":"acme","clearance":3,"on_duty":true}}}
    ]}"#;
    let engine = NativeEngine::new(parse_json(json).unwrap()).unwrap();

    let mut attrs = BTreeMap::new();
    let _ = attrs.insert("org".to_string(), AttrValue::Str("acme".to_string()));
    let _ = attrs.insert("clearance".to_string(), AttrValue::Int(3));
    let _ = attrs.insert("on_duty".to_string(), AttrValue::Bool(true));
    let id = id_with(None, attrs);
    assert!(
        engine
            .evaluate(
                &Subject::from_identity(&id),
                &Resource::Direct { target_cn: "bob" },
                Action::Send
            )
            .is_allow()
    );

    let mut wrong = BTreeMap::new();
    let _ = wrong.insert("org".to_string(), AttrValue::Str("evil".to_string()));
    let _ = wrong.insert("clearance".to_string(), AttrValue::Int(3));
    let _ = wrong.insert("on_duty".to_string(), AttrValue::Bool(true));
    let id2 = id_with(None, wrong);
    assert!(
        !engine
            .evaluate(
                &Subject::from_identity(&id2),
                &Resource::Direct { target_cn: "bob" },
                Action::Send
            )
            .is_allow()
    );
}

#[test]
fn attribute_set_subset() {
    let json = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"federate",
         "resource":{"kind":"federation"},
         "subject":{"attribute_eq":{"san_dns":["router-1.example.org"]}}}
    ]}"#;
    let engine = NativeEngine::new(parse_json(json).unwrap()).unwrap();

    let mut attrs = BTreeMap::new();
    let _ = attrs.insert(
        "san_dns".to_string(),
        AttrValue::Set(vec![
            "router-1.example.org".to_string(),
            "alt.example.org".to_string(),
        ]),
    );
    let id = id_with(None, attrs);
    assert!(
        engine
            .evaluate(
                &Subject::from_identity(&id),
                &Resource::Federation { peer_id: "peer-a" },
                Action::Federate,
            )
            .is_allow()
    );
}

#[test]
fn combined_predicates() {
    let json = br#"{"version":1,"rules":[
        {"id":"r","effect":"allow","action":"send",
         "resource":{"kind":"group","group":"blue"},
         "subject":{"groups_any_of":["ops"],
                    "spiffe_prefix":"spiffe://ex/",
                    "attribute_eq":{"clearance":5}}}
    ]}"#;
    let engine = NativeEngine::new(parse_json(json).unwrap()).unwrap();

    let mut groups = BTreeSet::new();
    let _ = groups.insert("ops".to_string());
    let mut attrs = BTreeMap::new();
    let _ = attrs.insert("clearance".to_string(), AttrValue::Int(5));
    let mut id = Identity::new("svc".to_string(), "fp".to_string(), groups).unwrap();
    id = id.with_attributes(attrs).with_spiffe_id("spiffe://ex/a");

    assert!(
        engine
            .evaluate(
                &Subject::from_identity(&id),
                &Resource::Group { group: "blue" },
                Action::Send,
            )
            .is_allow()
    );
}
