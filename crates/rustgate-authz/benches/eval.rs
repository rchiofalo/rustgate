#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use rustgate_authz::parser::parse_json;
use rustgate_authz::{Action, NativeEngine, PolicyEngine, Resource, Subject};
use rustgate_core::AttrValue;
use rustgate_core::identity::Identity;

fn build_engine(rules_json: &[u8]) -> NativeEngine {
    NativeEngine::new(parse_json(rules_json).unwrap()).unwrap()
}

fn make_identity() -> Identity {
    let mut groups = BTreeSet::new();
    let _ = groups.insert("ops".to_string());
    let mut attrs = BTreeMap::new();
    let _ = attrs.insert("org".to_string(), AttrValue::Str("acme".to_string()));
    let _ = attrs.insert("clearance".to_string(), AttrValue::Int(3));
    let _ = attrs.insert("on_duty".to_string(), AttrValue::Bool(true));
    let _ = attrs.insert(
        "san_dns".to_string(),
        AttrValue::Set(vec!["a.example.org".to_string()]),
    );
    Identity::new("alice".to_string(), "fp".to_string(), groups)
        .unwrap()
        .with_attributes(attrs)
        .with_spiffe_id("spiffe://example.org/ns/prod/sa/alice")
}

fn many_rules(n: usize, match_at: Option<usize>) -> String {
    let mut rules = Vec::with_capacity(n);
    for i in 0..n {
        let group = if Some(i) == match_at {
            "ops".to_string()
        } else {
            format!("g{i}")
        };
        rules.push(format!(
            r#"{{"id":"r{i}","effect":"allow","action":"send",
                "resource":{{"kind":"broadcast"}},
                "subject":{{"groups_any_of":["{group}"]}}}}"#
        ));
    }
    format!(
        r#"{{"version":1,"default_effect":"deny","rules":[{}]}}"#,
        rules.join(",")
    )
}

fn bench_eval(c: &mut Criterion) {
    let id = make_identity();

    let one = build_engine(
        br#"{"version":1,"rules":[
            {"id":"r","effect":"allow","action":"send",
             "resource":{"kind":"broadcast"},
             "subject":{"groups_any_of":["ops"]}}
        ]}"#,
    );
    c.bench_function("rbac_single_rule_hit", |b| {
        b.iter(|| {
            let s = Subject::from_identity(&id);
            black_box(one.evaluate(&s, &Resource::Broadcast, Action::Send));
        })
    });

    let ten = build_engine(many_rules(10, Some(9)).as_bytes());
    c.bench_function("rbac_10_rules", |b| {
        b.iter(|| {
            let s = Subject::from_identity(&id);
            black_box(ten.evaluate(&s, &Resource::Broadcast, Action::Send));
        })
    });

    let hundred = build_engine(many_rules(100, Some(99)).as_bytes());
    c.bench_function("rbac_100_rules", |b| {
        b.iter(|| {
            let s = Subject::from_identity(&id);
            black_box(hundred.evaluate(&s, &Resource::Broadcast, Action::Send));
        })
    });

    let spiffe = build_engine(
        br#"{"version":1,"rules":[
            {"id":"r","effect":"allow","action":"publish",
             "resource":{"kind":"nats_subject","subject_pattern":"cot.*"},
             "subject":{"spiffe_prefix":"spiffe://example.org/ns/prod/"}}
        ]}"#,
    );
    c.bench_function("abac_spiffe_prefix", |b| {
        b.iter(|| {
            let s = Subject::from_identity(&id);
            black_box(spiffe.evaluate(
                &s,
                &Resource::NatsSubject { subject: "cot.red" },
                Action::Publish,
            ));
        })
    });

    let five = build_engine(
        br#"{"version":1,"rules":[
            {"id":"r","effect":"allow","action":"send",
             "resource":{"kind":"broadcast"},
             "subject":{"cn_eq":"alice",
                        "groups_any_of":["ops"],
                        "spiffe_prefix":"spiffe://example.org/",
                        "attribute_eq":{"org":"acme","clearance":3}}}
        ]}"#,
    );
    c.bench_function("abac_5_predicates", |b| {
        b.iter(|| {
            let s = Subject::from_identity(&id);
            black_box(five.evaluate(&s, &Resource::Broadcast, Action::Send));
        })
    });

    let fallthrough = build_engine(many_rules(100, None).as_bytes());
    c.bench_function("worst_case_fallthrough", |b| {
        b.iter(|| {
            let s = Subject::from_identity(&id);
            black_box(fallthrough.evaluate(&s, &Resource::Broadcast, Action::Send));
        })
    });
}

criterion_group!(benches, bench_eval);
criterion_main!(benches);
