// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! P99 budget gate for the authz evaluation hot path.
//!
//! The test iterates each documented evaluation pattern a fixed number
//! of times, records wall-clock elapsed nanoseconds per call, and
//! asserts that the 99th-percentile is within the 10µs budget set by
//! the RBAC/ABAC epic (acceptance criterion #4).
//!
//! The test is `#[ignore]`d so `cargo nextest run` skips it by default
//! (micro-benchmarking is slow and noisy on laptops). CI runs it
//! explicitly per PR:
//!
//! ```bash
//! cargo nextest run -p rustgate-authz --run-ignored all perf_budget
//! ```
//!
//! If this test fails on a real machine, do NOT bump the budget. The
//! cache, hash function, or compiled-rule scan is the bug.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;
use std::time::Instant;

use rustgate_authz::parser::parse_json;
use rustgate_authz::{
    Action, DecisionOutcome, NativeEngine, PolicyEngine, Resource, Subject, SubjectHash,
};
use rustgate_core::AttrValue;
use rustgate_core::identity::Identity;

/// P99 budget for every supported evaluation pattern.
const BUDGET_NANOS: u128 = 10_000;

/// Samples per case. Large enough to stabilize the tail, small enough
/// to keep the full test under a minute on CI runners.
const SAMPLES: usize = 100_000;

fn run_with_p99_gate(name: &str, mut f: impl FnMut() -> DecisionOutcome) {
    // Warm up to let the allocator, branch predictor, and decision
    // cache all reach steady state before we start recording.
    for _ in 0..1_000 {
        let _ = black_box(f());
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t = Instant::now();
        let _ = black_box(f());
        samples.push(t.elapsed().as_nanos());
    }
    samples.sort_unstable();
    let p50 = samples[SAMPLES / 2];
    let p99 = samples[(SAMPLES as f64 * 0.99) as usize];
    let p999 = samples[(SAMPLES as f64 * 0.999) as usize];
    eprintln!("{name}: p50={p50}ns p99={p99}ns p99.9={p999}ns budget={BUDGET_NANOS}ns");
    assert!(
        p99 <= BUDGET_NANOS,
        "{name}: P99 {p99}ns exceeded budget {BUDGET_NANOS}ns"
    );
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

fn build_engine(rules_json: &[u8]) -> NativeEngine {
    NativeEngine::new(parse_json(rules_json).unwrap()).unwrap()
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

#[test]
#[ignore = "perf gate — run with --run-ignored all"]
fn perf_budget_p99_under_10us() {
    let id = make_identity();
    let subject_hash = Subject::compute_hash(&id);

    // rbac_single_rule_hit
    let e = build_engine(
        br#"{"version":1,"rules":[
            {"id":"r","effect":"allow","action":"send",
             "resource":{"kind":"broadcast"},
             "subject":{"groups_any_of":["ops"]}}
        ]}"#,
    );
    run_with_p99_gate("rbac_single_rule_hit", || {
        let s = Subject::with_hash(&id, subject_hash);
        e.evaluate(&s, &Resource::Broadcast, Action::Send)
    });

    // rbac_10_rules
    let e = build_engine(many_rules(10, Some(9)).as_bytes());
    run_with_p99_gate("rbac_10_rules", || {
        let s = Subject::with_hash(&id, subject_hash);
        e.evaluate(&s, &Resource::Broadcast, Action::Send)
    });

    // rbac_100_rules
    let e = build_engine(many_rules(100, Some(99)).as_bytes());
    run_with_p99_gate("rbac_100_rules", || {
        let s = Subject::with_hash(&id, subject_hash);
        e.evaluate(&s, &Resource::Broadcast, Action::Send)
    });

    // abac_spiffe_prefix
    let e = build_engine(
        br#"{"version":1,"rules":[
            {"id":"r","effect":"allow","action":"publish",
             "resource":{"kind":"nats_subject","subject_pattern":"cot.*"},
             "subject":{"spiffe_prefix":"spiffe://example.org/ns/prod/"}}
        ]}"#,
    );
    run_with_p99_gate("abac_spiffe_prefix", || {
        let s = Subject::with_hash(&id, subject_hash);
        e.evaluate(
            &s,
            &Resource::NatsSubject { subject: "cot.red" },
            Action::Publish,
        )
    });

    // abac_5_predicates
    let e = build_engine(
        br#"{"version":1,"rules":[
            {"id":"r","effect":"allow","action":"send",
             "resource":{"kind":"broadcast"},
             "subject":{"cn_eq":"alice",
                        "groups_any_of":["ops"],
                        "spiffe_prefix":"spiffe://example.org/",
                        "attribute_eq":{"org":"acme","clearance":3}}}
        ]}"#,
    );
    run_with_p99_gate("abac_5_predicates", || {
        let s = Subject::with_hash(&id, subject_hash);
        e.evaluate(&s, &Resource::Broadcast, Action::Send)
    });

    // cache_hit — 100 rules, steady state same subject/resource/action.
    let e = build_engine(many_rules(100, Some(50)).as_bytes());
    {
        let s = Subject::with_hash(&id, subject_hash);
        let _ = e.evaluate(&s, &Resource::Broadcast, Action::Send);
    }
    run_with_p99_gate("cache_hit", || {
        let s = Subject::with_hash(&id, subject_hash);
        e.evaluate(&s, &Resource::Broadcast, Action::Send)
    });

    // cache_miss_cold — rotate subject hash to force full scans + inserts.
    let e = build_engine(many_rules(10, Some(5)).as_bytes());
    {
        let mut counter: u64 = 0;
        run_with_p99_gate("cache_miss_cold", || {
            counter = counter.wrapping_add(1);
            let perturbed = SubjectHash {
                primary: subject_hash.primary ^ counter,
                secondary: subject_hash.secondary ^ counter.rotate_left(17),
            };
            let s = Subject::with_hash(&id, perturbed);
            e.evaluate(&s, &Resource::Broadcast, Action::Send)
        });
    }

    // worst_case_fallthrough — 100 rules, none match, deny by default.
    let e = build_engine(many_rules(100, None).as_bytes());
    run_with_p99_gate("worst_case_fallthrough", || {
        let s = Subject::with_hash(&id, subject_hash);
        e.evaluate(&s, &Resource::Broadcast, Action::Send)
    });
}
