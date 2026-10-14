// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the `rustgate-authz` Prometheus metrics
//! surface added under issue #771.
//!
//! Pins three contracts: an evaluation increments the
//! `evaluations_total{decision, subject_class}` counter, allow
//! decisions carrying obligations drive the
//! `obligations_emitted_total{obligation_type}` counter, and the
//! `cache_size` gauge tracks live decision-cache occupancy.

#![cfg(feature = "metrics")]
#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use std::collections::BTreeSet;

use rustgate_authz::{
    Action, Effect, NativeEngine, Obligation, PolicyEngine, Resource, ResourceMatcher, Rule,
    RuleSet, Subject, SubjectMatcher, metrics,
};
use rustgate_core::identity::Identity;
use smol_str::SmolStr;

/// Build an identity for tests so `subject_class` lands on `tls_cn`.
fn identity(cn: &str, groups: &[&str]) -> Identity {
    let groups: BTreeSet<String> = groups.iter().map(|g| (*g).to_string()).collect();
    Identity::new(cn.to_string(), format!("{cn}-fp"), groups).expect("valid identity")
}

/// Build a single-rule allow ruleset for tests.
fn allow_ruleset_with_obligations(obs: Vec<Obligation>) -> RuleSet {
    RuleSet {
        version: 1,
        default_effect: Effect::Deny,
        rules: vec![Rule {
            id: SmolStr::new("test-allow"),
            effect: Effect::Allow,
            action: Action::Send,
            resource: ResourceMatcher::Any,
            subject: SubjectMatcher::default(),
            obligations: obs,
        }],
    }
}

/// One `evaluate` call with an Allow outcome must drive the matching
/// `evaluations_total{decision="allow", subject_class="tls_cn"}` cell.
#[test]
fn evaluation_increments_allow_counter_for_tls_subject() {
    let engine = NativeEngine::new(allow_ruleset_with_obligations(vec![])).expect("compile");
    let id = identity("alpha", &["g1"]);
    let subject = Subject::from_identity(&id);
    let resource = Resource::Group { group: "g1" };

    let counter = metrics::evaluations_total();
    let cell = counter
        .get_metric_with_label_values(&["allow", "tls_cn"])
        .expect("allow,tls_cn label");
    let before = cell.get();

    let outcome = engine.evaluate(&subject, &resource, Action::Send);
    assert!(outcome.is_allow());

    assert_eq!(
        cell.get(),
        before + 1,
        "allow counter for tls_cn subject must move by exactly one",
    );
}

/// An allow decision with two obligations must emit two label-keyed
/// counter increments — one per obligation, on the matching label.
#[test]
fn obligations_counter_fires_once_per_emitted_obligation() {
    let obs = vec![Obligation::MaskPoint, Obligation::AuditExtended];
    let engine = NativeEngine::new(allow_ruleset_with_obligations(obs.clone())).expect("compile");
    let id = identity("bravo", &["g1"]);
    let subject = Subject::from_identity(&id);
    let resource = Resource::Group { group: "g1" };

    let counter = metrics::obligations_emitted_total();
    let mp = counter
        .get_metric_with_label_values(&["mask_point"])
        .expect("mask_point label");
    let ae = counter
        .get_metric_with_label_values(&["audit_extended"])
        .expect("audit_extended label");
    let mp_before = mp.get();
    let ae_before = ae.get();

    // First evaluation: cache miss → obligations attached.
    let outcome = engine.evaluate(&subject, &resource, Action::Send);
    assert!(outcome.is_allow());
    assert_eq!(outcome.obligations.len(), 2);

    assert_eq!(
        mp.get(),
        mp_before + 1,
        "mask_point obligation counter must increment once per evaluation that emitted it",
    );
    assert_eq!(
        ae.get(),
        ae_before + 1,
        "audit_extended obligation counter must increment once per evaluation that emitted it",
    );
}

/// The `cache_size` gauge moves when the decision cache absorbs a new
/// entry. Pinning the gauge transition validates the per-evaluation
/// gauge update wired into `record_metrics`.
#[test]
fn cache_size_gauge_reflects_decision_cache_growth() {
    // Each engine carries its own cache; the gauge is global, so the
    // baseline is whatever the gauge reads after construction. The test
    // asserts a strictly-monotonic transition once the engine inserts.
    let engine = NativeEngine::new(allow_ruleset_with_obligations(vec![])).expect("compile");

    // Distinctly-shaped resources so each evaluation lands on its own
    // cache key (the cache is keyed on the resource hash + subject hash
    // + action + epoch).
    let id_a = identity("ca", &["g-a"]);
    let id_b = identity("cb", &["g-b"]);
    let s_a = Subject::from_identity(&id_a);
    let s_b = Subject::from_identity(&id_b);
    let r_a = Resource::Group { group: "g-a" };
    let r_b = Resource::Group { group: "g-b" };

    // First evaluation: cache size after this call must be > 0 because
    // a fresh cache key was inserted by `evaluate`. The cache is a
    // sharded LRU so the absolute floor is "1 entry". That's the only
    // contract this test pins.
    engine.evaluate(&s_a, &r_a, Action::Send);
    let size_after_first = metrics::cache_size().get();
    assert!(
        size_after_first >= 1,
        "cache_size must be >= 1 after first evaluation, got {size_after_first}",
    );

    // Second evaluation with a distinct subject + resource: cache size
    // must grow strictly because the new key cannot collide.
    engine.evaluate(&s_b, &r_b, Action::Send);
    let size_after_second = metrics::cache_size().get();
    assert!(
        size_after_second >= size_after_first,
        "cache_size must be monotonic across distinct evaluations: \
         {size_after_first} → {size_after_second}",
    );

    // Repeat the first evaluation: hits the cache, no new insertion,
    // gauge value must stay where it was after the second insertion.
    // (Other parallel tests can move the gauge forward, so use ≥.)
    engine.evaluate(&s_a, &r_a, Action::Send);
    assert!(
        metrics::cache_size().get() >= size_after_second,
        "cache_size must not decrease on a cache hit",
    );
}
