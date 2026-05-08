// Copyright © 2026 Roberto Chiofalo.

#![cfg(all(feature = "cedar", feature = "cjadc2"))]
#![allow(clippy::panic, clippy::unwrap_used)]

//! End-to-end tests for CJADC2 multi-domain routing (closes #853).
//!
//! These tests pin the `@route("…")` annotation contract: the Cedar
//! backend evaluates `Action::"Route"` requests, walks the
//! determining-policy set, and parses each contributing policy's
//! `@route` JSON annotation into a `RoutingDecision` that the router's
//! egress fan-out planner consumes. The unit tests in
//! `src/route.rs` pin the merge / serde behaviour; these integration
//! tests pin the round-trip through Cedar so a future change to the
//! annotation key, the JSON schema, or the determining-policy walk
//! fails here before it lands in production.

use std::collections::{BTreeMap, BTreeSet};

use rustgate_authz::{
    Action, AuthzContext, CedarBackend, Decision, PolicyEngine, Resource, RouteObligation, Subject,
    SubjectHash,
};

fn subject<'a>(
    cn: &'a str,
    groups: &'a BTreeSet<String>,
    attrs: &'a BTreeMap<String, rustgate_core::AttrValue>,
) -> Subject<'a> {
    Subject {
        cn,
        spiffe_id: None,
        groups,
        attributes: attrs,
        fingerprint: "",
        subject_hash: SubjectHash {
            primary: 0,
            secondary: 0,
        },
    }
}

#[test]
fn route_decision_lifts_route_annotation_into_destinations_and_obligations() {
    // A single permit policy with a `@route` annotation describing
    // a three-destination fan-out. The annotation JSON pins the
    // wire-format contract policy authors will write against.
    let policy = r#"
        @route("{\"destinations\": [\"lattice\", \"link16\", \"foundry\"], \"obligations\": {\"lattice\": [], \"link16\": [{\"type\": \"set-classification\", \"value\": \"S\"}], \"foundry\": [{\"type\": \"drop-fields\", \"value\": [\"sensor_uid\"]}]}}")
        permit (
            principal == RustgatePrincipal::"sensor-01",
            action == Action::"Route",
            resource == Direct::"any-target"
        );
    "#;

    let backend = CedarBackend::from_source(policy).expect("policy parses");

    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject("sensor-01", &groups, &attrs);
    let r = Resource::Direct {
        target_cn: "any-target",
    };
    let ctx = AuthzContext::default();

    let decision = backend.evaluate_route(&s, &r, &ctx);

    assert_eq!(
        decision.destinations,
        vec![
            "lattice".to_string(),
            "link16".to_string(),
            "foundry".to_string()
        ],
        "destinations must match the policy's @route annotation"
    );

    // Lattice has no obligations attached.
    assert!(
        decision.obligations_for("lattice").is_empty(),
        "lattice should have no obligations"
    );

    // Link 16 sets classification.
    let link16 = decision.obligations_for("link16");
    assert_eq!(link16.len(), 1);
    assert!(matches!(
        &link16[0],
        RouteObligation::SetClassification(s) if s == "S"
    ));

    // Foundry drops the sensor_uid field.
    let foundry = decision.obligations_for("foundry");
    assert_eq!(foundry.len(), 1);
    match &foundry[0] {
        RouteObligation::DropFields(fields) => {
            assert_eq!(fields, &vec!["sensor_uid".to_string()]);
        }
        other => panic!("expected DropFields, got {other:?}"),
    }
}

#[test]
fn route_decision_empty_when_principal_does_not_match() {
    // The `@route` annotation must still fail closed if the principal
    // does not match the policy — `evaluate_route` should return
    // `RoutingDecision::none` so the router falls back to its
    // non-CJADC2 dispatch path.
    let policy = r#"
        @route("{\"destinations\": [\"lattice\"], \"obligations\": {}}")
        permit (
            principal == RustgatePrincipal::"sensor-01",
            action == Action::"Route",
            resource == Direct::"any-target"
        );
    "#;

    let backend = CedarBackend::from_source(policy).expect("policy parses");

    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject("intruder", &groups, &attrs);
    let r = Resource::Direct {
        target_cn: "any-target",
    };
    let ctx = AuthzContext::default();

    let decision = backend.evaluate_route(&s, &r, &ctx);
    assert!(
        decision.is_empty(),
        "non-matching principal must produce an empty routing decision"
    );
}

#[test]
fn route_decision_aggregates_across_multiple_matching_policies() {
    // Two policies match the same Route request — the backend must
    // merge their `@route` annotations: destination set is unioned,
    // per-destination obligations are concatenated.
    let policy = r#"
        @route("{\"destinations\": [\"lattice\", \"link16\"], \"obligations\": {\"link16\": [{\"type\": \"set-classification\", \"value\": \"S\"}]}}")
        permit (
            principal == RustgatePrincipal::"sensor-01",
            action == Action::"Route",
            resource == Direct::"any-target"
        );

        @route("{\"destinations\": [\"link16\", \"foundry\"], \"obligations\": {\"link16\": [{\"type\": \"tag\", \"value\": \"NOFORN\"}]}}")
        permit (
            principal == RustgatePrincipal::"sensor-01",
            action == Action::"Route",
            resource == Direct::"any-target"
        );
    "#;

    let backend = CedarBackend::from_source(policy).expect("policy parses");

    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject("sensor-01", &groups, &attrs);
    let r = Resource::Direct {
        target_cn: "any-target",
    };
    let ctx = AuthzContext::default();

    let decision = backend.evaluate_route(&s, &r, &ctx);

    // Destination set is unioned — three distinct destinations.
    assert_eq!(decision.destinations.len(), 3);
    assert!(decision.destinations.contains(&"lattice".to_string()));
    assert!(decision.destinations.contains(&"link16".to_string()));
    assert!(decision.destinations.contains(&"foundry".to_string()));

    // Per-destination obligations are concatenated — Link 16 gets two
    // obligations (one from each policy).
    let link16 = decision.obligations_for("link16");
    assert_eq!(
        link16.len(),
        2,
        "link16 should aggregate obligations from both policies"
    );
}

#[test]
fn route_decision_skips_policies_with_malformed_annotations() {
    // A policy whose `@route` annotation is not valid JSON is logged
    // at warn! and skipped — the live policy in the same set continues
    // to contribute its destinations. This is the policy-author bug
    // path and must not take down the entire fan-out.
    let policy = r#"
        @route("not-json-at-all")
        permit (
            principal == RustgatePrincipal::"sensor-01",
            action == Action::"Route",
            resource == Direct::"any-target"
        );

        @route("{\"destinations\": [\"lattice\"], \"obligations\": {}}")
        permit (
            principal == RustgatePrincipal::"sensor-01",
            action == Action::"Route",
            resource == Direct::"any-target"
        );
    "#;

    let backend = CedarBackend::from_source(policy).expect("policy parses");

    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject("sensor-01", &groups, &attrs);
    let r = Resource::Direct {
        target_cn: "any-target",
    };
    let ctx = AuthzContext::default();

    let decision = backend.evaluate_route(&s, &r, &ctx);
    assert_eq!(
        decision.destinations,
        vec!["lattice".to_string()],
        "the malformed-annotation policy must be skipped, the well-formed one applied"
    );
}

#[test]
fn route_decision_empty_when_policy_set_has_no_route_annotations() {
    // A policy that permits Route but carries no `@route` annotation
    // produces an empty routing decision. The verdict is allow (so a
    // future enhancement could attach default destinations) but no
    // destinations are named.
    let policy = r#"
        permit (
            principal == RustgatePrincipal::"sensor-01",
            action == Action::"Route",
            resource == Direct::"any-target"
        );
    "#;

    let backend = CedarBackend::from_source(policy).expect("policy parses");

    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject("sensor-01", &groups, &attrs);
    let r = Resource::Direct {
        target_cn: "any-target",
    };
    let ctx = AuthzContext::default();

    let decision = backend.evaluate_route(&s, &r, &ctx);
    assert!(
        decision.is_empty(),
        "no @route annotation = no routing destinations"
    );
}

#[test]
fn route_action_does_not_grant_send() {
    // A policy that permits `Action::"Route"` must NOT also permit
    // `Action::"send"` — the actions are distinct and operators must
    // gate Send and Route independently. This pins the action-name
    // contract: a `permit` for Route is NOT a permit for Send.
    let policy = r#"
        @route("{\"destinations\": [\"lattice\"], \"obligations\": {}}")
        permit (
            principal == RustgatePrincipal::"sensor-01",
            action == Action::"Route",
            resource == Direct::"any-target"
        );
    "#;

    let backend = CedarBackend::from_source(policy).expect("policy parses");

    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject("sensor-01", &groups, &attrs);
    let r = Resource::Direct {
        target_cn: "any-target",
    };

    // Send must deny — the policy only permits Route.
    let send_outcome = backend.evaluate(&s, &r, Action::Send);
    assert!(matches!(send_outcome.decision, Decision::Deny));

    // Route must produce destinations.
    let route_decision = backend.evaluate_route(&s, &r, &AuthzContext::default());
    assert!(!route_decision.is_empty());
}
