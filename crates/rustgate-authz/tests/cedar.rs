#![cfg(feature = "cedar")]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Smoke tests for the optional Cedar backend.
//!
//! These tests pin the principal/action/resource mapping defined in
//! `cedar_backend.rs`. They deliberately use a single-rule policy so a
//! failure here points straight at the mapping layer rather than at
//! Cedar's own evaluation semantics.

use std::collections::{BTreeMap, BTreeSet};

use rustgate_authz::{Action, CedarBackend, Decision, PolicyEngine, Resource, Subject};

const POLICY_SRC: &str = r#"
permit(
    principal == RustgatePrincipal::"alice",
    action == Action::"send",
    resource == Direct::"bob"
);
"#;

fn subject_alice<'a>(
    groups: &'a BTreeSet<String>,
    attrs: &'a BTreeMap<String, rustgate_core::AttrValue>,
) -> Subject<'a> {
    Subject {
        cn: "alice",
        spiffe_id: None,
        groups,
        attributes: attrs,
        fingerprint: "",
        subject_hash: 0,
    }
}

#[test]
fn cedar_allow_matches_rule() {
    let backend = CedarBackend::from_source(POLICY_SRC).expect("policy parses");
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject_alice(&groups, &attrs);
    let r = Resource::Direct { target_cn: "bob" };
    let out = backend.evaluate(&s, &r, Action::Send);
    assert!(matches!(out.decision, Decision::Allow));
}

#[test]
fn cedar_deny_on_wrong_principal() {
    let backend = CedarBackend::from_source(POLICY_SRC).expect("policy parses");
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = Subject {
        cn: "mallory",
        spiffe_id: None,
        groups: &groups,
        attributes: &attrs,
        fingerprint: "",
        subject_hash: 0,
    };
    let r = Resource::Direct { target_cn: "bob" };
    let out = backend.evaluate(&s, &r, Action::Send);
    assert!(matches!(out.decision, Decision::Deny));
}

#[test]
fn cedar_deny_on_wrong_resource() {
    let backend = CedarBackend::from_source(POLICY_SRC).expect("policy parses");
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject_alice(&groups, &attrs);
    let r = Resource::Direct { target_cn: "carol" };
    let out = backend.evaluate(&s, &r, Action::Send);
    assert!(matches!(out.decision, Decision::Deny));
}

#[test]
fn cedar_deny_on_wrong_action() {
    let backend = CedarBackend::from_source(POLICY_SRC).expect("policy parses");
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject_alice(&groups, &attrs);
    let r = Resource::Direct { target_cn: "bob" };
    let out = backend.evaluate(&s, &r, Action::Receive);
    assert!(matches!(out.decision, Decision::Deny));
}

#[test]
fn cedar_policy_id_is_stable() {
    let a = CedarBackend::from_source(POLICY_SRC).expect("policy parses");
    let b = CedarBackend::from_source(POLICY_SRC).expect("policy parses");
    assert_eq!(a.policy_id(), b.policy_id());
}

#[test]
fn cedar_cache_stats_returns_none() {
    let backend = CedarBackend::from_source(POLICY_SRC).expect("policy parses");
    assert!(backend.cache_stats().is_none());
}
