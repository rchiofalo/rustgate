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
        subject_hash: rustgate_authz::SubjectHash {
            primary: 0,
            secondary: 0,
        },
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
        subject_hash: rustgate_authz::SubjectHash {
            primary: 0,
            secondary: 0,
        },
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

/// A CN whose characters are entirely stripped by `escape()` (quotes,
/// backslashes, control chars) must deny, not fold onto a sentinel
/// `"unknown"` principal. Folding would mean two distinct hostile CNs
/// that both clean to empty would share the same Cedar principal UID,
/// letting any policy targeting the sentinel match an attacker's
/// pathological input. The fix returns `None` from `escape()` on an
/// empty result and the evaluator hard-denies.
///
/// Upstream validation in `Identity::new` already rejects pathological
/// CNs, so this test drives the invariant directly at the backend
/// boundary to pin the fail-closed contract regardless of what the
/// upstream sanitiser lets through.
#[test]
fn cedar_pathological_principal_denies() {
    // A policy that mentions the literal sentinel. If the backend
    // ever reinstates the "unknown" fallback, this permit would
    // match a pathological principal and the assertion below would
    // flip to Allow — the test fails loud.
    let sentinel_policy = r#"
        permit(
            principal == RustgatePrincipal::"unknown",
            action == Action::"send",
            resource == Direct::"bob"
        );
    "#;
    let backend = CedarBackend::from_source(sentinel_policy).expect("policy parses");
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    // All characters get filtered: `"`, `\`, and ASCII control bytes.
    let pathological = "\"\"\\\x01\x02";
    let s = Subject {
        cn: pathological,
        spiffe_id: None,
        groups: &groups,
        attributes: &attrs,
        fingerprint: "",
        subject_hash: rustgate_authz::SubjectHash {
            primary: 0,
            secondary: 0,
        },
    };
    let r = Resource::Direct { target_cn: "bob" };
    let out = backend.evaluate(&s, &r, Action::Send);
    assert!(
        matches!(out.decision, Decision::Deny),
        "principal that escapes to empty must deny, got {:?}",
        out.decision
    );
}

/// Same invariant, driven on the resource side. A Direct target whose
/// CN cleans to empty must deny instead of folding onto the sentinel
/// Direct::"unknown" entity.
#[test]
fn cedar_pathological_resource_denies() {
    let sentinel_policy = r#"
        permit(
            principal == RustgatePrincipal::"alice",
            action == Action::"send",
            resource == Direct::"unknown"
        );
    "#;
    let backend = CedarBackend::from_source(sentinel_policy).expect("policy parses");
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject_alice(&groups, &attrs);
    let pathological_target = "\"\\\x00";
    let r = Resource::Direct {
        target_cn: pathological_target,
    };
    let out = backend.evaluate(&s, &r, Action::Send);
    assert!(
        matches!(out.decision, Decision::Deny),
        "resource that escapes to empty must deny, got {:?}",
        out.decision
    );
}

/// A forbid rule that crashes at evaluation time must still result in
/// `Deny`, not fall through to a matching `permit`. Cedar normally
/// treats a policy that errors as if it did not match, which would
/// turn a broken forbid into a silent allow — unacceptable in a
/// deny-by-default system. The backend's `diagnostics().errors()`
/// check forces the verdict to Deny whenever any policy errors.
#[test]
fn cedar_forbid_runtime_error_forces_deny() {
    // `principal.clearance` is not set on any entity, so accessing
    // it triggers a runtime evaluation error inside Cedar. Without
    // the fail-closed override, the permit would win and Alice
    // would be allowed.
    let src = r#"
        permit(
            principal == RustgatePrincipal::"alice",
            action == Action::"send",
            resource == Direct::"bob"
        );
        forbid(
            principal == RustgatePrincipal::"alice",
            action == Action::"send",
            resource == Direct::"bob"
        ) when { principal.clearance < 5 };
    "#;
    let backend = CedarBackend::from_source(src).expect("policy parses");
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject_alice(&groups, &attrs);
    let r = Resource::Direct { target_cn: "bob" };
    let out = backend.evaluate(&s, &r, Action::Send);
    assert!(
        matches!(out.decision, Decision::Deny),
        "policy error in forbid rule must force-deny, got {:?}",
        out.decision
    );
}
