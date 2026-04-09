#![no_main]

//! Fuzz target: `NativeEngine::evaluate` against a small fixed policy.
//!
//! Builds a single engine at start-up (kept alive across fuzz iterations
//! via a `once_cell::Lazy`-like static `OnceLock`) with a `default_effect`
//! of `deny` and a few rules, then drives arbitrary subjects + resources
//! through `evaluate`. Asserts the deny-by-default invariant: when the
//! derived rule would not match the fuzz-generated request, the outcome
//! must be `Deny`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rustgate_authz::{
    Action, Decision, NativeEngine, PolicyEngine, Resource, Subject,
};

static ENGINE: OnceLock<NativeEngine> = OnceLock::new();

fn engine() -> &'static NativeEngine {
    ENGINE.get_or_init(|| {
        // Deny-by-default + exactly one narrow allow rule. Anything that
        // does not exactly match this rule must deny.
        let src = br#"{
            "version": 1,
            "default_effect": "deny",
            "rules": [
                {
                    "id": "allow-alpha-to-bravo",
                    "effect": "allow",
                    "action": "send",
                    "subject": { "cn_eq": "alpha" },
                    "resource": { "kind": "direct", "target_cn": "bravo" }
                }
            ]
        }"#;
        let rs = rustgate_authz::parser::parse_json(src).expect("fixed policy parses");
        NativeEngine::new(rs).expect("fixed policy compiles")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // Derive a (cn, target_cn, action) tuple from the fuzz input.
    let cn_byte = data[0];
    let target_byte = data[1];
    let cn = if cn_byte & 1 == 0 { "alpha" } else { "mallory" };
    let target = if target_byte & 1 == 0 { "bravo" } else { "carol" };

    let action = match data[data.len() - 1] % 5 {
        0 => Action::Send,
        1 => Action::Receive,
        2 => Action::Federate,
        3 => Action::Publish,
        _ => Action::Subscribe,
    };

    let groups: BTreeSet<String> = BTreeSet::new();
    let attrs: BTreeMap<String, rustgate_core::AttrValue> = BTreeMap::new();
    let subject = Subject {
        cn,
        spiffe_id: None,
        groups: &groups,
        attributes: &attrs,
        fingerprint: "",
        subject_hash: 0,
    };
    let resource = Resource::Direct { target_cn: target };

    let outcome = engine().evaluate(&subject, &resource, action);

    // Deny-by-default invariant: only the exact (alpha, bravo, send)
    // tuple is permitted; everything else must deny.
    let is_exact = cn == "alpha" && target == "bravo" && matches!(action, Action::Send);
    if !is_exact {
        assert!(
            matches!(outcome.decision, Decision::Deny),
            "deny-by-default violated for cn={cn} target={target} action={action:?}"
        );
    }
});
