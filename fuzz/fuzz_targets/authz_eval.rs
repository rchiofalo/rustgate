// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
    Action, Decision, NativeEngine, PolicyEngine, Resource, Subject, SubjectHash,
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

    // Derive a fresh 128-bit SubjectHash per iteration from the fuzz
    // input so the cache exercise both halves of the pair and their
    // interaction in the shard-index mix (primary ^ secondary<<17 ^
    // resource_hash<<31). A constant hash would wedge every request
    // into the same shard and defeat the length-prefix and
    // discriminant disambiguation the key is designed to resist.
    let primary = u64::from_le_bytes([
        data[0],
        data[data.len().saturating_sub(1)],
        cn_byte.wrapping_mul(17),
        target_byte.wrapping_mul(31),
        cn_byte ^ 0x5a,
        target_byte ^ 0xa5,
        cn_byte.rotate_left(3),
        target_byte.rotate_left(5),
    ]);
    let secondary = u64::from_le_bytes([
        target_byte,
        cn_byte,
        data[data.len().saturating_sub(1)].wrapping_add(13),
        data[0].wrapping_add(29),
        (cn_byte ^ target_byte).wrapping_mul(11),
        cn_byte.rotate_right(2),
        target_byte.rotate_right(4),
        (cn_byte.wrapping_add(target_byte)) ^ 0x3c,
    ]);
    let subject_hash = SubjectHash { primary, secondary };

    let groups: BTreeSet<String> = BTreeSet::new();
    let attrs: BTreeMap<String, rustgate_core::AttrValue> = BTreeMap::new();
    let subject = Subject {
        cn,
        spiffe_id: None,
        groups: &groups,
        attributes: &attrs,
        fingerprint: "",
        subject_hash,
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
