#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use proptest::prelude::*;
use rustgate_authz::policy::{Effect, ResourceMatcher, Rule, RuleSet, SubjectMatcher};
use rustgate_authz::{Action, NativeEngine, PolicyEngine, Resource, Subject};
use rustgate_core::identity::Identity;

fn arb_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::Send),
        Just(Action::Receive),
        Just(Action::Federate),
        Just(Action::Publish),
        Just(Action::Subscribe),
    ]
}

fn arb_resource_matcher() -> impl Strategy<Value = ResourceMatcher> {
    prop_oneof![
        Just(ResourceMatcher::Broadcast),
        Just(ResourceMatcher::Any),
        Just(ResourceMatcher::Direct { target_cn: None }),
        "[a-z]{1,8}".prop_map(|g| ResourceMatcher::Group { group: g }),
    ]
}

fn arb_rule(i: usize) -> impl Strategy<Value = Rule> {
    (arb_action(), arb_resource_matcher(), any::<bool>()).prop_map(move |(a, r, allow)| Rule {
        id: format!("r{i}").into(),
        effect: if allow { Effect::Allow } else { Effect::Deny },
        action: a,
        resource: r,
        subject: SubjectMatcher::default(),
        obligations: Vec::new(),
    })
}

fn arb_ruleset() -> impl Strategy<Value = RuleSet> {
    (0usize..6).prop_flat_map(|n| {
        let strategies: Vec<_> = (0..n).map(arb_rule).collect();
        strategies.prop_map(|rules| RuleSet {
            version: 1,
            default_effect: Effect::Deny,
            rules,
        })
    })
}

fn sample_id() -> Identity {
    Identity::new("alice".to_string(), "fp".to_string(), BTreeSet::new()).unwrap()
}

proptest! {
    #[test]
    fn compile_never_panics(set in arb_ruleset()) {
        // Unique rule ids are guaranteed by enumeration above.
        let _ = NativeEngine::new(set);
    }

    #[test]
    fn empty_policy_always_denies(action in arb_action()) {
        let engine = NativeEngine::empty();
        let id = sample_id();
        let subject = Subject::from_identity(&id);
        let out = engine.evaluate(&subject, &Resource::Broadcast, action);
        prop_assert!(!out.is_allow());
        let out = engine.evaluate(&subject, &Resource::Direct { target_cn: "x" }, action);
        prop_assert!(!out.is_allow());
    }

    #[test]
    fn default_allow_policy_allows(action in arb_action()) {
        let set = RuleSet {
            version: 1,
            default_effect: Effect::Allow,
            rules: Vec::new(),
        };
        let engine = NativeEngine::new(set).unwrap();
        let id = sample_id();
        let subject = Subject::from_identity(&id);
        prop_assert!(
            engine
                .evaluate(&subject, &Resource::Broadcast, action)
                .is_allow()
        );
    }
}
