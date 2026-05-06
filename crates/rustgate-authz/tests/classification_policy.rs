// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for policy-side `ClassificationMarking` enforcement
//! (refs #849).
//!
//! These tests pin the wiring of the new [`AuthzContext`] surface
//! (`rustgate_authz::AuthzContext`) and the override of
//! [`PolicyEngine::evaluate_with_context`] on the optional Cedar
//! backend. The Cedar-specific tests require the `cedar` feature; the
//! backend-agnostic tests (default-context shape, builder helper, native
//! engine pass-through) run unconditionally.
//!
//! # Scope
//!
//! - Item 2 from #849: policy hooks that let Cedar policies condition on
//!   the canonical CAPCO banner string forwarded under
//!   `context.classification.label`.
//! - Items 3 (`Metadata.classification` field), 4 (router enforcement),
//!   and 6 (MIL-STD-2525 SIDC carry on Entity) remain. Item 5
//!   (cross-domain guard) is tracked under #857.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use std::collections::{BTreeMap, BTreeSet};

use rustgate_authz::{
    Action, AuthzContext, Decision, NativeEngine, PolicyEngine, Resource, Subject, SubjectHash,
};
use rustgate_core::AttrValue;
use rustgate_core::classification::{Classification, ClassificationMarking};

/// Build a borrowed [`Subject`] for the given CN with empty groups and
/// attributes. Tests that need group/attribute fields reach into this
/// helper and override the references.
fn subject<'a>(
    cn: &'a str,
    groups: &'a BTreeSet<String>,
    attrs: &'a BTreeMap<String, AttrValue>,
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

// ──────────────────────────────────────────────────────────────────────
// Backend-agnostic surface — runs without `cedar`.
// ──────────────────────────────────────────────────────────────────────

/// `evaluate_with_context` on the [`NativeEngine`] must produce the
/// exact same outcome as `evaluate` when the context is the default
/// (empty). Pin the round-trip so a future change that started reading
/// the context unconditionally on the native path doesn't silently
/// regress the existing fall-through callers — every existing call site
/// continues to work unchanged with `AuthzContext::default()`.
#[test]
fn native_engine_evaluate_with_default_context_matches_evaluate() {
    let engine = NativeEngine::empty();
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject("alice", &groups, &attrs);
    let r = Resource::Broadcast;
    let plain = engine.evaluate(&s, &r, Action::Send);
    let with_ctx = engine.evaluate_with_context(&s, &r, Action::Send, &AuthzContext::default());
    assert_eq!(
        plain.decision, with_ctx.decision,
        "default-context evaluate_with_context must match evaluate"
    );
    assert_eq!(plain.rule_id, with_ctx.rule_id);
    assert_eq!(plain.obligations, with_ctx.obligations);
}

/// `evaluate_with_context` is wired through the `NativeEngine` path
/// even when a non-default context is supplied — the native backend
/// ignores the context today (item 2 ships at the trait surface; the
/// native engine only consumes the marking once item 4 lands), so the
/// outcome must be identical to a contextless evaluate. Pin the
/// pass-through so a regression that started reading the context on
/// the native path without a corresponding rule schema would surface
/// here.
#[test]
fn native_engine_pass_through_with_classification_set() {
    let engine = NativeEngine::empty();
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject("alice", &groups, &attrs);
    let r = Resource::Broadcast;
    let marking = ClassificationMarking::new(Classification::Secret);
    let ctx = AuthzContext::default().with_classification(marking);
    let with_ctx = engine.evaluate_with_context(&s, &r, Action::Send, &ctx);
    let plain = engine.evaluate(&s, &r, Action::Send);
    assert_eq!(
        with_ctx.decision, plain.decision,
        "native engine ignores classification context — outcome must match contextless evaluate"
    );
}

/// The `AuthzContext` round-trips through `evaluate_with_context` on a
/// custom [`PolicyEngine`] implementation. This pins the trait surface
/// itself: a backend that wires its own classification-aware decision
/// logic must observe the exact context passed by the caller. Uses an
/// observer engine that captures the context for inspection.
#[test]
fn engine_passes_classification_through_to_decision_callback() {
    use std::sync::Mutex;

    /// Custom engine that records every context it sees and returns
    /// allow when the marking dominates `//SECRET//`, deny otherwise.
    /// This mirrors the shape a real classification-aware backend
    /// would take while keeping the test self-contained.
    struct RecordingEngine {
        seen: Mutex<Vec<Option<ClassificationMarking>>>,
    }
    impl PolicyEngine for RecordingEngine {
        fn evaluate(
            &self,
            _subject: &Subject<'_>,
            _resource: &Resource<'_>,
            _action: Action,
        ) -> rustgate_authz::DecisionOutcome {
            // Default contextless path lands here; record None and
            // deny so the test can assert that contextful paths
            // override correctly.
            let mut seen = self.seen.lock().expect("recording mutex poisoned");
            seen.push(None);
            rustgate_authz::DecisionOutcome::deny()
        }
        fn evaluate_with_context(
            &self,
            _subject: &Subject<'_>,
            _resource: &Resource<'_>,
            _action: Action,
            ctx: &AuthzContext,
        ) -> rustgate_authz::DecisionOutcome {
            let mut seen = self.seen.lock().expect("recording mutex poisoned");
            seen.push(ctx.classification.clone());
            let secret = ClassificationMarking::new(Classification::Secret);
            match ctx.classification.as_ref() {
                Some(marking) if marking.dominates(&secret) => {
                    rustgate_authz::DecisionOutcome::allow()
                }
                _ => rustgate_authz::DecisionOutcome::deny(),
            }
        }
        fn policy_id(&self) -> &str {
            "recording"
        }
    }

    let engine = RecordingEngine {
        seen: Mutex::new(Vec::new()),
    };
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject("alice", &groups, &attrs);
    let r = Resource::Broadcast;

    // 1) Top-secret marking dominates Secret → allow.
    let top_secret = ClassificationMarking::new(Classification::TopSecret);
    let ctx = AuthzContext::default().with_classification(top_secret.clone());
    let out_ts = engine.evaluate_with_context(&s, &r, Action::Send, &ctx);
    assert_eq!(out_ts.decision, Decision::Allow);

    // 2) Confidential does not dominate Secret → deny.
    let confidential = ClassificationMarking::new(Classification::Confidential);
    let ctx_low = AuthzContext::default().with_classification(confidential.clone());
    let out_c = engine.evaluate_with_context(&s, &r, Action::Send, &ctx_low);
    assert_eq!(out_c.decision, Decision::Deny);

    // The recorded contexts must match what the caller supplied,
    // verbatim — no clone-on-write substitution, no enum re-wrapping.
    let seen = engine.seen.lock().expect("recording mutex poisoned");
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].as_ref(), Some(&top_secret));
    assert_eq!(seen[1].as_ref(), Some(&confidential));
}

/// LUB across two markings drives an egress decision. Even though
/// router-side enforcement (item 4) ships separately, the lattice op
/// must compose with the policy-side context surface so a future
/// router can fold two source markings into a single derivative
/// marking before the call. Pin the wiring at the AuthzContext layer.
#[test]
fn lub_of_two_inputs_drives_egress_decision() {
    use std::sync::Mutex;

    struct LubEngine {
        last_seen: Mutex<Option<ClassificationMarking>>,
    }
    impl PolicyEngine for LubEngine {
        fn evaluate(
            &self,
            _: &Subject<'_>,
            _: &Resource<'_>,
            _: Action,
        ) -> rustgate_authz::DecisionOutcome {
            rustgate_authz::DecisionOutcome::deny()
        }
        fn evaluate_with_context(
            &self,
            _: &Subject<'_>,
            _: &Resource<'_>,
            _: Action,
            ctx: &AuthzContext,
        ) -> rustgate_authz::DecisionOutcome {
            *self.last_seen.lock().expect("mutex") = ctx.classification.clone();
            // Allow when the LUB-encoded marking is at most Secret —
            // a stand-in for the real router-side egress check.
            let secret = ClassificationMarking::new(Classification::Secret);
            match ctx.classification.as_ref() {
                Some(m) if secret.dominates(m) => rustgate_authz::DecisionOutcome::allow(),
                _ => rustgate_authz::DecisionOutcome::deny(),
            }
        }
        fn policy_id(&self) -> &str {
            "lub"
        }
    }

    let engine = LubEngine {
        last_seen: Mutex::new(None),
    };
    let groups = BTreeSet::new();
    let attrs = BTreeMap::new();
    let s = subject("alice", &groups, &attrs);
    let r = Resource::Broadcast;

    // Two inputs at Confidential and Secret → LUB is Secret.
    let a = ClassificationMarking::new(Classification::Confidential);
    let b = ClassificationMarking::new(Classification::Secret);
    let lub = a.lub(&b);
    let ctx = AuthzContext::default().with_classification(lub.clone());
    let out = engine.evaluate_with_context(&s, &r, Action::Send, &ctx);
    assert_eq!(
        out.decision,
        Decision::Allow,
        "Secret-LUB must satisfy a Secret-dominated egress check"
    );
    assert_eq!(
        engine.last_seen.lock().expect("mutex").as_ref(),
        Some(&lub),
        "engine must observe the LUB-folded marking"
    );

    // Two inputs at Secret and TopSecret → LUB is TopSecret → deny.
    let c = ClassificationMarking::new(Classification::Secret);
    let d = ClassificationMarking::new(Classification::TopSecret);
    let lub_high = c.lub(&d);
    let ctx_high = AuthzContext::default().with_classification(lub_high);
    let out_high = engine.evaluate_with_context(&s, &r, Action::Send, &ctx_high);
    assert_eq!(
        out_high.decision,
        Decision::Deny,
        "TopSecret-LUB must fail a Secret-dominated egress check"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Cedar backend wiring — gated on `cedar`.
// ──────────────────────────────────────────────────────────────────────

#[cfg(feature = "cedar")]
mod cedar_classification {
    //! Cedar-backend tests for #849 item 2.
    //!
    //! Each test pins one shape of the classification context wiring:
    //! the canonical banner string lands under
    //! `context.classification.label`, policies can match on substrings
    //! (`contains`), and a malformed reference to an undefined field is
    //! rejected by Cedar's evaluator (forced to deny by our
    //! diagnostics-aware fail-closed override).

    use std::str::FromStr;

    use rustgate_authz::CedarBackend;

    use super::*;

    /// Cedar policy: allow when the marking carries `SECRET` and does
    /// NOT carry `NOFORN`. This is the canonical "release to allies"
    /// pattern for foreign coalition partners — they can read SECRET
    /// material but not the NOFORN-restricted fraction.
    const POLICY_SECRET_NO_NOFORN: &str = r#"
permit(
    principal,
    action == Action::"send",
    resource
)
when {
    context has classification &&
    context.classification has label &&
    context.classification.label like "*SECRET*" &&
    !(context.classification.label like "*NOFORN*")
};
"#;

    #[test]
    fn policy_can_condition_on_classification_label_substring() {
        // The headline integration: a Cedar policy reads the canonical
        // banner string from `context.classification.label` and decides
        // based on substring containment. Pin both directions so a
        // regression that dropped the wire format (e.g. forgot to call
        // `marking.to_string()`) or that flipped the field name
        // (`label` → `value`) would surface here.
        let backend = CedarBackend::from_source(POLICY_SECRET_NO_NOFORN).expect("policy parses");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let r = Resource::Broadcast;

        // Plain SECRET → allow.
        let secret = ClassificationMarking::new(Classification::Secret);
        let ctx = AuthzContext::default().with_classification(secret);
        let out = backend.evaluate_with_context(&s, &r, Action::Send, &ctx);
        assert_eq!(
            out.decision,
            Decision::Allow,
            "policy must permit plain SECRET marking"
        );

        // CONFIDENTIAL → deny (no SECRET in label).
        let conf = ClassificationMarking::new(Classification::Confidential);
        let ctx = AuthzContext::default().with_classification(conf);
        let out = backend.evaluate_with_context(&s, &r, Action::Send, &ctx);
        assert_eq!(
            out.decision,
            Decision::Deny,
            "policy must deny when label lacks SECRET"
        );

        // No classification → deny (the `context has classification`
        // guard short-circuits).
        let out = backend.evaluate_with_context(&s, &r, Action::Send, &AuthzContext::default());
        assert_eq!(
            out.decision,
            Decision::Deny,
            "policy must deny when classification is absent"
        );
    }

    #[test]
    fn policy_denies_when_classification_label_contains_noforn_for_foreign_subject() {
        // The operational example from the brief: a SECRET//NOFORN
        // marking must deny under the "release to allies" policy
        // because of the embedded NOFORN caveat. This is the bit-shape
        // the parser canonicalises in `Display`, so the policy literal
        // can rely on the substring `NOFORN` always appearing in the
        // banner when the marking carries that caveat.
        let backend = CedarBackend::from_source(POLICY_SECRET_NO_NOFORN).expect("policy parses");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let r = Resource::Broadcast;

        // Build SECRET//NOFORN via the canonical parser path so the
        // banner is byte-identical to what production would produce.
        let marking = ClassificationMarking::from_str("//SECRET//NOFORN")
            .expect("canonical SECRET//NOFORN must parse");
        let ctx = AuthzContext::default().with_classification(marking);
        let out = backend.evaluate_with_context(&s, &r, Action::Send, &ctx);
        assert_eq!(
            out.decision,
            Decision::Deny,
            "SECRET//NOFORN must deny under the no-NOFORN policy"
        );
    }

    #[test]
    fn classification_serializes_to_canonical_banner_in_policy_input() {
        // Verify the wire format: a marking constructed
        // programmatically must surface to Cedar with the same banner
        // string that `Display` produces. The most defensible way to
        // pin this without inspecting Cedar internals is to write a
        // policy that checks for an exact banner literal — if the
        // wire format drifts, the equality check fails and the policy
        // denies. Refs #849 — the canonical Display form is the wire
        // contract.
        const POLICY_EXACT_MATCH: &str = r#"
permit(
    principal,
    action == Action::"send",
    resource
)
when {
    context has classification &&
    context.classification has label &&
    context.classification.label == "//SECRET//NOFORN"
};
"#;
        let backend = CedarBackend::from_source(POLICY_EXACT_MATCH).expect("policy parses");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let r = Resource::Broadcast;

        let marking = ClassificationMarking::from_str("//SECRET//NOFORN")
            .expect("canonical SECRET//NOFORN must parse");
        // Sanity: the canonical Display form must equal the literal in
        // the policy. If this ever fails, the parser/Display contract
        // has drifted and the policy author can no longer rely on it.
        assert_eq!(marking.to_string(), "//SECRET//NOFORN");

        let ctx = AuthzContext::default().with_classification(marking);
        let out = backend.evaluate_with_context(&s, &r, Action::Send, &ctx);
        assert_eq!(
            out.decision,
            Decision::Allow,
            "exact-banner Cedar match must succeed for canonical SECRET//NOFORN"
        );
    }

    #[test]
    fn engine_rejects_policy_referencing_undefined_classification_field() {
        // A policy that references a classification field we don't
        // populate (`context.classification.foreign_disclosure`) must
        // fail evaluation. Cedar reports the missing-attribute error
        // via `Response::diagnostics()`, and our fail-closed override
        // forces a deny verdict — so even if the underlying authorizer
        // would have permitted via a separate matching `permit`, the
        // misconfigured rule cannot leak access. This pins the
        // diagnostics-driven deny from `evaluate_inner`.
        const POLICY_BAD_FIELD: &str = r#"
permit(
    principal,
    action == Action::"send",
    resource
)
when {
    context has classification &&
    context.classification.foreign_disclosure == "ALLIES"
};
"#;
        let backend = CedarBackend::from_source(POLICY_BAD_FIELD).expect("policy parses");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let r = Resource::Broadcast;

        let marking = ClassificationMarking::new(Classification::Secret);
        let ctx = AuthzContext::default().with_classification(marking);
        let out = backend.evaluate_with_context(&s, &r, Action::Send, &ctx);
        assert_eq!(
            out.decision,
            Decision::Deny,
            "policy referencing an undefined classification field must deny via fail-closed override"
        );
    }

    #[test]
    fn cedar_evaluate_without_context_matches_evaluate_with_default_context() {
        // Backward-compat: the legacy `evaluate(...)` entrypoint (no
        // context) must produce the same outcome as
        // `evaluate_with_context(..., AuthzContext::default())`. Pin
        // this round-trip on a policy that does NOT touch the
        // classification context — both paths must allow.
        const POLICY_PERMIT_ALL: &str = r#"
permit(
    principal,
    action,
    resource
);
"#;
        let backend = CedarBackend::from_source(POLICY_PERMIT_ALL).expect("policy parses");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let r = Resource::Broadcast;
        let plain = backend.evaluate(&s, &r, Action::Send);
        let with_default =
            backend.evaluate_with_context(&s, &r, Action::Send, &AuthzContext::default());
        assert_eq!(
            plain.decision, with_default.decision,
            "evaluate and evaluate_with_context(default) must agree"
        );
    }
}
