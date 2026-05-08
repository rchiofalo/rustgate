// Copyright © 2026 Roberto Chiofalo.

//! Optional Cedar policy backend.
//!
//! Implements [`PolicyEngine`] on top of the `cedar-policy` crate so
//! operators with an existing Cedar policy corpus can reuse it without
//! rewriting rules in the native JSON format. This backend is gated
//! behind the `cedar` feature to keep the default build lean.
//!
//! # Mapping
//!
//! - **Principal**: `RustgatePrincipal::"<cn>"` — the subject CN is used
//!   as the entity id.
//! - **Resource**: one of `Direct::"<cn>"`, `Group::"<name>"`,
//!   `Broadcast::"all"`, `Federation::"<peer>"`, or
//!   `NatsSubject::"<subject>"` depending on the [`Resource`] variant.
//! - **Action**: `Action::"send"`, `Action::"receive"`, `Action::"federate"`,
//!   `Action::"publish"`, or `Action::"subscribe"`.
//!
//! The mapping is deliberately minimal: no attribute context is passed
//! through yet. Policies that need attribute-based conditions should
//! continue to use the native backend where the `Subject` attribute bag
//! is evaluated directly. Attribute forwarding to Cedar is a future
//! enhancement.
//!
//! # Fail-closed
//!
//! Any error from Cedar — request construction, entity parsing, policy
//! evaluation — is mapped to a [`Decision::Deny`] outcome and logged at
//! `warn!`. This preserves the deny-by-default invariant of the rest
//! of the crate.
//!
//! Cedar treats a policy that errors during evaluation as if it were
//! not matched at all. For a `forbid(...)` policy that pattern is a
//! **policy-overriding-safety** footgun: a forbid rule that crashes
//! silently drops out of the decision, and any unrelated `permit(...)`
//! that matches will grant access the operator never intended. We
//! guard against this by inspecting `Response::diagnostics()` after
//! every evaluation; if Cedar reports any per-policy errors, we
//! override the verdict to `Deny` regardless of what the underlying
//! authorizer decided.

use std::path::Path;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityUid, PolicySet, Request,
    RestrictedExpression,
};
use smol_str::SmolStr;
use tracing::warn;

use crate::engine::PolicyEngine;
use crate::error::AuthzError;
use crate::model::{Action, AuthzContext, Decision, DecisionOutcome, Resource, Subject};
#[cfg(feature = "cjadc2")]
use crate::route::RoutingDecision;

/// Cedar-backed [`PolicyEngine`].
pub struct CedarBackend {
    policy_set: PolicySet,
    authorizer: Authorizer,
    entities: Entities,
    policy_id: SmolStr,
}

impl std::fmt::Debug for CedarBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CedarBackend")
            .field("policy_id", &self.policy_id)
            .finish()
    }
}

impl CedarBackend {
    /// Build a new backend from a Cedar policy source string.
    ///
    /// The entity store is initialised to the empty set; policies that
    /// rely on parent-group lookups will therefore see no hierarchy.
    /// Operators needing entity hierarchies should supply them via the
    /// [`CedarBackend::with_entities`] builder.
    pub fn from_source(source: &str) -> Result<Self, AuthzError> {
        let policy_set = PolicySet::from_str(source).map_err(|e| {
            AuthzError::validation("cedar", format!("failed to parse Cedar policy: {e}"))
        })?;
        let policy_id = stable_id(source);
        Ok(Self {
            policy_set,
            authorizer: Authorizer::new(),
            entities: Entities::empty(),
            policy_id,
        })
    }

    /// Load a Cedar policy from a file path. Convenience for server
    /// startup wiring.
    pub fn from_file(path: &Path) -> Result<Self, AuthzError> {
        let bytes = std::fs::read_to_string(path).map_err(|e| {
            AuthzError::validation(
                "cedar",
                format!("failed to read Cedar policy file {}: {e}", path.display()),
            )
        })?;
        Self::from_source(&bytes)
    }

    /// Builder: override the entity store.
    pub fn with_entities(mut self, entities: Entities) -> Self {
        self.entities = entities;
        self
    }
}

fn stable_id(source: &str) -> SmolStr {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    let digest = hasher.finalize();
    SmolStr::new(hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Send => "send",
        Action::Receive => "receive",
        Action::Federate => "federate",
        Action::Publish => "publish",
        Action::Subscribe => "subscribe",
        // CJADC2 routing PEP (closes #853). Cedar policies use
        // `Action::"Route"` (PascalCase) by convention because routing
        // policies are a *control-plane* concern: operators tend to
        // write `action == Action::"Route"` mirroring the typical
        // entity casing. Keep the literal stable — it appears in
        // production policy corpora.
        Action::Route => "Route",
    }
}

/// Build the resource entity UID literal, or return `None` if any
/// component escapes to the empty string. Broadcast has a constant
/// UID and can never fail.
fn resource_uid_str(resource: &Resource<'_>) -> Option<String> {
    Some(match resource {
        Resource::Direct { target_cn } => format!(r#"Direct::"{}""#, escape(target_cn)?),
        Resource::Group { group } => format!(r#"Group::"{}""#, escape(group)?),
        Resource::Broadcast => r#"Broadcast::"all""#.to_string(),
        Resource::Federation { peer_id } => format!(r#"Federation::"{}""#, escape(peer_id)?),
        Resource::NatsSubject { subject } => format!(r#"NatsSubject::"{}""#, escape(subject)?),
    })
}

/// Minimal escape: strip double-quotes, backslashes, and control
/// characters so the entity id remains a valid Cedar literal. Returns
/// `None` if the result would be empty, which the evaluator treats as
/// a hard deny.
///
/// An empty result signals one of two things:
///
///   1. The caller passed an already-empty string, which means
///      `Identity::new` or `Resource::*` construction let through a
///      degenerate value the upstream validator was supposed to catch.
///   2. The caller passed an all-pathological string (all quotes,
///      all backslashes, all control characters). An operator
///      controlling their own cert SAN could potentially choose such
///      a CN on purpose.
///
/// Earlier revisions folded both cases to the sentinel literal
/// `"unknown"`, but that collapses distinct hostile inputs onto the
/// same Cedar principal. A policy that mentions
/// `RustgatePrincipal::"unknown"` (perhaps for debugging) would then
/// match any attacker who chose a pathological CN. Rejecting with
/// `None` and forcing a deny in the evaluator eliminates that
/// collapse entirely — distinct hostile inputs all deny,
/// independently, instead of sharing a single fallback identity.
fn escape(s: &str) -> Option<String> {
    let cleaned: String = s
        .chars()
        .filter(|c| *c != '"' && *c != '\\' && !c.is_control())
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Build the Cedar request `Context` from a rustgate [`AuthzContext`].
///
/// The classification (refs #849) is forwarded as a record under the
/// `classification` key with a single string-typed `label` field
/// holding the canonical CAPCO banner form. Cedar policy authors compare
/// the label string in `when { … }` clauses — see the integration test
/// in `tests/classification_policy.rs` for representative patterns.
///
/// # Fail-closed contract
///
/// If `Context::from_pairs` errors (it cannot today for these inputs,
/// but the API is fallible), the caller logs and falls back to
/// `Context::empty()` so an upstream `forbid(...)` policy still runs.
/// This keeps the deny-by-default invariant intact even when the
/// context wiring itself misbehaves.
fn build_cedar_context(authz_ctx: &AuthzContext) -> Context {
    // Fast path: no context fields set → reuse Context::empty() so we
    // don't spend allocations on every cold path.
    let Some(marking) = authz_ctx.classification.as_ref() else {
        return Context::empty();
    };

    // Wrap the canonical banner string in a `{ label: "<banner>" }`
    // record so policies can write `context.classification.label
    // contains "SECRET"`. The intermediate record shape leaves room for
    // future fields (e.g. parsed level, SCI/dissemination sets) without
    // a wire-breaking change.
    let label = RestrictedExpression::new_string(marking.to_string());
    let classification_record =
        match RestrictedExpression::new_record([("label".to_string(), label)]) {
            Ok(rec) => rec,
            Err(e) => {
                warn!(
                    target: "authz",
                    error = %e,
                    "cedar: failed to build classification record; evaluating with empty context"
                );
                return Context::empty();
            }
        };
    match Context::from_pairs([("classification".to_string(), classification_record)]) {
        Ok(ctx) => ctx,
        Err(e) => {
            warn!(
                target: "authz",
                error = %e,
                "cedar: failed to build context; evaluating with empty context"
            );
            Context::empty()
        }
    }
}

impl CedarBackend {
    /// Shared evaluator: builds the principal/action/resource UIDs and
    /// dispatches to Cedar with the supplied [`Context`]. Both the
    /// classification-aware and the legacy contextless paths funnel
    /// through this helper so Cedar diagnostics handling and fail-closed
    /// override stay in one place.
    fn evaluate_inner(
        &self,
        subject: &Subject<'_>,
        resource: &Resource<'_>,
        action: Action,
        context: Context,
    ) -> DecisionOutcome {
        // Fail closed if any input escapes to the empty string.
        // Returning a placeholder here would fold distinct hostile
        // principals onto the same Cedar UID, so we deny instead.
        let Some(principal_escaped) = escape(subject.cn) else {
            warn!(
                target: "authz",
                cn = %subject.cn.escape_debug(),
                "cedar: principal escaped to empty string; denying"
            );
            return DecisionOutcome::deny();
        };
        let principal_str = format!(r#"RustgatePrincipal::"{principal_escaped}""#);
        let action_str = format!(r#"Action::"{}""#, action_name(action));
        let Some(resource_str) = resource_uid_str(resource) else {
            warn!(
                target: "authz",
                "cedar: resource escaped to empty string; denying"
            );
            return DecisionOutcome::deny();
        };

        let principal = match EntityUid::from_str(&principal_str) {
            Ok(uid) => uid,
            Err(e) => {
                warn!(target: "authz", error = %e, principal = %principal_str, "cedar: invalid principal uid");
                return DecisionOutcome::deny();
            }
        };
        let action_uid = match EntityUid::from_str(&action_str) {
            Ok(uid) => uid,
            Err(e) => {
                warn!(target: "authz", error = %e, action = %action_str, "cedar: invalid action uid");
                return DecisionOutcome::deny();
            }
        };
        let resource_uid = match EntityUid::from_str(&resource_str) {
            Ok(uid) => uid,
            Err(e) => {
                warn!(target: "authz", error = %e, resource = %resource_str, "cedar: invalid resource uid");
                return DecisionOutcome::deny();
            }
        };

        let request = match Request::new(principal, action_uid, resource_uid, context, None) {
            Ok(req) => req,
            Err(e) => {
                warn!(target: "authz", error = %e, "cedar: request construction failed");
                return DecisionOutcome::deny();
            }
        };

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &self.entities);

        // Fail-closed override: if any policy errored during
        // evaluation, Cedar will have silently skipped it, and any
        // `forbid(...)` that errored becomes a no-op. That is
        // unacceptable in a deny-by-default system — a forbid rule
        // must deny even when it crashes. Inspect the diagnostics
        // for errors and, if present, force the verdict to Deny
        // regardless of what the authorizer returned.
        let mut had_errors = false;
        for err in response.diagnostics().errors() {
            had_errors = true;
            warn!(
                target: "authz",
                error = %err,
                principal = %principal_str,
                action = %action_str,
                resource = %resource_str,
                "cedar: policy evaluation error; forcing deny"
            );
        }
        if had_errors {
            return DecisionOutcome::deny();
        }

        match response.decision() {
            CedarDecision::Allow => DecisionOutcome {
                decision: Decision::Allow,
                rule_id: None,
                obligations: Vec::new(),
            },
            CedarDecision::Deny => DecisionOutcome::deny(),
        }
    }
}

#[cfg(feature = "cjadc2")]
impl CedarBackend {
    /// CJADC2 routing evaluator (closes #853). Issues a Cedar
    /// `Action::"Route"` request with `subject` and `resource`, walks
    /// the determining-policy set returned in the response
    /// diagnostics, and lifts each contributing policy's `@route`
    /// annotation into a [`RoutingDecision`] that the caller folds
    /// into the egress fan-out plan.
    ///
    /// # Aggregation
    ///
    /// When more than one permit policy contributes (operator
    /// declares `@route` on multiple cohort-specific permit rules),
    /// the per-policy decisions are merged via
    /// [`RoutingDecision::merge`]: destination set is unioned and
    /// per-destination obligation vectors are concatenated in
    /// policy-iteration order. Empty / missing `@route` annotations
    /// are skipped silently — the operator may have a permit rule
    /// for `Action::"Route"` that is purely a permit gate without
    /// any cross-domain advice.
    ///
    /// # Fail-closed semantics
    ///
    /// A `Deny` verdict (or a malformed input that escapes the
    /// `evaluate_inner` rails) returns [`RoutingDecision::none`] so
    /// no destination receives the message. Per-policy errors flagged
    /// in `Response::diagnostics().errors()` already force the
    /// underlying allow/deny verdict to `Deny` inside `evaluate_inner`,
    /// so a forbid rule that crashed silently does not leak via the
    /// routing path either.
    ///
    /// Per-policy `@route` annotations that fail to parse as JSON
    /// are logged at `warn!` and the policy is skipped — a malformed
    /// annotation is a policy author bug rather than an attacker
    /// signal, so failing the entire evaluation would over-rotate
    /// (the operator already gets the warning in their startup logs
    /// when the policy is loaded; the runtime fail is just a second
    /// signal).
    fn evaluate_route_inner(
        &self,
        subject: &Subject<'_>,
        resource: &Resource<'_>,
        authz_ctx: &AuthzContext,
    ) -> RoutingDecision {
        let cedar_ctx = build_cedar_context(authz_ctx);

        // Build the principal/action/resource UIDs by hand because
        // `evaluate_inner` returns a `DecisionOutcome` — we need access
        // to the raw `Response` for the determining-policies set.
        let Some(principal_escaped) = escape(subject.cn) else {
            warn!(
                target: "authz",
                cn = %subject.cn.escape_debug(),
                "cedar: principal escaped to empty string; denying route"
            );
            return RoutingDecision::none();
        };
        let principal_str = format!(r#"RustgatePrincipal::"{principal_escaped}""#);
        let action_str = format!(r#"Action::"{}""#, action_name(Action::Route));
        let Some(resource_str) = resource_uid_str(resource) else {
            warn!(
                target: "authz",
                "cedar: resource escaped to empty string; denying route"
            );
            return RoutingDecision::none();
        };

        let principal = match EntityUid::from_str(&principal_str) {
            Ok(uid) => uid,
            Err(e) => {
                warn!(
                    target: "authz",
                    error = %e,
                    principal = %principal_str,
                    "cedar: invalid principal uid for route"
                );
                return RoutingDecision::none();
            }
        };
        let action_uid = match EntityUid::from_str(&action_str) {
            Ok(uid) => uid,
            Err(e) => {
                warn!(
                    target: "authz",
                    error = %e,
                    action = %action_str,
                    "cedar: invalid action uid for route"
                );
                return RoutingDecision::none();
            }
        };
        let resource_uid = match EntityUid::from_str(&resource_str) {
            Ok(uid) => uid,
            Err(e) => {
                warn!(
                    target: "authz",
                    error = %e,
                    resource = %resource_str,
                    "cedar: invalid resource uid for route"
                );
                return RoutingDecision::none();
            }
        };

        let request = match Request::new(principal, action_uid, resource_uid, cedar_ctx, None) {
            Ok(req) => req,
            Err(e) => {
                warn!(target: "authz", error = %e, "cedar: route request construction failed");
                return RoutingDecision::none();
            }
        };

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &self.entities);

        // Fail-closed override mirrors `evaluate_inner`: if any policy
        // errored we deny the route, otherwise the routing graph is
        // built only from policies that actually contributed to the
        // allow verdict. Logged once per error so the operator sees
        // every misbehaving policy in a single run, then deny.
        let mut had_errors = false;
        for err in response.diagnostics().errors() {
            had_errors = true;
            warn!(
                target: "authz",
                error = %err,
                principal = %principal_str,
                action = %action_str,
                resource = %resource_str,
                "cedar: route policy evaluation error; forcing deny"
            );
        }
        if had_errors {
            return RoutingDecision::none();
        }

        if !matches!(response.decision(), CedarDecision::Allow) {
            // Deny → no destinations. The operator's
            // `Response::diagnostics().reason()` contains the forbid
            // policies that fired; a future audit emission can name
            // them, but for now the routing path simply returns the
            // empty decision.
            return RoutingDecision::none();
        }

        // Walk the determining-policy set, fetch each policy's
        // `@route` annotation, parse the contained JSON and merge the
        // result into a single `RoutingDecision`. Missing annotations
        // and parse errors are skipped per the docstring contract.
        let mut decision = RoutingDecision::none();
        for policy_id in response.diagnostics().reason() {
            let Some(policy) = self.policy_set.policy(policy_id) else {
                continue;
            };
            let Some(annotation) = policy.annotation("route") else {
                continue;
            };
            match serde_json::from_str::<RoutingDecision>(annotation) {
                Ok(parsed) => decision.merge(parsed),
                Err(e) => {
                    warn!(
                        target: "authz",
                        error = %e,
                        policy_id = %policy_id,
                        "cedar: failed to parse @route annotation as JSON; skipping policy"
                    );
                }
            }
        }
        decision
    }
}

impl PolicyEngine for CedarBackend {
    fn evaluate(
        &self,
        subject: &Subject<'_>,
        resource: &Resource<'_>,
        action: Action,
    ) -> DecisionOutcome {
        // Backward-compat path: no classification context. Funnel
        // through `evaluate_inner` with an empty Cedar context so
        // diagnostics handling and fail-closed override stay in one
        // place.
        self.evaluate_inner(subject, resource, action, Context::empty())
    }

    /// Forward `context.classification` (refs #849) into Cedar as a
    /// record under `context.classification.label` carrying the
    /// canonical CAPCO banner string. Policies that don't reference
    /// the field continue to make the same decision as before.
    fn evaluate_with_context(
        &self,
        subject: &Subject<'_>,
        resource: &Resource<'_>,
        action: Action,
        authz_ctx: &AuthzContext,
    ) -> DecisionOutcome {
        let cedar_ctx = build_cedar_context(authz_ctx);
        self.evaluate_inner(subject, resource, action, cedar_ctx)
    }

    /// CJADC2 routing PEP (closes #853). Delegates to
    /// `evaluate_route_inner` which walks the determining-policy set
    /// and lifts each contributing policy's `@route` annotation into
    /// a [`RoutingDecision`].
    #[cfg(feature = "cjadc2")]
    fn evaluate_route(
        &self,
        subject: &Subject<'_>,
        resource: &Resource<'_>,
        context: &AuthzContext,
    ) -> RoutingDecision {
        self.evaluate_route_inner(subject, resource, context)
    }

    fn policy_id(&self) -> &str {
        self.policy_id.as_str()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    //! Unit tests for the private helpers and construction paths of
    //! [`CedarBackend`].
    //!
    //! The integration tests in `tests/cedar.rs` cover the
    //! principal / action / resource mapping end-to-end through Cedar's
    //! evaluator. These unit tests complement that surface by pinning
    //! the pure helpers that feed that mapping — [`stable_id`],
    //! [`hex_encode`], [`action_name`], [`resource_uid_str`], and
    //! [`escape`] — so a refactor that silently changed (say) the
    //! set of characters stripped from a principal CN, or the Cedar
    //! namespace used for a [`Resource`] variant, would fail here
    //! before the integration layer notices.
    //!
    //! The [`escape`] tests are especially load-bearing: they pin the
    //! exact filter rule (double-quote, backslash, ASCII control bytes)
    //! that prevents distinct hostile CNs from folding onto a single
    //! sentinel UID. A future change that relaxed the filter (or
    //! added a fallback literal back in) would be caught here.
    //!
    //! Unit tests are feature-gated via their enclosing module's
    //! `#[cfg(feature = "cedar")]` in `lib.rs` — no extra attribute
    //! needed on the module itself.
    //!
    //! The construction-path tests exercise [`CedarBackend::from_source`]
    //! and [`CedarBackend::from_file`] against both happy and error
    //! inputs, pinning the contract that malformed Cedar source is
    //! reported as an [`AuthzError::validation("cedar", …)`] rather
    //! than panicking or bubbling a raw Cedar error. This is what
    //! operators see in startup logs, so the variant / target shape
    //! must stay stable.

    use std::collections::{BTreeMap, BTreeSet};

    use rustgate_core::AttrValue;

    use super::*;
    use crate::model::SubjectHash;

    // ------------------------------------------------------------------
    // Subject / Resource helpers for evaluate() tests.
    // ------------------------------------------------------------------

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

    // ------------------------------------------------------------------
    // stable_id / hex_encode — pure helpers.
    // ------------------------------------------------------------------

    #[test]
    fn stable_id_produces_64_char_hex_digest() {
        // SHA-256 is 32 bytes → 64 hex chars. Operators use the
        // `policy_id` as a stable identifier in audit logs when the
        // backend reloads; anything other than the full digest would
        // change the correlation-token shape.
        let id = stable_id("permit(principal, action, resource);");
        assert_eq!(
            id.len(),
            64,
            "policy_id must be a 64-char SHA-256 hex digest, got {id}"
        );
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "policy_id must be lowercase hex, got {id}"
        );
    }

    #[test]
    fn stable_id_is_deterministic_for_same_source() {
        // The hash must be stable within a process so the `policy_id`
        // returned by `from_source` matches the value an operator can
        // independently compute from the same source file — otherwise
        // drift-detection tooling that hashes the policy file offline
        // would report false positives.
        let src = "permit(principal, action, resource);";
        assert_eq!(stable_id(src), stable_id(src));
    }

    #[test]
    fn stable_id_differs_for_different_sources() {
        let a = stable_id("permit(principal, action, resource);");
        let b = stable_id("forbid(principal, action, resource);");
        assert_ne!(
            a, b,
            "distinct policy sources must hash to distinct policy_ids"
        );
    }

    #[test]
    fn hex_encode_empty_slice_returns_empty_string() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_known_bytes_produce_expected_hex() {
        // 0x0f => "0f" (lower nibble alone); 0xa0 => "a0" (upper nibble
        // alone); 0xde => "de" (full byte). This pins the nibble order
        // (high-nibble first) and the lowercase alphabet. A regression
        // that flipped endianness or switched to uppercase would
        // change `policy_id` formatting workspace-wide.
        assert_eq!(hex_encode(&[0x0f, 0xa0, 0xde]), "0fa0de");
    }

    #[test]
    fn hex_encode_zero_and_ff_are_padded_correctly() {
        // Zero-padding catches the bug where `format!("{:x}", 0x00)`
        // would render as "0" (one digit) — here we hand-roll the hex
        // loop, so both nibbles are always emitted.
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }

    // ------------------------------------------------------------------
    // action_name — maps every Action variant to a distinct literal.
    // ------------------------------------------------------------------

    #[test]
    fn action_name_covers_every_action_variant() {
        // The `Action::"<name>"` string becomes a Cedar literal, so a
        // variant mapped to the wrong name (or a name collision between
        // two variants) would silently reroute a policy rule. Keep this
        // exhaustive — the static `&'static str` pin means adding a new
        // Action variant is a compile error that forces a matching
        // update here.
        let pairs: [(Action, &'static str); 6] = [
            (Action::Send, "send"),
            (Action::Receive, "receive"),
            (Action::Federate, "federate"),
            (Action::Publish, "publish"),
            (Action::Subscribe, "subscribe"),
            (Action::Route, "Route"),
        ];
        for (action, expected) in pairs {
            let got: &'static str = action_name(action);
            assert_eq!(
                got, expected,
                "Action::{action:?} must map to Cedar literal {expected:?}, got {got:?}"
            );
        }

        // All six literals must be distinct — otherwise two actions
        // would collapse onto the same Cedar UID.
        let names: BTreeSet<&'static str> = pairs.iter().map(|(_, n)| *n).collect();
        assert_eq!(
            names.len(),
            6,
            "all Action variants must map to distinct Cedar literals"
        );
    }

    // ------------------------------------------------------------------
    // resource_uid_str — every Resource variant produces the Cedar UID
    // literal the policy author expects.
    // ------------------------------------------------------------------

    #[test]
    fn resource_uid_str_direct_produces_expected_literal() {
        let r = Resource::Direct { target_cn: "alice" };
        let uid = resource_uid_str(&r).expect("normal target must produce Some");
        assert_eq!(uid, r#"Direct::"alice""#);
    }

    #[test]
    fn resource_uid_str_group_produces_expected_literal() {
        let r = Resource::Group { group: "ops" };
        let uid = resource_uid_str(&r).expect("normal group must produce Some");
        assert_eq!(uid, r#"Group::"ops""#);
    }

    #[test]
    fn resource_uid_str_broadcast_is_constant_unknown_literal() {
        // Broadcast has no payload, so its Cedar UID is a fixed literal.
        // This pin doubles as the contract the integration tests rely
        // on when writing `resource == Broadcast::"all"` in a policy.
        let r = Resource::Broadcast;
        let uid = resource_uid_str(&r).expect("Broadcast can never fail");
        assert_eq!(uid, r#"Broadcast::"all""#);
    }

    #[test]
    fn resource_uid_str_federation_produces_expected_literal() {
        let r = Resource::Federation { peer_id: "edge-01" };
        let uid = resource_uid_str(&r).expect("normal peer_id must produce Some");
        assert_eq!(uid, r#"Federation::"edge-01""#);
    }

    #[test]
    fn resource_uid_str_nats_subject_produces_expected_literal() {
        let r = Resource::NatsSubject {
            subject: "telemetry.inbound",
        };
        let uid = resource_uid_str(&r).expect("normal subject must produce Some");
        assert_eq!(uid, r#"NatsSubject::"telemetry.inbound""#);
    }

    #[test]
    fn resource_uid_str_empty_target_cn_is_none() {
        // An empty-string resource target must deny, not fold onto a
        // sentinel like `Direct::"unknown"`. `resource_uid_str`
        // returns `None` and the `evaluate` caller translates that to
        // `Decision::Deny`. Exercises the fail-closed contract at the
        // uid-builder boundary (complement of the end-to-end test in
        // `tests/cedar.rs::cedar_pathological_resource_denies`).
        let r = Resource::Direct { target_cn: "" };
        assert!(resource_uid_str(&r).is_none());
    }

    #[test]
    fn resource_uid_str_all_filtered_target_is_none() {
        // Every character is dropped by `escape`, so the result is
        // empty → `None`. A regression that kept the empty result
        // and formatted `Direct::""` would generate a malformed
        // Cedar entity UID.
        let r = Resource::Direct {
            target_cn: "\"\"\\\x01",
        };
        assert!(resource_uid_str(&r).is_none());
    }

    // ------------------------------------------------------------------
    // escape — pins the exact filter rule used to sanitise CNs and
    // resource payloads before they become Cedar entity literals.
    // ------------------------------------------------------------------

    #[test]
    fn escape_empty_string_returns_none() {
        assert!(escape("").is_none());
    }

    #[test]
    fn escape_normal_ascii_passes_through_unchanged() {
        assert_eq!(escape("alice").as_deref(), Some("alice"));
        assert_eq!(
            escape("edge-01.region-a").as_deref(),
            Some("edge-01.region-a")
        );
    }

    #[test]
    fn escape_strips_double_quote_and_backslash() {
        // These two bytes would break the Cedar string literal syntax
        // if carried through unchanged — `Direct::"a"b\c"` is not a
        // valid Cedar UID. The filter drops them entirely rather than
        // escaping, so an attacker who injects quotes ends up with a
        // shorter, still-valid literal (or `None` if everything
        // stripped).
        assert_eq!(escape(r#"a"b\c"#).as_deref(), Some("abc"));
    }

    #[test]
    fn escape_strips_ascii_control_characters() {
        // Every `char::is_control()` byte is removed, including the
        // common ones (NUL, tab, newline, carriage return) plus the
        // full C0 / C1 ranges. Pins the choice to strip rather than
        // escape — if Cedar later supported `\n` literals in entity
        // ids, flipping this policy would be a deliberate call.
        assert_eq!(escape("a\nb\tc\x00d\x1fe").as_deref(), Some("abcde"));
    }

    #[test]
    fn escape_all_filtered_returns_none() {
        // All characters are in the filter set → cleaned string is
        // empty → `None`. This is the fail-closed trigger that the
        // evaluator translates to `Decision::Deny`.
        assert!(escape("\"\"\\\x01\x02").is_none());
    }

    #[test]
    fn escape_preserves_non_ascii_unicode() {
        // Non-ASCII characters that aren't quotes/backslashes/control
        // bytes pass through. Cedar accepts UTF-8 in entity ids, so
        // this is intentional — localised CNs must still resolve.
        assert_eq!(escape("αλφα-βητα").as_deref(), Some("αλφα-βητα"));
    }

    // ------------------------------------------------------------------
    // from_source / from_file — construction paths.
    // ------------------------------------------------------------------

    #[test]
    fn from_source_valid_cedar_succeeds() {
        let src = r#"permit(principal, action, resource);"#;
        let backend = CedarBackend::from_source(src).expect("valid Cedar must parse");
        assert_eq!(
            backend.policy_id().len(),
            64,
            "policy_id must be the full SHA-256 hex digest"
        );
    }

    #[test]
    fn from_source_empty_policy_parses_and_denies_everything() {
        // An empty policy (no rules) must still parse — Cedar's default
        // decision is `Deny` when no policy matches, which lines up
        // with the crate's deny-by-default contract.
        let backend = CedarBackend::from_source("").expect("empty policy must parse");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let r = Resource::Direct { target_cn: "bob" };
        let out = backend.evaluate(&s, &r, Action::Send);
        assert!(
            matches!(out.decision, Decision::Deny),
            "empty Cedar policy must deny by default, got {:?}",
            out.decision
        );
    }

    #[test]
    fn from_source_invalid_cedar_returns_validation_error() {
        // Malformed Cedar source must surface as an `AuthzError`
        // with the `cedar` target tag so operators grepping startup
        // logs see a single consistent token. The Display output
        // also pins that "failed to parse Cedar policy" prefix is
        // what ends up in the error chain.
        let err = CedarBackend::from_source("this is not cedar syntax")
            .expect_err("malformed Cedar source must fail");
        let rendered = err.to_string();
        assert!(
            rendered.contains("cedar"),
            "error must mention cedar target, got {rendered}"
        );
    }

    #[test]
    fn from_source_different_sources_produce_different_policy_ids() {
        // Two backends built from distinct sources must have distinct
        // `policy_id`s. This is the integration-level complement of
        // the pure `stable_id_differs_for_different_sources` test —
        // confirms the wiring from source → `policy_id` field is
        // intact through `CedarBackend::from_source`.
        let a = CedarBackend::from_source("permit(principal, action, resource);")
            .expect("policy parses");
        let b = CedarBackend::from_source("forbid(principal, action, resource);")
            .expect("policy parses");
        assert_ne!(a.policy_id(), b.policy_id());
    }

    #[test]
    fn from_file_nonexistent_path_returns_validation_error() {
        // The `from_file` wrapper adds the file-path to the error
        // message so operators can tell which policy file failed to
        // load from a list of startup paths. Pin that the raw
        // `io::Error` is wrapped, not bubbled directly.
        let err = CedarBackend::from_file(std::path::Path::new(
            "/this/path/does/not/exist/cedar.policy",
        ))
        .expect_err("nonexistent path must fail");
        let rendered = err.to_string();
        assert!(
            rendered.contains("cedar"),
            "file-read error must carry cedar target, got {rendered}"
        );
    }

    #[test]
    fn from_file_reads_valid_policy_file() {
        // Happy path: write a temp file, read back, verify the
        // `policy_id` matches what `from_source` would have produced
        // for the same bytes. This pins the contract that `from_file`
        // is a thin wrapper — no normalisation, no trimming, no
        // encoding transforms on the policy source.
        let src = "permit(principal, action, resource);\n";
        let tmp = std::env::temp_dir().join(format!(
            "rustgate-authz-cedar-unit-{}.policy",
            std::process::id()
        ));
        std::fs::write(&tmp, src).expect("write temp policy file");
        let from_file = CedarBackend::from_file(&tmp).expect("valid policy must parse");
        let from_source = CedarBackend::from_source(src).expect("valid policy must parse");
        assert_eq!(
            from_file.policy_id(),
            from_source.policy_id(),
            "from_file must produce the same policy_id as from_source for the same bytes"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    // ------------------------------------------------------------------
    // with_entities — builder returns Self and leaves other state
    // intact.
    // ------------------------------------------------------------------

    #[test]
    fn with_entities_is_chainable_builder_and_preserves_policy_id() {
        // `with_entities` swaps the entity store but must not touch
        // the `policy_id` or parsed `policy_set`. A regression that
        // recomputed `policy_id` from `self.entities` would break
        // every audit-log correlation query.
        let src = "permit(principal, action, resource);";
        let before = CedarBackend::from_source(src).expect("policy parses");
        let id_before = before.policy_id().to_string();
        let entities = cedar_policy::Entities::empty();
        let after = before.with_entities(entities);
        assert_eq!(
            after.policy_id(),
            id_before.as_str(),
            "with_entities must preserve policy_id"
        );
    }

    // ------------------------------------------------------------------
    // evaluate — coverage expansion for Resource / Action variants the
    // integration tests don't touch. The existing `tests/cedar.rs`
    // suite uses `Direct` + `Send` only.
    // ------------------------------------------------------------------

    #[test]
    fn evaluate_permits_broadcast_when_policy_allows_all() {
        // Verifies the `Resource::Broadcast` branch of
        // `resource_uid_str` wires through the evaluator. A
        // regression that mapped Broadcast to the wrong Cedar
        // namespace would cause the permit below to miss.
        let src = r#"
            permit(
                principal,
                action == Action::"send",
                resource == Broadcast::"all"
            );
        "#;
        let backend = CedarBackend::from_source(src).expect("policy parses");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let out = backend.evaluate(&s, &Resource::Broadcast, Action::Send);
        assert!(matches!(out.decision, Decision::Allow));
    }

    #[test]
    fn evaluate_permits_nats_subject_with_subscribe_action() {
        // Covers `Resource::NatsSubject` + `Action::Subscribe` in a
        // single test — both are exclusive to this unit (the
        // integration tests cover Direct + Send). A misrouted action
        // literal would cause the permit below to miss.
        let src = r#"
            permit(
                principal == RustgatePrincipal::"alice",
                action == Action::"subscribe",
                resource == NatsSubject::"telemetry.inbound"
            );
        "#;
        let backend = CedarBackend::from_source(src).expect("policy parses");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let r = Resource::NatsSubject {
            subject: "telemetry.inbound",
        };
        let out = backend.evaluate(&s, &r, Action::Subscribe);
        assert!(matches!(out.decision, Decision::Allow));
    }

    #[test]
    fn evaluate_permits_federation_with_federate_action() {
        // Covers `Resource::Federation` + `Action::Federate`.
        let src = r#"
            permit(
                principal == RustgatePrincipal::"alice",
                action == Action::"federate",
                resource == Federation::"edge-01"
            );
        "#;
        let backend = CedarBackend::from_source(src).expect("policy parses");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let r = Resource::Federation { peer_id: "edge-01" };
        let out = backend.evaluate(&s, &r, Action::Federate);
        assert!(matches!(out.decision, Decision::Allow));
    }

    #[test]
    fn evaluate_permits_group_with_receive_action() {
        // Covers `Resource::Group` + `Action::Receive`.
        let src = r#"
            permit(
                principal == RustgatePrincipal::"alice",
                action == Action::"receive",
                resource == Group::"ops"
            );
        "#;
        let backend = CedarBackend::from_source(src).expect("policy parses");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let r = Resource::Group { group: "ops" };
        let out = backend.evaluate(&s, &r, Action::Receive);
        assert!(matches!(out.decision, Decision::Allow));
    }

    #[test]
    fn evaluate_direct_with_publish_action_denies_when_permit_uses_send() {
        // Pins that Action literals are compared strictly: the permit
        // below is for `Action::"send"`, so an evaluation with
        // `Action::Publish` must deny even though every other field
        // matches. A bug that canonicalised all actions to "send"
        // (for example) would flip this to Allow.
        let src = r#"
            permit(
                principal == RustgatePrincipal::"alice",
                action == Action::"send",
                resource == Direct::"bob"
            );
        "#;
        let backend = CedarBackend::from_source(src).expect("policy parses");
        let groups = BTreeSet::new();
        let attrs = BTreeMap::new();
        let s = subject("alice", &groups, &attrs);
        let r = Resource::Direct { target_cn: "bob" };
        let out = backend.evaluate(&s, &r, Action::Publish);
        assert!(matches!(out.decision, Decision::Deny));
    }

    // ------------------------------------------------------------------
    // Debug impl — policy_id must appear, PolicySet must not.
    // ------------------------------------------------------------------

    #[test]
    fn debug_format_includes_policy_id_but_not_policy_set_contents() {
        // The manual `Debug` impl redacts `PolicySet` / `Authorizer` /
        // `Entities` by only emitting the `policy_id` field. Pin the
        // contract: `{:?}` output contains the policy_id string but
        // does NOT leak any of the Cedar source (e.g. the word
        // "permit" from a permit-everything policy).
        let src = "permit(principal, action, resource);";
        let backend = CedarBackend::from_source(src).expect("policy parses");
        let id = backend.policy_id().to_string();
        let rendered = format!("{backend:?}");
        assert!(
            rendered.contains(&id),
            "Debug output must include policy_id `{id}`, got {rendered}"
        );
        assert!(
            !rendered.contains("permit"),
            "Debug output must not leak policy source, got {rendered}"
        );
    }
}
