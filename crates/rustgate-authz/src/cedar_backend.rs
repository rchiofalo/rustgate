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
};
use smol_str::SmolStr;
use tracing::warn;

use crate::engine::PolicyEngine;
use crate::error::AuthzError;
use crate::model::{Action, Decision, DecisionOutcome, Resource, Subject};

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

impl PolicyEngine for CedarBackend {
    fn evaluate(
        &self,
        subject: &Subject<'_>,
        resource: &Resource<'_>,
        action: Action,
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

        let request =
            match Request::new(principal, action_uid, resource_uid, Context::empty(), None) {
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

    fn policy_id(&self) -> &str {
        self.policy_id.as_str()
    }
}
