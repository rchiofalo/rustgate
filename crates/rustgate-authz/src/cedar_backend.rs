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

fn resource_uid_str(resource: &Resource<'_>) -> String {
    match resource {
        Resource::Direct { target_cn } => format!(r#"Direct::"{}""#, escape(target_cn)),
        Resource::Group { group } => format!(r#"Group::"{}""#, escape(group)),
        Resource::Broadcast => r#"Broadcast::"all""#.to_string(),
        Resource::Federation { peer_id } => format!(r#"Federation::"{}""#, escape(peer_id)),
        Resource::NatsSubject { subject } => format!(r#"NatsSubject::"{}""#, escape(subject)),
    }
}

/// Minimal escape: strip double-quotes and backslashes so the entity id
/// remains a valid Cedar literal. Cedar's lexer does not accept arbitrary
/// Unicode in quoted ids, so we defensively fall back to a placeholder
/// when the input is empty after escaping.
fn escape(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| *c != '"' && *c != '\\' && !c.is_control())
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

impl PolicyEngine for CedarBackend {
    fn evaluate(
        &self,
        subject: &Subject<'_>,
        resource: &Resource<'_>,
        action: Action,
    ) -> DecisionOutcome {
        let principal_str = format!(r#"RustgatePrincipal::"{}""#, escape(subject.cn));
        let action_str = format!(r#"Action::"{}""#, action_name(action));
        let resource_str = resource_uid_str(resource);

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
