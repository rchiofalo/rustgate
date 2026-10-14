// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! CJADC2 multi-domain routing decisions (closes #853).
//!
//! The `route` module models a *routing* policy decision: given an
//! authenticated subject and a routable entity, the policy engine
//! returns a [`RoutingDecision`] that names one or more **destination
//! adapters** (e.g. `lattice`, `link16`, `foundry`, `dis`) and attaches
//! per-destination [`RouteObligation`]s describing transformations the
//! egress path must apply before each adapter sees the message.
//!
//! # Why a dedicated decision shape
//!
//! The pre-CJADC2 [`crate::DecisionOutcome`] surface was the right
//! shape for **per-recipient** allow/deny verdicts: one subject, one
//! resource, one action, and (optionally) a flat list of obligations
//! that all apply to the single rendered copy. CJADC2 fan-out is
//! categorically different — a single inbound entity is duplicated
//! across N **disjoint** adapters with **different** obligations on
//! each copy. Folding that into the single-`Vec<Obligation>` shape
//! would either:
//!
//! 1. require the router to disambiguate which obligation belongs to
//!    which adapter at the call site (regressing the policy author's
//!    intent into a transport-side guess), or
//! 2. force the policy author to write N separate policies (one per
//!    `(subject, resource, adapter)`) and rely on transport-side
//!    fan-out to re-aggregate, which destroys the single-source
//!    declaration the cross-domain operator needs to audit.
//!
//! The dedicated [`RoutingDecision`] shape sidesteps both: each
//! destination name carries its own obligation vector, and the engine
//! emits the **complete** routing graph for one inbound entity in a
//! single evaluation.
//!
//! # Wire format (Cedar advice annotation)
//!
//! Cedar 4 does not natively support an `advice { … }` block, so the
//! cross-domain routing graph rides on a `@route("…")` **policy
//! annotation** containing JSON. A policy author writes:
//!
//! ```cedar
//! @route("{
//!   \"destinations\": [\"lattice\", \"link16\", \"foundry\"],
//!   \"obligations\": {
//!     \"lattice\": [],
//!     \"link16\": [{\"type\": \"set-classification\", \"value\": \"S\"}],
//!     \"foundry\": [{\"type\": \"drop-fields\", \"value\": [\"sensor_uid\"]}]
//!   }
//! }")
//! permit (
//!   principal in Group::"sensors",
//!   action == Action::"Route",
//!   resource is Entity
//! );
//! ```
//!
//! At evaluation time the Cedar backend iterates the
//! `Response::diagnostics().reason()` set (the policies that
//! contributed to the `Allow` verdict), reads each policy's `@route`
//! annotation, and merges the named destinations + per-destination
//! obligations into a single [`RoutingDecision`]. The aggregation is
//! **set-union** on destinations and **append** on per-destination
//! obligation vectors so multiple matching policies compose
//! additively.
//!
//! # Compatibility
//!
//! [`RoutingDecision::none()`] is the zero value: no destinations, no
//! obligations. Backends that do not implement
//! [`crate::PolicyEngine::evaluate_route`] inherit a default impl that
//! returns this value, so non-CJADC2 deployments pay nothing and the
//! trait extension is fully backward-compatible.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// One per-destination transformation a routing policy attaches to a
/// named adapter.
///
/// Each variant is a verb-shaped action the router applies to the
/// outbound copy *before* the destination adapter sees it. The variants
/// are deliberately small and string-typed: they ride out of the policy
/// engine through Cedar's annotation surface and the router's egress
/// fan-out, where the actual transformation is dispatched against the
/// payload by the destination-adapter glue.
///
/// `#[non_exhaustive]` — new transformations land additively. Match
/// statements that consume this enum from outside the defining crate
/// must include a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum RouteObligation {
    /// Override the classification level on the outbound copy. The
    /// string is opaque to the engine (e.g. `"S"`, `"TS"`, `"U"`,
    /// `"//SECRET//NOFORN"`); the destination adapter parses it under
    /// the marking dialect of its receiving network.
    SetClassification(String),
    /// Drop the named fields from the entity payload before delivery.
    /// Used to strip operator-identity PII (e.g. `sensor_uid`,
    /// `operator_callsign`) when crossing into a coalition feed.
    DropFields(Vec<String>),
    /// Coarsen position fields to a grid sized in metres. The router
    /// looks up the destination's geometry encoder and applies the
    /// rounding before serialising the entity.
    DegradePosition(u32),
    /// Tag the outbound copy with a free-form release marking the
    /// destination adapter inserts into its native envelope (e.g. a
    /// CAPCO banner for IC feeds, a STANAG dissemination tag for NATO
    /// links). The string is opaque to the engine.
    Tag(String),
}

/// CJADC2 multi-domain routing decision (closes #853).
///
/// Returned by [`crate::PolicyEngine::evaluate_route`]. Names the
/// destination adapters the inbound entity is fanned out to and
/// carries the per-destination obligation envelopes the router must
/// apply on the way out.
///
/// # Aggregation contract
///
/// When multiple permit policies match a single `(subject, entity)`
/// evaluation, the backend MUST set-union their `destinations` and
/// concatenate their per-destination obligation vectors (in
/// policy-iteration order). Two policies naming the same destination
/// produce a single entry whose obligation vector is the concatenation
/// of both policies' obligations. Duplicate obligations within a
/// single destination are NOT deduped — a policy author who attaches
/// the same `Tag("FOR-OFFICIAL-USE")` from two policies probably means
/// it.
///
/// # Empty / "none" representation
///
/// [`RoutingDecision::none()`] is the zero value (no destinations, no
/// obligations). The default implementation of
/// [`crate::PolicyEngine::evaluate_route`] returns this so any backend
/// that does not implement CJADC2 routing is forward-compatible.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingDecision {
    /// Named destination adapters the entity is fanned out to. The
    /// router looks each name up in its sink registry; an unknown
    /// destination name is logged at `warn!` and skipped (fail-open
    /// for unknowns is intentional — a destination the build does not
    /// support is most likely a future adapter the policy author
    /// added; the live destinations still receive their copies).
    pub destinations: Vec<String>,
    /// Per-destination obligation envelopes. Keyed on destination
    /// name; entries whose key is not in [`Self::destinations`] are
    /// silently ignored (the destination is not in the fan-out set).
    pub obligations: HashMap<String, Vec<RouteObligation>>,
}

impl RoutingDecision {
    /// The zero-routing decision: no destinations, no obligations.
    /// Used as the default return value of
    /// [`crate::PolicyEngine::evaluate_route`] so backends that do not
    /// implement CJADC2 routing are forward-compatible without breaking
    /// the trait surface.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Return `true` when this decision names no destinations. The
    /// router uses this to short-circuit the CJADC2 fan-out path: an
    /// empty decision means "no CJADC2 routing applies", and the
    /// pre-existing per-recipient PEP path handles the message.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }

    /// Borrow the per-destination obligation vector for `destination`,
    /// or return an empty slice if the destination has no obligations
    /// attached. Useful for the egress fan-out loop that walks
    /// [`Self::destinations`] and looks each one up in turn.
    #[must_use]
    pub fn obligations_for(&self, destination: &str) -> &[RouteObligation] {
        match self.obligations.get(destination) {
            Some(obligations) => obligations.as_slice(),
            None => &[],
        }
    }

    /// Merge `other` into `self` using the aggregation contract: the
    /// destination set is unioned (preserving first-seen order) and
    /// per-destination obligation vectors are concatenated.
    ///
    /// This is the workhorse of multi-policy aggregation — the Cedar
    /// backend iterates the determining-policies set and folds each
    /// policy's parsed `@route` annotation into a single decision via
    /// repeated calls to this method.
    pub fn merge(&mut self, other: RoutingDecision) {
        for dest in other.destinations {
            if !self.destinations.contains(&dest) {
                self.destinations.push(dest);
            }
        }
        for (dest, mut obligations) in other.obligations {
            self.obligations
                .entry(dest)
                .or_default()
                .append(&mut obligations);
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    #[test]
    fn none_is_empty() {
        let d = RoutingDecision::none();
        assert!(d.is_empty());
        assert!(d.destinations.is_empty());
        assert!(d.obligations.is_empty());
    }

    #[test]
    fn is_empty_true_when_no_destinations() {
        let d = RoutingDecision::default();
        assert!(d.is_empty());
    }

    #[test]
    fn is_empty_false_when_destination_present() {
        let d = RoutingDecision {
            destinations: vec!["lattice".to_string()],
            obligations: HashMap::new(),
        };
        assert!(!d.is_empty());
    }

    #[test]
    fn obligations_for_returns_empty_slice_for_unknown_destination() {
        let d = RoutingDecision::default();
        assert!(d.obligations_for("lattice").is_empty());
    }

    #[test]
    fn obligations_for_returns_attached_obligations() {
        let mut obligations = HashMap::new();
        obligations.insert(
            "link16".to_string(),
            vec![RouteObligation::SetClassification("S".to_string())],
        );
        let d = RoutingDecision {
            destinations: vec!["link16".to_string()],
            obligations,
        };
        let oblig = d.obligations_for("link16");
        assert_eq!(oblig.len(), 1);
        assert!(matches!(
            &oblig[0],
            RouteObligation::SetClassification(s) if s == "S"
        ));
    }

    #[test]
    fn merge_unions_destinations_preserving_first_seen_order() {
        let mut a = RoutingDecision {
            destinations: vec!["lattice".to_string(), "link16".to_string()],
            obligations: HashMap::new(),
        };
        let b = RoutingDecision {
            destinations: vec!["link16".to_string(), "foundry".to_string()],
            obligations: HashMap::new(),
        };
        a.merge(b);
        assert_eq!(
            a.destinations,
            vec![
                "lattice".to_string(),
                "link16".to_string(),
                "foundry".to_string()
            ]
        );
    }

    #[test]
    fn merge_concatenates_per_destination_obligations() {
        let mut a_obl = HashMap::new();
        a_obl.insert(
            "link16".to_string(),
            vec![RouteObligation::SetClassification("S".to_string())],
        );
        let mut a = RoutingDecision {
            destinations: vec!["link16".to_string()],
            obligations: a_obl,
        };

        let mut b_obl = HashMap::new();
        b_obl.insert(
            "link16".to_string(),
            vec![RouteObligation::Tag("NOFORN".to_string())],
        );
        let b = RoutingDecision {
            destinations: vec!["link16".to_string()],
            obligations: b_obl,
        };

        a.merge(b);
        let oblig = a.obligations_for("link16");
        assert_eq!(oblig.len(), 2);
    }

    #[test]
    fn obligation_serializes_kebab_case_tag() {
        let o = RouteObligation::SetClassification("TS".to_string());
        let json = serde_json::to_string(&o).expect("serialize");
        // The wire form is `{"type": "set-classification", "value": "TS"}`.
        assert!(json.contains(r#""type":"set-classification""#));
        assert!(json.contains(r#""value":"TS""#));
    }

    #[test]
    fn obligation_drop_fields_round_trips() {
        let original = RouteObligation::DropFields(vec!["sensor_uid".to_string()]);
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: RouteObligation = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn obligation_degrade_position_round_trips() {
        let original = RouteObligation::DegradePosition(1000);
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: RouteObligation = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, original);
    }
}
