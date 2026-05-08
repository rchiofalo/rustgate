// Copyright © 2026 Roberto Chiofalo.

//! CJADC2 multi-domain routing fan-out (closes #853).
//!
//! Given a [`rustgate_authz::RoutingDecision`] produced by a CJADC2
//! policy and an inbound message, this module produces one
//! [`crate::egress::EgressEnvelope`] per named destination adapter so
//! the router can dispatch a single inbound entity to N disjoint sinks
//! with per-destination obligations applied to each copy.
//!
//! # Why a thin layer over `prepare_egress_envelope`
//!
//! The pre-#746 egress fan-out (`Router::route_for_egress`) returns a
//! single `Arc<RoutableMessage>` shared by every external sink. That
//! contract is the right shape when **the same message** flows out to
//! every sink — for example, broadcasting a position report to every
//! attached federation peer with identical Send-PEP obligations
//! applied. CJADC2 is categorically different: a single inbound
//! `Entity` fans out to **disjoint** destinations (`lattice`,
//! `link16`, `foundry`, `dis`) where each destination receives its
//! own modified copy. The per-destination obligations
//! (`SetClassification("S")` for Link 16, `DropFields(["sensor_uid"])`
//! for Foundry) apply to a single recipient class, not the union.
//!
//! `prepare_destination_envelope` keeps the obligation-rendering
//! contract: each call produces one envelope whose
//! `applied_obligations` describes the transformations the egress
//! adapter must apply before serialising. The router's existing
//! [`crate::obligations`] machinery handles the actuation; this
//! module is purely the fan-out planner.
//!
//! # Feature gating
//!
//! The module is compiled only when the `cjadc2` feature is enabled
//! on `rustgate-router`, which in turn enables `rustgate-authz`'s
//! `cjadc2` feature so the [`rustgate_authz::RoutingDecision`] and
//! [`rustgate_authz::RouteObligation`] symbols are available. Non-CJADC2
//! deployments do not pay any per-message cost — neither the fan-out
//! plan nor the obligation-rendering loop runs.

use std::sync::Arc;

use rustgate_authz::{RouteObligation, RoutingDecision};
use rustgate_core::message::RoutableMessage;
use tracing::warn;

/// One per-destination egress envelope produced by
/// [`plan_routing_fanout`] for a single CJADC2 routing decision.
///
/// The struct is intentionally small: it carries the named
/// destination adapter, the (possibly mutated) outbound message
/// `Arc`, and the list of [`RouteObligation`]s that were applied to
/// produce the rendered copy. The adapter glue (e.g. the Lattice
/// gRPC publisher, the Link 16 J-series shaper) consumes the
/// envelope, serialises the message under its native dialect, and
/// dispatches to the destination network.
///
/// `applied_obligations` is the same vector the policy declared for
/// this destination — the planner does not reinterpret the
/// obligations, it only walks them in declaration order so the
/// adapter can apply them deterministically. A future revision may
/// move into a unified `Vec<rustgate_authz::Obligation>`-shaped
/// envelope alongside the existing [`crate::egress::EgressEnvelope`];
/// for the MVP the obligations stay typed as
/// [`RouteObligation`] so the adapter glue can match exhaustively
/// without paying for a non-CJADC2 [`rustgate_authz::Obligation`]
/// dispatch table.
#[derive(Debug, Clone)]
pub struct DestinationEnvelope {
    /// Destination adapter name as declared in the policy
    /// `destinations` list. The router looks this up against its
    /// sink registry to dispatch the envelope.
    pub destination: String,
    /// The outbound message. For the MVP the planner does NOT
    /// pre-mutate the payload; the destination adapter applies the
    /// obligations as part of its serialisation step. This keeps the
    /// planner cheap (no per-destination clone) and lets the adapter
    /// own the dialect-specific transformation (e.g. a Link 16
    /// classification override edits a J-series header field, not
    /// the source CoT XML).
    pub message: Arc<RoutableMessage>,
    /// Obligations the adapter must apply when serialising this
    /// envelope. Empty when the policy attached no obligations to
    /// the destination.
    pub applied_obligations: Vec<RouteObligation>,
}

/// Plan the CJADC2 fan-out for a single routing decision.
///
/// Produces one [`DestinationEnvelope`] per named destination in
/// `decision.destinations`, in declaration order. Destination names
/// not in `known_destinations` are logged at `warn!` and skipped
/// (fail-open for unknowns is intentional — a destination the build
/// does not support is most likely a future adapter the policy author
/// added; the live destinations still receive their copies).
///
/// The router's CJADC2 dispatch loop calls this once per inbound
/// message after `evaluate_route` produces an allow decision. Each
/// returned envelope is then handed to the matching adapter. The
/// per-destination obligations ride on the envelope so the adapter
/// can apply them inside its own egress path; the planner does NOT
/// pre-render the payload because the dialect-specific mutation
/// (Link 16 J-series header rewrite vs. CoT XML attribute injection)
/// belongs to the adapter, not the routing layer.
///
/// # Empty / "no routing" path
///
/// When `decision.is_empty()` (the default returned by backends that
/// do not implement CJADC2 routing) this returns an empty `Vec` so
/// the caller short-circuits the CJADC2 dispatch loop and falls back
/// to the pre-existing per-recipient PEP path. That is the
/// non-CJADC2 deployment baseline — no allocation, no warnings.
///
/// # Argument: `known_destinations`
///
/// The router supplies the list of destination names its sink
/// registry can dispatch to. The planner intersects the policy's
/// declared destinations with this set so a policy that names a
/// destination the build does not support (e.g. `lattice` in a
/// build without the Lattice adapter) silently skips that
/// destination instead of erroring the entire fan-out. Without this
/// filter a single mistyped destination name in a policy would
/// take down every CJADC2 message.
pub fn plan_routing_fanout(
    decision: &RoutingDecision,
    message: Arc<RoutableMessage>,
    known_destinations: &[&str],
) -> Vec<DestinationEnvelope> {
    if decision.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(decision.destinations.len());
    for dest in &decision.destinations {
        if !known_destinations.iter().any(|known| known == dest) {
            warn!(
                target: "router",
                destination = %dest,
                "cjadc2: destination named in routing decision is not registered; skipping"
            );
            continue;
        }
        let obligations = decision.obligations_for(dest).to_vec();
        out.push(DestinationEnvelope {
            destination: dest.clone(),
            message: Arc::clone(&message),
            applied_obligations: obligations,
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::Arc;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_authz::{RouteObligation, RoutingDecision};
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    use super::*;

    fn make_message() -> Arc<RoutableMessage> {
        let identity = Identity {
            cn: Arc::<str>::from("sensor-01"),
            fingerprint: "deadbeef".to_string(),
            groups: BTreeSet::new(),
            tenant: None,
            spiffe_id: None,
            attributes: Arc::new(BTreeMap::new()),
        };
        Arc::new(RoutableMessage {
            source: identity,
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event/>"),
            metadata: Metadata::new(
                SystemTime::UNIX_EPOCH,
                "test".to_string(),
                MessageType::Position,
            ),
        })
    }

    #[test]
    fn empty_decision_produces_empty_plan() {
        let decision = RoutingDecision::none();
        let plan = plan_routing_fanout(&decision, make_message(), &["lattice", "link16"]);
        assert!(plan.is_empty());
    }

    #[test]
    fn unknown_destinations_are_skipped() {
        let mut decision = RoutingDecision {
            destinations: vec!["lattice".to_string(), "made-up".to_string()],
            obligations: HashMap::new(),
        };
        // Sanity: decision is non-empty.
        assert!(!decision.is_empty());
        decision.obligations.insert(
            "lattice".to_string(),
            vec![RouteObligation::Tag("FOR-OFFICIAL-USE".to_string())],
        );

        let plan = plan_routing_fanout(&decision, make_message(), &["lattice", "link16"]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].destination, "lattice");
        assert_eq!(plan[0].applied_obligations.len(), 1);
    }

    #[test]
    fn known_destinations_preserve_declaration_order() {
        let decision = RoutingDecision {
            destinations: vec![
                "foundry".to_string(),
                "link16".to_string(),
                "lattice".to_string(),
            ],
            obligations: HashMap::new(),
        };
        let plan =
            plan_routing_fanout(&decision, make_message(), &["lattice", "link16", "foundry"]);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].destination, "foundry");
        assert_eq!(plan[1].destination, "link16");
        assert_eq!(plan[2].destination, "lattice");
    }

    #[test]
    fn per_destination_obligations_are_attached() {
        let mut obligations = HashMap::new();
        obligations.insert(
            "link16".to_string(),
            vec![RouteObligation::SetClassification("S".to_string())],
        );
        obligations.insert(
            "foundry".to_string(),
            vec![RouteObligation::DropFields(vec!["sensor_uid".to_string()])],
        );
        let decision = RoutingDecision {
            destinations: vec!["link16".to_string(), "foundry".to_string()],
            obligations,
        };

        let plan =
            plan_routing_fanout(&decision, make_message(), &["lattice", "link16", "foundry"]);

        assert_eq!(plan.len(), 2);
        let link16 = plan.iter().find(|p| p.destination == "link16").unwrap();
        let foundry = plan.iter().find(|p| p.destination == "foundry").unwrap();

        assert_eq!(link16.applied_obligations.len(), 1);
        assert!(matches!(
            &link16.applied_obligations[0],
            RouteObligation::SetClassification(s) if s == "S"
        ));
        assert_eq!(foundry.applied_obligations.len(), 1);
        assert!(matches!(
            &foundry.applied_obligations[0],
            RouteObligation::DropFields(fields) if fields == &["sensor_uid".to_string()]
        ));
    }

    #[test]
    fn plan_shares_arc_across_destinations() {
        let decision = RoutingDecision {
            destinations: vec![
                "lattice".to_string(),
                "link16".to_string(),
                "foundry".to_string(),
            ],
            obligations: HashMap::new(),
        };

        let msg = make_message();
        let strong_before = Arc::strong_count(&msg);
        let plan = plan_routing_fanout(
            &decision,
            Arc::clone(&msg),
            &["lattice", "link16", "foundry"],
        );

        // Each envelope shares the same `Arc<RoutableMessage>` — the
        // planner pays the cost of `Arc::clone` once per destination,
        // not a `RoutableMessage::clone`. Strong count grew by exactly
        // the number of destinations.
        assert_eq!(plan.len(), 3);
        assert_eq!(Arc::strong_count(&msg), strong_before + 3);
    }
}
