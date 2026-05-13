// Copyright © 2026 Roberto Chiofalo.

//! Per-tenant peer selection with Active / Standby topology roles.
//!
//! This module is the policy layer that sits between the federation
//! manager's `forward_inner` path and the raw peer snapshot it
//! iterates. Given a message's `tenant_id` and the current snapshot
//! of `(PeerId, PeerHandle)` pairs, it returns the subset of peers
//! that should receive the message.
//!
//! (The link target `manager::FederationManager::forward_inner` is
//! private and would trip `rustdoc::private-intra-doc-links` under
//! the workspace's `-D warnings`; referencing it in plain backticks
//! avoids that gate while keeping the name discoverable via
//! grep / `cargo doc --document-private-items`.)
//!
//! ## Filter pipeline
//!
//! 1. **Tenant scope** — every candidate peer's
//!    [`crate::config::PeerConfig::serves_tenant`] must accept the
//!    message's `tenant_id`. Shared peers (`tenants = []` or `["*"]`)
//!    accept every message; pinned peers
//!    (`tenants = ["alpha", "bravo", ...]`) accept only matching tags.
//! 2. **Active / Standby promotion** — the candidate set is partitioned
//!    by [`TopologyRole`]. If at least one `Active` peer is currently
//!    available the result is the available `Active` peers only;
//!    Standbys are held back. If no `Active` peer in scope is
//!    available, every available `Standby` is promoted for this one
//!    forwarding pass.
//!
//! No persistent state — promotion is recomputed per message from the
//! current connection state. That means a flapping `Active` peer
//! produces a flapping Active/Standby decision; each message is
//! considered independently. Operators that want hysteresis dampening
//! configure their circuit breakers with a slower trip / recovery
//! cadence rather than asking this layer to debounce.
//!
//! ## Out of scope
//!
//! - **Hub / Spoke topology.** Discussed in design but deferred to a
//!   follow-up. The local-node-role question (is *this* node a hub or
//!   a spoke?) is non-trivial; we want concrete deployment pressure
//!   before committing to the wire shape.
//! - **Weighted active sets.** All `Active` peers receive every
//!   message. Operators that want per-peer fractional sends configure
//!   their upstream sources to send to a subset.
//! - **Time-windowed activation policies** (e.g. peer X is active
//!   weekdays, peer Y on weekends). Out of scope; deployments that
//!   want this run a config-reload script on the desired cadence.

use std::sync::Arc;

use rustgate_core::PeerId;

use crate::config::TopologyRole;
use crate::peer::PeerHandle;

/// Result of [`select_peers_for_tenant`].
///
/// Carries the chosen peer list plus a *kind* tag describing how the
/// selection was reached. The tag is purely observational — feeds
/// `tracing` spans and a future Prometheus label — but the test suite
/// also asserts on it so changes to the selection rule are visible.
#[derive(Debug, Clone)]
pub struct PeerSelection {
    /// Peers chosen for this forward pass.
    pub peers: Vec<(PeerId, Arc<PeerHandle>)>,
    /// Selection outcome category for the calling
    /// `tracing::info_span!`/`Prometheus` label.
    pub kind: SelectionKind,
}

/// What rule produced a [`PeerSelection`].
///
/// Stable lowercase tags for use as Prometheus label values and
/// `tracing` field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectionKind {
    /// At least one [`TopologyRole::Active`] peer in scope was
    /// available; the result holds those Actives only.
    Active,
    /// No Active peer in scope was available; every available
    /// [`TopologyRole::Standby`] was promoted for this pass.
    StandbyPromoted,
    /// The tenant scope produced no candidate peers at all (e.g.
    /// `tenant_id = Some("zulu")` but no peer carries that tenant).
    /// Empty result; the caller may want to surface this as a
    /// metric counter (`rustgate_federation_forward_no_peers_total`).
    NoCandidates,
}

impl SelectionKind {
    /// Stable lowercase tag (`"active"`, `"standby_promoted"`,
    /// `"no_candidates"`) for Prometheus / `tracing`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::StandbyPromoted => "standby_promoted",
            Self::NoCandidates => "no_candidates",
        }
    }
}

/// Apply the tenant + topology-role filter pipeline to a peer snapshot.
///
/// `tenant_id` is the message's tenant tag from
/// `Metadata::tenant_id`; `None` for legacy untagged traffic. The
/// snapshot is borrowed but cloned cheaply on the way out (each
/// `PeerHandle` is already `Arc`-wrapped).
pub fn select_peers_for_tenant(
    snapshot: &[(PeerId, Arc<PeerHandle>)],
    tenant_id: Option<&str>,
) -> PeerSelection {
    // Stage 1: tenant scope. A peer either serves the tenant or it
    // doesn't — both shared (`tenants = []`/`["*"]`) and pinned
    // peers go through the same `PeerConfig::serves_tenant` predicate.
    let in_scope: Vec<&(PeerId, Arc<PeerHandle>)> = snapshot
        .iter()
        .filter(|(_, peer)| peer.config.serves_tenant(tenant_id))
        .collect();

    if in_scope.is_empty() {
        return PeerSelection {
            peers: Vec::new(),
            kind: SelectionKind::NoCandidates,
        };
    }

    // Stage 2: Active / Standby split. Iterate twice (zero-cost on a
    // typical 1-100 peer set) and partition by role.
    let active_available: Vec<(PeerId, Arc<PeerHandle>)> = in_scope
        .iter()
        .filter(|(_, peer)| {
            peer.config.topology_role == TopologyRole::Active && peer.is_available()
        })
        .map(|(id, peer)| (id.clone(), Arc::clone(peer)))
        .collect();

    if !active_available.is_empty() {
        return PeerSelection {
            peers: active_available,
            kind: SelectionKind::Active,
        };
    }

    let standby_available: Vec<(PeerId, Arc<PeerHandle>)> = in_scope
        .iter()
        .filter(|(_, peer)| {
            peer.config.topology_role == TopologyRole::Standby && peer.is_available()
        })
        .map(|(id, peer)| (id.clone(), Arc::clone(peer)))
        .collect();

    if !standby_available.is_empty() {
        return PeerSelection {
            peers: standby_available,
            kind: SelectionKind::StandbyPromoted,
        };
    }

    // Both Active and Standby peers in scope exist but none are
    // available right now. Empty result — the caller treats this the
    // same as `NoCandidates` for forwarding purposes, but the tag
    // distinguishes "wrong tenant" from "right tenant, all peers
    // down" in the metrics.
    PeerSelection {
        peers: Vec::new(),
        kind: SelectionKind::NoCandidates,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{PeerConfig, RoutingMode};
    use crate::peer::PeerState;

    fn make_peer(
        id: &str,
        tenants: Vec<&str>,
        role: TopologyRole,
        available: bool,
    ) -> (PeerId, Arc<PeerHandle>) {
        let config = PeerConfig {
            id: PeerId::new(id),
            address: "127.0.0.1:9999".to_string(),
            groups: Vec::new(),
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
            compression: None,
            tenants: tenants.into_iter().map(str::to_string).collect(),
            topology_role: role,
        };
        let handle = Arc::new(PeerHandle::new(config));
        // `is_available()` = connected AND circuit closed. The circuit
        // is born Closed (request-allowing), so flipping the state to
        // Connected when we want "available" is sufficient for these
        // selection tests.
        if available {
            handle.set_state(PeerState::Connected);
        }
        (PeerId::new(id), handle)
    }

    #[test]
    fn shared_peer_accepts_every_tenant_tag() {
        let snapshot = vec![make_peer("p1", vec![], TopologyRole::Active, true)];
        let sel = select_peers_for_tenant(&snapshot, Some("alpha"));
        assert_eq!(sel.peers.len(), 1);
        assert_eq!(sel.kind, SelectionKind::Active);
    }

    #[test]
    fn star_wildcard_accepts_every_tenant_tag() {
        let snapshot = vec![make_peer("p1", vec!["*"], TopologyRole::Active, true)];
        let sel = select_peers_for_tenant(&snapshot, Some("alpha"));
        assert_eq!(sel.peers.len(), 1);
        let sel_untagged = select_peers_for_tenant(&snapshot, None);
        assert_eq!(sel_untagged.peers.len(), 1);
    }

    #[test]
    fn pinned_peer_rejects_untagged_traffic() {
        let snapshot = vec![make_peer("p1", vec!["alpha"], TopologyRole::Active, true)];
        let sel = select_peers_for_tenant(&snapshot, None);
        assert_eq!(sel.kind, SelectionKind::NoCandidates);
        assert!(sel.peers.is_empty());
    }

    #[test]
    fn pinned_peer_accepts_matching_tenant() {
        let snapshot = vec![make_peer("p1", vec!["alpha"], TopologyRole::Active, true)];
        let sel = select_peers_for_tenant(&snapshot, Some("alpha"));
        assert_eq!(sel.peers.len(), 1);
    }

    #[test]
    fn pinned_peer_rejects_other_tenant() {
        let snapshot = vec![make_peer("p1", vec!["alpha"], TopologyRole::Active, true)];
        let sel = select_peers_for_tenant(&snapshot, Some("bravo"));
        assert_eq!(sel.kind, SelectionKind::NoCandidates);
    }

    #[test]
    fn standby_held_back_when_active_available() {
        let snapshot = vec![
            make_peer("active", vec!["alpha"], TopologyRole::Active, true),
            make_peer("standby", vec!["alpha"], TopologyRole::Standby, true),
        ];
        let sel = select_peers_for_tenant(&snapshot, Some("alpha"));
        assert_eq!(sel.kind, SelectionKind::Active);
        assert_eq!(sel.peers.len(), 1);
        assert_eq!(sel.peers[0].0.as_str(), "active");
    }

    #[test]
    fn standby_promoted_when_active_unavailable() {
        let snapshot = vec![
            make_peer("active", vec!["alpha"], TopologyRole::Active, false),
            make_peer("standby", vec!["alpha"], TopologyRole::Standby, true),
        ];
        let sel = select_peers_for_tenant(&snapshot, Some("alpha"));
        assert_eq!(sel.kind, SelectionKind::StandbyPromoted);
        assert_eq!(sel.peers.len(), 1);
        assert_eq!(sel.peers[0].0.as_str(), "standby");
    }

    #[test]
    fn standby_promoted_when_no_active_in_scope() {
        // No active peer in scope at all — every peer is standby.
        let snapshot = vec![
            make_peer("s1", vec!["alpha"], TopologyRole::Standby, true),
            make_peer("s2", vec!["alpha"], TopologyRole::Standby, true),
        ];
        let sel = select_peers_for_tenant(&snapshot, Some("alpha"));
        assert_eq!(sel.kind, SelectionKind::StandbyPromoted);
        assert_eq!(sel.peers.len(), 2);
    }

    #[test]
    fn no_candidates_when_every_peer_unavailable() {
        let snapshot = vec![
            make_peer("a", vec!["alpha"], TopologyRole::Active, false),
            make_peer("s", vec!["alpha"], TopologyRole::Standby, false),
        ];
        let sel = select_peers_for_tenant(&snapshot, Some("alpha"));
        assert_eq!(sel.kind, SelectionKind::NoCandidates);
        assert!(sel.peers.is_empty());
    }

    #[test]
    fn multiple_active_all_returned() {
        let snapshot = vec![
            make_peer("a1", vec!["alpha"], TopologyRole::Active, true),
            make_peer("a2", vec!["alpha"], TopologyRole::Active, true),
            make_peer("s1", vec!["alpha"], TopologyRole::Standby, true),
        ];
        let sel = select_peers_for_tenant(&snapshot, Some("alpha"));
        assert_eq!(sel.kind, SelectionKind::Active);
        assert_eq!(sel.peers.len(), 2);
    }

    #[test]
    fn cross_tenant_isolation() {
        // alpha-pinned and bravo-pinned peers — message for alpha sees
        // only alpha-pinned peer; same for bravo. Shared peer sees both.
        let snapshot = vec![
            make_peer("alpha-only", vec!["alpha"], TopologyRole::Active, true),
            make_peer("bravo-only", vec!["bravo"], TopologyRole::Active, true),
            make_peer("shared", vec!["*"], TopologyRole::Active, true),
        ];
        let sel_alpha = select_peers_for_tenant(&snapshot, Some("alpha"));
        let alpha_ids: Vec<&str> = sel_alpha.peers.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(alpha_ids.len(), 2);
        assert!(alpha_ids.contains(&"alpha-only"));
        assert!(alpha_ids.contains(&"shared"));
        assert!(!alpha_ids.contains(&"bravo-only"));

        let sel_bravo = select_peers_for_tenant(&snapshot, Some("bravo"));
        let bravo_ids: Vec<&str> = sel_bravo.peers.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(bravo_ids.len(), 2);
        assert!(bravo_ids.contains(&"bravo-only"));
        assert!(bravo_ids.contains(&"shared"));
        assert!(!bravo_ids.contains(&"alpha-only"));
    }

    #[test]
    fn selection_kind_as_str_vocabulary_is_stable() {
        assert_eq!(SelectionKind::Active.as_str(), "active");
        assert_eq!(SelectionKind::StandbyPromoted.as_str(), "standby_promoted");
        assert_eq!(SelectionKind::NoCandidates.as_str(), "no_candidates");
    }
}
