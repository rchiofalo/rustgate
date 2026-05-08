// Copyright © 2026 Roberto Chiofalo.

//! Mesh-native peer-to-peer multi-hop routing.
//!
//! This module turns the federation layer from a hub-and-spoke topology
//! into a mesh router. Each node maintains a [`MeshRoutingTable`] mapping
//! every reachable destination [`PeerId`] to the [`PeerId`] of the next
//! hop along the lowest-cost path. Routes are learned by exchanging
//! periodic [`RouteAdvertisement`] vectors with directly-connected
//! neighbors over the existing federation transport (gRPC heartbeat or
//! application-level CoT keepalive) — the MVP carries the payload as a
//! `serde_json` blob alongside the existing heartbeat so that the proto
//! schema does not have to change to ship the foundation. A follow-up
//! issue tracks a typed protobuf field replacement.
//!
//! # Distance-vector model
//!
//! The MVP uses a Bellman-Ford-style distance-vector:
//!
//! - Every neighbor advertises a list of `(destination, metric)` pairs
//!   describing the destinations *they* can reach and at what cost.
//! - On receipt, this node installs `(destination, neighbor, neighbor_metric + 1)`
//!   for any destination where the new metric beats the currently
//!   installed route, or where the previously-best next hop is the
//!   advertising neighbor (a route refresh).
//! - Routes are aged out by [`MeshRoutingTable::sweep_stale`] when their
//!   `last_updated` falls outside the configured staleness window.
//!
//! Distance-vector is intentionally simple — it does **not** detect a
//! count-to-infinity scenario. The current implementation guards
//! against runaway by capping the maximum installed metric at
//! [`MeshConfig::max_hops`]: any advertisement that would push a route
//! past that cap is rejected at the table boundary. Link-state (OSPF-like)
//! routing is documented as the planned upgrade path.
//!
//! # Multi-hop forwarding
//!
//! When an inbound federated message names a destination that is **not**
//! the local node, [`MeshRoutingTable::next_hop`] is consulted. If a
//! route exists, the message is re-forwarded to that neighbor via the
//! existing federation egress queue. If not, the message is dropped and
//! [`rustgate_core::audit::mesh_no_route_to_destination`] is emitted.
//!
//! # Loop detection
//!
//! Loop detection piggybacks on the existing [`crate::provenance::FederationMetadata`]
//! chain: before forwarding, the [`MeshRouter`] verifies that this
//! node's `federate_id` is not already present in the message's
//! provenance. If it is, the message is dropped and
//! [`rustgate_core::audit::mesh_loop_detected`] is emitted. This is a
//! defense-in-depth check on top of the routing table itself —
//! distance-vector advertisements, when correct, should keep packets
//! moving towards a destination without revisiting prior hops, but a
//! transient inconsistency can still produce a loop.
//!
//! # TTL
//!
//! Hop count is enforced via the existing
//! [`crate::provenance::FederationMetadata::current_hops`] /
//! [`crate::provenance::FederationMetadata::max_hops`] fields.
//! [`MeshRouter::should_forward`] rejects messages whose `current_hops`
//! has reached `max_hops` (default 8 for mesh-routing) and emits
//! [`rustgate_core::audit::mesh_ttl_expired`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rustgate_core::{PeerId, audit};
use serde::{Deserialize, Serialize};

use crate::provenance::FederationMetadata;

/// Default maximum hop count for a mesh-routed message.
///
/// Conservative cap to bound the worst-case per-message work in a
/// pathological topology. Operators wanting a deeper diameter should
/// raise [`MeshConfig::max_hops`] explicitly.
pub const DEFAULT_MAX_HOPS: u32 = 8;

/// Default interval at which the local node broadcasts its routing
/// table to directly-connected neighbors.
pub const DEFAULT_ADVERTISEMENT_INTERVAL: Duration = Duration::from_secs(30);

/// Default age after which a route entry is considered stale and
/// eligible for eviction by [`MeshRoutingTable::sweep_stale`].
///
/// Set to three advertisement intervals so a single missed advert does
/// not flap routes — only a sustained absence prunes the entry. This
/// mirrors the federation heartbeat-timeout-to-interval ratio.
pub const DEFAULT_ROUTE_STALENESS: Duration = Duration::from_secs(90);

/// A single mesh routing-table entry.
///
/// Identifies the next-hop peer to forward through to reach
/// `destination`, along with the distance-vector cost (`metric`,
/// measured in hops) and the wall-clock time the entry was last
/// refreshed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRoute {
    /// Final destination this route reaches.
    pub destination: PeerId,
    /// Directly-connected neighbor used as the next hop.
    pub next_hop: PeerId,
    /// Hop count from this node to the destination via `next_hop`.
    pub metric: u32,
    /// Last time this entry was refreshed (used to age out stale routes).
    pub last_updated: Instant,
}

/// One entry in a [`RouteAdvertisement`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertisedRoute {
    /// Destination this neighbor claims to be able to reach.
    pub destination: PeerId,
    /// Cost (hop count) from the advertising neighbor to `destination`.
    pub metric: u32,
}

/// A vector of `(destination, metric)` pairs that one neighbor publishes
/// to another so the receiver can update its routing table.
///
/// Carried over the existing federation transport: the MVP serializes
/// this struct to JSON and attaches it to the heartbeat side-channel.
/// A typed proto field replacement is tracked as a follow-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAdvertisement {
    /// Peer id of the advertising neighbor.
    pub origin: PeerId,
    /// Routes this neighbor offers.
    pub routes: Vec<AdvertisedRoute>,
}

/// Configuration for the mesh router.
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// Identity of the local node — must match the federation
    /// `federate_id` so loop detection compares against the same value
    /// the rest of the federation stack records in provenance.
    pub local_peer_id: PeerId,
    /// Maximum hop count for a single message. Messages exceeding this
    /// cap are dropped at the forwarding boundary.
    pub max_hops: u32,
    /// Interval at which the local node re-advertises its routes.
    pub advertisement_interval: Duration,
    /// Age after which an unrefreshed route entry is pruned.
    pub route_staleness: Duration,
}

impl MeshConfig {
    /// Build a config for a node identified by `local_peer_id`, using
    /// the documented defaults for all other fields.
    pub fn new(local_peer_id: impl Into<PeerId>) -> Self {
        Self {
            local_peer_id: local_peer_id.into(),
            max_hops: DEFAULT_MAX_HOPS,
            advertisement_interval: DEFAULT_ADVERTISEMENT_INTERVAL,
            route_staleness: DEFAULT_ROUTE_STALENESS,
        }
    }
}

/// In-memory distance-vector routing table.
///
/// Entries are keyed by destination peer id; each entry holds the
/// best-known next hop and the metric advertised when the entry was
/// last refreshed. The table is wrapped in a `parking_lot::RwLock` to
/// allow lock-free reads on the hot forwarding path while serializing
/// the relatively-rare advertisement-application writes.
#[derive(Debug, Default)]
pub struct MeshRoutingTable {
    inner: RwLock<HashMap<PeerId, MeshRoute>>,
}

impl MeshRoutingTable {
    /// Construct an empty routing table.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Look up the next hop for `destination`.
    ///
    /// Returns `None` if no route exists or the only known route is
    /// already older than the configured staleness window. The
    /// staleness check is performed *here* rather than only in
    /// [`Self::sweep_stale`] so that a missed sweep cannot cause stale
    /// forwards on the hot path.
    pub fn next_hop(&self, destination: &PeerId, staleness: Duration) -> Option<PeerId> {
        let now = Instant::now();
        let guard = self.inner.read();
        guard.get(destination).and_then(|route| {
            // `checked_duration_since` returns `None` if the clock went
            // backwards (e.g. NTP step). Treat that as "not stale" so
            // we keep forwarding rather than artificially pruning the
            // table.
            match now.checked_duration_since(route.last_updated) {
                Some(age) if age > staleness => None,
                _ => Some(route.next_hop.clone()),
            }
        })
    }

    /// Snapshot every known route. Useful for tests and route-API
    /// observability surfaces; not on the hot forwarding path.
    pub fn snapshot(&self) -> Vec<MeshRoute> {
        self.inner.read().values().cloned().collect()
    }

    /// Number of currently-installed route entries.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether the table has zero installed routes.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Apply a [`RouteAdvertisement`] received from a directly-connected
    /// neighbor.
    ///
    /// `local_peer_id` is the identity of this node — used to suppress
    /// self-routes (an advertisement that mentions us as a destination
    /// is dropped). `max_hops` is the hard cap from [`MeshConfig`];
    /// any route whose installed metric would exceed it is rejected
    /// to bound the count-to-infinity worst case.
    pub fn apply_advertisement(
        &self,
        advertisement: &RouteAdvertisement,
        local_peer_id: &PeerId,
        max_hops: u32,
    ) {
        // Don't learn routes from ourselves: an advert claiming to
        // originate at our own peer-id is either a misconfiguration or
        // a reflection.
        if &advertisement.origin == local_peer_id {
            return;
        }

        let now = Instant::now();
        let mut guard = self.inner.write();

        for advertised in &advertisement.routes {
            // Self-destination: never install a route to our own peer-id.
            if &advertised.destination == local_peer_id {
                continue;
            }

            // The neighbor's advertised metric is the cost from the
            // neighbor to the destination; the cost from *this* node is
            // one hop more (the link from us to the neighbor).
            let new_metric = advertised.metric.saturating_add(1);
            if new_metric > max_hops {
                continue;
            }

            let route = MeshRoute {
                destination: advertised.destination.clone(),
                next_hop: advertisement.origin.clone(),
                metric: new_metric,
                last_updated: now,
            };

            match guard.get(&advertised.destination) {
                None => {
                    let _ = guard.insert(advertised.destination.clone(), route);
                    audit::mesh_route_added(
                        &advertised.destination,
                        &advertisement.origin,
                        new_metric,
                    );
                }
                Some(existing) => {
                    // Refresh `last_updated` if the advertising
                    // neighbor is still our installed next hop, even
                    // when the metric is unchanged — this prevents a
                    // healthy route from aging out under
                    // [`Self::sweep_stale`]. Replace the entry only
                    // when a *strictly better* metric is offered or
                    // when the same neighbor reports a different
                    // metric (a topology change worth recording).
                    if existing.next_hop == advertisement.origin {
                        if existing.metric != new_metric {
                            let old_metric = existing.metric;
                            let _ = guard.insert(advertised.destination.clone(), route);
                            audit::mesh_route_updated(
                                &advertised.destination,
                                &advertisement.origin,
                                old_metric,
                                new_metric,
                            );
                        } else {
                            // Same neighbor, same metric: just refresh
                            // the timestamp.
                            if let Some(slot) = guard.get_mut(&advertised.destination) {
                                slot.last_updated = now;
                            }
                        }
                    } else if new_metric < existing.metric {
                        let old_metric = existing.metric;
                        let _ = guard.insert(advertised.destination.clone(), route);
                        audit::mesh_route_updated(
                            &advertised.destination,
                            &advertisement.origin,
                            old_metric,
                            new_metric,
                        );
                    }
                    // Else: existing route via different next hop with
                    // strictly worse new offer — keep the existing.
                }
            }
        }
    }

    /// Remove any route whose `last_updated` is older than `staleness`.
    /// Returns the destinations that were pruned.
    pub fn sweep_stale(&self, staleness: Duration) -> Vec<PeerId> {
        let now = Instant::now();
        let mut guard = self.inner.write();
        let mut removed = Vec::new();
        guard.retain(|destination, route| {
            let age = now
                .checked_duration_since(route.last_updated)
                .unwrap_or(Duration::ZERO);
            if age > staleness {
                removed.push(destination.clone());
                false
            } else {
                true
            }
        });
        drop(guard);
        for destination in &removed {
            audit::mesh_route_removed(destination, "stale");
        }
        removed
    }

    /// Drop every route whose next hop is `next_hop`. Used when a
    /// neighbor disconnects and is no longer a viable forwarder. Returns
    /// the destinations that were withdrawn as a result.
    pub fn withdraw_neighbor(&self, next_hop: &PeerId) -> Vec<PeerId> {
        let mut guard = self.inner.write();
        let mut removed = Vec::new();
        guard.retain(|destination, route| {
            if &route.next_hop == next_hop {
                removed.push(destination.clone());
                false
            } else {
                true
            }
        });
        drop(guard);
        for destination in &removed {
            audit::mesh_route_removed(destination, "neighbor_disconnected");
        }
        removed
    }

    /// Build a [`RouteAdvertisement`] describing every destination
    /// this node currently knows how to reach. The vector is the
    /// payload this node will broadcast on its next advertisement
    /// tick.
    pub fn build_advertisement(&self, local_peer_id: &PeerId) -> RouteAdvertisement {
        let guard = self.inner.read();
        let routes = guard
            .values()
            .map(|route| AdvertisedRoute {
                destination: route.destination.clone(),
                metric: route.metric,
            })
            .collect();
        RouteAdvertisement {
            origin: local_peer_id.clone(),
            routes,
        }
    }
}

/// Outcome of consulting [`MeshRouter::should_forward`].
///
/// Returned to callers so they can take the right action: forward to a
/// resolved next hop, drop with a specific audit reason, or treat the
/// message as locally-deliverable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardDecision {
    /// Destination is the local node — deliver locally.
    Local,
    /// Forward via the resolved neighbor.
    Forward {
        /// Next-hop peer id to enqueue the message towards.
        next_hop: PeerId,
    },
    /// Drop the message — provenance chain shows we already saw it.
    DropLoop,
    /// Drop the message — hop count exceeded.
    DropTtl,
    /// Drop the message — no route exists.
    DropNoRoute,
}

/// Top-level mesh router: configuration plus the in-memory routing
/// table. Owned by the [`crate::manager::FederationManager`] when the
/// `mesh-routing` feature is enabled.
#[derive(Debug)]
pub struct MeshRouter {
    config: MeshConfig,
    table: Arc<MeshRoutingTable>,
}

impl MeshRouter {
    /// Build a new router for the given configuration with an empty
    /// routing table.
    pub fn new(config: MeshConfig) -> Self {
        Self {
            config,
            table: Arc::new(MeshRoutingTable::new()),
        }
    }

    /// Borrow the underlying routing table (e.g. for direct insertion
    /// in tests, or for status APIs).
    pub fn table(&self) -> Arc<MeshRoutingTable> {
        Arc::clone(&self.table)
    }

    /// The mesh configuration.
    pub fn config(&self) -> &MeshConfig {
        &self.config
    }

    /// Decide what to do with a federated message destined for `destination`.
    ///
    /// Emits the appropriate audit event for every drop case so the
    /// caller does not need to mirror the bookkeeping. Side-effect-free
    /// otherwise (it does not enqueue forwards itself; the caller's
    /// existing federation outbound queue does that work).
    pub fn should_forward(
        &self,
        destination: &PeerId,
        provenance: &FederationMetadata,
    ) -> ForwardDecision {
        // Self-delivery: short-circuit.
        if destination == &self.config.local_peer_id {
            return ForwardDecision::Local;
        }

        // TTL: the inbound hop count already includes every prior
        // forwarder; if we're at the cap, dropping early prevents one
        // last useless re-forward.
        if provenance.current_hops >= self.config.max_hops {
            audit::mesh_ttl_expired(destination, provenance.current_hops, self.config.max_hops);
            return ForwardDecision::DropTtl;
        }

        // Loop: if our own peer-id is already in the chain, this packet
        // has been here before. Drop hard rather than re-forward into
        // the same loop on the next pass.
        if provenance
            .provenance
            .iter()
            .any(|p| p.server_id == self.config.local_peer_id)
        {
            audit::mesh_loop_detected(destination, provenance.current_hops);
            return ForwardDecision::DropLoop;
        }

        match self
            .table
            .next_hop(destination, self.config.route_staleness)
        {
            Some(next_hop) => {
                audit::mesh_forwarded(destination, &next_hop, provenance.current_hops);
                ForwardDecision::Forward { next_hop }
            }
            None => {
                audit::mesh_no_route_to_destination(destination);
                ForwardDecision::DropNoRoute
            }
        }
    }

    /// Apply an advertisement received from a directly-connected
    /// neighbor.
    pub fn apply_advertisement(&self, advertisement: &RouteAdvertisement) {
        self.table.apply_advertisement(
            advertisement,
            &self.config.local_peer_id,
            self.config.max_hops,
        );
    }

    /// Convenience: install a direct (one-hop) route to `neighbor`.
    /// Called when a federation peer connects, so the local mesh table
    /// immediately reflects the new direct neighbor without waiting
    /// for an advertisement round-trip.
    pub fn add_direct_neighbor(&self, neighbor: &PeerId) {
        let advert = RouteAdvertisement {
            origin: neighbor.clone(),
            routes: vec![AdvertisedRoute {
                destination: neighbor.clone(),
                // Cost from the neighbor to itself is 0; this routes
                // table will install (neighbor → 1 hop via neighbor).
                metric: 0,
            }],
        };
        self.apply_advertisement(&advert);
    }

    /// Withdraw every route that uses `neighbor` as the next hop.
    /// Called when a federation peer disconnects. Returns the
    /// destinations that were withdrawn — the caller may discard the
    /// vector if it does not need diagnostics.
    pub fn withdraw_neighbor(&self, neighbor: &PeerId) -> Vec<PeerId> {
        self.table.withdraw_neighbor(neighbor)
    }

    /// Build the advertisement vector this node will broadcast. The
    /// caller is responsible for plumbing the result onto the wire.
    pub fn build_advertisement(&self) -> RouteAdvertisement {
        self.table.build_advertisement(&self.config.local_peer_id)
    }

    /// Sweep stale entries. Returns the destinations pruned.
    pub fn sweep_stale(&self) -> Vec<PeerId> {
        self.table.sweep_stale(self.config.route_staleness)
    }
}

#[cfg(test)]
mod tests {
    use rustgate_core::ServerName;

    use super::*;

    fn pid(s: &str) -> PeerId {
        PeerId::new(s)
    }

    #[test]
    fn empty_table_returns_no_route() {
        let table = MeshRoutingTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(
            table
                .next_hop(&pid("dest"), Duration::from_secs(60))
                .is_none()
        );
    }

    #[test]
    fn applying_advertisement_installs_route_with_incremented_metric() {
        let table = MeshRoutingTable::new();
        let advert = RouteAdvertisement {
            origin: pid("neighbor"),
            routes: vec![AdvertisedRoute {
                destination: pid("far"),
                metric: 2,
            }],
        };
        table.apply_advertisement(&advert, &pid("local"), DEFAULT_MAX_HOPS);
        let next_hop = table
            .next_hop(&pid("far"), DEFAULT_ROUTE_STALENESS)
            .expect("route installed");
        assert_eq!(next_hop, pid("neighbor"));
        let snap = table.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].metric, 3);
    }

    #[test]
    fn self_origin_advertisement_is_ignored() {
        let table = MeshRoutingTable::new();
        let advert = RouteAdvertisement {
            origin: pid("local"),
            routes: vec![AdvertisedRoute {
                destination: pid("far"),
                metric: 1,
            }],
        };
        table.apply_advertisement(&advert, &pid("local"), DEFAULT_MAX_HOPS);
        assert!(table.is_empty());
    }

    #[test]
    fn self_destination_advertisement_is_ignored() {
        let table = MeshRoutingTable::new();
        let advert = RouteAdvertisement {
            origin: pid("neighbor"),
            routes: vec![
                AdvertisedRoute {
                    destination: pid("local"),
                    metric: 1,
                },
                AdvertisedRoute {
                    destination: pid("other"),
                    metric: 2,
                },
            ],
        };
        table.apply_advertisement(&advert, &pid("local"), DEFAULT_MAX_HOPS);
        assert_eq!(table.len(), 1);
        assert!(
            table
                .next_hop(&pid("local"), DEFAULT_ROUTE_STALENESS)
                .is_none()
        );
        assert_eq!(
            table
                .next_hop(&pid("other"), DEFAULT_ROUTE_STALENESS)
                .expect("route present"),
            pid("neighbor")
        );
    }

    #[test]
    fn route_above_max_hops_is_rejected() {
        let table = MeshRoutingTable::new();
        let advert = RouteAdvertisement {
            origin: pid("neighbor"),
            routes: vec![AdvertisedRoute {
                destination: pid("far"),
                metric: 10,
            }],
        };
        // Cap = 5, advertised cost = 10, installed = 11 → reject.
        table.apply_advertisement(&advert, &pid("local"), 5);
        assert!(table.is_empty());
    }

    #[test]
    fn lower_metric_via_different_neighbor_replaces_route() {
        let table = MeshRoutingTable::new();
        table.apply_advertisement(
            &RouteAdvertisement {
                origin: pid("n1"),
                routes: vec![AdvertisedRoute {
                    destination: pid("far"),
                    metric: 5,
                }],
            },
            &pid("local"),
            DEFAULT_MAX_HOPS,
        );
        table.apply_advertisement(
            &RouteAdvertisement {
                origin: pid("n2"),
                routes: vec![AdvertisedRoute {
                    destination: pid("far"),
                    metric: 1,
                }],
            },
            &pid("local"),
            DEFAULT_MAX_HOPS,
        );
        let next_hop = table
            .next_hop(&pid("far"), DEFAULT_ROUTE_STALENESS)
            .expect("route present");
        assert_eq!(next_hop, pid("n2"));
    }

    #[test]
    fn higher_metric_via_different_neighbor_does_not_replace() {
        let table = MeshRoutingTable::new();
        table.apply_advertisement(
            &RouteAdvertisement {
                origin: pid("n1"),
                routes: vec![AdvertisedRoute {
                    destination: pid("far"),
                    metric: 1,
                }],
            },
            &pid("local"),
            DEFAULT_MAX_HOPS,
        );
        table.apply_advertisement(
            &RouteAdvertisement {
                origin: pid("n2"),
                routes: vec![AdvertisedRoute {
                    destination: pid("far"),
                    metric: 5,
                }],
            },
            &pid("local"),
            DEFAULT_MAX_HOPS,
        );
        let next_hop = table
            .next_hop(&pid("far"), DEFAULT_ROUTE_STALENESS)
            .expect("route present");
        assert_eq!(next_hop, pid("n1"));
    }

    #[test]
    fn metric_change_from_same_neighbor_updates_entry() {
        let table = MeshRoutingTable::new();
        table.apply_advertisement(
            &RouteAdvertisement {
                origin: pid("n1"),
                routes: vec![AdvertisedRoute {
                    destination: pid("far"),
                    metric: 1,
                }],
            },
            &pid("local"),
            DEFAULT_MAX_HOPS,
        );
        table.apply_advertisement(
            &RouteAdvertisement {
                origin: pid("n1"),
                routes: vec![AdvertisedRoute {
                    destination: pid("far"),
                    metric: 4,
                }],
            },
            &pid("local"),
            DEFAULT_MAX_HOPS,
        );
        let snap = table.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].metric, 5);
    }

    #[test]
    fn withdraw_neighbor_removes_only_matching_routes() {
        let table = MeshRoutingTable::new();
        table.apply_advertisement(
            &RouteAdvertisement {
                origin: pid("n1"),
                routes: vec![AdvertisedRoute {
                    destination: pid("a"),
                    metric: 0,
                }],
            },
            &pid("local"),
            DEFAULT_MAX_HOPS,
        );
        table.apply_advertisement(
            &RouteAdvertisement {
                origin: pid("n2"),
                routes: vec![AdvertisedRoute {
                    destination: pid("b"),
                    metric: 0,
                }],
            },
            &pid("local"),
            DEFAULT_MAX_HOPS,
        );
        assert_eq!(table.len(), 2);
        let removed = table.withdraw_neighbor(&pid("n1"));
        assert_eq!(removed, vec![pid("a")]);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table
                .next_hop(&pid("b"), DEFAULT_ROUTE_STALENESS)
                .expect("route present"),
            pid("n2")
        );
    }

    #[test]
    fn sweep_stale_evicts_aged_entries() {
        let table = MeshRoutingTable::new();
        table.apply_advertisement(
            &RouteAdvertisement {
                origin: pid("n1"),
                routes: vec![AdvertisedRoute {
                    destination: pid("a"),
                    metric: 0,
                }],
            },
            &pid("local"),
            DEFAULT_MAX_HOPS,
        );
        // A 0-second staleness threshold treats every entry as stale.
        let removed = table.sweep_stale(Duration::from_secs(0));
        assert!(removed.contains(&pid("a")));
        assert!(table.is_empty());
    }

    #[test]
    fn build_advertisement_emits_installed_routes() {
        let table = MeshRoutingTable::new();
        table.apply_advertisement(
            &RouteAdvertisement {
                origin: pid("n1"),
                routes: vec![AdvertisedRoute {
                    destination: pid("a"),
                    metric: 1,
                }],
            },
            &pid("local"),
            DEFAULT_MAX_HOPS,
        );
        let advert = table.build_advertisement(&pid("local"));
        assert_eq!(advert.origin, pid("local"));
        assert_eq!(advert.routes.len(), 1);
        assert_eq!(advert.routes[0].destination, pid("a"));
        assert_eq!(advert.routes[0].metric, 2);
    }

    fn provenance_with(server_ids: &[&str]) -> FederationMetadata {
        let mut meta = FederationMetadata::new(DEFAULT_MAX_HOPS);
        for id in server_ids {
            meta.add_hop(&pid(id), &ServerName::new(*id));
        }
        meta
    }

    #[test]
    fn router_decides_local_for_self_destination() {
        let router = MeshRouter::new(MeshConfig::new(pid("local")));
        let meta = provenance_with(&[]);
        assert_eq!(
            router.should_forward(&pid("local"), &meta),
            ForwardDecision::Local
        );
    }

    #[test]
    fn router_decides_drop_no_route_for_unknown_destination() {
        let router = MeshRouter::new(MeshConfig::new(pid("local")));
        let meta = provenance_with(&[]);
        assert_eq!(
            router.should_forward(&pid("unknown"), &meta),
            ForwardDecision::DropNoRoute
        );
    }

    #[test]
    fn router_decides_drop_loop_when_self_in_provenance() {
        let router = MeshRouter::new(MeshConfig::new(pid("local")));
        // Add a route so the loop check is the *reason* we drop, not
        // an accidental absence of route.
        router.add_direct_neighbor(&pid("dest"));
        let meta = provenance_with(&["a", "local", "b"]);
        assert_eq!(
            router.should_forward(&pid("dest"), &meta),
            ForwardDecision::DropLoop
        );
    }

    #[test]
    fn router_decides_drop_ttl_when_at_cap() {
        let router = MeshRouter::new(MeshConfig {
            local_peer_id: pid("local"),
            max_hops: 2,
            advertisement_interval: DEFAULT_ADVERTISEMENT_INTERVAL,
            route_staleness: DEFAULT_ROUTE_STALENESS,
        });
        router.add_direct_neighbor(&pid("dest"));
        let meta = provenance_with(&["a", "b"]);
        assert_eq!(
            router.should_forward(&pid("dest"), &meta),
            ForwardDecision::DropTtl
        );
    }

    #[test]
    fn router_decides_forward_through_resolved_next_hop() {
        let router = MeshRouter::new(MeshConfig::new(pid("local")));
        router.apply_advertisement(&RouteAdvertisement {
            origin: pid("neighbor"),
            routes: vec![AdvertisedRoute {
                destination: pid("far"),
                metric: 1,
            }],
        });
        let meta = provenance_with(&["origin"]);
        assert_eq!(
            router.should_forward(&pid("far"), &meta),
            ForwardDecision::Forward {
                next_hop: pid("neighbor"),
            }
        );
    }

    #[test]
    fn add_direct_neighbor_creates_one_hop_route() {
        let router = MeshRouter::new(MeshConfig::new(pid("local")));
        router.add_direct_neighbor(&pid("neighbor"));
        let snap = router.table().snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].destination, pid("neighbor"));
        assert_eq!(snap[0].next_hop, pid("neighbor"));
        assert_eq!(snap[0].metric, 1);
    }

    #[test]
    fn build_advertisement_is_serde_round_trippable() {
        let router = MeshRouter::new(MeshConfig::new(pid("local")));
        router.add_direct_neighbor(&pid("neighbor"));
        let advert = router.build_advertisement();
        let json = serde_json::to_string(&advert).expect("serializes");
        let parsed: RouteAdvertisement = serde_json::from_str(&json).expect("parses");
        assert_eq!(advert, parsed);
    }

    #[test]
    fn config_defaults_are_documented_constants() {
        let config = MeshConfig::new(pid("local"));
        assert_eq!(config.max_hops, DEFAULT_MAX_HOPS);
        assert_eq!(
            config.advertisement_interval,
            DEFAULT_ADVERTISEMENT_INTERVAL
        );
        assert_eq!(config.route_staleness, DEFAULT_ROUTE_STALENESS);
    }
}
