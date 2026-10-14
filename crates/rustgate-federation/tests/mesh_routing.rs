// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the mesh-routing MVP.
//!
//! Three-node topology `A → B → C` exercises the multi-hop forwarding
//! decision path: B has direct neighbors A and C, A learns about C
//! through B's advertisement, and `should_forward` resolves the
//! correct next hop. The other two tests cover loop detection (the
//! provenance chain already contains the local peer-id) and TTL
//! exhaustion (`current_hops == max_hops`).

#![cfg(feature = "mesh-routing")]

use rustgate_core::{PeerId, ServerName};
use rustgate_federation::mesh::{
    AdvertisedRoute, ForwardDecision, MeshConfig, MeshRouter, RouteAdvertisement,
};
use rustgate_federation::provenance::FederationMetadata;

fn pid(s: &str) -> PeerId {
    PeerId::new(s)
}

fn provenance_with(server_ids: &[&str], max_hops: u32) -> FederationMetadata {
    let mut meta = FederationMetadata::new(max_hops);
    for id in server_ids {
        meta.add_hop(&pid(id), &ServerName::new(*id));
    }
    meta
}

#[test]
fn three_node_chain_a_b_c_resolves_multi_hop_forward() {
    // Three-node mesh: A — B — C. B is directly connected to both A
    // and C; A only knows about C via B's advertisement. Verify A
    // forwards a message destined for C through B.
    let a = MeshRouter::new(MeshConfig::new(pid("A")));

    // A's only direct neighbor is B.
    a.add_direct_neighbor(&pid("B"));

    // B advertises that it can reach C in one hop. Distance-vector
    // installs (C → next_hop=B, metric=2) on A's table.
    a.apply_advertisement(&RouteAdvertisement {
        origin: pid("B"),
        routes: vec![AdvertisedRoute {
            destination: pid("C"),
            metric: 1,
        }],
    });

    // Inbound message from upstream `origin` heads for C; A should
    // forward to B.
    let meta = provenance_with(&["origin"], 8);
    let decision = a.should_forward(&pid("C"), &meta);
    assert_eq!(decision, ForwardDecision::Forward { next_hop: pid("B") });

    // The direct destination B still resolves to itself as next hop.
    let decision_to_b = a.should_forward(&pid("B"), &meta);
    assert_eq!(
        decision_to_b,
        ForwardDecision::Forward { next_hop: pid("B") }
    );
}

#[test]
fn loop_detection_drops_packet_when_self_in_provenance() {
    let a = MeshRouter::new(MeshConfig::new(pid("A")));
    a.add_direct_neighbor(&pid("B"));
    a.apply_advertisement(&RouteAdvertisement {
        origin: pid("B"),
        routes: vec![AdvertisedRoute {
            destination: pid("C"),
            metric: 1,
        }],
    });

    // Provenance shows the packet already passed through A — dropping
    // here prevents an infinite loop in the routing fabric.
    let meta = provenance_with(&["origin", "A", "B"], 8);
    let decision = a.should_forward(&pid("C"), &meta);
    assert_eq!(decision, ForwardDecision::DropLoop);
}

#[test]
fn ttl_exhaustion_drops_packet_at_max_hops() {
    let a = MeshRouter::new(MeshConfig {
        local_peer_id: pid("A"),
        max_hops: 3,
        advertisement_interval: rustgate_federation::mesh::DEFAULT_ADVERTISEMENT_INTERVAL,
        route_staleness: rustgate_federation::mesh::DEFAULT_ROUTE_STALENESS,
    });
    a.add_direct_neighbor(&pid("B"));
    a.apply_advertisement(&RouteAdvertisement {
        origin: pid("B"),
        routes: vec![AdvertisedRoute {
            destination: pid("C"),
            metric: 1,
        }],
    });

    // Three prior hops with max_hops=3 → packet has reached its TTL
    // and must not be forwarded further.
    let meta = provenance_with(&["o", "p", "q"], 3);
    let decision = a.should_forward(&pid("C"), &meta);
    assert_eq!(decision, ForwardDecision::DropTtl);
}

#[test]
fn unknown_destination_yields_drop_no_route() {
    let a = MeshRouter::new(MeshConfig::new(pid("A")));
    a.add_direct_neighbor(&pid("B"));

    let meta = provenance_with(&["origin"], 8);
    // C is unknown — no advertisement has been received.
    let decision = a.should_forward(&pid("C"), &meta);
    assert_eq!(decision, ForwardDecision::DropNoRoute);
}

#[test]
fn neighbor_disconnect_withdraws_routes_through_that_neighbor() {
    // Topology: A learns about C via B. When B disconnects, A must
    // drop the C route too.
    let a = MeshRouter::new(MeshConfig::new(pid("A")));
    a.add_direct_neighbor(&pid("B"));
    a.apply_advertisement(&RouteAdvertisement {
        origin: pid("B"),
        routes: vec![
            AdvertisedRoute {
                destination: pid("C"),
                metric: 1,
            },
            AdvertisedRoute {
                destination: pid("D"),
                metric: 2,
            },
        ],
    });
    assert_eq!(a.table().len(), 3); // B (direct), C, D

    // B disconnects.
    let _ = a.withdraw_neighbor(&pid("B"));

    let meta = provenance_with(&["origin"], 8);
    assert_eq!(
        a.should_forward(&pid("C"), &meta),
        ForwardDecision::DropNoRoute
    );
    assert_eq!(
        a.should_forward(&pid("D"), &meta),
        ForwardDecision::DropNoRoute
    );
    assert_eq!(
        a.should_forward(&pid("B"), &meta),
        ForwardDecision::DropNoRoute
    );
}

#[test]
fn distance_vector_prefers_lower_metric_path() {
    // Four nodes: A is connected to both B and D. Both B and D
    // advertise that they can reach C, but B says metric=4 while D
    // says metric=1. A should route through D.
    let a = MeshRouter::new(MeshConfig::new(pid("A")));
    a.add_direct_neighbor(&pid("B"));
    a.add_direct_neighbor(&pid("D"));

    a.apply_advertisement(&RouteAdvertisement {
        origin: pid("B"),
        routes: vec![AdvertisedRoute {
            destination: pid("C"),
            metric: 4,
        }],
    });
    a.apply_advertisement(&RouteAdvertisement {
        origin: pid("D"),
        routes: vec![AdvertisedRoute {
            destination: pid("C"),
            metric: 1,
        }],
    });

    let meta = provenance_with(&["origin"], 8);
    assert_eq!(
        a.should_forward(&pid("C"), &meta),
        ForwardDecision::Forward { next_hop: pid("D") }
    );
}

#[test]
fn build_advertisement_round_trips_through_serde_json() {
    // The MVP serializes route advertisements as JSON for transport
    // alongside the existing federation heartbeat. Verify the
    // round-trip reconstructs an equivalent advertisement.
    let a = MeshRouter::new(MeshConfig::new(pid("A")));
    a.add_direct_neighbor(&pid("B"));
    a.apply_advertisement(&RouteAdvertisement {
        origin: pid("B"),
        routes: vec![AdvertisedRoute {
            destination: pid("C"),
            metric: 1,
        }],
    });

    let advert = a.build_advertisement();
    let json = serde_json::to_string(&advert).expect("advert serializes");
    let parsed: RouteAdvertisement = serde_json::from_str(&json).expect("advert parses");
    assert_eq!(advert, parsed);
    assert_eq!(parsed.origin, pid("A"));
    // Two routes: B (direct, metric=1) and C (via B, metric=2).
    assert_eq!(parsed.routes.len(), 2);
}
