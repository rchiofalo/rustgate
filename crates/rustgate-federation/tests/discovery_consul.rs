// Copyright © 2026 Roberto Chiofalo.

//! Integration test for the Consul peer-discovery backend's response handling
//! (#1619): a normal catalog response round-trips through the size-capped,
//! chunk-streamed body reader into a peer set, confirming the body-cap refactor
//! did not regress the happy path.

#![cfg(feature = "peer-discovery-consul")]
#![allow(clippy::panic, clippy::unwrap_used)]

use rustgate_federation::discovery::PeerDiscovery;
use rustgate_federation::discovery::consul::ConsulDiscovery;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn consul_discover_returns_peers_from_catalog() {
    let server = MockServer::start().await;
    // A normal Consul catalog response: one entry with an explicit
    // ServiceAddress, one that falls back to the node Address.
    let body = serde_json::json!([
        {"ServiceID": "rustgate-1", "ServiceAddress": "10.0.0.5", "ServicePort": 9000, "Address": "node-a"},
        {"ServiceID": "rustgate-2", "ServicePort": 9001, "Address": "node-b"}
    ]);
    Mock::given(method("GET"))
        .and(path("/v1/catalog/service/rustgate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&server)
        .await;

    let disco = ConsulDiscovery::new(server.uri(), "rustgate").expect("build discovery");
    let peers = disco.discover().await.expect("discover should succeed");
    assert_eq!(peers.len(), 2, "both catalog entries become peers");
}
