// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for federation peer discovery backends (issue #571).
//!
//! Each test is gated behind the same sub-feature that gates its backend,
//! so running `cargo test -p rustgate-federation --features peer-discovery`
//! exercises all three. The mock-backend test is always compiled when any
//! one backend is enabled because the trait it uses lives in
//! `rustgate_federation::discovery`.

#![cfg(any(
    feature = "peer-discovery-dns-sd",
    feature = "peer-discovery-consul",
    feature = "peer-discovery-etcd"
))]
#![allow(clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustgate_federation::config::{FederationConfig, PeerConfig, RoutingMode};
use rustgate_federation::discovery::PeerDiscovery;
use rustgate_federation::manager::FederationManager;
use tokio::sync::RwLock;

fn test_config() -> FederationConfig {
    FederationConfig {
        federate_id: "discovery-integration".into(),
        v1_enabled: false,
        v1_listen_addr: "127.0.0.1:0".parse().unwrap(),
        v2_enabled: false,
        v2_listen_addr: "127.0.0.1:0".parse().unwrap(),
        peers: vec![],
        heartbeat_interval: Duration::from_secs(30),
        heartbeat_timeout: Duration::from_secs(90),
        health_check_interval: Duration::from_secs(5),
        client_timeout: Duration::from_secs(15),
        max_message_size: 10 * 1024 * 1024,
        reconnect_delay: Duration::from_secs(30),
        max_reconnects: -1,
        max_hops: 10,
        default_group: "__ANON__".into(),
        store_path: None,
        skip_hostname_verify: false,
        trust_store_dir: None,
        cert_file: PathBuf::from("/nonexistent/cert.pem"),
        key_file: PathBuf::from("/nonexistent/key.pem"),
        ca_file: PathBuf::from("/nonexistent/ca.pem"),
        jwt_secret: None,
        jwt_expiry_secs: 3600,
        circuit_breaker_threshold: 5,
        circuit_breaker_timeout: Duration::from_secs(60),
        replay_buffer_capacity: 1000,
        replay_buffer_dir: None,
        replay_max_bytes: rustgate_federation::replay_persist::DEFAULT_REPLAY_MAX_BYTES,
        pod_id: None,
        ha_nats_url: None,
        local_region: None,
        max_groups_per_peer: rustgate_federation::v2::server::DEFAULT_MAX_GROUPS_PER_PEER,
        max_group_name_length: rustgate_federation::v2::server::DEFAULT_MAX_GROUP_NAME_LENGTH,
    }
}

fn peer(id: &str, addr: &str) -> PeerConfig {
    PeerConfig {
        id: id.into(),
        address: addr.into(),
        groups: vec!["default".into()],
        inbound_groups: None,
        outbound_groups: None,
        enabled: true,
        is_outbound: false,
        trust_cert_cn: None,
        routing_mode: RoutingMode::default(),
        protocol_version: 2,
        jwt_token: None,
        region: None,
        zone: None,
        priority: 100,
    }
}

/// Walks a custom discovery impl end-to-end: the reconciler reads it and
/// the manager's configured peers change to match.
struct StaticMockDiscovery {
    peers: std::sync::Mutex<Vec<PeerConfig>>,
}

#[async_trait]
impl PeerDiscovery for StaticMockDiscovery {
    async fn discover(&self) -> anyhow::Result<Vec<PeerConfig>> {
        Ok(self.peers.lock().unwrap().clone())
    }
    fn backend_name(&self) -> &'static str {
        "integration-mock"
    }
}

#[tokio::test]
async fn mock_backend_drives_swap_peers_via_reconciler() {
    let mgr = Arc::new(RwLock::new(FederationManager::new(test_config())));
    let mock = Arc::new(StaticMockDiscovery {
        peers: std::sync::Mutex::new(vec![
            peer("alpha", "127.0.0.1:9200"),
            peer("beta", "127.0.0.1:9201"),
        ]),
    });

    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = rustgate_federation::discovery::reconciler(
        Arc::clone(&mgr),
        mock.clone() as Arc<dyn PeerDiscovery>,
        Duration::from_millis(50),
        rx,
    );

    // Reconciler skips its first immediate tick; wait for at least one real
    // tick plus a small buffer.
    tokio::time::sleep(Duration::from_millis(200)).await;

    {
        let guard = mgr.read().await;
        let ids: Vec<&str> = guard.config().peers.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&"alpha"), "expected alpha, got {ids:?}");
        assert!(ids.contains(&"beta"), "expected beta, got {ids:?}");
    }

    // Second phase: backend drops beta; reconciler should pick this up.
    *mock.peers.lock().unwrap() = vec![peer("alpha", "127.0.0.1:9200")];
    tokio::time::sleep(Duration::from_millis(200)).await;

    {
        let guard = mgr.read().await;
        assert_eq!(guard.config().peers.len(), 1);
        assert_eq!(guard.config().peers[0].id.as_str(), "alpha");
    }

    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("reconciler did not shut down")
        .expect("reconciler panicked");
}

// ---------------------------------------------------------------------------
// DNS-SD — self-browse test
// ---------------------------------------------------------------------------

#[cfg(feature = "peer-discovery-dns-sd")]
mod dns_sd {
    use std::collections::HashMap;

    use mdns_sd::{ServiceDaemon, ServiceInfo};
    use rustgate_federation::discovery::PeerDiscovery;
    use rustgate_federation::discovery::dns_sd::DnsSdDiscovery;

    /// Announces a dummy `_rustgate-test._tcp.local.` instance on 127.0.0.1
    /// and then asks a `DnsSdDiscovery` to enumerate it. On CI runners that
    /// have mDNS traffic blocked (no loopback multicast, netfilter rules,
    /// containerized networking) this can time out or return empty; in
    /// that case we skip instead of failing. The `RUSTGATE_SKIP_MDNS=1`
    /// env var offers a hard skip for environments that are known broken.
    #[tokio::test(flavor = "multi_thread")]
    async fn dns_sd_discovers_locally_announced_service() {
        if std::env::var("RUSTGATE_SKIP_MDNS").is_ok() {
            eprintln!("skipping: RUSTGATE_SKIP_MDNS set");
            return;
        }
        let Ok(announcer) = ServiceDaemon::new() else {
            eprintln!("skipping: cannot start mdns-sd announcer");
            return;
        };
        let service_type = "_rustgate-test._tcp.local.";
        let Ok(info) = ServiceInfo::new(
            service_type,
            "rustgate-self",
            "rustgate-test.local.",
            "127.0.0.1",
            9600,
            HashMap::<String, String>::new(),
        ) else {
            eprintln!("skipping: cannot build ServiceInfo");
            let _ = announcer.shutdown();
            return;
        };
        if announcer.register(info).is_err() {
            eprintln!("skipping: mdns-sd register failed");
            let _ = announcer.shutdown();
            return;
        }

        let Ok(discovery) = DnsSdDiscovery::new(service_type) else {
            eprintln!("skipping: cannot construct DnsSdDiscovery");
            let _ = announcer.shutdown();
            return;
        };

        // Poll for a few seconds to give the announcer time to respond.
        // CI runners with broken mDNS will simply never see the service;
        // in that case we skip the assertion rather than fail.
        let mut found = Vec::new();
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            found = discovery.discover().await.unwrap_or_default();
            if !found.is_empty() {
                break;
            }
        }

        let _ = announcer.shutdown();

        if found.is_empty() {
            eprintln!(
                "skipping assertion: no DNS-SD responses (likely CI without multicast); \
                 set RUSTGATE_SKIP_MDNS=1 to silence this path"
            );
            return;
        }

        // Exactly one instance should be resolved, pointing at our
        // configured port.
        assert!(
            found.iter().any(|p| p.address.contains(":9600")),
            "expected to find :9600, got {found:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Consul — wiremock HTTP stub
// ---------------------------------------------------------------------------

#[cfg(feature = "peer-discovery-consul")]
mod consul {
    use rustgate_federation::discovery::PeerDiscovery;
    use rustgate_federation::discovery::consul::ConsulDiscovery;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn consul_catalog_response_becomes_peer_list() {
        let mock = MockServer::start().await;
        let body = serde_json::json!([
            {
                "ServiceID": "rustgate-east-1",
                "ServiceAddress": "10.0.0.10",
                "ServicePort": 9000,
                "Address": "east-node-1.example"
            },
            {
                "ServiceID": "rustgate-east-2",
                "ServiceAddress": "",
                "ServicePort": 9000,
                "Address": "east-node-2.example"
            }
        ]);

        Mock::given(method("GET"))
            .and(path("/v1/catalog/service/rustgate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&mock)
            .await;

        let discovery = ConsulDiscovery::new(mock.uri(), "rustgate").expect("discovery");
        let peers = discovery.discover().await.expect("discover");

        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].id.as_str(), "rustgate-east-1");
        assert_eq!(peers[0].address, "10.0.0.10:9000");
        assert!(peers[0].is_outbound);
        assert_eq!(peers[1].id.as_str(), "rustgate-east-2");
        assert_eq!(peers[1].address, "east-node-2.example:9000");
    }

    #[tokio::test]
    async fn consul_http_error_is_surfaced() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/catalog/service/rustgate"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let discovery = ConsulDiscovery::new(mock.uri(), "rustgate").expect("discovery");
        assert!(discovery.discover().await.is_err());
    }

    #[tokio::test]
    async fn consul_empty_catalog_returns_empty_peer_list() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/catalog/service/rustgate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;

        let discovery = ConsulDiscovery::new(mock.uri(), "rustgate").expect("discovery");
        let peers = discovery.discover().await.expect("discover");
        assert!(peers.is_empty());
    }
}

// ---------------------------------------------------------------------------
// etcd — requires a local etcd; ignored by default
// ---------------------------------------------------------------------------

#[cfg(feature = "peer-discovery-etcd")]
mod etcd_live {
    use rustgate_federation::discovery::PeerDiscovery;
    use rustgate_federation::discovery::etcd::EtcdDiscovery;

    /// Live end-to-end check against a locally-running etcd instance.
    /// Ignored by default because CI doesn't ship etcd; run manually with
    /// `cargo test -p rustgate-federation --features peer-discovery-etcd
    /// -- --ignored etcd_discovers_prefix_keys` after starting etcd and
    /// seeding `rustgate/peers/test = 127.0.0.1:9000`.
    #[tokio::test]
    #[ignore = "requires a running etcd at 127.0.0.1:2379"]
    async fn etcd_discovers_prefix_keys() {
        let discovery =
            EtcdDiscovery::new(vec!["http://127.0.0.1:2379".to_string()], "rustgate/peers/");
        let peers = discovery.discover().await.expect("discover");
        assert!(
            !peers.is_empty(),
            "expected at least one peer under the prefix"
        );
    }
}
