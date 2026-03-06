//! HA subsystem integration tests.
//!
//! These tests require a real `nats-server` binary with JetStream support
//! in `$PATH`. If `nats-server` is not found, all tests are skipped gracefully.
//! Feature-gated on `ha` to match the crate feature.

#![cfg(feature = "ha")]
#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use rustgate_federation::ha::claims::ClaimManager;
use rustgate_federation::ha::registry::{ConnectionRegistry, Direction};
use rustgate_test_utils::require_nats;

// ── Claim Manager tests ─────────────────────────────────────────

#[tokio::test]
async fn claim_gates_peer_connection() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cm_a = ClaimManager::new(js.clone(), "pod-a".into())
        .await
        .expect("create cm_a");
    cm_a.start().await;

    let cm_b = ClaimManager::new(js, "pod-b".into())
        .await
        .expect("create cm_b");
    cm_b.start().await;

    // Pod A claims peer-1 first
    assert!(cm_a.try_claim("peer-1").await, "pod-a should claim peer-1");
    assert!(cm_a.is_owner("peer-1").await, "pod-a should own peer-1");

    // Pod B should fail to claim the same peer
    assert!(
        !cm_b.try_claim("peer-1").await,
        "pod-b should NOT claim peer-1 (already claimed by pod-a)"
    );
    assert!(
        !cm_b.is_owner("peer-1").await,
        "pod-b should NOT own peer-1"
    );

    cm_a.stop().await;
    cm_b.stop().await;
}

#[tokio::test]
async fn claim_release_allows_reclaim() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cm_a = ClaimManager::new(js.clone(), "pod-a".into())
        .await
        .expect("create cm_a");
    cm_a.start().await;

    let cm_b = ClaimManager::new(js, "pod-b".into())
        .await
        .expect("create cm_b");
    cm_b.start().await;

    // Pod A claims and releases
    assert!(cm_a.try_claim("peer-1").await);
    cm_a.release("peer-1").await.expect("release");
    assert!(!cm_a.is_owner("peer-1").await);

    // Pod B should now be able to claim it
    assert!(
        cm_b.try_claim("peer-1").await,
        "pod-b should claim peer-1 after release"
    );
    assert!(cm_b.is_owner("peer-1").await);

    cm_a.stop().await;
    cm_b.stop().await;
}

#[tokio::test]
async fn shutdown_releases_all_claims() {
    let nats = require_nats!();
    let js_a = nats.jetstream().await;
    let js_b = nats.jetstream().await;

    let cm_a = ClaimManager::new(js_a, "pod-a".into())
        .await
        .expect("create cm_a");
    cm_a.start().await;

    // Pod A claims 3 peers
    assert!(cm_a.try_claim("peer-1").await);
    assert!(cm_a.try_claim("peer-2").await);
    assert!(cm_a.try_claim("peer-3").await);
    assert_eq!(cm_a.claimed_peers().await.len(), 3);

    // Stop releases all claims
    cm_a.stop().await;

    // New claim manager should be able to claim all 3
    let cm_b = ClaimManager::new(js_b, "pod-b".into())
        .await
        .expect("create cm_b");
    cm_b.start().await;

    assert!(
        cm_b.try_claim("peer-1").await,
        "peer-1 should be available after pod-a stop"
    );
    assert!(
        cm_b.try_claim("peer-2").await,
        "peer-2 should be available after pod-a stop"
    );
    assert!(
        cm_b.try_claim("peer-3").await,
        "peer-3 should be available after pod-a stop"
    );

    cm_b.stop().await;
}

#[tokio::test]
async fn two_pods_partition_peers() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cm_a = ClaimManager::new(js.clone(), "pod-a".into())
        .await
        .expect("create cm_a");
    cm_a.start().await;

    let cm_b = ClaimManager::new(js, "pod-b".into())
        .await
        .expect("create cm_b");
    cm_b.start().await;

    // Deterministic: pod-a claims odd, pod-b claims even
    let peers: Vec<String> = (1..=6).map(|i| format!("peer-{i}")).collect();

    for (i, peer) in peers.iter().enumerate() {
        if i % 2 == 0 {
            assert!(cm_a.try_claim(peer).await, "pod-a should claim {peer}");
        } else {
            assert!(cm_b.try_claim(peer).await, "pod-b should claim {peer}");
        }
    }

    // Verify partitioning: each peer is claimed by exactly one pod
    let a_peers = cm_a.claimed_peers().await;
    let b_peers = cm_b.claimed_peers().await;

    assert_eq!(a_peers.len(), 3, "pod-a should own 3 peers");
    assert_eq!(b_peers.len(), 3, "pod-b should own 3 peers");

    // No overlap
    for p in &a_peers {
        assert!(!b_peers.contains(p), "peer {p} should not be in both pods");
    }

    // Total = 6
    assert_eq!(a_peers.len() + b_peers.len(), 6);

    cm_a.stop().await;
    cm_b.stop().await;
}

#[tokio::test]
async fn adoption_callback_fires_on_release() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    // Pod A claims peer-1
    let cm_a = ClaimManager::new(js.clone(), "pod-a".into())
        .await
        .expect("create cm_a");
    cm_a.start().await;
    assert!(cm_a.try_claim("peer-1").await);

    // Pod B watches for available peers via callback
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let mut cm_b = ClaimManager::new(js, "pod-b".into())
        .await
        .expect("create cm_b");
    cm_b.set_callbacks(
        Arc::new(move |peer_id| {
            let _ = tx.send(peer_id);
        }),
        Arc::new(|_| {}),
    );
    cm_b.start().await;

    // Give the watcher time to initialize
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Pod A releases peer-1 — should trigger pod B's on_peer_available callback
    cm_a.release("peer-1").await.expect("release peer-1");

    // Wait for the callback (with timeout)
    let available_peer = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for adoption callback")
        .expect("channel closed");

    assert_eq!(available_peer, "peer-1");

    cm_a.stop().await;
    cm_b.stop().await;
}

// NOTE: claim_lost_callback_fires is omitted because the current ClaimManager
// implementation snapshots the claims HashMap at start() time. Claims added
// after start() via try_claim() are written to self.claims but not to the
// refresh loop's local copy, so the refresh loop cannot detect claim-loss
// for dynamically acquired claims. This is a known limitation tracked separately.

// ── Connection Registry tests ───────────────────────────────────

#[tokio::test]
async fn registry_tracks_connections() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cr = ConnectionRegistry::new(js, "pod-a".into())
        .await
        .expect("create registry");
    cr.start().await;

    // Register connections
    cr.register("peer-1", Direction::Outbound)
        .await
        .expect("register peer-1");
    cr.register("peer-2", Direction::Outbound)
        .await
        .expect("register peer-2");
    cr.register("peer-3", Direction::Inbound)
        .await
        .expect("register peer-3");

    // List connections
    let conns = cr.list_connections().await.expect("list connections");
    assert_eq!(
        conns.len(),
        3,
        "expected 3 connections, got {}",
        conns.len()
    );

    let outbound_count = conns
        .iter()
        .filter(|c| c.direction == Direction::Outbound)
        .count();
    let inbound_count = conns
        .iter()
        .filter(|c| c.direction == Direction::Inbound)
        .count();
    assert_eq!(outbound_count, 2);
    assert_eq!(inbound_count, 1);

    // List pods
    let pods = cr.list_pods().await.expect("list pods");
    assert_eq!(pods.len(), 1);
    assert_eq!(pods[0].id, "pod-a");
    assert_eq!(pods[0].connections, 3);

    // Unregister one
    cr.unregister("peer-2").await.expect("unregister peer-2");
    let conns = cr.list_connections().await.expect("list after unregister");
    assert_eq!(conns.len(), 2);

    cr.stop().await;
}

#[tokio::test]
async fn registry_multi_pod() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cr_a = ConnectionRegistry::new(js.clone(), "pod-a".into())
        .await
        .expect("create registry_a");
    cr_a.start().await;

    let cr_b = ConnectionRegistry::new(js, "pod-b".into())
        .await
        .expect("create registry_b");
    cr_b.start().await;

    cr_a.register("peer-1", Direction::Outbound)
        .await
        .expect("register");
    cr_a.register("peer-2", Direction::Outbound)
        .await
        .expect("register");
    cr_b.register("peer-3", Direction::Outbound)
        .await
        .expect("register");

    // Both pods should see all connections
    let conns_a = cr_a.list_connections().await.expect("list_a");
    let conns_b = cr_b.list_connections().await.expect("list_b");
    assert_eq!(conns_a.len(), 3);
    assert_eq!(conns_b.len(), 3);

    // Pod listing
    let pods = cr_a.list_pods().await.expect("list pods");
    assert_eq!(pods.len(), 2);

    let pod_a = pods.iter().find(|p| p.id == "pod-a").expect("find pod-a");
    let pod_b = pods.iter().find(|p| p.id == "pod-b").expect("find pod-b");
    assert_eq!(pod_a.connections, 2);
    assert_eq!(pod_b.connections, 1);

    cr_a.stop().await;
    cr_b.stop().await;
}

// ── Combined Claim + Registry workflow ──────────────────────────

#[tokio::test]
async fn claim_and_register_workflow() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    // Simulate what FederationManager.start() does
    let cm = ClaimManager::new(js.clone(), "pod-a".into())
        .await
        .expect("create cm");
    let cr = ConnectionRegistry::new(js, "pod-a".into())
        .await
        .expect("create cr");
    cm.start().await;
    cr.start().await;

    // Claim + register (like the peer connection loop)
    assert!(cm.try_claim("peer-1").await);
    cr.register("peer-1", Direction::Outbound)
        .await
        .expect("register");

    assert!(cm.try_claim("peer-2").await);
    cr.register("peer-2", Direction::Outbound)
        .await
        .expect("register");

    // Verify state
    assert_eq!(cm.claimed_peers().await.len(), 2);
    let conns = cr.list_connections().await.expect("list");
    assert_eq!(conns.len(), 2);

    // Simulate disconnect_peer: unregister + release
    cr.unregister("peer-1").await.expect("unregister");
    cm.release("peer-1").await.expect("release");

    assert_eq!(cm.claimed_peers().await.len(), 1);
    let conns = cr.list_connections().await.expect("list after disconnect");
    assert_eq!(conns.len(), 1);

    // Simulate shutdown: stop both
    cm.stop().await;
    cr.stop().await;
}
