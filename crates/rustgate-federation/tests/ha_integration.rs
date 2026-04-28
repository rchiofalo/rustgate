// Copyright © 2026 Roberto Chiofalo.

//! HA subsystem integration tests.
//!
//! These tests require a real `nats-server` binary with JetStream support
//! in `$PATH`. If `nats-server` is not found, all tests are skipped gracefully.
//! Feature-gated on `ha` to match the crate feature.

#![cfg(feature = "ha")]
#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use rustgate_core::PeerId;
use rustgate_federation::ha::claims::ClaimManager;
use rustgate_federation::ha::registry::{ConnectionRegistry, Direction};
use rustgate_test_utils::require_nats;

/// F-113: helper that constructs a typed [`PeerId`] for HA tests so the
/// integration suite can keep its compact `"peer-N"` string-literal
/// style while the underlying API now requires the typed wrapper.
fn pid(s: &str) -> PeerId {
    PeerId::new(s)
}

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

    // Pod A claims peer-1 first — returns fencing token
    let token = cm_a.try_claim(&pid("peer-1")).await;
    assert!(token.is_some(), "pod-a should claim peer-1");
    assert!(token.unwrap() > 0, "fencing token should be positive");
    assert!(
        cm_a.is_owner(&pid("peer-1")).await,
        "pod-a should own peer-1"
    );

    // Pod B should fail to claim the same peer
    assert!(
        cm_b.try_claim(&pid("peer-1")).await.is_none(),
        "pod-b should NOT claim peer-1 (already claimed by pod-a)"
    );
    assert!(
        !cm_b.is_owner(&pid("peer-1")).await,
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
    assert!(cm_a.try_claim(&pid("peer-1")).await.is_some());
    cm_a.release(&pid("peer-1")).await.expect("release");
    assert!(!cm_a.is_owner(&pid("peer-1")).await);

    // Pod B should now be able to claim it
    assert!(
        cm_b.try_claim(&pid("peer-1")).await.is_some(),
        "pod-b should claim peer-1 after release"
    );
    assert!(cm_b.is_owner(&pid("peer-1")).await);

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
    assert!(cm_a.try_claim(&pid("peer-1")).await.is_some());
    assert!(cm_a.try_claim(&pid("peer-2")).await.is_some());
    assert!(cm_a.try_claim(&pid("peer-3")).await.is_some());
    assert_eq!(cm_a.claimed_peers().await.len(), 3);

    // Stop releases all claims
    cm_a.stop().await;

    // New claim manager should be able to claim all 3
    let cm_b = ClaimManager::new(js_b, "pod-b".into())
        .await
        .expect("create cm_b");
    cm_b.start().await;

    assert!(
        cm_b.try_claim(&pid("peer-1")).await.is_some(),
        "peer-1 should be available after pod-a stop"
    );
    assert!(
        cm_b.try_claim(&pid("peer-2")).await.is_some(),
        "peer-2 should be available after pod-a stop"
    );
    assert!(
        cm_b.try_claim(&pid("peer-3")).await.is_some(),
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

    // Deterministic: pod-a claims odd, pod-b claims even.
    // F-113: callers pre-construct typed `PeerId`s so the claim API
    // gets a `&PeerId` from the typed collection.
    let peers: Vec<PeerId> = (1..=6).map(|i| PeerId::new(format!("peer-{i}"))).collect();

    for (i, peer) in peers.iter().enumerate() {
        if i % 2 == 0 {
            assert!(
                cm_a.try_claim(peer).await.is_some(),
                "pod-a should claim {peer}"
            );
        } else {
            assert!(
                cm_b.try_claim(peer).await.is_some(),
                "pod-b should claim {peer}"
            );
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
    assert!(cm_a.try_claim(&pid("peer-1")).await.is_some());

    // Pod B watches for available peers via callback.
    // F-113: callback delivers a typed `PeerId` now.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PeerId>();
    let mut cm_b = ClaimManager::new(js, "pod-b".into())
        .await
        .expect("create cm_b");
    cm_b.set_callbacks(
        Arc::new(move |peer_id| {
            let _ = tx.send(peer_id);
        }),
        Arc::new(|_peer_id, _stale_token| {}),
    );
    cm_b.start().await;

    // Give the watcher time to initialize
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Pod A releases peer-1 — should trigger pod B's on_peer_available callback
    cm_a.release(&pid("peer-1")).await.expect("release peer-1");

    // Wait for the callback (with timeout)
    let available_peer = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for adoption callback")
        .expect("channel closed");

    assert_eq!(available_peer, pid("peer-1"));

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
    cr.register(&pid("peer-1"), Direction::Outbound, Some(1))
        .await
        .expect("register peer-1");
    cr.register(&pid("peer-2"), Direction::Outbound, Some(2))
        .await
        .expect("register peer-2");
    cr.register(&pid("peer-3"), Direction::Inbound, None)
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
    cr.unregister(&pid("peer-2"))
        .await
        .expect("unregister peer-2");
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

    cr_a.register(&pid("peer-1"), Direction::Outbound, Some(1))
        .await
        .expect("register");
    cr_a.register(&pid("peer-2"), Direction::Outbound, Some(2))
        .await
        .expect("register");
    cr_b.register(&pid("peer-3"), Direction::Outbound, Some(3))
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
    let token_1 = cm.try_claim(&pid("peer-1")).await;
    assert!(token_1.is_some());
    cr.register(&pid("peer-1"), Direction::Outbound, token_1)
        .await
        .expect("register");

    let token_2 = cm.try_claim(&pid("peer-2")).await;
    assert!(token_2.is_some());
    cr.register(&pid("peer-2"), Direction::Outbound, token_2)
        .await
        .expect("register");

    // Verify state
    assert_eq!(cm.claimed_peers().await.len(), 2);
    let conns = cr.list_connections().await.expect("list");
    assert_eq!(conns.len(), 2);

    // Simulate disconnect_peer: unregister + release
    cr.unregister(&pid("peer-1")).await.expect("unregister");
    cm.release(&pid("peer-1")).await.expect("release");

    assert_eq!(cm.claimed_peers().await.len(), 1);
    let conns = cr.list_connections().await.expect("list after disconnect");
    assert_eq!(conns.len(), 1);

    // Simulate shutdown: stop both
    cm.stop().await;
    cr.stop().await;
}

// ── Fencing Token tests ────────────────────────────────────────

#[tokio::test]
async fn fencing_token_returned_on_claim() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cm = ClaimManager::new(js, "pod-a".into())
        .await
        .expect("create cm");
    cm.start().await;

    let token = cm.try_claim(&pid("peer-1")).await;
    assert!(token.is_some(), "try_claim should return a fencing token");
    assert!(token.unwrap() > 0, "fencing token should be positive");

    // fencing_token() should return the same value
    let stored = cm.fencing_token(&pid("peer-1")).await;
    assert_eq!(stored, token);

    cm.stop().await;
}

#[tokio::test]
async fn fencing_token_none_for_unclaimed() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cm = ClaimManager::new(js, "pod-a".into())
        .await
        .expect("create cm");
    cm.start().await;

    assert_eq!(
        cm.fencing_token(&pid("unknown-peer")).await,
        None,
        "unclaimed peer should have no fencing token"
    );

    cm.stop().await;
}

#[tokio::test]
async fn is_token_valid_for_current_claim() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cm = ClaimManager::new(js, "pod-a".into())
        .await
        .expect("create cm");
    cm.start().await;

    let token = cm.try_claim(&pid("peer-1")).await.unwrap();
    assert!(
        cm.is_token_valid(&pid("peer-1"), token).await,
        "current token should be valid"
    );

    cm.stop().await;
}

#[tokio::test]
async fn is_token_valid_false_after_release() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cm = ClaimManager::new(js, "pod-a".into())
        .await
        .expect("create cm");
    cm.start().await;

    let token = cm.try_claim(&pid("peer-1")).await.unwrap();
    cm.release(&pid("peer-1")).await.expect("release");

    assert!(
        !cm.is_token_valid(&pid("peer-1"), token).await,
        "released claim token should be invalid"
    );

    cm.stop().await;
}

#[tokio::test]
async fn fencing_token_increases_across_reclaim() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cm = ClaimManager::new(js, "pod-a".into())
        .await
        .expect("create cm");
    cm.start().await;

    let token_1 = cm.try_claim(&pid("peer-1")).await.unwrap();
    cm.release(&pid("peer-1")).await.expect("release");

    // Re-claim should get a higher fencing token
    let token_2 = cm.try_claim(&pid("peer-1")).await.unwrap();
    assert!(
        token_2 > token_1,
        "new fencing token ({token_2}) should be greater than old ({token_1})"
    );

    cm.stop().await;
}

#[tokio::test]
async fn registry_stores_fencing_token() {
    let nats = require_nats!();
    let js = nats.jetstream().await;

    let cr = ConnectionRegistry::new(js, "pod-a".into())
        .await
        .expect("create registry");
    cr.start().await;

    cr.register(&pid("peer-1"), Direction::Outbound, Some(42))
        .await
        .expect("register with token");

    let conns = cr.list_connections().await.expect("list");
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].fencing_token, Some(42));

    // Inbound connection without fencing token
    cr.register(&pid("peer-2"), Direction::Inbound, None)
        .await
        .expect("register inbound");

    let conns = cr.list_connections().await.expect("list");
    let inbound = conns
        .iter()
        .find(|c| c.peer_id.as_str() == "peer-2")
        .unwrap();
    assert_eq!(inbound.fencing_token, None);

    cr.stop().await;
}
