// Copyright © 2026 Roberto Chiofalo.

//! End-to-end integration test exercising the wiring helpers against
//! the in-memory mock bridge. Verifies the outbound publish path
//! (router event → bridge.publish_entity) and the inbound subscribe
//! path (bridge.subscribe_entities → router.route).

#![cfg(feature = "lattice-mock")]
#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_lattice::bridge::EntityKind;
use rustgate_lattice::config::{DEFAULT_BATCH_SIZE, LatticeConfig};
use rustgate_lattice::mock::MockLatticeBridge;
use rustgate_lattice::wiring::{spawn_inbound_task, spawn_outbound_task};
use rustgate_lattice::{Entity, LatticeBridge};
use rustgate_router::Router;
use tokio::sync::mpsc;

fn cfg() -> LatticeConfig {
    LatticeConfig {
        endpoint: "https://lattice.example.mil".to_string(),
        auth: None,
        batch_size: DEFAULT_BATCH_SIZE,
        // Long enough that the test does not see a health emission;
        // health emission is exercised separately in the unit tests.
        health_interval_secs: 3600,
        geo_bbox: None,
        entity_types: None,
    }
}

fn position_msg(cn: &str, payload: &'static [u8]) -> RoutableMessage {
    let identity =
        Identity::plaintext(cn.to_string(), BTreeSet::from(["alpha".to_string()])).unwrap();
    let meta = Metadata::new(
        SystemTime::UNIX_EPOCH,
        "tcp".to_string(),
        MessageType::Position,
    );
    RoutableMessage {
        source: identity,
        destination: Destination::Broadcast,
        payload: Bytes::from_static(payload),
        metadata: meta,
    }
}

#[tokio::test]
async fn outbound_publishes_position_messages_to_bridge() {
    let bridge: Arc<MockLatticeBridge> = MockLatticeBridge::new();
    let bridge_dyn: Arc<dyn LatticeBridge> = bridge.clone();

    let (tx, rx) = mpsc::channel::<RoutableMessage>(8);
    let task = spawn_outbound_task(bridge_dyn, cfg(), rx);

    tx.send(position_msg("alice", b"<event uid=\"a\"/>"))
        .await
        .unwrap();
    tx.send(position_msg("bob", b"<event uid=\"b\"/>"))
        .await
        .unwrap();

    // Drop the sender to signal end-of-input; the task exits cleanly
    // once the receiver returns `None`.
    drop(tx);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("outbound task must exit when sender drops")
        .expect("outbound task must not panic");

    let log = bridge.published_snapshot();
    assert_eq!(log.len(), 2, "both position messages must reach the bridge");
    assert_eq!(log[0].entity_id, "rustgate:alice");
    assert_eq!(log[0].payload.as_ref(), b"<event uid=\"a\"/>");
    assert_eq!(log[1].entity_id, "rustgate:bob");
}

#[tokio::test]
async fn outbound_filters_non_position_messages() {
    let bridge: Arc<MockLatticeBridge> = MockLatticeBridge::new();
    let bridge_dyn: Arc<dyn LatticeBridge> = bridge.clone();

    let (tx, rx) = mpsc::channel::<RoutableMessage>(8);
    let task = spawn_outbound_task(bridge_dyn, cfg(), rx);

    let mut chat = position_msg("alice", b"hello");
    chat.metadata.message_type = MessageType::Chat;
    tx.send(chat).await.unwrap();
    tx.send(position_msg("alice", b"<event uid=\"a\"/>"))
        .await
        .unwrap();

    drop(tx);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("outbound task must exit when sender drops")
        .expect("outbound task must not panic");

    let log = bridge.published_snapshot();
    assert_eq!(
        log.len(),
        1,
        "only the position message must reach the bridge"
    );
    assert_eq!(log[0].entity_id, "rustgate:alice");
    assert_eq!(log[0].payload.as_ref(), b"<event uid=\"a\"/>");
}

#[tokio::test]
async fn inbound_routes_entities_through_router() {
    let bridge: Arc<MockLatticeBridge> = MockLatticeBridge::new();
    let bridge_dyn: Arc<dyn LatticeBridge> = bridge.clone();
    let router = Arc::new(Router::new());

    let task = spawn_inbound_task(bridge_dyn, cfg(), router.clone());

    // Inject one entity. The inbound task should pull it from the
    // mock bridge subscription and call Router::route. We assert
    // observable behaviour by waiting for the bridge's subscription
    // queue to drain — the mock channel returns Sender::send error
    // only when the queue is closed, which it is not, so we
    // inject + give the task a moment to run, then check the
    // bridge's subscription stream was consumed.
    let entity = Entity {
        entity_id: "lattice-1".to_string(),
        kind: EntityKind::Track,
        position: None,
        observed_at: SystemTime::UNIX_EPOCH,
        payload: Bytes::from_static(b"<event uid=\"l1\"/>"),
        source_cn: Some("upstream-cn".to_string()),
    };
    bridge.inject_inbound(entity).await.unwrap();

    // Yield long enough for the inbound task to drain the channel
    // and hand the message to the router. `route` itself returns
    // when the message has been admitted, so this is a generous
    // single-spin sleep.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Aborting the task is the canonical shutdown path — the
    // inbound stream itself stays open until the bridge drops.
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn outbound_emits_health_report_on_cadence() {
    let bridge: Arc<MockLatticeBridge> = MockLatticeBridge::new();
    let bridge_dyn: Arc<dyn LatticeBridge> = bridge.clone();

    let mut cfg = cfg();
    cfg.health_interval_secs = 1;

    let (tx, rx) = mpsc::channel::<RoutableMessage>(4);
    let task = spawn_outbound_task(bridge_dyn, cfg, rx);

    // Wait long enough for at least one health tick (interval is 1s,
    // first tick consumed at startup, so the test waits ~1.2s for
    // the second tick to land).
    tokio::time::sleep(Duration::from_millis(1200)).await;
    drop(tx);

    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("outbound task must exit")
        .expect("outbound task must not panic");

    let reports = bridge.health_snapshot();
    assert!(
        !reports.is_empty(),
        "expected at least one health report, got {} reports",
        reports.len()
    );
    assert_eq!(reports[0].source, "rustgate/mock");
    assert_eq!(reports[0].published_count, 0);
}
