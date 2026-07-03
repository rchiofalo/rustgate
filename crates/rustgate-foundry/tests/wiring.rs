// Copyright © 2026 Roberto Chiofalo.

//! End-to-end wiring tests against `MockFoundryBridge`.
//!
//! These tests exercise the full outbound and inbound paths through
//! the wiring module without spinning up a Router — the mock is the
//! only stateful piece. The Router-driven path requires #847 step 2
//! (attach Entity to RoutableMessage) to be in flight; the wiring
//! exposes a `dispatch_entity` test hook that lets the integration
//! test cover the same machinery in the meantime. When the attach
//! lands, this test grows a Router and the dispatch hook becomes
//! redundant.

#![cfg(feature = "foundry-mock")]
#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use rustgate_core::entity::{Entity, EntityKind, Position, Velocity};
use rustgate_foundry::bridge::{ChangeType, FoundryBridge, ObjectId};
use rustgate_foundry::config::{FoundryConfig, ObjectTypeMapping, PropertyMap};
use rustgate_foundry::mock::MockFoundryBridge;
use rustgate_foundry::wiring::testing;

fn config() -> FoundryConfig {
    FoundryConfig {
        endpoint: "https://foundry.example.com".into(),
        auth_token_path: "/secrets/foundry-token".into(),
        object_types: vec![ObjectTypeMapping {
            entity_type: "ground".into(),
            foundry_type: "mil-track-dismount".into(),
            property_map: vec![
                PropertyMap {
                    entity: "uid".into(),
                    foundry: "rustgate.uid".into(),
                },
                PropertyMap {
                    entity: "callsign".into(),
                    foundry: "callSign".into(),
                },
                PropertyMap {
                    entity: "position.lat".into(),
                    foundry: "latitude".into(),
                },
                PropertyMap {
                    entity: "position.lon".into(),
                    foundry: "longitude".into(),
                },
                PropertyMap {
                    entity: "velocity.speed_m_s".into(),
                    foundry: "speedMps".into(),
                },
            ],
        }],
    }
}

fn ground_entity(uid: &str, callsign: &str, lat: f64, lon: f64, speed: f64) -> Entity {
    Entity {
        uid: uid.into(),
        kind: EntityKind::Ground,
        position: Some(Position {
            lat,
            lon,
            hae_meters: None,
        }),
        velocity: Some(Velocity {
            speed_m_s: speed,
            course_deg: 0.0,
        }),
        timestamp: SystemTime::UNIX_EPOCH,
        callsign: Some(callsign.into()),
        mil_std_2525_sidc: None,
        attributes: BTreeMap::new(),
        taskings: Default::default(),
        files: Default::default(),
    }
}

#[tokio::test]
async fn outbound_round_trip_through_mock_bridge() {
    let bridge: Arc<dyn FoundryBridge> = Arc::new(MockFoundryBridge::new());
    let cfg = config();
    let mappers = testing::build_mapper_table_for_test(&cfg.object_types);
    let mut queue = testing::fresh_queue();

    testing::dispatch_for_test(
        &bridge,
        &mappers,
        &mut queue,
        &ground_entity("GOLF-1", "alpha", 38.5, -77.25, 7.5),
    )
    .await
    .expect("dispatch");

    // Mock should have stored exactly one object under the
    // configured Foundry type with the projected property bag.
    // Downcast for assertion access — Arc<dyn> doesn't expose the
    // mock's helpers directly, so we hold a separate Arc clone.
    let mock = MockFoundryBridge::new();
    let bridge2: Arc<dyn FoundryBridge> = Arc::new(mock.clone());
    let mut queue2 = testing::fresh_queue();
    testing::dispatch_for_test(
        &bridge2,
        &mappers,
        &mut queue2,
        &ground_entity("GOLF-2", "bravo", 41.0, -71.0, 12.0),
    )
    .await
    .expect("dispatch");

    let stored = mock.stored_objects();
    assert_eq!(stored.len(), 1);
    let ((type_id, uid), props) = &stored[0];
    assert_eq!(type_id, "mil-track-dismount");
    assert_eq!(uid, "GOLF-2");
    let obj = props.as_object().unwrap();
    assert_eq!(obj["rustgate.uid"], "GOLF-2");
    assert_eq!(obj["callSign"], "bravo");
    assert_eq!(obj["latitude"].as_f64(), Some(41.0));
    assert_eq!(obj["longitude"].as_f64(), Some(-71.0));
    assert_eq!(obj["speedMps"].as_f64(), Some(12.0));
}

#[tokio::test]
async fn unmapped_entity_type_surfaces_typed_error() {
    let bridge: Arc<dyn FoundryBridge> = Arc::new(MockFoundryBridge::new());
    let cfg = config();
    let mappers = testing::build_mapper_table_for_test(&cfg.object_types);
    let mut queue = testing::fresh_queue();

    let mut entity = ground_entity("X", "y", 0.0, 0.0, 0.0);
    entity.kind = EntityKind::Aircraft; // no mapping configured

    let err = testing::dispatch_for_test(&bridge, &mappers, &mut queue, &entity)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("aircraft"), "got: {msg}");
}

#[tokio::test]
async fn offline_replay_drains_queue_on_reconnect() {
    let mock = MockFoundryBridge::new();
    let bridge: Arc<dyn FoundryBridge> = Arc::new(mock.clone());
    let cfg = config();
    let mappers = testing::build_mapper_table_for_test(&cfg.object_types);
    let mut queue = testing::fresh_queue();

    // Bridge starts offline → queue grows.
    mock.set_offline(true);
    testing::dispatch_for_test(
        &bridge,
        &mappers,
        &mut queue,
        &ground_entity("Q1", "one", 1.0, 1.0, 1.0),
    )
    .await
    .expect("dispatch (offline path returns Ok after queueing)");
    testing::dispatch_for_test(
        &bridge,
        &mappers,
        &mut queue,
        &ground_entity("Q2", "two", 2.0, 2.0, 2.0),
    )
    .await
    .expect("dispatch");
    assert_eq!(testing::queue_depth(&queue), 2);
    assert_eq!(mock.stored_count(), 0);

    // Bridge reconnects → next dispatch drains the queue head-to-
    // tail before returning. The freshly-dispatched message lands
    // on top.
    mock.set_offline(false);
    testing::dispatch_for_test(
        &bridge,
        &mappers,
        &mut queue,
        &ground_entity("Q3", "three", 3.0, 3.0, 3.0),
    )
    .await
    .expect("dispatch");

    assert_eq!(testing::queue_depth(&queue), 0);
    assert_eq!(mock.stored_count(), 3);
}

#[tokio::test]
async fn last_writer_wins_collapses_duplicate_uid_in_queue() {
    let mock = MockFoundryBridge::new();
    let bridge: Arc<dyn FoundryBridge> = Arc::new(mock.clone());
    let cfg = config();
    let mappers = testing::build_mapper_table_for_test(&cfg.object_types);
    let mut queue = testing::fresh_queue();

    mock.set_offline(true);
    testing::dispatch_for_test(
        &bridge,
        &mappers,
        &mut queue,
        &ground_entity("SAME", "v1", 1.0, 1.0, 1.0),
    )
    .await
    .unwrap();
    testing::dispatch_for_test(
        &bridge,
        &mappers,
        &mut queue,
        &ground_entity("SAME", "v2", 2.0, 2.0, 2.0),
    )
    .await
    .unwrap();
    testing::dispatch_for_test(
        &bridge,
        &mappers,
        &mut queue,
        &ground_entity("SAME", "v3", 3.0, 3.0, 3.0),
    )
    .await
    .unwrap();

    assert_eq!(testing::queue_depth(&queue), 1);
    let keys = testing::queue_keys(&queue);
    assert_eq!(keys, vec![("mil-track-dismount".into(), "SAME".into())]);

    mock.set_offline(false);
    testing::dispatch_for_test(
        &bridge,
        &mappers,
        &mut queue,
        &ground_entity("OTHER", "x", 0.0, 0.0, 0.0),
    )
    .await
    .unwrap();
    assert_eq!(testing::queue_depth(&queue), 0);
    let stored = mock.stored_objects();
    let same = stored
        .iter()
        .find(|((_, uid), _)| uid == "SAME")
        .expect("SAME persisted");
    assert_eq!(same.1["callSign"], "v3");
}

#[tokio::test]
async fn inbound_change_stream_reaches_subscribers() {
    let bridge: Arc<dyn FoundryBridge> = Arc::new(MockFoundryBridge::new());

    // Subscribe BEFORE injecting so the broadcast channel has a live
    // receiver — broadcast::Sender drops messages with no listeners.
    let mut stream = bridge
        .subscribe_changes("mil-track-dismount")
        .await
        .unwrap();
    let _ = bridge
        .upsert_object(
            "mil-track-dismount",
            serde_json::json!({"rustgate.uid": "X", "callSign": "x"}),
        )
        .await
        .unwrap();
    let evt = futures::StreamExt::next(&mut stream).await.expect("change");
    assert_eq!(evt.type_id, "mil-track-dismount");
    assert_eq!(evt.object_id, ObjectId("X".into()));
    assert_eq!(evt.change_type, ChangeType::Created);
}

// ── #1540 attached-entity outbound path (ADR 0035) ──────────────────

fn message_with_entity(entity: Option<Entity>) -> rustgate_core::message::RoutableMessage {
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    let msg = RoutableMessage {
        source: Identity::plaintext("foundry-test".into(), Default::default())
            .expect("plaintext identity"),
        destination: Destination::Broadcast,
        payload: bytes::Bytes::from_static(b"<event/>"),
        metadata: Metadata::new(SystemTime::now(), "cot".into(), MessageType::Position),
        entity: None,
    };
    match entity {
        Some(e) => msg.with_entity(e),
        None => msg,
    }
}

#[tokio::test]
async fn handle_outbound_dispatches_attached_entity_to_bridge() {
    // #1540: when the envelope carries an attached Entity, the outbound
    // handler must project + upsert it through the bridge — the same
    // observable effect as `dispatch_entity`.
    let mock = MockFoundryBridge::new();
    let bridge: Arc<dyn FoundryBridge> = Arc::new(mock.clone());
    let cfg = config();
    let mappers = testing::build_mapper_table_for_test(&cfg.object_types);
    let mut queue = testing::fresh_queue();

    let msg = message_with_entity(Some(ground_entity("DELTA-1", "delta", 10.0, 20.0, 3.0)));
    testing::handle_outbound_for_test(&bridge, &mappers, &mut queue, msg).await;

    let stored = mock.stored_objects();
    assert_eq!(stored.len(), 1, "attached entity must produce one upsert");
    let ((type_id, uid), props) = &stored[0];
    assert_eq!(type_id, "mil-track-dismount");
    assert_eq!(uid, "DELTA-1");
    assert_eq!(props.as_object().unwrap()["callSign"], "delta");
}

#[tokio::test]
async fn handle_outbound_without_entity_is_a_noop_scaffold() {
    // Control: with no attached entity — the shape at every router
    // ingress today — the handler drops the message without upserting.
    let mock = MockFoundryBridge::new();
    let bridge: Arc<dyn FoundryBridge> = Arc::new(mock.clone());
    let cfg = config();
    let mappers = testing::build_mapper_table_for_test(&cfg.object_types);
    let mut queue = testing::fresh_queue();

    testing::handle_outbound_for_test(&bridge, &mappers, &mut queue, message_with_entity(None))
        .await;

    assert!(
        mock.stored_objects().is_empty(),
        "a message with no attached entity must not upsert (deliberate scaffold)"
    );
    assert_eq!(testing::queue_depth(&queue), 0);
}
