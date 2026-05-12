// Copyright © 2026 Roberto Chiofalo.

//! End-to-end wiring tests against `MockDdsBridge`.
//!
//! These tests exercise the full outbound and inbound paths through
//! the wiring module without spinning up a Router — the mock is the
//! only stateful piece. The Router-driven path requires #847 step 2
//! (attach Entity to RoutableMessage) to be in flight; the wiring
//! exposes a `dispatch_entity` test hook that lets the integration
//! test cover the same machinery in the meantime. When the attach
//! lands, this test grows a Router and the dispatch hook becomes
//! redundant.

#![cfg(feature = "dds-mock")]
#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::entity::{Entity, EntityKind, Position, Velocity};
use rustgate_dds::bridge::{DdsBridge, DdsSample, QosProfile};
use rustgate_dds::config::{DdsConfig, PropertyMap, Subscription};
use rustgate_dds::mock::MockDdsBridge;
use rustgate_dds::wiring::testing;

fn config() -> DdsConfig {
    DdsConfig {
        domain_id: 0,
        participant_name: "rustgate".into(),
        subscriptions: vec![Subscription {
            topic: "rustgate.ngva.Navigation".into(),
            entity_kind: "ground".into(),
            qos: QosProfile::TELEMETRY,
            property_map: vec![
                PropertyMap {
                    dds: "uid".into(),
                    entity: "uid".into(),
                },
                PropertyMap {
                    dds: "callsign".into(),
                    entity: "callsign".into(),
                },
                PropertyMap {
                    dds: "lat".into(),
                    entity: "position.lat".into(),
                },
                PropertyMap {
                    dds: "lon".into(),
                    entity: "position.lon".into(),
                },
                PropertyMap {
                    dds: "speed".into(),
                    entity: "velocity.speed_m_s".into(),
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
    let mock = MockDdsBridge::new();
    let bridge: Arc<dyn DdsBridge> = Arc::new(mock.clone());
    let cfg = config();
    let bindings = testing::build_bindings_for_test(&cfg.subscriptions);
    let mut queue = testing::fresh_queue();

    testing::dispatch_for_test(
        &bridge,
        &bindings,
        &mut queue,
        &ground_entity("GOLF-1", "alpha", 38.5, -77.25, 7.5),
    )
    .await
    .expect("dispatch");

    // Mock should have logged exactly one publish on the configured
    // topic with the projected property bag.
    let logged = mock.published("rustgate.ngva.Navigation");
    assert_eq!(logged.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&logged[0].payload).unwrap();
    assert_eq!(body["uid"], "GOLF-1");
    assert_eq!(body["callsign"], "alpha");
    assert_eq!(body["lat"].as_f64(), Some(38.5));
    assert_eq!(body["lon"].as_f64(), Some(-77.25));
    assert_eq!(body["speed"].as_f64(), Some(7.5));
}

#[tokio::test]
async fn unmapped_entity_kind_surfaces_typed_error() {
    let bridge: Arc<dyn DdsBridge> = Arc::new(MockDdsBridge::new());
    let cfg = config();
    let bindings = testing::build_bindings_for_test(&cfg.subscriptions);
    let mut queue = testing::fresh_queue();

    let mut entity = ground_entity("X", "y", 0.0, 0.0, 0.0);
    entity.kind = EntityKind::Aircraft; // no binding configured

    let err = testing::dispatch_for_test(&bridge, &bindings, &mut queue, &entity)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("aircraft"), "got: {msg}");
}

#[tokio::test]
async fn offline_replay_drains_queue_on_reconnect() {
    let mock = MockDdsBridge::new();
    let bridge: Arc<dyn DdsBridge> = Arc::new(mock.clone());
    let cfg = config();
    let bindings = testing::build_bindings_for_test(&cfg.subscriptions);
    let mut queue = testing::fresh_queue();

    // Bridge starts unavailable → queue grows.
    mock.set_unavailable(true);
    testing::dispatch_for_test(
        &bridge,
        &bindings,
        &mut queue,
        &ground_entity("Q1", "one", 1.0, 1.0, 1.0),
    )
    .await
    .expect("dispatch (unavailable path returns Ok after queueing)");
    testing::dispatch_for_test(
        &bridge,
        &bindings,
        &mut queue,
        &ground_entity("Q2", "two", 2.0, 2.0, 2.0),
    )
    .await
    .expect("dispatch");
    assert_eq!(testing::queue_depth(&queue), 2);
    assert_eq!(mock.published_count(), 0);

    // Bridge reconnects → next dispatch drains the queue head-to-
    // tail before returning. The freshly-dispatched message lands
    // on top.
    mock.set_unavailable(false);
    testing::dispatch_for_test(
        &bridge,
        &bindings,
        &mut queue,
        &ground_entity("Q3", "three", 3.0, 3.0, 3.0),
    )
    .await
    .expect("dispatch");

    assert_eq!(testing::queue_depth(&queue), 0);
    assert_eq!(mock.published_count(), 3);
}

#[tokio::test]
async fn last_writer_wins_collapses_duplicate_uid_in_queue() {
    let mock = MockDdsBridge::new();
    let bridge: Arc<dyn DdsBridge> = Arc::new(mock.clone());
    let cfg = config();
    let bindings = testing::build_bindings_for_test(&cfg.subscriptions);
    let mut queue = testing::fresh_queue();

    mock.set_unavailable(true);
    testing::dispatch_for_test(
        &bridge,
        &bindings,
        &mut queue,
        &ground_entity("SAME", "v1", 1.0, 1.0, 1.0),
    )
    .await
    .unwrap();
    testing::dispatch_for_test(
        &bridge,
        &bindings,
        &mut queue,
        &ground_entity("SAME", "v2", 2.0, 2.0, 2.0),
    )
    .await
    .unwrap();
    testing::dispatch_for_test(
        &bridge,
        &bindings,
        &mut queue,
        &ground_entity("SAME", "v3", 3.0, 3.0, 3.0),
    )
    .await
    .unwrap();

    assert_eq!(testing::queue_depth(&queue), 1);
    let keys = testing::queue_keys(&queue);
    assert_eq!(
        keys,
        vec![("rustgate.ngva.Navigation".into(), "SAME".into())]
    );

    mock.set_unavailable(false);
    testing::dispatch_for_test(
        &bridge,
        &bindings,
        &mut queue,
        &ground_entity("OTHER", "x", 0.0, 0.0, 0.0),
    )
    .await
    .unwrap();
    assert_eq!(testing::queue_depth(&queue), 0);

    // Last value to enqueue under uid=SAME was v3; it should be
    // the one persisted on the mock.
    let logged = mock.published("rustgate.ngva.Navigation");
    let same = logged
        .iter()
        .filter_map(|s| serde_json::from_slice::<serde_json::Value>(&s.payload).ok())
        .find(|body| body["uid"] == "SAME")
        .expect("SAME persisted");
    assert_eq!(same["callsign"], "v3");
}

#[tokio::test]
async fn shutdown_blocks_subsequent_publishes_via_offline_path() {
    // Once a bridge is shut down, subsequent publishes surface as
    // ParticipantUnavailable and the offline queue absorbs them.
    let mock = MockDdsBridge::new();
    let bridge: Arc<dyn DdsBridge> = Arc::new(mock.clone());
    mock.shutdown().await.unwrap();

    let cfg = config();
    let bindings = testing::build_bindings_for_test(&cfg.subscriptions);
    let mut queue = testing::fresh_queue();

    testing::dispatch_for_test(
        &bridge,
        &bindings,
        &mut queue,
        &ground_entity("post-shutdown", "x", 0.0, 0.0, 0.0),
    )
    .await
    .expect("dispatch returns Ok after queueing");

    assert_eq!(testing::queue_depth(&queue), 1);
    assert_eq!(mock.published_count(), 0);
}

#[tokio::test]
async fn inbound_subscription_observes_published_samples() {
    let mock = MockDdsBridge::new();
    let bridge: Arc<dyn DdsBridge> = Arc::new(mock.clone());

    // Subscribe BEFORE injecting so the broadcast channel has a live
    // receiver — broadcast::Sender drops messages with no listeners.
    let mut stream = bridge
        .subscribe_topic("rustgate.ngva.Navigation", QosProfile::TELEMETRY)
        .await
        .unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({
        "uid": "INBOUND-1",
        "callsign": "bravo",
        "lat": 41.0,
        "lon": -71.5
    }))
    .unwrap();
    bridge
        .publish_sample(
            "rustgate.ngva.Navigation",
            DdsSample {
                topic: "rustgate.ngva.Navigation".into(),
                source_guid: [7; 16],
                timestamp: SystemTime::UNIX_EPOCH,
                payload: Bytes::from(payload),
            },
        )
        .await
        .unwrap();
    let evt = futures::StreamExt::next(&mut stream).await.expect("sample");
    assert_eq!(evt.topic, "rustgate.ngva.Navigation");
    let body: serde_json::Value = serde_json::from_slice(&evt.payload).unwrap();
    assert_eq!(body["uid"], "INBOUND-1");
}

#[tokio::test]
async fn guid_to_hex_renders_canonical_lowercase() {
    let guid = [
        0xfa, 0xce, 0xfe, 0xed, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    assert_eq!(
        testing::guid_to_hex_for_test(&guid),
        "facefeed000000000000000000000001"
    );
}
