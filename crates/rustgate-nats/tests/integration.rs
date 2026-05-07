// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the NATS adapter.
//!
//! These tests spin up a real `nats-server` subprocess (with JetStream enabled)
//! and exercise the full publish → subscribe → route pipeline. Each test gets
//! its own server on a random port for isolation.
//!
//! Requires `nats-server` on PATH. Tests are skipped (not failed) if the
//! binary isn't available.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use futures::StreamExt;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_nats::{
    NatsAdapter, NatsConfig, NatsRequestHandler, NatsRequestResponder, RequestError, WireEvent,
};
use rustgate_router::Router;
use rustgate_test_utils::require_nats;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Build a config pointing at the test server with a unique instance ID.
fn test_config(url: &str, instance_id: &str) -> NatsConfig {
    NatsConfig {
        url: url.to_string(),
        instance_id: instance_id.to_string(),
        ..Default::default()
    }
}

/// Build a valid CoT XML position message.
fn cot_position_xml(uid: &str, lat: f64, lon: f64) -> Bytes {
    cot_position_xml_with_error(uid, lat, lon, 50.0, 30.0)
}

/// CoT position XML with explicit circular/linear error fields.
///
/// Use `ce=9_999_999, le=9_999_999` to produce the CoT "position
/// unknown" sentinel; other values represent a valid fix.
fn cot_position_xml_with_error(uid: &str, lat: f64, lon: f64, ce: f64, le: f64) -> Bytes {
    Bytes::from(format!(
        "<event version=\"2.0\" uid=\"{uid}\" type=\"a-f-G-U-C\" \
         time=\"2026-01-01T00:00:00Z\" start=\"2026-01-01T00:00:00Z\" \
         stale=\"2026-01-01T00:05:00Z\" how=\"m-g\">\
         <point lat=\"{lat}\" lon=\"{lon}\" hae=\"0\" ce=\"{ce}\" le=\"{le}\"/>\
         <detail/></event>"
    ))
}

/// Build a RoutableMessage from CoT XML with the given identity.
fn position_message(uid: &str, group: &str, lat: f64, lon: f64) -> RoutableMessage {
    let mut groups = BTreeSet::new();
    let _ = groups.insert(group.to_string());

    RoutableMessage {
        source: Identity::plaintext(uid.to_string(), groups).expect("valid identity"),
        destination: Destination::Broadcast,
        payload: cot_position_xml(uid, lat, lon),
        metadata: Metadata::new(SystemTime::now(), "tak".to_string(), MessageType::Position),
    }
}

/// Register a dummy session on the router and return the receiver.
async fn register_session(
    router: &Router,
    cn: &str,
    group: &str,
) -> mpsc::Receiver<rustgate_router::RoutedMessage> {
    let (ptx, prx) = mpsc::channel(16);
    let (ntx, _nrx) = mpsc::channel(64);
    let mut groups = BTreeSet::new();
    let _ = groups.insert(group.to_string());
    let identity = Arc::new(Identity::plaintext(cn.to_string(), groups).expect("valid identity"));
    let handle = rustgate_router::SessionHandle::new(identity, ptx, ntx);
    let _ = router.register(handle).await;
    // Return priority receiver — NATS-bridged messages are typically
    // positions which route to the priority channel.
    prx
}

/// Like [`register_session`] but returns BOTH the priority and the
/// normal-channel receivers. Tests that exercise Send-PEP obligations
/// which rewrite `metadata.message_type` (e.g. `MaskPayload` →
/// `Other("masked")`) need the normal channel to observe the masked
/// envelope; the standard `register_session` drops it.
async fn register_session_dual(
    router: &Router,
    cn: &str,
    group: &str,
) -> (
    mpsc::Receiver<rustgate_router::RoutedMessage>,
    mpsc::Receiver<rustgate_router::RoutedMessage>,
) {
    let (ptx, prx) = mpsc::channel(16);
    let (ntx, nrx) = mpsc::channel(64);
    let mut groups = BTreeSet::new();
    let _ = groups.insert(group.to_string());
    let identity = Arc::new(Identity::plaintext(cn.to_string(), groups).expect("valid identity"));
    let handle = rustgate_router::SessionHandle::new(identity, ptx, ntx);
    let _ = router.register(handle).await;
    (prx, nrx)
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// Connect to NATS and verify the adapter initializes without error.
#[tokio::test]
async fn connect_and_disconnect() {
    let server = require_nats!();
    let config = test_config(server.url(), "test-connect");
    let _adapter = NatsAdapter::connect(config).await.expect("should connect");
}

/// Publish a position message and verify the subscriber delivers it
/// to a locally registered session via the Router.
#[tokio::test]
async fn publish_subscribe_round_trip() {
    let server = require_nats!();

    // Two adapters simulating two rustgate instances
    let config_a = test_config(server.url(), "instance-A");
    let config_b = test_config(server.url(), "instance-B");

    let adapter_a = NatsAdapter::connect(config_a).await.expect("connect A");
    let adapter_b = NatsAdapter::connect(config_b).await.expect("connect B");

    // Instance B subscribes and routes to a local session
    let router_b = Arc::new(Router::new());
    let mut rx = register_session(&router_b, "local-client", "Cyan").await;

    let subscriber = adapter_b.subscriber();
    let sub_router = Arc::clone(&router_b);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    // Give the subscriber time to connect to NATS
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Instance A publishes a position
    let msg = position_message("track-1", "Cyan", 37.7749, -122.4194);
    adapter_a.publisher().publish(&msg).await;

    // Instance B's local session should receive the message
    let received = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for message")
        .expect("channel closed");

    assert_eq!(&*received.source.cn, "track-1");
    assert_eq!(received.metadata.source_protocol, "nats");
    assert!(received.source.groups.contains("Cyan"));

    sub_task.abort();
}

/// Verify that a publisher does NOT re-publish messages originating from NATS
/// (source_protocol == "nats"), preventing infinite loops.
///
/// Uses a raw NATS subscription to observe the wire directly — bypasses the
/// rustgate subscriber so only the publisher's source_protocol guard is tested.
#[tokio::test]
async fn echo_prevention_source_protocol() {
    let server = require_nats!();

    let config = test_config(server.url(), "echo-proto-test");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    // Raw NATS subscription — no rustgate subscriber, no instance header filtering
    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    let mut raw_sub = raw_client.subscribe("points.>").await.expect("subscribe");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Build a message that looks like it came FROM NATS (should be dropped by publisher)
    let mut msg = position_message("track-echo", "Cyan", 37.0, -122.0);
    msg.metadata.source_protocol = "nats".to_string();

    adapter.publisher().publish(&msg).await;

    // Nothing should appear on the NATS subject — publisher should have dropped it
    let result = timeout(Duration::from_secs(2), raw_sub.next()).await;
    assert!(
        result.is_err(),
        "publisher should not emit nats-sourced messages to NATS"
    );
}

/// Regression for #748: a federated message whose `source_protocol` arrives
/// as `"NATS"` (uppercase) must still be caught by echo prevention. A
/// case-sensitive `==` check would let this slip through and form a
/// publish loop with the federated peer.
#[tokio::test]
async fn echo_prevention_matches_uppercase_source_protocol() {
    let server = require_nats!();

    let config = test_config(server.url(), "echo-upper-test");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    let mut raw_sub = raw_client.subscribe("points.>").await.expect("subscribe");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut msg = position_message("track-upper", "Cyan", 37.0, -122.0);
    msg.metadata.source_protocol = "NATS".to_string();

    adapter.publisher().publish(&msg).await;

    let result = timeout(Duration::from_secs(2), raw_sub.next()).await;
    assert!(
        result.is_err(),
        "publisher should not emit NATS-sourced messages to NATS regardless of case"
    );
}

/// Regression for #748: mixed-case `source_protocol` (e.g. `"Nats"`) must
/// also be caught by echo prevention.
#[tokio::test]
async fn echo_prevention_matches_mixed_case() {
    let server = require_nats!();

    let config = test_config(server.url(), "echo-mixed-test");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    let mut raw_sub = raw_client.subscribe("points.>").await.expect("subscribe");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut msg = position_message("track-mixed", "Cyan", 37.0, -122.0);
    msg.metadata.source_protocol = "Nats".to_string();

    adapter.publisher().publish(&msg).await;

    let result = timeout(Duration::from_secs(2), raw_sub.next()).await;
    assert!(
        result.is_err(),
        "publisher should not emit Nats-sourced messages to NATS regardless of case"
    );
}

/// Regression for #748: the case-insensitive echo guard must not over-match
/// other transports. Messages from MQTT, federation, TCP etc. must still
/// be republished onto NATS — that is the point of the bridge.
#[tokio::test]
async fn echo_prevention_does_not_block_non_nats_sources() {
    let server = require_nats!();

    let config = test_config(server.url(), "echo-foreign-test");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    let mut raw_sub = raw_client.subscribe("points.>").await.expect("subscribe");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // A message whose source_protocol contains "nats" only as a substring
    // (or is something else entirely) must NOT be filtered.
    let mut msg = position_message("track-mqtt", "Cyan", 37.0, -122.0);
    msg.metadata.source_protocol = "mqtt".to_string();

    adapter.publisher().publish(&msg).await;

    let result = timeout(Duration::from_secs(5), raw_sub.next()).await;
    assert!(
        result.is_ok(),
        "publisher must republish messages from non-NATS transports to NATS"
    );
}

/// Verify that a subscriber ignores messages published by its own instance
/// (X-Rustgate-Instance header echo prevention).
#[tokio::test]
async fn echo_prevention_instance_header() {
    let server = require_nats!();

    // Same instance ID for both publisher and subscriber
    let config = test_config(server.url(), "same-instance");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    let router = Arc::new(Router::new());
    let mut rx = register_session(&router, "listener", "Cyan").await;

    let subscriber = adapter.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Publish from the same instance — subscriber should drop it
    let msg = position_message("track-self", "Cyan", 37.0, -122.0);
    adapter.publisher().publish(&msg).await;

    let result = timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(
        result.is_err(),
        "subscriber should ignore own instance messages"
    );

    sub_task.abort();
}

/// Verify that messages published to NATS are NOT delivered back to the same
/// instance, but ARE delivered to a different instance.
#[tokio::test]
async fn cross_instance_delivery() {
    let server = require_nats!();

    let config_a = test_config(server.url(), "cross-A");
    let config_b = test_config(server.url(), "cross-B");

    let adapter_a = NatsAdapter::connect(config_a).await.expect("connect A");
    let adapter_b = NatsAdapter::connect(config_b).await.expect("connect B");

    // Both instances have local sessions
    let router_a = Arc::new(Router::new());
    let router_b = Arc::new(Router::new());

    let mut rx_a = register_session(&router_a, "client-A", "Cyan").await;
    let mut rx_b = register_session(&router_b, "client-B", "Cyan").await;

    // Subscribe on both instances
    let sub_a = adapter_a.subscriber();
    let sub_b = adapter_b.subscriber();

    let router_a_clone = Arc::clone(&router_a);
    let router_b_clone = Arc::clone(&router_b);

    let task_a = tokio::spawn(async move {
        let _ = sub_a.run(router_a_clone).await;
    });
    let task_b = tokio::spawn(async move {
        let _ = sub_b.run(router_b_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Instance A publishes
    let msg = position_message("track-cross", "Cyan", 38.0, -121.0);
    adapter_a.publisher().publish(&msg).await;

    // Instance B should receive it
    let received = timeout(Duration::from_secs(5), rx_b.recv())
        .await
        .expect("B should receive within timeout")
        .expect("B channel closed");
    assert_eq!(&*received.source.cn, "track-cross");

    // Instance A should NOT receive its own message back
    let self_echo = timeout(Duration::from_secs(2), rx_a.recv()).await;
    assert!(self_echo.is_err(), "A should not receive its own message");

    task_a.abort();
    task_b.abort();
}

/// Publish positions, then verify JetStream replay populates the router cache.
#[tokio::test]
async fn jetstream_replay() {
    let server = require_nats!();

    let config = test_config(server.url(), "replay-publisher");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    // Create the JetStream stream that the replay consumer expects
    let js = async_nats::jetstream::new(
        async_nats::connect(server.url())
            .await
            .expect("raw connect"),
    );
    let _ = js
        .create_stream(async_nats::jetstream::stream::Config {
            name: "TRACKS_HISTORY".to_string(),
            subjects: vec!["TRACKS.HISTORY.>".to_string()],
            max_messages_per_subject: 1,
            ..Default::default()
        })
        .await
        .expect("create stream");

    // Publish 3 distinct tracks
    for i in 0..3 {
        let msg = position_message(
            &format!("track-{i}"),
            "Cyan",
            37.0 + i as f64 * 0.01,
            -122.0,
        );
        adapter.publisher().publish(&msg).await;
    }

    // Small delay for NATS to persist
    tokio::time::sleep(Duration::from_millis(500)).await;

    // New adapter (different instance) replays from JetStream
    let replay_config = test_config(server.url(), "replay-consumer");
    let replay_adapter = NatsAdapter::connect(replay_config)
        .await
        .expect("connect replay");

    let router = Arc::new(Router::new());
    let count = replay_adapter
        .jetstream_replay()
        .replay(Arc::clone(&router))
        .await
        .expect("replay");

    assert_eq!(count, 3, "should replay 3 tracks");
    assert_eq!(router.cache().len().await, 3);
}

/// Verify that publishing the same UID twice results in only the latest
/// position being replayed from JetStream (LastPerSubject policy).
#[tokio::test]
async fn jetstream_replay_latest_per_subject() {
    let server = require_nats!();

    let config = test_config(server.url(), "replay-latest-pub");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    let js = async_nats::jetstream::new(
        async_nats::connect(server.url())
            .await
            .expect("raw connect"),
    );
    let _ = js
        .create_stream(async_nats::jetstream::stream::Config {
            name: "TRACKS_HISTORY".to_string(),
            subjects: vec!["TRACKS.HISTORY.>".to_string()],
            max_messages_per_subject: 1,
            ..Default::default()
        })
        .await
        .expect("create stream");

    // Publish same UID twice with different positions
    let msg1 = position_message("track-update", "Cyan", 37.0, -122.0);
    adapter.publisher().publish(&msg1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let msg2 = position_message("track-update", "Cyan", 38.0, -121.0);
    adapter.publisher().publish(&msg2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Replay should give us exactly 1 message (the latest)
    let replay_config = test_config(server.url(), "replay-latest-con");
    let replay_adapter = NatsAdapter::connect(replay_config).await.expect("connect");

    let router = Arc::new(Router::new());
    let count = replay_adapter
        .jetstream_replay()
        .replay(Arc::clone(&router))
        .await
        .expect("replay");

    assert_eq!(count, 1, "should replay only latest per subject");
}

/// Verify that the subscriber drops messages exceeding max_payload_bytes.
#[tokio::test]
async fn oversized_payload_dropped() {
    let server = require_nats!();

    // Publisher with default config (no size limit on publish side)
    let pub_config = test_config(server.url(), "oversize-pub");
    let pub_adapter = NatsAdapter::connect(pub_config).await.expect("connect pub");

    // Subscriber with tiny max payload
    let mut sub_config = test_config(server.url(), "oversize-sub");
    sub_config.max_payload_bytes = 10; // Very small limit

    let sub_adapter = NatsAdapter::connect(sub_config).await.expect("connect sub");

    let router = Arc::new(Router::new());
    let mut rx = register_session(&router, "listener", "Cyan").await;

    let subscriber = sub_adapter.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Publish a normal position (its JSON payload will exceed 10 bytes)
    let msg = position_message("track-big", "Cyan", 37.0, -122.0);
    pub_adapter.publisher().publish(&msg).await;

    // Should NOT be delivered due to payload size limit
    let result = timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(
        result.is_err(),
        "oversized message should be dropped by subscriber"
    );

    sub_task.abort();
}

/// Verify that non-position messages are not published to NATS (without full-detail).
///
/// Uses valid CoT XML (parseable with uid + point) so the ONLY reason the
/// publisher drops this is the MessageType::Chat check, not a parse failure.
/// Raw NATS subscription verifies nothing was emitted.
///
/// With `full-detail`, all CoT types are published, so this test is skipped.
#[cfg(not(feature = "full-detail"))]
#[tokio::test]
async fn non_position_messages_filtered() {
    let server = require_nats!();

    let config = test_config(server.url(), "filter-pub");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    // Raw subscription — observe the wire directly
    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    let mut raw_sub = raw_client.subscribe("points.>").await.expect("subscribe");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Valid CoT XML that would parse successfully — the ONLY guard is MessageType
    let chat_xml = Bytes::from(
        "<event version=\"2.0\" uid=\"chat-msg-1\" type=\"b-t-f\" \
         time=\"2026-01-01T00:00:00Z\" start=\"2026-01-01T00:00:00Z\" \
         stale=\"2026-01-01T00:05:00Z\" how=\"h-e\">\
         <point lat=\"37.0\" lon=\"-122.0\" hae=\"0\" ce=\"50\" le=\"30\"/>\
         <detail/></event>",
    );

    let mut groups = BTreeSet::new();
    let _ = groups.insert("Cyan".to_string());
    let chat_msg = RoutableMessage {
        source: Identity::plaintext("chatter".to_string(), groups).expect("valid identity"),
        destination: Destination::Broadcast,
        payload: chat_xml,
        metadata: Metadata::new(SystemTime::now(), "tak".to_string(), MessageType::Chat),
    };

    adapter.publisher().publish(&chat_msg).await;

    // Nothing should appear on NATS — publisher drops non-Position messages
    let result = timeout(Duration::from_secs(2), raw_sub.next()).await;
    assert!(
        result.is_err(),
        "chat messages should not be published to NATS"
    );
}

/// Verify that non-position messages ARE published to NATS with full-detail.
///
/// The full-detail feature enables publishing all CoT types (chat, shapes, etc.)
/// using the full XML parser for richer wire events.
#[cfg(feature = "full-detail")]
#[tokio::test]
async fn non_position_messages_published() {
    let server = require_nats!();

    let config = test_config(server.url(), "full-detail-pub");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    let mut raw_sub = raw_client.subscribe("points.>").await.expect("subscribe");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let chat_xml = Bytes::from(
        "<event version=\"2.0\" uid=\"chat-msg-1\" type=\"b-t-f\" \
         time=\"2026-01-01T00:00:00Z\" start=\"2026-01-01T00:00:00Z\" \
         stale=\"2026-01-01T00:05:00Z\" how=\"h-e\">\
         <point lat=\"37.0\" lon=\"-122.0\" hae=\"0\" ce=\"50\" le=\"30\"/>\
         <detail><remarks>hello world</remarks></detail></event>",
    );

    let mut groups = BTreeSet::new();
    let _ = groups.insert("Cyan".to_string());
    let chat_msg = RoutableMessage {
        source: Identity::plaintext("chatter".to_string(), groups).expect("valid identity"),
        destination: Destination::Broadcast,
        payload: chat_xml,
        metadata: Metadata::new(SystemTime::now(), "tak".to_string(), MessageType::Chat),
    };

    adapter.publisher().publish(&chat_msg).await;

    let result = timeout(Duration::from_secs(5), raw_sub.next()).await;
    assert!(
        result.is_ok(),
        "chat messages should be published with full-detail"
    );

    let nats_msg = result.expect("result").expect("msg");
    let wire: WireEvent = serde_json::from_slice(&nats_msg.payload).expect("valid JSON");
    assert_eq!(wire.uid, "chat-msg-1");
    assert_eq!(wire.event_type, "b-t-f");
    // With full-detail, remarks are extracted as a typed field
    let detail = wire.detail.expect("detail should be populated");
    assert!(
        detail.remarks.is_some(),
        "remarks should be populated as typed field"
    );
    let notes = &detail.remarks.as_ref().unwrap().note;
    assert!(!notes.is_empty(), "should have at least one note");
    assert_eq!(notes[0].text, "hello world");
}

/// Verify that a position flagged "unknown" via the CoT ce/le sentinel
/// is filtered by the publisher.
///
/// The CoT spec defines `ce=9999999 && le=9999999` as "position
/// unknown" — reports with this sentinel indicate the reporter could
/// not determine a fix. Raw NATS subscription verifies nothing was
/// emitted.
#[tokio::test]
async fn unknown_position_filtered() {
    let server = require_nats!();

    let config = test_config(server.url(), "unknown-pub");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    // Raw subscription — observe the wire directly
    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    let mut raw_sub = raw_client.subscribe("points.>").await.expect("subscribe");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Position flagged unknown via the ce/le sentinel.
    let mut groups = BTreeSet::new();
    let _ = groups.insert("Cyan".to_string());
    let msg = RoutableMessage {
        source: Identity::plaintext("track-unknown".to_string(), groups).expect("valid identity"),
        destination: Destination::Broadcast,
        payload: cot_position_xml_with_error(
            "track-unknown",
            37.0,
            -122.0,
            9_999_999.0,
            9_999_999.0,
        ),
        metadata: Metadata::new(SystemTime::now(), "tak".to_string(), MessageType::Position),
    };
    adapter.publisher().publish(&msg).await;

    // Nothing should appear on NATS — publisher drops unknown-position reports
    let result = timeout(Duration::from_secs(2), raw_sub.next()).await;
    assert!(
        result.is_err(),
        "position-unknown sentinel should not be published to NATS"
    );
}

/// Verify that a report at lat=0, lon=0 with a *valid* ce/le is NOT
/// filtered. The Gulf of Guinea and other equatorial ocean zones are
/// legitimate operating areas; an earlier heuristic dropped them by
/// treating 0,0 as "position unknown", which loses real data.
#[tokio::test]
async fn zero_position_with_valid_error_is_published() {
    let server = require_nats!();

    let config = test_config(server.url(), "zero-ok-pub");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    let mut raw_sub = raw_client.subscribe("points.>").await.expect("subscribe");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 0,0 with a normal ce/le — Gulf of Guinea ocean water, valid fix.
    let msg = position_message("track-zero", "Cyan", 0.0, 0.0);
    adapter.publisher().publish(&msg).await;

    let result = timeout(Duration::from_secs(5), raw_sub.next()).await;
    assert!(
        result.is_ok(),
        "0,0 with valid ce/le must be published (equatorial ocean is valid)"
    );
}

/// Verify group extraction from NATS subject — publisher encodes group
/// in the subject and subscriber extracts it for the RoutableMessage.
#[tokio::test]
async fn group_preserved_through_nats() {
    let server = require_nats!();

    let config_a = test_config(server.url(), "group-pub");
    let config_b = test_config(server.url(), "group-sub");

    let adapter_a = NatsAdapter::connect(config_a).await.expect("connect A");
    let adapter_b = NatsAdapter::connect(config_b).await.expect("connect B");

    let router = Arc::new(Router::new());
    let mut rx = register_session(&router, "listener", "Alpha").await;

    let subscriber = adapter_b.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Publish with group "Alpha"
    let msg = position_message("track-alpha", "Alpha", 38.5, -121.5);
    adapter_a.publisher().publish(&msg).await;

    let received = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert!(
        received.source.groups.contains("Alpha"),
        "group should be preserved: got {:?}",
        received.source.groups
    );

    sub_task.abort();
}

/// Verify that max_replay_count limits the number of replayed messages.
#[tokio::test]
async fn jetstream_replay_count_limit() {
    let server = require_nats!();

    let config = test_config(server.url(), "limit-pub");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    let js = async_nats::jetstream::new(
        async_nats::connect(server.url())
            .await
            .expect("raw connect"),
    );
    let _ = js
        .create_stream(async_nats::jetstream::stream::Config {
            name: "TRACKS_HISTORY".to_string(),
            subjects: vec!["TRACKS.HISTORY.>".to_string()],
            max_messages_per_subject: 1,
            ..Default::default()
        })
        .await
        .expect("create stream");

    // Publish 5 tracks
    for i in 0..5 {
        let msg = position_message(
            &format!("track-limit-{i}"),
            "Cyan",
            37.0 + i as f64 * 0.01,
            -122.0,
        );
        adapter.publisher().publish(&msg).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Replay with max_replay_count = 2
    let mut replay_config = test_config(server.url(), "limit-con");
    replay_config.max_replay_count = 2;

    let replay_adapter = NatsAdapter::connect(replay_config).await.expect("connect");
    let router = Arc::new(Router::new());

    let count = replay_adapter
        .jetstream_replay()
        .replay(Arc::clone(&router))
        .await
        .expect("replay");

    assert_eq!(count, 2, "replay should stop at max_replay_count");
    assert_eq!(router.cache().len().await, 2);
}

/// Wire format round-trip: verify WireEvent serialization/deserialization
/// through actual NATS publish/subscribe produces valid data.
#[tokio::test]
async fn wire_format_fidelity() {
    let server = require_nats!();

    let config_a = test_config(server.url(), "wire-pub");
    let config_b = test_config(server.url(), "wire-sub");

    let adapter_a = NatsAdapter::connect(config_a).await.expect("connect A");
    let adapter_b = NatsAdapter::connect(config_b).await.expect("connect B");

    let router = Arc::new(Router::new());
    let mut rx = register_session(&router, "listener", "Cyan").await;

    let subscriber = adapter_b.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let msg = position_message("track-wire", "Cyan", 51.5074, -0.1278);
    adapter_a.publisher().publish(&msg).await;

    let received = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    // The payload should be valid JSON containing the original coordinates
    let wire: WireEvent =
        serde_json::from_slice(&received.payload).expect("payload should be valid JSON");
    assert_eq!(wire.uid, "track-wire");
    assert!((wire.point.lat - 51.5074).abs() < 0.001);
    assert!((wire.point.lon - (-0.1278)).abs() < 0.001);
    assert_eq!(wire.event_type, "a-f-G-U-C");

    sub_task.abort();
}

/// Verify that the subscriber creates the JetStream stream and pull consumer
/// automatically when they don't exist yet.
#[tokio::test]
async fn jetstream_pull_consumer_creation() {
    let server = require_nats!();

    let config = test_config(server.url(), "consumer-create-test");
    let adapter = NatsAdapter::connect(config.clone()).await.expect("connect");

    let router = Arc::new(Router::new());
    let subscriber = adapter.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    // Give the subscriber time to create stream and consumer
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify the stream was created
    let js = server.jetstream().await;
    let mut stream = js
        .get_stream(&config.live_stream)
        .await
        .expect("live stream should exist");

    let info = stream.info().await.expect("stream info");
    assert_eq!(info.config.name, config.live_stream);

    // Verify the consumer was created
    let consumer_name = format!("rustgate-sub-{}", config.instance_id);
    let mut consumer = stream
        .get_consumer::<async_nats::jetstream::consumer::pull::Config>(&consumer_name)
        .await
        .expect("consumer should exist");
    let consumer_info = consumer.info().await.expect("consumer info");
    assert_eq!(consumer_info.config.max_ack_pending, config.max_ack_pending);

    sub_task.abort();
}

/// Verify that messages are explicitly acknowledged after processing,
/// ensuring they are not redelivered.
#[tokio::test]
async fn jetstream_pull_consumer_ack_flow() {
    let server = require_nats!();

    let config_pub = test_config(server.url(), "ack-pub");
    let config_sub = test_config(server.url(), "ack-sub");

    let adapter_pub = NatsAdapter::connect(config_pub).await.expect("connect pub");
    let adapter_sub = NatsAdapter::connect(config_sub.clone())
        .await
        .expect("connect sub");

    let router = Arc::new(Router::new());
    let mut rx = register_session(&router, "ack-listener", "Cyan").await;

    let subscriber = adapter_sub.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Publish a message
    let msg = position_message("track-ack", "Cyan", 37.0, -122.0);
    adapter_pub.publisher().publish(&msg).await;

    // Wait for delivery
    let received = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert_eq!(&*received.source.cn, "track-ack");

    // Give time for ACK to propagate
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check the consumer has 0 pending (all messages acknowledged)
    let js = server.jetstream().await;
    let stream = js
        .get_stream(&config_sub.live_stream)
        .await
        .expect("stream");
    let consumer_name = format!("rustgate-sub-{}", config_sub.instance_id);
    let mut consumer = stream
        .get_consumer::<async_nats::jetstream::consumer::pull::Config>(&consumer_name)
        .await
        .expect("consumer");
    let info = consumer.info().await.expect("info");
    assert_eq!(
        info.num_ack_pending, 0,
        "all messages should be acknowledged"
    );

    sub_task.abort();
}

/// Verify that unacknowledged messages are retained when the subscriber
/// shuts down, providing graceful shutdown semantics.
#[tokio::test]
async fn jetstream_pull_consumer_graceful_shutdown() {
    let server = require_nats!();

    let config_pub = test_config(server.url(), "shutdown-pub");
    let config_sub = test_config(server.url(), "shutdown-sub");

    let adapter_pub = NatsAdapter::connect(config_pub).await.expect("connect pub");
    let adapter_sub = NatsAdapter::connect(config_sub.clone())
        .await
        .expect("connect sub");

    let router = Arc::new(Router::new());
    let _rx = register_session(&router, "shutdown-listener", "Cyan").await;

    let subscriber = adapter_sub.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Publish a message and wait for processing
    let msg = position_message("track-shutdown", "Cyan", 37.0, -122.0);
    adapter_pub.publisher().publish(&msg).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Abort the subscriber (simulates shutdown)
    sub_task.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The stream should still have the message stored (even if acknowledged,
    // it remains in the stream until retention limits are reached)
    let js = server.jetstream().await;
    let mut stream = js
        .get_stream(&config_sub.live_stream)
        .await
        .expect("stream should exist after shutdown");
    let info = stream.info().await.expect("stream info");
    assert!(
        info.state.messages >= 1,
        "stream should retain messages after subscriber shutdown"
    );
}

// ── Request/reply (#907b) ─────────────────────────────────────────────────

/// Build a config that enables the request/reply responder.
fn request_config(url: &str, instance_id: &str, request_subject: &str) -> NatsConfig {
    NatsConfig {
        url: url.to_string(),
        instance_id: instance_id.to_string(),
        request_subject: Some(request_subject.to_string()),
        ..Default::default()
    }
}

/// Build an echo handler that prefixes the request payload with "echo:".
fn echo_handler() -> NatsRequestHandler {
    Arc::new(|payload: bytes::Bytes| {
        Box::pin(async move {
            let mut out = Vec::with_capacity(payload.len() + 5);
            out.extend_from_slice(b"echo:");
            out.extend_from_slice(&payload);
            Ok(bytes::Bytes::from(out))
        })
    })
}

/// Round-trip: responder subscribes on a subject, client publishes a
/// request, handler runs, reply is delivered. Covers the core happy path
/// for [`NatsRequestClient`] and [`NatsRequestResponder`].
#[tokio::test]
async fn request_reply_round_trip() {
    let server = require_nats!();
    let subject = "rustgate.ops.echo";

    let responder_adapter = NatsAdapter::connect(request_config(server.url(), "resp-A", subject))
        .await
        .expect("connect responder");
    let client_adapter = NatsAdapter::connect(test_config(server.url(), "cli-A"))
        .await
        .expect("connect client");

    let responder: NatsRequestResponder = responder_adapter
        .request_responder(echo_handler())
        .expect("responder configured");
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    let resp_task = tokio::spawn(async move { responder.run(shutdown_clone).await });

    // Give the subscription time to register with the server before the
    // client sends — otherwise the server returns NoResponders.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = client_adapter.request_client();
    let reply = timeout(
        Duration::from_secs(3),
        client.request(subject, Bytes::from_static(b"hello")),
    )
    .await
    .expect("request did not complete in time")
    .expect("request should succeed");

    assert_eq!(reply.as_ref(), b"echo:hello");

    shutdown.notify_waiters();
    // Ensure the responder observes the shutdown signal before the test exits.
    let _ = timeout(Duration::from_secs(2), resp_task)
        .await
        .expect("responder task did not shut down");
}

/// A responder configured for subject `A` must not answer requests sent
/// to subject `B` — confirms the subscription is narrow and does not
/// accidentally match a superset.
#[tokio::test]
async fn request_reply_no_responders_on_unrelated_subject() {
    let server = require_nats!();

    let responder_adapter = NatsAdapter::connect(request_config(
        server.url(),
        "resp-isolated",
        "rustgate.ops.only",
    ))
    .await
    .expect("connect responder");
    let client_adapter = NatsAdapter::connect(test_config(server.url(), "cli-isolated"))
        .await
        .expect("connect client");

    let responder = responder_adapter
        .request_responder(echo_handler())
        .expect("responder configured");
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    let resp_task = tokio::spawn(async move { responder.run(shutdown_clone).await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = client_adapter.request_client();
    let err = client
        .request("rustgate.ops.different", Bytes::from_static(b"hi"))
        .await
        .expect_err("expected NoResponders error");

    assert!(
        matches!(err, RequestError::NoResponders { ref subject } if subject == "rustgate.ops.different"),
        "expected NoResponders for unrelated subject, got: {err:?}",
    );

    shutdown.notify_waiters();
    let _ = timeout(Duration::from_secs(2), resp_task).await;
}

/// A handler that returns `Err(msg)` should surface as
/// [`RequestError::HandlerError`] on the client side, carrying the
/// original error string — not `NoResponders` or `Timeout`.
#[tokio::test]
async fn request_reply_handler_error_propagates() {
    let server = require_nats!();
    let subject = "rustgate.ops.fail";

    let responder_adapter = NatsAdapter::connect(request_config(server.url(), "resp-err", subject))
        .await
        .expect("connect responder");
    let client_adapter = NatsAdapter::connect(test_config(server.url(), "cli-err"))
        .await
        .expect("connect client");

    let failing_handler: NatsRequestHandler = Arc::new(|_payload| {
        Box::pin(async move { Err("handler explicitly rejected".to_string()) })
    });
    let responder = responder_adapter
        .request_responder(failing_handler)
        .expect("responder configured");
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    let resp_task = tokio::spawn(async move { responder.run(shutdown_clone).await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = client_adapter.request_client();
    let err = client
        .request(subject, Bytes::from_static(b"anything"))
        .await
        .expect_err("expected HandlerError");

    match err {
        RequestError::HandlerError {
            subject: s,
            message,
        } => {
            assert_eq!(s, subject);
            assert_eq!(message, "handler explicitly rejected");
        }
        other => panic!("expected HandlerError, got: {other:?}"),
    }

    shutdown.notify_waiters();
    let _ = timeout(Duration::from_secs(2), resp_task).await;
}

/// When the handler sleeps past the per-call timeout the client must
/// fail with [`RequestError::Timeout`] — not hang forever. The responder
/// itself stays up and can still serve subsequent requests.
#[tokio::test]
async fn request_reply_timeout_when_handler_too_slow() {
    let server = require_nats!();
    let subject = "rustgate.ops.slow";

    let responder_adapter =
        NatsAdapter::connect(request_config(server.url(), "resp-slow", subject))
            .await
            .expect("connect responder");
    let client_adapter = NatsAdapter::connect(test_config(server.url(), "cli-slow"))
        .await
        .expect("connect client");

    // Handler sleeps for longer than the request timeout. We intentionally
    // exceed the 200ms request timeout but keep it short enough for fast
    // CI runs (a few hundred milliseconds, not seconds).
    let slow_handler: NatsRequestHandler = Arc::new(|_payload| {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok(bytes::Bytes::from_static(b"late"))
        })
    });
    let responder = responder_adapter
        .request_responder(slow_handler)
        .expect("responder configured");
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    let resp_task = tokio::spawn(async move { responder.run(shutdown_clone).await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = client_adapter.request_client();
    let err = client
        .request_with_timeout(
            subject.to_string(),
            Bytes::from_static(b"please-timeout"),
            Duration::from_millis(200),
        )
        .await
        .expect_err("expected Timeout");

    assert!(
        matches!(err, RequestError::Timeout { ref subject, timeout } if subject == "rustgate.ops.slow" && timeout == Duration::from_millis(200)),
        "expected Timeout for slow handler, got: {err:?}",
    );

    shutdown.notify_waiters();
    let _ = timeout(Duration::from_secs(3), resp_task).await;
}

/// Building a responder when `request_subject` is `None` returns `None`
/// — the opt-in contract. Without this, callers would have to duplicate
/// the check in every wiring site.
#[tokio::test]
async fn request_responder_not_configured_returns_none() {
    let server = require_nats!();

    // Default config has request_subject = None.
    let adapter = NatsAdapter::connect(test_config(server.url(), "no-resp"))
        .await
        .expect("connect");

    let responder = adapter.request_responder(echo_handler());
    assert!(
        responder.is_none(),
        "adapter with no request_subject should return None",
    );
}

// ---------------------------------------------------------------------------
// Dead-letter subject (poison message preservation).
//
// The subscriber silently ACKs four classes of local-drop traffic so the
// pull consumer can advance past stuck sequences: oversized payloads,
// unparseable JSON, unknown-position CoT, and identity-validation
// failures. When `dead_letter_subject` is set, the original bytes are
// republished there (with diagnostic headers) before the ACK so operators
// can inspect what the upstream producer sent. These tests exercise the
// happy path (unparseable JSON → DLQ) and the opt-in semantics (DLQ not
// configured → silent drop, no DLQ traffic anywhere).
// ---------------------------------------------------------------------------

/// Unparseable JSON published to the live subject surfaces on the DLQ with
/// the expected diagnostic headers, and the original payload is preserved
/// unchanged. This is the end-to-end proof that the poison-preservation
/// path in `NatsSubscriber::publish_dead_letter` actually reaches the wire.
#[tokio::test]
async fn dead_letter_publishes_unparseable_payload() {
    let server = require_nats!();

    let mut sub_config = test_config(server.url(), "dlq-sub-unparseable");
    // Canonical deployment pattern: DLQ in a sibling subject namespace,
    // disjoint from the live stream's `points.>` wildcard, so DLQ traffic
    // is not recaptured and redelivered.
    sub_config.dead_letter_subject = Some("rustgate.dlq".to_string());
    let sub_adapter = NatsAdapter::connect(sub_config).await.expect("connect sub");

    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    let mut dlq_sub = raw_client
        .subscribe("rustgate.dlq")
        .await
        .expect("subscribe DLQ");

    let pub_client = async_nats::connect(server.url())
        .await
        .expect("pub connect");

    let router = Arc::new(Router::new());
    let subscriber = sub_adapter.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    // Let the subscriber materialize the live stream and bind a consumer
    // before we inject the poison. Without this, the publish races the
    // stream creation and the message is silently dropped by NATS.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Bogus bytes that cannot be decoded as `WireEvent` — this fires the
    // `unparseable` branch in the subscriber receive loop.
    let poison = bytes::Bytes::from_static(b"not-json-at-all-just-garbage");
    pub_client
        .publish("points.ALPHA", poison.clone())
        .await
        .expect("publish poison");

    let dlq_msg = timeout(Duration::from_secs(5), dlq_sub.next())
        .await
        .expect("DLQ timeout")
        .expect("DLQ subscription ended");

    // Original payload preserved byte-for-byte — the whole point of DLQ
    // is that forensic tooling sees what the producer actually sent.
    assert_eq!(dlq_msg.payload.as_ref(), poison.as_ref());

    let headers = dlq_msg.headers.as_ref().expect("DLQ message has headers");
    assert_eq!(
        headers.get("X-Rustgate-DLQ-Reason").map(|v| v.as_str()),
        Some("unparseable"),
        "reason slug identifies which drop path fired",
    );
    assert_eq!(
        headers
            .get("X-Rustgate-DLQ-Original-Subject")
            .map(|v| v.as_str()),
        Some("points.ALPHA"),
        "original subject preserved for per-tenant triage",
    );
    assert!(
        headers
            .get("X-Rustgate-DLQ-Timestamp")
            .and_then(|v| v.as_str().parse::<u128>().ok())
            .is_some(),
        "timestamp header is a parseable unix-millis integer",
    );

    sub_task.abort();
}

// ── Subscriber egress fan-out (refs #737 — NATS subscriber sub-item) ─────
//
// The subscriber's consumer loop drives every inbound NATS message
// through `Router::route_for_egress` so any Send-PEP obligations land
// on the envelope before the optional federation / HTTP / NATS-publish
// forwarder callbacks observe it. The five tests below pin the
// load-bearing security properties of that path:
//
// 1. **Federation fan-out fires once per inbound message.** A federation
//    forwarder wired on the subscriber must be invoked exactly once per
//    NATS message that survives the router's admission, with the
//    post-Send-PEP payload + groups + metadata.
// 2. **HTTP fan-out fires once per inbound message.** Symmetric to
//    federation — wires an HTTP forwarder and asserts it fires.
// 3. **Obligations apply before fan-out.** A `MaskPayload` obligation
//    on the Send PEP MUST strip the payload before the local recipient
//    sees it AND before the federation forwarder observes the
//    envelope. A regression that fired the egress callbacks against
//    the pre-PEP form would leak raw payload bytes to a federation
//    peer while the in-process delivery looked compliant.
//    `MaskPayload` is used here rather than `MaskPoint` because the
//    NATS wire form is JSON, not CoT XML — `MaskPoint`'s non-XML
//    branch would silently forward the payload unmasked.
// 4. **Echo prevention.** A NATS-sourced `RoutableMessage` re-published
//    onto the bus through the publisher must short-circuit on the
//    case-insensitive `source_protocol == "nats"` guard (#1192) — the
//    new `nats_publish` callback on the subscriber is therefore a
//    no-op in practice. Pinned so a future change to the echo
//    discipline breaks here rather than at runtime.
// 5. **`source_protocol` stamping.** Every envelope the subscriber
//    constructs from a NATS message must stamp
//    `metadata.source_protocol = "nats"`. This is the workspace
//    convention the publisher's echo guard depends on; pinning it
//    here protects the loop-prevention contract end-to-end.

/// Wire a federation forwarder on the subscriber and assert it fires
/// exactly once per inbound NATS message with the post-Send-PEP
/// envelope shape (payload + source-groups + metadata).
#[tokio::test]
async fn nats_subscriber_publish_fans_out_to_federation() {
    use std::sync::Mutex as StdMutex;

    let server = require_nats!();

    let config_a = test_config(server.url(), "fed-fanout-A");
    let config_b = test_config(server.url(), "fed-fanout-B");

    let adapter_a = NatsAdapter::connect(config_a).await.expect("connect A");
    let adapter_b = NatsAdapter::connect(config_b).await.expect("connect B");

    let router_b = Arc::new(Router::new());
    let _rx = register_session(&router_b, "local-fed-recv", "Cyan").await;

    type FedCall = (bytes::Bytes, Vec<String>, Metadata);
    let fed_calls: Arc<StdMutex<Vec<FedCall>>> = Arc::new(StdMutex::new(Vec::new()));
    let fed_calls_clone = Arc::clone(&fed_calls);
    let fed_cb: rustgate_core::egress::OnFederationForward =
        Arc::new(move |payload, groups, meta| {
            fed_calls_clone
                .lock()
                .expect("fed_calls mutex poisoned")
                .push((payload, groups, meta));
        });

    let subscriber = adapter_b.subscriber().with_federation_forward(fed_cb);
    let sub_router = Arc::clone(&router_b);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    // Give the subscriber time to bind its consumer.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let msg = position_message("track-fed-fanout", "Cyan", 37.7749, -122.4194);
    adapter_a.publisher().publish(&msg).await;

    // Poll up to 5s for the federation callback to fire — the consumer
    // loop runs on a separate task so wall-clock latency includes
    // JetStream pull, decode, route, and fan-out.
    let mut snapshot = Vec::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        snapshot = fed_calls.lock().expect("fed_calls mutex poisoned").clone();
        if !snapshot.is_empty() {
            break;
        }
    }
    assert_eq!(
        snapshot.len(),
        1,
        "federation_forward must fire exactly once per inbound NATS message",
    );
    let (payload, groups, meta) = &snapshot[0];
    assert!(
        !payload.is_empty(),
        "federation forward must carry the post-Send-PEP payload",
    );
    assert!(
        groups.iter().any(|g| g == "Cyan"),
        "federation forward must carry the source identity's groups: {groups:?}",
    );
    assert_eq!(
        meta.source_protocol, "nats",
        "federation forward metadata must preserve the inbound source_protocol",
    );

    sub_task.abort();
}

/// Wire an HTTP egress forwarder on the subscriber and assert it
/// fires exactly once per inbound NATS message with the post-Send-PEP
/// `RoutableMessage` envelope.
#[tokio::test]
async fn nats_subscriber_publish_fans_out_to_http() {
    use std::sync::Mutex as StdMutex;

    let server = require_nats!();

    let config_a = test_config(server.url(), "http-fanout-A");
    let config_b = test_config(server.url(), "http-fanout-B");

    let adapter_a = NatsAdapter::connect(config_a).await.expect("connect A");
    let adapter_b = NatsAdapter::connect(config_b).await.expect("connect B");

    let router_b = Arc::new(Router::new());
    let _rx = register_session(&router_b, "local-http-recv", "Cyan").await;

    let http_calls: Arc<StdMutex<Vec<RoutableMessage>>> = Arc::new(StdMutex::new(Vec::new()));
    let http_calls_clone = Arc::clone(&http_calls);
    let http_cb: rustgate_core::egress::OnHttpForward = Arc::new(move |msg| {
        http_calls_clone
            .lock()
            .expect("http_calls mutex poisoned")
            .push(msg);
    });

    let subscriber = adapter_b.subscriber().with_http_forward(http_cb);
    let sub_router = Arc::clone(&router_b);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let msg = position_message("track-http-fanout", "Cyan", 38.0, -121.0);
    adapter_a.publisher().publish(&msg).await;

    let mut snapshot = Vec::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        snapshot = http_calls
            .lock()
            .expect("http_calls mutex poisoned")
            .clone();
        if !snapshot.is_empty() {
            break;
        }
    }
    assert_eq!(
        snapshot.len(),
        1,
        "http_forward must fire exactly once per inbound NATS message",
    );
    let routed = &snapshot[0];
    assert_eq!(routed.metadata.source_protocol, "nats");
    assert!(routed.source.groups.contains("Cyan"));
    assert!(
        !routed.payload.is_empty(),
        "http forward payload must be non-empty",
    );

    sub_task.abort();
}

/// A Send-PEP obligation MUST scrub the payload BEFORE the local
/// recipient sees it AND BEFORE the federation forwarder observes it.
/// A regression that fired the egress callback against the pre-PEP
/// form would leak raw payload bytes to a federation peer while the
/// in-process delivery looked compliant — exactly the gap closed by
/// switching the subscriber's call site from `Router::route` to
/// `Router::route_for_egress` (refs #737).
///
/// Uses [`Obligation::MaskPayload`] (which works on any payload) rather
/// than [`Obligation::MaskPoint`] (CoT-XML-specific) because the
/// payload arriving over NATS is the JSON wire form produced by
/// `WireEvent`, not raw CoT XML; `MaskPoint`'s non-XML branch would
/// silently forward unmasked bytes and miss the property under test.
#[tokio::test]
async fn nats_subscriber_with_send_pep_obligation_applies_obligation_before_fanout() {
    use std::sync::Mutex as StdMutex;

    use rustgate_authz::{
        Action, Decision, DecisionOutcome, Obligation, PolicyEngine, Resource, Subject,
    };

    /// Engine that allows everything but attaches `MaskPayload` on the
    /// Send PEP. The obligation strips the payload bytes and rewrites
    /// `metadata.message_type` to `Other("masked")`, both of which are
    /// observable from the local recipient and the egress fan-out copy.
    struct AllowWithSendMaskPayloadEngine;
    impl PolicyEngine for AllowWithSendMaskPayloadEngine {
        fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, a: Action) -> DecisionOutcome {
            let obligations = if a == Action::Send {
                vec![Obligation::MaskPayload]
            } else {
                Vec::new()
            };
            DecisionOutcome {
                decision: Decision::Allow,
                rule_id: None,
                obligations,
            }
        }
        fn policy_id(&self) -> &str {
            "test-nats-subscriber-send-mask-payload"
        }
    }

    let server = require_nats!();

    let config_a = test_config(server.url(), "mask-fanout-A");
    let config_b = test_config(server.url(), "mask-fanout-B");

    let adapter_a = NatsAdapter::connect(config_a).await.expect("connect A");
    let adapter_b = NatsAdapter::connect(config_b).await.expect("connect B");

    // Bob is the local recipient; the router has Send-MaskPayload wired.
    // After the obligation rewrites `message_type` to `Other("masked")`
    // the message routes to Bob's NORMAL channel (not the priority
    // channel that Position would have taken), so we register the dual
    // helper and read from `nrx`.
    let router_b = Arc::new(Router::new().with_authz(Arc::new(AllowWithSendMaskPayloadEngine)));
    let (_prx, mut nrx) = register_session_dual(&router_b, "bob-mask", "Cyan").await;

    type FedCall = (bytes::Bytes, Vec<String>, Metadata);
    let fed_calls: Arc<StdMutex<Vec<FedCall>>> = Arc::new(StdMutex::new(Vec::new()));
    let fed_calls_clone = Arc::clone(&fed_calls);
    let fed_cb: rustgate_core::egress::OnFederationForward =
        Arc::new(move |payload, groups, meta| {
            fed_calls_clone
                .lock()
                .expect("fed_calls mutex poisoned")
                .push((payload, groups, meta));
        });

    let subscriber = adapter_b.subscriber().with_federation_forward(fed_cb);
    let sub_router = Arc::clone(&router_b);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Alice publishes a position. The Send PEP scrubs the payload bytes
    // BEFORE Bob's session channel receives the message and BEFORE the
    // federation callback fires.
    let msg = position_message("track-mask", "Cyan", 38.8977, -77.0365);
    adapter_a.publisher().publish(&msg).await;

    // Bob receives the masked envelope on his normal channel (the
    // obligation rewrote `message_type` away from `Position`):
    // payload bytes stripped, message type rewritten to
    // `Other("masked")`.
    let received = timeout(Duration::from_secs(5), nrx.recv())
        .await
        .expect("local recipient must receive the masked message")
        .expect("session channel closed");
    assert!(
        received.payload.is_empty(),
        "local subscriber must see Send-PEP MaskPayload applied (payload bytes stripped); got {} bytes",
        received.payload.len(),
    );
    assert!(
        matches!(received.metadata.message_type, MessageType::Other(ref s) if s == "masked"),
        "local subscriber must see message_type rewritten to Other(\"masked\"); got {:?}",
        received.metadata.message_type,
    );

    // Federation callback observes the same masked form.
    let mut snapshot = Vec::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        snapshot = fed_calls.lock().expect("fed_calls mutex poisoned").clone();
        if !snapshot.is_empty() {
            break;
        }
    }
    assert_eq!(
        snapshot.len(),
        1,
        "federation_forward must fire exactly once for the obligation-allowed inbound NATS message",
    );
    let (egress_payload, _groups, egress_meta) = &snapshot[0];
    assert!(
        egress_payload.is_empty(),
        "federation egress must see Send-PEP MaskPayload applied (payload bytes stripped); got {} bytes",
        egress_payload.len(),
    );
    assert!(
        matches!(egress_meta.message_type, MessageType::Other(ref s) if s == "masked"),
        "federation egress must see message_type rewritten to Other(\"masked\"); got {:?}",
        egress_meta.message_type,
    );

    sub_task.abort();
}

/// A NATS-sourced `RoutableMessage` re-published onto the bus through
/// the publisher must short-circuit on the case-insensitive
/// `source_protocol == "nats"` guard (#1192). The new `nats_publish`
/// callback on the subscriber composes with that guard so wiring it
/// cannot form a publish loop — pinned so a future change to the echo
/// discipline breaks here rather than at runtime in production.
#[tokio::test]
async fn nats_subscriber_does_not_re_publish_to_nats() {
    let server = require_nats!();

    let config = test_config(server.url(), "echo-subscriber-test");
    let adapter = NatsAdapter::connect(config).await.expect("connect");

    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    let mut raw_sub = raw_client.subscribe("points.>").await.expect("subscribe");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // A message stamped as if it had just come off the subscriber's
    // consumer loop (the workspace convention is
    // `metadata.source_protocol = "nats"`). Publishing this through the
    // publisher MUST short-circuit on the echo guard — otherwise a NATS
    // → subscriber → nats_publish callback → publisher → NATS loop
    // would form.
    let mut msg = position_message("track-echo-sub", "Cyan", 37.0, -122.0);
    msg.metadata.source_protocol = "nats".to_string();

    adapter.publisher().publish(&msg).await;

    let result = timeout(Duration::from_secs(2), raw_sub.next()).await;
    assert!(
        result.is_err(),
        "publisher must short-circuit on source_protocol=nats so the subscriber's nats_publish callback cannot form a loop",
    );
}

/// The subscriber's `WireEvent::into_routable` MUST stamp
/// `metadata.source_protocol = "nats"` on every envelope it
/// constructs from an inbound NATS message. The publisher's echo
/// guard depends on this convention; pinning the invariant here
/// protects the loop-prevention contract end-to-end (refs #737).
#[tokio::test]
async fn nats_subscriber_source_protocol_stamped_correctly() {
    let server = require_nats!();

    let config_a = test_config(server.url(), "stamp-A");
    let config_b = test_config(server.url(), "stamp-B");

    let adapter_a = NatsAdapter::connect(config_a).await.expect("connect A");
    let adapter_b = NatsAdapter::connect(config_b).await.expect("connect B");

    let router_b = Arc::new(Router::new());
    let mut rx = register_session(&router_b, "local-stamp", "Cyan").await;

    let subscriber = adapter_b.subscriber();
    let sub_router = Arc::clone(&router_b);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let msg = position_message("track-stamp", "Cyan", 37.0, -122.0);
    adapter_a.publisher().publish(&msg).await;

    let received = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("local recipient must receive the message")
        .expect("session channel closed");

    assert_eq!(
        received.metadata.source_protocol, "nats",
        "subscriber must stamp source_protocol=nats so the publisher's echo guard catches future loops",
    );

    sub_task.abort();
}

// ── Sub-item 3 of #883: poison-message redelivery cap + audit ─────────────
//
// JetStream's `max_deliver` field bounds redelivery so a poison message
// cannot wedge the consumer indefinitely. The subscriber-side audit event
// `nats.poison_dlq` gives SIEM a structured signal regardless of whether
// the optional DLQ subject is wired. The tests below cover the contract
// end-to-end: the new default of 5 attempts, the `0` legacy-compat
// escape hatch, the audit-event emission on every poison drop, and the
// `attempts` field crossing into the audit record.

/// The new default `max_deliver = 5` flows into the actual JetStream
/// consumer config — pre-#883-sub3 the default was `0` (unlimited),
/// which let a single poison message redeliver indefinitely. Verifies
/// the projection by introspecting `consumer.info()` against a live
/// JetStream server, not just the in-memory `pull::Config` (the
/// build-config unit tests cover that).
#[tokio::test]
async fn nats_subscriber_default_max_deliver_is_five_in_jetstream() {
    let server = require_nats!();

    let config = test_config(server.url(), "default-max-deliver");
    assert_eq!(
        config.max_deliver, 5,
        "default config must enable five-attempt poison cap (refs #883 sub-item 3)",
    );
    let adapter = NatsAdapter::connect(config.clone()).await.expect("connect");

    let router = Arc::new(Router::new());
    let subscriber = adapter.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let js = server.jetstream().await;
    let stream = js
        .get_stream(&config.live_stream)
        .await
        .expect("live stream exists");
    let consumer_name = format!("rustgate-sub-{}", config.instance_id);
    let mut consumer = stream
        .get_consumer::<async_nats::jetstream::consumer::pull::Config>(&consumer_name)
        .await
        .expect("consumer exists");
    let info = consumer.info().await.expect("consumer info");
    assert_eq!(
        info.config.max_deliver, 5,
        "JetStream consumer must carry the new default max_deliver=5 cap",
    );

    sub_task.abort();
}

/// Operators who need the pre-#883 unlimited-redelivery semantics back
/// must set `max_deliver = 0` explicitly. Verifies the legacy-compat
/// escape hatch reaches JetStream — a regression that mapped `0` onto
/// the new default would silently re-enable the poison cap for
/// operators who explicitly opted out.
#[tokio::test]
async fn nats_subscriber_explicit_zero_max_deliver_is_unlimited_in_jetstream() {
    let server = require_nats!();

    let mut config = test_config(server.url(), "legacy-unlimited");
    config.max_deliver = 0;
    let adapter = NatsAdapter::connect(config.clone()).await.expect("connect");

    let router = Arc::new(Router::new());
    let subscriber = adapter.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let js = server.jetstream().await;
    let stream = js
        .get_stream(&config.live_stream)
        .await
        .expect("live stream exists");
    let consumer_name = format!("rustgate-sub-{}", config.instance_id);
    let mut consumer = stream
        .get_consumer::<async_nats::jetstream::consumer::pull::Config>(&consumer_name)
        .await
        .expect("consumer exists");
    let info = consumer.info().await.expect("consumer info");
    assert!(
        info.config.max_deliver <= 0,
        "explicit max_deliver=0 must round-trip into JetStream as the unlimited sentinel \
         (server may render as 0 or -1); got {got}",
        got = info.config.max_deliver,
    );

    sub_task.abort();
}

/// The default 5-attempt cap MUST NOT break the happy path: a
/// well-formed message published to the live subject still reaches a
/// locally-registered session and is ACKed. Pinning this prevents a
/// future regression where the new default (or a refactor of the
/// drop paths) accidentally rejects valid traffic.
#[tokio::test]
async fn nats_subscriber_default_5_attempts_does_not_break_happy_path() {
    let server = require_nats!();

    let config_pub = test_config(server.url(), "happy-pub");
    let config_sub = test_config(server.url(), "happy-sub");
    assert_eq!(
        config_sub.max_deliver, 5,
        "test must run against the new five-attempt default",
    );

    let adapter_pub = NatsAdapter::connect(config_pub).await.expect("connect pub");
    let adapter_sub = NatsAdapter::connect(config_sub.clone())
        .await
        .expect("connect sub");

    let router = Arc::new(Router::new());
    let mut rx = register_session(&router, "happy-listener", "Cyan").await;

    let subscriber = adapter_sub.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let msg = position_message("happy-track", "Cyan", 37.0, -122.0);
    adapter_pub.publisher().publish(&msg).await;

    let received = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("happy-path message must arrive within 5s")
        .expect("session channel closed");
    assert_eq!(&*received.source.cn, "happy-track");

    // ACK should land within a few hundred ms — pin that the new
    // default does not leave the message sitting in ack-pending.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let js = server.jetstream().await;
    let stream = js
        .get_stream(&config_sub.live_stream)
        .await
        .expect("stream");
    let consumer_name = format!("rustgate-sub-{}", config_sub.instance_id);
    let mut consumer = stream
        .get_consumer::<async_nats::jetstream::consumer::pull::Config>(&consumer_name)
        .await
        .expect("consumer");
    let info = consumer.info().await.expect("info");
    assert_eq!(
        info.num_ack_pending, 0,
        "happy-path message must be ACKed under the new five-attempt default",
    );

    sub_task.abort();
}

/// JetStream gives up on a poison message after `max_deliver` attempts
/// rather than redelivering forever. Verifies the cap reaches
/// JetStream by manually creating a non-rustgate consumer with a
/// short ack-wait and `max_deliver = 3`, intentionally never ACKing,
/// and asserting redelivery stops at three. The subscriber's own
/// poison paths ACK explicitly so they do not exercise the
/// JetStream-side cap directly — but the cap exists for the panic
/// edge-case where the handler dies between receive and ACK, which is
/// exactly what this test simulates.
#[tokio::test]
async fn nats_subscriber_acks_after_max_delivery_attempts_to_break_redelivery_loop() {
    let server = require_nats!();

    // Use the rustgate live-stream subject space so the test exercises
    // the same JetStream config the production subscriber uses.
    let stream_name = "RUSTGATE_TEST_REDELIVERY_CAP";
    let subject = "points.REDELIVERY";

    let js = server.jetstream().await;
    // Build a stream that captures `points.>` exactly like the
    // production live stream.
    let stream = js
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: stream_name.to_string(),
            subjects: vec!["points.>".to_string()],
            retention: async_nats::jetstream::stream::RetentionPolicy::Limits,
            max_messages: 100,
            ..Default::default()
        })
        .await
        .expect("create test stream");

    // Manually create a pull consumer with `max_deliver = 3` and a
    // short `ack_wait` so redelivery cycles fit in the test budget.
    let consumer = stream
        .get_or_create_consumer(
            "redelivery-cap-test",
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some("redelivery-cap-test".to_string()),
                ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                ack_wait: Duration::from_millis(500),
                max_deliver: 3,
                deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::All,
                filter_subject: subject.to_string(),
                ..Default::default()
            },
        )
        .await
        .expect("create test consumer");

    // Publish one message; it will be delivered up to 3 times before
    // JetStream gives up.
    let _ack = js
        .publish(subject.to_string(), bytes::Bytes::from_static(b"poison"))
        .await
        .expect("publish")
        .await
        .expect("publish ack");

    // Drain the consumer for long enough that a 4th delivery would
    // have happened if the cap were not enforced. Each fetch is bounded
    // to 1 message at a time so we can count attempts. Never ACK.
    let mut attempts = 0_u32;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline && attempts < 5 {
        let mut batch = match consumer
            .batch()
            .max_messages(1)
            .expires(Duration::from_millis(700))
            .messages()
            .await
        {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Some(Ok(_msg)) = batch.next().await {
            attempts += 1;
            // Intentionally never ACK — let `ack_wait` expire so
            // JetStream redelivers (or gives up after `max_deliver`).
        }
    }

    assert_eq!(
        attempts, 3,
        "JetStream must give up after `max_deliver = 3` attempts; \
         observed {attempts} (a cap regression would yield 4+)",
    );

    // Verify the consumer's post-give-up view: after the cap fires,
    // the message is no longer in the redelivery queue, so a fresh
    // batch fetch must time out cleanly with no payload.
    let info_consumer = stream
        .get_consumer::<async_nats::jetstream::consumer::pull::Config>("redelivery-cap-test")
        .await
        .expect("consumer info");
    let mut after_cap = info_consumer
        .batch()
        .max_messages(1)
        .expires(Duration::from_millis(700))
        .messages()
        .await
        .expect("post-cap batch");
    let post_cap = timeout(Duration::from_secs(2), after_cap.next()).await;
    assert!(
        matches!(post_cap, Ok(None) | Err(_)),
        "after the cap fires, no further deliveries must arrive; got {post_cap:?}",
    );
}

/// On every poison drop, the subscriber emits the structured
/// `nats.poison_dlq` audit event. Captures the audit-target tracing
/// output via a custom `tracing_subscriber::Layer` and asserts the
/// event fires once per poison drop with the expected `subject` and
/// `reason` fields. The audit fires regardless of whether the
/// optional DLQ subject is wired — the audit trail is the security
/// record; the DLQ subject is the forensic-payload sink.
#[tokio::test]
async fn nats_poison_message_dlq_audit_event_fires() {
    use std::sync::Mutex;

    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::layer::SubscriberExt;

    let server = require_nats!();

    // Capture every audit-target event with `event_type ==
    // "nats.poison_dlq"`, recording its `subject` and `reason` fields.
    #[derive(Debug, Clone)]
    struct CapturedEvent {
        subject: String,
        reason: String,
    }

    #[derive(Default)]
    struct FieldCollector {
        event_type: Option<String>,
        subject: Option<String>,
        reason: Option<String>,
    }
    impl Visit for FieldCollector {
        fn record_str(&mut self, field: &Field, value: &str) {
            match field.name() {
                "event_type" => self.event_type = Some(value.to_string()),
                "subject" => self.subject = Some(value.to_string()),
                "reason" => self.reason = Some(value.to_string()),
                _ => {}
            }
        }
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            // tracing renders `%val` via Display through Debug; capture
            // both shapes so tests are robust to formatter choice.
            let rendered = format!("{value:?}");
            // Strip surrounding quotes that Debug adds for &str.
            let trimmed = rendered.trim_matches('"').to_string();
            match field.name() {
                "event_type" => self.event_type = Some(trimmed),
                "subject" => self.subject = Some(trimmed),
                "reason" => self.reason = Some(trimmed),
                _ => {}
            }
        }
    }

    struct CapturingLayer(Arc<Mutex<Vec<CapturedEvent>>>);
    impl<S: tracing::Subscriber> Layer<S> for CapturingLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut collector = FieldCollector::default();
            event.record(&mut collector);
            if collector.event_type.as_deref() == Some("nats.poison_dlq")
                && let (Some(subject), Some(reason)) = (collector.subject, collector.reason)
            {
                self.0
                    .lock()
                    .expect("audit capture mutex poisoned")
                    .push(CapturedEvent { subject, reason });
            }
        }
    }

    let captured: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let layer = CapturingLayer(Arc::clone(&captured))
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let sub_config = test_config(server.url(), "audit-event-sub");
    let sub_adapter = NatsAdapter::connect(sub_config).await.expect("connect sub");

    let pub_client = async_nats::connect(server.url())
        .await
        .expect("pub connect");

    let router = Arc::new(Router::new());
    let subscriber = sub_adapter.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    pub_client
        .publish(
            "points.AUDIT",
            bytes::Bytes::from_static(b"not-json-poison"),
        )
        .await
        .expect("publish poison");

    // Wait for the subscriber to process and emit the audit event.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if !captured
            .lock()
            .expect("audit capture mutex poisoned")
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let events = captured.lock().expect("audit capture mutex poisoned");
    assert_eq!(
        events.len(),
        1,
        "exactly one nats.poison_dlq audit event expected, got {}",
        events.len(),
    );
    assert_eq!(events[0].subject, "points.AUDIT");
    assert_eq!(events[0].reason, "unparseable");

    sub_task.abort();
}

/// The DLQ message wrapper carries the original subject (so a
/// forensic operator can correlate per-tenant) and JetStream's
/// stream-sequence-derived `msg_id` reaches the audit event so SIEM
/// rules can rate-limit on `(subject, msg_id)`. This test pins that
/// the audit event includes the JetStream-derived `msg_id` and
/// `attempts` fields; the DLQ wire payload coverage lives in
/// `dead_letter_publishes_unparseable_payload`.
#[tokio::test]
async fn nats_subscriber_dead_letter_payload_includes_original_subject_and_attempts() {
    use std::sync::Mutex;

    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::layer::SubscriberExt;

    let server = require_nats!();

    #[derive(Default)]
    struct PoisonAttemptsVisitor {
        event_type: Option<String>,
        subject: Option<String>,
        msg_id: Option<String>,
        attempts: Option<u64>,
    }
    impl Visit for PoisonAttemptsVisitor {
        fn record_str(&mut self, field: &Field, value: &str) {
            match field.name() {
                "event_type" => self.event_type = Some(value.to_string()),
                "subject" => self.subject = Some(value.to_string()),
                "msg_id" => self.msg_id = Some(value.to_string()),
                _ => {}
            }
        }
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            let rendered = format!("{value:?}");
            let trimmed = rendered.trim_matches('"').to_string();
            match field.name() {
                "event_type" => self.event_type = Some(trimmed),
                "subject" => self.subject = Some(trimmed),
                "msg_id" => self.msg_id = Some(trimmed),
                _ => {}
            }
        }
        fn record_u64(&mut self, field: &Field, value: u64) {
            if field.name() == "attempts" {
                self.attempts = Some(value);
            }
        }
        fn record_i64(&mut self, field: &Field, value: i64) {
            if field.name() == "attempts" {
                self.attempts = Some(value as u64);
            }
        }
    }

    #[derive(Debug, Clone)]
    struct CapturedEvent {
        subject: String,
        msg_id: String,
        attempts: u64,
    }

    struct CapturingLayer(Arc<Mutex<Vec<CapturedEvent>>>);
    impl<S: tracing::Subscriber> Layer<S> for CapturingLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = PoisonAttemptsVisitor::default();
            event.record(&mut visitor);
            if visitor.event_type.as_deref() == Some("nats.poison_dlq")
                && let (Some(subject), Some(msg_id), Some(attempts)) =
                    (visitor.subject, visitor.msg_id, visitor.attempts)
            {
                self.0
                    .lock()
                    .expect("capture mutex poisoned")
                    .push(CapturedEvent {
                        subject,
                        msg_id,
                        attempts,
                    });
            }
        }
    }

    let captured: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let layer = CapturingLayer(Arc::clone(&captured))
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber_layer = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber_layer);

    let sub_config = test_config(server.url(), "audit-attempts-sub");
    let sub_adapter = NatsAdapter::connect(sub_config).await.expect("connect sub");

    let pub_client = async_nats::connect(server.url())
        .await
        .expect("pub connect");

    let router = Arc::new(Router::new());
    let subscriber = sub_adapter.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    pub_client
        .publish("points.ATTEMPTS", bytes::Bytes::from_static(b"poison"))
        .await
        .expect("publish poison");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if !captured.lock().expect("capture mutex poisoned").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let events = captured.lock().expect("capture mutex poisoned");
    assert_eq!(events.len(), 1, "expected exactly one audit event");
    assert_eq!(events[0].subject, "points.ATTEMPTS");
    // The first delivery from a fresh JetStream consumer has
    // `delivered = 1`; the audit fires with whatever attempts value
    // the JetStream server reports at the moment the drop is taken.
    assert!(
        events[0].attempts >= 1,
        "attempts must be >= 1 (first delivery is attempt 1); got {got}",
        got = events[0].attempts,
    );
    // `msg_id` is the JetStream stream sequence rendered as a decimal
    // string. The first message published to a fresh stream gets
    // sequence 1, so the rendered token must be "1".
    assert_eq!(
        events[0].msg_id, "1",
        "first poison message in a fresh stream must surface stream-sequence 1 as msg_id",
    );

    sub_task.abort();
}

/// When `dead_letter_subject` is `None` (the default), poison messages are
/// silently dropped as before — nothing arrives on any would-be DLQ
/// subject. Guards against a regression where the DLQ helper fires
/// unconditionally and surprises operators who never opted in.
#[tokio::test]
async fn no_dead_letter_when_subject_not_configured() {
    let server = require_nats!();

    // Default config has `dead_letter_subject = None`.
    let sub_config = test_config(server.url(), "no-dlq-sub");
    assert!(
        sub_config.dead_letter_subject.is_none(),
        "default config must not enable DLQ",
    );
    let sub_adapter = NatsAdapter::connect(sub_config).await.expect("connect sub");

    let raw_client = async_nats::connect(server.url())
        .await
        .expect("raw connect");
    // Subscribe to a plausible DLQ subject anyway — if the helper ever
    // started publishing unconditionally, this subscription would catch it.
    let mut dlq_sub = raw_client
        .subscribe("rustgate.dlq")
        .await
        .expect("subscribe DLQ");

    let pub_client = async_nats::connect(server.url())
        .await
        .expect("pub connect");

    let router = Arc::new(Router::new());
    let subscriber = sub_adapter.subscriber();
    let sub_router = Arc::clone(&router);
    let sub_task = tokio::spawn(async move {
        let _ = subscriber.run(sub_router).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    pub_client
        .publish("points.ALPHA", bytes::Bytes::from_static(b"not-json"))
        .await
        .expect("publish poison");

    let result = timeout(Duration::from_secs(2), dlq_sub.next()).await;
    assert!(
        result.is_err(),
        "no DLQ traffic expected when dead_letter_subject is unset",
    );

    sub_task.abort();
}
