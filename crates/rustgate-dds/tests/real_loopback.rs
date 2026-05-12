// Copyright © 2026 Roberto Chiofalo.

//! End-to-end loopback test for the real DDS bridge.
//!
//! Two [`RealDdsBridge`] instances are constructed on the same DDS
//! domain and exchange a sample over the RTPS wire (multicast on
//! loopback). The test exercises the full publish → discovery →
//! subscribe matching → sample delivery chain through rustdds.
//!
//! ## Why this is gated
//!
//! Real DDS discovery uses UDP multicast on the loopback interface.
//! Most CI runners allow this, but a hardened container (no UDP
//! multicast, no IPv4 multicast routes) will fail to match the two
//! participants. To keep CI deterministic across runner classes, the
//! tests in this file are `#[ignore]` by default; run them locally
//! with `cargo test -p rustgate-dds --features dds-real -- --ignored`.
//!
//! CI runs the lighter `tests/wiring.rs` mock-bridge tests on every
//! PR and these real-bridge tests only on the nightly extended job
//! (a follow-up wires that — for now this file is the doc that the
//! tests exist and how to invoke them locally).

#![cfg(feature = "dds-real")]
#![allow(clippy::panic, clippy::unwrap_used)]

use std::time::{Duration, SystemTime};

use bytes::Bytes;
use futures::StreamExt;
use rustgate_dds::bridge::{DdsBridge, DdsSample, QosProfile};
use rustgate_dds::real::RealDdsBridge;

/// A unique-ish domain ID derived from process state so concurrent
/// test runs of this file (or alongside other DDS-using projects on
/// the same host) don't bleed into each other. ROS 2 reserves
/// domain 0 by convention; we pick an unprivileged high domain.
fn test_domain_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    // The DDS spec caps domain IDs at 232 (port number 0 - 65535 vs
    // RTPS port formula); we stay well under that.
    100 + COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The bridge constructs cleanly on every host — this doesn't
/// require the discovery path to find anything, so it runs in
/// regular CI alongside the mock tests. It exercises participant
/// creation, the QoS mapping path, topic registration, and writer
/// creation but never blocks waiting for a peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_bridge_construction_and_publish_no_subscriber() {
    let domain = test_domain_id();
    let bridge = RealDdsBridge::new(domain).expect("create participant");
    assert_eq!(bridge.domain_id(), domain);

    // Publish a sample with no subscriber attached. DDS publishers
    // are fire-and-forget under BestEffort QoS — the call should
    // succeed regardless of whether anyone's listening. This proves
    // the topic-create + writer-create + write code path is wired
    // correctly without requiring a discovery round-trip.
    let sample = DdsSample {
        topic: "rustgate.test.PublishNoSub".to_string(),
        source_guid: [0x01; 16],
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        payload: Bytes::from_static(b"{\"hello\":\"world\"}"),
    };
    bridge
        .publish_sample("rustgate.test.PublishNoSub", sample)
        .await
        .expect("publish should succeed with no subscribers");

    bridge.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires UDP multicast on loopback"]
async fn real_bridge_round_trip_one_sample() {
    let domain = test_domain_id();
    let publisher = RealDdsBridge::new(domain).expect("create publisher participant");
    let subscriber = RealDdsBridge::new(domain).expect("create subscriber participant");

    let mut sub_stream = subscriber
        .subscribe_topic("rustgate.test.RoundTrip", QosProfile::TELEMETRY)
        .await
        .expect("subscribe");

    // RTPS discovery is asynchronous — give the two participants a
    // moment to find each other before publishing.
    tokio::time::sleep(Duration::from_millis(750)).await;

    let sent = DdsSample {
        topic: "rustgate.test.RoundTrip".to_string(),
        source_guid: [0xab; 16],
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        payload: Bytes::from_static(b"{\"hello\":\"dds\"}"),
    };
    publisher
        .publish_sample("rustgate.test.RoundTrip", sent.clone())
        .await
        .expect("publish");

    // Wait up to 5 seconds for the sample to arrive — typical
    // loopback latency is 5-50 ms, but the discovery handshake on a
    // cold participant takes longer.
    let received = tokio::time::timeout(Duration::from_secs(5), sub_stream.next())
        .await
        .expect("subscribe timed out")
        .expect("subscribe stream closed");

    assert_eq!(received.topic, sent.topic);
    assert_eq!(received.source_guid, sent.source_guid);
    assert_eq!(received.payload, sent.payload);
    assert_eq!(received.timestamp, sent.timestamp);

    publisher.shutdown().await.unwrap();
    subscriber.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires UDP multicast on loopback"]
async fn real_bridge_reliable_qos_round_trip() {
    // Same as the telemetry round-trip, but with Reliable +
    // TransientLocal QoS to exercise the reliable history buffer.
    let domain = test_domain_id();
    let publisher = RealDdsBridge::new(domain).unwrap();
    let subscriber = RealDdsBridge::new(domain).unwrap();

    let mut sub_stream = subscriber
        .subscribe_topic("rustgate.test.Reliable", QosProfile::COMMAND)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(750)).await;

    for i in 0..5u32 {
        let sample = DdsSample {
            topic: "rustgate.test.Reliable".to_string(),
            source_guid: [i as u8; 16],
            timestamp: SystemTime::now(),
            payload: Bytes::from(format!("seq={i}")),
        };
        publisher
            .publish_sample("rustgate.test.Reliable", sample)
            .await
            .unwrap();
    }

    let mut received = Vec::new();
    for _ in 0..5 {
        let s = tokio::time::timeout(Duration::from_secs(2), sub_stream.next())
            .await
            .expect("timed out")
            .expect("stream closed");
        received.push(s);
    }
    assert_eq!(received.len(), 5);
    publisher.shutdown().await.unwrap();
    subscriber.shutdown().await.unwrap();
}
