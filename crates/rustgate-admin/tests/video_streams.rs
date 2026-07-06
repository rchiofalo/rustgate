// Copyright © 2026 Roberto Chiofalo.

#![cfg(feature = "video")]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the CoT `b-i-v` video stream catalog (#862).
//!
//! The catalog is wired in via [`rustgate_router::Router::set_on_routed`]
//! so the realistic shape of the test is: spin up a router, install the
//! catalog observer, push a synthetic `b-i-v` message through
//! `route_for_egress`, then snapshot the catalog and assert the entry
//! shows up. A second test exercises the lazy TTL eviction path by
//! advancing the catalog past an expired entry.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_admin::VideoStreamCatalog;
use rustgate_admin::video::{handler, router_callback};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::Router;

fn synth_b_i_v_msg(uid: &str, url: &str, ttl: Option<Duration>) -> RoutableMessage {
    let identity = Identity::plaintext("alpha-cn".to_string(), BTreeSet::new()).unwrap();
    let payload = format!(
        r#"<event uid="{uid}" type="b-i-v-r" version="2.0">
            <point lat="35.5" lon="-100.2" hae="120.0"/>
            <detail>
              <__video url="{url}"/>
              <sensor type="EO" fov="42.5" azimuth="180.0" elevation="-15.0"/>
              <contact callsign="Drone-Alpha"/>
            </detail>
          </event>"#
    );
    let mut meta = Metadata::new(
        SystemTime::now(),
        "tcp".to_string(),
        MessageType::Other("b-i-v-r".to_string()),
    );
    if let Some(t) = ttl {
        meta = meta.with_ttl(t);
    }
    RoutableMessage {
        source: identity,
        destination: Destination::Broadcast,
        payload: Bytes::from(payload),
        metadata: meta,
        entity: None,
    }
}

#[tokio::test]
async fn router_routed_callback_populates_catalog() {
    let catalog = Arc::new(VideoStreamCatalog::new());
    let router = Router::new();
    router.set_on_routed(Some(router_callback(Arc::clone(&catalog))));

    let msg = synth_b_i_v_msg("VID-X1", "rtsp://10.0.0.1:8554/feed", None);
    // route_for_egress must return Some(_) for the post-route observer
    // to fire — Broadcast routing succeeds on a default router because
    // the lack of subscribers is not a routing failure (still admitted).
    let _ = router.route_for_egress(msg).await;

    // Allow the lock-free callback path to settle before snapshotting.
    let snap = catalog.snapshot();
    assert_eq!(snap.len(), 1, "expected one entry after routing");
    let entry = &snap[0];
    assert_eq!(entry.uid, "VID-X1");
    assert_eq!(entry.source_cn, "alpha-cn");
    assert_eq!(entry.event_type, "b-i-v-r");
    assert_eq!(
        entry.stream_url.as_deref(),
        Some("rtsp://10.0.0.1:8554/feed")
    );
    assert_eq!(entry.sensor_fov, Some(42.5));
    assert_eq!(entry.lat, Some(35.5));
    assert_eq!(entry.lon, Some(-100.2));
}

#[tokio::test]
async fn handler_serves_routed_entries_as_json() {
    use http_body_util::BodyExt;
    use hyper::Method;

    let catalog = Arc::new(VideoStreamCatalog::new());
    let router = Router::new();
    router.set_on_routed(Some(router_callback(Arc::clone(&catalog))));
    let _ = router
        .route_for_egress(synth_b_i_v_msg("VID-A", "rtsp://a", None))
        .await;
    let _ = router
        .route_for_egress(synth_b_i_v_msg("VID-B", "rtsp://b", None))
        .await;

    let h = handler(Arc::clone(&catalog));
    let resp = h(&Method::GET, "/api/video/streams", b"").expect("matched");
    assert_eq!(resp.status(), hyper::StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = parsed.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    let uids: Vec<&str> = arr
        .iter()
        .map(|v| v["uid"].as_str().unwrap_or(""))
        .collect();
    assert!(uids.contains(&"VID-A"));
    assert!(uids.contains(&"VID-B"));
}

#[tokio::test]
async fn ttl_evicts_stale_entries_on_snapshot() {
    let catalog = Arc::new(VideoStreamCatalog::new());
    let router = Router::new();
    router.set_on_routed(Some(router_callback(Arc::clone(&catalog))));

    // 1ns TTL — guaranteed expired by the time we snapshot.
    let _ = router
        .route_for_egress(synth_b_i_v_msg(
            "VID-EXP",
            "rtsp://expired",
            Some(Duration::from_nanos(1)),
        ))
        .await;
    // Sleep long enough that the wall-clock has advanced past the TTL.
    tokio::time::sleep(Duration::from_millis(10)).await;

    // The lazy-eviction snapshot path drops the expired entry.
    let snap = catalog.snapshot();
    assert!(
        snap.is_empty(),
        "expired entry should have been evicted on snapshot"
    );
}

#[tokio::test]
async fn non_video_messages_do_not_populate_catalog() {
    let catalog = Arc::new(VideoStreamCatalog::new());
    let router = Router::new();
    router.set_on_routed(Some(router_callback(Arc::clone(&catalog))));

    let identity = Identity::plaintext("alpha".to_string(), BTreeSet::new()).unwrap();
    let payload = r#"<event uid="X" type="a-f-G"><point lat="0" lon="0" hae="0"/></event>"#;
    let msg = RoutableMessage {
        source: identity,
        destination: Destination::Broadcast,
        payload: Bytes::from(payload),
        metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), MessageType::Position),
        entity: None,
    };
    let _ = router.route_for_egress(msg).await;

    assert!(catalog.snapshot().is_empty());
}
