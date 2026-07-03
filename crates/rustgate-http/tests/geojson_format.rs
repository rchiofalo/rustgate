// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the GeoJSON ([RFC 7946]) HTTP egress format.
//!
//! Validates the on-the-wire shape end-to-end through the publisher
//! and a wiremock receiver: the per-message Feature, the
//! FeatureCollection batch envelope, and the IANA-registered
//! `application/geo+json` content-type.
//!
//! [RFC 7946]: https://datatracker.ietf.org/doc/html/rfc7946

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_http::HttpPublisher;
use rustgate_http::config::{HttpConfig, PayloadFormat, TargetConfig};
use serde_json::Value;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const COT_POSITION: &[u8] = br#"<event version="2.0" uid="ALPHA-1" type="a-f-G-U-C" time="2026-01-01T00:00:00Z" start="2026-01-01T00:00:00Z" stale="2026-01-01T01:00:00Z" how="m-g"><point lat="38.8977" lon="-77.0365" hae="100.5" ce="9999999" le="9999999"/><detail><__group name="Cyan" role="Team Member"/><contact callsign="ALPHA-1"/></detail></event>"#;

fn make_msg(payload: &[u8], cn: &str, msg_type: MessageType) -> RoutableMessage {
    RoutableMessage {
        source: Identity {
            cn: cn.into(),
            fingerprint: Default::default(),
            groups: {
                let mut s = BTreeSet::new();
                let _ = s.insert("blue".to_string());
                s
            },
            tenant: None,
            spiffe_id: None,
            attributes: Arc::new(Default::default()),
        },
        destination: Destination::Broadcast,
        payload: Bytes::from(payload.to_vec()),
        metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), msg_type),
        entity: None,
    }
}

fn target_config(name: &str, url: &str) -> TargetConfig {
    TargetConfig {
        name: name.to_string(),
        url: url.to_string(),
        method: None,
        auth: None,
        tls: None,
        timeout_secs: Some(5),
        format: Some(PayloadFormat::GeoJson),
        filter: None,
        retry: None,
        enabled: None,
        headers: None,
        max_payload_bytes: None,
        rate_limit_per_sec: None,
        capture_response_body: None,
        max_response_body_bytes: None,
        batch_enabled: None,
        batch_max_messages: None,
        batch_max_bytes: None,
        batch_format: None,
    }
}

fn http_config(targets: Vec<TargetConfig>) -> HttpConfig {
    HttpConfig {
        instance_id: Some("test-instance".to_string()),
        targets,
        dlq_dir: None,
        dlq_key_file: None,
        dlq_max_bytes: None,
        dlq_max_target_bytes: None,
        allow_private_urls: true,
    }
}

#[tokio::test]
async fn per_message_feature_emits_geo_plus_json_content_type() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/geojson"))
        .and(header("content-type", "application/geo+json"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "geo-test",
        &format!("{}/geojson", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg(COT_POSITION, "alpha-operator", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn per_message_feature_body_is_rfc7946_feature_with_point_geometry() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/geojson"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "geo-shape",
        &format!("{}/geojson", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg(COT_POSITION, "alpha-operator", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;

    // Inspect the received request body.
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req: &Request = &received[0];
    let parsed: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(parsed["type"], "Feature");
    assert_eq!(parsed["geometry"]["type"], "Point");
    let coords = parsed["geometry"]["coordinates"].as_array().unwrap();
    // RFC 7946 §3.1.1: `[longitude, latitude, altitude]`
    assert!((coords[0].as_f64().unwrap() - (-77.0365)).abs() < 1e-9);
    assert!((coords[1].as_f64().unwrap() - 38.8977).abs() < 1e-9);
    assert!((coords[2].as_f64().unwrap() - 100.5).abs() < 1e-9);
    // Round-trip-safe properties.
    assert_eq!(parsed["properties"]["source_cn"], "alpha-operator");
    assert_eq!(parsed["properties"]["cot_uid"], "ALPHA-1");
    assert_eq!(parsed["properties"]["cot_type"], "a-f-G-U-C");
    assert_eq!(parsed["properties"]["instance_id"], "test-instance");
}

#[tokio::test]
async fn batched_geojson_emits_feature_collection_envelope() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/collect"))
        .and(header("content-type", "application/geo+json"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let mut tc = target_config("geo-batch", &format!("{}/collect", server.uri()));
    tc.batch_enabled = Some(true);
    tc.batch_max_messages = Some(3);
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    // Push three messages; the third triggers a Count flush.
    for cn in ["alpha", "bravo", "charlie"] {
        publisher.publish(&make_msg(COT_POSITION, cn, MessageType::Position));
    }

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    publisher.shutdown().await;

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let parsed: Value = serde_json::from_slice(&received[0].body).unwrap();
    assert_eq!(parsed["type"], "FeatureCollection");
    let features = parsed["features"].as_array().unwrap();
    assert_eq!(
        features.len(),
        3,
        "all three messages framed in one collection"
    );
    for feat in features {
        assert_eq!(feat["type"], "Feature");
        assert_eq!(feat["geometry"]["type"], "Point");
    }
    // Order preservation — first feature is `alpha`, last is `charlie`.
    assert_eq!(features[0]["properties"]["source_cn"], "alpha");
    assert_eq!(features[2]["properties"]["source_cn"], "charlie");
}

#[tokio::test]
async fn non_cot_payload_emits_feature_with_null_geometry() {
    // RFC 7946 §3.2 explicitly permits a Feature with `geometry: null`.
    // Pin the end-to-end behaviour so a non-CoT payload (e.g. a chat
    // message proxied through the GeoJSON target) does not break the
    // GIS-tool consumer.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/null-geom"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "null-geom-test",
        &format!("{}/null-geom", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg(b"not-cot-just-bytes", "alpha-operator", MessageType::Chat);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let parsed: Value = serde_json::from_slice(&received[0].body).unwrap();
    assert_eq!(parsed["type"], "Feature");
    assert!(parsed["geometry"].is_null());
    assert_eq!(parsed["properties"]["message_type"], "chat");
    // CoT-derived keys must be absent — consumers guard on `cot_uid`
    // presence to distinguish "had spatial info" from "did not".
    assert!(parsed["properties"].get("cot_uid").is_none());
}
