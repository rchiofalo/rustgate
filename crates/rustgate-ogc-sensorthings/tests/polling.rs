// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the OGC SensorThings v1.0 polling client.
//!
//! Drives a real `reqwest::Client` against a `wiremock`-served
//! SensorThings response and asserts that:
//!
//! 1. The polling URL contains the expected `?$top=`,
//!    `?$expand=…`, and (after the first poll) `?$filter=…` clauses.
//! 2. The response decodes through the typed `ObservationsPage`
//!    shape.
//! 3. The mapper produces an `Entity` whose `position` is populated
//!    from the `?$expand=Datastream/Thing/Locations` payload.
//! 4. The wiring's projection emits a `RoutableMessage` whose
//!    `source_protocol` is `"ogc-sensorthings"` and whose payload
//!    decodes back to the same `Entity`.
//! 5. The client surfaces a non-success HTTP status as the
//!    `HttpStatus` error variant rather than panicking.
//!
//! These tests intentionally exercise the public client API plus
//! the wiring's `observation_to_message_for_test` helper so the
//! shape that hits the router is pinned end-to-end.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use rustgate_core::entity::EntityKind;
use rustgate_core::message::{Destination, MessageType};
use rustgate_ogc_sensorthings::config::{EntityKindTag, SensorThingsConfig, Subscription};
use rustgate_ogc_sensorthings::wiring::{SOURCE_OGC_SENSORTHINGS, testing};
use rustgate_ogc_sensorthings::{SensorThingsClient, SensorThingsError};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const FIXTURE_RESPONSE: &str = r#"{
    "@iot.count": 1,
    "value": [
        {
            "@iot.id": 7,
            "@iot.selfLink": "https://example.org/SensorThings/v1.0/Observations(7)",
            "phenomenonTime": "2026-05-08T10:30:00Z",
            "resultTime": "2026-05-08T10:30:01Z",
            "result": 23.5,
            "Datastream": {
                "@iot.id": 42,
                "name": "Air Temperature",
                "description": "outdoor air temp at met tower #5",
                "unitOfMeasurement": { "symbol": "degC", "name": "degree Celsius" },
                "Thing": {
                    "@iot.id": 99,
                    "name": "Met Tower 5",
                    "description": "fixed met tower at Pier 9",
                    "Locations": [
                        {
                            "@iot.id": 1001,
                            "name": "Pier 9",
                            "encodingType": "application/vnd.geo+json",
                            "location": {
                                "type": "Point",
                                "coordinates": [-77.0365, 38.8977, 12.5]
                            }
                        }
                    ]
                }
            }
        }
    ]
}"#;

fn config_with_endpoint(endpoint: &str) -> SensorThingsConfig {
    SensorThingsConfig {
        endpoint: endpoint.to_string(),
        auth_token_path: None,
        poll_interval_secs: 30,
        request_timeout_secs: 10,
        expand_location: true,
        subscriptions: vec![Subscription {
            datastream_id: 42,
            entity_kind: EntityKindTag::Sensor,
            group: Some("weather".into()),
            poll_interval_secs: None,
            page_size: Some(50),
        }],
        #[cfg(feature = "mqtt-push")]
        mqtt_push: None,
    }
}

#[tokio::test]
async fn one_polling_cycle_decodes_observation_and_projects_to_entity() {
    let server = MockServer::start().await;
    // wiremock decodes `+` in query strings as a literal space when
    // matching `query_param`, so the expected value here is the
    // decoded form. The on-the-wire URL still carries the `+` shape
    // (composed by `SensorThingsClient::build_url`).
    Mock::given(method("GET"))
        .and(path("/SensorThings/v1.0/Datastreams(42)/Observations"))
        .and(query_param("$top", "50"))
        .and(query_param("$orderby", "phenomenonTime asc"))
        .and(query_param("$expand", "Datastream/Thing/Locations"))
        .respond_with(ResponseTemplate::new(200).set_body_string(FIXTURE_RESPONSE))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = config_with_endpoint(&format!("{}/SensorThings/v1.0", server.uri()));
    let client = SensorThingsClient::new(&cfg, None).expect("build client");

    let page = client.poll(42, 50, None).await.expect("poll succeeds");
    assert_eq!(page.value.len(), 1, "fixture has one observation");
    let obs = &page.value[0];
    assert_eq!(obs.iot_id, 7);

    // Project through the wiring's helper to pin the
    // RoutableMessage shape that would reach the router.
    let sub = &cfg.subscriptions[0];
    let msg = testing::observation_to_message_for_test(obs, EntityKind::Sensor, sub)
        .expect("identity built");
    assert_eq!(msg.metadata.source_protocol, SOURCE_OGC_SENSORTHINGS);
    assert_eq!(msg.metadata.message_type, MessageType::Status);
    match &msg.destination {
        Destination::Group(g) => assert_eq!(g.as_ref(), "weather"),
        other => panic!("expected Group destination, got {:?}", other),
    }

    let entity = testing::decode_entity_payload(&msg);
    assert_eq!(entity.uid, "sensorthings-observation-7");
    assert_eq!(entity.kind, EntityKind::Sensor);
    assert_eq!(entity.callsign.as_deref(), Some("Air Temperature"));
    let position = entity.position.expect("position projected from $expand");
    assert!((position.lat - 38.8977).abs() < 1e-9, "lat must round-trip");
    assert!(
        (position.lon - (-77.0365)).abs() < 1e-9,
        "lon must round-trip"
    );
    assert_eq!(position.hae_meters, Some(12.5));
}

#[tokio::test]
async fn polling_with_since_cursor_includes_filter_clause() {
    let server = MockServer::start().await;
    let since = "2026-05-08T10:00:00Z";
    Mock::given(method("GET"))
        .and(path("/SensorThings/v1.0/Datastreams(42)/Observations"))
        .and(query_param("$top", "100"))
        .and(query_param(
            "$filter",
            format!("phenomenonTime gt {since}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"value":[]}"#))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = SensorThingsConfig {
        endpoint: format!("{}/SensorThings/v1.0", server.uri()),
        auth_token_path: None,
        poll_interval_secs: 30,
        request_timeout_secs: 10,
        expand_location: false,
        subscriptions: vec![],
        #[cfg(feature = "mqtt-push")]
        mqtt_push: None,
    };
    let client = SensorThingsClient::new(&cfg, None).expect("build");
    let page = client.poll(42, 100, Some(since)).await.expect("poll");
    assert!(
        page.value.is_empty(),
        "fixture intentionally returns an empty page so the test pins the URL shape"
    );
}

#[tokio::test]
async fn http_500_surfaces_as_http_status_variant() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/SensorThings/v1.0/Datastreams(42)/Observations"))
        .respond_with(ResponseTemplate::new(500).set_body_string("server is sad"))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = SensorThingsConfig {
        endpoint: format!("{}/SensorThings/v1.0", server.uri()),
        auth_token_path: None,
        poll_interval_secs: 30,
        request_timeout_secs: 10,
        expand_location: false,
        subscriptions: vec![],
        #[cfg(feature = "mqtt-push")]
        mqtt_push: None,
    };
    let client = SensorThingsClient::new(&cfg, None).expect("build");
    let err = client
        .poll(42, 100, None)
        .await
        .expect_err("server returned 500");
    match err {
        SensorThingsError::HttpStatus { status, message } => {
            assert_eq!(status, 500);
            assert!(
                message.contains("server is sad"),
                "captured message must include body, got {message}"
            );
        }
        other => panic!("expected HttpStatus, got {:?}", other),
    }
    assert!(
        SensorThingsError::HttpStatus {
            status: 500,
            message: String::new(),
        }
        .is_transient(),
        "5xx must classify as transient"
    );
}

#[tokio::test]
async fn http_404_classifies_as_non_transient() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/SensorThings/v1.0/Datastreams(42)/Observations"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = SensorThingsConfig {
        endpoint: format!("{}/SensorThings/v1.0", server.uri()),
        auth_token_path: None,
        poll_interval_secs: 30,
        request_timeout_secs: 10,
        expand_location: false,
        subscriptions: vec![],
        #[cfg(feature = "mqtt-push")]
        mqtt_push: None,
    };
    let client = SensorThingsClient::new(&cfg, None).expect("build");
    let err = client
        .poll(42, 100, None)
        .await
        .expect_err("server returned 404");
    assert!(
        !err.is_transient(),
        "404 must classify as non-transient (operator action required)"
    );
}

#[tokio::test]
async fn malformed_response_body_surfaces_as_decode_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/SensorThings/v1.0/Datastreams(42)/Observations"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not valid JSON"))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = SensorThingsConfig {
        endpoint: format!("{}/SensorThings/v1.0", server.uri()),
        auth_token_path: None,
        poll_interval_secs: 30,
        request_timeout_secs: 10,
        expand_location: false,
        subscriptions: vec![],
        #[cfg(feature = "mqtt-push")]
        mqtt_push: None,
    };
    let client = SensorThingsClient::new(&cfg, None).expect("build");
    let err = client
        .poll(42, 100, None)
        .await
        .expect_err("body is not JSON");
    match err {
        SensorThingsError::Decode { .. } => {}
        other => panic!("expected Decode, got {:?}", other),
    }
    assert!(
        !err.is_transient(),
        "decode failures are not retried at the same cadence"
    );
}

#[tokio::test]
async fn bearer_token_is_attached_to_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/SensorThings/v1.0/Datastreams(42)/Observations"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer test-token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"value":[]}"#))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = SensorThingsConfig {
        endpoint: format!("{}/SensorThings/v1.0", server.uri()),
        auth_token_path: None,
        poll_interval_secs: 30,
        request_timeout_secs: 10,
        expand_location: false,
        subscriptions: vec![],
        #[cfg(feature = "mqtt-push")]
        mqtt_push: None,
    };
    let client =
        SensorThingsClient::new(&cfg, Some(Arc::from("test-token"))).expect("build with token");
    let _ = client.poll(42, 100, None).await.expect("poll succeeds");
}

#[tokio::test]
async fn poll_request_timeout_surfaces_as_transient_error() {
    // Force the configured per-request timeout to elapse before
    // wiremock responds. The fixture sleeps 500ms; the client
    // timeout is 100ms.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/SensorThings/v1.0/Datastreams(42)/Observations"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"value":[]}"#)
                .set_delay(Duration::from_millis(500)),
        )
        .mount(&server)
        .await;

    // Build a client with a sub-second timeout via `from_parts` —
    // the config validator's `secs > 0` check would reject the
    // millisecond-grained value the test needs.
    let inner = reqwest::Client::builder()
        .timeout(Duration::from_millis(100))
        .build()
        .expect("inner client");
    let client = SensorThingsClient::from_parts(
        inner,
        format!("{}/SensorThings/v1.0", server.uri()),
        false,
        None,
        Duration::from_millis(100),
    );
    let err = client.poll(42, 100, None).await.expect_err("timeout");
    // Some reqwest builds classify the elapsed deadline as
    // `Transport { source.is_timeout() = true }` rather than the
    // typed `Timeout` variant. Both are acceptable as long as
    // the transient classifier returns `true`.
    match &err {
        SensorThingsError::Timeout { .. } | SensorThingsError::Transport { .. } => {}
        other => panic!("expected Timeout/Transport, got {:?}", other),
    }
    assert!(err.is_transient(), "timeouts are transient");
}
