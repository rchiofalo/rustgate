// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the HTTP egress publisher using wiremock.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_http::HttpPublisher;
use rustgate_http::config::{HttpConfig, TargetConfig};
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_msg(cn: &str, protocol: &str, msg_type: MessageType) -> RoutableMessage {
    RoutableMessage {
        source: Identity {
            cn: cn.into(),
            fingerprint: Default::default(),
            groups: {
                let mut s = BTreeSet::new();
                let _ = s.insert("alpha".to_string());
                s
            },
            tenant: None,
            spiffe_id: None,
            attributes: Arc::new(Default::default()),
        },
        destination: Destination::Broadcast,
        payload: Bytes::from_static(b"<event uid='test-1'/>"),
        metadata: Metadata::new(SystemTime::now(), protocol.to_string(), msg_type),
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
        format: None,
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
        allow_private_urls: true, // wiremock binds to 127.0.0.1
    }
}

#[tokio::test]
async fn publish_to_single_target() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "test",
        &format!("{}/webhook", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    // Allow time for async dispatch
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn publish_json_format() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "json-test",
        &format!("{}/api", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("bob", "tcp", MessageType::Alert);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn publish_raw_xml_format() {
    use rustgate_http::config::PayloadFormat;

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("content-type", "application/xml"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let mut tc = target_config("xml-test", &format!("{}/xml", server.uri()));
    tc.format = Some(PayloadFormat::RawXml);
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("carol", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn echo_prevention_blocks_http_protocol() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0) // Should NOT receive anything
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "echo-test",
        &format!("{}/hook", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    // Message from HTTP protocol should be echo-prevented
    let msg = make_msg("alice", "http", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn filter_excludes_non_matching_groups() {
    use rustgate_http::config::FilterConfig;

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0) // Filtered out
        .mount(&server)
        .await;

    let mut tc = target_config("filtered", &format!("{}/hook", server.uri()));
    tc.filter = Some(FilterConfig {
        groups: Some(vec!["bravo".to_string()]),
        message_types: None,
        source_cns: None,
        exclude_protocols: None,
    });
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    // Sender is in "alpha" group, filter requires "bravo"
    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn retry_on_5xx() {
    let server = MockServer::start().await;

    // First two requests return 503, third succeeds
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut tc = target_config("retry-test", &format!("{}/api", server.uri()));
    tc.retry = Some(rustgate_http::config::RetryConfig {
        max_attempts: Some(3),
        backoff_base_secs: Some(0), // No delay in tests
        circuit_breaker_threshold: Some(10),
        circuit_breaker_cooldown_secs: Some(60),
        half_open_max_probes: None,
        half_open_success_threshold: None,
    });
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn no_retry_on_4xx() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1) // Only one attempt — no retry on 4xx
        .mount(&server)
        .await;

    let mut tc = target_config("no-retry", &format!("{}/api", server.uri()));
    tc.retry = Some(rustgate_http::config::RetryConfig {
        max_attempts: Some(3),
        backoff_base_secs: Some(0),
        circuit_breaker_threshold: Some(10),
        circuit_breaker_cooldown_secs: Some(60),
        half_open_max_probes: None,
        half_open_success_threshold: None,
    });
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn disabled_target_skipped() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1) // Only enabled target should receive
        .mount(&server)
        .await;

    let enabled = target_config("enabled", &format!("{}/hook", server.uri()));
    let mut disabled = target_config("disabled", &format!("{}/hook", server.uri()));
    disabled.enabled = Some(false);

    let config = http_config(vec![enabled, disabled]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn multiple_targets_fan_out() {
    let server1 = MockServer::start().await;
    let server2 = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server1)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server2)
        .await;

    let config = http_config(vec![
        target_config("target-a", &format!("{}/hook", server1.uri())),
        target_config("target-b", &format!("{}/hook", server2.uri())),
    ]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn custom_headers_sent() {
    use rustgate_http::config::HeaderEntry;

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("x-api-version", "2"))
        .and(header("x-tenant", "alpha"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let mut tc = target_config("headers-test", &format!("{}/api", server.uri()));
    tc.headers = Some(vec![
        HeaderEntry {
            name: "X-API-Version".to_string(),
            value: "2".to_string(),
        },
        HeaderEntry {
            name: "X-Tenant".to_string(),
            value: "alpha".to_string(),
        },
    ]);
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn instance_id_header_present() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("x-rustgate-instance", "test-instance"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "instance-test",
        &format!("{}/hook", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn bearer_auth_header_present() {
    use rustgate_http::config::AuthConfig;

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("authorization", "Bearer test-token-123"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    // Write a temp token file with owner-only permissions
    let dir = std::env::temp_dir().join("rustgate-http-integ");
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("bearer-token");
    std::fs::write(&token_path, "test-token-123\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut tc = target_config("bearer-test", &format!("{}/api", server.uri()));
    tc.auth = Some(AuthConfig::Bearer {
        token_file: token_path.to_str().unwrap().to_string(),
    });
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = std::fs::remove_file(&token_path);
}

#[tokio::test]
async fn hmac_signature_present() {
    use rustgate_http::config::AuthConfig;

    let server = MockServer::start().await;

    // Verify both the signature and the replay-prevention timestamp header
    Mock::given(method("POST"))
        .and(wiremock::matchers::header_exists("x-signature-256"))
        .and(wiremock::matchers::header_exists("x-rustgate-timestamp"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let dir = std::env::temp_dir().join("rustgate-http-integ");
    std::fs::create_dir_all(&dir).unwrap();
    let secret_path = dir.join("hmac-secret");
    std::fs::write(&secret_path, "test-hmac-key").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut tc = target_config("hmac-test", &format!("{}/webhook", server.uri()));
    tc.auth = Some(AuthConfig::Hmac {
        secret_file: secret_path.to_str().unwrap().to_string(),
        header: None,
    });
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = std::fs::remove_file(&secret_path);
}

#[tokio::test]
async fn circuit_breaker_opens_after_threshold() {
    let server = MockServer::start().await;

    // All requests return 500
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let mut tc = target_config("circuit-test", &format!("{}/api", server.uri()));
    tc.retry = Some(rustgate_http::config::RetryConfig {
        max_attempts: Some(1), // No retries — fail immediately
        backoff_base_secs: Some(0),
        circuit_breaker_threshold: Some(2), // Open after 2 failures
        circuit_breaker_cooldown_secs: Some(300),
        half_open_max_probes: None,
        half_open_success_threshold: None,
    });
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    assert!(publisher.is_healthy());

    // Send 2 messages to trip the circuit breaker
    for _ in 0..2 {
        let msg = make_msg("alice", "tcp", MessageType::Position);
        publisher.publish(&msg);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // Circuit should now be open
    assert!(!publisher.is_healthy());

    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn graceful_shutdown_drains_queue() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "drain-test",
        &format!("{}/hook", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    // Immediately shut down — pending messages should still be delivered
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    // wiremock expect(1) will panic on drop if the request wasn't received
}

#[tokio::test]
async fn is_healthy_reflects_circuit_state() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "health-test",
        &format!("{}/hook", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    // Initially healthy (all circuits closed)
    assert!(publisher.is_healthy());

    publisher.shutdown().await;
}

#[tokio::test]
async fn content_digest_header_present() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header_exists("content-digest"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "digest-test",
        &format!("{}/hook", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn delivery_id_stable_across_retries() {
    let server = MockServer::start().await;

    // First request fails with 503, second succeeds — both should carry
    // the same X-Rustgate-Delivery-Id (stable idempotency key).
    Mock::given(method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(503))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let mut tc = target_config("retry-id-test", &format!("{}/hook", server.uri()));
    tc.retry = Some(rustgate_http::config::RetryConfig {
        max_attempts: Some(3),
        backoff_base_secs: Some(0),
        ..Default::default()
    });
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify both requests were received (wiremock expect guards handle this)
    let received = server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        2,
        "expected 2 requests (1 retry + 1 success)"
    );

    // Both should have the same delivery ID
    let id1 = received[0]
        .headers
        .get("x-rustgate-delivery-id")
        .expect("missing delivery ID on request 1")
        .to_str()
        .unwrap()
        .to_string();
    let id2 = received[1]
        .headers
        .get("x-rustgate-delivery-id")
        .expect("missing delivery ID on request 2")
        .to_str()
        .unwrap()
        .to_string();

    assert_eq!(id1, id2, "delivery ID should be stable across retries");
    assert_eq!(id1.len(), 32, "delivery ID should be 32-char hex");
}

#[tokio::test]
async fn rate_limiting_sheds_excess_traffic() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut tc = target_config("rate-test", &format!("{}/hook", server.uri()));
    // Very low rate: 1 request/sec with burst of 1
    tc.rate_limit_per_sec = Some(1.0);
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    // Fire 10 messages rapidly — only 1 (the initial burst token) should get through
    for _ in 0..10 {
        let msg = make_msg("alice", "tcp", MessageType::Position);
        publisher.publish(&msg);
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let received = server.received_requests().await.unwrap();
    // With rate_limit=1.0 and burst=1, only the first should get through immediately.
    // Over 500ms, ~0.5 more tokens refill, so we might get 1-2 through.
    assert!(
        received.len() <= 3,
        "rate limiter should shed most traffic, got {} requests",
        received.len()
    );
    assert!(
        !received.is_empty(),
        "at least 1 request should have been allowed"
    );
}

#[tokio::test]
async fn slow_egress_target_pressures_global_backpressure_gate() {
    // ── Cross-crate proof that a stalled HTTP egress target produces
    // ── observable backpressure on the workspace-wide gate.
    //
    // The acceptance criterion for #956 asks for "integration test
    // demonstrating global gate pressure from a slow egress target".
    // We simulate that by wiring a wiremock responder that holds every
    // request open for multiple seconds, attaching an `HttpPublisher`
    // to a shared `BackpressureGate` with a small high-water mark, and
    // firing enough payload to exceed it.  The gate MUST flip to
    // non-admitting before a flusher can drain it, proving that a slow
    // downstream target is observable at the global admission layer.
    use std::time::Duration;

    use rustgate_resilience::backpressure::BackpressureGate;

    let server = MockServer::start().await;

    // Responder stalls for long enough that the worker's in-flight
    // buffer accumulates permits instead of recycling them quickly.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&server)
        .await;

    // Small high-water so we can push past it with a handful of msgs.
    // `acquire` never blocks — the gate tracks in-flight bytes and we
    // assert the flag flips once the cumulative reservation exceeds
    // the high-water mark.
    //
    // Dwell is set to `Duration::ZERO` so the "admitting" flag flips
    // back to `true` the moment in-flight bytes drop below the
    // low-water mark. Production keeps the default 1s dwell to avoid
    // accept-loop oscillation; tests explicitly opt into the
    // pre-#878 immediate-resume behaviour.
    let mut gate = BackpressureGate::with_limits(1_024, 512);
    gate.with_resume_dwell(Duration::ZERO)
        .expect("dwell must set before gate is cloned");

    let config = http_config(vec![target_config(
        "slow-egress",
        &format!("{}/webhook", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config)
        .expect("publisher must build")
        .with_backpressure(Arc::clone(&gate));

    // Baseline: no traffic yet, gate admitting.
    assert!(
        gate.is_admitting(),
        "gate MUST start in the admitting state before any traffic"
    );

    // Build a payload just under 1 KiB so 2 messages push past the
    // 1024-byte high-water mark. One-shot bursts arriving back-to-back
    // simulate a router under steady load behind a stalled target.
    let big_payload = Bytes::from(vec![b'A'; 900]);
    for _ in 0..3u8 {
        let mut msg = make_msg("alice", "tcp", MessageType::Position);
        msg.payload = big_payload.clone();
        publisher.publish(&msg);
    }

    // Poll briefly — the permits are acquired synchronously in
    // `publish`, so the flip should happen almost immediately.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let mut flipped = false;
    while tokio::time::Instant::now() < deadline {
        if !gate.is_admitting() {
            flipped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        flipped,
        "gate must stop admitting once slow egress in-flight bytes exceed the high-water mark"
    );

    // Drain: shut down the publisher. Workers abort mid-flight; the
    // `QueuedMessage` drops release the permits so the gate recovers.
    publisher.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // After drain, the gate should admit again — permits released.
    // We tolerate the default `resume_dwell` by polling a bounded
    // window; if the gate still reports blocked after the dwell,
    // the permit accounting regressed.
    let resume_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut resumed = false;
    while tokio::time::Instant::now() < resume_deadline {
        if gate.is_admitting() {
            resumed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        resumed,
        "gate must return to admitting after in-flight permits drain"
    );
}

// ── Response body capture (issue #906) ───────────────────────────────

/// Success-path capture: the target is configured with
/// `capture-response-body = true`, the server returns a JSON ack body,
/// and the request is delivered without panic. The assertion is that
/// wiremock's `expect(1)` is honoured on shutdown — the publisher
/// consumed the body and released the connection back to the pool.
/// Log-line verification is out of scope for an integration test (no
/// tracing subscriber is wired); the unit tests in `publisher.rs`
/// pin the helper-level contract.
#[tokio::test]
async fn capture_response_body_success_path_completes() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"ackId":"splunk-abc-123"}"#)
                .insert_header("content-type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut tc = target_config("capture-test", &format!("{}/hec", server.uri()));
    tc.capture_response_body = Some(true);
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    let msg = make_msg("alice", "tcp", MessageType::Position);
    publisher.publish(&msg);

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // `expect(1)` is enforced on MockServer drop — the publisher must
    // have consumed the response. `is_healthy()` is a belt-and-braces
    // check that the circuit breaker stayed closed (no capture-induced
    // failure).
    assert!(
        publisher.is_healthy(),
        "capture-enabled success must leave circuit closed"
    );
}

/// Capture-disabled success: the default behaviour is unchanged.
/// Regression pin: a refactor that silently flipped the default to
/// "always capture" would explode log volume in every existing
/// deployment. wiremock still verifies the request reaches the mock;
/// the `capture_response_body` flag only affects whether the body is
/// *also* emitted on a debug line.
#[tokio::test]
async fn capture_response_body_disabled_still_drains_body() {
    let server = MockServer::start().await;

    // Server returns a non-empty body; with capture disabled the
    // publisher must still drain it (pool hygiene) but not surface it.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"id":"quiet"}"#))
        .expect(1)
        .mount(&server)
        .await;

    let config = http_config(vec![target_config(
        "no-capture",
        &format!("{}/api", server.uri()),
    )]);
    let publisher = HttpPublisher::new(config).unwrap();

    publisher.publish(&make_msg("alice", "tcp", MessageType::Position));

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(publisher.is_healthy());
}

/// Error-path capture is always on: a 5xx response with a JSON error
/// body must surface through the normal failure-logging path without
/// blowing up. wiremock verifies the request reached the server; we
/// then assert the circuit breaker observed the failure (tripped after
/// threshold). The captured body is embedded in the error string that
/// feeds the `http_publish_failed` audit event and the Prometheus
/// `errors{reason="status_5xx"}` counter.
#[tokio::test]
async fn error_response_body_captured_in_failure_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(r#"{"error":"ingest pipeline saturated","code":"E-SATURATE"}"#),
        )
        .mount(&server)
        .await;

    let mut tc = target_config("err-capture", &format!("{}/ingest", server.uri()));
    tc.retry = Some(rustgate_http::config::RetryConfig {
        max_attempts: Some(1), // fail fast — we only care about capture-on-error
        backoff_base_secs: Some(0),
        circuit_breaker_threshold: Some(1), // trip immediately
        circuit_breaker_cooldown_secs: Some(300),
        half_open_max_probes: None,
        half_open_success_threshold: None,
    });
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    publisher.publish(&make_msg("alice", "tcp", MessageType::Position));

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // Circuit breaker must have seen the 5xx — error-path body capture
    // is downstream of the failure path, so a healthy circuit here
    // would indicate the response wasn't processed as a failure.
    assert!(
        !publisher.is_healthy(),
        "5xx response must trip circuit breaker; capture path must not mask the failure"
    );

    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// Oversized response body: the server returns a 5 KiB body but the
/// target caps capture at 1 KiB. The publisher must still drain the
/// full response (pool hygiene) and truncate the captured snippet to
/// 1 KiB. Verification is implicit — wiremock records the full
/// exchange, and `is_healthy()` confirms the publisher processed the
/// 2xx cleanly despite the size mismatch.
#[tokio::test]
async fn oversized_response_body_is_truncated_not_rejected() {
    let server = MockServer::start().await;

    // 5 KiB body — well above the 1 KiB cap below.
    let oversized = "A".repeat(5 * 1024);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(oversized))
        .expect(1)
        .mount(&server)
        .await;

    let mut tc = target_config("truncated", &format!("{}/big", server.uri()));
    tc.capture_response_body = Some(true);
    tc.max_response_body_bytes = Some(1024);
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    publisher.publish(&make_msg("alice", "tcp", MessageType::Position));

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 2xx response with oversized body must still count as success;
    // the publisher drains the full body but only captures the cap.
    assert!(
        publisher.is_healthy(),
        "oversized response body must NOT trip the circuit — truncation is silent"
    );
}

/// Config validation: a target with `max-response-body-bytes` above
/// the 1 MiB ceiling is rejected at construction time. Pins the
/// guardrail against deployments that could otherwise flood structured
/// logs with megabytes of response body per request.
#[tokio::test]
async fn publisher_rejects_oversized_cap_at_construction() {
    let mut tc = target_config("oversized-cap", "https://example.com/hook");
    tc.max_response_body_bytes = Some(2 * 1024 * 1024); // 2 MiB, over cap
    let config = http_config(vec![tc]);

    let err = HttpPublisher::new(config).unwrap_err();
    assert!(
        err.to_string().contains("exceeds the 1 MiB cap"),
        "expected 1 MiB cap error, got: {err}"
    );
}

// ── Batch egress tests (issue #906) ────────────────────────────────

/// A batch-enabled target with `batch_max_messages = 3` accumulates two
/// messages silently and emits a single HTTP POST when the third arrives.
/// The request body is a JSON array carrying all three per-message
/// payloads in insertion order.
#[tokio::test]
async fn batch_json_array_flushes_on_count_threshold() {
    use rustgate_http::config::BatchFormat;

    let server = MockServer::start().await;

    // Exactly one outbound request should reach the server — the count
    // threshold must coalesce all three messages into a single POST.
    Mock::given(method("POST"))
        .and(path("/ingest"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let mut tc = target_config("batch-count", &format!("{}/ingest", server.uri()));
    tc.batch_enabled = Some(true);
    tc.batch_max_messages = Some(3);
    tc.batch_max_bytes = Some(1024 * 1024); // large enough that count wins
    tc.batch_format = Some(BatchFormat::JsonArray);
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    for cn in ["alice", "bob", "carol"] {
        publisher.publish(&make_msg(cn, "tcp", MessageType::Position));
    }

    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let received = server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        1,
        "batch-count target must emit exactly one POST for three messages"
    );
    let body = std::str::from_utf8(&received[0].body).expect("utf-8 body");
    // The body is a JSON array with three serialized entries whose
    // source_cn fields must match insertion order.
    let value: serde_json::Value = serde_json::from_str(body).expect("valid json array");
    let arr = value.as_array().expect("body is a JSON array");
    assert_eq!(arr.len(), 3, "batch array carries all three messages");
    let cns: Vec<_> = arr
        .iter()
        .map(|v| v["source_cn"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(cns, vec!["alice", "bob", "carol"]);
}

/// When `batch_format = ndjson`, the flushed body uses newline-delimited
/// JSON and the `application/x-ndjson` content type. One line per
/// per-message payload, terminating newline included — the format most
/// SIEM ingestion endpoints (Elastic `_bulk`, Splunk HEC, Loki Push)
/// actually expect.
#[tokio::test]
async fn batch_ndjson_flushes_with_correct_content_type() {
    use rustgate_http::config::BatchFormat;

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/ingest"))
        .and(header("content-type", "application/x-ndjson"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let mut tc = target_config("batch-ndjson", &format!("{}/ingest", server.uri()));
    tc.batch_enabled = Some(true);
    tc.batch_max_messages = Some(2);
    tc.batch_max_bytes = Some(1024 * 1024);
    tc.batch_format = Some(BatchFormat::Ndjson);
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    publisher.publish(&make_msg("alice", "tcp", MessageType::Position));
    publisher.publish(&make_msg("bob", "tcp", MessageType::Position));

    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "ndjson target must emit one POST");
    let body = std::str::from_utf8(&received[0].body).expect("utf-8 body");
    assert!(
        body.ends_with('\n'),
        "ndjson body must end with a terminating newline"
    );
    let lines: Vec<&str> = body.trim_end_matches('\n').split('\n').collect();
    assert_eq!(lines.len(), 2, "two messages produce two ndjson lines");
    for line in &lines {
        let _: serde_json::Value = serde_json::from_str(line).expect("each line is valid json");
    }
}

/// A trickle of messages that never hits count or byte thresholds must
/// not be lost — the worker's shutdown path drains every non-empty
/// batcher before returning. Pins the no-leak promise baked into
/// `drain_batchers`.
#[tokio::test]
async fn batch_drains_trailing_messages_on_shutdown() {
    use rustgate_http::config::BatchFormat;

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/ingest"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1) // exactly one drain-flushed request
        .mount(&server)
        .await;

    // Thresholds configured well above the two messages we send so the
    // only way a request reaches the server is via the shutdown drain.
    let mut tc = target_config("batch-drain", &format!("{}/ingest", server.uri()));
    tc.batch_enabled = Some(true);
    tc.batch_max_messages = Some(100);
    tc.batch_max_bytes = Some(1024 * 1024);
    tc.batch_format = Some(BatchFormat::JsonArray);
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    publisher.publish(&make_msg("alice", "tcp", MessageType::Position));
    publisher.publish(&make_msg("bob", "tcp", MessageType::Position));

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let received = server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        1,
        "shutdown drain must flush the trailing batch exactly once"
    );
    let body = std::str::from_utf8(&received[0].body).expect("utf-8 body");
    let value: serde_json::Value = serde_json::from_str(body).expect("valid json");
    let arr = value.as_array().expect("body is a JSON array");
    assert_eq!(arr.len(), 2, "drain flushes both buffered messages");
}

/// When `batch_enabled` is absent or false, the publisher must retain
/// the pre-#906 per-message dispatch behaviour — one POST per message.
/// Pins that the batching branch is strictly additive and does not leak
/// into un-opted-in targets.
#[tokio::test]
async fn batch_disabled_retains_per_message_dispatch() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/solo"))
        .respond_with(ResponseTemplate::new(200))
        .expect(3) // one per message, batching off
        .mount(&server)
        .await;

    // batch_enabled left as None — should behave identically to a pre-
    // #906 target.
    let tc = target_config("solo", &format!("{}/solo", server.uri()));
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    for cn in ["a", "b", "c"] {
        publisher.publish(&make_msg(cn, "tcp", MessageType::Position));
    }

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let received = server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        3,
        "batching-off target must dispatch one POST per message"
    );
}

/// Batch-size is stable across the same batched request's retries.
/// Pins that a single logical batch is not fragmented when the receiver
/// returns 503 — the same combined body hits the wire on every attempt,
/// and the `x-rustgate-delivery-id` header is identical, so downstream
/// deduplication still works.
#[tokio::test]
async fn batch_delivery_id_is_stable_across_retries() {
    use rustgate_http::config::BatchFormat;

    let server = MockServer::start().await;

    // First request fails 503, second succeeds. Both carry the same
    // rendered batch body and the same delivery-id header.
    Mock::given(method("POST"))
        .and(path("/ingest"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/ingest"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut tc = target_config("batch-retry", &format!("{}/ingest", server.uri()));
    tc.batch_enabled = Some(true);
    tc.batch_max_messages = Some(2);
    tc.batch_max_bytes = Some(1024 * 1024);
    tc.batch_format = Some(BatchFormat::JsonArray);
    tc.retry = Some(rustgate_http::config::RetryConfig {
        max_attempts: Some(3),
        backoff_base_secs: Some(0),
        circuit_breaker_threshold: Some(10),
        circuit_breaker_cooldown_secs: Some(60),
        half_open_max_probes: None,
        half_open_success_threshold: None,
    });
    let config = http_config(vec![tc]);
    let publisher = HttpPublisher::new(config).unwrap();

    publisher.publish(&make_msg("alice", "tcp", MessageType::Position));
    publisher.publish(&make_msg("bob", "tcp", MessageType::Position));

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    publisher.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2, "one 503 + one success for the batch");
    let id1 = received[0]
        .headers
        .get("x-rustgate-delivery-id")
        .expect("delivery id on request 1")
        .to_str()
        .unwrap()
        .to_string();
    let id2 = received[1]
        .headers
        .get("x-rustgate-delivery-id")
        .expect("delivery id on request 2")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        id1, id2,
        "delivery id stable across batched-request retries"
    );
    assert_eq!(received[0].body, received[1].body, "same batched body");
}

/// Config validation: a target with batching enabled but a non-JSON
/// serialization format must be rejected at construction time. Only
/// JSON-valued entries can be framed into a JSON array or NDJSON stream;
/// mixing RawXml or Protobuf bodies into a JSON envelope would produce
/// an invalid payload for the receiver.
#[tokio::test]
async fn batch_rejects_non_json_payload_format() {
    use rustgate_http::config::PayloadFormat;

    let mut tc = target_config("batch-xml", "https://example.com/hook");
    tc.batch_enabled = Some(true);
    tc.format = Some(PayloadFormat::RawXml);
    let config = http_config(vec![tc]);

    let err = HttpPublisher::new(config).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("json") || msg.to_lowercase().contains("batch"),
        "expected batch+format conflict message, got: {msg}"
    );
}
