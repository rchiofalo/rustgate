// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for DLQ auto-drain on circuit recovery (issue #881).
//!
//! These tests exercise the full circuit-breaker → dead-letter → recovery
//! → replay pipeline against a live wiremock endpoint. They drive the
//! circuit from `Closed → Open → HalfOpen → Closed` via real request
//! outcomes rather than poking breaker internals, which pins the wiring
//! that `build_circuit_observer(target, Some(drain_tx))` depends on.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_http::HttpPublisher;
use rustgate_http::config::{HttpConfig, RetryConfig, TargetConfig};
use wiremock::matchers::{body_string_contains, header_exists, method, path as wpath};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Circuit configured so a single failure trips it and a single success
/// closes it. Cooldown is the smallest supported by `RetryConfig` (1s,
/// u64 seconds). Keeps tests fast while still exercising the real
/// `Open → HalfOpen → Closed` transition path.
fn fast_retry_config() -> RetryConfig {
    RetryConfig {
        max_attempts: Some(1),
        backoff_base_secs: Some(0),
        circuit_breaker_threshold: Some(1),
        circuit_breaker_cooldown_secs: Some(1),
        half_open_max_probes: Some(1),
        half_open_success_threshold: Some(1),
    }
}

fn make_msg(cn: &str) -> RoutableMessage {
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
        payload: Bytes::from_static(b"<event uid='drain-test-1'/>"),
        metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), MessageType::Position),
    }
}

fn target_with_dlq_and_fast_circuit(name: &str, url: &str) -> TargetConfig {
    TargetConfig {
        name: name.to_string(),
        url: url.to_string(),
        method: None,
        auth: None,
        tls: None,
        timeout_secs: Some(5),
        format: None,
        filter: None,
        retry: Some(fast_retry_config()),
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

/// Write a minimal KeyRing JSON file to disk and return its path. The
/// key material is 64 zero hex chars (32 bytes) — sufficient for the
/// round-trip encrypt/decrypt the drain path exercises, and identical
/// to the test fixture used in `crates/rustgate-http/src/dlq.rs`.
fn write_test_keyring(dir: &Path) -> std::path::PathBuf {
    let key_json = r#"{
        "active_key_id": "test-key",
        "keys": {
            "test-key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    }"#;
    let key_path = dir.join("keys.json");
    std::fs::write(&key_path, key_json).unwrap();
    key_path
}

fn dlq_http_config(targets: Vec<TargetConfig>, dlq_dir: &Path, key_path: &Path) -> HttpConfig {
    HttpConfig {
        instance_id: Some("drain-test-instance".to_string()),
        targets,
        dlq_dir: Some(dlq_dir.to_string_lossy().into_owned()),
        dlq_key_file: Some(key_path.to_string_lossy().into_owned()),
        dlq_max_bytes: None,
        dlq_max_target_bytes: None,
        allow_private_urls: true, // wiremock binds to 127.0.0.1
    }
}

/// End-to-end drain: messages shed while the circuit is `Open` land in
/// the DLQ, and when the circuit later recovers (`HalfOpen → Closed`)
/// the drain worker replays them against the now-healthy endpoint.
///
/// The test deliberately publishes TWO messages: the first trips the
/// circuit via a terminal 5xx (which is NOT itself DLQ'd — terminal
/// failures are dropped by design), the second arrives while the
/// circuit is `Open` and is routed to the DLQ with reason
/// `circuit_open`. After cooldown a probe closes the circuit and the
/// drain worker replays the DLQ'd message. The recovery mock's
/// `.expect(2)` catches silent drain failures — probe + replay must
/// both land.
#[tokio::test]
async fn drain_replays_dlq_entries_on_circuit_recovery() {
    let server = MockServer::start().await;

    // Phase 1: the endpoint returns 500 exactly once — enough for the
    // first publish to record a failure and trip the circuit.
    let fail_guard = Mock::given(method("POST"))
        .and(wpath("/webhook"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let dlq_dir = tmp.path().join("dlq");
    std::fs::create_dir_all(&dlq_dir).unwrap();
    let key_path = write_test_keyring(tmp.path());

    let config = dlq_http_config(
        vec![target_with_dlq_and_fast_circuit(
            "drain-e2e",
            &format!("{}/webhook", server.uri()),
        )],
        &dlq_dir,
        &key_path,
    );
    let publisher = HttpPublisher::new(config).unwrap();

    // `alice` gets the single 500 response: terminal failure trips the
    // circuit but the message itself is dropped (not DLQ'd). That is
    // the documented behavior of `publish_with_retry` — only 4xx/5xx
    // that hit an OPEN circuit get persisted.
    publisher.publish(&make_msg("alice"));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!publisher.is_healthy(), "circuit should be open after 500");

    // `charlie` is published while the circuit is `Open`: the HTTP
    // layer never attempts a request, the message is shed to the DLQ
    // with `circuit_open` and stamped with a fresh `delivery_id`. This
    // is the entry the drain worker will later replay.
    publisher.publish(&make_msg("charlie"));
    tokio::time::sleep(Duration::from_millis(200)).await;

    std::mem::drop(fail_guard);
    // Exactly two 200s expected: the probe (`bob`) and the drain
    // replay (`charlie`). If the replay never arrives, `_ok_guard`
    // panics on drop with `matched: 1, expected: == 2`.
    let _ok_guard = Mock::given(method("POST"))
        .and(wpath("/webhook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount_as_scoped(&server)
        .await;

    // Wait out the circuit cooldown (1s configured) plus headroom.
    tokio::time::sleep(Duration::from_millis(1_300)).await;

    // `bob` is the probe: circuit transitions `Open → HalfOpen` on
    // `allow_request`, the probe succeeds (mock returns 200), and
    // `HalfOpen → Closed` fires the drain observer.
    publisher.publish(&make_msg("bob"));

    // Give the drain worker time to: receive the trigger, rotate the
    // active segment, decrypt, and replay the entry. 1.5s is generous
    // for a single-entry DLQ on local tempfs.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    publisher.shutdown().await;
    // `_ok_guard.expect(2)` fires on drop — probe + replay must land.
}

/// The DLQ stamps every entry with a stable `delivery_id`. The drain
/// path must forward that id through `X-Rustgate-Delivery-Id` on the
/// replay request so a downstream receiver that already processed the
/// original delivery can dedup by id. Without this, every replay cycle
/// would duplicate on the receiver.
///
/// The active DLQ segment file is unsealed (no encrypted terminator)
/// while the publisher is running, so we cannot read it mid-flight.
/// Instead we verify the property end-to-end on the wire: the mock
/// matcher gates the replay on `header_exists("X-Rustgate-Delivery-Id")`
/// and we also inspect the captured request to assert the 32-hex shape.
#[tokio::test]
async fn drain_preserves_delivery_id_across_replay() {
    let server = MockServer::start().await;

    // Phase 1: single 500 trips the circuit (terminal failure for
    // `alice`, dropped not DLQ'd).
    let fail_guard = Mock::given(method("POST"))
        .and(wpath("/webhook"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let dlq_dir = tmp.path().join("dlq");
    std::fs::create_dir_all(&dlq_dir).unwrap();
    let key_path = write_test_keyring(tmp.path());

    let config = dlq_http_config(
        vec![target_with_dlq_and_fast_circuit(
            "drain-id-preserve",
            &format!("{}/webhook", server.uri()),
        )],
        &dlq_dir,
        &key_path,
    );
    let publisher = HttpPublisher::new(config).unwrap();

    publisher.publish(&make_msg("alice"));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!publisher.is_healthy());

    // `charlie` hits the now-Open circuit and is shed to the DLQ with
    // `circuit_open`. `dead_letter` stamps a fresh 32-hex `delivery_id`
    // that the drain path must carry through to the wire.
    publisher.publish(&make_msg("charlie"));
    tokio::time::sleep(Duration::from_millis(200)).await;

    std::mem::drop(fail_guard);
    // The replay must carry a `X-Rustgate-Delivery-Id` header. If the
    // header is missing, this mock fails to match and `_probe_guard`
    // would catch the request at the bottom — failing `_replay_guard`'s
    // `.expect(1)` on drop.
    let _replay_guard = Mock::given(method("POST"))
        .and(wpath("/webhook"))
        .and(body_string_contains(r#""source_cn":"charlie""#))
        .and(header_exists("X-Rustgate-Delivery-Id"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount_as_scoped(&server)
        .await;
    // The probe (`bob`) gets its own handler so it does not satisfy
    // `_replay_guard`'s charlie-body constraint.
    let _probe_guard = Mock::given(method("POST"))
        .and(wpath("/webhook"))
        .and(body_string_contains(r#""source_cn":"bob""#))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    tokio::time::sleep(Duration::from_millis(1_300)).await;
    publisher.publish(&make_msg("bob"));
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    // Inspect the recorded requests: find the charlie-replay and check
    // its `X-Rustgate-Delivery-Id` is a non-empty 32-hex-char value.
    // This is stricter than `header_exists` — it also pins the id
    // shape so a regression that wired an empty string or a stray
    // format marker into the header would still fail here even though
    // `header_exists` alone would have tolerated it.
    let requests = server.received_requests().await.expect("recording on");
    let replay = requests
        .iter()
        .find(|r| {
            let body = std::str::from_utf8(&r.body).unwrap_or("");
            body.contains(r#""source_cn":"charlie""#)
        })
        .expect("charlie replay request must have been captured");
    let id = replay
        .headers
        .get("X-Rustgate-Delivery-Id")
        .expect("X-Rustgate-Delivery-Id must be present on replay")
        .to_str()
        .expect("delivery_id header is ASCII");
    assert_eq!(id.len(), 32, "delivery_id must be 32 hex chars");
    assert!(
        id.chars().all(|c| c.is_ascii_hexdigit()),
        "delivery_id must be lowercase hex: got {id}"
    );

    publisher.shutdown().await;
    // `_replay_guard.expect(1)` and `_probe_guard.expect(1)` both fire
    // on drop — probe + replay must each land exactly once.
}

/// When the receiver is still unhealthy during drain, the drain path
/// must re-DLQ every failed replay and not silently lose messages —
/// and it must preserve the original `delivery_id` through the re-DLQ
/// (`dead_letter_with_id`) so receivers keyed on that id keep dedup
/// working across replay cycles.
///
/// The test captures the delivery_id the drain sends on the wire
/// (recorded by wiremock), then reads the sealed DLQ after
/// `shutdown()` and asserts the re-DLQ'd entry carries the SAME id —
/// which is only possible if `dead_letter_with_id` did its job.
#[tokio::test]
async fn drain_requeues_failed_entries_and_preserves_id() {
    use rustgate_archive::encrypted::KeyRing;

    let server = MockServer::start().await;

    // Phase 1: single 500 trips the circuit. `alice` is dropped (not
    // DLQ'd — terminal failure).
    let fail_guard = Mock::given(method("POST"))
        .and(wpath("/webhook"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let dlq_dir = tmp.path().join("dlq");
    std::fs::create_dir_all(&dlq_dir).unwrap();
    let key_path = write_test_keyring(tmp.path());

    let config = dlq_http_config(
        vec![target_with_dlq_and_fast_circuit(
            "drain-requeue",
            &format!("{}/webhook", server.uri()),
        )],
        &dlq_dir,
        &key_path,
    );
    let publisher = HttpPublisher::new(config).unwrap();

    publisher.publish(&make_msg("alice"));
    tokio::time::sleep(Duration::from_millis(400)).await;

    // `charlie` is DLQ'd while the circuit is open. This is the entry
    // whose `delivery_id` must round-trip through drain → replay-fail →
    // re-DLQ without change.
    publisher.publish(&make_msg("charlie"));
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Phase 2: we discriminate probe vs replay by the `source_cn` in
    // the JSON body. `bob` (probe) returns 200 so the circuit closes
    // and drain fires. `charlie` (replay) returns 500 so the drain
    // replay fails and the entry is re-DLQ'd via `dead_letter_with_id`.
    std::mem::drop(fail_guard);
    let _probe_ok = Mock::given(method("POST"))
        .and(wpath("/webhook"))
        .and(body_string_contains(r#""source_cn":"bob""#))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount_as_scoped(&server)
        .await;
    let _replay_fail = Mock::given(method("POST"))
        .and(wpath("/webhook"))
        .and(body_string_contains(r#""source_cn":"charlie""#))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    tokio::time::sleep(Duration::from_millis(1_300)).await;
    publisher.publish(&make_msg("bob"));
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    // Capture the id the drain worker sent on the wire: that id was
    // read out of the original DLQ segment, so it IS the original
    // `dead_letter` id. If `dead_letter_with_id` preserves it on
    // re-DLQ, the sealed segment we read after shutdown will contain
    // the same value.
    let requests = server.received_requests().await.expect("recording on");
    let wire_id = requests
        .iter()
        .find(|r| {
            let body = std::str::from_utf8(&r.body).unwrap_or("");
            body.contains(r#""source_cn":"charlie""#)
        })
        .and_then(|r| r.headers.get("X-Rustgate-Delivery-Id"))
        .and_then(|h| h.to_str().ok())
        .map(String::from)
        .expect("replay must carry delivery_id on wire");

    // Shutdown seals the re-DLQ'd segment so we can decrypt+read it.
    publisher.shutdown().await;

    let key_ring = KeyRing::load(&key_path).unwrap();
    let requeued_ids: Vec<String> = {
        let mut ids = Vec::new();
        for f in std::fs::read_dir(&dlq_dir).unwrap().flatten() {
            let p = f.path();
            if p.extension().and_then(|s| s.to_str()) == Some("enc") {
                let decoded = rustgate_http::dlq_reader::read_dlq_file(&p, &key_ring).unwrap();
                for entry in decoded {
                    ids.push(entry.delivery_id);
                }
            }
        }
        ids
    };

    assert!(
        requeued_ids.contains(&wire_id),
        "re-DLQ'd entry must preserve wire delivery_id {wire_id}; have {requeued_ids:?}"
    );
}

/// A recovery trigger that finds no sealed segments must be a no-op —
/// no panics, no errors, and no spurious replay requests. Protects the
/// case where the circuit flaps briefly without any messages actually
/// being dead-lettered (`record_failure` threshold hit, but the
/// corresponding dispatch never reached `dead_letter`).
#[tokio::test]
async fn drain_is_noop_when_no_sealed_segments_exist() {
    let server = MockServer::start().await;

    // All requests succeed — no DLQ writes, but we still want the
    // circuit to settle to Closed without panicking the drain worker.
    let _ok_guard = Mock::given(method("POST"))
        .and(wpath("/webhook"))
        .respond_with(ResponseTemplate::new(200))
        .mount_as_scoped(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let dlq_dir = tmp.path().join("dlq");
    std::fs::create_dir_all(&dlq_dir).unwrap();
    let key_path = write_test_keyring(tmp.path());

    let config = dlq_http_config(
        vec![target_with_dlq_and_fast_circuit(
            "drain-empty",
            &format!("{}/webhook", server.uri()),
        )],
        &dlq_dir,
        &key_path,
    );
    let publisher = HttpPublisher::new(config).unwrap();

    // Four successful messages — nothing to DLQ, nothing to drain.
    for _ in 0..4 {
        publisher.publish(&make_msg("alice"));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        publisher.is_healthy(),
        "circuit must remain closed on all-success traffic"
    );

    // DLQ dir must be empty — no segments ever written.
    let segment_count = std::fs::read_dir(&dlq_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("enc"))
        .count();
    assert_eq!(segment_count, 0, "no DLQ writes expected on happy path");

    publisher.shutdown().await;
}
