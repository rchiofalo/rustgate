// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Proptest coverage for [`HttpPublisher::publish`] (F-131, refs #789).
//!
//! [`HttpPublisher::publish`] is fire-and-forget: it returns `()` and
//! either enqueues the message onto the dispatch channel, drops it on
//! channel-full / circuit-open / payload-too-large, or routes it to
//! the DLQ. The contract this module pins is "no input shape causes a
//! panic". A panic in `publish` would tear down the router task that
//! invoked it, which is the worst-case outcome for an egress bridge —
//! one bad payload would silently drop every other recipient on the
//! same routing pass.
//!
//! Three input families are exercised:
//!
//! 1. **Random payloads** of arbitrary bytes up to a few hundred KiB.
//!    None of these should panic; the worker either enqueues, drops,
//!    or DLQ-routes.
//! 2. **Boundary payloads** at zero, exactly `max_payload_bytes`, and
//!    `max_payload_bytes + 1`. The size check at the worker boundary
//!    must surface as a typed log + drop, not a panic.
//! 3. **Random source-protocol strings**. The publisher's echo-prevention
//!    drops any message whose `metadata.source_protocol` matches `"http"`
//!    case-insensitively; arbitrary protocol strings still must not
//!    panic.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use proptest::prelude::*;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_http::HttpPublisher;
use rustgate_http::config::{HttpConfig, TargetConfig};

/// Bound on the `max_payload_bytes` field so the test's "boundary"
/// shape generates payloads we can actually allocate.
const TEST_MAX_PAYLOAD_BYTES: usize = 32 * 1024;

fn target_config(name: &str, url: &str, max_payload_bytes: Option<usize>) -> TargetConfig {
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
        max_payload_bytes,
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
        instance_id: Some("proptest-instance".to_string()),
        targets,
        dlq_dir: None,
        dlq_key_file: None,
        dlq_max_bytes: None,
        dlq_max_target_bytes: None,
        allow_private_urls: true,
    }
}

fn make_publisher() -> HttpPublisher {
    // The publisher does not need a live HTTP listener for `publish`
    // not to panic — the dispatch worker handles connection failures
    // out-of-band. A reachable-looking but un-bound localhost URL is
    // sufficient.
    let cfg = http_config(vec![target_config(
        "proptest",
        "http://127.0.0.1:1/webhook",
        Some(TEST_MAX_PAYLOAD_BYTES),
    )]);
    HttpPublisher::new(cfg).expect("HttpPublisher::new must succeed for the proptest target")
}

fn make_msg(payload: Bytes, protocol: &str) -> RoutableMessage {
    RoutableMessage {
        source: Identity {
            cn: "proptest-source".into(),
            fingerprint: Default::default(),
            groups: BTreeSet::new(),
            tenant: None,
            spiffe_id: None,
            attributes: Arc::new(Default::default()),
        },
        destination: Destination::Broadcast,
        payload,
        metadata: Metadata::new(
            SystemTime::now(),
            protocol.to_string(),
            MessageType::Other("proptest".to_string()),
        ),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Random payload bytes (0..=64 KiB, comfortably below
    /// `max_payload_bytes`) must never cause `publish` to panic.
    /// The publisher is fire-and-forget; if the worker rejects the
    /// payload, that surfaces as a log warning and the call still
    /// returns cleanly.
    #[test]
    fn random_payload_bytes_never_panic(payload in proptest::collection::vec(any::<u8>(), 0..=65536)) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let publisher = make_publisher();
            let msg = make_msg(Bytes::from(payload), "tcp");
            publisher.publish(&msg);
            publisher.shutdown().await;
        });
    }

    /// Random `source_protocol` strings — the echo-prevention path
    /// matches `"http"` case-insensitively and silently drops; any
    /// other string falls through to the dispatch channel. Both
    /// branches must be panic-free.
    #[test]
    fn random_source_protocol_never_panics(
        protocol in "[a-zA-Z0-9_-]{0,32}",
        payload in proptest::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let publisher = make_publisher();
            let msg = make_msg(Bytes::from(payload), &protocol);
            publisher.publish(&msg);
            publisher.shutdown().await;
        });
    }
}

/// Empty payload boundary. The worker's size check uses `>` so a
/// zero-byte payload is always under the limit. `publish` must accept
/// the call without panicking; the worker may still drop the message
/// for other reasons (e.g. unreachable target) but that path is
/// out-of-band.
#[tokio::test]
async fn publish_empty_payload_does_not_panic() {
    let publisher = make_publisher();
    let msg = make_msg(Bytes::new(), "tcp");
    publisher.publish(&msg);
    publisher.shutdown().await;
}

/// Exactly-at-limit payload boundary. `publish` must accept the call
/// and the worker's size check (`>` not `>=`) must allow it through.
#[tokio::test]
async fn publish_exact_max_payload_does_not_panic() {
    let publisher = make_publisher();
    let payload = Bytes::from(vec![0xAB; TEST_MAX_PAYLOAD_BYTES]);
    let msg = make_msg(payload, "tcp");
    publisher.publish(&msg);
    publisher.shutdown().await;
}

/// Just-over-limit payload boundary. The worker's size check rejects,
/// but the rejection surfaces as a log warning — `publish` itself is
/// fire-and-forget and must return cleanly without panicking.
#[tokio::test]
async fn publish_over_max_payload_does_not_panic() {
    let publisher = make_publisher();
    let payload = Bytes::from(vec![0xCD; TEST_MAX_PAYLOAD_BYTES + 1]);
    let msg = make_msg(payload, "tcp");
    publisher.publish(&msg);
    publisher.shutdown().await;
}
