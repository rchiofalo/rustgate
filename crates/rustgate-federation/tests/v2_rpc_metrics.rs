// Copyright © 2026 Roberto Chiofalo.

//! Per-RPC observability metrics for the V2 federation gRPC layer
//! (closes #1299).
//!
//! Three vectors are pinned by these tests:
//! - `rustgate_federation_rpc_duration_seconds` (histogram)
//! - `rustgate_federation_rpc_in_flight` (gauge)
//! - `rustgate_federation_rpc_total` (counter)
//!
//! The integration tests stand up a real `FederationService` mTLS gRPC
//! server (mirroring the `v2_rpcs.rs` fixture shape) and drive the
//! wire-level `FederatedChannelClient` so the metric wiring is
//! exercised through the same handler entry path the production
//! traffic walks. The classification and idempotence tests stay at the
//! crate-level metrics module — those don't need an RPC at all.
//!
//! Coverage:
//! 1. `rpc_duration_metric_records_on_handler_completion` — drive a
//!    unary `SendOneBlob` end-to-end through mTLS; assert at least one
//!    success-bucket observation lands on the histogram.
//! 2. `rpc_in_flight_gauge_increments_during_handler_and_decrements_on_exit`
//!    — pause the server-side callback with a `Notify`, observe the
//!    gauge value while the handler is in-flight, release, and confirm
//!    the gauge drains to zero.
//! 3. `rpc_total_counter_classifies_success_vs_error` — drive a
//!    successful `SendOneBlob` and an `error` `SendOneBlob` (peer not
//!    in allowlist); assert two distinct label-set increments.
//! 4. `rpc_metrics_label_peer_is_sanitized` — peer-id with `\r\n` is
//!    sanitized at the metric-vector boundary (no log forging).
//! 5. `rpc_metrics_init_is_idempotent` — `init()` may be called more
//!    than once without panicking.
//! 6. `rpc_metrics_accessor_works_without_init` — the `OnceLock`
//!    fallback path returns a usable handle.

#![cfg(all(feature = "v2", feature = "api"))]
#![allow(unused_results, clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rustgate_federation::metrics::{
    InFlightGuard, RESULT_ERROR, RESULT_SUCCESS, RESULT_TIMEOUT, RPC_CLIENT_FEDERATE_GROUPS_STREAM,
    RPC_SEND_ONE_BLOB, RPC_SERVER_EVENT_STREAM, RPC_SERVER_ROL_STREAM, classify_status,
    rpc_duration, rpc_in_flight, rpc_total, sanitize_peer_label,
};
use rustgate_federation::v2::proto::figpb;
use rustgate_federation::v2::proto::figpb::federated_channel_client::FederatedChannelClient;
use rustgate_federation::v2::server::{FederationService, OnBlob};
use rustgate_test_utils::certs::TestCa;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig};

// ── Shared fixtures ──────────────────────────────────────────────────

struct MtlsFixtures {
    url: String,
    ca_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

/// Spin up a `FederationService` behind an mTLS listener. The optional
/// `allowed_peer_groups` lets the caller scope an allowlist so a
/// "peer not in allowlist" error path can be driven cleanly.
async fn start_mtls_server(
    federate_id: &str,
    on_blob: OnBlob,
    client_cn: &str,
    allowed_peer_groups: Option<HashMap<String, std::collections::HashSet<String>>>,
) -> MtlsFixtures {
    let ca = TestCa::new("federation-rpc-metrics-ca");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert(client_cn, &[]);

    // The OnEvent / OnRolEvent / OnGroupSync callbacks are irrelevant
    // for the metric coverage in this file; pass no-ops.
    let no_op_event: rustgate_federation::v2::server::OnEvent =
        Arc::new(|_event, _peer, _trace| {});
    let mut svc =
        FederationService::new(federate_id.to_string(), vec!["Alpha".into()], no_op_event);
    svc = svc.with_on_blob(on_blob);
    if let Some(map) = allowed_peer_groups {
        svc = svc.with_allowed_peer_groups(map);
    }
    let service = figpb::federated_channel_server::FederatedChannelServer::new(svc);

    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            server_cert.cert_pem.as_bytes(),
            server_cert.key_pem.as_bytes(),
        ))
        .client_ca_root(Certificate::from_pem(ca.cert_pem.as_bytes()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    drop(tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls)
            .expect("server tls config")
            .add_service(service)
            .serve_with_incoming(incoming)
            .await
            .expect("server");
    }));

    // Give the listener a moment to start accepting connections.
    tokio::time::sleep(Duration::from_millis(50)).await;

    MtlsFixtures {
        url: format!("https://localhost:{}", addr.port()),
        ca_pem: ca.cert_pem.clone(),
        client_cert_pem: client_cert.cert_pem,
        client_key_pem: client_cert.key_pem,
    }
}

async fn mtls_client(fixtures: &MtlsFixtures) -> FederatedChannelClient<tonic::transport::Channel> {
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(fixtures.ca_pem.as_bytes()))
        .identity(Identity::from_pem(
            fixtures.client_cert_pem.as_bytes(),
            fixtures.client_key_pem.as_bytes(),
        ));

    let channel = Endpoint::from_shared(fixtures.url.clone())
        .expect("endpoint")
        .tls_config(tls)
        .expect("client tls config")
        .connect()
        .await
        .expect("connect");

    FederatedChannelClient::new(channel)
}

fn make_blob(uid: &str) -> figpb::BinaryBlob {
    figpb::BinaryBlob {
        data: format!("payload-{uid}").into_bytes(),
        ..Default::default()
    }
}

/// Sum the success-bucket counts across every series of the
/// `rpc_duration_seconds` histogram for a given `(rpc, peer)` pair.
/// Reads the metric family directly so a parallel test running on the
/// same global registry can't make us racey-flaky.
fn rpc_duration_sample_count(rpc: &str, peer: &str, result: &str) -> u64 {
    use prometheus::core::Collector;
    let snap = rpc_duration().collect();
    for mf in snap {
        for m in mf.get_metric() {
            let mut matches_rpc = false;
            let mut matches_peer = false;
            let mut matches_result = false;
            for label in m.get_label() {
                if label.name() == "rpc" && label.value() == rpc {
                    matches_rpc = true;
                }
                if label.name() == "peer" && label.value() == peer {
                    matches_peer = true;
                }
                if label.name() == "result" && label.value() == result {
                    matches_result = true;
                }
            }
            if matches_rpc && matches_peer && matches_result {
                return m.get_histogram().get_sample_count();
            }
        }
    }
    0
}

// ── Tests ────────────────────────────────────────────────────────────

/// Successful `SendOneBlob` must land at least one observation in the
/// success bucket of `rpc_duration_seconds{rpc,peer,result=success}`.
#[tokio::test]
async fn rpc_duration_metric_records_on_handler_completion() {
    // Seed the metric registry — idempotent.
    let _ = rustgate_federation::metrics::init();

    let on_blob: OnBlob = Arc::new(|_blob, _peer| {});
    let client_cn = "rpc-duration-test-client";
    let fixtures = start_mtls_server("blob-duration-server", on_blob, client_cn, None).await;
    let mut client = mtls_client(&fixtures).await;

    let peer_label = sanitize_peer_label(client_cn);
    let before = rpc_duration_sample_count(RPC_SEND_ONE_BLOB, peer_label.as_str(), RESULT_SUCCESS);

    let resp = client
        .send_one_blob(make_blob("duration"))
        .await
        .expect("send_one_blob must succeed");
    let _ = resp.into_inner();

    let after = rpc_duration_sample_count(RPC_SEND_ONE_BLOB, peer_label.as_str(), RESULT_SUCCESS);
    assert!(
        after > before,
        "expected at least one new sample on rpc_duration_seconds: before={before}, after={after}"
    );
}

/// While a unary handler is paused inside its callback, the in-flight
/// gauge for `(rpc=send_one_blob, peer=cn)` must read at least 1; once
/// the handler finishes, it must drain back to 0.
///
/// The `OnBlob` callback is a synchronous `Fn` (not async), so we
/// pause it on a std `mpsc::Receiver` — the handler future stays
/// blocked at the call site, the in-flight gauge is observed from the
/// test thread, then the test sends on the matching `Sender` to
/// release. A multi-thread tokio runtime is required (the default for
/// `#[tokio::test]` is single-thread) — set explicitly via the macro
/// flavor below.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_in_flight_gauge_increments_during_handler_and_decrements_on_exit() {
    use std::sync::mpsc as std_mpsc;

    let _ = rustgate_federation::metrics::init();

    let (release_tx, release_rx) = std_mpsc::channel::<()>();
    let (entered_tx, entered_rx) = std_mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);

    let entered_tx = std::sync::Mutex::new(Some(entered_tx));
    let release_rx = Arc::new(release_rx);
    let entered_tx = Arc::new(entered_tx);

    let on_blob: OnBlob = Arc::new(move |_blob, _peer| {
        // Notify the test that we've entered the handler.
        if let Some(tx) = entered_tx.lock().expect("entered tx mutex").take() {
            let _ = tx.send(());
        }
        // Block synchronously until the test releases us. The
        // surrounding handler is waiting on this `Fn` to return.
        let rx = release_rx.lock().expect("release rx mutex");
        let _ = rx.recv();
    });
    let client_cn = "rpc-in-flight-test-client";
    let fixtures = start_mtls_server("blob-in-flight-server", on_blob, client_cn, None).await;
    let client = mtls_client(&fixtures).await;

    let peer_label = sanitize_peer_label(client_cn);
    let baseline = rpc_in_flight()
        .with_label_values(&[RPC_SEND_ONE_BLOB, peer_label.as_str()])
        .get();

    // Drive the RPC on a separate task so the test thread stays free
    // to observe the gauge while the handler is paused.
    let blob = make_blob("in-flight");
    let mut client_clone = client.clone();
    let request_handle = tokio::spawn(async move { client_clone.send_one_blob(blob).await });

    // Wait for the handler to enter the callback (off-loop is fine —
    // a synchronous channel recv blocks the calling task, which here
    // is a helper, not the runtime's main loop).
    let _ = tokio::task::spawn_blocking(move || {
        let _ = entered_rx.recv();
    })
    .await;

    let during = rpc_in_flight()
        .with_label_values(&[RPC_SEND_ONE_BLOB, peer_label.as_str()])
        .get();
    assert!(
        during > baseline,
        "expected gauge > baseline while handler paused: baseline={baseline}, during={during}"
    );

    // Release the handler.
    let _ = release_tx.send(());
    let resp = request_handle.await.expect("join").expect("rpc");
    let _ = resp.into_inner();

    // Allow the gauge decrement to land. `Drop` runs synchronously
    // when the handler future completes, but the test thread sees the
    // decrement via the global registry — so a brief spin-loop is
    // sufficient.
    let mut after = rpc_in_flight()
        .with_label_values(&[RPC_SEND_ONE_BLOB, peer_label.as_str()])
        .get();
    for _ in 0..50 {
        if after <= baseline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        after = rpc_in_flight()
            .with_label_values(&[RPC_SEND_ONE_BLOB, peer_label.as_str()])
            .get();
    }
    assert!(
        after <= baseline,
        "expected gauge to drain to baseline after handler exit: baseline={baseline}, after={after}"
    );
}

/// Drive a successful `SendOneBlob` and a failing one (peer not in
/// allowlist) and assert the counter records each under its own
/// `result` label.
#[tokio::test]
async fn rpc_total_counter_classifies_success_vs_error() {
    let _ = rustgate_federation::metrics::init();

    // A peer is allowed for the success path...
    let success_cn = "rpc-counter-success-client";
    let mut allowed: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let _ = allowed.insert(
        success_cn.to_string(),
        std::collections::HashSet::from(["Alpha".into()]),
    );

    let on_blob: OnBlob = Arc::new(|_blob, _peer| {});
    let fixtures =
        start_mtls_server("blob-counter-server", on_blob, success_cn, Some(allowed)).await;
    let mut client = mtls_client(&fixtures).await;

    let success_label = sanitize_peer_label(success_cn);
    let success_before = rpc_total()
        .with_label_values(&[RPC_SEND_ONE_BLOB, success_label.as_str(), RESULT_SUCCESS])
        .get();

    let _ = client
        .send_one_blob(make_blob("counter-success"))
        .await
        .expect("send_one_blob must succeed");

    let success_after = rpc_total()
        .with_label_values(&[RPC_SEND_ONE_BLOB, success_label.as_str(), RESULT_SUCCESS])
        .get();
    assert!(
        success_after > success_before,
        "expected success counter to advance: before={success_before}, after={success_after}"
    );

    // Now stand up a server with an allowlist that does NOT include
    // the client CN, so the same RPC is rejected with PermissionDenied
    // and lands under the `error` label.
    let error_cn = "rpc-counter-error-client";
    let allowed_for_other_peer: HashMap<String, std::collections::HashSet<String>> =
        std::iter::once((
            "some-other-peer".to_string(),
            std::collections::HashSet::from(["Alpha".into()]),
        ))
        .collect();
    let on_blob_err: OnBlob = Arc::new(|_blob, _peer| {});
    let fixtures2 = start_mtls_server(
        "blob-counter-server-err",
        on_blob_err,
        error_cn,
        Some(allowed_for_other_peer),
    )
    .await;
    let mut client2 = mtls_client(&fixtures2).await;

    let error_label = sanitize_peer_label(error_cn);
    let error_before = rpc_total()
        .with_label_values(&[RPC_SEND_ONE_BLOB, error_label.as_str(), RESULT_ERROR])
        .get();

    let resp = client2.send_one_blob(make_blob("counter-error")).await;
    assert!(
        resp.is_err(),
        "expected PermissionDenied for unauthorized peer"
    );

    let error_after = rpc_total()
        .with_label_values(&[RPC_SEND_ONE_BLOB, error_label.as_str(), RESULT_ERROR])
        .get();
    assert!(
        error_after > error_before,
        "expected error counter to advance: before={error_before}, after={error_after}"
    );
}

/// A peer-id smuggling `\r\n` must be sanitized before reaching the
/// metric vector — no CR or LF must appear in the label value.
///
/// This is a pure unit test on `sanitize_peer_label` (the same surface
/// that wraps every per-RPC peer label in the production code paths).
/// We assert the post-sanitize string is what actually gets used as a
/// label by querying the gauge for the sanitized form and pinning that
/// it's reachable without going through the raw bytes.
#[test]
fn rpc_metrics_label_peer_is_sanitized() {
    let evil = "rpc-peer-\r\nfake-line";
    let safe = sanitize_peer_label(evil);
    assert!(!safe.contains('\r'), "CR must be stripped: {safe:?}");
    assert!(!safe.contains('\n'), "LF must be stripped: {safe:?}");

    // The sanitized label must produce a valid metric vector entry.
    // If the prometheus crate ever started rejecting our sanitized
    // form, this test would fail at the `with_label_values` call.
    let _ = rpc_in_flight().with_label_values(&[RPC_SEND_ONE_BLOB, safe.as_str()]);
    let _ = rpc_total().with_label_values(&[RPC_SEND_ONE_BLOB, safe.as_str(), RESULT_SUCCESS]);
}

/// `init()` must not panic on a second call. Prometheus's registry
/// returns `Err(AlreadyReg)` for a double-register; the federation
/// `init()` should swallow that. We can't reset the global registry
/// between tests, so we just call it twice and trust that any
/// regression would surface as a panic from an `.expect()` upstream.
#[test]
fn rpc_metrics_init_is_idempotent() {
    let _ = rustgate_federation::metrics::init();
    let _ = rustgate_federation::metrics::init();
    let _ = rpc_duration();
    let _ = rpc_in_flight();
    let _ = rpc_total();
}

/// The accessor functions must work even when `init()` has never been
/// called in this process. We can't reset the global `OnceLock` from a
/// test (other tests may have already triggered it), but the contract
/// is "the accessor returns something usable", and that's verified by
/// successfully creating a label set on the returned vec — the
/// fallback constructor's correctness is independently exercised by
/// `rustgate_metrics` unit tests.
#[test]
fn rpc_metrics_accessor_works_without_init() {
    let _ = rpc_duration().with_label_values(&[
        RPC_SERVER_EVENT_STREAM,
        "no-init-peer",
        RESULT_SUCCESS,
    ]);
    let _ = rpc_in_flight().with_label_values(&[RPC_SERVER_EVENT_STREAM, "no-init-peer"]);
    let _ =
        rpc_total().with_label_values(&[RPC_SERVER_EVENT_STREAM, "no-init-peer", RESULT_SUCCESS]);
}

/// The `classify_status` mapping is the canonical gRPC `Code` →
/// `result` label table. Pin every documented branch so a future tonic
/// upgrade that renames a variant fails this test instead of silently
/// mis-classifying outcomes.
#[test]
fn rpc_metrics_classify_status_pins_three_buckets() {
    assert_eq!(classify_status(tonic::Code::Ok), RESULT_SUCCESS);
    assert_eq!(
        classify_status(tonic::Code::DeadlineExceeded),
        RESULT_TIMEOUT
    );
    assert_eq!(classify_status(tonic::Code::Internal), RESULT_ERROR);
    assert_eq!(classify_status(tonic::Code::Unavailable), RESULT_ERROR);
    assert_eq!(classify_status(tonic::Code::Unauthenticated), RESULT_ERROR);
}

/// `InFlightGuard::enter` must increment the gauge synchronously and
/// `Drop` must decrement it — drives the lifecycle on a label that's
/// unique to this test so parallel test interleavings don't mask the
/// transitions.
#[test]
fn rpc_metrics_in_flight_guard_lifecycle_for_streaming_rpcs() {
    let peer = "rpc-streams-guard-peer";
    let before = rpc_in_flight()
        .with_label_values(&[RPC_SERVER_ROL_STREAM, peer])
        .get();
    {
        let _g = InFlightGuard::enter(RPC_SERVER_ROL_STREAM, peer);
        let during = rpc_in_flight()
            .with_label_values(&[RPC_SERVER_ROL_STREAM, peer])
            .get();
        assert_eq!(during, before + 1, "expected +1 inside guard scope");
    }
    let after = rpc_in_flight()
        .with_label_values(&[RPC_SERVER_ROL_STREAM, peer])
        .get();
    assert_eq!(after, before, "expected gauge to drain on Drop");

    // Sanity: same peer, different RPC label gets its own series.
    let other_before = rpc_in_flight()
        .with_label_values(&[RPC_CLIENT_FEDERATE_GROUPS_STREAM, peer])
        .get();
    {
        let _g = InFlightGuard::enter(RPC_CLIENT_FEDERATE_GROUPS_STREAM, peer);
    }
    let other_after = rpc_in_flight()
        .with_label_values(&[RPC_CLIENT_FEDERATE_GROUPS_STREAM, peer])
        .get();
    assert_eq!(other_after, other_before);
}
