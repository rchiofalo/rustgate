// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Drain test for the V1 federation inbound server (F-133, refs #789).
//!
//! Pins the contract that [`V1Server::shutdown`] honours its watch-channel
//! shutdown signal and returns within the workspace's 5-second graceful
//! drain budget, even when the accept loop has been running for some
//! time.
//!
//! Mirrors the abstract `SubsystemHandle` drain test in
//! `rustgate-server/tests/shutdown_drains_subsystems.rs` (added by
//! #1270). That file pins the abstraction; this file pins the concrete
//! V1 federation listener wiring. V1 uses an internal
//! `tokio::sync::watch` instead of a `Notify`, but the contract is
//! identical: the accept loop must observe the wakeup and unwind in
//! well under 5 seconds.
//!
//! V2 is gRPC + tonic, where shutdown is exercised by tonic's own
//! `serve_with_shutdown` future already covered by `v2_integration.rs`
//! and `v2_rpcs.rs`. This file pins the V1 surface, which is the only
//! drain path with a hand-rolled accept loop in this crate.

use std::sync::Arc;
use std::time::Duration;

use rustgate_federation::v1::server::{OnMessage, V1Server};
use rustgate_test_utils::certs::TestCa;
use rustgate_transport::TlsConfig;

const DRAIN_BUDGET: Duration = Duration::from_secs(5);

fn test_tls_config(ca: &TestCa) -> TlsConfig {
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config")
}

#[tokio::test]
async fn shutdown_drains_idle_v1_server_within_budget() {
    // Strong-form pin: with no peers connected the accept loop must
    // still observe the shutdown wakeup. A regression that left the
    // `select!` arm watching the wrong channel would only show up
    // here — this test would catch it via the 5-second timeout.
    let ca = TestCa::new("Federation Drain CA");
    let tls_config = test_tls_config(&ca);

    let on_msg: OnMessage = Arc::new(|_cn, _data| {});
    let mut server = V1Server::start(
        "127.0.0.1:0".parse().expect("addr"),
        &tls_config,
        "drain-test-server".into(),
        Duration::from_secs(30),
        Duration::from_secs(90),
        on_msg,
        None,
    )
    .await
    .expect("start V1 server");

    // Give the accept loop a moment to enter `select!`.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = std::time::Instant::now();
    tokio::time::timeout(DRAIN_BUDGET, server.shutdown())
        .await
        .expect("idle V1 federation server must drain within the 5s budget");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "idle federation drain should be near-instant, got {elapsed:?}"
    );
}

#[tokio::test]
async fn shutdown_drains_after_repeated_signals() {
    // Cross-check the documented #1270 behavior that repeated shutdown
    // signals are idempotent — `V1Server::shutdown` may be called
    // many times without panicking and each call must return inside
    // the budget.
    let ca = TestCa::new("Federation Drain CA");
    let tls_config = test_tls_config(&ca);

    let on_msg: OnMessage = Arc::new(|_cn, _data| {});
    let mut server = V1Server::start(
        "127.0.0.1:0".parse().expect("addr"),
        &tls_config,
        "drain-repeat-server".into(),
        Duration::from_secs(30),
        Duration::from_secs(90),
        on_msg,
        None,
    )
    .await
    .expect("start V1 server");

    // First call drains the listener task.
    let started = std::time::Instant::now();
    tokio::time::timeout(DRAIN_BUDGET, server.shutdown())
        .await
        .expect("first shutdown must drain within the 5s budget");
    // Subsequent calls are no-ops — they must still return inside the
    // budget rather than blocking.
    tokio::time::timeout(DRAIN_BUDGET, server.shutdown())
        .await
        .expect("second shutdown must remain within the 5s budget");
    tokio::time::timeout(DRAIN_BUDGET, server.shutdown())
        .await
        .expect("third shutdown must remain within the 5s budget");
    let elapsed = started.elapsed();
    assert!(
        elapsed < DRAIN_BUDGET,
        "three shutdowns combined must stay below the 5s budget: {elapsed:?}"
    );
}
