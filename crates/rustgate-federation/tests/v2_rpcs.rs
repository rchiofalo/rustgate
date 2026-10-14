// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! V2 federation ROL / `BinaryBlob` / GroupSync round-trip integration
//! tests (refs #864).
//!
//! These tests stand up a real `FederationService` mTLS gRPC server and
//! drive the `FederatedChannelClient` directly to verify that:
//!
//! - `SendOneBlob` (unary) accepts a `BinaryBlob` and the server's
//!   `OnBlob` callback fires with the payload intact.
//! - `ServerROLStream` (client-streaming) accepts a stream of `Rol`
//!   messages and the server's `OnRolEvent` callback fires once per event.
//! - `ClientFederateGroupsStream` (client-streaming) accepts a stream of
//!   `FederateGroups` updates and the server's `OnGroupSync` callback fires
//!   once per update.
//!
//! The tests use the wire-level `FederatedChannelClient` (not the higher-
//! level `V2Client`) so the round-trip exercises only the gRPC wire
//! contract — `V2Client::send_blob` / `send_rol` / `send_groups` are
//! covered by separate `v2::client::tests` unit tests that drive the
//! channel-closure paths without needing a full TLS handshake.

#![cfg(feature = "v2")]
#![allow(unused_results, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustgate_federation::v2::proto::figpb;
use rustgate_federation::v2::proto::figpb::federated_channel_client::FederatedChannelClient;
use rustgate_federation::v2::server::{FederationService, OnBlob, OnGroupSync, OnRolEvent};
use rustgate_test_utils::certs::TestCa;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig};

/// mTLS fixtures returned by [`start_mtls_server_full`]. Mirrors the
/// `MtlsFixtures` struct in `v2_integration.rs` — split out into this
/// file so the round-trip tests own their fixture surface and do not
/// drag in the broader integration helpers.
struct MtlsFixtures {
    url: String,
    ca_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

/// Spin up a `FederationService` behind an mTLS listener with
/// configurable callbacks for all three V2 RPCs (refs #864). Each
/// callback defaults to a no-op when `None` is passed; tests that
/// only care about one RPC can leave the others unset.
async fn start_mtls_server_full(
    federate_id: &str,
    groups: Vec<String>,
    on_blob: Option<OnBlob>,
    on_rol_event: Option<OnRolEvent>,
    on_group_sync: Option<OnGroupSync>,
    client_cn: &str,
) -> MtlsFixtures {
    let ca = TestCa::new("federation-rpc-ca");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert(client_cn, &[]);

    // The OnEvent callback is irrelevant for these tests but the
    // `FederationService::new` builder requires one — pass a no-op.
    let no_op_event: rustgate_federation::v2::server::OnEvent =
        Arc::new(|_event, _peer, _trace| {});
    let mut svc = FederationService::new(federate_id.to_string(), groups, no_op_event);
    if let Some(cb) = on_blob {
        svc = svc.with_on_blob(cb);
    }
    if let Some(cb) = on_rol_event {
        svc = svc.with_on_rol_event(cb);
    }
    if let Some(cb) = on_group_sync {
        svc = svc.with_on_group_sync(cb);
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

    tokio::time::sleep(Duration::from_millis(50)).await;

    MtlsFixtures {
        url: format!("https://localhost:{}", addr.port()),
        ca_pem: ca.cert_pem.clone(),
        client_cert_pem: client_cert.cert_pem,
        client_key_pem: client_cert.key_pem,
    }
}

/// Connect to an mTLS-protected federation server using the wire-level
/// `FederatedChannelClient`.
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

// -- BinaryBlob (unary SendOneBlob) ---------------------------------

#[tokio::test]
async fn send_one_blob_round_trip_invokes_on_blob() {
    // Capture the inbound blob so we can assert its bytes round-trip
    // intact. Using a `tokio::sync::Mutex<Vec<_>>` lets us collect
    // multiple blobs in a single test without race conditions on the
    // callback's internal buffer.
    let received = Arc::new(tokio::sync::Mutex::new(Vec::<figpb::BinaryBlob>::new()));
    let received_for_cb = Arc::clone(&received);
    let on_blob: OnBlob = Arc::new(move |blob, _peer| {
        let received = Arc::clone(&received_for_cb);
        drop(tokio::spawn(async move {
            received.lock().await.push(blob);
        }));
    });

    let fixtures = start_mtls_server_full(
        "blob-server",
        vec!["Alpha".into()],
        Some(on_blob),
        None,
        None,
        "blob-client",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    let payload: Vec<u8> = b"the quick brown fox jumps over the lazy dog".to_vec();
    let blob = figpb::BinaryBlob {
        r#type: figpb::BinaryTypes::Other as i32,
        data: payload.clone(),
        filename: "pangram.txt".into(),
        timestamp: 1_700_000_000,
        description: "test blob".into(),
        federate_provenance: Vec::new(),
        federate_hops: None,
        federate_group_hop_limits: None,
    };

    client.send_one_blob(blob).await.expect("send_one_blob");

    // Allow the spawned receiver to finish pushing into the vec.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let received = received.lock().await;
    assert_eq!(received.len(), 1, "exactly one blob should arrive");
    let got = &received[0];
    assert_eq!(got.data, payload, "blob payload bytes round-trip intact");
    assert_eq!(got.filename, "pangram.txt");
    assert_eq!(got.description, "test blob");
    assert_eq!(got.timestamp, 1_700_000_000);
    assert_eq!(got.r#type, figpb::BinaryTypes::Other as i32);
}

#[tokio::test]
async fn send_one_blob_with_no_callback_still_succeeds() {
    // Default `OnBlob` is a no-op factory inside FederationService.
    // The RPC must still complete and return Empty without surfacing
    // a Status to the caller — proves the no-op default is
    // unconditionally invoked rather than left as `None`.
    let fixtures = start_mtls_server_full(
        "blob-noop-server",
        vec![],
        None,
        None,
        None,
        "blob-noop-client",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    let blob = figpb::BinaryBlob {
        r#type: figpb::BinaryTypes::Empty as i32,
        ..Default::default()
    };

    let resp = client.send_one_blob(blob).await.expect("send_one_blob");
    let _empty: figpb::Empty = resp.into_inner();
}

#[tokio::test]
async fn send_one_blob_at_hop_limit_silently_drops() {
    // Hop-count exceeded blobs are dropped at the protocol layer with
    // an audit record; the RPC still returns Empty (the wire contract
    // has no per-RPC "rejected" signal beyond Status, and the server
    // intentionally doesn't surface that for hop drops). This test
    // pins the silent-drop behaviour: callback must not fire.
    let count = Arc::new(AtomicU64::new(0));
    let count_for_cb = Arc::clone(&count);
    let on_blob: OnBlob = Arc::new(move |_blob, _peer| {
        let _ = count_for_cb.fetch_add(1, Ordering::Relaxed);
    });

    let fixtures = start_mtls_server_full(
        "blob-hop-server",
        vec![],
        Some(on_blob),
        None,
        None,
        "blob-hop-client",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    // Default max_hops = 8; send a blob that's already at the limit.
    let blob = figpb::BinaryBlob {
        federate_hops: Some(figpb::FederateHops {
            max_hops: 8,
            current_hops: 8,
        }),
        ..Default::default()
    };

    let _ = client.send_one_blob(blob).await.expect("send_one_blob");

    // Give the server time to process (or not).
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        count.load(Ordering::Relaxed),
        0,
        "callback must not fire when hop limit is exceeded"
    );
}

// -- ROL (client-streaming ServerROLStream) -------------------------

#[tokio::test]
async fn server_rol_stream_round_trip_invokes_on_rol_event() {
    // Three ROL events go up the stream; the server must invoke
    // `on_rol_event` exactly three times with the right `program`
    // values in order. Programs are TAK-side dictionary identifiers —
    // they're the most caller-visible field on `Rol`, so asserting
    // against them gives the clearest signal that payloads are
    // round-tripping.
    let received = Arc::new(tokio::sync::Mutex::new(Vec::<figpb::Rol>::new()));
    let received_for_cb = Arc::clone(&received);
    let on_rol_event: OnRolEvent = Arc::new(move |rol, _peer| {
        let received = Arc::clone(&received_for_cb);
        drop(tokio::spawn(async move {
            received.lock().await.push(rol);
        }));
    });

    let fixtures = start_mtls_server_full(
        "rol-server",
        vec!["Alpha".into()],
        None,
        Some(on_rol_event),
        None,
        "rol-client",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    let (tx, rx) = mpsc::channel::<figpb::Rol>(8);
    let stream = ReceiverStream::new(rx);

    let _resp = client
        .server_rol_stream(stream)
        .await
        .expect("server_rol_stream");

    for program in &["dict-update-1", "dict-update-2", "object-delete"] {
        tx.send(figpb::Rol {
            program: (*program).to_string(),
            ..Default::default()
        })
        .await
        .expect("send rol");
    }

    // Drop the tx so the server's drain loop sees end-of-stream and
    // we don't race on shutdown timing.
    drop(tx);

    // Allow time for the server's drain loop and the spawned
    // collector to finish.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let received = received.lock().await;
    assert_eq!(
        received.len(),
        3,
        "expected 3 ROL events, got {}",
        received.len()
    );
    let programs: Vec<&str> = received.iter().map(|r| r.program.as_str()).collect();
    assert_eq!(
        programs,
        vec!["dict-update-1", "dict-update-2", "object-delete"]
    );
}

#[tokio::test]
async fn server_rol_stream_drops_event_at_hop_limit() {
    // Hop-count exceeded ROL events are filtered before the callback
    // — same policy as `SendOneBlob`. Two events: one valid, one at
    // the hop limit. Only the valid one must reach the callback.
    let count = Arc::new(AtomicU64::new(0));
    let count_for_cb = Arc::clone(&count);
    let on_rol_event: OnRolEvent = Arc::new(move |_rol, _peer| {
        let _ = count_for_cb.fetch_add(1, Ordering::Relaxed);
    });

    let fixtures = start_mtls_server_full(
        "rol-hop-server",
        vec![],
        None,
        Some(on_rol_event),
        None,
        "rol-hop-client",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    let (tx, rx) = mpsc::channel::<figpb::Rol>(8);
    let stream = ReceiverStream::new(rx);
    let _resp = client
        .server_rol_stream(stream)
        .await
        .expect("server_rol_stream");

    // Valid ROL — first hop, no metadata.
    tx.send(figpb::Rol {
        program: "valid".into(),
        ..Default::default()
    })
    .await
    .expect("send valid");

    // Over-hop ROL — current_hops == max_hops triggers the drop.
    tx.send(figpb::Rol {
        program: "over-hop".into(),
        federate_hops: Some(figpb::FederateHops {
            max_hops: 8,
            current_hops: 8,
        }),
        ..Default::default()
    })
    .await
    .expect("send over-hop");

    drop(tx);

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        count.load(Ordering::Relaxed),
        1,
        "only the valid ROL should reach the callback"
    );
}

// -- GroupSync (client-streaming ClientFederateGroupsStream) --------

#[tokio::test]
async fn client_federate_groups_stream_round_trip_invokes_on_group_sync() {
    // Three group-sync updates climb the stream; the server's
    // `on_group_sync` callback must fire exactly three times. The
    // existing `peer_groups` bookkeeping (count + name-length limits)
    // continues to run alongside — that path is covered by the
    // pre-existing `client_federate_groups_stream_tracks_groups` test
    // in `v2_integration.rs`, so this test focuses on the callback.
    let received = Arc::new(tokio::sync::Mutex::new(Vec::<figpb::FederateGroups>::new()));
    let received_for_cb = Arc::clone(&received);
    let on_group_sync: OnGroupSync = Arc::new(move |groups, _peer| {
        let received = Arc::clone(&received_for_cb);
        drop(tokio::spawn(async move {
            received.lock().await.push(groups);
        }));
    });

    let fixtures = start_mtls_server_full(
        "groupsync-server",
        vec!["Local".into()],
        None,
        None,
        Some(on_group_sync),
        "groupsync-client",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    let (tx, rx) = mpsc::channel::<figpb::FederateGroups>(8);
    let stream = ReceiverStream::new(rx);
    let _resp = client
        .client_federate_groups_stream(stream)
        .await
        .expect("client_federate_groups_stream");

    let updates = vec![
        figpb::FederateGroups {
            stream_update: Some(figpb::ServerHealth {
                status: figpb::server_health::ServingStatus::Serving as i32,
            }),
            federate_groups: vec!["Alpha".into()],
            ..Default::default()
        },
        figpb::FederateGroups {
            stream_update: Some(figpb::ServerHealth {
                status: figpb::server_health::ServingStatus::Serving as i32,
            }),
            federate_groups: vec!["Alpha".into(), "Bravo".into()],
            ..Default::default()
        },
        figpb::FederateGroups {
            stream_update: Some(figpb::ServerHealth {
                status: figpb::server_health::ServingStatus::Serving as i32,
            }),
            federate_groups: vec!["Charlie".into()],
            ..Default::default()
        },
    ];

    for update in &updates {
        tx.send(update.clone()).await.expect("send group update");
    }

    drop(tx);

    tokio::time::sleep(Duration::from_millis(200)).await;

    let received = received.lock().await;
    assert_eq!(
        received.len(),
        3,
        "expected 3 group updates, got {}",
        received.len()
    );
    let groups_at_step_2: &Vec<String> = &received[1].federate_groups;
    assert_eq!(
        groups_at_step_2,
        &vec!["Alpha".to_string(), "Bravo".to_string()]
    );
}

#[tokio::test]
async fn client_federate_groups_stream_drops_update_at_hop_limit() {
    let count = Arc::new(AtomicU64::new(0));
    let count_for_cb = Arc::clone(&count);
    let on_group_sync: OnGroupSync = Arc::new(move |_groups, _peer| {
        let _ = count_for_cb.fetch_add(1, Ordering::Relaxed);
    });

    let fixtures = start_mtls_server_full(
        "groupsync-hop-server",
        vec![],
        None,
        None,
        Some(on_group_sync),
        "groupsync-hop-client",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    let (tx, rx) = mpsc::channel::<figpb::FederateGroups>(8);
    let stream = ReceiverStream::new(rx);
    let _resp = client
        .client_federate_groups_stream(stream)
        .await
        .expect("client_federate_groups_stream");

    // Valid update.
    tx.send(figpb::FederateGroups {
        federate_groups: vec!["A".into()],
        ..Default::default()
    })
    .await
    .expect("send valid");

    // Hop-exceeded update.
    tx.send(figpb::FederateGroups {
        federate_groups: vec!["B".into()],
        federate_hops: Some(figpb::FederateHops {
            max_hops: 8,
            current_hops: 8,
        }),
        ..Default::default()
    })
    .await
    .expect("send hop-exceeded");

    drop(tx);

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        count.load(Ordering::Relaxed),
        1,
        "only the valid update should reach the callback"
    );
}
