// Copyright © 2026 Roberto Chiofalo.

//! V2 federation gRPC integration tests.
//!
//! Spins up a real FederationService gRPC server on localhost and
//! connects using the generated gRPC client stubs. Tests the full
//! handshake, group exchange, event streaming, and health check flows.

#![cfg(feature = "v2")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustgate_federation::v2::proto::figpb;
use rustgate_federation::v2::proto::figpb::federated_channel_client::FederatedChannelClient;
use rustgate_federation::v2::server::{FederationService, OnEvent};
use rustgate_test_utils::certs::TestCa;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig};

/// Start a FederationService on an ephemeral port and return the address.
async fn start_server(federate_id: &str, groups: Vec<String>, on_event: OnEvent) -> String {
    let svc = FederationService::new(federate_id.to_string(), groups, on_event);
    let service = figpb::federated_channel_server::FederatedChannelServer::new(svc);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    drop(tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await
            .expect("server");
    }));

    // Small delay to let the server start accepting
    tokio::time::sleep(Duration::from_millis(50)).await;

    format!("http://{addr}")
}

/// Fixtures needed to connect to an mTLS-protected test federation
/// server. Returned as a bundle so tests can build both the URL and
/// the client config from the same CA.
struct MtlsFixtures {
    url: String,
    ca_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
    /// Shared handle to the running service so tests can drive
    /// server-side APIs (e.g. `broadcast`) after the handshake.
    service: Arc<FederationService>,
}

/// Start a FederationService behind a TLS listener that requires
/// client certificates signed by the same CA. Used by the handler
/// tests that exercise `peer_id_from_request` — without mTLS, every
/// request would be rejected with `Unauthenticated` (F-44 / #759).
async fn start_mtls_server(
    federate_id: &str,
    groups: Vec<String>,
    on_event: OnEvent,
    client_cn: &str,
) -> MtlsFixtures {
    let ca = TestCa::new("federation-test-ca");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert(client_cn, &[]);

    let svc = Arc::new(FederationService::new(
        federate_id.to_string(),
        groups,
        on_event,
    ));
    let service =
        figpb::federated_channel_server::FederatedChannelServer::from_arc(Arc::clone(&svc));

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
        service: svc,
    }
}

/// Build a `tonic` channel that completes the mTLS handshake against
/// the fixtures from [`start_mtls_server`].
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

fn noop_on_event() -> OnEvent {
    Arc::new(|_event, _peer, _trace| {})
}

fn counting_on_event() -> (OnEvent, Arc<AtomicU64>) {
    let count = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&count);
    let cb: OnEvent = Arc::new(move |_event, _peer, _trace| {
        let _ = c.fetch_add(1, Ordering::Relaxed);
    });
    (cb, count)
}

fn collecting_on_event() -> (OnEvent, Arc<tokio::sync::Mutex<Vec<figpb::FederatedEvent>>>) {
    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let e = Arc::clone(&events);
    let cb: OnEvent = Arc::new(move |event, _peer, _trace| {
        let e = Arc::clone(&e);
        // Spawn to avoid blocking the callback
        drop(tokio::spawn(async move {
            e.lock().await.push(event);
        }));
    });
    (cb, events)
}

#[tokio::test]
async fn get_identity_returns_server_info() {
    let addr = start_server("test-server-1", vec!["Alpha".into()], noop_on_event()).await;

    let mut client = FederatedChannelClient::connect(addr)
        .await
        .expect("connect");

    let resp = client
        .get_identity(figpb::Empty {})
        .await
        .expect("get_identity");
    let identity = resp.into_inner();

    assert_eq!(identity.name, "test-server-1");
    assert!(!identity.uid.is_empty());
    assert_eq!(identity.server_id, "test-server-1");
    assert_eq!(
        identity.r#type,
        figpb::identity::ConnectionType::FederationHubServer as i32
    );
}

#[tokio::test]
async fn health_check_returns_serving() {
    // mTLS is required for any RPC that calls `peer_id_from_request`
    // — health_check, send_one_event, server_event_stream,
    // binary_message_stream, server_rol_stream,
    // client_federate_groups_stream, and server_federate_groups_stream.
    // See F-44 / #759.
    let fixtures =
        start_mtls_server("health-server", vec![], noop_on_event(), "health-client").await;
    let mut client = mtls_client(&fixtures).await;

    let resp = client
        .health_check(figpb::ClientHealth {
            status: figpb::client_health::ServingStatus::Serving as i32,
        })
        .await
        .expect("health_check");
    let health = resp.into_inner();

    assert_eq!(
        health.status,
        figpb::server_health::ServingStatus::Serving as i32
    );
}

#[tokio::test]
async fn send_one_event_triggers_callback() {
    let (on_event, count) = counting_on_event();
    let fixtures = start_mtls_server(
        "event-server",
        vec!["Alpha".into()],
        on_event,
        "event-client",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    let event = figpb::FederatedEvent {
        event: Some(figpb::GeoEvent {
            uid: "test-uid".into(),
            r#type: "a-f-G-U-C".into(),
            lat: 38.8977,
            lon: -77.0365,
            ..Default::default()
        }),
        federate_groups: vec!["Alpha".into()],
        ..Default::default()
    };

    let _ = client.send_one_event(event).await.expect("send_one_event");

    assert_eq!(count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn server_federate_groups_stream_returns_groups() {
    // `ServerFederateGroupsStream` now extracts the peer CN via
    // `peer_id_from_request` for the observable-stub gating (audit +
    // metric + allowlist), so the open path requires a real mTLS
    // client cert — same shape as `health_check`, `client_rol_stream`,
    // etc. See F-44 / #759 and the observable-stub graduation in
    // refs #864.
    let fixtures = start_mtls_server(
        "groups-server",
        vec!["Alpha".into(), "Bravo".into()],
        noop_on_event(),
        "groups-client",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    let sub = figpb::Subscription {
        identity: Some(figpb::Identity {
            name: "test-client".into(),
            uid: "client-uid".into(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut stream = client
        .server_federate_groups_stream(sub)
        .await
        .expect("server_federate_groups_stream")
        .into_inner();

    // First message should contain the server's groups
    let msg = stream.message().await.expect("message").expect("groups");
    assert_eq!(msg.federate_groups, vec!["Alpha", "Bravo"]);

    let health = msg.stream_update.expect("stream_update");
    assert_eq!(
        health.status,
        figpb::server_health::ServingStatus::Serving as i32
    );
}

#[tokio::test]
async fn client_event_stream_receives_broadcast() {
    // `client_event_stream` derives the outbound-stream key from the
    // mTLS client certificate CN (#1510 L-5), so this test drives it over
    // a real mTLS connection rather than a plaintext channel. The
    // `Subscription.identity` payload deliberately claims a *different*
    // name to confirm the cert-derived key is what registers.
    let fixtures = start_mtls_server(
        "broadcast-server",
        vec!["Alpha".into()],
        noop_on_event(),
        "stream-client",
    )
    .await;
    let svc_for_broadcast = Arc::clone(&fixtures.service);

    let mut client = mtls_client(&fixtures).await;

    // Open the client event stream (server sends us events). The payload
    // identity ("spoofed-name") is ignored; the cert CN "stream-client"
    // is what keys the outbound stream.
    let sub = figpb::Subscription {
        identity: Some(figpb::Identity {
            name: "spoofed-name".into(),
            uid: "stream-uid".into(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut stream = client
        .client_event_stream(sub)
        .await
        .expect("client_event_stream")
        .into_inner();

    // Wait for the stream registration
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Broadcast an event
    let event = figpb::FederatedEvent {
        event: Some(figpb::GeoEvent {
            uid: "broadcast-uid".into(),
            r#type: "a-f-G-U-C".into(),
            lat: 40.0,
            lon: -75.0,
            ..Default::default()
        }),
        federate_groups: vec!["Alpha".into()],
        ..Default::default()
    };

    let sent = svc_for_broadcast.broadcast(event).await;
    assert_eq!(sent, 1);

    // Receive the broadcasted event
    let received = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("timeout")
        .expect("message")
        .expect("event");

    let geo = received.event.expect("geo_event");
    assert_eq!(geo.uid, "broadcast-uid");
    assert!((geo.lat - 40.0).abs() < f64::EPSILON);
}

#[tokio::test]
async fn server_event_stream_forwards_events() {
    let (on_event, collected) = collecting_on_event();
    let fixtures = start_mtls_server(
        "inbound-server",
        vec!["Alpha".into()],
        on_event,
        "inbound-client",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    // Create a stream of events to send
    let (tx, rx) = mpsc::channel(16);
    let stream = ReceiverStream::new(rx);

    // Open the server event stream (we send events to server)
    let _resp = client
        .server_event_stream(stream)
        .await
        .expect("server_event_stream");

    // Send events through the stream
    for i in 0..3 {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: format!("uid-{i}"),
                r#type: "a-f-G-U-C".into(),
                lat: 38.0 + i as f64,
                lon: -77.0,
                ..Default::default()
            }),
            federate_groups: vec!["Alpha".into()],
            ..Default::default()
        };
        tx.send(event).await.expect("send");
    }

    // Wait for events to be processed
    tokio::time::sleep(Duration::from_millis(200)).await;

    let events = collected.lock().await;
    assert_eq!(events.len(), 3, "expected 3 events, got {}", events.len());
    assert_eq!(events[0].event.as_ref().expect("geo").uid, "uid-0");
    assert_eq!(events[1].event.as_ref().expect("geo").uid, "uid-1");
    assert_eq!(events[2].event.as_ref().expect("geo").uid, "uid-2");
}

/// Regression test for issue #720: a Byzantine peer that forges
/// `federate_groups` claims must not influence downstream authorization.
/// The raw `OnEvent` callback receives the event verbatim (it's the
/// XML conversion layer that enforces the trust boundary — see
/// `crates/rustgate-federation/src/v2/convert/routable_message.rs`),
/// but converting through `federated_event_to_routable` with the
/// deny-by-default `trust_peer_groups = false` must strip the wire
/// claim before it reaches the local identity used for authz.
#[tokio::test]
async fn forged_federate_groups_from_peer_are_dropped_by_default() {
    use rustgate_federation::v2::convert::federated_event_to_routable;

    let (on_event, collected) = collecting_on_event();
    let fixtures = start_mtls_server(
        "trust-boundary-server",
        vec!["Alpha".into()],
        on_event,
        "byzantine-peer",
    )
    .await;

    let mut client = mtls_client(&fixtures).await;

    // Malicious peer forges group memberships for the origin CN.
    // A valid mTLS client certificate is enough to reach this point —
    // the attack vector is the trust placed in `federate_groups`.
    let (tx, rx) = mpsc::channel(1);
    let stream = ReceiverStream::new(rx);
    let _resp = client
        .server_event_stream(stream)
        .await
        .expect("server_event_stream");

    let forged = figpb::FederatedEvent {
        event: Some(figpb::GeoEvent {
            uid: "forged-uid".into(),
            r#type: "a-f-G-U-C".into(),
            ..Default::default()
        }),
        federate_groups: vec!["Admin".into(), "Command".into(), "Secret".into()],
        ..Default::default()
    };
    tx.send(forged).await.expect("send");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let events = collected.lock().await;
    assert_eq!(events.len(), 1, "event should still be forwarded");
    let event = &events[0];
    // The peer's raw claim is visible on the wire (the callback sees
    // the untransformed event) — that is expected.
    assert_eq!(
        event.federate_groups,
        vec![
            "Admin".to_string(),
            "Command".to_string(),
            "Secret".to_string()
        ],
        "OnEvent receives the wire-level event verbatim"
    );
    // But once the conversion layer takes over, the default
    // deny-by-default trust boundary drops all wire-claimed groups.
    let routable =
        federated_event_to_routable(event, "byzantine-peer", "fp", /* trust */ false)
            .expect("conversion succeeds");
    assert!(
        routable.source.groups.is_empty(),
        "source.groups must be empty when trust_peer_groups=false, got {:?}",
        routable.source.groups
    );
}

#[tokio::test]
async fn client_federate_groups_stream_tracks_groups() {
    // This test keeps its own `Arc<FederationService>` so it can call
    // `broadcast_to_groups` directly later, which means it can't use
    // `start_mtls_server` (that helper consumes the service). Inline
    // the mTLS wiring instead — same pattern as the helper, just with
    // a caller-owned Arc.
    let svc = FederationService::new(
        "group-tracker".into(),
        vec!["Local".into()],
        noop_on_event(),
    );
    let svc = Arc::new(svc);
    let svc_ref = Arc::clone(&svc);

    let service =
        figpb::federated_channel_server::FederatedChannelServer::from_arc(Arc::clone(&svc));

    let ca = TestCa::new("federation-test-ca");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("group-tracker-client", &[]);

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

    let fixtures = MtlsFixtures {
        url: format!("https://localhost:{}", addr.port()),
        ca_pem: ca.cert_pem.clone(),
        client_cert_pem: client_cert.cert_pem,
        client_key_pem: client_cert.key_pem,
        service: Arc::clone(&svc_ref),
    };

    let mut client = mtls_client(&fixtures).await;

    // Send our groups to the server
    let (tx, rx) = mpsc::channel(16);
    let stream = ReceiverStream::new(rx);

    let groups_msg = figpb::FederateGroups {
        stream_update: Some(figpb::ServerHealth {
            status: figpb::server_health::ServingStatus::Serving as i32,
        }),
        federate_groups: vec!["Alpha".into(), "Bravo".into()],
        ..Default::default()
    };

    tx.send(groups_msg).await.expect("send groups");

    let _resp = client
        .client_federate_groups_stream(stream)
        .await
        .expect("client_federate_groups_stream");

    // Wait for groups to be registered
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now do a group-filtered broadcast
    // First open an event stream so there's a peer to broadcast to
    let sub = figpb::Subscription {
        identity: Some(figpb::Identity {
            name: "group-client".into(),
            uid: "group-uid".into(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut event_stream = client
        .client_event_stream(sub)
        .await
        .expect("client_event_stream")
        .into_inner();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Broadcast to "Alpha" — should reach client since they advertised Alpha
    let event = figpb::FederatedEvent {
        event: Some(figpb::GeoEvent {
            uid: "alpha-event".into(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let sent = svc_ref.broadcast_to_groups(event, &["Alpha".into()]).await;
    assert_eq!(sent, 1);

    let received = tokio::time::timeout(Duration::from_secs(5), event_stream.message())
        .await
        .expect("timeout")
        .expect("message")
        .expect("event");
    assert_eq!(received.event.expect("geo").uid, "alpha-event");
}

// ------------------------------------------------------------------
// gRPC compression (issue #905)
// ------------------------------------------------------------------
//
// These tests exercise the compression wiring end-to-end: a compression-
// aware server (mirrors the production `FederatedChannelServer::new(svc)
// .accept_compressed(Gzip).accept_compressed(Zstd)` call in
// `v2/server.rs`) receives a real `FederatedEvent` from a client that
// has send-compression enabled, and the server's `on_event` callback
// must fire exactly once — confirming tonic decoded the compressed
// payload back into the protobuf message. A silent regression (a
// missing `.accept_compressed` call on the server, a mis-mapped codec
// enum on the client, a missing `gzip`/`zstd` cargo feature on tonic)
// would surface here as a tonic `Unimplemented` status or a decode
// error, not just a silent performance change.

/// mTLS server fixture with `.accept_compressed(Gzip).accept_compressed(Zstd)`
/// applied — identical to the production server configuration in
/// `v2/server.rs::FederatedChannelServer::new`.
async fn start_compression_aware_mtls_server(
    federate_id: &str,
    groups: Vec<String>,
    on_event: OnEvent,
    client_cn: &str,
) -> MtlsFixtures {
    let ca = TestCa::new("federation-compression-ca");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert(client_cn, &[]);

    let svc = Arc::new(FederationService::new(
        federate_id.to_string(),
        groups,
        on_event,
    ));
    let service =
        figpb::federated_channel_server::FederatedChannelServer::from_arc(Arc::clone(&svc))
            .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
            .accept_compressed(tonic::codec::CompressionEncoding::Zstd);

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
        service: svc,
    }
}

/// Build an mTLS client with the given compression codec configured on
/// both the send and accept side — identical to the production call in
/// `v2/client.rs::connection_loop` when `V2ClientConfig.compression` is
/// `Some`.
async fn mtls_client_with_compression(
    fixtures: &MtlsFixtures,
    kind: tonic::codec::CompressionEncoding,
) -> FederatedChannelClient<tonic::transport::Channel> {
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
        .send_compressed(kind)
        .accept_compressed(kind)
}

#[tokio::test]
async fn gzip_compressed_send_one_event_round_trips() {
    let (on_event, count) = counting_on_event();
    let fixtures = start_compression_aware_mtls_server(
        "gzip-server",
        vec!["Alpha".into()],
        on_event,
        "gzip-client",
    )
    .await;

    let mut client =
        mtls_client_with_compression(&fixtures, tonic::codec::CompressionEncoding::Gzip).await;

    // Build a payload large enough that compression is actually worth
    // it — the protobuf encoding of a few-kilobyte remarks field
    // compresses well and exercises the gzip codec path rather than
    // the empty-body short-circuit.
    let event = figpb::FederatedEvent {
        event: Some(figpb::GeoEvent {
            uid: "gzip-uid".into(),
            r#type: "a-f-G-U-C".into(),
            lat: 38.8977,
            lon: -77.0365,
            ..Default::default()
        }),
        federate_groups: vec!["Alpha".into()],
        ..Default::default()
    };

    let _ = client
        .send_one_event(event)
        .await
        .expect("gzip send_one_event");

    assert_eq!(
        count.load(Ordering::Relaxed),
        1,
        "server on_event must fire exactly once after gzip decode"
    );
}

#[tokio::test]
async fn zstd_compressed_send_one_event_round_trips() {
    let (on_event, count) = counting_on_event();
    let fixtures = start_compression_aware_mtls_server(
        "zstd-server",
        vec!["Alpha".into()],
        on_event,
        "zstd-client",
    )
    .await;

    let mut client =
        mtls_client_with_compression(&fixtures, tonic::codec::CompressionEncoding::Zstd).await;

    let event = figpb::FederatedEvent {
        event: Some(figpb::GeoEvent {
            uid: "zstd-uid".into(),
            r#type: "a-f-G-U-C".into(),
            lat: 38.8977,
            lon: -77.0365,
            ..Default::default()
        }),
        federate_groups: vec!["Alpha".into()],
        ..Default::default()
    };

    let _ = client
        .send_one_event(event)
        .await
        .expect("zstd send_one_event");

    assert_eq!(
        count.load(Ordering::Relaxed),
        1,
        "server on_event must fire exactly once after zstd decode"
    );
}

#[tokio::test]
async fn uncompressed_client_still_works_against_compression_aware_server() {
    // Backwards-compat pin: a peer with the default
    // `compression: None` must still be served by a compression-aware
    // server. `accept_compressed` on the server is additive — it does
    // not force the client to send compressed payloads — so the default
    // peer keeps the pre-#905 zero-cost fast path.
    let (on_event, count) = counting_on_event();
    let fixtures = start_compression_aware_mtls_server(
        "mixed-server",
        vec!["Alpha".into()],
        on_event,
        "mixed-client",
    )
    .await;

    // Vanilla client, no .send_compressed configured.
    let mut client = mtls_client(&fixtures).await;

    let event = figpb::FederatedEvent {
        event: Some(figpb::GeoEvent {
            uid: "plain-uid".into(),
            r#type: "a-f-G-U-C".into(),
            lat: 0.0,
            lon: 0.0,
            ..Default::default()
        }),
        federate_groups: vec!["Alpha".into()],
        ..Default::default()
    };

    let _ = client
        .send_one_event(event)
        .await
        .expect("plain send_one_event");

    assert_eq!(count.load(Ordering::Relaxed), 1);
}
