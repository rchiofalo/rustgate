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
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

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

fn noop_on_event() -> OnEvent {
    Arc::new(|_event, _peer| {})
}

fn counting_on_event() -> (OnEvent, Arc<AtomicU64>) {
    let count = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&count);
    let cb: OnEvent = Arc::new(move |_event, _peer| {
        let _ = c.fetch_add(1, Ordering::Relaxed);
    });
    (cb, count)
}

fn collecting_on_event() -> (OnEvent, Arc<tokio::sync::Mutex<Vec<figpb::FederatedEvent>>>) {
    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let e = Arc::clone(&events);
    let cb: OnEvent = Arc::new(move |event, _peer| {
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
    let addr = start_server("health-server", vec![], noop_on_event()).await;

    let mut client = FederatedChannelClient::connect(addr)
        .await
        .expect("connect");

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
    let addr = start_server("event-server", vec!["Alpha".into()], on_event).await;

    let mut client = FederatedChannelClient::connect(addr)
        .await
        .expect("connect");

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
    let addr = start_server(
        "groups-server",
        vec!["Alpha".into(), "Bravo".into()],
        noop_on_event(),
    )
    .await;

    let mut client = FederatedChannelClient::connect(addr)
        .await
        .expect("connect");

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
    let svc = FederationService::new(
        "broadcast-server".into(),
        vec!["Alpha".into()],
        noop_on_event(),
    );
    let svc = Arc::new(svc);
    let svc_for_broadcast = Arc::clone(&svc);

    let service =
        figpb::federated_channel_server::FederatedChannelServer::from_arc(Arc::clone(&svc));

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

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = FederatedChannelClient::connect(format!("http://{addr}"))
        .await
        .expect("connect");

    // Open the client event stream (server sends us events)
    let sub = figpb::Subscription {
        identity: Some(figpb::Identity {
            name: "stream-client".into(),
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
    let addr = start_server("inbound-server", vec!["Alpha".into()], on_event).await;

    let mut client = FederatedChannelClient::connect(addr)
        .await
        .expect("connect");

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

#[tokio::test]
async fn client_federate_groups_stream_tracks_groups() {
    let svc = FederationService::new(
        "group-tracker".into(),
        vec!["Local".into()],
        noop_on_event(),
    );
    let svc = Arc::new(svc);
    let svc_ref = Arc::clone(&svc);

    let service =
        figpb::federated_channel_server::FederatedChannelServer::from_arc(Arc::clone(&svc));

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

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = FederatedChannelClient::connect(format!("http://{addr}"))
        .await
        .expect("connect");

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
