// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the IPv4 UDP multicast CoT input + optional
//! rebroadcast egress paths. Closes #861.
//!
//! ## CI must enable multicast
//!
//! Some CI runners disable IPv4 multicast on the loopback interface or
//! refuse `join_multicast_v4`. The integration tests below are gated
//! with `#[cfg_attr(not(target_os = "linux"), ignore)]` so non-Linux
//! CI ignores them; on Linux runners the kernel typically allows
//! 224.0.0.0/4 on `lo` provided the loopback iface is up.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{
    MulticastConfig, MulticastGroup, RoutedMessage, Router, SessionHandle, udp_multicast,
};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};

/// Pick a per-test unique IPv4 multicast address + port. Different
/// tests must not share a `(addr, port)` because joins are sticky on
/// the kernel side and tests run in parallel.
fn unique_group(salt: u16) -> MulticastGroup {
    // 239.x.y.z is the IPv4 administratively-scoped block — safe for
    // tests because routers don't forward it. We compose a
    // per-test-unique address using the salt so parallel tests on the
    // same loopback don't collide.
    let third = ((salt >> 8) & 0xff) as u8;
    let fourth = (salt & 0xff) as u8;
    MulticastGroup {
        addr: Ipv4Addr::new(239, 200, third, fourth.max(1)),
        port: 30_000_u16.saturating_add(salt),
    }
}

fn cot_xml(uid: &str) -> Bytes {
    let s = format!(
        r#"<event version="2.0" uid="{uid}" type="a-f-G" start="2025-01-01T00:00:00Z" stale="2025-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0"/></event>"#
    );
    Bytes::from(s)
}

fn register_listener(
    router: &Arc<Router>,
    cn: &str,
) -> (mpsc::Receiver<RoutedMessage>, mpsc::Receiver<RoutedMessage>) {
    let mut groups = BTreeSet::new();
    let _ = groups.insert("__plaintext__".to_string());
    let id = Arc::new(Identity::plaintext(cn.to_string(), groups).expect("identity"));
    let (ptx, prx) = mpsc::channel::<RoutedMessage>(64);
    let (ntx, nrx) = mpsc::channel::<RoutedMessage>(64);
    let h = SessionHandle::new(id, ptx, ntx);
    let r = Arc::clone(router);
    let _ = futures::executor::block_on(r.register(h));
    (prx, nrx)
}

async fn send_multicast_once(group: &MulticastGroup, payload: &[u8]) {
    let sender = UdpSocket::bind("0.0.0.0:0").await.expect("sender bind");
    sender
        .set_multicast_loop_v4(true)
        .expect("loop on for test send");
    let _ = sender
        .send_to(payload, (group.addr, group.port))
        .await
        .expect("send_to multicast group");
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn udp_multicast_join_on_default_group() {
    // Bind, join 239.200.0.1:30001, send a CoT datagram from a sibling
    // socket, assert the listener processes it (no router subscriber
    // assertion here — that's the next test).
    let group = unique_group(1);
    let router = Arc::new(Router::new());

    let cfg = MulticastConfig {
        groups: vec![group.clone()],
        interface: Ipv4Addr::UNSPECIFIED,
        // Loop must be true to observe our own send on the same host.
        multicast_loop: true,
        ..MulticastConfig::default()
    };
    let shutdown = Arc::new(Notify::new());

    // Subscribe before sending so the routed message can be observed.
    let (mut prx, mut nrx) = register_listener(&router, "join-listener");

    let handles = udp_multicast::spawn_inbound(cfg, Arc::clone(&router), Arc::clone(&shutdown))
        .expect("spawn inbound");
    assert_eq!(handles.len(), 1, "one group => one task");

    // Give the kernel a beat to register the join.
    tokio::time::sleep(Duration::from_millis(150)).await;
    send_multicast_once(&group, &cot_xml("MC-JOIN-1")).await;

    let msg = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            biased;
            m = prx.recv() => m,
            m = nrx.recv() => m,
        }
    })
    .await
    .expect("multicast datagram should be received and routed")
    .expect("recv");
    assert_eq!(msg.metadata.source_protocol, "udp-multicast");

    shutdown.notify_waiters();
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn udp_multicast_dispatches_through_router() {
    // Plus assert a registered subscriber actually received the
    // routed message.
    let group = unique_group(2);
    let router = Arc::new(Router::new());

    let (mut prx, mut nrx) = register_listener(&router, "dispatch-listener");

    let cfg = MulticastConfig {
        groups: vec![group.clone()],
        interface: Ipv4Addr::UNSPECIFIED,
        multicast_loop: true,
        ..MulticastConfig::default()
    };
    let shutdown = Arc::new(Notify::new());

    let handles = udp_multicast::spawn_inbound(cfg, Arc::clone(&router), Arc::clone(&shutdown))
        .expect("spawn inbound");

    tokio::time::sleep(Duration::from_millis(150)).await;
    send_multicast_once(&group, &cot_xml("MC-DISPATCH")).await;

    let msg = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            biased;
            m = prx.recv() => m,
            m = nrx.recv() => m,
        }
    })
    .await
    .expect("subscriber should observe the routed message")
    .expect("recv");
    assert_eq!(msg.metadata.source_protocol, "udp-multicast");
    // The CoT uid must be embedded in the routed payload.
    assert!(
        std::str::from_utf8(&msg.payload)
            .unwrap_or("")
            .contains("MC-DISPATCH"),
        "payload should round-trip the original CoT bytes"
    );

    shutdown.notify_waiters();
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn udp_multicast_source_protocol_stamped_correctly() {
    let group = unique_group(3);
    let router = Arc::new(Router::new());
    let (mut prx, mut nrx) = register_listener(&router, "src-proto-listener");

    let cfg = MulticastConfig {
        groups: vec![group.clone()],
        multicast_loop: true,
        ..MulticastConfig::default()
    };
    let shutdown = Arc::new(Notify::new());
    let handles = udp_multicast::spawn_inbound(cfg, Arc::clone(&router), Arc::clone(&shutdown))
        .expect("spawn inbound");

    tokio::time::sleep(Duration::from_millis(150)).await;
    send_multicast_once(&group, &cot_xml("MC-PROTO")).await;

    let msg = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            biased;
            m = prx.recv() => m,
            m = nrx.recv() => m,
        }
    })
    .await
    .expect("must receive routed message")
    .expect("recv");
    assert_eq!(msg.metadata.source_protocol, "udp-multicast");
    assert_eq!(
        msg.metadata.source_protocol,
        rustgate_transport::SOURCE_UDP_MULTICAST
    );

    shutdown.notify_waiters();
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn udp_multicast_rebroadcast_emits_to_configured_group() {
    // Opt-in flag wired: install the egress callback on the router,
    // route a CoT-shaped message via the router (simulating
    // arrival from another transport), and assert the multicast
    // group sees the bytes.
    let group = unique_group(4);
    let router = Arc::new(Router::new());

    let cfg = MulticastConfig {
        groups: vec![group.clone()],
        interface: Ipv4Addr::UNSPECIFIED,
        multicast_loop: true,
        rebroadcast: true,
        max_bps: 10_000_000,
        ..MulticastConfig::default()
    };
    let shutdown = Arc::new(Notify::new());

    // Sniffer socket: bind to the same group so it observes the
    // egress datagrams. This is independent of the inbound listener
    // tasks below.
    let sniffer = {
        use socket2::{Domain, Protocol, Socket, Type};
        let s =
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("socket2 create");
        s.set_reuse_address(true).expect("set reuse");
        s.bind(&std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, group.port).into())
            .expect("sniffer bind");
        s.set_nonblocking(true).expect("nonblocking");
        let std_sock: std::net::UdpSocket = s.into();
        let tokio_sock = UdpSocket::from_std(std_sock).expect("tokio adapt");
        tokio_sock
            .join_multicast_v4(group.addr, Ipv4Addr::UNSPECIFIED)
            .expect("sniffer join");
        tokio_sock
            .set_multicast_loop_v4(true)
            .expect("sniffer loop");
        tokio_sock
    };

    let (cb, egress_handle) = udp_multicast::spawn_egress(cfg.clone(), Arc::clone(&shutdown))
        .await
        .expect("spawn egress");
    router.set_on_multicast_forward(Some(cb));

    // Need at least one registered session for the router to admit
    // the message — broadcast destinations require a destination set.
    let (mut prx, mut nrx) = register_listener(&router, "rb-listener");

    let payload = cot_xml("RB-1");
    let id =
        Identity::plaintext("simulated-tls-client".to_string(), BTreeSet::new()).expect("identity");
    let msg = RoutableMessage {
        source: id,
        destination: Destination::Broadcast,
        payload: payload.clone(),
        metadata: Metadata {
            received_at: std::time::SystemTime::now(),
            source_protocol: "tcp".into(),
            message_type: MessageType::Position,
            ttl: None,
        },
    };
    let _ = router.route_for_egress(msg).await;
    // Drain the listener channels so they don't block the router.
    let _ = tokio::time::timeout(Duration::from_millis(200), prx.recv()).await;
    let _ = tokio::time::timeout(Duration::from_millis(200), nrx.recv()).await;

    let mut buf = vec![0u8; 65_535];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(2), sniffer.recv_from(&mut buf))
        .await
        .expect("egress datagram should reach the multicast group")
        .expect("recv_from");
    assert!(
        std::str::from_utf8(&buf[..n])
            .unwrap_or("")
            .contains("RB-1"),
        "rebroadcast must include original CoT bytes"
    );

    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), egress_handle).await;
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn udp_multicast_rate_limit_caps_outbound_bps() {
    // Configure a deliberately tiny BPS cap, fire a flurry of
    // messages, assert the sniffer observed strictly fewer datagrams
    // than were submitted.
    let group = unique_group(5);
    let router = Arc::new(Router::new());

    // 200 bytes/s — each ~80-byte datagram exhausts a token quickly.
    let cfg = MulticastConfig {
        groups: vec![group.clone()],
        interface: Ipv4Addr::UNSPECIFIED,
        multicast_loop: true,
        rebroadcast: true,
        max_bps: 200,
        ..MulticastConfig::default()
    };
    let shutdown = Arc::new(Notify::new());

    let sniffer = {
        use socket2::{Domain, Protocol, Socket, Type};
        let s =
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("socket2 create");
        s.set_reuse_address(true).expect("set reuse");
        s.bind(&std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, group.port).into())
            .expect("sniffer bind");
        s.set_nonblocking(true).expect("nonblocking");
        let std_sock: std::net::UdpSocket = s.into();
        let tokio_sock = UdpSocket::from_std(std_sock).expect("tokio adapt");
        tokio_sock
            .join_multicast_v4(group.addr, Ipv4Addr::UNSPECIFIED)
            .expect("sniffer join");
        tokio_sock
            .set_multicast_loop_v4(true)
            .expect("sniffer loop");
        tokio_sock
    };

    let (cb, egress_handle) = udp_multicast::spawn_egress(cfg.clone(), Arc::clone(&shutdown))
        .await
        .expect("spawn egress");
    router.set_on_multicast_forward(Some(cb));

    let (mut prx, mut nrx) = register_listener(&router, "rl-listener");

    let total = 30_u32;
    for i in 0..total {
        let payload = cot_xml(&format!("RL-{i}"));
        let id = Identity::plaintext(format!("rl-source-{i}"), BTreeSet::new()).expect("identity");
        let msg = RoutableMessage {
            source: id,
            destination: Destination::Broadcast,
            payload,
            metadata: Metadata {
                received_at: std::time::SystemTime::now(),
                source_protocol: "tcp".into(),
                message_type: MessageType::Position,
                ttl: None,
            },
        };
        let _ = router.route_for_egress(msg).await;
        // Drain to avoid back-pressure on the router.
        let _ = tokio::time::timeout(Duration::from_millis(5), prx.recv()).await;
        let _ = tokio::time::timeout(Duration::from_millis(5), nrx.recv()).await;
    }

    // Read everything that arrives in a small window.
    let mut received = 0u32;
    let deadline = std::time::Instant::now() + Duration::from_millis(700);
    let mut buf = vec![0u8; 65_535];
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), sniffer.recv_from(&mut buf)).await {
            Ok(Ok(_)) => received += 1,
            _ => continue,
        }
    }

    assert!(
        received < total,
        "rate-limit must drop at least one datagram (received {received} of {total})"
    );
    assert!(
        received >= 1,
        "at least one datagram should pass within the initial 1-second burst (received {received})"
    );

    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), egress_handle).await;
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn udp_multicast_audit_join_event_fires() {
    use std::sync::Mutex;

    use tracing::subscriber::with_default;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::{Layer, Registry};

    /// Cooperative writer so a `tracing-subscriber` JSON layer can push
    /// formatted events into a shared buffer for assertion. Mirrors the
    /// `SharedBuf` pattern used in `rustgate-core::audit::tests`.
    #[derive(Default, Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = Registry::default().with(layer);

    let group = unique_group(6);
    let router = Arc::new(Router::new());
    let cfg = MulticastConfig {
        groups: vec![group.clone()],
        interface: Ipv4Addr::UNSPECIFIED,
        multicast_loop: true,
        ..MulticastConfig::default()
    };
    let shutdown = Arc::new(Notify::new());

    let handles = with_default(subscriber, || {
        udp_multicast::spawn_inbound(cfg, Arc::clone(&router), Arc::clone(&shutdown))
    })
    .expect("spawn inbound");

    let snapshot = String::from_utf8_lossy(&buf.0.lock().unwrap()).to_string();
    assert!(
        snapshot.contains("udp_multicast.joined"),
        "audit log must contain udp_multicast.joined event: {snapshot}"
    );
    assert!(
        snapshot.contains(&group.to_socket_string()),
        "audit log must reference the joined group: {snapshot}"
    );

    shutdown.notify_waiters();
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }
}

#[tokio::test]
async fn udp_multicast_disabled_by_default() {
    // No groups configured ⇒ no listener spawned, the helper
    // returns an empty handle list immediately.
    let cfg = MulticastConfig::default();
    assert!(!cfg.enabled(), "default config must be disabled");
    let router = Arc::new(Router::new());
    let shutdown = Arc::new(Notify::new());
    let handles = udp_multicast::spawn_inbound(cfg, Arc::clone(&router), shutdown)
        .expect("spawn inbound with empty groups");
    assert!(
        handles.is_empty(),
        "no groups configured ⇒ no listener tasks spawned"
    );
}
