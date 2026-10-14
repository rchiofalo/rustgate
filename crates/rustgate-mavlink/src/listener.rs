// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! UDP and TCP listeners that ingest MAVLink frames into the router.
//!
//! UDP is the canonical MAVLink transport — one frame per datagram, the
//! shape ground-control stations and autopilots speak by default. TCP is
//! used by tethered ground-control stations that want a reliable stream.
//! Both paths share the same per-frame pipeline:
//!
//! 1. The [`crate::frame::MavlinkFrameCodec`] slices complete frames out
//!    of the wire and enforces the framing-layer signing policy (v1
//!    rejected unless allowed; unsigned v2 rejected unless signing is
//!    relaxed).
//! 2. v2 frames are verified against the [`SigningKeyStore`] — signature
//!    and replay — which yields the trailer's `link_id`.
//! 3. The `link_id` is resolved to a rustgate [`Identity`] via the
//!    [`LinkRegistry`] (the link manifest from ADR 0020 §1). v1 frames,
//!    when admitted, take the registry's shared fallback identity.
//! 4. A [`RoutableMessage`] is built with the per-listener
//!    [`MavlinkDestination`] and handed to the [`OnMavlinkMessage`] sink.
//!    The server crate wires that sink to `Router::route_for_egress`, so
//!    ACL and authz apply to MAVLink exactly as they do to every other
//!    transport.
//!
//! # Why a sink callback instead of a `Router` dependency
//!
//! This crate stays free of `rustgate-router` / `rustgate-cot`: the
//! listener emits a `RoutableMessage` through an `Arc<dyn Fn(..)>` sink
//! and the server crate (PR 6) owns the wiring to the router. That keeps
//! the dependency graph acyclic — `rustgate-transport` already depends on
//! `rustgate-mavlink` — and matches the workspace convention where
//! transports hand off via callbacks rather than reaching into the
//! routing crate.
//!
//! # Identity over UDP
//!
//! MAVLink over UDP has no TLS, so the v2 signing `link_id` *is* the
//! identity primitive (ADR 0020 §1). A frame whose `link_id` is not in
//! the manifest is dropped with an audit event — there is no
//! "anonymous MAVLink" path. This is the property that lets MAVLink cross
//! the same identity boundary as CoT and chat instead of being
//! wide-open ingress with a policy bypass.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::{Bytes, BytesMut};
use rustgate_core::audit;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage, SOURCE_MAVLINK};
use rustgate_core::net::configure_tactical_socket;
use rustgate_core::tasks::SubsystemHandle;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;
use tokio::time::timeout;
use tokio_util::codec::Decoder;
use tracing::{debug, info, warn};

use crate::frame::{MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC, MavlinkFrameCodec};
use crate::signing::{SigningError, SigningKeyStore};

rustgate_core::on_callback!(
    /// Sink the listener calls once per accepted MAVLink frame.
    ///
    /// The server crate wires this to `Router::route_for_egress`. Async
    /// work inside the closure is dispatched via `spawn_background` so the
    /// listener's read loop is never blocked.
    pub OnMavlinkMessage,
    RoutableMessage
);

/// Maximum bytes a single UDP datagram may carry before it is dropped.
///
/// MAVLink is a one-frame-per-datagram protocol and the largest signed v2
/// frame is 280 bytes ([`crate::frame::MAX_MAVLINK_FRAME_SIZE`]). A 2 KiB
/// receive buffer leaves generous headroom for a datagram carrying a
/// couple of back-to-back frames without inviting amplification via
/// oversize reads.
const UDP_RECV_BUFFER: usize = 2048;

/// Routing destination a MAVLink listener applies to every frame it
/// ingests.
///
/// ADR 0020 §2 restricts MAVLink ingress to `group` and `broadcast`
/// destinations — `direct` and `multicast` have no sensible mapping for
/// telemetry, so they are unrepresentable here rather than rejected at
/// runtime.
#[derive(Debug, Clone)]
pub enum MavlinkDestination {
    /// Route every frame to a single group.
    Group(Arc<str>),
    /// Broadcast every frame to all sessions.
    Broadcast,
}

impl MavlinkDestination {
    /// Project onto the core routing [`Destination`].
    fn to_core(&self) -> Destination {
        match self {
            Self::Group(g) => Destination::Group(Arc::clone(g)),
            Self::Broadcast => Destination::Broadcast,
        }
    }
}

/// Resolves a MAVLink `link_id` (and the v1 fallback) to a rustgate
/// [`Identity`].
///
/// This is the identity half of the ADR 0020 §1 link manifest; the
/// signing-key half lives in the [`SigningKeyStore`]. The server crate
/// (PR 6) parses the TOML manifest once and populates both. Keeping the
/// two split lets the signing store own its replay table while the
/// registry stays a plain immutable lookup.
#[derive(Debug, Clone, Default)]
pub struct LinkRegistry {
    links: std::collections::HashMap<u8, Identity>,
    v1_fallback: Option<Identity>,
}

impl LinkRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the identity for a `link_id`.
    #[must_use]
    pub fn with_link(mut self, link_id: u8, identity: Identity) -> Self {
        let _ = self.links.insert(link_id, identity);
        self
    }

    /// Set the shared identity applied to admitted v1 frames.
    ///
    /// v1 has no signing and therefore no per-link identity; ADR 0020 §1
    /// requires operators who accept v1 to configure a single shared CN
    /// that cannot collide with a real client.
    #[must_use]
    pub fn with_v1_fallback(mut self, identity: Identity) -> Self {
        self.v1_fallback = Some(identity);
        self
    }

    /// Resolve the identity for a verified `link_id`.
    #[must_use]
    pub fn resolve(&self, link_id: u8) -> Option<&Identity> {
        self.links.get(&link_id)
    }

    /// The shared v1 fallback identity, if configured.
    #[must_use]
    pub fn v1_fallback(&self) -> Option<&Identity> {
        self.v1_fallback.as_ref()
    }
}

/// Static configuration for a single MAVLink listener.
#[derive(Debug, Clone)]
pub struct MavlinkListenerConfig {
    /// Address to bind.
    pub bind: SocketAddr,
    /// Destination every ingested frame routes to.
    pub destination: MavlinkDestination,
    /// When `true`, v2 frames must carry the SIGNED INCOMPAT bit to be
    /// admitted by the framing layer. Mirrors
    /// [`MavlinkFrameCodec::with_require_signing`].
    pub require_signing: bool,
    /// When `true`, v1 frames are admitted and routed under the
    /// registry's v1 fallback identity. Mirrors
    /// [`MavlinkFrameCodec::with_allow_v1`].
    pub allow_v1: bool,
}

impl MavlinkListenerConfig {
    /// Build the framing codec matching this listener's signing policy.
    fn codec(&self) -> MavlinkFrameCodec {
        MavlinkFrameCodec::new()
            .with_require_signing(self.require_signing)
            .with_allow_v1(self.allow_v1)
    }
}

/// Shared per-listener state threaded through the per-frame pipeline.
struct ListenerCtx {
    config: MavlinkListenerConfig,
    signing: Arc<SigningKeyStore>,
    links: Arc<LinkRegistry>,
    sink: OnMavlinkMessage,
}

impl ListenerCtx {
    /// Verify, identity-resolve, and route one decoded frame.
    ///
    /// All rejection paths are terminal for the frame and emit an audit
    /// event; nothing here can panic on hostile input.
    fn process_frame(&self, frame: Bytes, peer: SocketAddr) {
        match frame.first().copied() {
            Some(MAVLINK_V2_MAGIC) => self.process_v2(frame, peer),
            Some(MAVLINK_V1_MAGIC) => self.process_v1(frame, peer),
            // The codec only emits frames with a valid magic, so this is
            // unreachable in practice; drop defensively rather than panic.
            _ => debug!(peer = %peer, "dropping MAVLink frame with unrecognised magic"),
        }
    }

    fn process_v2(&self, frame: Bytes, peer: SocketAddr) {
        match self.signing.verify(&frame) {
            Ok(verified) => match self.links.resolve(verified.link_id) {
                Some(identity) => self.deliver(identity.clone(), frame),
                None => {
                    audit::mavlink_signature_rejected(peer, "no identity registered for link_id");
                    debug!(
                        peer = %peer,
                        link_id = verified.link_id,
                        "MAVLink frame verified but link_id has no identity"
                    );
                }
            },
            Err(SigningError::ReplayedTimestamp {
                link_id,
                timestamp,
                last,
                ..
            }) => audit::mavlink_replay_rejected(peer, link_id, timestamp, last),
            Err(err) => audit::mavlink_signature_rejected(peer, &err.to_string()),
        }
    }

    fn process_v1(&self, frame: Bytes, peer: SocketAddr) {
        // The codec only emits v1 frames when `allow_v1` is set, but guard
        // again so a config/codec mismatch cannot wave v1 through.
        match (self.config.allow_v1, self.links.v1_fallback()) {
            (true, Some(identity)) => {
                audit::mavlink_v1_admitted(&identity.cn, peer);
                self.deliver(identity.clone(), frame);
            }
            _ => debug!(peer = %peer, "dropping MAVLink v1 frame: no v1 fallback identity"),
        }
    }

    fn deliver(&self, source: Identity, frame: Bytes) {
        let msg = RoutableMessage {
            source,
            destination: self.config.destination.to_core(),
            payload: frame,
            metadata: Metadata::new(
                SystemTime::now(),
                SOURCE_MAVLINK.to_string(),
                MessageType::Mavlink,
            ),
            entity: None,
        };
        (self.sink)(msg);
    }
}

/// Spawn a UDP MAVLink listener, returning a drainable subsystem handle.
///
/// One datagram is decoded with a fresh codec so partial or hostile
/// framing in one datagram cannot corrupt the parse of the next (UDP has
/// no stream continuity between datagrams, and successive datagrams may
/// come from different peers).
///
/// # Errors
///
/// Returns the bind error if the socket cannot be opened.
pub async fn spawn_udp_listener(
    config: MavlinkListenerConfig,
    signing: Arc<SigningKeyStore>,
    links: Arc<LinkRegistry>,
    sink: OnMavlinkMessage,
) -> std::io::Result<SubsystemHandle> {
    let socket = UdpSocket::bind(config.bind).await?;
    let local = socket.local_addr().ok();
    info!(bind = ?local, destination = config.destination_kind(), "MAVLink UDP listener bound");

    let ctx = ListenerCtx {
        config,
        signing,
        links,
        sink,
    };
    let shutdown = Arc::new(Notify::new());
    let shutdown_task = Arc::clone(&shutdown);

    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_RECV_BUFFER];
        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => match result {
                    Ok((len, peer)) => ctx.drain_datagram(&buf[..len], peer),
                    Err(e) => warn!(error = %e, "MAVLink UDP recv error"),
                },
                _ = shutdown_task.notified() => {
                    info!(bind = ?local, "MAVLink UDP listener shutting down");
                    break;
                }
            }
        }
    });

    Ok(SubsystemHandle::new(shutdown, task))
}

/// Spawn a TCP MAVLink listener, returning a drainable subsystem handle.
///
/// Each accepted connection runs its own read loop with its own codec,
/// so a slow or malformed peer cannot stall the others.
///
/// # Errors
///
/// Returns the bind error if the listener cannot be opened.
pub async fn spawn_tcp_listener(
    config: MavlinkListenerConfig,
    signing: Arc<SigningKeyStore>,
    links: Arc<LinkRegistry>,
    sink: OnMavlinkMessage,
) -> std::io::Result<SubsystemHandle> {
    let listener = TcpListener::bind(config.bind).await?;
    let local = listener.local_addr().ok();
    info!(bind = ?local, destination = config.destination_kind(), "MAVLink TCP listener bound");

    let ctx = Arc::new(ListenerCtx {
        config,
        signing,
        links,
        sink,
    });
    let shutdown = Arc::new(Notify::new());
    let shutdown_task = Arc::clone(&shutdown);

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => match result {
                    Ok((stream, peer)) => {
                        configure_tactical_socket(&stream);
                        let ctx = Arc::clone(&ctx);
                        let conn_shutdown = Arc::clone(&shutdown_task);
                        rustgate_core::tasks::spawn_background("mavlink-tcp-conn", async move {
                            handle_tcp_connection(stream, peer, ctx, conn_shutdown).await;
                        });
                    }
                    Err(e) => warn!(error = %e, "MAVLink TCP accept error"),
                },
                _ = shutdown_task.notified() => {
                    info!(bind = ?local, "MAVLink TCP listener shutting down");
                    break;
                }
            }
        }
    });

    Ok(SubsystemHandle::new(shutdown, task))
}

impl MavlinkListenerConfig {
    /// Stable destination tag for structured logs.
    fn destination_kind(&self) -> &'static str {
        match self.destination {
            MavlinkDestination::Group(_) => "group",
            MavlinkDestination::Broadcast => "broadcast",
        }
    }
}

impl ListenerCtx {
    /// Decode and process every complete frame in a single UDP datagram.
    fn drain_datagram(&self, datagram: &[u8], peer: SocketAddr) {
        let mut codec = self.config.codec();
        let mut buf = BytesMut::from(datagram);
        loop {
            match codec.decode(&mut buf) {
                Ok(Some(frame)) => self.process_frame(frame.freeze(), peer),
                Ok(None) => break,
                Err(e) => {
                    // Framing-layer rejection (v1 disallowed, unsigned v2,
                    // unknown MSG_ID). One bad frame ends the datagram.
                    debug!(peer = %peer, error = %e, "dropping MAVLink datagram frame");
                    break;
                }
            }
        }
    }
}

/// Read-loop for a single MAVLink TCP connection.
async fn handle_tcp_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ListenerCtx>,
    shutdown: Arc<Notify>,
) {
    debug!(peer = %peer, "MAVLink TCP connection opened");
    let mut codec = ctx.config.codec();
    let mut buf = BytesMut::with_capacity(UDP_RECV_BUFFER);

    loop {
        // Drain any complete frames already buffered before reading more.
        loop {
            match codec.decode(&mut buf) {
                Ok(Some(frame)) => ctx.process_frame(frame.freeze(), peer),
                Ok(None) => break,
                Err(e) => {
                    debug!(peer = %peer, error = %e, "MAVLink TCP frame rejected; closing");
                    return;
                }
            }
        }

        tokio::select! {
            read = timeout(rustgate_core::constants::READ_TIMEOUT, stream.read_buf(&mut buf)) => {
                match read {
                    Ok(Ok(0)) => {
                        debug!(peer = %peer, "MAVLink TCP connection closed by peer");
                        return;
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        warn!(peer = %peer, error = %e, "MAVLink TCP read error");
                        return;
                    }
                    Err(_) => {
                        debug!(peer = %peer, "MAVLink TCP read timed out; closing");
                        return;
                    }
                }
            }
            _ = shutdown.notified() => {
                debug!(peer = %peer, "MAVLink TCP connection draining on shutdown");
                return;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    use bytes::BufMut;

    use super::*;
    use crate::signing::{SIGNING_KEY_LEN, sign_through_crc_for_test};

    const KEY: [u8; SIGNING_KEY_LEN] = [0x5A; SIGNING_KEY_LEN];

    fn test_identity(cn: &str, group: &str) -> Identity {
        let mut groups = BTreeSet::new();
        groups.insert(group.to_string());
        Identity::plaintext(cn.to_string(), groups).unwrap()
    }

    /// Collecting sink for assertions.
    fn collecting_sink() -> (OnMavlinkMessage, Arc<Mutex<Vec<RoutableMessage>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = Arc::clone(&seen);
        let sink: OnMavlinkMessage = Arc::new(move |msg| {
            seen_cb.lock().unwrap().push(msg);
        });
        (sink, seen)
    }

    fn ctx_with(
        allow_v1: bool,
        registry: LinkRegistry,
        store: SigningKeyStore,
    ) -> (ListenerCtx, Arc<Mutex<Vec<RoutableMessage>>>) {
        let (sink, seen) = collecting_sink();
        let ctx = ListenerCtx {
            config: MavlinkListenerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                destination: MavlinkDestination::Group(Arc::from("tactical/uav")),
                require_signing: true,
                allow_v1,
            },
            signing: Arc::new(store),
            links: Arc::new(registry),
            sink,
        };
        (ctx, seen)
    }

    fn peer() -> SocketAddr {
        "192.0.2.10:14550".parse().unwrap()
    }

    #[test]
    fn destination_projects_to_core() {
        assert_eq!(
            MavlinkDestination::Group(Arc::from("g"))
                .to_core()
                .kind_str(),
            "group"
        );
        assert_eq!(
            MavlinkDestination::Broadcast.to_core().kind_str(),
            "broadcast"
        );
    }

    #[test]
    fn verified_v2_frame_is_delivered_with_link_identity() {
        let mut store = SigningKeyStore::new();
        store.insert_key(0x42, KEY);
        let registry =
            LinkRegistry::new().with_link(0x42, test_identity("drone-007", "tactical/uav"));
        let (ctx, seen) = ctx_with(false, registry, store);

        let frame = sign_through_crc_for_test(&KEY, 7, 1, 0x42, 1000, 5);
        ctx.process_frame(frame, peer());

        let msgs = seen.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(&*msgs[0].source.cn, "drone-007");
        assert_eq!(msgs[0].destination.kind_str(), "group");
        assert_eq!(msgs[0].metadata.source_protocol, "mavlink");
        assert_eq!(msgs[0].metadata.message_type, MessageType::Mavlink);
    }

    #[test]
    fn verified_frame_with_unknown_link_id_is_dropped() {
        let mut store = SigningKeyStore::new();
        store.insert_key(0x42, KEY);
        // Registry has no identity for link 0x42.
        let (ctx, seen) = ctx_with(false, LinkRegistry::new(), store);

        let frame = sign_through_crc_for_test(&KEY, 7, 1, 0x42, 1000, 5);
        ctx.process_frame(frame, peer());

        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn bad_signature_is_dropped() {
        let mut store = SigningKeyStore::new();
        store.insert_key(0x42, [0xFF; SIGNING_KEY_LEN]); // store key != signer key
        let registry =
            LinkRegistry::new().with_link(0x42, test_identity("drone-007", "tactical/uav"));
        let (ctx, seen) = ctx_with(false, registry, store);

        let frame = sign_through_crc_for_test(&KEY, 7, 1, 0x42, 1000, 5);
        ctx.process_frame(frame, peer());

        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn replayed_frame_is_dropped() {
        let mut store = SigningKeyStore::new();
        store.insert_key(0x42, KEY);
        let registry =
            LinkRegistry::new().with_link(0x42, test_identity("drone-007", "tactical/uav"));
        let (ctx, seen) = ctx_with(false, registry, store);

        let frame = sign_through_crc_for_test(&KEY, 7, 1, 0x42, 1000, 5);
        ctx.process_frame(frame.clone(), peer());
        ctx.process_frame(frame, peer()); // same timestamp → replay

        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn v1_frame_uses_fallback_identity_when_allowed() {
        let registry = LinkRegistry::new()
            .with_v1_fallback(test_identity("mavlink-v1-shared", "tactical/uav"));
        let (ctx, seen) = ctx_with(true, registry, SigningKeyStore::new());

        // Minimal v1 frame: magic + 5 header bytes + payload + 2 CRC.
        let mut frame = BytesMut::new();
        frame.put_u8(MAVLINK_V1_MAGIC);
        frame.put_u8(0); // LEN
        frame.put_u8(0); // SEQ
        frame.put_u8(7); // SYSID
        frame.put_u8(1); // COMPID
        frame.put_u8(0); // MSGID = HEARTBEAT
        frame.put_u16(0xBEEF); // CRC
        ctx.process_frame(frame.freeze(), peer());

        let msgs = seen.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(&*msgs[0].source.cn, "mavlink-v1-shared");
    }

    #[test]
    fn v1_frame_dropped_when_no_fallback() {
        let (ctx, seen) = ctx_with(true, LinkRegistry::new(), SigningKeyStore::new());
        let mut frame = BytesMut::new();
        frame.put_u8(MAVLINK_V1_MAGIC);
        frame.put_bytes(0, 7);
        ctx.process_frame(frame.freeze(), peer());
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn registry_resolves_and_falls_back() {
        let id = test_identity("a", "g");
        let fb = test_identity("fb", "g");
        let reg = LinkRegistry::new().with_link(1, id).with_v1_fallback(fb);
        assert_eq!(reg.resolve(1).map(|i| &*i.cn), Some("a"));
        assert!(reg.resolve(2).is_none());
        assert_eq!(reg.v1_fallback().map(|i| &*i.cn), Some("fb"));
    }
}
