// Copyright © 2026 Roberto Chiofalo.

//! Generic codec-pluggable **TCP** ingress for stream-framed tactical
//! protocols (SAPIENT, NFFI, Link 16 JREAP-C, …) — the connection-oriented
//! sibling of [`crate::codec_ingress::CodecUdpInput`].
//!
//! A datagram is self-delimiting; a TCP stream is not. So this listener owns
//! **frame delimitation** (via a [`FramedCodec`] created fresh per
//! connection) on top of everything the UDP listener does. Per connection:
//!
//! 1. **Accept admission** ([`UdpAdmission`]) — CIDR allowlist → per-IP
//!    connection-accept rate → synthetic-identity cap, applied **once at
//!    accept time** (decision D3 of the stream-ingress design note, #1473).
//! 2. **Concurrent-connection cap** — a semaphore bounds how many
//!    connections may be open at once; over-cap accepts are dropped + audited.
//! 3. **Framed read loop** — a `FramedCodec` finds frame boundaries. Two
//!    independent deadlines close a stalled peer: the per-read
//!    [`READ_TIMEOUT`] (no bytes arrive at all) and an
//!    `INCOMPLETE_FRAME_TIMEOUT` (a *partial* frame sits buffered too long
//!    without completing). Together they stop both a slow-loris and a
//!    slow-drip peer from squatting a concurrency-cap slot, while a healthy
//!    connection — including a low-rate sensor idling between complete
//!    frames — is never penalised.
//! 4. **Per-frame validate-and-drop** — each delimited frame is decoded with
//!    the *same* `DynEntityCodec` the router holds for `source_protocol`; a
//!    frame that does not decode is dropped + audited and the connection
//!    continues (one bad frame does not kill a stream).
//! 5. **Route** — accepted frames become synthetic-identity
//!    [`RoutableMessage`]s tagged with `source_protocol`. **Wire identifiers
//!    never enter the CN or any authz input** (D3).
//!
//! Unauthenticated and trusted-network-only, same posture as the UDP
//! listener — there is no mTLS on these legs.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustgate_core::audit;
use rustgate_core::constants::READ_TIMEOUT;
use rustgate_core::entity::DynEntityCodec;
use rustgate_core::identity::Identity;
use rustgate_core::masking::mask_ip;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::net::configure_tactical_socket;
use rustgate_core::tasks::spawn_background;
use rustgate_router::Router;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::time::{Instant, sleep_until, timeout};
use tokio_util::bytes::{Bytes, BytesMut};
use tokio_util::codec::Decoder;
use tracing::warn;

use crate::codec::FramedCodec;
use crate::codec_ingress::{DEFAULT_INGRESS_MAX_IDENTITIES, DEFAULT_INGRESS_MAX_PPS};
use crate::udp::CidrPrefix;
use crate::udp_common::{AdmitDecision, UdpAdmission};

/// Default maximum number of simultaneously-open ingress connections.
pub const DEFAULT_INGRESS_MAX_CONNECTIONS: usize = 1024;

/// Initial per-connection read buffer (grows as needed up to the frame cap).
const READ_BUFFER_INIT: usize = 4096;

/// Maximum wall-clock time an **incomplete** frame may sit buffered before the
/// connection is closed. This bounds the slow-drip / slow-loris signature — a
/// peer that holds bytes which never complete a frame, squatting a
/// concurrency-cap slot — without penalising a healthy connection: the clock
/// only runs while a *partial* frame is pending. A connection sitting on a
/// clean frame boundary (empty buffer) is not subject to it and may idle up to
/// the per-read [`READ_TIMEOUT`] between frames, so a legitimate low-rate
/// sensor (one report every few minutes) is never disconnected. Dribbling more
/// bytes does not reset it (the anchor is the partial frame's start, not the
/// last byte), so a byte-at-a-time attacker cannot defeat it; only *completing*
/// a frame — real progress — clears it.
const INCOMPLETE_FRAME_TIMEOUT: Duration = Duration::from_secs(60);

/// Factory that produces a fresh, per-connection [`FramedCodec`].
///
/// Framing codecs are stateful (partial-frame buffers, nesting depth), so
/// each connection gets its own instance — never a shared one.
pub type FramingFactory = Arc<dyn Fn() -> FramedCodec + Send + Sync>;

/// Configuration for a [`CodecTcpInput`] listener instance.
#[derive(Clone)]
pub struct CodecTcpIngressConfig {
    /// CN prefix for the synthetic per-connection identity (peer appended).
    pub cn_prefix: String,
    /// Destination group every accepted frame routes to (the sole trust
    /// decision for an unauthenticated feed; ACL/authz apply to it).
    pub group: String,
    /// Per-IP connection-accept rate (connections/sec). `None` applies
    /// [`DEFAULT_INGRESS_MAX_PPS`] — never truly unlimited.
    pub max_accepts_per_sec: Option<usize>,
    /// Source CIDR allowlist. `None` accepts all but warns loudly.
    pub allowed_cidrs: Option<Vec<CidrPrefix>>,
    /// Synthetic-identity LRU bound (per source IP).
    pub max_identities: usize,
    /// Maximum simultaneously-open connections.
    pub max_connections: usize,
}

impl std::fmt::Debug for CodecTcpIngressConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodecTcpIngressConfig")
            .field("cn_prefix", &self.cn_prefix)
            .field("group", &self.group)
            .field("max_accepts_per_sec", &self.max_accepts_per_sec)
            .field("allowed_cidrs", &self.allowed_cidrs)
            .field("max_identities", &self.max_identities)
            .field("max_connections", &self.max_connections)
            .finish()
    }
}

impl Default for CodecTcpIngressConfig {
    fn default() -> Self {
        Self {
            cn_prefix: "ingress-anonymous".to_string(),
            group: rustgate_core::constants::PLAINTEXT_GROUP.to_string(),
            max_accepts_per_sec: None,
            allowed_cidrs: None,
            max_identities: DEFAULT_INGRESS_MAX_IDENTITIES,
            max_connections: DEFAULT_INGRESS_MAX_CONNECTIONS,
        }
    }
}

/// A generic codec-pluggable TCP ingress listener.
#[derive(Debug)]
pub struct CodecTcpInput;

impl CodecTcpInput {
    /// Run the accept loop until `shutdown` is notified.
    ///
    /// - `framing` produces a fresh stateful [`FramedCodec`] per connection.
    /// - `codec` validates each delimited frame (the same
    ///   `Arc<dyn DynEntityCodec>` the router holds for `source_protocol`).
    /// - `source_protocol` tags routed messages; `message_type` is the
    ///   coarse routing/audit hint.
    // justification: the listener entrypoint takes the full per-listener
    // context (socket, router, validation codec, framing factory, two tag
    // fields, config, shutdown). Bundling into a struct would just move the
    // same fan-out to the single call site without removing live references.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        listener: TcpListener,
        router: Arc<Router>,
        codec: Arc<dyn DynEntityCodec>,
        framing: FramingFactory,
        source_protocol: String,
        message_type: MessageType,
        config: CodecTcpIngressConfig,
        shutdown: Arc<Notify>,
    ) {
        let local = listener.local_addr().ok();
        let max_pps = config
            .max_accepts_per_sec
            .unwrap_or(DEFAULT_INGRESS_MAX_PPS);

        warn!(
            protocol = %source_protocol,
            local_addr = ?local,
            "tactical stream ingress active — connections are UNAUTHENTICATED and NOT encrypted"
        );
        if config.allowed_cidrs.is_none() {
            warn!(
                protocol = %source_protocol,
                local_addr = ?local,
                "tactical stream ingress has NO source CIDR allowlist — exposed to the whole \
                 reachable network; restrict to a trusted segment"
            );
        }

        let admission = Arc::new(UdpAdmission::new(
            Some(max_pps),
            config.allowed_cidrs.clone(),
            config.max_identities,
        ));
        let conn_limit = Arc::new(Semaphore::new(config.max_connections.max(1)));

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (stream, peer) = match accept {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(protocol = %source_protocol, error = %e, "ingress accept error");
                            continue;
                        }
                    };

                    // --- Accept admission (CIDR / accept-rate / identity cap) ---
                    match admission.admit(peer.ip()) {
                        AdmitDecision::Accept => {}
                        AdmitDecision::DeniedCidr => {
                            audit::connection_rejected(peer, "cidr_not_allowed");
                            continue;
                        }
                        AdmitDecision::RateLimited => {
                            audit::rate_limit_triggered(
                                &mask_ip(&peer.to_string()), &source_protocol, max_pps,
                            );
                            continue;
                        }
                        AdmitDecision::IdentityCapReached => {
                            audit::connection_rejected(peer, "identity_cap_reached");
                            continue;
                        }
                    }

                    // --- Concurrent-connection cap ---
                    let permit = match Arc::clone(&conn_limit).try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            audit::connection_rejected(peer, "connection_cap_reached");
                            tracing::warn!(
                                protocol = %source_protocol, peer = %mask_ip(&peer.to_string()),
                                max_connections = config.max_connections,
                                "ingress connection rejected: connection cap reached"
                            );
                            continue;
                        }
                    };

                    configure_tactical_socket(&stream);

                    let codec = Arc::clone(&codec);
                    let router = Arc::clone(&router);
                    let mut framed = (framing)();
                    let source_protocol = source_protocol.clone();
                    let message_type = message_type.clone();
                    let cn_prefix = config.cn_prefix.clone();
                    let group = config.group.clone();
                    let conn_shutdown = Arc::clone(&shutdown);

                    spawn_background("codec-tcp-conn", async move {
                        handle_connection(
                            stream, peer, &mut framed, codec.as_ref(), &router,
                            &source_protocol, &message_type, &cn_prefix, &group, conn_shutdown,
                        ).await;
                        // Permit released on drop — frees a connection slot.
                        drop(permit);
                    });
                }
                _ = shutdown.notified() => {
                    tracing::info!(protocol = %source_protocol, "tactical stream ingress shutting down");
                    break;
                }
            }
        }
    }
}

/// Drive one accepted connection: read → delimit → validate → route, until
/// EOF, a read timeout, a fatal framing error, or shutdown.
// justification: this is the per-connection entrypoint, called once per
// accept from a single site; bundling the borrowed context into a struct
// would move the same field fan-out one level up without removing any live
// references. The arguments are all distinct borrowed context, not config.
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    framed: &mut FramedCodec,
    codec: &dyn DynEntityCodec,
    router: &Arc<Router>,
    source_protocol: &str,
    message_type: &MessageType,
    cn_prefix: &str,
    group: &str,
    shutdown: Arc<Notify>,
) {
    let masked = mask_ip(&peer.to_string());
    let mut buf = BytesMut::with_capacity(READ_BUFFER_INIT);
    // Anchor for the incomplete-frame cap: when the current *partial* frame
    // first began buffering, or `None` while the buffer sits on a clean frame
    // boundary. See [`INCOMPLETE_FRAME_TIMEOUT`] for why this (not
    // time-since-last-frame, which would close idle low-rate sensors, nor
    // time-since-last-byte, which a dribble would defeat) is the right anchor.
    let mut partial_since: Option<Instant> = None;

    loop {
        // Drain every complete frame currently in the buffer.
        let mut completed_frame = false;
        loop {
            match framed.decode(&mut buf) {
                Ok(Some(frame)) => {
                    route_frame(
                        frame.freeze(),
                        peer,
                        codec,
                        router,
                        source_protocol,
                        message_type,
                        cn_prefix,
                        group,
                        &masked,
                    )
                    .await;
                    completed_frame = true;
                }
                Ok(None) => break, // need more bytes
                Err(e) => {
                    // A framing-level error (oversize prefix, malformed
                    // varint) is fatal for the stream — we can no longer
                    // trust frame boundaries. Drop the connection + audit.
                    audit::connection_rejected(peer, "malformed_frame");
                    tracing::debug!(
                        protocol = %source_protocol, peer = %masked, error = %e,
                        "stream ingress connection closed: framing error"
                    );
                    return;
                }
            }
        }

        // Maintain the incomplete-frame dwell anchor:
        //  - empty buffer  -> clean boundary; clear the cap (idle is fine, up
        //    to READ_TIMEOUT — a low-rate sensor between reports is healthy).
        //  - bytes remain  -> a partial frame is pending. Start its clock when
        //    it is fresh (a frame just completed, or none was tracked); an
        //    already-tracked, still-growing partial keeps its ORIGINAL start
        //    so dribbling more bytes cannot push the deadline out.
        if buf.is_empty() {
            partial_since = None;
        } else if completed_frame || partial_since.is_none() {
            partial_since = Some(Instant::now());
        }
        let dwell_deadline = partial_since.map(|since| since + INCOMPLETE_FRAME_TIMEOUT);

        tokio::select! {
            read = timeout(READ_TIMEOUT, stream.read_buf(&mut buf)) => {
                match read {
                    Ok(Ok(0)) => return,                 // clean EOF
                    Ok(Ok(_)) => {}                       // got bytes; loop to decode
                    Ok(Err(e)) => {
                        tracing::debug!(protocol = %source_protocol, peer = %masked, error = %e, "stream ingress read error");
                        return;
                    }
                    Err(_) => {
                        // No bytes at all within READ_TIMEOUT (slow-loris).
                        audit::connection_rejected(peer, "read_timeout");
                        tracing::debug!(protocol = %source_protocol, peer = %masked, "stream ingress connection closed: read timeout");
                        return;
                    }
                }
            }
            // Armed only while a partial frame is pending (otherwise this
            // branch parks forever via `pending()`). Fires when an incomplete
            // frame has dwelled past the cap: bytes may keep arriving so
            // READ_TIMEOUT never trips, yet the frame never completes —
            // slow-drip squatting a concurrency slot.
            () = async {
                match dwell_deadline {
                    Some(deadline) => sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                audit::connection_rejected(peer, "incomplete_frame_timeout");
                tracing::debug!(protocol = %source_protocol, peer = %masked, "stream ingress connection closed: incomplete frame exceeded dwell cap");
                return;
            }
            _ = shutdown.notified() => return,
        }
    }
}

/// Validate one delimited frame and route it, or drop + audit on decode
/// failure. The decoded entity is discarded — the router re-decodes via its
/// registry (single source of routing truth).
// justification: forwards the same borrowed per-connection context as
// `handle_connection`; a context struct would only relocate the fan-out.
#[allow(clippy::too_many_arguments)]
async fn route_frame(
    frame: Bytes,
    peer: SocketAddr,
    codec: &dyn DynEntityCodec,
    router: &Arc<Router>,
    source_protocol: &str,
    message_type: &MessageType,
    cn_prefix: &str,
    group: &str,
    masked: &str,
) {
    if frame.is_empty() {
        return;
    }
    if let Err(e) = codec.to_entity_dyn(&frame) {
        audit::connection_rejected(peer, "malformed_frame");
        tracing::debug!(
            protocol = %source_protocol, peer = %masked, error = %e,
            "stream ingress frame dropped: failed to decode"
        );
        return;
    }

    let cn = format!("{cn_prefix}-{peer}");
    let mut groups = BTreeSet::new();
    let _ = groups.insert(group.to_string());
    let identity = match Identity::plaintext(cn, groups) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                protocol = %source_protocol, peer = %masked, error = %e,
                "stream ingress frame dropped: invalid synthetic identity"
            );
            return;
        }
    };
    let msg = RoutableMessage {
        source: identity,
        destination: Destination::Group(Arc::from(group)),
        payload: frame,
        metadata: Metadata::new(
            std::time::SystemTime::now(),
            source_protocol.to_string(),
            message_type.clone(),
        ),
        entity: None,
    };
    router.route(msg).await;
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_secure() {
        let cfg = CodecTcpIngressConfig::default();
        // Accept rate is "secure default", not unlimited, when unset.
        assert!(cfg.max_accepts_per_sec.is_none());
        assert_eq!(cfg.max_identities, DEFAULT_INGRESS_MAX_IDENTITIES);
        assert_eq!(cfg.max_connections, DEFAULT_INGRESS_MAX_CONNECTIONS);
    }
}
