// Copyright © 2026 Roberto Chiofalo.

//! Session handling for connected clients.
//!
//! Contains the TLS session lifecycle (handshake, read/write loops, protocol
//! negotiation), the plaintext TCP accept loop, and the `NatsPublish` trait
//! that abstracts over optional NATS support.

use std::num::NonZeroUsize;
use std::sync::Arc;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use rustgate_core::codec::Codec;
use rustgate_core::constants::{READ_TIMEOUT, WRITE_TIMEOUT};
use rustgate_core::identity::Identity;
#[cfg(feature = "metrics")]
use rustgate_core::message::Destination;
use rustgate_core::message::RoutableMessage;
use rustgate_cot::MessageBuilder;
use rustgate_cot::delta::{DeltaEncoder, DeltaOutput};
use rustgate_transport::{
    AuthenticatedSession, FramedCodec, ReplayFilter, Router, SessionHandle, ThrottleConfig,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::archive;
use crate::cli::Framing;
#[cfg(feature = "metrics")]
use crate::metrics;

/// Optional callback for forwarding messages to federation peers.
///
/// The closure receives `(payload, source_groups)` and spawns async work
/// internally (fire-and-forget). Defined unconditionally so the `Option`
/// type is available regardless of feature flags.
///
/// Uses `Fn` (not `AsyncFn`) because `dyn AsyncFn` is not object-safe
/// as of Rust 1.93. Async work is dispatched via `spawn_background()`.
pub(crate) type FedForwardFn =
    Arc<dyn Fn(Bytes, Vec<String>, rustgate_core::message::Metadata) + Send + Sync>;

/// Callback for forwarding messages to HTTP targets (fire-and-forget).
///
/// Uses `Fn` (not `AsyncFn`) because `dyn AsyncFn` is not object-safe
/// as of Rust 1.94. Async work is dispatched via `spawn_background()`.
#[cfg(feature = "http")]
pub(crate) type HttpForwardFn = Arc<dyn Fn(rustgate_core::message::RoutableMessage) + Send + Sync>;

/// Configuration for the per-session CoT delta encoder.
///
/// When `enabled`, each writer task constructs a [`DeltaEncoder`] with
/// `cache_size` capacity and `epsilon_meters` suppression threshold. See
/// `rustgate_cot::delta` for the wire format and suppression semantics.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeltaConfig {
    pub(crate) enabled: bool,
    pub(crate) cache_size: u64,
    pub(crate) epsilon_meters: f64,
}

impl DeltaConfig {
    /// Construct a [`DeltaEncoder`] matching this configuration when
    /// enabled. Returns `None` when `enabled` is false so the writer task
    /// can cheaply skip delta processing.
    pub(crate) fn build_encoder(&self) -> Option<DeltaEncoder> {
        if !self.enabled {
            return None;
        }
        let cap = NonZeroUsize::new(self.cache_size.max(1) as usize).unwrap_or(NonZeroUsize::MIN);
        Some(DeltaEncoder::new(cap, self.epsilon_meters))
    }
}

/// Shared dependencies passed to each session handler task.
pub(crate) struct SessionDeps<P: NatsPublish> {
    pub(crate) router: Arc<Router>,
    /// CLI framing mode — only used to detect `TakNegotiate` for the
    /// protocol negotiation handshake. The actual codec is in `codec`.
    pub(crate) framing: Framing,
    pub(crate) codec: Arc<dyn Codec>,
    pub(crate) nats_publisher: Option<P>,
    pub(crate) fed_forward: Option<FedForwardFn>,
    #[cfg(feature = "http")]
    pub(crate) http_forward: Option<HttpForwardFn>,
    pub(crate) throttle_config: Option<ThrottleConfig>,
    pub(crate) archiver: Option<Arc<archive::CotArchiver>>,
    pub(crate) replay_filter: Option<Arc<ReplayFilter>>,
    pub(crate) circuit_breaker_threshold: u32,
    /// Optional per-session CoT delta encoding for outbound XML sessions.
    pub(crate) delta_config: DeltaConfig,
    /// Per-identity metrics configuration: allowlist for label
    /// bucketing plus the Tier 2 enable flag.
    #[cfg(feature = "metrics")]
    pub(crate) metrics_identity: Arc<metrics::MetricsIdentity>,
}

/// Runtime context for a connected session's read/write loops.
struct SessionContext<'a, P: NatsPublish> {
    identity: &'a Identity,
    router: &'a Router,
    codec: &'a dyn Codec,
    nats_publisher: &'a Option<P>,
    fed_forward: &'a Option<FedForwardFn>,
    #[cfg(feature = "http")]
    http_forward: &'a Option<HttpForwardFn>,
    throttle: Option<rustgate_transport::ClientThrottle>,
    archiver: &'a Option<Arc<archive::CotArchiver>>,
    replay_filter: &'a Option<Arc<ReplayFilter>>,
    delta_config: DeltaConfig,
    #[cfg(feature = "metrics")]
    metrics_identity: &'a metrics::MetricsIdentity,
}

/// Trait for optional NATS publishing. Allows the server to compile with or
/// without the `nats` feature by abstracting over the publisher type.
pub(crate) trait NatsPublish: Clone {
    fn publish(&self, msg: &RoutableMessage) -> impl std::future::Future<Output = ()> + Send;
}

#[cfg(feature = "nats")]
impl NatsPublish for rustgate_nats::NatsPublisher {
    async fn publish(&self, msg: &RoutableMessage) {
        self.publish(msg).await;
    }
}

/// No-op publisher used when NATS is not enabled.
impl NatsPublish for () {
    async fn publish(&self, _msg: &RoutableMessage) {}
}

/// Handle a single authenticated TLS session from accept to disconnect.
pub(crate) async fn handle_session<P: NatsPublish + Send + Sync + 'static>(
    session: AuthenticatedSession,
    deps: SessionDeps<P>,
    _permit: OwnedSemaphorePermit, // Held for session lifetime; released on drop
) {
    let identity = session.identity_arc();
    let cn = identity.cn.clone();
    let peer_addr = session.peer_addr();

    #[cfg(feature = "metrics")]
    metrics::sessions_active().inc();

    let (priority_tx, priority_rx) = mpsc::channel::<rustgate_transport::RoutedMessage>(
        rustgate_transport::PRIORITY_CHANNEL_CAPACITY,
    );
    let (normal_tx, normal_rx) = mpsc::channel::<rustgate_transport::RoutedMessage>(
        rustgate_transport::NORMAL_CHANNEL_CAPACITY,
    );
    let handle = if deps.circuit_breaker_threshold > 0 {
        SessionHandle::with_drop_threshold(
            Arc::clone(&identity),
            priority_tx,
            normal_tx,
            deps.circuit_breaker_threshold,
        )
    } else {
        SessionHandle::with_drop_threshold(Arc::clone(&identity), priority_tx, normal_tx, u32::MAX)
    };
    let session_id = handle.id;

    tracing::info!(cn = %cn, peer = %peer_addr, session_id = session_id, "connected");
    crate::audit::client_connected(&cn, peer_addr, &identity.fingerprint, session_id);
    // Drain any messages persisted while this CN was offline BEFORE
    // registering the handle — otherwise live traffic routed between
    // `register` and the drain would slip ahead of the queued
    // messages, breaking FIFO across the reconnect boundary.
    let buffered_offline = deps.router.drain_offline_messages(&cn).await;
    let before = buffered_offline.len();
    let buffered_offline = deps
        .router
        .filter_offline_messages(&identity, buffered_offline);
    let filtered = before - buffered_offline.len();
    if filtered > 0 {
        tracing::info!(
            cn = %cn,
            filtered,
            delivered = buffered_offline.len(),
            "filtered offline messages through current ACL/authz policy"
        );
    }
    if !deps.router.register(handle.clone()).await {
        #[cfg(feature = "metrics")]
        if let Some(ref tenant) = identity.tenant {
            crate::metrics::tenant_quota_rejections()
                .with_label_values(&[tenant])
                .inc();
        }
        tracing::warn!(cn = %cn, "session rejected by tenant quota");
        crate::audit::connection_rejected(peer_addr, "tenant quota exceeded");
        return;
    }
    for pending in buffered_offline {
        let (msg, audit) = pending.into_parts();
        if handle.send(Arc::new(msg)).await.is_err() {
            // Send failed — drop `audit` without emitting so the
            // drain-path `authz.classified_delivery` count matches
            // on-the-wire deliveries exactly.
            break;
        }
        audit.emit_on_delivered();
    }
    deps.router.replay_positions(&handle).await;

    #[allow(unused_mut)] // Mutable borrows needed for proto negotiation
    let (mut reader, mut writer) = session.split();

    // Run protocol negotiation for TakNegotiate mode.
    // This may upgrade the codec from XML to protobuf.
    let (final_codec, read_buf): (Arc<dyn Codec>, _) = match deps.framing {
        #[cfg(feature = "proto")]
        Framing::TakNegotiate => {
            match negotiate_tak_protocol(&mut reader, &mut writer, &cn).await {
                Ok((codec, buf)) => {
                    let protocol = codec.protocol_id();
                    #[cfg(feature = "metrics")]
                    {
                        let label = if protocol == "tak-protobuf" {
                            "protobuf"
                        } else {
                            "xml"
                        };
                        metrics::negotiations().with_label_values(&[label]).inc();
                    }
                    crate::audit::negotiation_result(&cn, protocol, true);
                    (codec, buf)
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    metrics::negotiations().with_label_values(&["failed"]).inc();
                    tracing::debug!(cn = %cn, error = %e, "negotiation failed");
                    crate::audit::negotiation_result(&cn, "tak", false);
                    deps.router.unregister(&cn, session_id).await;
                    #[cfg(feature = "metrics")]
                    {
                        metrics::sessions_active().dec();
                        metrics::connections_active().dec();
                    }
                    crate::audit::client_disconnected(&cn, session_id);
                    tracing::info!(cn = %cn, "disconnected");
                    return;
                }
            }
        }
        _ => (deps.codec.clone(), tokio_util::bytes::BytesMut::new()),
    };

    let throttle = deps.throttle_config.map(|tc| tc.build());
    #[cfg(feature = "metrics")]
    let session_started = std::time::Instant::now();
    let ctx = SessionContext {
        identity: &identity,
        router: &deps.router,
        codec: final_codec.as_ref(),
        nats_publisher: &deps.nats_publisher,
        fed_forward: &deps.fed_forward,
        #[cfg(feature = "http")]
        http_forward: &deps.http_forward,
        throttle,
        archiver: &deps.archiver,
        replay_filter: &deps.replay_filter,
        delta_config: deps.delta_config,
        #[cfg(feature = "metrics")]
        metrics_identity: deps.metrics_identity.as_ref(),
    };

    let result = run_session_loops(
        reader,
        writer,
        priority_rx,
        normal_rx,
        &ctx,
        read_buf,
        #[cfg(feature = "metrics")]
        &cn,
    )
    .await;

    if let Err(e) = result {
        tracing::debug!(cn = %cn, error = %e, "session error");
    }

    deps.router.unregister(&cn, session_id).await;
    #[cfg(feature = "metrics")]
    {
        metrics::sessions_active().dec();
        metrics::connections_active().dec();
        if let Some(hist) = metrics::per_identity_session_duration() {
            let bucket = deps.metrics_identity.bucket(&cn);
            hist.with_label_values(&[bucket])
                .observe(session_started.elapsed().as_secs_f64());
        }
    }
    crate::audit::client_disconnected(&cn, session_id);
    tracing::info!(cn = %cn, "disconnected");
}

/// TAK protocol negotiation handshake.
///
/// Sends TakProtocolSupport advertisement, then peeks the first byte of the
/// client's response. If 0xBF (protobuf magic), completes the handshake and
/// upgrades to protobuf. Otherwise, stays XML.
///
/// Returns the negotiated codec and any buffered read bytes.
#[cfg(feature = "proto")]
async fn negotiate_tak_protocol(
    reader: &mut rustgate_transport::SessionReader,
    writer: &mut rustgate_transport::SessionWriter,
    cn: &str,
) -> std::io::Result<(Arc<dyn Codec>, tokio_util::bytes::BytesMut)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::bytes::BufMut;

    let server_uid = format!("rustgate-{cn}");

    // Step 1: Send TakProtocolSupport XML advertisement
    let advert = rustgate_proto::build_protocol_support_xml(&server_uid);
    writer.write_all(&advert).await?;
    writer.flush().await?;

    tracing::debug!(cn = %cn, "sent TakProtocolSupport advertisement");

    // Step 2: Peek the first byte to determine if client wants protobuf
    let mut peek = [0u8; 1];
    let n = reader.read(&mut peek).await?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "client disconnected during negotiation",
        ));
    }

    if peek[0] == 0xBF {
        // Client is requesting protobuf upgrade.
        // Magic byte already consumed; read_tak_request handles varint + payload + validation.
        let version = rustgate_proto::read_tak_request(reader).await?;

        tracing::info!(cn = %cn, ?version, "client requested protobuf upgrade");

        // Step 3: Send TakResponse (0xBF-framed TakControl acknowledgement)
        let response = rustgate_proto::build_tak_response(version);
        writer.write_all(&response).await?;
        writer.flush().await?;

        tracing::info!(cn = %cn, ?version, "protobuf negotiation complete");

        Ok((
            Arc::new(rustgate_proto::TakProtobufCodec),
            tokio_util::bytes::BytesMut::new(),
        ))
    } else {
        // Client sent XML (legacy mode). Preserve the byte we already read.
        tracing::info!(cn = %cn, "client staying XML (no protobuf request)");

        let mut buf = tokio_util::bytes::BytesMut::with_capacity(64);
        buf.put_u8(peek[0]);
        Ok((Arc::new(rustgate_transport::TakXmlCodec), buf))
    }
}

/// Spawn concurrent read and write loops as a `select` race.
///
/// Returns when either loop finishes (EOF, timeout, or error).
async fn run_session_loops(
    reader: rustgate_transport::SessionReader,
    writer: rustgate_transport::SessionWriter,
    priority_rx: mpsc::Receiver<rustgate_transport::RoutedMessage>,
    normal_rx: mpsc::Receiver<rustgate_transport::RoutedMessage>,
    ctx: &SessionContext<'_, impl NatsPublish>,
    read_buf: tokio_util::bytes::BytesMut,
    #[cfg(feature = "metrics")] cn: &str,
) -> std::io::Result<()> {
    #[cfg(feature = "metrics")]
    let bucket = ctx.metrics_identity.bucket(cn).to_string();
    let delta_encoder = if codec_is_xml(ctx.codec) {
        ctx.delta_config.build_encoder()
    } else {
        None
    };
    tokio::select! {
        r = read_loop(reader, ctx, read_buf) => r,
        r = write_loop(
            writer,
            priority_rx,
            normal_rx,
            ctx.codec,
            delta_encoder,
            #[cfg(feature = "metrics")]
            bucket,
        ) => r,
    }
}

/// Whether the active codec speaks XML on the wire. The delta encoder
/// only operates on XML-framed sessions — protobuf and raw length-prefixed
/// codecs are passed through unchanged.
fn codec_is_xml(codec: &dyn Codec) -> bool {
    codec.protocol_id() == "tak-xml"
}

/// Decode inbound frames, apply rate limiting, and route to local clients,
/// NATS, federation peers, and the event archiver.
async fn read_loop(
    reader: rustgate_transport::SessionReader,
    ctx: &SessionContext<'_, impl NatsPublish>,
    prefix: tokio_util::bytes::BytesMut,
) -> std::io::Result<()> {
    let framed_codec = FramedCodec::from_strategy(&ctx.codec.framing());

    // When negotiation consumed a peek byte and fell back to XML,
    // we need to feed that byte to the codec before reading from the socket.
    let prefix_opt = if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    };
    let mut framed = FramedRead::new(PrefixedReader::new(reader, prefix_opt), framed_codec);

    let mut msg_builder = MessageBuilder::new();

    loop {
        let frame = match tokio::time::timeout(READ_TIMEOUT, framed.next()).await {
            Ok(Some(result)) => result?,
            Ok(None) => break, // EOF -- client closed cleanly
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read timeout: no complete frame received",
                ));
            }
        };

        // Convert framed bytes to canonical payload format via the codec.
        // Passthrough codecs use frame.freeze() for zero-copy; converting
        // codecs (protobuf) allocate regardless so the owned buffer is free.
        let payload = ctx.codec.decode_payload(frame)?;

        #[cfg(feature = "metrics")]
        metrics::messages_received().inc();

        // Per-client rate limiting -- drop excess messages
        if let Some(t) = &ctx.throttle
            && !t.allow()
        {
            tracing::debug!(cn = %ctx.identity.cn, "message dropped: rate limit exceeded");
            #[cfg(feature = "metrics")]
            {
                let bucket = ctx.metrics_identity.bucket(&ctx.identity.cn);
                metrics::messages_dropped()
                    .with_label_values(&[bucket])
                    .inc();
            }
            continue;
        }

        // Anti-replay: drop messages with duplicate (uid, time) within the window
        if let Some(filter) = ctx.replay_filter
            && filter.is_replay(&payload)
        {
            tracing::debug!(cn = %ctx.identity.cn, "message dropped: replay detected");
            #[cfg(feature = "metrics")]
            metrics::messages_replayed().inc();
            continue;
        }

        let msg = msg_builder.build(ctx.identity, payload, "tcp");

        // Archive to JSONL if enabled
        if let Some(arch) = ctx.archiver {
            arch.record(&msg).await;
        }

        #[cfg(feature = "metrics")]
        {
            let dest_label = match msg.destination {
                Destination::Broadcast => "broadcast",
                Destination::Group(_) => "group",
                Destination::Direct(_) => "direct",
                Destination::Multicast(_) => "multicast",
            };
            let bucket = ctx.metrics_identity.bucket(&ctx.identity.cn);
            metrics::messages_routed()
                .with_label_values(&[dest_label, bucket])
                .inc();
            // Tier 2: bytes received accounting (payload size)
            if let Some(c) = metrics::per_identity_bytes_received() {
                c.with_label_values(&[bucket])
                    .inc_by(msg.payload.len() as u64);
            }
        }

        // Route and capture the post-Send-PEP form so NATS / federation /
        // HTTP egress forwarders receive the same mutated payload that
        // local sessions did. Dispatching `msg` pre-route would bypass
        // data-plane obligations such as `MaskPoint` / `MaskPayload` and
        // leak the raw payload to external sinks (SIEM, federation peers).
        // `None` means the router dropped the message (dedup, TTL expired,
        // Send-PEP deny, oversize multicast) and all egress MUST be
        // skipped so external sinks stay consistent with local delivery.
        let Some(routed) = ctx.router.route_for_egress(msg).await else {
            continue;
        };

        // Publish to NATS after local routing (fire-and-forget)
        if let Some(publisher) = ctx.nats_publisher {
            #[cfg(feature = "metrics")]
            metrics::nats_publishes().inc();
            publisher.publish(&routed).await;
        }

        // Forward to federation peers (fire-and-forget)
        if let Some(fwd) = ctx.fed_forward {
            let groups: Vec<String> = routed.source.groups.iter().cloned().collect();
            fwd(routed.payload.clone(), groups, routed.metadata.clone());
        }

        // Forward to HTTP targets (fire-and-forget)
        #[cfg(feature = "http")]
        if let Some(fwd) = ctx.http_forward {
            fwd((*routed).clone());
        }
    }

    Ok(())
}

/// Encode outbound messages and send to the client with a write timeout.
///
/// Uses biased `tokio::select!` to always drain the priority channel
/// (Position and Alert messages) before processing normal messages.
async fn write_loop(
    writer: rustgate_transport::SessionWriter,
    mut priority_rx: mpsc::Receiver<rustgate_transport::RoutedMessage>,
    mut normal_rx: mpsc::Receiver<rustgate_transport::RoutedMessage>,
    codec: &dyn Codec,
    mut delta_encoder: Option<DeltaEncoder>,
    #[cfg(feature = "metrics")] bucket: String,
) -> std::io::Result<()> {
    let mut framed = FramedWrite::new(writer, FramedCodec::from_strategy(&codec.framing()));

    let mut priority_open = true;
    let mut normal_open = true;
    loop {
        if !priority_open && !normal_open {
            break;
        }
        let msg = tokio::select! {
            biased;
            msg = priority_rx.recv(), if priority_open => match msg {
                Some(m) => m,
                None => {
                    priority_open = false;
                    continue;
                }
            },
            msg = normal_rx.recv(), if normal_open => match msg {
                Some(m) => m,
                None => {
                    normal_open = false;
                    continue;
                }
            },
        };

        let encoded = codec.encode_payload(&msg)?;
        let wire_bytes = match delta_encoder.as_mut() {
            Some(enc) => match apply_delta(enc, &encoded) {
                DeltaDispatch::Send(bytes) => bytes,
                DeltaDispatch::Skip => continue,
            },
            None => encoded,
        };
        #[cfg(feature = "metrics")]
        if let Some(c) = metrics::per_identity_bytes_sent() {
            c.with_label_values(&[bucket.as_str()])
                .inc_by(wire_bytes.len() as u64);
        }
        let send_fut = framed.send(tokio_util::bytes::BytesMut::from(wire_bytes.as_ref()));

        match tokio::time::timeout(WRITE_TIMEOUT, send_fut).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "write timeout: slow consumer",
                ));
            }
        }
    }

    Ok(())
}

/// Outcome of feeding an outbound payload through the delta encoder.
enum DeltaDispatch {
    /// Bytes to actually write to the socket.
    Send(Bytes),
    /// The encoder suppressed the event entirely — skip the write.
    Skip,
}

/// Run one payload through the per-session delta encoder, updating the
/// matching Prometheus counters. Returns the bytes to send, or `Skip` when
/// the encoder determined the update was redundant.
fn apply_delta(enc: &mut DeltaEncoder, encoded: &Bytes) -> DeltaDispatch {
    let prior = enc.stats();
    let out = enc.encode(encoded);
    let stats = enc.stats();
    #[cfg(feature = "metrics")]
    {
        let full_delta = stats.full.saturating_sub(prior.full);
        if full_delta > 0 {
            metrics::cot_delta_full().inc_by(full_delta);
        }
        let delta_delta = stats.delta.saturating_sub(prior.delta);
        if delta_delta > 0 {
            metrics::cot_delta_delta().inc_by(delta_delta);
        }
        let suppressed_delta = stats.suppressed.saturating_sub(prior.suppressed);
        if suppressed_delta > 0 {
            metrics::cot_delta_suppressed().inc_by(suppressed_delta);
        }
        let bytes_delta = stats.bytes_saved.saturating_sub(prior.bytes_saved);
        if bytes_delta > 0 {
            metrics::cot_delta_bytes_saved().inc_by(bytes_delta);
        }
    }
    #[cfg(not(feature = "metrics"))]
    let _ = (prior, stats);
    match out {
        DeltaOutput::Full(b) | DeltaOutput::Delta(b) => DeltaDispatch::Send(b),
        DeltaOutput::Suppressed => DeltaDispatch::Skip,
    }
}

// ---------------------------------------------------------------------------
// Plaintext TCP
// ---------------------------------------------------------------------------

/// Configuration for the plaintext TCP accept loop, bundling arguments that
/// would otherwise require `#[allow(clippy::too_many_arguments)]`.
pub(crate) struct PlaintextTcpConfig<P: NatsPublish> {
    pub(crate) listener: rustgate_transport::PlaintextListener,
    pub(crate) router: Arc<Router>,
    pub(crate) connection_limit: Arc<Semaphore>,
    pub(crate) codec: Arc<dyn Codec>,
    pub(crate) nats_publisher: Option<P>,
    pub(crate) fed_forward: Option<FedForwardFn>,
    #[cfg(feature = "http")]
    pub(crate) http_forward: Option<HttpForwardFn>,
    pub(crate) throttle_config: Option<ThrottleConfig>,
    pub(crate) archiver: Option<Arc<archive::CotArchiver>>,
    pub(crate) replay_filter: Option<Arc<ReplayFilter>>,
    pub(crate) circuit_breaker_threshold: u32,
    pub(crate) delta_config: DeltaConfig,
    pub(crate) shutdown: Arc<tokio::sync::Notify>,
    #[cfg(feature = "metrics")]
    pub(crate) metrics_identity: Arc<metrics::MetricsIdentity>,
}

/// Accept loop for plaintext TCP connections.
///
/// Mirrors the main TLS accept loop but operates on unencrypted sockets.
/// Each connection gets a synthetic identity and participates in the same
/// router, NATS bridge, and federation forwarding as TLS sessions.
pub(crate) async fn run_plaintext_tcp<P: NatsPublish + Send + Sync + 'static>(
    config: PlaintextTcpConfig<P>,
) {
    let PlaintextTcpConfig {
        listener,
        router,
        connection_limit,
        codec,
        nats_publisher,
        fed_forward,
        #[cfg(feature = "http")]
        http_forward,
        throttle_config,
        archiver,
        replay_filter,
        circuit_breaker_threshold,
        delta_config,
        shutdown,
        #[cfg(feature = "metrics")]
        metrics_identity,
    } = config;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok(session) => {
                        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::warn!("plaintext TCP: connection limit reached, rejecting");
                                continue;
                            }
                        };

                        let identity = Arc::new(session.identity().clone());
                        let cn = identity.cn.clone();
                        let peer_addr = session.peer_addr();

                        tracing::info!(cn = %cn, peer = %peer_addr, "plaintext TCP connected");

                        let (priority_tx, priority_rx) = mpsc::channel::<rustgate_transport::RoutedMessage>(
                            rustgate_transport::PRIORITY_CHANNEL_CAPACITY,
                        );
                        let (normal_tx, normal_rx) = mpsc::channel::<rustgate_transport::RoutedMessage>(
                            rustgate_transport::NORMAL_CHANNEL_CAPACITY,
                        );
                        let handle = if circuit_breaker_threshold > 0 {
                            SessionHandle::with_drop_threshold(Arc::clone(&identity), priority_tx, normal_tx, circuit_breaker_threshold)
                        } else {
                            SessionHandle::with_drop_threshold(Arc::clone(&identity), priority_tx, normal_tx, u32::MAX)
                        };
                        let session_id = handle.id;
                        // Drain offline queue BEFORE register so live
                        // traffic cannot race ahead of queued entries.
                        let buffered_offline = router.drain_offline_messages(&cn).await;
                        let before = buffered_offline.len();
                        let buffered_offline = router.filter_offline_messages(&identity, buffered_offline);
                        let filtered = before - buffered_offline.len();
                        if filtered > 0 {
                            tracing::info!(
                                cn = %cn,
                                filtered,
                                delivered = buffered_offline.len(),
                                "filtered offline messages through current ACL/authz policy"
                            );
                        }
                        if !router.register(handle.clone()).await {
                            tracing::warn!(cn = %cn, "connection rejected: tenant quota exceeded");
                            crate::audit::connection_rejected(
                                peer_addr,
                                "tenant quota exceeded",
                            );
                            continue;
                        }
                        for pending in buffered_offline {
                            let (msg, audit) = pending.into_parts();
                            if handle.send(Arc::new(msg)).await.is_err() {
                                // Drop `audit` without emitting: the
                                // drain-path classified_delivery record
                                // fires only on actual delivery.
                                break;
                            }
                            audit.emit_on_delivered();
                        }
                        router.replay_positions(&handle).await;

                        let (reader, writer) = session.into_split();

                        let session_router = Arc::clone(&router);
                        let session_codec = Arc::clone(&codec);
                        #[allow(clippy::clone_on_copy)]
                        let session_nats = nats_publisher.clone();
                        let session_fed = fed_forward.clone();
                        #[cfg(feature = "http")]
                        let session_http = http_forward.clone();
                        let session_throttle = throttle_config.map(|tc| tc.build());
                        let session_arch = archiver.clone();
                        let session_rf = replay_filter.clone();
                        #[cfg(feature = "metrics")]
                        let session_metrics_id = Arc::clone(&metrics_identity);

                        rustgate_core::tasks::spawn_background("plaintext-tcp-session", async move {
                            let _permit = permit;

                            let result = run_plaintext_session_loops(PlaintextSessionContext {
                                reader,
                                writer,
                                priority_rx,
                                normal_rx,
                                identity: &identity,
                                router: &session_router,
                                codec: session_codec.as_ref(),
                                nats_publisher: &session_nats,
                                fed_forward: &session_fed,
                                #[cfg(feature = "http")]
                                http_forward: &session_http,
                                throttle: session_throttle,
                                archiver: &session_arch,
                                replay_filter: &session_rf,
                                delta_config,
                                #[cfg(feature = "metrics")]
                                metrics_identity: session_metrics_id.as_ref(),
                            }).await;

                            if let Err(e) = result {
                                tracing::debug!(cn = %cn, error = %e, "plaintext TCP session error");
                            }

                            session_router.unregister(&cn, session_id).await;
                            tracing::info!(cn = %cn, "plaintext TCP disconnected");
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "plaintext TCP accept error");
                    }
                }
            }
            _ = shutdown.notified() => {
                tracing::info!("plaintext TCP listener stopping");
                break;
            }
        }
    }
}

/// Context for a plaintext TCP session's read/write loops.
struct PlaintextSessionContext<'a, P: NatsPublish> {
    reader: tokio::io::ReadHalf<tokio::net::TcpStream>,
    writer: tokio::io::WriteHalf<tokio::net::TcpStream>,
    priority_rx: mpsc::Receiver<rustgate_transport::RoutedMessage>,
    normal_rx: mpsc::Receiver<rustgate_transport::RoutedMessage>,
    identity: &'a Identity,
    router: &'a Router,
    codec: &'a dyn Codec,
    nats_publisher: &'a Option<P>,
    fed_forward: &'a Option<FedForwardFn>,
    #[cfg(feature = "http")]
    http_forward: &'a Option<HttpForwardFn>,
    throttle: Option<rustgate_transport::ClientThrottle>,
    archiver: &'a Option<Arc<archive::CotArchiver>>,
    replay_filter: &'a Option<Arc<ReplayFilter>>,
    delta_config: DeltaConfig,
    #[cfg(feature = "metrics")]
    metrics_identity: &'a metrics::MetricsIdentity,
}

/// Read/write loops for a plaintext TCP session.
///
/// Uses the same codec pipeline as TLS sessions but operates on a raw
/// `TcpStream` split. The codec handles both framing and payload conversion.
async fn run_plaintext_session_loops<P: NatsPublish>(
    ctx: PlaintextSessionContext<'_, P>,
) -> std::io::Result<()> {
    let PlaintextSessionContext {
        reader,
        writer,
        mut priority_rx,
        mut normal_rx,
        identity,
        router,
        codec,
        nats_publisher,
        fed_forward,
        #[cfg(feature = "http")]
        http_forward,
        throttle,
        archiver,
        replay_filter,
        delta_config,
        #[cfg(feature = "metrics")]
        metrics_identity,
    } = ctx;
    let mut plaintext_delta_encoder = if codec_is_xml(codec) {
        delta_config.build_encoder()
    } else {
        None
    };
    let framed_codec = FramedCodec::from_strategy(&codec.framing());
    let mut framed_read = FramedRead::new(reader, framed_codec);
    let mut msg_builder = MessageBuilder::new();

    let write_framed_codec = FramedCodec::from_strategy(&codec.framing());
    let mut framed_write = FramedWrite::new(writer, write_framed_codec);

    tokio::select! {
        r = async {
            loop {
                let frame = match tokio::time::timeout(READ_TIMEOUT, framed_read.next()).await {
                    Ok(Some(result)) => result?,
                    Ok(None) => break,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "read timeout",
                        ));
                    }
                };

                let payload = codec.decode_payload(frame)?;

                // Per-client rate limiting — drop excess messages
                if let Some(t) = &throttle
                    && !t.allow()
                {
                    tracing::debug!(cn = %identity.cn, "message dropped: rate limit exceeded");
                    #[cfg(feature = "metrics")]
                    {
                        let bucket = metrics_identity.bucket(&identity.cn);
                        metrics::messages_dropped()
                            .with_label_values(&[bucket])
                            .inc();
                    }
                    continue;
                }

                // Anti-replay: drop messages with duplicate (uid, time) within the window
                if let Some(filter) = replay_filter
                    && filter.is_replay(&payload)
                {
                    tracing::debug!(cn = %identity.cn, "message dropped: replay detected");
                    #[cfg(feature = "metrics")]
                    metrics::messages_replayed().inc();
                    continue;
                }

                let msg = msg_builder.build(identity, payload, "tcp-plaintext");

                // Archive to JSONL if enabled
                if let Some(arch) = archiver {
                    arch.record(&msg).await;
                }

                // Capture the post-Send-PEP form so NATS / federation /
                // HTTP egress dispatch the same mutated payload local
                // sessions received. `None` means the router dropped the
                // message and all egress MUST be skipped.
                let Some(routed) = router.route_for_egress(msg).await else {
                    continue;
                };

                if let Some(publisher) = nats_publisher {
                    publisher.publish(&routed).await;
                }

                if let Some(fwd) = fed_forward {
                    let groups: Vec<String> = routed.source.groups.iter().cloned().collect();
                    fwd(routed.payload.clone(), groups, routed.metadata.clone());
                }

                #[cfg(feature = "http")]
                if let Some(fwd) = http_forward {
                    fwd((*routed).clone());
                }
            }
            Ok(())
        } => r,
        r = async {
            let mut priority_open = true;
            let mut normal_open = true;
            loop {
                if !priority_open && !normal_open {
                    break;
                }
                let msg = tokio::select! {
                    biased;
                    msg = priority_rx.recv(), if priority_open => match msg {
                        Some(m) => m,
                        None => {
                            priority_open = false;
                            continue;
                        }
                    },
                    msg = normal_rx.recv(), if normal_open => match msg {
                        Some(m) => m,
                        None => {
                            normal_open = false;
                            continue;
                        }
                    },
                };
                let encoded = codec.encode_payload(&msg)?;
                let wire_bytes = match plaintext_delta_encoder.as_mut() {
                    Some(enc) => match apply_delta(enc, &encoded) {
                        DeltaDispatch::Send(b) => b,
                        DeltaDispatch::Skip => continue,
                    },
                    None => encoded,
                };
                let send_fut = framed_write.send(tokio_util::bytes::BytesMut::from(wire_bytes.as_ref()));
                match tokio::time::timeout(WRITE_TIMEOUT, send_fut).await {
                    Ok(result) => result?,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "write timeout: slow consumer",
                        ));
                    }
                }
            }
            Ok(())
        } => r,
    }
}

// ---------------------------------------------------------------------------
// PrefixedReader
// ---------------------------------------------------------------------------

/// AsyncRead wrapper that yields prefix bytes before delegating to the inner reader.
///
/// Used after protocol negotiation to feed the peeked byte back to the codec
/// when the client stays in XML mode.
pub(crate) struct PrefixedReader<R> {
    inner: R,
    prefix: Vec<u8>,
    prefix_pos: usize,
}

impl<R> PrefixedReader<R> {
    pub(crate) fn new(inner: R, prefix: Option<tokio_util::bytes::BytesMut>) -> Self {
        let prefix = prefix.map_or_else(Vec::new, |b| b.to_vec());
        Self {
            inner,
            prefix,
            prefix_pos: 0,
        }
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Drain prefix bytes first
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.prefix_pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
