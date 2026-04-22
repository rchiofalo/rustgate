// Copyright © 2026 Roberto Chiofalo.

//! WebSocket server with session lifecycle management.
//!
//! Bridges authenticated WebSocket connections into the message [`Router`]
//! as full routing participants. WebSocket and TCP clients are interoperable —
//! same session registration, group enforcement, position cache replay.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use rustgate_core::codec::Codec;
use rustgate_core::constants::{READ_TIMEOUT, WRITE_TIMEOUT};
use rustgate_core::identity::Identity;
use rustgate_core::masking::hash_cn;
use rustgate_core::message::RoutableMessage;
use rustgate_cot::MessageBuilder;
use rustgate_transport::{ClientThrottle, ReplayFilter, Router, SessionHandle, ThrottleConfig};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{Interval, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::health::{HealthCheckConfig, LastPong, new_last_pong};
use crate::{WsListener, WsSession, WsStream};

/// Callback for NATS publishing after local routing.
///
/// The closure spawns async work internally (fire-and-forget).
///
/// Uses `Fn` (not `AsyncFn`) because `dyn AsyncFn` is not object-safe
/// as of Rust 1.93. Async work is dispatched via `spawn_background()`.
pub type OnNatsPublish = Arc<dyn Fn(RoutableMessage) + Send + Sync>;

/// Callback for federation forwarding.
///
/// Receives `(payload_bytes, source_groups)`.
///
/// Uses `Fn` (not `AsyncFn`) because `dyn AsyncFn` is not object-safe
/// as of Rust 1.93. Async work is dispatched via `spawn_background()`.
pub type OnFederationForward =
    Arc<dyn Fn(Bytes, Vec<String>, rustgate_core::message::Metadata) + Send + Sync>;

/// Callback for HTTP egress forwarding (fire-and-forget).
///
/// Uses `Fn` (not `AsyncFn`) because `dyn AsyncFn` is not object-safe
/// as of Rust 1.94. Async work is dispatched via the publisher's internal channel.
pub type OnHttpForward = Arc<dyn Fn(RoutableMessage) + Send + Sync>;

/// Default maximum pending write bytes per WebSocket connection: 4 MiB.
///
/// When the write loop has sent more than this many bytes without the
/// client draining them (i.e. the cumulative payload exceeds this between
/// successful flushes), the connection is terminated to prevent memory
/// exhaustion from slow-reading clients.
pub const DEFAULT_MAX_WRITE_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Configuration for the WebSocket server.
pub struct WsServerConfig {
    pub listener: WsListener,
    pub router: Arc<Router>,
    pub connection_limit: Arc<Semaphore>,
    pub codec: Arc<dyn Codec>,
    pub nats_publish: Option<OnNatsPublish>,
    pub fed_forward: Option<OnFederationForward>,
    pub http_forward: Option<OnHttpForward>,
    pub throttle_config: Option<ThrottleConfig>,
    pub replay_filter: Option<Arc<ReplayFilter>>,
    /// Consecutive send failures before the circuit breaker disconnects a session.
    /// Set to 0 to disable.
    pub circuit_breaker_threshold: u32,
    /// Maximum WebSocket frames per second per connection (0 = unlimited).
    pub ws_max_frames_per_sec: u32,
    /// Maximum WebSocket bytes per second per connection (0 = unlimited).
    pub ws_max_bytes_per_sec: u64,
    /// Consecutive WebSocket rate limit violations before disconnecting.
    pub ws_max_violations: u32,
    /// Maximum pending write bytes per connection before disconnecting
    /// a slow consumer. 0 = unlimited (not recommended).
    pub max_write_buffer_bytes: usize,
    /// Active WebSocket heartbeat configuration. See [`HealthCheckConfig`]
    /// for semantics. Defaults to fully disabled.
    pub health_check: HealthCheckConfig,
    pub shutdown: Arc<Notify>,
}

impl std::fmt::Debug for WsServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsServerConfig")
            .field("listener", &self.listener)
            .field("router", &"<Router>")
            .field("codec", &self.codec.protocol_id())
            .finish()
    }
}

/// WebSocket server managing the accept loop and session lifecycle.
#[derive(Debug)]
pub struct WebSocketServer;

impl WebSocketServer {
    /// Run the WebSocket server accept loop.
    ///
    /// Listens for new connections, authenticates via mTLS, and spawns
    /// a session handler for each. Returns when the shutdown signal fires.
    pub async fn run(config: WsServerConfig) {
        let WsServerConfig {
            listener,
            router,
            connection_limit,
            codec,
            nats_publish,
            fed_forward,
            http_forward,
            throttle_config,
            replay_filter,
            circuit_breaker_threshold,
            ws_max_frames_per_sec,
            ws_max_bytes_per_sec,
            ws_max_violations,
            max_write_buffer_bytes,
            health_check,
            shutdown,
        } = config;

        info!(addr = ?listener.local_addr().ok(), "WebSocket server started");

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok(session) => {
                            let peer_addr = session.peer_addr();
                            let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!(peer = %peer_addr, "connection limit reached, rejecting WebSocket client");
                                    rustgate_core::audit::connection_rejected(
                                        peer_addr,
                                        "WebSocket connection limit reached",
                                    );
                                    continue;
                                }
                            };

                            let router = Arc::clone(&router);
                            let session_codec = Arc::clone(&codec);
                            let nats = nats_publish.clone();
                            let fed = fed_forward.clone();
                            let http = http_forward.clone();
                            let tc = throttle_config;
                            let rf = replay_filter.clone();

                            let cb = circuit_breaker_threshold;
                            let fps = ws_max_frames_per_sec;
                            let bps = ws_max_bytes_per_sec;
                            let vio = ws_max_violations;
                            let mwb = max_write_buffer_bytes;
                            let hc = health_check;
                            drop(tokio::spawn(handle_ws_session(
                                session, router, session_codec, nats, fed, http, tc, rf,
                                cb, fps, bps, vio, mwb, hc, permit,
                            )));
                        }
                        Err(e) => {
                            warn!(error = %e, "WebSocket accept error");
                        }
                    }
                }
                () = shutdown.notified() => {
                    info!("WebSocket server shutting down");
                    break;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_ws_session(
    session: WsSession,
    router: Arc<Router>,
    codec: Arc<dyn Codec>,
    nats_publish: Option<OnNatsPublish>,
    fed_forward: Option<OnFederationForward>,
    http_forward: Option<OnHttpForward>,
    throttle_config: Option<ThrottleConfig>,
    replay_filter: Option<Arc<ReplayFilter>>,
    circuit_breaker_threshold: u32,
    ws_max_frames_per_sec: u32,
    ws_max_bytes_per_sec: u64,
    ws_max_violations: u32,
    max_write_buffer_bytes: usize,
    health_check: HealthCheckConfig,
    _permit: OwnedSemaphorePermit,
) {
    let identity = session.identity_arc();
    let peer_addr = session.peer_addr();
    let cn = identity.cn.clone();

    info!(
        peer_addr = %peer_addr,
        cn = %hash_cn(&cn),
        groups = ?identity.groups,
        "WebSocket session started"
    );

    let (priority_tx, mut priority_rx) = mpsc::channel::<rustgate_transport::RoutedMessage>(
        rustgate_transport::PRIORITY_CHANNEL_CAPACITY,
    );
    let (normal_tx, mut normal_rx) = mpsc::channel::<rustgate_transport::RoutedMessage>(
        rustgate_transport::NORMAL_CHANNEL_CAPACITY,
    );
    let handle = if circuit_breaker_threshold > 0 {
        SessionHandle::with_drop_threshold(
            Arc::clone(&identity),
            priority_tx,
            normal_tx,
            circuit_breaker_threshold,
        )
    } else {
        SessionHandle::with_drop_threshold(Arc::clone(&identity), priority_tx, normal_tx, u32::MAX)
    };
    let session_id = handle.id;

    // Drain offline queue BEFORE register so queued messages are
    // delivered ahead of any live traffic routed to this CN after
    // registration completes. Filter through current ACL/authz policy
    // to prevent stale permissions from the time of storage.
    let buffered_offline = router.drain_offline_messages(&identity.cn).await;
    let before = buffered_offline.len();
    let buffered_offline = router.filter_offline_messages(&identity, buffered_offline);
    let filtered_count = before - buffered_offline.len();
    if filtered_count > 0 {
        info!(
            cn = %hash_cn(&identity.cn),
            filtered = filtered_count,
            delivered = buffered_offline.len(),
            "filtered offline messages on WebSocket reconnect",
        );
    }
    if !router.register(handle.clone()).await {
        // F-153: hash CN before logging — the audit call retains the raw
        // CN for compliance, but the structured log field is PII-safe.
        warn!(cn = %hash_cn(&identity.cn), "connection rejected: tenant quota exceeded");
        rustgate_core::audit::connection_rejected(peer_addr, "tenant quota exceeded");
        return;
    }
    for pending in buffered_offline {
        let (msg, audit) = pending.into_parts();
        if handle.send(Arc::new(msg)).await.is_err() {
            // Drop `audit` without emitting: the drain-path
            // classified_delivery record fires only on actual delivery.
            break;
        }
        audit.emit_on_delivered();
    }
    router.replay_positions(&handle).await;

    let ws_stream = session.into_stream();
    let (ws_write, ws_read) = ws_stream.split();

    let throttle = throttle_config.map(|tc| tc.build());

    let mut ws_rate_limiter = if ws_max_frames_per_sec > 0 || ws_max_bytes_per_sec > 0 {
        Some(crate::rate_limit::WsRateLimiter::new(
            ws_max_frames_per_sec,
            ws_max_bytes_per_sec,
            ws_max_violations,
        ))
    } else {
        None
    };

    let last_pong = new_last_pong();

    let read_result = {
        let router = Arc::clone(&router);
        let read_last_pong = Arc::clone(&last_pong);
        tokio::select! {
            r = ws_read_loop(ws_read, &identity, &router, nats_publish.as_ref(), fed_forward.as_ref(), http_forward.as_ref(), &throttle, &replay_filter, &mut ws_rate_limiter, read_last_pong) => r,
            r = ws_write_loop(ws_write, &mut priority_rx, &mut normal_rx, &*codec, max_write_buffer_bytes, health_check, Arc::clone(&last_pong)) => r,
        }
    };

    if let Err(ref e) = read_result {
        debug!(cn = %hash_cn(&cn), error = %e, "WebSocket session ended with error");
    }

    router.unregister(&cn, session_id).await;

    info!(
        peer_addr = %peer_addr,
        cn = %hash_cn(&cn),
        "WebSocket session ended"
    );
}

#[allow(clippy::too_many_arguments)]
async fn ws_read_loop(
    mut ws_read: SplitStream<WsStream>,
    identity: &Identity,
    router: &Router,
    nats_publish: Option<&OnNatsPublish>,
    fed_forward: Option<&OnFederationForward>,
    http_forward: Option<&OnHttpForward>,
    throttle: &Option<ClientThrottle>,
    replay_filter: &Option<Arc<ReplayFilter>>,
    ws_rate_limiter: &mut Option<crate::rate_limit::WsRateLimiter>,
    last_pong: LastPong,
) -> Result<(), String> {
    let mut msg_builder = MessageBuilder::new();

    loop {
        let frame = match tokio::time::timeout(READ_TIMEOUT, ws_read.next()).await {
            Ok(Some(Ok(msg))) => msg,
            Ok(Some(Err(e))) => return Err(format!("WebSocket read error: {e}")),
            Ok(None) => return Ok(()), // stream closed
            Err(_) => return Err("read timeout".into()),
        };

        let payload = match frame {
            Message::Binary(data) => data,
            Message::Text(text) => Bytes::copy_from_slice(text.as_bytes()),
            Message::Close(_) => return Ok(()),
            Message::Pong(_) => {
                // Record liveness for the write loop's deadline check.
                // Lock is only held for the Instant write; never across await.
                *last_pong.lock() = Instant::now();
                continue;
            }
            _ => continue, // Ping auto-replied by tungstenite; frames ignored
        };

        // Per-connection frame/byte rate limiting
        if let Some(limiter) = ws_rate_limiter
            && let Err(exceeded) = limiter.check(payload.len())
        {
            if exceeded.frame_exceeded {
                // F-153: `identity.cn` is control-char-validated at
                // `Identity::new()`, but we still hash it so production logs
                // never carry raw client CNs (PII hygiene).
                warn!(
                    cn = %hash_cn(&identity.cn),
                    frames = limiter.frame_count(),
                    limit = limiter.max_frames_per_sec(),
                    "WebSocket frame dropped: frame rate exceeded",
                );
            }
            if exceeded.byte_exceeded {
                warn!(
                    cn = %hash_cn(&identity.cn),
                    bytes = limiter.byte_count(),
                    limit = limiter.max_bytes_per_sec(),
                    "WebSocket frame dropped: byte rate exceeded",
                );
            }
            if limiter.should_disconnect() {
                return Err("disconnected: sustained rate limit violations".into());
            }
            continue;
        }

        // Per-client rate limiting — drop excess messages
        if let Some(t) = throttle
            && !t.allow()
        {
            warn!(cn = %hash_cn(&identity.cn), "message dropped: rate limit exceeded");
            rustgate_core::audit::rate_limit_triggered(
                &identity.cn,
                "websocket/inbound",
                t.rate() as usize,
            );
            continue;
        }

        // Anti-replay: drop messages with duplicate (uid, time) within the window
        if let Some(filter) = replay_filter
            && filter.is_replay(&payload)
        {
            debug!(cn = %hash_cn(&identity.cn), "message dropped: replay detected");
            continue;
        }

        let msg = msg_builder.build(identity, payload, "websocket");

        // Capture the post-Send-PEP form so NATS / federation / HTTP
        // egress forwarders receive the mutated payload (obligations
        // such as `MaskPoint` applied). `None` means the router dropped
        // the message — dedup, TTL, Send-PEP deny, oversize multicast —
        // and all egress MUST be skipped to keep external sinks
        // consistent with local delivery.
        let Some(routed) = router.route_for_egress(msg).await else {
            continue;
        };

        if let Some(cb) = nats_publish {
            cb((*routed).clone());
        }
        if let Some(fwd) = fed_forward {
            let groups: Vec<String> = routed.source.groups.iter().cloned().collect();
            fwd(routed.payload.clone(), groups, routed.metadata.clone());
        }
        if let Some(fwd) = http_forward {
            fwd((*routed).clone());
        }
    }
}

/// Action chosen on each iteration of the write loop.
enum WriteAction {
    /// A routed message is ready to be encoded and sent.
    Send(rustgate_transport::RoutedMessage),
    /// The ping interval elapsed; emit a Ping frame after a staleness check.
    Ping,
}

/// Await the next tick of an optional interval, or never if the interval
/// is `None`. `std::future::pending()` keeps the select! arm disarmed
/// without ever completing, which is what we want when the feature is off.
async fn tick_or_never(ticker: Option<&mut Interval>) -> Instant {
    match ticker {
        Some(t) => t.tick().await.into_std(),
        None => std::future::pending::<Instant>().await,
    }
}

/// Write loop for WebSocket sessions with biased priority drain.
///
/// Always checks the priority channel (Position and Alert messages)
/// before the normal channel, ensuring time-sensitive messages are
/// delivered first.
///
/// Tracks cumulative bytes written to the underlying WebSocket sink.
/// If `max_write_buffer_bytes` is non-zero and the pending byte count
/// exceeds the limit, the connection is terminated to prevent memory
/// exhaustion from slow-reading clients.
///
/// When `health_check.ping_enabled()` is true, emits a `Message::Ping`
/// every `ping_interval`. Before sending, the last recorded Pong is
/// consulted via `health_check.is_stale`; if the peer has been silent
/// past the configured tolerance the session is terminated.
#[allow(clippy::too_many_arguments)]
async fn ws_write_loop(
    mut ws_write: SplitSink<WsStream, Message>,
    priority_rx: &mut mpsc::Receiver<rustgate_transport::RoutedMessage>,
    normal_rx: &mut mpsc::Receiver<rustgate_transport::RoutedMessage>,
    codec: &dyn Codec,
    max_write_buffer_bytes: usize,
    health_check: HealthCheckConfig,
    last_pong: LastPong,
) -> Result<(), String> {
    let mut priority_open = true;
    let mut normal_open = true;
    let mut pending_bytes: usize = 0;

    let mut ping_ticker: Option<Interval> = if health_check.ping_enabled() {
        let mut t = tokio::time::interval(health_check.ping_interval);
        // Skip missed ticks instead of bursting catch-up Pings if the
        // loop stalls (e.g. blocked on a slow send). Delay avoids a
        // flurry of frames after any backpressure event.
        t.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Some(t)
    } else {
        None
    };

    loop {
        if !priority_open && !normal_open {
            break;
        }
        let action = tokio::select! {
            biased;
            msg = priority_rx.recv(), if priority_open => match msg {
                Some(m) => WriteAction::Send(m),
                None => {
                    priority_open = false;
                    continue;
                }
            },
            msg = normal_rx.recv(), if normal_open => match msg {
                Some(m) => WriteAction::Send(m),
                None => {
                    normal_open = false;
                    continue;
                }
            },
            _ = tick_or_never(ping_ticker.as_mut()) => WriteAction::Ping,
        };

        let msg = match action {
            WriteAction::Send(m) => m,
            WriteAction::Ping => {
                // Snapshot the last pong before emitting the next ping so a
                // silent peer is detected before more Pings pile up.
                let recorded = *last_pong.lock();
                if health_check.is_stale(recorded, Instant::now()) {
                    return Err("WebSocket heartbeat timeout: no Pong received".into());
                }
                match tokio::time::timeout(
                    WRITE_TIMEOUT,
                    ws_write.send(Message::Ping(Bytes::new())),
                )
                .await
                {
                    Ok(Ok(())) => continue,
                    Ok(Err(e)) => return Err(format!("WebSocket ping write error: {e}")),
                    Err(_) => return Err("write timeout on Ping (slow consumer)".into()),
                }
            }
        };

        let encoded = match codec.encode_payload(&msg) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(error = %e, "failed to encode outbound message");
                continue;
            }
        };

        let frame_len = encoded.len();

        // Check write buffer limit before sending. A slow-reading client
        // causes the TLS/WebSocket write buffers to grow unbounded; this
        // guard caps per-connection memory usage and disconnects the
        // offending session.
        if max_write_buffer_bytes > 0 {
            pending_bytes = pending_bytes.saturating_add(frame_len);
            if pending_bytes > max_write_buffer_bytes {
                warn!(
                    pending_bytes,
                    limit = max_write_buffer_bytes,
                    "WebSocket write buffer limit exceeded, disconnecting slow consumer"
                );
                return Err("write buffer limit exceeded (slow consumer)".into());
            }
        }

        let frame = Message::Binary(encoded.to_vec().into());

        match tokio::time::timeout(WRITE_TIMEOUT, ws_write.send(frame)).await {
            Ok(Ok(())) => {
                // Successful send: the frame has been flushed to the
                // underlying transport, so reset the pending counter.
                pending_bytes = 0;
            }
            Ok(Err(e)) => return Err(format!("WebSocket write error: {e}")),
            Err(_) => return Err("write timeout (slow consumer)".into()),
        }
    }

    Ok(())
}
