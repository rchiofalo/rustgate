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
// Egress callback aliases live in `rustgate_core::egress` so that any
// session crate (WebSocket, MQTT, future adapters) can reuse the same
// shapes without depending on a sibling transport crate. Re-exporting
// here keeps the public WS API stable for existing callers.
pub use rustgate_core::egress::{OnFederationForward, OnHttpForward, OnNatsPublish};
use rustgate_core::identity::Identity;
use rustgate_core::masking::hash_cn;
use rustgate_core::tasks::spawn_background;
use rustgate_cot::MessageBuilder;
use rustgate_transport::{ClientThrottle, ReplayFilter, Router, SessionHandle, ThrottleConfig};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{Interval, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::health::{HealthCheckConfig, LastPong, new_last_pong};
use crate::{TRANSPORT_LABEL, WsListener, WsSession, WsStream};

rustgate_core::on_callback!(
    /// Fired once per successful WebSocket session registration (post-mTLS,
    /// post-upgrade, post-tenant-quota). Used by `rustgate-server` to increment
    /// the `rustgate_ws_connections_total` Prometheus counter. The crate stays
    /// metrics-agnostic — no `prometheus` dependency leaks in.
    pub OnWsAcceptFn
);

rustgate_core::on_callback!(
    /// Fired once per WebSocket connection rejected on the session-handler
    /// boundary: per-IP rate limit, TLS handshake failure, identity extraction
    /// failure, upgrade handshake failure, connection-limit exhaustion, tenant
    /// quota exhaustion. Used by `rustgate-server` to increment the
    /// `rustgate_ws_connections_rejected_total` Prometheus counter.
    pub OnWsRejectFn
);

/// Bundle of WebSocket session lifecycle callbacks.
///
/// Held by `WsServerConfig` to keep its constructor under the clippy
/// `too_many_arguments` threshold while preserving per-event fan-out.
/// Adding a frame-level counter in the future slots in additional
/// `Option<Arc<dyn Fn() + Send + Sync>>` fields without further widening.
#[derive(Clone, Default)]
pub struct WsSessionHooks {
    /// See [`OnWsAcceptFn`].
    pub on_connection_accept: Option<OnWsAcceptFn>,
    /// See [`OnWsRejectFn`]. Cloned into `WsListenerConfig.on_connection_rejected`
    /// so the accept-loop reject branches can observe it as well.
    pub on_connection_rejected: Option<OnWsRejectFn>,
}

impl std::fmt::Debug for WsSessionHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsSessionHooks")
            .field("on_connection_accept", &self.on_connection_accept.is_some())
            .field(
                "on_connection_rejected",
                &self.on_connection_rejected.is_some(),
            )
            .finish()
    }
}

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
    /// Observability callbacks fired on connection accept / reject. Wired by
    /// `rustgate-server` under `#[cfg(feature = "metrics")]` to increment the
    /// `rustgate_ws_connections_total` and `rustgate_ws_connections_rejected_total`
    /// Prometheus counters. `None` disables dispatch with no runtime cost.
    pub session_hooks: Option<WsSessionHooks>,
    /// Optional SA auto-upgrade observer wired to the per-session
    /// [`MessageBuilder`]. When set, every WebSocket session inherits
    /// the callback and feeds the
    /// `rustgate_sa_auto_upgraded_total{from_version}` Prometheus
    /// counter. Closes #741.
    pub sa_upgrade_observer: Option<rustgate_cot::OnSaAutoUpgraded>,
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
            session_hooks,
            sa_upgrade_observer,
            shutdown,
        } = config;

        info!(
            transport = TRANSPORT_LABEL,
            addr = ?listener.local_addr().ok(),
            "WebSocket server started",
        );

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok(session) => {
                            let peer_addr = session.peer_addr();
                            let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!(
                                        transport = TRANSPORT_LABEL,
                                        peer = %peer_addr,
                                        "connection limit reached, rejecting WebSocket client",
                                    );
                                    rustgate_core::audit::connection_rejected(
                                        peer_addr,
                                        "WebSocket connection limit reached",
                                    );
                                    if let Some(hooks) = session_hooks.as_ref()
                                        && let Some(cb) = hooks.on_connection_rejected.as_ref()
                                    {
                                        cb();
                                    }
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
                            let hooks = session_hooks.clone();
                            let sa_obs = sa_upgrade_observer.clone();
                            spawn_background(
                                "ws-session",
                                handle_ws_session(
                                    session, router, session_codec, nats, fed, http, tc, rf,
                                    cb, fps, bps, vio, mwb, hc, hooks, sa_obs, permit,
                                ),
                            );
                        }
                        Err(e) => {
                            warn!(transport = TRANSPORT_LABEL, error = %e, "WebSocket accept error");
                        }
                    }
                }
                () = shutdown.notified() => {
                    info!(transport = TRANSPORT_LABEL, "WebSocket server shutting down");
                    break;
                }
            }
        }
    }
}

// justification: per-WebSocket-connection task spawned once by the accept
// loop. Each argument is a distinct runtime handle or cap that must be
// owned by this task for its lifetime (router, codec, three optional
// forwarders, throttle, replay filter, circuit threshold, three rate-limit
// caps, observability hooks, and more below). Bundling into a
// `WsSessionArgs` struct would push the fan-in onto the accept loop with
// no call-site reduction.
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
    session_hooks: Option<WsSessionHooks>,
    sa_upgrade_observer: Option<rustgate_cot::OnSaAutoUpgraded>,
    _permit: OwnedSemaphorePermit,
) {
    let identity = session.identity_arc();
    let peer_addr = session.peer_addr();
    let cn = identity.cn.clone();

    // Per-session metric instrumentation (issue #771). The active-
    // connections gauge is decremented in the matching scope-exit
    // path below. Compression and subprotocol counters are recorded
    // once at session start with the bounded label vocabulary
    // documented on `crate::metrics`.
    #[cfg(feature = "metrics")]
    {
        crate::metrics::active_connections().inc();
        let compression_label = if session.negotiated_compression().is_some() {
            "enabled"
        } else {
            // Without listener-config visibility on the session, the
            // disabled-vs-not-offered distinction collapses into a
            // single `not_offered` bucket. Operators read the
            // server-config dashboard panel alongside this metric to
            // disambiguate, and the label vocabulary stays bounded.
            "not_offered"
        };
        crate::metrics::compression_negotiated_total()
            .with_label_values(&[compression_label])
            .inc();
        let subprotocol_label = session.negotiated_subprotocol().unwrap_or("none");
        crate::metrics::subprotocol_selected_total()
            .with_label_values(&[subprotocol_label])
            .inc();
    }

    info!(
        transport = TRANSPORT_LABEL,
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
            transport = TRANSPORT_LABEL,
            cn = %hash_cn(&identity.cn),
            filtered = filtered_count,
            delivered = buffered_offline.len(),
            "filtered offline messages on WebSocket reconnect",
        );
    }
    if !router.register(handle.clone()).await {
        // F-153: hash CN before logging — the audit call retains the raw
        // CN for compliance, but the structured log field is PII-safe.
        warn!(
            transport = TRANSPORT_LABEL,
            cn = %hash_cn(&identity.cn),
            "connection rejected: tenant quota exceeded",
        );
        rustgate_core::audit::connection_rejected(peer_addr, "tenant quota exceeded");
        if let Some(hooks) = session_hooks.as_ref()
            && let Some(cb) = hooks.on_connection_rejected.as_ref()
        {
            cb();
        }
        // Mirror the gauge inc that fired at session start so the
        // tenant-quota rejection arm does not leak a count.
        #[cfg(feature = "metrics")]
        crate::metrics::active_connections().dec();
        return;
    }
    if let Some(hooks) = session_hooks.as_ref()
        && let Some(cb) = hooks.on_connection_accept.as_ref()
    {
        cb();
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
            r = ws_read_loop(ws_read, &identity, &router, nats_publish.as_ref(), fed_forward.as_ref(), http_forward.as_ref(), &throttle, &replay_filter, &mut ws_rate_limiter, read_last_pong, sa_upgrade_observer.as_ref()) => r,
            r = ws_write_loop(ws_write, &mut priority_rx, &mut normal_rx, &*codec, max_write_buffer_bytes, health_check, Arc::clone(&last_pong)) => r,
        }
    };

    if let Err(ref e) = read_result {
        debug!(cn = %hash_cn(&cn), error = %e, "WebSocket session ended with error");
    }

    router.unregister(&cn, session_id).await;
    #[cfg(feature = "metrics")]
    crate::metrics::active_connections().dec();

    info!(
        transport = TRANSPORT_LABEL,
        peer_addr = %peer_addr,
        cn = %hash_cn(&cn),
        "WebSocket session ended"
    );
}

// justification: half of the `handle_ws_session` fan-in plus the rate
// limiter state that only the read path mutates. Called from exactly one
// place; extracting a struct would force the session handler to hold a
// redundant copy of references it already has in scope.
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
    sa_upgrade_observer: Option<&rustgate_cot::OnSaAutoUpgraded>,
) -> Result<(), String> {
    // Closes #741. The SA auto-upgrade observer is wired here so
    // legacy `<event version=…>` payloads received over WebSocket
    // feed the same `rustgate_sa_auto_upgraded_total{from_version}`
    // counter as the TLS and UDP listeners.
    let mut msg_builder = match sa_upgrade_observer {
        Some(cb) => MessageBuilder::new().with_on_sa_upgraded(Arc::clone(cb)),
        None => MessageBuilder::new(),
    };

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

        // Inbound data-frame counter (issue #771). Records text and
        // binary frames only; control frames (Ping/Pong/Close) are
        // not observable at the application layer.
        #[cfg(feature = "metrics")]
        crate::metrics::messages_total()
            .with_label_values(&["in"])
            .inc();

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
// justification: single-call dispatch entrypoint from the accept-path in
// `handle_websocket_session`; bundling the seven fields into a struct would
// shift the fan-in upstream without reducing live references at the only
// call site and hurt readability of the select-loop body below.
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

        // tungstenite's `Message::Binary` carries `Bytes`; pass the codec
        // output through directly — `encoded.to_vec().into()` would copy
        // every outbound frame on the WebSocket fan-out hot path.
        let frame = Message::Binary(encoded);

        match tokio::time::timeout(WRITE_TIMEOUT, ws_write.send(frame)).await {
            Ok(Ok(())) => {
                // Successful send: the frame has been flushed to the
                // underlying transport, so reset the pending counter.
                pending_bytes = 0;
                // Outbound data-frame counter (issue #771). Counted
                // post-flush so failed writes do not contribute.
                #[cfg(feature = "metrics")]
                crate::metrics::messages_total()
                    .with_label_values(&["out"])
                    .inc();
            }
            Ok(Err(e)) => return Err(format!("WebSocket write error: {e}")),
            Err(_) => return Err("write timeout (slow consumer)".into()),
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use rustgate_core::codec::Codec;
    use rustgate_core::message::RoutableMessage;
    use rustgate_test_utils::certs::TestCa;
    use rustgate_transport::{Router, TlsConfig};
    use tokio::sync::{Notify, Semaphore};

    use super::*;
    use crate::WsListener;
    use crate::health::HealthCheckConfig;

    // ------------------------------------------------------------------
    // These tests exercise the lifecycle surface of `WebSocketServer::run`
    // and the type-alias / Debug / Default contracts of the surrounding
    // configuration types. The integration suite under `tests/ws_server.rs`
    // (12 tests) already covers the full handshake + upgrade + framing
    // path end-to-end, so here we pin the bits that integration coverage
    // cannot see without spinning up a full TLS + upgrade + mTLS stack:
    // Debug derives, callback trait bounds, shutdown responsiveness of
    // the accept loop, and the pure async helper `tick_or_never`.
    // ------------------------------------------------------------------

    /// Build a server-side `TlsConfig` using a throw-away test CA.
    fn test_tls_config(label: &str) -> TlsConfig {
        let ca = TestCa::new(label);
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
            .expect("build TlsConfig from freshly issued test certs")
    }

    fn loopback_zero() -> SocketAddr {
        "127.0.0.1:0"
            .parse()
            .expect("static loopback address must parse")
    }

    /// Minimal stub codec that is only ever asked for its `protocol_id`
    /// during Debug rendering and never exercised on the wire. A full
    /// `LengthPrefixedCodec` would drag `rustgate-transport`'s codec
    /// stack into these tests without paying for its weight.
    #[derive(Debug)]
    struct NoopCodec;

    impl Codec for NoopCodec {
        fn protocol_id(&self) -> &'static str {
            "noop-test"
        }
        fn framing(&self) -> rustgate_core::protocol::FramingStrategy {
            rustgate_core::protocol::FramingStrategy::LineDelimited
        }
        fn decode_payload(&self, frame: bytes::BytesMut) -> std::io::Result<bytes::Bytes> {
            Ok(frame.freeze())
        }
        fn encode_payload(&self, msg: &RoutableMessage) -> std::io::Result<bytes::Bytes> {
            Ok(msg.payload.clone())
        }
        fn detect(&self, _prefix: &[u8]) -> f32 {
            0.0
        }
    }

    /// Assemble a `WsServerConfig` bound to a fresh loopback port.
    ///
    /// No clients connect during these tests, so the accept loop parks on
    /// the select. This keeps each test focused on lifecycle semantics
    /// (Debug surface, shutdown responsiveness) rather than handshake
    /// mechanics.
    fn build_config(shutdown: Arc<Notify>, label: &str) -> WsServerConfig {
        let tls = test_tls_config(label);
        let listener = WsListener::bind(loopback_zero(), &tls).expect("bind WsListener");
        WsServerConfig {
            listener,
            router: Arc::new(Router::default()),
            connection_limit: Arc::new(Semaphore::new(1)),
            codec: Arc::new(NoopCodec),
            nats_publish: None,
            fed_forward: None,
            http_forward: None,
            throttle_config: None,
            replay_filter: None,
            circuit_breaker_threshold: 0,
            ws_max_frames_per_sec: 0,
            ws_max_bytes_per_sec: 0,
            ws_max_violations: 0,
            max_write_buffer_bytes: DEFAULT_MAX_WRITE_BUFFER_BYTES,
            health_check: HealthCheckConfig::DISABLED,
            session_hooks: None,
            sa_upgrade_observer: None,
            shutdown,
        }
    }

    // ------------------------------------------------------------------
    // Trait bounds — pin the `Debug` derive on `WebSocketServer` and the
    // operator-observable default buffer cap. A refactor that dropped
    // either would land as a compile error or a silent drift in operator
    // expectations, neither of which integration tests would flag.
    // ------------------------------------------------------------------

    #[test]
    fn server_type_is_debug() {
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<WebSocketServer>();
    }

    #[test]
    fn server_debug_renders_struct_name() {
        assert_eq!(format!("{:?}", WebSocketServer), "WebSocketServer");
    }

    #[test]
    fn default_max_write_buffer_bytes_is_four_mib() {
        // 4 MiB is the documented slow-consumer cap. Changing it affects
        // every WebSocket session's memory accounting; a silent drift
        // would surface only under production load where memory pressure
        // would already be hurting.
        assert_eq!(DEFAULT_MAX_WRITE_BUFFER_BYTES, 4 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_WRITE_BUFFER_BYTES, 4_194_304);
    }

    // ------------------------------------------------------------------
    // Callback type aliases — every cross-thread callback must satisfy
    // `Send + Sync + 'static` so it can be cloned into spawned tasks
    // without re-boxing. Compile-time assertions here mean a refactor
    // that narrowed any bound lands as a failure at this file, not at a
    // transitive call site in `rustgate-server::setup`.
    // ------------------------------------------------------------------

    #[test]
    fn on_nats_publish_type_is_send_sync_arc_fn() {
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnNatsPublish = Arc::new(|_msg: RoutableMessage| {});
        assert_bounds(&cb);
    }

    #[test]
    fn on_federation_forward_type_is_send_sync_arc_fn() {
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnFederationForward =
            Arc::new(|_b: Bytes, _g: Vec<String>, _m: rustgate_core::message::Metadata| {});
        assert_bounds(&cb);
    }

    #[test]
    fn on_http_forward_type_is_send_sync_arc_fn() {
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnHttpForward = Arc::new(|_msg: RoutableMessage| {});
        assert_bounds(&cb);
    }

    #[test]
    fn on_ws_accept_type_is_send_sync_arc_fn() {
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnWsAcceptFn = Arc::new(|| {});
        assert_bounds(&cb);
    }

    #[test]
    fn on_ws_reject_type_is_send_sync_arc_fn() {
        fn assert_bounds<T: Send + Sync + 'static>(_: &T) {}
        let cb: OnWsRejectFn = Arc::new(|| {});
        assert_bounds(&cb);
    }

    // ------------------------------------------------------------------
    // `WsSessionHooks` — pin Default (both callbacks None), manual Debug
    // rendering (so a `tracing::debug!(?config, …)` call site never leaks
    // a raw closure pointer), and Clone sharing (no Arc-in-Arc wrapping).
    // ------------------------------------------------------------------

    #[test]
    fn session_hooks_default_has_no_callbacks_installed() {
        let hooks = WsSessionHooks::default();
        assert!(hooks.on_connection_accept.is_none());
        assert!(hooks.on_connection_rejected.is_none());
    }

    #[test]
    fn session_hooks_debug_renders_bool_sentinels_for_none() {
        let rendered = format!("{:?}", WsSessionHooks::default());
        // The manual Debug impl collapses each callback field to
        // `.is_some()` so the rendered output carries `false` when
        // neither is installed. Pin both tokens so a regression that
        // accidentally printed the raw Option (which would try to render
        // the non-Debug `Arc<dyn Fn>` and fail to compile) is caught.
        assert!(
            rendered.contains("on_connection_accept: false"),
            "expected `on_connection_accept: false` sentinel, got: {rendered}",
        );
        assert!(
            rendered.contains("on_connection_rejected: false"),
            "expected `on_connection_rejected: false` sentinel, got: {rendered}",
        );
    }

    #[test]
    fn session_hooks_debug_renders_true_when_callbacks_installed() {
        let hooks = WsSessionHooks {
            on_connection_accept: Some(Arc::new(|| {})),
            on_connection_rejected: Some(Arc::new(|| {})),
        };
        let rendered = format!("{hooks:?}");
        assert!(rendered.contains("on_connection_accept: true"));
        assert!(rendered.contains("on_connection_rejected: true"));
    }

    #[test]
    fn session_hooks_clone_shares_inner_arc() {
        // `WsSessionHooks` derives `Clone` so the server crate can hand
        // it by value into every session spawn without bumping
        // `Arc`-of-`Arc` indirection. Verify that cloning preserves
        // strong_count sharing rather than creating a new arc.
        let inner: OnWsAcceptFn = Arc::new(|| {});
        let hooks = WsSessionHooks {
            on_connection_accept: Some(Arc::clone(&inner)),
            on_connection_rejected: None,
        };
        let initial = Arc::strong_count(&inner);
        let cloned = hooks.clone();
        assert_eq!(
            Arc::strong_count(&inner),
            initial + 1,
            "cloning hooks must bump the inner Arc's strong count",
        );
        drop(cloned);
        assert_eq!(
            Arc::strong_count(&inner),
            initial,
            "dropping the clone must restore the original strong count",
        );
    }

    // ------------------------------------------------------------------
    // `WsServerConfig::Debug` — operators depend on this rendering in
    // startup log lines. Pin that Debug does not leak the router's inner
    // state (rendered as `<Router>`) or the codec's live trait object
    // (rendered as its `protocol_id`). Either regression would surface
    // as a sudden deluge of noise in operator logs.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn config_debug_redacts_router_and_renders_codec_id() {
        let shutdown = Arc::new(Notify::new());
        let config = build_config(shutdown, "ws-config-debug");
        let rendered = format!("{config:?}");
        assert!(
            rendered.contains("<Router>"),
            "Debug must redact Router inner state, got: {rendered}",
        );
        assert!(
            rendered.contains("noop-test"),
            "Debug must render codec protocol_id, got: {rendered}",
        );
    }

    // ------------------------------------------------------------------
    // `tick_or_never` — pure async helper that parks forever on `None`
    // and ticks on `Some`. The write loop relies on `None` keeping the
    // select-arm disarmed without ever completing. A regression that
    // resolved immediately on `None` would flood the write loop with
    // spurious Ping dispatches.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn tick_or_never_with_none_never_resolves() {
        // Bound the non-resolution check with a short timeout — if
        // the future resolved spuriously, the `expect_err` would fail
        // and the test would flag the regression.
        let result = tokio::time::timeout(Duration::from_millis(50), tick_or_never(None)).await;
        assert!(
            result.is_err(),
            "tick_or_never(None) must never resolve — got: {result:?}",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tick_or_never_with_some_returns_after_interval_elapses() {
        // Use a 1ms interval so the first tick fires immediately (the
        // initial tick from `tokio::time::interval` completes
        // instantly), then the helper resolves. Bound by a 500ms
        // timeout so a regression that never ticked would flag.
        let mut interval = tokio::time::interval(Duration::from_millis(1));
        let _initial = tokio::time::timeout(
            Duration::from_millis(500),
            tick_or_never(Some(&mut interval)),
        )
        .await
        .expect("tick_or_never(Some) must resolve within the timeout");
    }

    // ------------------------------------------------------------------
    // Shutdown responsiveness — the accept loop `tokio::select!`s on
    // `listener.accept()` and `shutdown.notified()`. These tests pin
    // that the shutdown branch wins deterministically when no client is
    // connecting, so operator-initiated SIGTERM translates into a clean
    // drain rather than a hang waiting for an accept that will never
    // arrive.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn run_returns_immediately_when_shutdown_pre_notified() {
        // `tokio::sync::Notify` stores one permit — a `notify_one`
        // before spawn means the first `notified()` poll inside the
        // select completes without ever parking.
        let shutdown = Arc::new(Notify::new());
        shutdown.notify_one();
        let config = build_config(Arc::clone(&shutdown), "ws-server-pre-notified");

        tokio::time::timeout(Duration::from_secs(5), WebSocketServer::run(config))
            .await
            .expect("WebSocketServer::run must exit when shutdown was notified before spawn");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_returns_when_shutdown_fires_after_spawn() {
        let shutdown = Arc::new(Notify::new());
        let config = build_config(Arc::clone(&shutdown), "ws-server-post-notified");

        let handle = tokio::spawn(WebSocketServer::run(config));
        // One yield is enough under current_thread flavour to let the
        // spawned task advance past the setup and park on the select.
        tokio::task::yield_now().await;
        shutdown.notify_one();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run must exit within timeout after shutdown is notified")
            .expect("run task must not panic during shutdown");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_notify_is_observed_by_cloned_external_handle() {
        // Pin the contract that the `Arc<Notify>` handed to
        // `WsServerConfig` is the *same* handle the run loop awaits —
        // cloning before the move must not detach the outside holder.
        // A regression here would break `rustgate-server`'s
        // `stop_subsystem` driver silently.
        let shutdown = Arc::new(Notify::new());
        let external = Arc::clone(&shutdown);
        let config = build_config(shutdown, "ws-server-cloned-notify");

        let handle = tokio::spawn(WebSocketServer::run(config));
        tokio::task::yield_now().await;
        external.notify_one();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("external Arc<Notify> must still trigger shutdown")
            .expect("run task must not panic when notified via the cloned Arc");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_exits_cleanly_with_observers_installed() {
        // Install panicking observers that *must not* fire on a clean
        // shutdown with no inbound clients. A future refactor that
        // accidentally fired the callbacks on the shutdown branch
        // would panic the spawned task.
        let shutdown = Arc::new(Notify::new());
        let tls = test_tls_config("ws-server-observers");
        let listener = WsListener::bind(loopback_zero(), &tls).expect("bind");
        let config = WsServerConfig {
            listener,
            router: Arc::new(Router::default()),
            connection_limit: Arc::new(Semaphore::new(1)),
            codec: Arc::new(NoopCodec),
            nats_publish: None,
            fed_forward: None,
            http_forward: None,
            throttle_config: None,
            replay_filter: None,
            circuit_breaker_threshold: 0,
            ws_max_frames_per_sec: 0,
            ws_max_bytes_per_sec: 0,
            ws_max_violations: 0,
            max_write_buffer_bytes: DEFAULT_MAX_WRITE_BUFFER_BYTES,
            health_check: HealthCheckConfig::DISABLED,
            session_hooks: Some(WsSessionHooks {
                on_connection_accept: Some(Arc::new(|| {
                    panic!("on_connection_accept must not fire on clean shutdown with no clients")
                })),
                on_connection_rejected: Some(Arc::new(|| {
                    panic!("on_connection_rejected must not fire on clean shutdown with no clients")
                })),
            }),
            sa_upgrade_observer: None,
            shutdown: Arc::clone(&shutdown),
        };

        let handle = tokio::spawn(WebSocketServer::run(config));
        tokio::task::yield_now().await;
        shutdown.notify_one();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run must terminate with observers installed")
            .expect("run task must not panic on shutdown with no accept / reject events");
    }

    // ------------------------------------------------------------------
    // Additional defensive-invariant coverage: constants relationship,
    // per-callback-alias end-to-end invocation round-trips, deepened
    // Debug redaction checks, shutdown resilience under hostile config
    // (zero permits, double-notify, enabled health-check), and
    // tick_or_never's Some branch under a microsecond-scale interval.
    // ------------------------------------------------------------------

    #[test]
    fn default_max_write_buffer_bytes_is_less_than_core_max_frame_size() {
        // The slow-consumer cap gates *cumulative* pending bytes across
        // successive sends, but the arithmetic
        // `pending_bytes.saturating_add(frame_len) > max_write_buffer_bytes`
        // means the relationship between the cap and the core-wide
        // frame-size limit determines whether a single max-size frame is
        // admissible at all. The workspace-wide max frame is 16 MiB and
        // the per-session cap is 4 MiB — pin the strict inequality so a
        // refactor that bumped the cap beyond the frame cap (defeating
        // the slow-consumer defence entirely) or dropped it below a
        // plausible tactical payload would trip here rather than at a
        // Grafana outage.
        const {
            assert!(DEFAULT_MAX_WRITE_BUFFER_BYTES < rustgate_core::constants::MAX_FRAME_SIZE);
        }
    }

    #[test]
    fn default_max_write_buffer_bytes_is_inside_sanity_band() {
        // Defensive lower + upper bounds so a typo that e.g. lost a MiB
        // multiplier (dropping to 4 KiB — would refuse every real-world
        // payload) or added an extra zero (40 MiB — would let a runaway
        // producer pin ~40 MiB of per-session buffers on top of the
        // tenant-quota accounting) fails a focused test rather than
        // manifesting as a production outage.
        const {
            assert!(DEFAULT_MAX_WRITE_BUFFER_BYTES >= 1024 * 1024);
        }
        const {
            assert!(DEFAULT_MAX_WRITE_BUFFER_BYTES <= 32 * 1024 * 1024);
        }
    }

    #[test]
    fn on_nats_publish_callback_round_trips_message_through_arc_invocation() {
        // The alias is `Arc<dyn Fn(RoutableMessage) + Send + Sync>` — a
        // regression that accidentally reboxed the closure on every
        // clone, or stripped the `Send + Sync` bound so the clone
        // couldn't cross a spawn, would surface here rather than at a
        // transitive call site. The test captures the arg via a shared
        // `Mutex<Option<_>>` so it works with the `Fn` (not `FnMut`)
        // bound the alias imposes.
        use std::sync::Mutex;
        let captured: Arc<Mutex<Option<Bytes>>> = Arc::new(Mutex::new(None));
        let captured_cb = Arc::clone(&captured);
        let cb: OnNatsPublish = Arc::new(move |msg: RoutableMessage| {
            *captured_cb.lock().expect("mutex not poisoned") = Some(msg.payload.clone());
        });

        let msg = RoutableMessage {
            source: Identity::new(
                "test-cn".to_string(),
                "test-fp".to_string(),
                std::collections::BTreeSet::new(),
            )
            .expect("identity"),
            destination: rustgate_core::message::Destination::Broadcast,
            payload: Bytes::from_static(b"hello"),
            metadata: rustgate_core::message::Metadata {
                received_at: std::time::SystemTime::now(),
                source_protocol: "test".into(),
                message_type: rustgate_core::message::MessageType::Other("test".into()),
                ttl: None,
            },
        };

        let cloned = Arc::clone(&cb);
        cloned(msg);

        assert_eq!(
            captured
                .lock()
                .expect("mutex")
                .as_ref()
                .map(|b| b.as_ref().to_vec()),
            Some(b"hello".to_vec()),
            "Arc-cloned callback must invoke the underlying closure with the supplied message",
        );
    }

    #[test]
    fn on_federation_forward_callback_receives_all_three_args_verbatim() {
        // `OnFederationForward` is a three-argument callback:
        // `(Bytes, Vec<String>, Metadata)`. The read loop splits a
        // `RoutedMessage` into these three pieces before handing them
        // to the forwarder (see `ws_read_loop` at the `fed_forward` call
        // site). Pin that every argument reaches the closure with its
        // identity preserved — a regression that swapped the payload
        // and groups arguments would silently fan every federated send
        // out to the wrong set of peers.
        use std::sync::Mutex;
        #[derive(Default)]
        struct Captured {
            payload: Option<Bytes>,
            groups: Option<Vec<String>>,
            source_protocol: Option<String>,
        }
        let captured: Arc<Mutex<Captured>> = Arc::new(Mutex::new(Captured::default()));
        let captured_cb = Arc::clone(&captured);
        let cb: OnFederationForward = Arc::new(move |b, g, m: rustgate_core::message::Metadata| {
            let mut guard = captured_cb.lock().expect("mutex");
            guard.payload = Some(b);
            guard.groups = Some(g);
            guard.source_protocol = Some(m.source_protocol);
        });

        cb(
            Bytes::from_static(b"payload"),
            vec!["alpha".into(), "beta".into()],
            rustgate_core::message::Metadata {
                received_at: std::time::SystemTime::now(),
                source_protocol: "websocket".into(),
                message_type: rustgate_core::message::MessageType::Other("test".into()),
                ttl: None,
            },
        );

        let guard = captured.lock().expect("mutex");
        assert_eq!(
            guard.payload.as_ref().map(|b| b.as_ref().to_vec()),
            Some(b"payload".to_vec()),
        );
        assert_eq!(
            guard.groups.as_deref(),
            Some(&["alpha".to_string(), "beta".to_string()][..])
        );
        assert_eq!(guard.source_protocol.as_deref(), Some("websocket"));
    }

    #[test]
    fn on_http_forward_callback_round_trips_message_through_arc_invocation() {
        // Same shape as the NATS-publish test but for the HTTP egress
        // alias — they have identical trait bounds (`Fn(RoutableMessage)`)
        // but distinct wire semantics, and the two aliases can drift out
        // of sync without a compile-time check if one caller is
        // refactored without the other.
        use std::sync::Mutex;
        let captured: Arc<Mutex<Option<Bytes>>> = Arc::new(Mutex::new(None));
        let captured_cb = Arc::clone(&captured);
        let cb: OnHttpForward = Arc::new(move |msg: RoutableMessage| {
            *captured_cb.lock().expect("mutex") = Some(msg.payload.clone());
        });

        let msg = RoutableMessage {
            source: Identity::new(
                "http-cn".to_string(),
                "http-fp".to_string(),
                std::collections::BTreeSet::new(),
            )
            .expect("identity"),
            destination: rustgate_core::message::Destination::Broadcast,
            payload: Bytes::from_static(b"http-payload"),
            metadata: rustgate_core::message::Metadata {
                received_at: std::time::SystemTime::now(),
                source_protocol: "test".into(),
                message_type: rustgate_core::message::MessageType::Other("test".into()),
                ttl: None,
            },
        };
        cb(msg);

        assert_eq!(
            captured
                .lock()
                .expect("mutex")
                .as_ref()
                .map(|b| b.as_ref().to_vec()),
            Some(b"http-payload".to_vec()),
        );
    }

    #[test]
    fn on_ws_accept_callback_round_trips_through_arc_invocation() {
        // `OnWsAcceptFn` is the fire-on-session-accepted counter hook.
        // A regression that dropped the Arc-clone semantics (e.g.
        // narrowing the alias to `Box<dyn Fn()>` so it could not be
        // shared with the listener's accept-loop observer) would break
        // the Prometheus counter wiring silently. Pin the two-Arc
        // call-site shape and that both clones invoke the underlying
        // closure.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cb = Arc::clone(&counter);
        let cb: OnWsAcceptFn = Arc::new(move || {
            counter_cb.fetch_add(1, Ordering::SeqCst);
        });

        cb();
        Arc::clone(&cb)();
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn on_ws_reject_callback_round_trips_through_arc_invocation() {
        // Same shape as the accept hook but for the reject counter —
        // listener reject arms (rate limit, TLS failure, upgrade
        // failure) and session-handler reject arms (connection limit,
        // tenant quota) both fire through this alias, so cross-crate
        // call-site symmetry is the contract the alias encodes.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cb = Arc::clone(&counter);
        let cb: OnWsRejectFn = Arc::new(move || {
            counter_cb.fetch_add(1, Ordering::SeqCst);
        });

        cb();
        Arc::clone(&cb)();
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn session_hooks_default_equals_explicit_all_none_literal_init() {
        // The `#[derive(Default)]` on `WsSessionHooks` is declared, but
        // a manual refactor that added a non-None default (e.g. a
        // `NoopCallback` to "avoid branching on None") would silently
        // break the documented "None disables dispatch with no runtime
        // cost" contract. Pin the field-by-field equivalence.
        let via_default = WsSessionHooks::default();
        let via_literal = WsSessionHooks {
            on_connection_accept: None,
            on_connection_rejected: None,
        };
        assert!(via_default.on_connection_accept.is_none());
        assert!(via_default.on_connection_rejected.is_none());
        assert!(via_literal.on_connection_accept.is_none());
        assert!(via_literal.on_connection_rejected.is_none());
    }

    #[test]
    fn session_hooks_debug_asymmetric_when_only_one_callback_installed() {
        // Pin the asymmetric boolean sentinels so a regression that
        // collapsed both fields into a single shared flag (saving one
        // line in the manual Debug impl but silently misreporting the
        // actual configuration to operators) fails here.
        let hooks = WsSessionHooks {
            on_connection_accept: Some(Arc::new(|| {})),
            on_connection_rejected: None,
        };
        let rendered = format!("{hooks:?}");
        assert!(
            rendered.contains("on_connection_accept: true"),
            "expected accept=true, got: {rendered}",
        );
        assert!(
            rendered.contains("on_connection_rejected: false"),
            "expected rejected=false, got: {rendered}",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn config_debug_does_not_leak_closure_or_arc_internals() {
        // The manual `Debug` for `WsServerConfig` only renders
        // `listener`, a redacted `<Router>` token, and the codec's
        // `protocol_id()`. A regression that swapped it back to
        // `#[derive(Debug)]` would splatter every `Arc<dyn Fn>` into
        // the rendered output, which at best pollutes operator logs
        // with function pointers and at worst leaks closure captures.
        // Pin that the rendered string contains none of the canonical
        // derive-printout tokens.
        let shutdown = Arc::new(Notify::new());
        let config = build_config(shutdown, "ws-config-debug-redaction");
        let rendered = format!("{config:?}");

        // The redaction helpers used elsewhere in the workspace render
        // as `<Router>` and the codec id. A raw derive would print
        // `router: Router { .. }` and `codec: Arc<dyn Codec>`-like
        // tokens — pin their absence.
        assert!(
            !rendered.contains("Router {"),
            "Debug must not expose Router internals, got: {rendered}",
        );
        assert!(
            !rendered.contains("dyn Fn"),
            "Debug must not expose raw closure trait objects, got: {rendered}",
        );
        // The callback-bearing fields must not be in the rendered
        // output at all — they are deliberately omitted by the manual
        // impl, not redacted-and-shown.
        assert!(
            !rendered.contains("nats_publish"),
            "Debug must omit optional callback fields, got: {rendered}",
        );
        assert!(
            !rendered.contains("session_hooks"),
            "Debug must omit session_hooks, got: {rendered}",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_exits_on_shutdown_even_with_zero_permit_connection_limit() {
        // A deployment that set `connection_limit` to a zero-permit
        // semaphore (defensive lockdown mode) must still honour
        // SIGTERM — the shutdown branch of the select must not be
        // gated by the permit-acquisition path. Pin that the run loop
        // terminates cleanly even when no client could ever be
        // admitted.
        let shutdown = Arc::new(Notify::new());
        let tls = test_tls_config("ws-server-zero-permits");
        let listener = WsListener::bind(loopback_zero(), &tls).expect("bind");
        let config = WsServerConfig {
            listener,
            router: Arc::new(Router::default()),
            connection_limit: Arc::new(Semaphore::new(0)),
            codec: Arc::new(NoopCodec),
            nats_publish: None,
            fed_forward: None,
            http_forward: None,
            throttle_config: None,
            replay_filter: None,
            circuit_breaker_threshold: 0,
            ws_max_frames_per_sec: 0,
            ws_max_bytes_per_sec: 0,
            ws_max_violations: 0,
            max_write_buffer_bytes: DEFAULT_MAX_WRITE_BUFFER_BYTES,
            health_check: HealthCheckConfig::DISABLED,
            session_hooks: None,
            sa_upgrade_observer: None,
            shutdown: Arc::clone(&shutdown),
        };

        let handle = tokio::spawn(WebSocketServer::run(config));
        tokio::task::yield_now().await;
        shutdown.notify_one();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run must exit under zero-permit lockdown")
            .expect("run task must not panic on shutdown under zero-permit lockdown");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_exits_cleanly_after_repeated_shutdown_notify_calls() {
        // `tokio::sync::Notify::notify_one` on an already-notified
        // handle is a no-op (the permit is already stored), so a
        // caller that fires SIGTERM twice in quick succession (e.g.
        // operator restart script on a flaky TTY) must see the same
        // clean exit as a single-fire. Pin that extra notifications
        // do not stall or mis-order the accept loop.
        let shutdown = Arc::new(Notify::new());
        let config = build_config(Arc::clone(&shutdown), "ws-server-double-notify");
        shutdown.notify_one();
        shutdown.notify_one();
        shutdown.notify_one();

        tokio::time::timeout(Duration::from_secs(5), WebSocketServer::run(config))
            .await
            .expect("run must exit within timeout after three successive notify_one calls");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_exits_cleanly_when_health_check_is_enabled_but_no_clients_connect() {
        // Enabled `HealthCheckConfig` only affects the per-session
        // write loop (ping ticker, pong deadline). The accept-loop
        // shutdown path must be entirely independent of that
        // configuration — a regression that moved the health-check
        // construction out of the session spawn and into the accept
        // select would stall shutdown until the first ping tick. Pin
        // that a 30-second-interval health-check config does not
        // prevent an immediate SIGTERM.
        let shutdown = Arc::new(Notify::new());
        let tls = test_tls_config("ws-server-health-enabled");
        let listener = WsListener::bind(loopback_zero(), &tls).expect("bind");
        let config = WsServerConfig {
            listener,
            router: Arc::new(Router::default()),
            connection_limit: Arc::new(Semaphore::new(1)),
            codec: Arc::new(NoopCodec),
            nats_publish: None,
            fed_forward: None,
            http_forward: None,
            throttle_config: None,
            replay_filter: None,
            circuit_breaker_threshold: 0,
            ws_max_frames_per_sec: 0,
            ws_max_bytes_per_sec: 0,
            ws_max_violations: 0,
            max_write_buffer_bytes: DEFAULT_MAX_WRITE_BUFFER_BYTES,
            health_check: HealthCheckConfig {
                ping_interval: Duration::from_secs(30),
                pong_timeout: Duration::from_secs(10),
            },
            session_hooks: None,
            sa_upgrade_observer: None,
            shutdown: Arc::clone(&shutdown),
        };

        let handle = tokio::spawn(WebSocketServer::run(config));
        tokio::task::yield_now().await;
        shutdown.notify_one();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run must exit cleanly even with health-check enabled (no clients connected)")
            .expect("run task must not panic");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tick_or_never_with_some_resolves_under_microsecond_interval() {
        // Pin that the `Some(Interval)` branch works at the smallest
        // practically-usable cadence. `tokio::time::interval` panics
        // on `Duration::ZERO`, so use `1 µs` as the minimum — this is
        // already below every production ping cadence, but a
        // regression that added a lower-bound guard inside
        // `tick_or_never` would trip here rather than at a surprised
        // downstream operator.
        let mut interval = tokio::time::interval(Duration::from_micros(1));
        tokio::time::timeout(
            Duration::from_millis(500),
            tick_or_never(Some(&mut interval)),
        )
        .await
        .expect("microsecond-cadence tick_or_never must resolve within the timeout");
    }

    #[test]
    fn session_hooks_is_send_sync_clone_default() {
        // Compile-time bound check so any future refactor that
        // weakened the `Send + Sync + Clone + Default` bound set
        // (which the server binary relies on to hand the hooks by
        // value into every session spawn across tokio threads) fails
        // at this file rather than at a transitive call site in
        // `rustgate-server::setup`.
        fn assert_bounds<T: Send + Sync + Clone + Default>() {}
        assert_bounds::<WsSessionHooks>();
    }

    #[test]
    fn write_action_ping_variant_is_constructible_and_parkable() {
        // `WriteAction::Ping` is the unit variant the write loop
        // produces when the ping ticker fires. Pin that the variant
        // is still a zero-payload shape the loop can match — a
        // regression that added a payload (e.g. `Ping(Bytes)`) would
        // break every `WriteAction::Ping =>` arm in the module.
        let action = WriteAction::Ping;
        match action {
            WriteAction::Ping => {}
            // Any non-Ping match here is a compile-time reminder that
            // the enum has grown a new variant and the write loop
            // must be updated to handle it. The `_` arm satisfies
            // exhaustive-match without hiding that outcome.
            _ => panic!("expected WriteAction::Ping unit variant"),
        }
    }
}
