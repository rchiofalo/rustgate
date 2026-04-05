//! WebSocket server with session lifecycle management.
//!
//! Bridges authenticated WebSocket connections into the message [`Router`]
//! as full routing participants. WebSocket and TCP clients are interoperable —
//! same session registration, group enforcement, position cache replay.

use std::sync::Arc;

use bytes::Bytes;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use rustgate_core::codec::Codec;
use rustgate_core::constants::{READ_TIMEOUT, WRITE_TIMEOUT};
use rustgate_core::identity::Identity;
use rustgate_core::message::RoutableMessage;
use rustgate_cot::MessageBuilder;
use rustgate_transport::{ClientThrottle, ReplayFilter, Router, SessionHandle, ThrottleConfig};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::{WsListener, WsSession, WsStream};

/// Bounded channel capacity for outbound messages per session.
const CHANNEL_CAPACITY: usize = 64;

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
pub type OnFederationForward = Arc<dyn Fn(Bytes, Vec<String>) + Send + Sync>;

/// Configuration for the WebSocket server.
pub struct WsServerConfig {
    pub listener: WsListener,
    pub router: Arc<Router>,
    pub connection_limit: Arc<Semaphore>,
    pub codec: Arc<dyn Codec>,
    pub nats_publish: Option<OnNatsPublish>,
    pub fed_forward: Option<OnFederationForward>,
    pub throttle_config: Option<ThrottleConfig>,
    pub replay_filter: Option<Arc<ReplayFilter>>,
    /// Consecutive send failures before the circuit breaker disconnects a session.
    /// Set to 0 to disable.
    pub circuit_breaker_threshold: u32,
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
            throttle_config,
            replay_filter,
            circuit_breaker_threshold,
            shutdown,
        } = config;

        info!(addr = ?listener.local_addr().ok(), "WebSocket server started");

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok(session) => {
                            let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!("connection limit reached, rejecting WebSocket client");
                                    continue;
                                }
                            };

                            let router = Arc::clone(&router);
                            let session_codec = Arc::clone(&codec);
                            let nats = nats_publish.clone();
                            let fed = fed_forward.clone();
                            let tc = throttle_config;
                            let rf = replay_filter.clone();

                            let cb = circuit_breaker_threshold;
                            drop(tokio::spawn(handle_ws_session(
                                session, router, session_codec, nats, fed, tc, rf, cb, permit,
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
    throttle_config: Option<ThrottleConfig>,
    replay_filter: Option<Arc<ReplayFilter>>,
    circuit_breaker_threshold: u32,
    _permit: OwnedSemaphorePermit,
) {
    let identity = session.identity_arc();
    let peer_addr = session.peer_addr();
    let cn = identity.cn.clone();

    info!(
        peer_addr = %peer_addr,
        cn = %cn,
        groups = ?identity.groups,
        "WebSocket session started"
    );

    let (tx, mut rx) = mpsc::channel::<Arc<RoutableMessage>>(CHANNEL_CAPACITY);
    let handle = if circuit_breaker_threshold > 0 {
        SessionHandle::with_drop_threshold(Arc::clone(&identity), tx, circuit_breaker_threshold)
    } else {
        SessionHandle::with_drop_threshold(Arc::clone(&identity), tx, u32::MAX)
    };
    let session_id = handle.id;

    router.register(handle.clone()).await;
    router.replay_positions(&handle).await;

    let ws_stream = session.into_stream();
    let (ws_write, ws_read) = ws_stream.split();

    let throttle = throttle_config.map(|tc| tc.build());

    let read_result = {
        let router = Arc::clone(&router);
        tokio::select! {
            r = ws_read_loop(ws_read, &identity, &router, nats_publish.as_ref(), fed_forward.as_ref(), &throttle, &replay_filter) => r,
            r = ws_write_loop(ws_write, &mut rx, &*codec) => r,
        }
    };

    if let Err(ref e) = read_result {
        debug!(cn = %cn, error = %e, "WebSocket session ended with error");
    }

    router.unregister(&cn, session_id).await;

    info!(
        peer_addr = %peer_addr,
        cn = %cn,
        "WebSocket session ended"
    );
}

async fn ws_read_loop(
    mut ws_read: SplitStream<WsStream>,
    identity: &Identity,
    router: &Router,
    nats_publish: Option<&OnNatsPublish>,
    fed_forward: Option<&OnFederationForward>,
    throttle: &Option<ClientThrottle>,
    replay_filter: &Option<Arc<ReplayFilter>>,
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
            _ => continue, // Ping/Pong handled by tungstenite
        };

        // Per-client rate limiting — drop excess messages
        if let Some(t) = throttle
            && !t.allow()
        {
            warn!(cn = %identity.cn, "message dropped: rate limit exceeded");
            continue;
        }

        // Anti-replay: drop messages with duplicate (uid, time) within the window
        if let Some(filter) = replay_filter
            && filter.is_replay(&payload)
        {
            debug!(cn = %identity.cn, "message dropped: replay detected");
            continue;
        }

        let msg = msg_builder.build(identity, payload, "websocket");

        router.route(msg.clone()).await;

        if let Some(cb) = nats_publish {
            cb(msg.clone());
        }
        if let Some(fwd) = fed_forward {
            let groups: Vec<String> = msg.source.groups.iter().cloned().collect();
            fwd(msg.payload.clone(), groups);
        }
    }
}

async fn ws_write_loop(
    mut ws_write: SplitSink<WsStream, Message>,
    rx: &mut mpsc::Receiver<Arc<RoutableMessage>>,
    codec: &dyn Codec,
) -> Result<(), String> {
    while let Some(msg) = rx.recv().await {
        let encoded = match codec.encode_payload(&msg) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(error = %e, "failed to encode outbound message");
                continue;
            }
        };

        let frame = Message::Binary(encoded.to_vec().into());

        match tokio::time::timeout(WRITE_TIMEOUT, ws_write.send(frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("WebSocket write error: {e}")),
            Err(_) => return Err("write timeout (slow consumer)".into()),
        }
    }

    Ok(())
}
