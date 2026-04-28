// Copyright © 2026 Roberto Chiofalo.

//! WebSocket (wss://) listener and session management for rustgate.
//!
//! Provides [`WsListener`] for accepting WebSocket connections over TLS,
//! [`WsSession`] representing an authenticated client, and [`WebSocketServer`]
//! for managing the accept loop and session lifecycle with router integration.
//!
//! All connections require a valid client certificate; identity is extracted
//! exclusively from the X.509 certificate, never from headers or query params.
//!
//! # Error handling
//!
//! This crate uses [`rustgate_core::error::Result`] (i.e.
//! [`rustgate_core::error::RustgateError`]) directly — listener bring-up
//! and identity-extraction failures surface as
//! [`rustgate_core::error::TransportError`] variants. There is no
//! crate-local error enum; binary callers in `rustgate-server` propagate
//! these via `?` and surface them through `anyhow::Error` at the
//! orchestration layer.

pub mod compression;
pub mod health;
mod rate_limit;
mod server;

pub use compression::{
    CompressionConfig, Deflater, Inflater, NegotiatedExtension, PermessageDeflateConfig,
};

/// Canonical value of the `transport` structured-log field emitted by every
/// session-lifecycle event in this crate.
///
/// Exposed as a named constant (not a magic string) so downstream consumers
/// grep for the exact token their log aggregator is configured against, and
/// so a future rename surfaces as a single-point diff rather than a silent
/// dashboard regression.
pub const TRANSPORT_LABEL: &str = "websocket";

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustgate_core::constants::HANDSHAKE_TIMEOUT;
use rustgate_core::error::{Result, TransportError};
use rustgate_core::identity::Identity;
use rustgate_core::masking::hash_cn;
use rustgate_core::net::configure_tactical_socket;
use rustgate_resilience::SlidingWindowLimiter;
use rustgate_transport::{TlsConfig, extract_identity};
pub use server::{
    DEFAULT_MAX_WRITE_BUFFER_BYTES, OnFederationForward, OnHttpForward, OnNatsPublish,
    OnWsAcceptFn, OnWsRejectFn, WebSocketServer, WsServerConfig, WsSessionHooks,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, header};
use tracing::{debug, warn};

/// Server-side TLS stream over TCP.
type TlsStream = tokio_rustls::server::TlsStream<TcpStream>;

/// A WebSocket stream layered on top of a TLS connection.
pub type WsStream = WebSocketStream<TlsStream>;

/// An authenticated WebSocket session.
///
/// Created by [`WsListener::accept`] after successful mTLS authentication and
/// WebSocket upgrade. Identity is derived from the client certificate.
pub struct WsSession {
    identity: Arc<Identity>,
    stream: WsStream,
    peer_addr: SocketAddr,
    /// The subprotocol negotiated during the WebSocket handshake, if any.
    ///
    /// Set when both (a) the server was configured with a non-empty
    /// [`WsListenerConfig::supported_subprotocols`] list, and (b) the client's
    /// `Sec-WebSocket-Protocol` offer intersected that list. The chosen
    /// protocol is the first server-preferred entry that also appears in the
    /// client's offer — consistent with RFC 6455 §4.2.2, which gives the
    /// server final say. `None` means no subprotocol was negotiated; the
    /// session is still valid and MUST be treated as the default (unnamed)
    /// application protocol.
    negotiated_subprotocol: Option<String>,
    /// Outcome of the RFC 7692 `permessage-deflate` extension negotiation.
    ///
    /// Set when both (a) the server's [`WsListenerConfig::compression`] is
    /// [`CompressionConfig::Enabled`] and (b) the client's offer fit the
    /// configured envelope. `None` means compression was not negotiated
    /// (operator opted out, client did not offer, or no offer fit the
    /// envelope). Downstream metrics code can branch on this for
    /// per-session compression telemetry. The negotiation surface ships
    /// today; per-frame wire compression is gated on a future
    /// tokio-tungstenite release exposing the upstream `deflate` feature
    /// — see the `compression` module docs for details.
    negotiated_compression: Option<NegotiatedExtension>,
}

impl WsSession {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn identity_arc(&self) -> Arc<Identity> {
        Arc::clone(&self.identity)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// The subprotocol token selected by the server during the WebSocket
    /// handshake, or `None` if no subprotocol was negotiated.
    ///
    /// See [`WsSession::negotiated_subprotocol`](Self) field docs for the
    /// exact selection semantics.
    pub fn negotiated_subprotocol(&self) -> Option<&str> {
        self.negotiated_subprotocol.as_deref()
    }

    /// The outcome of the RFC 7692 `permessage-deflate` negotiation, or
    /// `None` if compression was not negotiated for this session.
    ///
    /// See [`WsSession::negotiated_compression`](Self) field docs for the
    /// exact semantics, including the current wire-level limitation.
    pub fn negotiated_compression(&self) -> Option<&NegotiatedExtension> {
        self.negotiated_compression.as_ref()
    }

    pub fn into_stream(self) -> WsStream {
        self.stream
    }

    pub fn into_parts(self) -> (Arc<Identity>, WsStream, SocketAddr) {
        (self.identity, self.stream, self.peer_addr)
    }
}

impl std::fmt::Debug for WsSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsSession")
            .field("identity", &self.identity)
            .field("peer_addr", &self.peer_addr)
            .field("stream", &"<WebSocketStream>")
            .field("negotiated_subprotocol", &self.negotiated_subprotocol)
            .field("negotiated_compression", &self.negotiated_compression)
            .finish()
    }
}

/// Default maximum connection attempts per IP within the rate limit window.
pub const DEFAULT_CONN_RATE_LIMIT: usize = 10;

/// Default sliding window duration for connection rate limiting.
pub const DEFAULT_CONN_RATE_WINDOW: Duration = Duration::from_secs(10);

/// Default maximum WebSocket frame size: 16 MiB.
pub const DEFAULT_MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Default maximum WebSocket message size: 64 MiB.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

/// WebSocket listener with mandatory mTLS.
///
/// Mirrors [`TlsListener`](rustgate_transport::TlsListener) but adds the
/// WebSocket upgrade handshake after TLS completes. The accept loop handles
/// TCP, TLS, identity extraction, and WS upgrade — callers receive a fully
/// authenticated [`WsSession`] ready for message exchange.
///
/// Includes per-IP connection rate limiting to mitigate slow-handshake DoS
/// attacks where an adversary repeatedly initiates and abandons TLS handshakes.
///
/// **NAT/proxy caveat:** rate limiting uses the raw TCP peer address. Behind
/// NAT or a load balancer, all clients sharing one egress IP are rate-limited
/// together, and an attacker with multiple IPs bypasses the limit entirely.
/// See the threat model (D8) for deployment guidance.
pub struct WsListener {
    tcp: TcpListener,
    tls: TlsAcceptor,
    conn_rate: SlidingWindowLimiter,
    max_frame_size: usize,
    max_message_size: usize,
    /// Ordered list of WebSocket subprotocol tokens the server advertises.
    /// When empty (the default), subprotocol negotiation is disabled and the
    /// handshake proceeds without a `Sec-WebSocket-Protocol` response header,
    /// matching historical behaviour. When non-empty, the first entry that
    /// also appears in the client's `Sec-WebSocket-Protocol` offer is
    /// selected, per RFC 6455 §4.2.2. Stored as `Arc<[String]>` so each
    /// handshake callback closure only clones an `Arc`, not the vec contents.
    supported_subprotocols: Arc<[String]>,
    /// When `true`, a client that offered a `Sec-WebSocket-Protocol` set
    /// disjoint from [`Self::supported_subprotocols`] is rejected with a
    /// 400 Bad Request. When `false` (the default), the upgrade still
    /// completes — the response simply omits the
    /// `Sec-WebSocket-Protocol` header. The lenient default favours
    /// interop with TAK/tactical clients that probe many subprotocols and
    /// fall back to native framing on no-match. Strict mode is the right
    /// choice for deployments with a single well-known client family.
    subprotocol_strict: bool,
    /// `permessage-deflate` (RFC 7692) negotiation envelope. See
    /// [`CompressionConfig`] for semantics. Stored as a plain owned
    /// value, not `Arc<…>`, because the type is small (one bool tuple +
    /// `u8`) and cloning per handshake is cheaper than the `Arc`
    /// indirection on the hot path.
    compression: CompressionConfig,
    on_connection_rejected: Option<OnWsRejectFn>,
}

impl std::fmt::Debug for WsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsListener")
            .field("tcp", &self.tcp)
            .field("tls", &"<TlsAcceptor>")
            .field("conn_rate", &self.conn_rate)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_message_size", &self.max_message_size)
            .field("supported_subprotocols", &self.supported_subprotocols)
            .field("subprotocol_strict", &self.subprotocol_strict)
            .field("compression", &self.compression)
            .field(
                "on_connection_rejected",
                &self.on_connection_rejected.is_some(),
            )
            .finish()
    }
}

/// Configuration for constructing a [`WsListener`].
pub struct WsListenerConfig {
    /// Maximum connection attempts per IP within the rate limit window.
    pub conn_rate_limit: usize,
    /// Sliding window duration for connection rate limiting.
    pub conn_rate_window: Duration,
    /// Maximum WebSocket frame size in bytes.
    pub max_frame_size: usize,
    /// Maximum WebSocket message size in bytes.
    pub max_message_size: usize,
    /// Ordered list of WebSocket subprotocol tokens the server advertises, in
    /// server-preference order. Empty (the default) disables negotiation and
    /// preserves historical behaviour — the handshake succeeds but no
    /// `Sec-WebSocket-Protocol` header is emitted in the response.
    ///
    /// When non-empty, the handshake callback walks the client's offered
    /// tokens in client order and picks the first one that matches any
    /// server entry (case-sensitive, whitespace-trimmed per RFC 6455 §4.1
    /// /ABNF rules). If no client token matches any server entry, behaviour
    /// depends on [`Self::subprotocol_strict`]: lenient (the default) lets
    /// the upgrade complete with no `Sec-WebSocket-Protocol` header, strict
    /// rejects with 400.
    pub supported_subprotocols: Vec<String>,
    /// Whether to reject (`true`) or silently accept (`false`) a client
    /// whose `Sec-WebSocket-Protocol` offer is disjoint from
    /// [`Self::supported_subprotocols`]. Defaults to `false` (lenient) — most
    /// tactical clients probe several subprotocols and fall back to a
    /// native non-subprotocol framing on no-match, so a strict 400 there
    /// regresses interop. Operators running a homogeneous client fleet can
    /// flip this on for stricter handshake hygiene.
    pub subprotocol_strict: bool,
    /// `permessage-deflate` (RFC 7692) compression negotiation envelope.
    /// Defaults to [`CompressionConfig::default`] which enables negotiation
    /// at the RFC 7692 maxima — see [`CompressionConfig`] field docs and
    /// the `compression` module-level docs for the rationale (mTLS already
    /// kills CRIME-style attacks; the operator gets a kill-switch via
    /// [`CompressionConfig::Disabled`] regardless).
    pub compression: CompressionConfig,
    /// Fired on every connection rejected inside the accept loop (per-IP
    /// rate limit, TLS handshake failure, identity extraction failure,
    /// upgrade handshake failure). Typically cloned from
    /// [`WsSessionHooks::on_connection_rejected`] so both the accept-loop
    /// rejects and the post-accept rejects in the session handler increment
    /// the same counter.
    pub on_connection_rejected: Option<OnWsRejectFn>,
}

impl std::fmt::Debug for WsListenerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsListenerConfig")
            .field("conn_rate_limit", &self.conn_rate_limit)
            .field("conn_rate_window", &self.conn_rate_window)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_message_size", &self.max_message_size)
            .field("supported_subprotocols", &self.supported_subprotocols)
            .field("subprotocol_strict", &self.subprotocol_strict)
            .field("compression", &self.compression)
            .field(
                "on_connection_rejected",
                &self.on_connection_rejected.is_some(),
            )
            .finish()
    }
}

impl Default for WsListenerConfig {
    fn default() -> Self {
        Self {
            conn_rate_limit: DEFAULT_CONN_RATE_LIMIT,
            conn_rate_window: DEFAULT_CONN_RATE_WINDOW,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            supported_subprotocols: Vec::new(),
            subprotocol_strict: false,
            compression: CompressionConfig::default(),
            on_connection_rejected: None,
        }
    }
}

impl WsListener {
    /// Bind to the given address with SO_REUSEADDR for clean restarts.
    pub fn bind(addr: SocketAddr, tls_config: &TlsConfig) -> Result<Self> {
        Self::bind_with_config(addr, tls_config, WsListenerConfig::default())
    }

    /// Bind to the given address with custom protocol limits.
    pub fn bind_with_config(
        addr: SocketAddr,
        tls_config: &TlsConfig,
        config: WsListenerConfig,
    ) -> Result<Self> {
        let server_config = tls_config.build_server_config()?;
        let tls = TlsAcceptor::from(Arc::new(server_config));

        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .map_err(|e| TransportError::Other(format!("failed to create socket: {e}")))?;

        socket
            .set_reuse_address(true)
            .map_err(|e| TransportError::Other(format!("failed to set SO_REUSEADDR: {e}")))?;

        socket
            .bind(&addr.into())
            .map_err(|e| TransportError::Bind {
                addr: addr.to_string(),
                source: e,
            })?;

        socket
            .listen(128)
            .map_err(|e| TransportError::Other(format!("failed to listen on {addr}: {e}")))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| TransportError::Other(format!("failed to set nonblocking: {e}")))?;

        let tcp = TcpListener::from_std(socket.into())
            .map_err(|e| TransportError::Other(format!("failed to create TcpListener: {e}")))?;

        debug!(local_addr = ?tcp.local_addr().ok(), "WebSocket listener bound");

        Ok(Self {
            tcp,
            tls,
            conn_rate: SlidingWindowLimiter::new(
                config.conn_rate_limit,
                config.conn_rate_window,
                "connection",
            )
            .with_ipv6_64_collapse(true),
            max_frame_size: config.max_frame_size,
            max_message_size: config.max_message_size,
            supported_subprotocols: config.supported_subprotocols.into(),
            subprotocol_strict: config.subprotocol_strict,
            compression: config.compression,
            on_connection_rejected: config.on_connection_rejected,
        })
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.tcp
            .local_addr()
            .map_err(|e| TransportError::Other(format!("failed to get local address: {e}")).into())
    }

    #[inline]
    fn fire_rejected(&self) {
        if let Some(cb) = self.on_connection_rejected.as_ref() {
            cb();
        }
    }

    /// Accept a new WebSocket connection with mTLS authentication.
    ///
    /// Loops internally on TCP, TLS, and WebSocket handshake failures.
    /// Returns only when a fully authenticated session is ready, or
    /// when identity extraction fails (which is a configuration error).
    ///
    /// Connections are subject to per-IP rate limiting before the TLS
    /// handshake to mitigate slow-handshake denial-of-service attacks.
    // justification: the handshake callback returns
    // `Result<Response, Response<Option<String>>>` — a shape dictated by
    // tungstenite's `Callback` trait, whose `Err` variant is a full HTTP
    // response (~136 bytes). We cannot box or shrink it without breaking
    // the trait-required signature, and the callback fires once per
    // handshake, so the occasional stack-copy cost is irrelevant.
    #[allow(clippy::result_large_err)]
    pub async fn accept(&self) -> Result<WsSession> {
        loop {
            let (tcp_stream, peer_addr) = match self.tcp.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "TCP accept failed");
                    self.fire_rejected();
                    continue;
                }
            };

            // Per-IP connection rate limiting to mitigate slow-handshake DoS.
            if self.conn_rate.is_limited(peer_addr.ip()) {
                warn!(
                    peer_addr = %peer_addr,
                    "connection rejected: rate limit exceeded for IP"
                );
                drop(tcp_stream);
                self.fire_rejected();
                continue;
            }

            configure_tactical_socket(&tcp_stream);
            debug!(peer_addr = %peer_addr, "TCP connection accepted");

            let tls_stream = match self.tls.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(peer_addr = %peer_addr, error = %e, "TLS handshake failed");
                    self.fire_rejected();
                    continue;
                }
            };

            let kx_group = tls_stream
                .get_ref()
                .1
                .negotiated_key_exchange_group()
                .map(|g| g.name());
            debug!(peer_addr = %peer_addr, kx_group = ?kx_group, "TLS handshake completed");

            let identity = match extract_client_identity(&tls_stream) {
                Ok(id) => id,
                Err(e) => {
                    warn!(peer_addr = %peer_addr, error = %e, "identity extraction failed");
                    self.fire_rejected();
                    continue;
                }
            };

            debug!(
                peer_addr = %peer_addr,
                cn = %hash_cn(&identity.cn),
                groups = ?identity.groups,
                "client authenticated"
            );

            let mut ws_config =
                tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
            ws_config.max_frame_size = Some(self.max_frame_size);
            ws_config.max_message_size = Some(self.max_message_size);

            // Capture the subprotocol and compression-extension outcomes
            // inside the handshake callback. The tungstenite `Callback`
            // trait is `FnOnce(Request, Response) -> Result<Response,
            // ErrorResponse>`, so the callback's return value stays
            // header-shaped; we thread the selected values back
            // out-of-band through shared
            // `Arc<parking_lot::Mutex<Option<…>>>` slots. Both the closure
            // and the post-handshake reader live on the same task — the
            // mutexes are never contended, just syntactically required.
            let selected_subprotocol = Arc::new(parking_lot::Mutex::new(None::<String>));
            let selected_subprotocol_cb = Arc::clone(&selected_subprotocol);
            let selected_compression =
                Arc::new(parking_lot::Mutex::new(None::<NegotiatedExtension>));
            let selected_compression_cb = Arc::clone(&selected_compression);
            let server_protocols = Arc::clone(&self.supported_subprotocols);
            let subprotocol_strict = self.subprotocol_strict;
            let compression_cfg = self.compression.clone();

            let ws_stream = match tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                tokio_tungstenite::accept_hdr_async_with_config(
                    tls_stream,
                    move |req: &Request, mut resp: Response| {
                        // 1) Subprotocol — RFC 6455 §4.2.2.
                        match negotiate_subprotocol(&server_protocols, req.headers()) {
                            NegotiationOutcome::Selected(picked) => {
                                if let Ok(hv) = HeaderValue::from_str(&picked) {
                                    let _ = resp
                                        .headers_mut()
                                        .insert(header::SEC_WEBSOCKET_PROTOCOL, hv);
                                }
                                *selected_subprotocol_cb.lock() = Some(picked);
                            }
                            NegotiationOutcome::NoProtocolRequired => {
                                // No header echoed; session has no
                                // negotiated subprotocol. Lenient and
                                // strict modes converge here.
                            }
                            NegotiationOutcome::Unsupported => {
                                if subprotocol_strict {
                                    // Operator opted into strict mode:
                                    // a disjoint client offer is a fatal
                                    // 400. Real homogeneous-fleet
                                    // deployments use this so a config
                                    // drift surfaces in server logs
                                    // instead of as opaque client-side
                                    // protocol errors.
                                    let body = "no advertised subprotocol matches server support";
                                    let err_resp = build_400(body)?;
                                    return Err(err_resp);
                                }
                                // Lenient (the default): the upgrade
                                // proceeds with no
                                // `Sec-WebSocket-Protocol` header — TAK
                                // and similar tactical clients probe
                                // several subprotocols and fall back to
                                // a native non-subprotocol framing on
                                // no-match, so a hard 400 here would
                                // regress interop.
                            }
                        }

                        // 2) `permessage-deflate` — RFC 7692 §5.
                        if let Some(ext) =
                            compression::negotiate_extension(&compression_cfg, req.headers())
                        {
                            if let Ok(hv) = HeaderValue::from_str(&ext.response_header_value) {
                                let _ = resp
                                    .headers_mut()
                                    .insert(header::SEC_WEBSOCKET_EXTENSIONS, hv);
                            }
                            *selected_compression_cb.lock() = Some(ext);
                        }

                        Ok(resp)
                    },
                    Some(ws_config),
                ),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    warn!(peer_addr = %peer_addr, error = %e, "WebSocket upgrade failed");
                    self.fire_rejected();
                    continue;
                }
                Err(_) => {
                    warn!(peer_addr = %peer_addr, "WebSocket upgrade timed out");
                    self.fire_rejected();
                    continue;
                }
            };

            let negotiated_subprotocol = selected_subprotocol.lock().take();
            let negotiated_compression = selected_compression.lock().take();

            debug!(
                peer_addr = %peer_addr,
                cn = %hash_cn(&identity.cn),
                subprotocol = ?negotiated_subprotocol,
                compression_negotiated = negotiated_compression.is_some(),
                "WebSocket session established"
            );

            return Ok(WsSession {
                identity: Arc::new(identity),
                stream: ws_stream,
                peer_addr,
                negotiated_subprotocol,
                negotiated_compression,
            });
        }
    }
}

/// Build a 400 Bad Request response for the tungstenite handshake callback.
/// Factored out so the strict-subprotocol path stays readable; future
/// strict checks (e.g. forbidden extensions) reuse the same helper.
///
/// The fallback path constructs a 500 if response building somehow fails;
/// `tungstenite::http::Response::builder()` only returns errors on
/// invalid header construction, which `Response::builder().status(400)
/// .body(Some(_))` cannot trigger — but we keep the fallback so a future
/// regression of the builder's invariants does not crash the accept loop.
// justification: the tungstenite `Callback` trait dictates the
// `Result<Response, Response<Option<String>>>` shape — we cannot box or
// shrink it without breaking the trait-required signature.
#[allow(clippy::result_large_err)]
fn build_400(
    body: &str,
) -> std::result::Result<
    tokio_tungstenite::tungstenite::http::Response<Option<String>>,
    tokio_tungstenite::tungstenite::http::Response<Option<String>>,
> {
    use tokio_tungstenite::tungstenite::http::{Response, StatusCode};

    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Some(body.to_string()))
        .map_err(|e| {
            // The inner builder is given a known-valid status code and a
            // string body, so the builder cannot fail here. If
            // tungstenite's HTTP type ever evolves a way for this to break,
            // we want the error surfaced — but today this `expect` is
            // unreachable on every supported tungstenite minor version.
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Some(format!("error building 400 response: {e}")))
                .expect("500 fallback always builds")
        })
}

/// Outcome of the `Sec-WebSocket-Protocol` negotiation step. Three cases,
/// not two, because the accept loop needs to distinguish "skip the header"
/// from "reject the handshake":
#[derive(Debug, PartialEq, Eq)]
enum NegotiationOutcome {
    /// Server and client agreed on `String`. The server echoes it in the
    /// response header and the session records it for downstream code.
    Selected(String),
    /// No negotiation is required. Either the server is not configured with
    /// any subprotocols (the historical default — pre-#884 behaviour) or
    /// the client did not offer any. The handshake completes with no
    /// `Sec-WebSocket-Protocol` response header and the session's
    /// `negotiated_subprotocol()` returns `None`.
    NoProtocolRequired,
    /// The server advertises a non-empty list, the client offered at least
    /// one entry, and the intersection is empty. The handshake is rejected
    /// with a 400 response — real clients (browsers, Python `websockets`,
    /// Go `nhooyr/websocket`, tungstenite's own client) treat "I asked, you
    /// didn't pick" as a fatal error anyway, so rejecting explicitly surfaces
    /// the mismatch cleanly in server logs instead of leaving it as an
    /// opaque client-side protocol error.
    Unsupported,
}

/// Decide which `Sec-WebSocket-Protocol` outcome applies to this request.
///
/// Walks the client's offered tokens in *client* order and returns the first
/// token that also appears (case-sensitive) in the server's configured list.
/// The "client-preference" scan is the prevailing pattern across `ws` /
/// Node / Python `websockets` / Jetty — TAK and observability tooling expect
/// it — and keeps the server's advertised order as a *filter* rather than a
/// strict ranking.
///
/// Case sensitivity: RFC 6455 defines these tokens as ABNF `token` values,
/// which per RFC 7230 are case-sensitive. We do not lowercase-fold — a
/// client asking for `TAK` and a server advertising `tak` do not match,
/// intentionally.
fn negotiate_subprotocol(
    server_protocols: &[String],
    headers: &tokio_tungstenite::tungstenite::http::HeaderMap,
) -> NegotiationOutcome {
    if server_protocols.is_empty() {
        // Server opted out of negotiation. Historical default. Even if the
        // client asked, we do not and cannot know what to pick — stay silent.
        return NegotiationOutcome::NoProtocolRequired;
    }
    // `Sec-WebSocket-Protocol` may appear as multiple headers *or* as one
    // comma-separated value (RFC 7230 §3.2.2). Flatten both.
    let mut client_tokens: Vec<&str> = Vec::new();
    for hv in headers.get_all(header::SEC_WEBSOCKET_PROTOCOL).iter() {
        let Ok(s) = hv.to_str() else { continue };
        for tok in s.split(',') {
            let trimmed = tok.trim();
            if !trimmed.is_empty() {
                client_tokens.push(trimmed);
            }
        }
    }
    if client_tokens.is_empty() {
        // Server advertises a list but the client is indifferent. RFC allows
        // this — continue with no negotiated protocol, same as the empty-
        // server case.
        return NegotiationOutcome::NoProtocolRequired;
    }
    for tok in &client_tokens {
        if server_protocols.iter().any(|p| p == tok) {
            return NegotiationOutcome::Selected((*tok).to_string());
        }
    }
    NegotiationOutcome::Unsupported
}

/// Extract client identity from TLS peer certificates.
fn extract_client_identity(tls_stream: &TlsStream) -> Result<Identity> {
    let (_, server_conn) = tls_stream.get_ref();

    let certs = server_conn
        .peer_certificates()
        .ok_or(TransportError::NoCertificate)?;

    let client_cert = certs.first().ok_or(TransportError::EmptyCertChain)?;

    extract_identity(client_cert)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::net::IpAddr;

    use super::*;

    #[test]
    fn rate_limit_allows_under_threshold() {
        let limiter = SlidingWindowLimiter::new(
            DEFAULT_CONN_RATE_LIMIT,
            DEFAULT_CONN_RATE_WINDOW,
            "connection",
        )
        .with_ipv6_64_collapse(true);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        for _ in 0..DEFAULT_CONN_RATE_LIMIT - 1 {
            assert!(!limiter.is_limited(ip));
        }
    }

    #[test]
    fn rate_limit_blocks_at_threshold() {
        let limiter = SlidingWindowLimiter::new(
            DEFAULT_CONN_RATE_LIMIT,
            DEFAULT_CONN_RATE_WINDOW,
            "connection",
        )
        .with_ipv6_64_collapse(true);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        for _ in 0..DEFAULT_CONN_RATE_LIMIT {
            assert!(!limiter.is_limited(ip));
        }

        // Next attempt should be blocked.
        assert!(limiter.is_limited(ip));
    }

    #[test]
    fn rate_limit_isolates_ips() {
        let limiter = SlidingWindowLimiter::new(
            DEFAULT_CONN_RATE_LIMIT,
            DEFAULT_CONN_RATE_WINDOW,
            "connection",
        )
        .with_ipv6_64_collapse(true);
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust limit for ip_a.
        for _ in 0..DEFAULT_CONN_RATE_LIMIT {
            assert!(!limiter.is_limited(ip_a));
        }
        assert!(limiter.is_limited(ip_a));

        // ip_b should still be allowed.
        assert!(!limiter.is_limited(ip_b));
    }

    #[test]
    fn rate_limit_window_expiry() {
        // Tiny window so we can sleep through it.
        let limiter = SlidingWindowLimiter::new(1, Duration::from_millis(1), "connection")
            .with_ipv6_64_collapse(true);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(!limiter.is_limited(ip));
        assert!(limiter.is_limited(ip));

        std::thread::sleep(Duration::from_millis(10));

        // Should be allowed again after window expires.
        assert!(!limiter.is_limited(ip));
    }

    mod session_hooks {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use super::*;

        fn assert_send_sync<T: Send + Sync + 'static>() {}

        #[test]
        fn on_ws_accept_fn_is_send_sync_static() {
            assert_send_sync::<OnWsAcceptFn>();
        }

        #[test]
        fn on_ws_reject_fn_is_send_sync_static() {
            assert_send_sync::<OnWsRejectFn>();
        }

        #[test]
        fn ws_session_hooks_default_is_all_none() {
            let hooks = WsSessionHooks::default();
            assert!(hooks.on_connection_accept.is_none());
            assert!(hooks.on_connection_rejected.is_none());
        }

        #[test]
        fn ws_session_hooks_debug_redacts_closure_bodies() {
            let hooks = WsSessionHooks {
                on_connection_accept: Some(Arc::new(|| {})),
                on_connection_rejected: None,
            };
            let debug = format!("{:?}", hooks);
            // Presence is reported as a bool, not the closure body.
            assert!(debug.contains("on_connection_accept: true"), "{debug}");
            assert!(debug.contains("on_connection_rejected: false"), "{debug}");
        }

        #[test]
        fn ws_session_hooks_clone_shares_callback_state() {
            let counter = Arc::new(AtomicUsize::new(0));
            let c = Arc::clone(&counter);
            let hooks = WsSessionHooks {
                on_connection_accept: Some(Arc::new(move || {
                    let _ = c.fetch_add(1, Ordering::SeqCst);
                })),
                on_connection_rejected: None,
            };
            let cloned = hooks.clone();
            if let Some(cb) = hooks.on_connection_accept.as_ref() {
                cb();
            }
            if let Some(cb) = cloned.on_connection_accept.as_ref() {
                cb();
            }
            assert_eq!(counter.load(Ordering::SeqCst), 2);
        }

        #[test]
        fn ws_listener_config_default_has_no_reject_hook() {
            let cfg = WsListenerConfig::default();
            assert!(cfg.on_connection_rejected.is_none());
        }
    }

    /// Unit tests for [`negotiate_subprotocol`] — the RFC 6455 §4.2.2
    /// selection logic, tested purely against a `HeaderMap` so we avoid
    /// standing up a full WebSocket handshake. Integration-level round-trip
    /// tests live in `tests/ws_subprotocol.rs`.
    mod subprotocol_selection {
        use tokio_tungstenite::tungstenite::http::{HeaderMap, HeaderValue, header};

        use super::*;

        fn headers_with(tokens: &[&str]) -> HeaderMap {
            let mut h = HeaderMap::new();
            for t in tokens {
                // HeaderMap::append returns bool ("was the key already
                // present?"); we don't use it.
                let _ = h.append(
                    header::SEC_WEBSOCKET_PROTOCOL,
                    HeaderValue::from_str(t).unwrap(),
                );
            }
            h
        }

        #[test]
        fn default_config_has_empty_subprotocols() {
            let cfg = WsListenerConfig::default();
            assert!(cfg.supported_subprotocols.is_empty());
        }

        #[test]
        fn empty_server_list_is_no_protocol_required_even_if_client_offers() {
            // Historical / pre-#884 default: the listener advertises nothing,
            // so negotiation is disabled even if the client asked. The
            // handshake proceeds with no `Sec-WebSocket-Protocol` response
            // header. Real clients that sent a protocol request will treat
            // this as a fatal error at their end — operators opting out of
            // subprotocols must be sure their clients do the same.
            let server: Vec<String> = Vec::new();
            let headers = headers_with(&["cot.v2"]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::NoProtocolRequired
            );
        }

        #[test]
        fn empty_client_is_no_protocol_required_even_if_server_advertises() {
            // Server advertises, client is silent. RFC 6455 §4.2.2 allows
            // this — the server leaves the header off the response and the
            // handshake completes with an unnegotiated session.
            let server = vec!["cot.v2".to_string()];
            let headers = HeaderMap::new();
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::NoProtocolRequired
            );
        }

        #[test]
        fn single_match_returns_selected() {
            let server = vec!["cot.v2".to_string()];
            let headers = headers_with(&["cot.v2"]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::Selected("cot.v2".to_string())
            );
        }

        #[test]
        fn no_overlap_when_both_sides_speak_is_unsupported() {
            // Both sides spoke but have zero overlap → reject. Most real
            // clients (browsers, Python websockets, Go nhooyr/websocket,
            // tungstenite's own client) treat "I asked, you didn't pick" as
            // fatal anyway, so a 400 surfaces the mismatch cleanly in
            // server-side logs rather than leaving it as an opaque client
            // protocol error.
            let server = vec!["cot.v2".to_string()];
            let headers = headers_with(&["unrelated.protocol"]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::Unsupported
            );
        }

        #[test]
        fn client_preference_wins_on_overlapping_offers() {
            // Server advertises A, B. Client offers B, A. RFC 6455 §4.2.2
            // leaves the final choice to the server, but the prevailing
            // pattern across ws / Node / Python `websockets` / Jetty is to
            // scan the *client's* list in client order and take the first
            // server match. That keeps the server's advertised order as a
            // filter rather than a strict preference — matches what TAK and
            // observability tooling expect.
            let server = vec!["a.v1".to_string(), "b.v1".to_string()];
            let headers = headers_with(&["b.v1", "a.v1"]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::Selected("b.v1".to_string())
            );
        }

        #[test]
        fn server_still_filters_unsupported_client_tokens() {
            // Client offers: unknown, b.v1, a.v1. Server: a, b. First
            // client-order token the server recognizes is b.v1, so that
            // wins — even though the server listed a.v1 first.
            let server = vec!["a.v1".to_string(), "b.v1".to_string()];
            let headers = headers_with(&["unknown", "b.v1", "a.v1"]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::Selected("b.v1".to_string())
            );
        }

        #[test]
        fn case_sensitive_mismatch_is_unsupported() {
            // RFC 6455 `Sec-WebSocket-Protocol` tokens inherit RFC 7230
            // `token` ABNF, which is case-sensitive. Do not lowercase-fold.
            let server = vec!["TAK".to_string()];
            let headers = headers_with(&["tak"]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::Unsupported
            );
        }

        #[test]
        fn comma_separated_single_header_is_split() {
            // RFC 7230 §3.2.2: a list-valued header may collapse multiple
            // values into one comma-separated header. Handle both forms.
            let server = vec!["b.v1".to_string()];
            let headers = headers_with(&["a.v1, b.v1, c.v1"]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::Selected("b.v1".to_string())
            );
        }

        #[test]
        fn multiple_headers_are_flattened() {
            // Same RFC 7230 rule but for the other form — two separate
            // `Sec-WebSocket-Protocol` headers instead of one comma list.
            let server = vec!["b.v1".to_string()];
            let headers = headers_with(&["a.v1", "b.v1"]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::Selected("b.v1".to_string())
            );
        }

        #[test]
        fn trims_whitespace_around_comma_separated_tokens() {
            // Curl / wscat / some Python stacks emit `"a.v1 , b.v1"` with
            // whitespace around the comma. Per ABNF (RFC 7230 OWS), trim.
            let server = vec!["b.v1".to_string()];
            let headers = headers_with(&["  a.v1  ,  b.v1  "]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::Selected("b.v1".to_string())
            );
        }

        #[test]
        fn empty_tokens_in_comma_list_are_ignored() {
            // `",, b.v1 ,,"` should still match `b.v1`; empty tokens are
            // skipped, not surfaced as spurious "" matches.
            let server = vec!["b.v1".to_string()];
            let headers = headers_with(&[",, b.v1 ,,"]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::Selected("b.v1".to_string())
            );
        }

        #[test]
        fn client_offers_only_empty_tokens_is_no_protocol_required() {
            // Pathological client sending `"  , , "` — after trimming and
            // filtering empty entries, there is nothing for the server to
            // match. Treat the same as "client offered nothing".
            let server = vec!["cot.v2".to_string()];
            let headers = headers_with(&["  ,  ,  "]);
            assert_eq!(
                negotiate_subprotocol(&server, &headers),
                NegotiationOutcome::NoProtocolRequired
            );
        }

        #[test]
        fn ws_listener_config_debug_renders_subprotocols() {
            // Operators inspect this struct in tracing output; pin the
            // field rendering to catch an accidental `skip`.
            let cfg = WsListenerConfig {
                supported_subprotocols: vec!["cot.v2".to_string(), "tak.v1".to_string()],
                ..WsListenerConfig::default()
            };
            let s = format!("{cfg:?}");
            assert!(s.contains("cot.v2"), "{s}");
            assert!(s.contains("tak.v1"), "{s}");
        }
    }
}
