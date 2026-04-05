//! WebSocket (wss://) listener and session management for rustgate.
//!
//! Provides [`WsListener`] for accepting WebSocket connections over TLS,
//! [`WsSession`] representing an authenticated client, and [`WebSocketServer`]
//! for managing the accept loop and session lifecycle with router integration.
//!
//! All connections require a valid client certificate; identity is extracted
//! exclusively from the X.509 certificate, never from headers or query params.

mod server;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustgate_core::constants::HANDSHAKE_TIMEOUT;
use rustgate_core::error::{Result, TransportError};
use rustgate_core::identity::Identity;
use rustgate_core::net::configure_tcp_keepalive;
use rustgate_transport::{TlsConfig, extract_identity};
pub use server::{OnFederationForward, OnNatsPublish, WebSocketServer, WsServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
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
            .finish()
    }
}

/// Maximum connection attempts per IP within the rate limit window.
const CONN_RATE_LIMIT: usize = 10;

/// Sliding window duration for connection rate limiting.
const CONN_RATE_WINDOW: Duration = Duration::from_secs(10);

/// Number of tracked IPs that triggers an inline sweep of stale entries.
const CONN_RATE_SWEEP_THRESHOLD: usize = 512;

/// WebSocket listener with mandatory mTLS.
///
/// Mirrors [`TlsListener`](rustgate_transport::TlsListener) but adds the
/// WebSocket upgrade handshake after TLS completes. The accept loop handles
/// TCP, TLS, identity extraction, and WS upgrade — callers receive a fully
/// authenticated [`WsSession`] ready for message exchange.
///
/// Includes per-IP connection rate limiting to mitigate slow-handshake DoS
/// attacks where an adversary repeatedly initiates and abandons TLS handshakes.
pub struct WsListener {
    tcp: TcpListener,
    tls: TlsAcceptor,
    conn_rate: Mutex<ConnRateState>,
}

/// Per-IP connection attempt tracking for DoS mitigation.
#[derive(Debug)]
struct ConnRateState {
    map: HashMap<IpAddr, VecDeque<Instant>>,
    last_sweep: Instant,
}

impl std::fmt::Debug for WsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsListener")
            .field("tcp", &self.tcp)
            .field("tls", &"<TlsAcceptor>")
            .field("conn_rate", &"<ConnRateState>")
            .finish()
    }
}

impl WsListener {
    /// Bind to the given address with SO_REUSEADDR for clean restarts.
    pub fn bind(addr: SocketAddr, tls_config: &TlsConfig) -> Result<Self> {
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
            conn_rate: Mutex::new(ConnRateState {
                map: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        })
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.tcp
            .local_addr()
            .map_err(|e| TransportError::Other(format!("failed to get local address: {e}")).into())
    }

    /// Accept a new WebSocket connection with mTLS authentication.
    ///
    /// Loops internally on TCP, TLS, and WebSocket handshake failures.
    /// Returns only when a fully authenticated session is ready, or
    /// when identity extraction fails (which is a configuration error).
    /// Check whether `ip` has exceeded the connection rate limit.
    ///
    /// Returns `true` if the IP is rate-limited, `false` otherwise.
    /// Records the attempt timestamp on success.
    fn is_conn_rate_limited(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - CONN_RATE_WINDOW;

        let mut state = match self.conn_rate.lock() {
            Ok(s) => s,
            Err(e) => e.into_inner(),
        };

        // Periodic sweep of stale IPs to bound memory.
        if state.map.len() > CONN_RATE_SWEEP_THRESHOLD
            || now.duration_since(state.last_sweep) >= CONN_RATE_WINDOW
        {
            state.map.retain(|_, timestamps| {
                while timestamps.front().is_some_and(|t| *t <= cutoff) {
                    let _ = timestamps.pop_front();
                }
                !timestamps.is_empty()
            });
            state.last_sweep = now;
        }

        let timestamps = state.map.entry(ip).or_default();

        // Prune expired entries for this IP.
        while timestamps.front().is_some_and(|t| *t <= cutoff) {
            let _ = timestamps.pop_front();
        }

        if timestamps.len() >= CONN_RATE_LIMIT {
            return true;
        }

        timestamps.push_back(now);
        false
    }

    pub async fn accept(&self) -> Result<WsSession> {
        loop {
            let (tcp_stream, peer_addr) = match self.tcp.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "TCP accept failed");
                    continue;
                }
            };

            // Per-IP connection rate limiting to mitigate slow-handshake DoS.
            if self.is_conn_rate_limited(peer_addr.ip()) {
                warn!(
                    peer_addr = %peer_addr,
                    "connection rejected: rate limit exceeded for IP"
                );
                drop(tcp_stream);
                continue;
            }

            configure_tcp_keepalive(&tcp_stream);
            debug!(peer_addr = %peer_addr, "TCP connection accepted");

            let tls_stream = match self.tls.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(peer_addr = %peer_addr, error = %e, "TLS handshake failed");
                    continue;
                }
            };

            debug!(peer_addr = %peer_addr, "TLS handshake completed");

            let identity = match extract_client_identity(&tls_stream) {
                Ok(id) => id,
                Err(e) => {
                    warn!(peer_addr = %peer_addr, error = %e, "identity extraction failed");
                    continue;
                }
            };

            debug!(
                peer_addr = %peer_addr,
                cn = %identity.cn,
                groups = ?identity.groups,
                "client authenticated"
            );

            let mut ws_config =
                tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
            ws_config.max_frame_size = Some(16 * 1024 * 1024);
            ws_config.max_message_size = Some(64 * 1024 * 1024);

            let ws_stream = match tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                tokio_tungstenite::accept_async_with_config(tls_stream, Some(ws_config)),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    warn!(peer_addr = %peer_addr, error = %e, "WebSocket upgrade failed");
                    continue;
                }
                Err(_) => {
                    warn!(peer_addr = %peer_addr, "WebSocket upgrade timed out");
                    continue;
                }
            };

            debug!(peer_addr = %peer_addr, cn = %identity.cn, "WebSocket session established");

            return Ok(WsSession {
                identity: Arc::new(identity),
                stream: ws_stream,
                peer_addr,
            });
        }
    }
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
