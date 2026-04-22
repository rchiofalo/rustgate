// Copyright © 2026 Roberto Chiofalo.

//! WebSocket (wss://) listener and session management for rustgate.
//!
//! Provides [`WsListener`] for accepting WebSocket connections over TLS,
//! [`WsSession`] representing an authenticated client, and [`WebSocketServer`]
//! for managing the accept loop and session lifecycle with router integration.
//!
//! All connections require a valid client certificate; identity is extracted
//! exclusively from the X.509 certificate, never from headers or query params.

pub mod health;
mod rate_limit;
mod server;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustgate_core::constants::HANDSHAKE_TIMEOUT;
use rustgate_core::error::{Result, TransportError};
use rustgate_core::identity::Identity;
use rustgate_core::net::configure_tactical_socket;
use rustgate_resilience::conn_rate_limiter::ConnRateLimiter;
use rustgate_transport::{TlsConfig, extract_identity};
pub use server::{
    DEFAULT_MAX_WRITE_BUFFER_BYTES, OnFederationForward, OnHttpForward, OnNatsPublish,
    WebSocketServer, WsServerConfig,
};
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
    conn_rate: ConnRateLimiter,
    max_frame_size: usize,
    max_message_size: usize,
}

impl std::fmt::Debug for WsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsListener")
            .field("tcp", &self.tcp)
            .field("tls", &"<TlsAcceptor>")
            .field("conn_rate", &self.conn_rate)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_message_size", &self.max_message_size)
            .finish()
    }
}

/// Configuration for constructing a [`WsListener`].
#[derive(Debug)]
pub struct WsListenerConfig {
    /// Maximum connection attempts per IP within the rate limit window.
    pub conn_rate_limit: usize,
    /// Sliding window duration for connection rate limiting.
    pub conn_rate_window: Duration,
    /// Maximum WebSocket frame size in bytes.
    pub max_frame_size: usize,
    /// Maximum WebSocket message size in bytes.
    pub max_message_size: usize,
}

impl Default for WsListenerConfig {
    fn default() -> Self {
        Self {
            conn_rate_limit: DEFAULT_CONN_RATE_LIMIT,
            conn_rate_window: DEFAULT_CONN_RATE_WINDOW,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
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
            conn_rate: ConnRateLimiter::new(config.conn_rate_limit, config.conn_rate_window),
            max_frame_size: config.max_frame_size,
            max_message_size: config.max_message_size,
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
    ///
    /// Connections are subject to per-IP rate limiting before the TLS
    /// handshake to mitigate slow-handshake denial-of-service attacks.
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
            if self.conn_rate.is_limited(peer_addr.ip()) {
                warn!(
                    peer_addr = %peer_addr,
                    "connection rejected: rate limit exceeded for IP"
                );
                drop(tcp_stream);
                continue;
            }

            configure_tactical_socket(&tcp_stream);
            debug!(peer_addr = %peer_addr, "TCP connection accepted");

            let tls_stream = match self.tls.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(peer_addr = %peer_addr, error = %e, "TLS handshake failed");
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
            ws_config.max_frame_size = Some(self.max_frame_size);
            ws_config.max_message_size = Some(self.max_message_size);

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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::net::IpAddr;

    use super::*;

    #[test]
    fn rate_limit_allows_under_threshold() {
        let limiter = ConnRateLimiter::new(DEFAULT_CONN_RATE_LIMIT, DEFAULT_CONN_RATE_WINDOW);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        for _ in 0..DEFAULT_CONN_RATE_LIMIT - 1 {
            assert!(!limiter.is_limited(ip));
        }
    }

    #[test]
    fn rate_limit_blocks_at_threshold() {
        let limiter = ConnRateLimiter::new(DEFAULT_CONN_RATE_LIMIT, DEFAULT_CONN_RATE_WINDOW);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        for _ in 0..DEFAULT_CONN_RATE_LIMIT {
            assert!(!limiter.is_limited(ip));
        }

        // Next attempt should be blocked.
        assert!(limiter.is_limited(ip));
    }

    #[test]
    fn rate_limit_isolates_ips() {
        let limiter = ConnRateLimiter::new(DEFAULT_CONN_RATE_LIMIT, DEFAULT_CONN_RATE_WINDOW);
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
        let limiter = ConnRateLimiter::new(1, Duration::from_millis(1));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(!limiter.is_limited(ip));
        assert!(limiter.is_limited(ip));

        std::thread::sleep(Duration::from_millis(10));

        // Should be allowed again after window expires.
        assert!(!limiter.is_limited(ip));
    }
}
