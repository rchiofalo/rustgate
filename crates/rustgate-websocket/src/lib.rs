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
    OnWsAcceptFn, OnWsFrameReceivedFn, OnWsFrameRejectedFn, OnWsRejectFn, WebSocketServer,
    WsServerConfig, WsSessionHooks,
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
            conn_rate: ConnRateLimiter::new(config.conn_rate_limit, config.conn_rate_window),
            max_frame_size: config.max_frame_size,
            max_message_size: config.max_message_size,
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
                    self.fire_rejected();
                    continue;
                }
                Err(_) => {
                    warn!(peer_addr = %peer_addr, "WebSocket upgrade timed out");
                    self.fire_rejected();
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
            assert!(hooks.on_frame_received.is_none());
            assert!(hooks.on_frame_rejected.is_none());
        }

        #[test]
        fn ws_session_hooks_debug_redacts_closure_bodies() {
            let hooks = WsSessionHooks {
                on_connection_accept: Some(Arc::new(|| {})),
                on_connection_rejected: None,
                on_frame_received: Some(Arc::new(|| {})),
                on_frame_rejected: None,
            };
            let debug = format!("{:?}", hooks);
            // Presence is reported as a bool, not the closure body.
            assert!(debug.contains("on_connection_accept: true"), "{debug}");
            assert!(debug.contains("on_connection_rejected: false"), "{debug}");
            assert!(debug.contains("on_frame_received: true"), "{debug}");
            assert!(debug.contains("on_frame_rejected: false"), "{debug}");
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
                on_frame_received: None,
                on_frame_rejected: None,
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
        fn ws_session_hooks_frame_callbacks_fire_independently() {
            let recv_count = Arc::new(AtomicUsize::new(0));
            let rej_count = Arc::new(AtomicUsize::new(0));
            let r = Arc::clone(&recv_count);
            let j = Arc::clone(&rej_count);
            let hooks = WsSessionHooks {
                on_frame_received: Some(Arc::new(move || {
                    let _ = r.fetch_add(1, Ordering::SeqCst);
                })),
                on_frame_rejected: Some(Arc::new(move || {
                    let _ = j.fetch_add(1, Ordering::SeqCst);
                })),
                ..Default::default()
            };
            if let Some(cb) = hooks.on_frame_received.as_ref() {
                cb();
                cb();
            }
            if let Some(cb) = hooks.on_frame_rejected.as_ref() {
                cb();
            }
            assert_eq!(recv_count.load(Ordering::SeqCst), 2);
            assert_eq!(rej_count.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn ws_listener_config_default_has_no_reject_hook() {
            let cfg = WsListenerConfig::default();
            assert!(cfg.on_connection_rejected.is_none());
        }

        #[test]
        fn on_ws_frame_received_fn_is_send_sync_static() {
            fn assert_send_sync<T: Send + Sync + 'static>() {}
            assert_send_sync::<OnWsFrameReceivedFn>();
        }

        #[test]
        fn on_ws_frame_rejected_fn_is_send_sync_static() {
            fn assert_send_sync<T: Send + Sync + 'static>() {}
            assert_send_sync::<OnWsFrameRejectedFn>();
        }
    }
}
