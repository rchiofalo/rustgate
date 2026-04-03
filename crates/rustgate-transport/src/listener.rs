//! TLS listener for accepting mTLS connections.

use std::net::SocketAddr;
use std::sync::Arc;

use rustgate_core::error::{Result, TransportError};
use rustgate_core::net::configure_tcp_keepalive;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::config::TlsConfig;
use crate::extract::{ExpectedKeyUsage, extract_identity, validate_key_usage};
use crate::session::AuthenticatedSession;

/// Default maximum number of concurrent TLS handshakes when no limit is specified.
const DEFAULT_MAX_HANDSHAKES: usize = 100;

pub struct TlsListener {
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    /// Semaphore that limits the number of TLS handshakes in progress.
    /// Each handshake acquires a permit before starting and releases it
    /// once the handshake completes (successfully or not).
    handshake_semaphore: Arc<Semaphore>,
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsListener")
            .field("tcp_listener", &self.tcp_listener)
            .field("tls_acceptor", &"<TlsAcceptor>")
            .field(
                "max_concurrent_handshakes",
                &self.handshake_semaphore.available_permits(),
            )
            .finish()
    }
}

impl TlsListener {
    /// Bind a TLS listener with the default handshake concurrency limit.
    pub async fn bind<A: ToSocketAddrs>(addr: A, config: &TlsConfig) -> Result<Self> {
        Self::bind_with_handshake_limit(addr, config, DEFAULT_MAX_HANDSHAKES).await
    }

    /// Bind a TLS listener with a configurable handshake concurrency limit.
    ///
    /// `max_concurrent_handshakes` controls how many TLS handshakes may be in
    /// progress simultaneously. Incoming TCP connections that arrive while all
    /// handshake slots are occupied will wait until a slot becomes available.
    /// This prevents connection-flood DoS attacks from exhausting server
    /// resources with expensive cryptographic operations.
    pub async fn bind_with_handshake_limit<A: ToSocketAddrs>(
        addr: A,
        config: &TlsConfig,
        max_concurrent_handshakes: usize,
    ) -> Result<Self> {
        let server_config = config.build_server_config()?;
        Self::bind_with_server_config(addr, Arc::new(server_config), max_concurrent_handshakes)
            .await
    }

    /// Bind a TLS listener with a pre-built `ServerConfig`.
    ///
    /// Use this when you need custom TLS configuration, such as a
    /// [`DynamicCertVerifier`](crate::DynamicCertVerifier) that refreshes
    /// trusted CAs at runtime.
    pub async fn bind_with_server_config<A: ToSocketAddrs>(
        addr: A,
        server_config: Arc<rustls::ServerConfig>,
        max_concurrent_handshakes: usize,
    ) -> Result<Self> {
        let tcp_listener = TcpListener::bind(addr)
            .await
            .map_err(|e| TransportError::Other(format!("failed to bind TLS listener: {e}")))?;
        let tls_acceptor = TlsAcceptor::from(server_config);

        debug!(
            local_addr = ?tcp_listener.local_addr().ok(),
            max_concurrent_handshakes,
            "TLS listener bound"
        );

        Ok(Self {
            tcp_listener,
            tls_acceptor,
            handshake_semaphore: Arc::new(Semaphore::new(max_concurrent_handshakes)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.tcp_listener
            .local_addr()
            .map_err(|e| TransportError::Other(format!("failed to get local address: {e}")).into())
    }

    /// Accept a new mTLS connection. Loops internally on TCP/TLS failures,
    /// only returning when a fully authenticated session is ready or
    /// identity extraction fails.
    ///
    /// TLS handshake concurrency is bounded by the semaphore configured at
    /// construction time. When all handshake slots are occupied, the listener
    /// still accepts TCP connections but waits for a free slot before
    /// beginning the TLS handshake.
    pub async fn accept(&self) -> Result<AuthenticatedSession> {
        loop {
            let (tcp_stream, peer_addr) = match self.tcp_listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "TCP accept failed");
                    continue;
                }
            };

            configure_tcp_keepalive(&tcp_stream);

            debug!(peer_addr = %peer_addr, "TCP connection accepted");

            // Acquire a handshake permit before starting the TLS handshake.
            // This bounds the number of concurrent cryptographic operations
            // to prevent resource exhaustion under connection floods.
            let _permit = match self.handshake_semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    // Semaphore closed — listener is shutting down.
                    return Err(
                        TransportError::Other("handshake semaphore closed".to_string()).into(),
                    );
                }
            };

            let available = self.handshake_semaphore.available_permits();
            if available == 0 {
                info!(
                    peer_addr = %peer_addr,
                    "all handshake slots occupied, new connections will wait"
                );
            }

            let tls_stream = match self.tls_acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    // Permit is released here when `_permit` is dropped.
                    rustgate_core::audit::tls_accept_error(peer_addr, &e.to_string());
                    warn!(peer_addr = %peer_addr, error = %e, "TLS handshake failed");
                    continue;
                }
            };

            // Permit released — handshake slot freed for the next connection.
            drop(_permit);

            debug!(peer_addr = %peer_addr, "TLS handshake completed");

            let identity = match Self::extract_client_identity(&tls_stream) {
                Ok(id) => id,
                Err(e) => {
                    warn!(peer_addr = %peer_addr, error = %e, "identity extraction failed");
                    return Err(e);
                }
            };

            debug!(
                peer_addr = %peer_addr,
                cn = %identity.cn,
                groups = ?identity.groups,
                "client authenticated"
            );

            return Ok(AuthenticatedSession::new(identity, peer_addr, tls_stream));
        }
    }

    fn extract_client_identity(
        tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) -> Result<rustgate_core::identity::Identity> {
        let (_, server_conn) = tls_stream.get_ref();

        let certs = server_conn
            .peer_certificates()
            .ok_or(TransportError::NoCertificate)?;

        let client_cert = certs.first().ok_or(TransportError::EmptyCertChain)?;

        validate_key_usage(client_cert, ExpectedKeyUsage::ClientAuth)?;

        extract_identity(client_cert)
    }
}
