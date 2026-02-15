//! TLS listener for accepting mTLS connections.

use crate::config::TlsConfig;
use crate::extract::extract_identity;
use crate::session::AuthenticatedSession;
use rustgate_core::error::{Result, RustgateError};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

pub struct TlsListener {
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsListener")
            .field("tcp_listener", &self.tcp_listener)
            .field("tls_acceptor", &"<TlsAcceptor>")
            .finish()
    }
}

impl TlsListener {
    pub async fn bind<A: ToSocketAddrs>(addr: A, config: &TlsConfig) -> Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        let server_config = config.build_server_config()?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

        debug!(
            local_addr = ?tcp_listener.local_addr().ok(),
            "TLS listener bound"
        );

        Ok(Self {
            tcp_listener,
            tls_acceptor,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.tcp_listener
            .local_addr()
            .map_err(|e| RustgateError::Transport(format!("failed to get local address: {e}")))
    }

    /// Accept a new mTLS connection. Loops internally on TCP/TLS failures,
    /// only returning when a fully authenticated session is ready or
    /// identity extraction fails.
    pub async fn accept(&self) -> Result<AuthenticatedSession> {
        loop {
            let (tcp_stream, peer_addr) = match self.tcp_listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "TCP accept failed");
                    continue;
                }
            };

            debug!(peer_addr = %peer_addr, "TCP connection accepted");

            let tls_stream = match self.tls_acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(peer_addr = %peer_addr, error = %e, "TLS handshake failed");
                    continue;
                }
            };

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

        let certs = server_conn.peer_certificates().ok_or_else(|| {
            RustgateError::Transport("no client certificate presented".to_string())
        })?;

        let client_cert = certs.first().ok_or_else(|| {
            RustgateError::Transport("empty client certificate chain".to_string())
        })?;

        extract_identity(client_cert)
    }
}
