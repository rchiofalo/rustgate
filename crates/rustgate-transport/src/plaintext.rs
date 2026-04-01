//! Plaintext TCP listener for trusted/air-gapped networks.
//!
//! Accepts TCP connections without TLS. Each connection is assigned a
//! configurable anonymous identity (default CN `anonymous`, default group
//! `__plaintext__`). This is strictly opt-in and logs a prominent warning
//! when started.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use rustgate_core::error::{Result, RustgateError};
use rustgate_core::identity::Identity;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tracing::{debug, warn};

/// TCP keepalive idle time for plaintext connections.
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);

/// Interval between keepalive probes.
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Configuration for the anonymous identity assigned to plaintext clients.
#[derive(Debug, Clone)]
pub struct PlaintextIdentityConfig {
    /// Common name assigned to all plaintext clients.
    pub cn: String,
    /// Default group membership for plaintext clients.
    pub default_group: String,
}

impl Default for PlaintextIdentityConfig {
    fn default() -> Self {
        Self {
            cn: "anonymous".to_string(),
            default_group: "__plaintext__".to_string(),
        }
    }
}

/// Accepted plaintext TCP connection with an assigned identity.
#[derive(Debug)]
pub struct PlaintextSession {
    identity: Identity,
    peer_addr: SocketAddr,
    stream: TcpStream,
}

impl PlaintextSession {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Split into a standard tokio read/write pair.
    pub fn into_split(
        self,
    ) -> (
        tokio::io::ReadHalf<TcpStream>,
        tokio::io::WriteHalf<TcpStream>,
    ) {
        tokio::io::split(self.stream)
    }
}

/// Plaintext TCP listener for non-TLS connections.
///
/// Each accepted connection receives a synthetic identity based on the
/// configured [`PlaintextIdentityConfig`]. The CN is suffixed with the
/// peer address to disambiguate concurrent connections.
pub struct PlaintextListener {
    tcp_listener: TcpListener,
    identity_config: PlaintextIdentityConfig,
}

impl std::fmt::Debug for PlaintextListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaintextListener")
            .field("tcp_listener", &self.tcp_listener)
            .field("identity_config", &self.identity_config)
            .finish()
    }
}

impl PlaintextListener {
    /// Bind to the given address.
    ///
    /// Logs a security warning — plaintext transport must only be used on
    /// trusted or air-gapped networks.
    pub async fn bind<A: ToSocketAddrs>(
        addr: A,
        identity_config: PlaintextIdentityConfig,
    ) -> Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;

        warn!(
            local_addr = ?tcp_listener.local_addr().ok(),
            "PLAINTEXT TCP listener bound — connections are NOT encrypted"
        );

        Ok(Self {
            tcp_listener,
            identity_config,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.tcp_listener
            .local_addr()
            .map_err(|e| RustgateError::Transport(format!("failed to get local address: {e}")))
    }

    /// Accept a new plaintext TCP connection.
    ///
    /// Returns a [`PlaintextSession`] with a synthetic identity derived
    /// from the configuration and the peer address.
    pub async fn accept(&self) -> Result<PlaintextSession> {
        loop {
            let (tcp_stream, peer_addr) = match self.tcp_listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "plaintext TCP accept failed");
                    continue;
                }
            };

            configure_tcp_keepalive(&tcp_stream);

            debug!(peer_addr = %peer_addr, "plaintext TCP connection accepted");

            let cn = format!("{}-{}", self.identity_config.cn, peer_addr);
            let mut groups = BTreeSet::new();
            let _ = groups.insert(self.identity_config.default_group.clone());

            let identity = Identity::plaintext(cn, groups).map_err(|e| {
                RustgateError::Transport(format!("invalid plaintext identity for {peer_addr}: {e}"))
            })?;

            return Ok(PlaintextSession {
                identity,
                peer_addr,
                stream: tcp_stream,
            });
        }
    }
}

fn configure_tcp_keepalive(stream: &TcpStream) {
    let sock_ref = socket2::SockRef::from(stream);

    let mut keepalive = socket2::TcpKeepalive::new().with_time(TCP_KEEPALIVE_IDLE);
    keepalive = keepalive.with_interval(TCP_KEEPALIVE_INTERVAL);

    if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
        warn!(error = %e, "failed to set TCP keepalive on plaintext socket");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_identity_config() {
        let cfg = PlaintextIdentityConfig::default();
        assert_eq!(cfg.cn, "anonymous");
        assert_eq!(cfg.default_group, "__plaintext__");
    }

    #[tokio::test]
    async fn bind_and_accept() {
        let cfg = PlaintextIdentityConfig::default();
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });

        let session = listener.accept().await.expect("accept");
        assert!(session.identity().cn.starts_with("anonymous-"));
        assert!(session.identity().groups.contains("__plaintext__"));
        assert!(session.identity().fingerprint.is_empty());

        let _client_stream = client.await.expect("join");
    }

    #[tokio::test]
    async fn custom_identity_config() {
        let cfg = PlaintextIdentityConfig {
            cn: "radio-mesh".to_string(),
            default_group: "field-ops".to_string(),
        };
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });

        let session = listener.accept().await.expect("accept");
        assert!(session.identity().cn.starts_with("radio-mesh-"));
        assert!(session.identity().groups.contains("field-ops"));

        let _client_stream = client.await.expect("join");
    }
}
