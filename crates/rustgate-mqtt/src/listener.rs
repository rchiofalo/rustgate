// Copyright © 2026 Roberto Chiofalo.

//! MQTT TLS listener — accepts TCP connections and performs mTLS handshake.
//!
//! Mirrors the pattern from [`rustgate_websocket`]: binds a TCP socket with
//! `SO_REUSEADDR`, wraps it with a [`TlsAcceptor`], and extracts the client
//! identity from the peer certificate.
//!
//! Includes per-IP connection rate limiting to mitigate slow-handshake DoS
//! attacks where an adversary repeatedly initiates and abandons TLS
//! handshakes. **Note:** rate limiting uses the raw TCP peer address. Behind
//! NAT or a load balancer, all clients sharing one egress IP are rate-limited
//! together. See the threat model (D8) for deployment guidance.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustgate_core::constants::HANDSHAKE_TIMEOUT;
use rustgate_core::error::{Result, TransportError};
use rustgate_core::identity::Identity;
use rustgate_core::net::configure_tactical_socket;
use rustgate_resilience::conn_rate_limiter::ConnRateLimiter;
use rustgate_transport::{TlsConfig, extract_identity};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

/// Server-side TLS stream over TCP.
pub(crate) type TlsStream = tokio_rustls::server::TlsStream<TcpStream>;

/// A pre-session: a TLS-authenticated connection before CONNECT processing.
#[derive(Debug)]
pub struct MqttPreSession {
    /// The authenticated client identity from the X.509 certificate.
    pub identity: Arc<Identity>,
    /// The TLS stream ready for MQTT packet I/O.
    pub stream: TlsStream,
    /// The remote peer address.
    pub peer_addr: SocketAddr,
}

/// Maximum connection attempts per IP within the rate limit window.
const CONN_RATE_LIMIT: usize = 10;

/// Sliding window duration for connection rate limiting.
const CONN_RATE_WINDOW: Duration = Duration::from_secs(10);

/// MQTT TLS listener bound to a local address.
///
/// Call [`accept`](MqttListener::accept) to wait for the next authenticated
/// connection. Identity is derived from the client certificate; no MQTT-level
/// authentication is performed here.
///
/// Includes per-IP connection rate limiting to mitigate slow-handshake DoS.
/// Rate limiting uses the raw TCP peer address — see module docs for
/// NAT/proxy caveats.
pub struct MqttListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    conn_rate: ConnRateLimiter,
}

impl std::fmt::Debug for MqttListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MqttListener")
            .field("local_addr", &self.tcp.local_addr())
            .field("conn_rate", &self.conn_rate)
            .finish()
    }
}

impl MqttListener {
    /// Bind the MQTT listener to `addr` using the provided TLS configuration.
    pub fn bind(addr: SocketAddr, tls: &TlsConfig) -> Result<Self> {
        let server_config = tls.build_server_config()?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        socket.listen(1024)?;

        let tcp = TcpListener::from_std(socket.into())?;

        Ok(Self {
            tcp,
            acceptor,
            conn_rate: ConnRateLimiter::new(CONN_RATE_LIMIT, CONN_RATE_WINDOW),
        })
    }

    /// Return the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.tcp
            .local_addr()
            .map_err(|e| TransportError::Other(e.to_string()).into())
    }

    /// Accept the next mTLS-authenticated connection.
    ///
    /// Returns `None` if the TLS handshake fails, the client certificate
    /// cannot be validated, or the IP is rate-limited. Callers should
    /// retry on `None`.
    pub async fn accept(&self) -> Result<Option<MqttPreSession>> {
        let (tcp_stream, peer_addr) = self.tcp.accept().await?;

        // Per-IP connection rate limiting to mitigate slow-handshake DoS.
        if self.conn_rate.is_limited(peer_addr.ip()) {
            warn!(
                peer = %peer_addr,
                "MQTT connection rejected: rate limit exceeded for IP"
            );
            drop(tcp_stream);
            return Ok(None);
        }

        configure_tactical_socket(&tcp_stream);

        let tls_result =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(tcp_stream)).await;

        let tls_stream = match tls_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                return Ok(None);
            }
            Err(_) => {
                warn!(peer = %peer_addr, "TLS handshake timed out");
                return Ok(None);
            }
        };

        let identity = match extract_client_identity(&tls_stream) {
            Ok(id) => Arc::new(id),
            Err(e) => {
                warn!(peer = %peer_addr, error = %e, "failed to extract identity");
                return Ok(None);
            }
        };

        debug!(
            peer = %peer_addr,
            cn = %identity.cn,
            groups = ?identity.groups,
            "MQTT client authenticated"
        );

        Ok(Some(MqttPreSession {
            identity,
            stream: tls_stream,
            peer_addr,
        }))
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
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use rustgate_test_utils::certs::TestCa;

    use super::*;

    // ------------------------------------------------------------------
    // These tests exercise the bind / local_addr / Debug surface of the
    // listener without driving real TLS handshakes — the integration
    // suite under `tests/mqtt_integration.rs` already covers the
    // handshake + CONNECT path end-to-end, so here we pin the
    // socket-level invariants (SO_REUSEADDR, port release on drop,
    // EADDRINUSE propagation) and the operator-visible Debug shape.
    // ------------------------------------------------------------------

    /// Build a server-side `TlsConfig` using a throw-away test CA.
    fn test_tls_config() -> TlsConfig {
        let ca = TestCa::new("mqtt-listener-test");
        let server = ca.issue_server_cert("localhost", &["localhost"]);
        TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
            .expect("build TlsConfig from freshly issued test certs")
    }

    fn loopback_zero() -> SocketAddr {
        "127.0.0.1:0"
            .parse()
            .expect("static loopback address must parse")
    }

    // ------------------------------------------------------------------
    // bind(…) happy path + local_addr
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn bind_to_loopback_zero_succeeds() {
        let listener = MqttListener::bind(loopback_zero(), &test_tls_config())
            .expect("bind to 127.0.0.1:0 should succeed");
        // Just holding `listener` long enough to drop here proves the
        // full bind→listen→from_std chain does not panic on a clean host.
        drop(listener);
    }

    #[tokio::test]
    async fn local_addr_returns_non_zero_port() {
        let listener = MqttListener::bind(loopback_zero(), &test_tls_config()).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        assert!(
            addr.port() != 0,
            "kernel should have assigned a concrete ephemeral port, got {addr}",
        );
    }

    #[tokio::test]
    async fn local_addr_ip_is_loopback() {
        let listener = MqttListener::bind(loopback_zero(), &test_tls_config()).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        assert!(
            addr.ip().is_loopback(),
            "bound IP should be loopback, got {}",
            addr.ip(),
        );
    }

    #[tokio::test]
    async fn two_listeners_on_different_ports_coexist() {
        // Proves the builder is not accidentally stateful — each call
        // yields a fresh socket, independently accepting on its own
        // port.
        let tls = test_tls_config();
        let a = MqttListener::bind(loopback_zero(), &tls).expect("bind a");
        let b = MqttListener::bind(loopback_zero(), &tls).expect("bind b");
        let addr_a = a.local_addr().expect("local_addr a");
        let addr_b = b.local_addr().expect("local_addr b");
        assert_ne!(
            addr_a.port(),
            addr_b.port(),
            "two concurrent binds to 0 should get distinct ports",
        );
    }

    // ------------------------------------------------------------------
    // Error path: EADDRINUSE when the port is actively held.
    // SO_REUSEADDR allows rebinding to a TIME_WAIT socket, but it does
    // NOT let two live listeners share the same (addr, port) — that
    // requires SO_REUSEPORT, which the listener intentionally does not
    // enable.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn second_bind_to_same_port_fails_while_first_is_alive() {
        let tls = test_tls_config();
        let first = MqttListener::bind(loopback_zero(), &tls).expect("first bind");
        let addr = first.local_addr().expect("local_addr");

        // Second bind MUST fail while `first` is still alive.
        let second = MqttListener::bind(addr, &tls);
        assert!(
            second.is_err(),
            "second bind to {addr} while first is alive must fail (EADDRINUSE), \
             but succeeded — SO_REUSEPORT must not be enabled",
        );
    }

    // ------------------------------------------------------------------
    // SO_REUSEADDR behaviour: after the first listener drops, rebinding
    // to the same concrete port works. Without the set_reuse_address
    // call this can race with lingering kernel state on some platforms.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn port_is_released_on_drop_and_can_be_rebound() {
        let tls = test_tls_config();
        let first = MqttListener::bind(loopback_zero(), &tls).expect("first bind");
        let addr = first.local_addr().expect("local_addr");
        drop(first);

        // Rebinding to the exact same (addr, port) must succeed — this
        // is the user-visible outcome of set_reuse_address(true) in the
        // bind path.
        let second = MqttListener::bind(addr, &tls).expect("second bind after drop");
        let addr2 = second.local_addr().expect("local_addr");
        assert_eq!(
            addr, addr2,
            "rebound listener should report the same port as the dropped one",
        );
    }

    // ------------------------------------------------------------------
    // Debug impl — stabilised shape for operator log lines. The listener
    // ends up printed by `tracing::info!(?listener, …)` on startup, so
    // drift here is visible to operators.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn debug_impl_renders_type_name() {
        let listener = MqttListener::bind(loopback_zero(), &test_tls_config()).expect("bind");
        let rendered = format!("{listener:?}");
        assert!(
            rendered.contains("MqttListener"),
            "Debug should mention the type name; got: {rendered}",
        );
    }

    #[tokio::test]
    async fn debug_impl_includes_local_addr_field() {
        let listener = MqttListener::bind(loopback_zero(), &test_tls_config()).expect("bind");
        let rendered = format!("{listener:?}");
        assert!(
            rendered.contains("local_addr"),
            "Debug should include the local_addr field; got: {rendered}",
        );
        assert!(
            rendered.contains("conn_rate"),
            "Debug should include the conn_rate field; got: {rendered}",
        );
    }

    #[tokio::test]
    async fn debug_impl_includes_bound_port_value() {
        let listener = MqttListener::bind(loopback_zero(), &test_tls_config()).expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let rendered = format!("{listener:?}");
        assert!(
            rendered.contains(&port.to_string()),
            "Debug output should embed the concrete bound port {port}; got: {rendered}",
        );
    }

    // ------------------------------------------------------------------
    // Type-surface checks (compile-time only).
    // ------------------------------------------------------------------

    #[test]
    fn pre_session_is_debug() {
        // `MqttPreSession` is printed by `tracing::debug!(?pre_session, …)`
        // in the accept loop before it is converted into a full session
        // object; losing the derive would silently break that diagnostic.
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<MqttPreSession>();
    }
}
