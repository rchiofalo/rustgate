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

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustgate_core::constants::HANDSHAKE_TIMEOUT;
use rustgate_core::error::{Result, TransportError};
use rustgate_core::identity::Identity;
use rustgate_core::net::configure_tcp_keepalive;
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

/// Number of tracked IPs that triggers an inline sweep of stale entries.
const CONN_RATE_SWEEP_THRESHOLD: usize = 512;

/// Per-IP connection attempt tracking for DoS mitigation.
#[derive(Debug)]
struct ConnRateState {
    map: HashMap<IpAddr, VecDeque<Instant>>,
    last_sweep: Instant,
}

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
    conn_rate: Mutex<ConnRateState>,
}

impl std::fmt::Debug for MqttListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MqttListener")
            .field("local_addr", &self.tcp.local_addr())
            .field("conn_rate", &"<ConnRateState>")
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
            conn_rate: Mutex::new(ConnRateState {
                map: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        })
    }

    /// Check whether `ip` has exceeded the connection rate limit.
    ///
    /// Uses a sliding window of [`CONN_RATE_WINDOW`] seconds, rejecting IPs
    /// with [`CONN_RATE_LIMIT`] or more attempts in the window. Records the
    /// attempt timestamp when the IP is not rate-limited.
    ///
    /// Returns `true` if the IP is rate-limited, `false` otherwise.
    fn is_conn_rate_limited(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - CONN_RATE_WINDOW;

        let mut state = match self.conn_rate.lock() {
            Ok(s) => s,
            Err(e) => e.into_inner(),
        };

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

        while timestamps.front().is_some_and(|t| *t <= cutoff) {
            let _ = timestamps.pop_front();
        }

        if timestamps.len() >= CONN_RATE_LIMIT {
            return true;
        }

        timestamps.push_back(now);
        false
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
        if self.is_conn_rate_limited(peer_addr.ip()) {
            warn!(
                peer = %peer_addr,
                "MQTT connection rejected: rate limit exceeded for IP"
            );
            drop(tcp_stream);
            return Ok(None);
        }

        configure_tcp_keepalive(&tcp_stream);

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
