// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! TLS listener for accepting mTLS connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustgate_core::error::{Result, TransportError};
use rustgate_core::masking::hash_cn;
use rustgate_core::net::configure_tactical_socket;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument, debug, info, warn};

use crate::config::TlsConfig;
use crate::extract::{ExpectedKeyUsage, extract_identity_with_chain, validate_key_usage};
use crate::session::AuthenticatedSession;

rustgate_core::on_callback!(
    /// Callback invoked when a TLS handshake fails.
    ///
    /// Receives the peer address and the error message string, allowing the
    /// caller to classify and record the failure (e.g. for metrics).
    pub OnHandshakeError,
    SocketAddr,
    &str
);

rustgate_core::on_callback!(
    /// Callback invoked once each TLS handshake completes, regardless of outcome.
    ///
    /// Receives the elapsed handshake duration and an `outcome` label —
    /// `"success"` when the handshake produced a usable TLS stream, `"failure"`
    /// when the acceptor returned an error. Fired after identity extraction
    /// is *not* attempted; the boundary is the TLS layer, so a cert that fails
    /// downstream `extract_identity()` still counts as a `"success"` here.
    ///
    /// Intended for histogram observation (e.g. Prometheus
    /// `rustgate_tls_handshake_duration_seconds`). The callback must not block
    /// the accept loop — keep the observation cheap.
    pub OnHandshakeDuration,
    Duration,
    &str
);

/// Default maximum number of concurrent TLS handshakes when no limit is specified.
pub const DEFAULT_MAX_HANDSHAKES: usize = 100;

pub struct TlsListener {
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    /// Semaphore that limits the number of TLS handshakes in progress.
    /// Each handshake acquires a permit before starting and releases it
    /// once the handshake completes (successfully or not).
    handshake_semaphore: Arc<Semaphore>,
    /// Optional callback invoked on TLS handshake failures.
    on_handshake_error: Option<OnHandshakeError>,
    /// Optional callback invoked after every handshake attempt with the
    /// measured duration and an outcome label.
    on_handshake_duration: Option<OnHandshakeDuration>,
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
            on_handshake_error: None,
            on_handshake_duration: None,
        })
    }

    /// Register a callback invoked whenever a TLS handshake fails.
    ///
    /// The callback receives the peer address and the error message,
    /// allowing the caller to classify and record failure reasons
    /// (e.g. for Prometheus metrics).
    pub fn set_on_handshake_error(&mut self, cb: OnHandshakeError) {
        self.on_handshake_error = Some(cb);
    }

    /// Register a callback invoked after every handshake attempt with the
    /// measured duration and an outcome label (`"success"` / `"failure"`).
    ///
    /// Intended for histogram observation. Timing begins when the
    /// accept-loop starts the `TlsAcceptor::accept` future and ends when
    /// that future resolves, so the measurement captures the full TLS
    /// handshake round-trip but not the upstream TCP accept or the
    /// downstream identity-extraction work.
    pub fn set_on_handshake_duration(&mut self, cb: OnHandshakeDuration) {
        self.on_handshake_duration = Some(cb);
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
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn accept(&self) -> Result<AuthenticatedSession> {
        loop {
            let (tcp_stream, peer_addr) = match self.tcp_listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "TCP accept failed");
                    continue;
                }
            };

            configure_tactical_socket(&tcp_stream);

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

            let handshake_start = Instant::now();
            let tls_stream = match self
                .tls_acceptor
                .accept(tcp_stream)
                .instrument(tracing::info_span!("tls_handshake", peer_addr = %peer_addr))
                .await
            {
                Ok(stream) => {
                    if let Some(ref cb) = self.on_handshake_duration {
                        cb(handshake_start.elapsed(), "success");
                    }
                    stream
                }
                Err(e) => {
                    // Permit is released here when `_permit` is dropped.
                    let err_msg = e.to_string();
                    rustgate_core::audit::tls_accept_error(peer_addr, &err_msg);
                    if let Some(ref cb) = self.on_handshake_error {
                        cb(peer_addr, &err_msg);
                    }
                    if let Some(ref cb) = self.on_handshake_duration {
                        cb(handshake_start.elapsed(), "failure");
                    }
                    warn!(peer_addr = %peer_addr, error = %e, "TLS handshake failed");
                    continue;
                }
            };

            // _permit is released here by RAII when it goes out of scope.

            let kx_group = tls_stream
                .get_ref()
                .1
                .negotiated_key_exchange_group()
                .map(|g| g.name());
            debug!(peer_addr = %peer_addr, kx_group = ?kx_group, "TLS handshake completed");

            let identity = match Self::extract_client_identity(&tls_stream) {
                Ok(id) => id,
                Err(e) => {
                    warn!(peer_addr = %peer_addr, error = %e, "identity extraction failed");
                    return Err(e);
                }
            };

            debug!(
                peer_addr = %peer_addr,
                cn = %hash_cn(&identity.cn),
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

        extract_identity_with_chain(certs)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use rustgate_test_utils::certs::TestCa;

    use super::*;

    /// Install the default crypto provider (idempotent across tests) and
    /// build a minimal `TlsConfig` backed by a fresh in-memory CA.
    ///
    /// The tests here never complete a handshake — they only exercise
    /// `TlsListener`'s bind / local-addr / Debug surface — so the server
    /// cert just has to satisfy `TlsConfig::from_pem`.
    fn test_tls_config() -> TlsConfig {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = TestCa::new("listener-test-ca");
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
        TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
            .expect("tls config")
    }

    // ------------------------------------------------------------------
    // Module-level constants that operators size tactical deployments
    // against — pinned so a silent change to the default handshake
    // concurrency shows up as a test diff.
    // ------------------------------------------------------------------

    #[test]
    fn default_max_handshakes_constant_is_100() {
        // Also guards against dropping the public re-export; the constant
        // is documented as the default for `TlsListener::bind` so operators
        // can compare it to their deployment's `--max-handshakes`.
        assert_eq!(DEFAULT_MAX_HANDSHAKES, 100);
    }

    // ------------------------------------------------------------------
    // bind / bind_with_handshake_limit — the async entry points every
    // server wiring goes through on startup. We don't complete a
    // handshake here (the integration tests do) — we just prove bind
    // succeeds on loopback and surfaces the expected listener state.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn bind_succeeds_on_loopback_zero_port() {
        let tls = test_tls_config();
        let listener = TlsListener::bind("127.0.0.1:0", &tls).await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        assert!(
            addr.port() > 0,
            "expected a non-zero ephemeral port after binding to :0, got {addr}",
        );
    }

    #[tokio::test]
    async fn bind_default_listener_reports_default_permits() {
        // The Debug impl publishes `available_permits()`, which equals
        // the configured maximum while no handshakes are in flight —
        // use that to pin that `bind` really does wire through the
        // `DEFAULT_MAX_HANDSHAKES` constant rather than a magic number.
        let tls = test_tls_config();
        let listener = TlsListener::bind("127.0.0.1:0", &tls).await.expect("bind");
        let rendered = format!("{listener:?}");
        let expected = format!("max_concurrent_handshakes: {DEFAULT_MAX_HANDSHAKES}");
        assert!(
            rendered.contains(&expected),
            "Debug should reflect the default handshake limit `{expected}`; got: {rendered}",
        );
    }

    #[tokio::test]
    async fn bind_with_handshake_limit_applies_custom_value() {
        // Distinct from the default, to prove the custom value is not
        // silently coerced back to DEFAULT_MAX_HANDSHAKES on the way in.
        let tls = test_tls_config();
        let listener = TlsListener::bind_with_handshake_limit("127.0.0.1:0", &tls, 42)
            .await
            .expect("bind");
        let rendered = format!("{listener:?}");
        assert!(
            rendered.contains("max_concurrent_handshakes: 42"),
            "Debug should reflect the configured custom limit; got: {rendered}",
        );
    }

    #[tokio::test]
    async fn bind_with_handshake_limit_accepts_single_permit() {
        // Boundary: the `Semaphore::new(n)` contract allows `n == 1`
        // and downstream operators do use 1 for tests that want to
        // serialize TLS handshakes. A zero value is explicitly *not*
        // tested — the documented contract is "limits concurrent
        // handshakes" and the semaphore deadlocks the accept loop at 0;
        // that's a caller-side misconfiguration, not our invariant.
        let tls = test_tls_config();
        let listener = TlsListener::bind_with_handshake_limit("127.0.0.1:0", &tls, 1)
            .await
            .expect("bind");
        let rendered = format!("{listener:?}");
        assert!(
            rendered.contains("max_concurrent_handshakes: 1"),
            "Debug should reflect the single-permit limit; got: {rendered}",
        );
    }

    // ------------------------------------------------------------------
    // local_addr — used by every wiring site to log the bound endpoint
    // and by integration tests to discover the ephemeral port.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn local_addr_ip_is_loopback() {
        let tls = test_tls_config();
        let listener = TlsListener::bind("127.0.0.1:0", &tls).await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        assert!(
            addr.ip().is_loopback(),
            "expected loopback IP after binding to 127.0.0.1:0, got {addr}",
        );
    }

    #[tokio::test]
    async fn two_listeners_coexist_on_different_ephemeral_ports() {
        // The accept loop is per-listener, so two servers in the same
        // process must not collide on the kernel side. With both bound
        // to :0 the kernel assigns distinct ephemeral ports; if a
        // future refactor accidentally reused a socket the two
        // `local_addr` calls would collapse to the same port.
        let tls = test_tls_config();
        let first = TlsListener::bind("127.0.0.1:0", &tls)
            .await
            .expect("first bind");
        let second = TlsListener::bind("127.0.0.1:0", &tls)
            .await
            .expect("second bind");
        let first_addr = first.local_addr().expect("first addr");
        let second_addr = second.local_addr().expect("second addr");
        assert_ne!(
            first_addr.port(),
            second_addr.port(),
            "two simultaneous listeners must get distinct ephemeral ports",
        );
    }

    // ------------------------------------------------------------------
    // bind error path — the `map_err` wrap that translates a
    // tokio-level bind failure into `TransportError::Other`. A silently
    // unwrapped `io::Error` here would lose the "failed to bind TLS
    // listener" context operators rely on when triaging startup
    // failures.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn bind_wraps_tcp_bind_failure_with_context_prefix() {
        // Hold a synchronous std listener on an ephemeral port, then
        // try to bind our TLS listener to the exact same (addr, port).
        // On Linux/macOS without SO_REUSEPORT the kernel rejects the
        // second bind with EADDRINUSE; `tokio::net::TcpListener::bind`
        // does not set SO_REUSEPORT, so the second bind must fail.
        let blocker = std::net::TcpListener::bind("127.0.0.1:0").expect("blocker bind");
        let busy = blocker.local_addr().expect("blocker addr");

        let tls = test_tls_config();
        let result = TlsListener::bind(busy, &tls).await;
        let err = match result {
            Ok(_) => panic!("expected bind to fail on occupied port {}", busy.port()),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to bind TLS listener"),
            "error must carry the TransportError::Other context prefix so operators can triage bind failures; got: {msg}",
        );
    }

    // ------------------------------------------------------------------
    // Debug impl — rendered by `tracing::info!(?listener, …)` and
    // `tracing::debug!(?listener, …)` at startup and in the accept
    // loop. Drift here is visible to operators inspecting logs.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn debug_impl_renders_type_name() {
        let tls = test_tls_config();
        let listener = TlsListener::bind("127.0.0.1:0", &tls).await.expect("bind");
        let rendered = format!("{listener:?}");
        assert!(
            rendered.contains("TlsListener"),
            "Debug should mention the type name; got: {rendered}",
        );
    }

    #[tokio::test]
    async fn debug_impl_includes_bound_port_value() {
        // The tcp_listener field is printed via its own Debug impl,
        // which embeds the bound socket address. A future refactor
        // that drops the listener from the Debug output (e.g. because
        // someone decided it was noisy) would silently erase the
        // endpoint from startup logs; this guards against that.
        let tls = test_tls_config();
        let listener = TlsListener::bind("127.0.0.1:0", &tls).await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let rendered = format!("{listener:?}");
        assert!(
            rendered.contains(&port.to_string()),
            "Debug should embed the concrete bound port {port}; got: {rendered}",
        );
    }

    #[tokio::test]
    async fn debug_impl_redacts_tls_acceptor_as_placeholder() {
        // The acceptor carries the server's private key material via
        // the embedded `ServerConfig`. It must never be rendered by
        // Debug — the manual impl replaces it with a fixed
        // `"<TlsAcceptor>"` sentinel.
        let tls = test_tls_config();
        let listener = TlsListener::bind("127.0.0.1:0", &tls).await.expect("bind");
        let rendered = format!("{listener:?}");
        assert!(
            rendered.contains("<TlsAcceptor>"),
            "Debug must render TlsAcceptor as a redaction sentinel to keep server keys out of logs; got: {rendered}",
        );
    }

    #[tokio::test]
    async fn debug_impl_includes_max_concurrent_handshakes_field_name() {
        // The field name is the knob operators tune via
        // `--max-handshakes`; its presence in logs lets them verify at
        // runtime which limit the running process actually took.
        let tls = test_tls_config();
        let listener = TlsListener::bind("127.0.0.1:0", &tls).await.expect("bind");
        let rendered = format!("{listener:?}");
        assert!(
            rendered.contains("max_concurrent_handshakes"),
            "Debug should include the max_concurrent_handshakes field; got: {rendered}",
        );
    }

    // ------------------------------------------------------------------
    // set_on_handshake_error — the only mutable knob after construction.
    // We can't observe the stored closure without triggering a
    // handshake (that's the integration-test territory), but we can
    // prove the setter does not panic and returns `()`, and that
    // calling it twice overwrites rather than appending.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn set_on_handshake_error_accepts_and_overwrites_callback() {
        let tls = test_tls_config();
        let mut listener = TlsListener::bind("127.0.0.1:0", &tls).await.expect("bind");
        // First install — must not panic.
        let cb1: OnHandshakeError = Arc::new(|_addr, _msg| {});
        listener.set_on_handshake_error(cb1);
        // Second install — overwrites cleanly. A future refactor that
        // turned this into a `Vec<OnHandshakeError>` would silently
        // double-fire callbacks; Option-based storage forbids that.
        let cb2: OnHandshakeError = Arc::new(|_addr, _msg| {});
        listener.set_on_handshake_error(cb2);
    }

    // ------------------------------------------------------------------
    // set_on_handshake_duration — parallel to set_on_handshake_error.
    // We cannot observe the stored closure without completing a handshake
    // (covered in the rustgate-server integration wiring), but we prove
    // the setter accepts any correctly-typed Arc and that repeat installs
    // overwrite rather than accumulate — the same Option-based invariant
    // the error callback relies on.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn set_on_handshake_duration_accepts_and_overwrites_callback() {
        let tls = test_tls_config();
        let mut listener = TlsListener::bind("127.0.0.1:0", &tls).await.expect("bind");
        let cb1: OnHandshakeDuration = Arc::new(|_elapsed, _outcome| {});
        listener.set_on_handshake_duration(cb1);
        let cb2: OnHandshakeDuration = Arc::new(|_elapsed, _outcome| {});
        listener.set_on_handshake_duration(cb2);
    }

    #[test]
    fn on_handshake_duration_fn_is_send_sync_static() {
        // The callback is stored behind `Option<Arc<dyn Fn>>` and invoked
        // from the accept-loop task, so the alias must satisfy the trait
        // bounds the Arc holds (`Send + Sync + 'static`). If the type were
        // ever relaxed to not require one of those, wiring it from
        // `rustgate-server::setup.rs` would stop compiling; pin here to
        // catch it before it reaches downstream crates.
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<OnHandshakeDuration>();
    }

    // ------------------------------------------------------------------
    // Type-surface checks (compile-time only). `tracing::info!(?x, …)`
    // is wired at construction sites and would break at `cargo build`
    // if the derive were ever dropped — faster to catch here than via
    // a downstream build break.
    // ------------------------------------------------------------------

    #[test]
    fn tls_listener_is_debug() {
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<TlsListener>();
    }
}
