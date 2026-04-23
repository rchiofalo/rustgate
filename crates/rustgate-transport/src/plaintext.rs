// Copyright © 2026 Roberto Chiofalo.

//! Plaintext TCP listener for trusted/air-gapped networks.
//!
//! Accepts TCP connections without TLS. Each connection is assigned a
//! configurable anonymous identity (default CN `anonymous`, default group
//! `__plaintext__`). This is strictly opt-in and logs a prominent warning
//! when started.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use rustgate_core::constants::{ANONYMOUS_IDENTITY, PLAINTEXT_GROUP};
use rustgate_core::error::{Result, TransportError};
use rustgate_core::identity::Identity;
use rustgate_core::net::configure_tactical_socket;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tracing::{debug, warn};

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
            cn: ANONYMOUS_IDENTITY.to_string(),
            default_group: PLAINTEXT_GROUP.to_string(),
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
            .map_err(|e| TransportError::Other(format!("failed to get local address: {e}")).into())
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

            configure_tactical_socket(&tcp_stream);

            debug!(peer_addr = %peer_addr, "plaintext TCP connection accepted");

            let cn = format!("{}-{}", self.identity_config.cn, peer_addr);
            let mut groups = BTreeSet::new();
            let _ = groups.insert(self.identity_config.default_group.clone());

            let identity = Identity::plaintext(cn, groups).map_err(|e| {
                TransportError::Other(format!("invalid plaintext identity for {peer_addr}: {e}"))
            })?;

            return Ok(PlaintextSession {
                identity,
                peer_addr,
                stream: tcp_stream,
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn default_identity_config() {
        let cfg = PlaintextIdentityConfig::default();
        assert_eq!(cfg.cn, "anonymous");
        assert_eq!(cfg.default_group, "__plaintext__");
    }

    #[test]
    fn default_identity_config_matches_core_constants() {
        // Regression sentinel: `Default` must delegate to the canonical
        // `rustgate_core::constants` values rather than inline literals.
        // If either constant is renamed or the defaults drift, other crates
        // (router, ACL, audit log filters) that key on the exact strings
        // `"anonymous"` / `"__plaintext__"` would silently stop matching
        // plaintext sessions. Pin the exact-equality to the re-exported
        // constants to fail fast when they are altered.
        let cfg = PlaintextIdentityConfig::default();
        assert_eq!(cfg.cn, ANONYMOUS_IDENTITY);
        assert_eq!(cfg.default_group, PLAINTEXT_GROUP);
    }

    #[test]
    fn identity_config_clone_produces_independent_copy() {
        // `PlaintextIdentityConfig` derives `Clone`; pin that the clone
        // yields independent owned Strings so mutating one does not
        // alias the other. Config is cloned into the listener at bind
        // time — if `Clone` were ever switched to a shared `Arc`, later
        // mutations to the source would unexpectedly affect sessions.
        let mut cfg = PlaintextIdentityConfig {
            cn: "original-cn".to_string(),
            default_group: "original-group".to_string(),
        };
        let cloned = cfg.clone();
        cfg.cn = "mutated".to_string();
        cfg.default_group = "mutated".to_string();
        assert_eq!(cloned.cn, "original-cn");
        assert_eq!(cloned.default_group, "original-group");
    }

    #[test]
    fn identity_config_debug_exposes_fields() {
        // `PlaintextIdentityConfig` derives `Debug`. Pin that both fields
        // appear in the rendered output — operators rely on the derived
        // struct rendering when logging `listener.identity_config` during
        // startup diagnostics. Dropping `Debug` or hiding fields would
        // make incident triage harder.
        let cfg = PlaintextIdentityConfig {
            cn: "mesh-node".to_string(),
            default_group: "trusted-lan".to_string(),
        };
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("PlaintextIdentityConfig"), "{dbg}");
        assert!(dbg.contains("mesh-node"), "{dbg}");
        assert!(dbg.contains("trusted-lan"), "{dbg}");
    }

    #[tokio::test]
    async fn listener_debug_includes_type_name_and_config() {
        // Custom `Debug` impl on `PlaintextListener` must include the
        // type name and the identity config — without this, the struct
        // would render as opaque in `tracing::debug!` events during
        // listener lifecycle audits. Regression guard for the manual
        // `fmt` implementation.
        let cfg = PlaintextIdentityConfig::default();
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let dbg = format!("{listener:?}");
        assert!(dbg.contains("PlaintextListener"), "{dbg}");
        assert!(dbg.contains("identity_config"), "{dbg}");
    }

    #[tokio::test]
    async fn session_derives_debug() {
        // `PlaintextSession` derives `Debug`; pin the derive so the
        // struct can be logged without forcing callers to gate on a
        // feature flag. Removing the derive would break downstream
        // `#[derive(Debug)]` wrappers that hold a `PlaintextSession`.
        let cfg = PlaintextIdentityConfig::default();
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });
        let session = listener.accept().await.expect("accept");
        let dbg = format!("{session:?}");
        assert!(dbg.contains("PlaintextSession"), "{dbg}");
        assert!(
            dbg.contains("identity"),
            "Debug should expose identity field: {dbg}"
        );
        let _c = client.await.expect("join");
    }

    #[tokio::test]
    async fn session_peer_addr_matches_client_local_addr() {
        // `PlaintextSession::peer_addr()` must report the client's local
        // socket address (the accepted endpoint), not the listener's
        // bind address. Audit code keys off `peer_addr` to log which
        // client attempted the connection; an inverted value would
        // point every event at the server itself.
        let cfg = PlaintextIdentityConfig::default();
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let server_addr = listener.local_addr().expect("local_addr");

        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(server_addr).await.expect("connect");
            let client_local = stream.local_addr().expect("client local");
            (stream, client_local)
        });

        let session = listener.accept().await.expect("accept");
        let (_client_stream, client_local) = client.await.expect("join");

        assert_eq!(
            session.peer_addr(),
            client_local,
            "session.peer_addr() should match the client's local address"
        );
        assert_ne!(
            session.peer_addr(),
            server_addr,
            "session.peer_addr() must never equal the listener bind address"
        );
    }

    #[tokio::test]
    async fn session_identity_fingerprint_is_empty_string_for_plaintext() {
        // `Identity::plaintext` documents that the fingerprint is the
        // empty string (not "none", not the literal "plaintext"). Router
        // and audit code uses `fingerprint.is_empty()` to distinguish
        // TLS from non-TLS sessions. Pinning exact emptiness prevents
        // a future refactor from sneaking in a sentinel string that
        // would defeat those checks.
        let cfg = PlaintextIdentityConfig::default();
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });
        let session = listener.accept().await.expect("accept");
        assert_eq!(session.identity().fingerprint, "");
        assert!(session.identity().fingerprint.is_empty());
        let _c = client.await.expect("join");
    }

    #[tokio::test]
    async fn session_identity_groups_contain_only_default_group() {
        // The accept path seeds the identity with exactly one group —
        // the configured `default_group`. If a future change accidentally
        // added multiple groups (e.g. ANONYMOUS_IDENTITY plus
        // PLAINTEXT_GROUP), plaintext sessions would gain unintended
        // ACL surface. Pin the set size and membership.
        let cfg = PlaintextIdentityConfig {
            cn: "radio".to_string(),
            default_group: "sole-group".to_string(),
        };
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });
        let session = listener.accept().await.expect("accept");
        assert_eq!(session.identity().groups.len(), 1);
        assert!(session.identity().groups.contains("sole-group"));
        let _c = client.await.expect("join");
    }

    #[tokio::test]
    async fn session_cn_is_unique_for_concurrent_connections() {
        // The CN is built as `{configured_cn}-{peer_addr}`. Two concurrent
        // clients from different source ports must receive distinct CNs —
        // otherwise ACL/audit logs would conflate sessions and
        // deduplication caches could silently swallow messages from the
        // "second" client. Pin the disambiguation invariant.
        let cfg = PlaintextIdentityConfig::default();
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client_a = tokio::spawn(async move { TcpStream::connect(addr).await.expect("ca") });
        let session_a = listener.accept().await.expect("accept a");
        let client_b = tokio::spawn(async move { TcpStream::connect(addr).await.expect("cb") });
        let session_b = listener.accept().await.expect("accept b");

        assert_ne!(
            session_a.identity().cn,
            session_b.identity().cn,
            "concurrent plaintext sessions must have distinct CNs"
        );
        assert!(session_a.identity().cn.starts_with("anonymous-"));
        assert!(session_b.identity().cn.starts_with("anonymous-"));

        let _a = client_a.await.expect("join a");
        let _b = client_b.await.expect("join b");
    }

    #[tokio::test]
    async fn session_into_split_round_trips_payload() {
        // `PlaintextSession::into_split()` yields tokio read/write halves
        // of the underlying stream. Pin that the split actually produces
        // usable halves by round-tripping a small payload — a regression
        // that swapped the halves or consumed the stream would be caught
        // here. This is end-to-end: server writes, client reads.
        let cfg = PlaintextIdentityConfig::default();
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            let mut buf = [0u8; 5];
            let _ = stream.read_exact(&mut buf).await.expect("read");
            buf
        });

        let session = listener.accept().await.expect("accept");
        let (_read_half, mut write_half) = session.into_split();
        write_half.write_all(b"HELLO").await.expect("write");
        write_half.flush().await.expect("flush");
        drop(write_half);

        let received = client.await.expect("join");
        assert_eq!(&received, b"HELLO");
    }

    #[tokio::test]
    async fn listener_local_addr_reports_ephemeral_port() {
        // Binding to port `0` must produce a concrete ephemeral port
        // via `local_addr()`. Tests and service discovery rely on this
        // to publish the actual listening address — returning `0` back
        // would make those advertisements useless.
        let cfg = PlaintextIdentityConfig::default();
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        assert!(addr.ip().is_loopback());
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn listener_accepts_multiple_sequential_connections() {
        // After accepting one connection, the listener must remain
        // usable for subsequent accepts. A regression that closed or
        // consumed the underlying `TcpListener` after the first accept
        // would make the server single-shot — pin the reusability.
        let cfg = PlaintextIdentityConfig::default();
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        for _ in 0..3 {
            let client =
                tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });
            let session = listener.accept().await.expect("accept");
            assert!(session.identity().cn.starts_with("anonymous-"));
            let _c = client.await.expect("join");
        }
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
    async fn accepted_socket_has_tcp_nodelay_set() {
        // F-151 / #745 — `configure_tactical_socket` must leave
        // `TCP_NODELAY = 1` on the accepted end. A regression that drops
        // Nagle-disable would silently reintroduce a 40 ms latency
        // penalty on small tactical messages; assert it end-to-end.
        let cfg = PlaintextIdentityConfig::default();
        let listener = PlaintextListener::bind("127.0.0.1:0", cfg)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });

        let session = listener.accept().await.expect("accept");
        let nodelay = socket2::SockRef::from(&session.stream)
            .tcp_nodelay()
            .expect("tcp_nodelay readable");
        assert!(nodelay, "accepted socket should have TCP_NODELAY set");

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
