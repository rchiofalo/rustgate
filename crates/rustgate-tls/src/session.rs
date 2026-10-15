// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Authenticated TLS session.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustgate_core::identity::Identity;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

#[derive(Debug)]
pub struct AuthenticatedSession {
    identity: Arc<Identity>,
    peer_addr: SocketAddr,
    stream: TlsStream<TcpStream>,
}

impl AuthenticatedSession {
    pub(crate) fn new(
        identity: Identity,
        peer_addr: SocketAddr,
        stream: TlsStream<TcpStream>,
    ) -> Self {
        Self {
            identity: Arc::new(identity),
            peer_addr,
            stream,
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn identity_arc(&self) -> Arc<Identity> {
        Arc::clone(&self.identity)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn split(self) -> (SessionReader, SessionWriter) {
        let (read_half, write_half) = tokio::io::split(self.stream);
        (
            SessionReader {
                inner: read_half,
                identity: Arc::clone(&self.identity),
            },
            SessionWriter {
                inner: write_half,
                identity: self.identity,
            },
        )
    }
}

impl AsyncRead for AuthenticatedSession {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for AuthenticatedSession {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub struct SessionReader {
    inner: tokio::io::ReadHalf<TlsStream<TcpStream>>,
    identity: Arc<Identity>,
}

impl SessionReader {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}

impl AsyncRead for SessionReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[derive(Debug)]
pub struct SessionWriter {
    inner: tokio::io::WriteHalf<TlsStream<TcpStream>>,
    identity: Arc<Identity>,
}

impl SessionWriter {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}

impl AsyncWrite for SessionWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use rustgate_core::net::configure_tactical_socket;
    use rustgate_test_utils::certs::TestCa;
    use rustgate_test_utils::tls::build_client_tls_config;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;
    use crate::config::TlsConfig;
    use crate::extract::extract_identity;

    /// Drive a local client↔server TLS handshake and return a fully-authenticated
    /// server-side session plus a handle for the client half so the caller can
    /// keep the TLS connection alive for the duration of a test. Dropping the
    /// returned client stream closes the underlying TCP connection, which is
    /// fine — every test here inspects only the server-side metadata and never
    /// reads/writes through the stream.
    async fn establish_test_session(
        client_cn: &str,
        client_groups: &[&str],
    ) -> (
        AuthenticatedSession,
        SocketAddr,
        tokio_rustls::client::TlsStream<TcpStream>,
    ) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let ca = TestCa::new("session-test-ca");
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
        let client_cert = ca.issue_client_cert(client_cn, client_groups);

        let tls_config =
            TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem).unwrap();
        let server_config = tls_config.build_server_config().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let client_config =
            build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
        let connector = TlsConnector::from(Arc::new(client_config));

        let client_handle = tokio::spawn(async move {
            let tcp = TcpStream::connect(server_addr).await.unwrap();
            let server_name = "localhost".try_into().unwrap();
            connector.connect(server_name, tcp).await.unwrap()
        });

        let (tcp, peer_addr) = listener.accept().await.unwrap();
        // Mirror `TlsListener::accept` — the shared-infrastructure check
        // enforces that any file touching `TcpListener` routes accepted
        // streams through `rustgate_core::net`'s socket-hardening helper.
        configure_tactical_socket(&tcp);
        let tls_stream = acceptor.accept(tcp).await.unwrap();
        let client_stream = client_handle.await.unwrap();

        let certs = tls_stream.get_ref().1.peer_certificates().unwrap();
        let identity = extract_identity(certs.first().unwrap()).unwrap();

        let session = AuthenticatedSession::new(identity, peer_addr, tls_stream);
        (session, peer_addr, client_stream)
    }

    #[tokio::test]
    async fn identity_exposes_cn_from_client_cert() {
        let (session, _peer, _client) = establish_test_session("route-client", &["alpha"]).await;
        assert_eq!(&*session.identity().cn, "route-client");
    }

    #[tokio::test]
    async fn identity_exposes_groups_from_client_cert() {
        let (session, _peer, _client) =
            establish_test_session("route-client", &["alpha", "bravo"]).await;
        assert!(session.identity().groups.contains("alpha"));
        assert!(session.identity().groups.contains("bravo"));
    }

    #[tokio::test]
    async fn identity_arc_returns_shared_pointer_to_stored_identity() {
        // identity() hands out a borrow; identity_arc() hands out a clone. The
        // clone must point at the same allocation so session-scoped state can be
        // shared cheaply across tasks (e.g. the router's per-session routing
        // context holds an Arc<Identity>).
        let (session, _peer, _client) = establish_test_session("arc-client", &["grp"]).await;
        let arc_a = session.identity_arc();
        let arc_b = session.identity_arc();
        assert!(Arc::ptr_eq(&arc_a, &arc_b));
        assert_eq!(&*arc_a.cn, "arc-client");
    }

    #[tokio::test]
    async fn peer_addr_matches_accepted_tcp_peer() {
        let (session, peer_addr, _client) = establish_test_session("peer-client", &["grp"]).await;
        assert_eq!(session.peer_addr(), peer_addr);
        assert!(session.peer_addr().ip().is_loopback());
    }

    #[tokio::test]
    async fn split_produces_reader_and_writer_sharing_identity() {
        // split() hands the read/write halves to independent tasks in the real
        // server. Both halves must observe the same `Identity` — a regression
        // that handed each half a freshly-cloned Identity would silently break
        // ACL enforcement on the write path.
        let (session, _peer, _client) = establish_test_session("split-client", &["shared"]).await;
        let (reader, writer) = session.split();
        assert_eq!(&*reader.identity().cn, "split-client");
        assert_eq!(&*writer.identity().cn, "split-client");
        assert!(reader.identity().groups.contains("shared"));
        assert!(writer.identity().groups.contains("shared"));
    }

    #[tokio::test]
    async fn split_halves_observe_same_identity_allocation() {
        // Pin the Arc-sharing contract of split(): reader and writer must hold
        // clones of the same `Arc<Identity>`, not two independently-allocated
        // copies. We can't take `Arc::ptr_eq` across the accessor because the
        // accessor only exposes `&Identity`, so we use strong-count semantics
        // via a separately-obtained third clone before split, then drop that
        // clone and verify count after split.
        let (session, _peer, _client) = establish_test_session("alloc-client", &["grp"]).await;
        let pre_split_arc = session.identity_arc();
        // Strong count is at least 2: session + pre_split_arc.
        let count_before = Arc::strong_count(&pre_split_arc);
        assert!(count_before >= 2);
        let (reader, writer) = session.split();
        // After split: pre_split_arc + reader's arc + writer's arc = at least 3.
        let count_after = Arc::strong_count(&pre_split_arc);
        assert!(
            count_after >= 3,
            "expected reader+writer to hold same Arc allocation (count_after={count_after})"
        );
        // Keep reader/writer alive until here so the count reflects them.
        drop((reader, writer));
    }

    #[tokio::test]
    async fn debug_impl_renders_authenticated_session_type() {
        // Debug is used by `tracing::info!(?session, …)` in the accept loop; a
        // refactor that removed the derive would silently drop session metadata
        // from every structured log line.
        let (session, _peer, _client) = establish_test_session("dbg-client", &["g"]).await;
        let rendered = format!("{session:?}");
        assert!(
            rendered.contains("AuthenticatedSession"),
            "debug output missing type name: {rendered}"
        );
    }

    #[tokio::test]
    async fn debug_impl_renders_session_reader_type() {
        let (session, _peer, _client) = establish_test_session("dbg-client", &["g"]).await;
        let (reader, _writer) = session.split();
        let rendered = format!("{reader:?}");
        assert!(
            rendered.contains("SessionReader"),
            "debug output missing type name: {rendered}"
        );
    }

    #[tokio::test]
    async fn debug_impl_renders_session_writer_type() {
        let (session, _peer, _client) = establish_test_session("dbg-client", &["g"]).await;
        let (_reader, writer) = session.split();
        let rendered = format!("{writer:?}");
        assert!(
            rendered.contains("SessionWriter"),
            "debug output missing type name: {rendered}"
        );
    }

    #[test]
    fn session_types_implement_async_traits() {
        // Compile-time contract: each type must keep its tokio-io trait bound so
        // it can flow into `tokio::io::copy`, framed codecs, or the router's
        // session loop. A refactor that dropped AsyncRead for AuthenticatedSession
        // (say, by making the TlsStream `pub`) would silently break every caller.
        fn assert_async_read<T: tokio::io::AsyncRead>() {}
        fn assert_async_write<T: tokio::io::AsyncWrite>() {}
        assert_async_read::<AuthenticatedSession>();
        assert_async_write::<AuthenticatedSession>();
        assert_async_read::<SessionReader>();
        assert_async_write::<SessionWriter>();
    }

    #[test]
    fn session_types_are_debug() {
        // Pin `Debug` at the type level so `tracing::info!(?session, …)` sites
        // keep compiling. Redundant with the value-level tests above, but fails
        // earlier (at type-check time) and documents the invariant.
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<AuthenticatedSession>();
        assert_debug::<SessionReader>();
        assert_debug::<SessionWriter>();
    }
}
