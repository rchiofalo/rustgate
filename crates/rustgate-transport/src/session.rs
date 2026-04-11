// Copyright © 2026 Roberto Chiofalo.

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
