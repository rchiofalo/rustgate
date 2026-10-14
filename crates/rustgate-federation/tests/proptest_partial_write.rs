// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]

//! Partial-write proptest for the V1 federation length-prefixed
//! framing path (F-134, refs #789).
//!
//! V1 federation wraps its TLS stream in a `Framed<LengthPrefixedCodec>`
//! and writes complete length-prefixed frames via `Sink::send`. If the
//! underlying writer errors after only N of the L expected bytes have
//! reached the wire, the framing layer must surface a typed
//! [`std::io::Error`] (not a panic), and the receiver's parse buffer
//! must be clean — meaning a follow-up valid frame on a fresh stream
//! parses without inheriting the half-frame bytes.
//!
//! Why this is the right level of test:
//!
//! - The V1 federation client sits on top of `Framed<TlsStream,
//!   LengthPrefixedCodec>` and calls `Sink::send` per outbound message
//!   (`crates/rustgate-federation/src/v1/client.rs::run_session`). The
//!   reconnect logic in `run_session` matches the inner I/O error
//!   pattern via `FederationError::other(format!("..."))` and re-enters
//!   the connection loop. The test pins the documented invariant:
//!   any partial-write error surfaces as a typed `io::Error` from
//!   the framing layer, never as a panic, so the reconnect schedule
//!   is reachable.
//! - A test that drove the full reconnect loop with a duplex shim
//!   would also exercise the TLS handshake, the heartbeat task, and
//!   the watch-channel shutdown plumbing — all of which are covered
//!   by `chaos_network_partition.rs` and `v2_integration.rs`. The
//!   partial-write contract belongs at the codec/framed boundary.
//!
//! Two shapes are exercised:
//!
//! 1. **Random partial-write cutoff `N` from 1 to a frame size**.
//!    Each cutoff must produce a typed error and not a panic.
//! 2. **Buffer cleanliness** — after a partial-write failure on one
//!    `Framed`, a *fresh* `Framed` over a fresh duplex pair parses
//!    a follow-up valid frame cleanly. This pins the documented
//!    invariant that a partial frame in the writer's local buffer
//!    cannot leak into the next session's parse state.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use futures::SinkExt;
use futures::stream::StreamExt;
use proptest::prelude::*;
use rustgate_core::protocol::HeaderSize;
use rustgate_transport::LengthPrefixedCodec;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::Framed;

/// AsyncWrite shim that delegates the first `cutoff` bytes to its
/// inner stream and then fails every subsequent call with the
/// supplied [`io::ErrorKind`]. Mirrors the kind of partial-write
/// behaviour a flaky NIC, a TLS half-close, or a SO_SNDBUF stall
/// produces in the wild.
struct CutoffWriter<W> {
    inner: W,
    written: usize,
    cutoff: usize,
    error_kind: io::ErrorKind,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CutoffWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.written >= self.cutoff {
            return Poll::Ready(Err(io::Error::new(
                self.error_kind,
                "cutoff exceeded — simulated partial write",
            )));
        }
        let allowed = self.cutoff - self.written;
        let take = buf.len().min(allowed);
        let truncated = &buf[..take];
        match Pin::new(&mut self.inner).poll_write(cx, truncated) {
            Poll::Ready(Ok(n)) => {
                self.written += n;
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<W: AsyncRead + Unpin> AsyncRead for CutoffWriter<W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

const FRAME_PAYLOAD: &[u8] = b"<event uid='probe'/>";
/// Total bytes a complete length-prefixed frame produces with a 4-byte
/// header — header + payload.
const FULL_FRAME_BYTES: usize = 4 + FRAME_PAYLOAD.len();

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Random cutoff between 1 and `FULL_FRAME_BYTES - 1` — any
    /// partial-write that does not let the full frame through must
    /// surface a typed [`io::Error`]. A panic here would mean a
    /// flaky TLS write could take down the federation client task
    /// instead of triggering its reconnect logic.
    #[test]
    fn partial_write_surfaces_typed_io_error(cutoff in 1usize..FULL_FRAME_BYTES) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let (writer_inner, _reader) = tokio::io::duplex(64 * 1024);
            let cutoff_writer = CutoffWriter {
                inner: writer_inner,
                written: 0,
                cutoff,
                error_kind: io::ErrorKind::WriteZero,
            };
            let mut framed = Framed::new(cutoff_writer, LengthPrefixedCodec::new(HeaderSize::Four));
            let result = framed.send(BytesMut::from(FRAME_PAYLOAD)).await;
            prop_assert!(
                result.is_err(),
                "partial write at cutoff {cutoff} must surface as a typed error from Framed::send"
            );
            // The error type is `io::Error` — pinning the type here
            // catches a regression where the codec's `Encoder::Error`
            // changed to a bare `String` or `()`.
            let err = result.unwrap_err();
            prop_assert!(
                err.kind() == io::ErrorKind::WriteZero
                    || err.kind() == io::ErrorKind::BrokenPipe
                    || err.kind() == io::ErrorKind::UnexpectedEof,
                "expected WriteZero/BrokenPipe/UnexpectedEof error kind, got {:?}",
                err.kind()
            );
            Ok(())
        })?;
    }
}

/// After a partial-write error on one stream, a *fresh* duplex pair
/// must parse a follow-up valid frame cleanly. The pin: a partial
/// frame in the previous writer's buffer cannot leak into the next
/// session's parse state. This is the documented invariant the V1
/// reconnect path relies on — every reconnect mints a fresh
/// `Framed`, and the parse buffer for that fresh `Framed` is local.
#[tokio::test]
async fn fresh_stream_parses_after_partial_write_failure() {
    // Step 1: partial-write a frame, observe the typed error.
    let (writer_inner, _ignored_reader) = tokio::io::duplex(64 * 1024);
    let cutoff_writer = CutoffWriter {
        inner: writer_inner,
        written: 0,
        cutoff: 3, // header is 4 bytes — abort halfway through the header.
        error_kind: io::ErrorKind::BrokenPipe,
    };
    let mut framed_failed = Framed::new(cutoff_writer, LengthPrefixedCodec::new(HeaderSize::Four));
    let send_result = framed_failed.send(BytesMut::from(FRAME_PAYLOAD)).await;
    assert!(
        send_result.is_err(),
        "partial write must surface as a typed error"
    );

    // Step 2: a fresh duplex pair + fresh `Framed` parses the next
    // valid frame cleanly. If the codec or `Framed`'s internal write
    // buffer leaked across instances we would get an
    // `UnexpectedEof`/`InvalidData` here from the corrupted prefix.
    let (writer_inner_fresh, reader_inner_fresh) = tokio::io::duplex(64 * 1024);
    let mut framed_writer = Framed::new(
        writer_inner_fresh,
        LengthPrefixedCodec::new(HeaderSize::Four),
    );
    let mut framed_reader = Framed::new(
        reader_inner_fresh,
        LengthPrefixedCodec::new(HeaderSize::Four),
    );

    framed_writer
        .send(BytesMut::from(FRAME_PAYLOAD))
        .await
        .expect("fresh stream must accept a valid frame");

    let received = tokio::time::timeout(std::time::Duration::from_secs(2), framed_reader.next())
        .await
        .expect("fresh stream parse timeout")
        .expect("fresh stream must yield a frame")
        .expect("fresh frame must parse without an io error");
    assert_eq!(
        received.as_ref(),
        FRAME_PAYLOAD,
        "follow-up valid frame on fresh stream must parse byte-for-byte"
    );
}

/// Partial-write at cutoff = 0 — every write attempt fails
/// immediately. This is the worst-case partial-write shape. The test
/// pins the contract that even with a writer that produces zero
/// bytes total, [`Framed::send`] surfaces a typed [`io::Error`]
/// rather than spinning or panicking.
#[tokio::test]
async fn zero_byte_writer_surfaces_typed_io_error() {
    let (writer_inner, _reader) = tokio::io::duplex(64 * 1024);
    let cutoff_writer = CutoffWriter {
        inner: writer_inner,
        written: 0,
        cutoff: 0,
        error_kind: io::ErrorKind::BrokenPipe,
    };
    let mut framed = Framed::new(cutoff_writer, LengthPrefixedCodec::new(HeaderSize::Four));
    let err = framed
        .send(BytesMut::from(FRAME_PAYLOAD))
        .await
        .expect_err("zero-byte writer must surface a typed error");
    assert_eq!(
        err.kind(),
        io::ErrorKind::BrokenPipe,
        "zero-byte cutoff must propagate the configured error kind"
    );
}
