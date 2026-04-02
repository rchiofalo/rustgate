//! Session handling for connected clients.
//!
//! Contains the TLS session lifecycle (handshake, read/write loops, protocol
//! negotiation), the plaintext TCP accept loop, and the `NatsPublish` trait
//! that abstracts over optional NATS support.

use std::sync::Arc;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use rustgate_core::constants::{READ_TIMEOUT, WRITE_TIMEOUT};
use rustgate_core::identity::Identity;
#[cfg(any(feature = "metrics", feature = "federation"))]
use rustgate_core::message::Destination;
use rustgate_core::message::RoutableMessage;
use rustgate_core::protocol::FramingStrategy;
use rustgate_cot::MessageBuilder;
use rustgate_transport::{
    AuthenticatedSession, CotEncoder, FramedCodec, MessageEncoder, RawEncoder, Router,
    SessionHandle, ThrottleConfig,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::archive;
use crate::cli::{Encoding, Framing};
#[cfg(feature = "metrics")]
use crate::metrics;

/// Optional callback for forwarding messages to federation peers.
///
/// The closure receives `(payload, source_groups)` and spawns async work
/// internally (fire-and-forget). Defined unconditionally so the `Option`
/// type is available regardless of feature flags.
pub(crate) type FedForwardFn = Arc<dyn Fn(Bytes, Vec<String>) + Send + Sync>;

/// Shared dependencies passed to each session handler task.
pub(crate) struct SessionDeps<P: NatsPublish> {
    pub(crate) router: Arc<Router>,
    pub(crate) framing: Framing,
    pub(crate) encoding: Encoding,
    pub(crate) nats_publisher: Option<P>,
    pub(crate) fed_forward: Option<FedForwardFn>,
    pub(crate) throttle_config: Option<ThrottleConfig>,
    pub(crate) archiver: Option<Arc<archive::CotArchiver>>,
}

/// Runtime context for a connected session's read/write loops.
struct SessionContext<'a, P: NatsPublish> {
    identity: &'a Identity,
    router: &'a Router,
    framing: &'a FramingStrategy,
    nats_publisher: &'a Option<P>,
    fed_forward: &'a Option<FedForwardFn>,
    throttle: Option<rustgate_transport::ClientThrottle>,
    archiver: &'a Option<Arc<archive::CotArchiver>>,
}

/// Trait for optional NATS publishing. Allows the server to compile with or
/// without the `nats` feature by abstracting over the publisher type.
pub(crate) trait NatsPublish: Clone {
    fn publish(&self, msg: &RoutableMessage) -> impl std::future::Future<Output = ()> + Send;
}

#[cfg(feature = "nats")]
impl NatsPublish for rustgate_nats::NatsPublisher {
    async fn publish(&self, msg: &RoutableMessage) {
        self.publish(msg).await;
    }
}

/// No-op publisher used when NATS is not enabled.
impl NatsPublish for () {
    async fn publish(&self, _msg: &RoutableMessage) {}
}

/// Handle a single authenticated TLS session from accept to disconnect.
pub(crate) async fn handle_session<P: NatsPublish + Send + Sync + 'static>(
    session: AuthenticatedSession,
    deps: SessionDeps<P>,
    _permit: OwnedSemaphorePermit, // Held for session lifetime; released on drop
) {
    let identity = session.identity_arc();
    let cn = identity.cn.clone();

    tracing::info!(cn = %cn, peer = %session.peer_addr(), "connected");
    crate::audit::client_connected(&cn, session.peer_addr(), &identity.fingerprint);

    #[cfg(feature = "metrics")]
    metrics::sessions_active().inc();

    let (tx, rx) = mpsc::channel::<RoutableMessage>(64);
    let handle = SessionHandle::new(Arc::clone(&identity), tx);
    let session_id = handle.id;
    deps.router.register(handle.clone()).await;
    deps.router.replay_positions(&handle).await;

    #[allow(unused_mut)] // Mutable borrows needed for proto negotiation
    let (mut reader, mut writer) = session.split();

    // Run protocol negotiation for TakNegotiate mode.
    // This may upgrade both framing and encoding from XML to protobuf.
    let (final_framing, final_encoding, read_buf) = match deps.framing {
        #[cfg(feature = "proto")]
        Framing::TakNegotiate => {
            match negotiate_tak_protocol(&mut reader, &mut writer, &cn).await {
                Ok(result) => {
                    let protocol = if matches!(result.1, Encoding::TakProtobuf) {
                        "protobuf"
                    } else {
                        "xml"
                    };
                    #[cfg(feature = "metrics")]
                    metrics::negotiations().with_label_values(&[protocol]).inc();
                    crate::audit::negotiation_result(&cn, protocol, true);
                    result
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    metrics::negotiations().with_label_values(&["failed"]).inc();
                    tracing::debug!(cn = %cn, error = %e, "negotiation failed");
                    crate::audit::negotiation_result(&cn, "tak", false);
                    deps.router.unregister(&cn, session_id).await;
                    #[cfg(feature = "metrics")]
                    {
                        metrics::sessions_active().dec();
                        metrics::connections_active().dec();
                    }
                    crate::audit::client_disconnected(&cn);
                    tracing::info!(cn = %cn, "disconnected");
                    return;
                }
            }
        }
        _ => {
            let fs = FramingStrategy::from(deps.framing);
            (fs, deps.encoding, tokio_util::bytes::BytesMut::new())
        }
    };

    let throttle = deps.throttle_config.map(|tc| tc.build());
    let ctx = SessionContext {
        identity: &identity,
        router: &deps.router,
        framing: &final_framing,
        nats_publisher: &deps.nats_publisher,
        fed_forward: &deps.fed_forward,
        throttle,
        archiver: &deps.archiver,
    };

    let result = match final_encoding {
        Encoding::Raw => run_session_loops(reader, writer, rx, &ctx, &RawEncoder, read_buf).await,
        Encoding::Cot => run_session_loops(reader, writer, rx, &ctx, &CotEncoder, read_buf).await,
        #[cfg(feature = "proto")]
        Encoding::TakProtobuf => {
            run_session_loops(
                reader,
                writer,
                rx,
                &ctx,
                &rustgate_proto::TakProtobufEncoder,
                read_buf,
            )
            .await
        }
        #[cfg(not(feature = "proto"))]
        Encoding::TakProtobuf => {
            tracing::error!("--encoding tak-protobuf requires --features proto");
            return;
        }
    };

    if let Err(e) = result {
        tracing::debug!(cn = %cn, error = %e, "session error");
    }

    deps.router.unregister(&cn, session_id).await;
    #[cfg(feature = "metrics")]
    {
        metrics::sessions_active().dec();
        metrics::connections_active().dec();
    }
    crate::audit::client_disconnected(&cn);
    tracing::info!(cn = %cn, "disconnected");
}

/// TAK protocol negotiation handshake.
///
/// Sends TakProtocolSupport advertisement, then peeks the first byte of the
/// client's response. If 0xBF (protobuf magic), completes the handshake and
/// upgrades to protobuf. Otherwise, stays XML.
///
/// Returns (final_framing, final_encoding, buffered_read_bytes).
#[cfg(feature = "proto")]
async fn negotiate_tak_protocol(
    reader: &mut rustgate_transport::SessionReader,
    writer: &mut rustgate_transport::SessionWriter,
    cn: &str,
) -> std::io::Result<(FramingStrategy, Encoding, tokio_util::bytes::BytesMut)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::bytes::BufMut;

    let server_uid = format!("rustgate-{cn}");

    // Step 1: Send TakProtocolSupport XML advertisement
    let advert = rustgate_proto::build_protocol_support_xml(&server_uid);
    writer.write_all(&advert).await?;
    writer.flush().await?;

    tracing::debug!(cn = %cn, "sent TakProtocolSupport advertisement");

    // Step 2: Peek the first byte to determine if client wants protobuf
    let mut peek = [0u8; 1];
    let n = reader.read(&mut peek).await?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "client disconnected during negotiation",
        ));
    }

    if peek[0] == 0xBF {
        // Client is requesting protobuf upgrade.
        // Magic byte already consumed; read_tak_request handles varint + payload + validation.
        rustgate_proto::read_tak_request(reader).await?;

        tracing::info!(cn = %cn, "client requested protobuf upgrade");

        // Step 3: Send TakResponse (0xBF-framed TakControl acknowledgement)
        let response = rustgate_proto::build_tak_response();
        writer.write_all(&response).await?;
        writer.flush().await?;

        tracing::info!(cn = %cn, "protobuf negotiation complete");

        Ok((
            FramingStrategy::TakProtobuf,
            Encoding::TakProtobuf,
            tokio_util::bytes::BytesMut::new(),
        ))
    } else {
        // Client sent XML (legacy mode). Preserve the byte we already read.
        tracing::info!(cn = %cn, "client staying XML (no protobuf request)");

        let mut buf = tokio_util::bytes::BytesMut::with_capacity(64);
        buf.put_u8(peek[0]);
        Ok((FramingStrategy::XmlStream, Encoding::Cot, buf))
    }
}

async fn run_session_loops(
    reader: rustgate_transport::SessionReader,
    writer: rustgate_transport::SessionWriter,
    rx: mpsc::Receiver<RoutableMessage>,
    ctx: &SessionContext<'_, impl NatsPublish>,
    encoder: &impl MessageEncoder,
    read_buf: tokio_util::bytes::BytesMut,
) -> std::io::Result<()> {
    tokio::select! {
        r = read_loop(reader, ctx, read_buf) => r,
        r = write_loop(writer, rx, ctx.framing, encoder) => r,
    }
}

async fn read_loop(
    reader: rustgate_transport::SessionReader,
    ctx: &SessionContext<'_, impl NatsPublish>,
    prefix: tokio_util::bytes::BytesMut,
) -> std::io::Result<()> {
    let is_proto = matches!(ctx.framing, FramingStrategy::TakProtobuf);
    let codec = FramedCodec::from_strategy(ctx.framing);

    // When negotiation consumed a peek byte and fell back to XML,
    // we need to feed that byte to the codec before reading from the socket.
    let prefix_opt = if prefix.is_empty() { None } else { Some(prefix) };
    let mut framed = FramedRead::new(PrefixedReader::new(reader, prefix_opt), codec);

    let mut msg_builder = MessageBuilder::new();

    loop {
        let frame = match tokio::time::timeout(READ_TIMEOUT, framed.next()).await {
            Ok(Some(result)) => result?,
            Ok(None) => break, // EOF -- client closed cleanly
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read timeout: no complete frame received",
                ));
            }
        };

        // For protobuf sessions, convert proto -> XML to get the canonical format.
        // The RoutableMessage payload is always XML.
        let payload = if is_proto {
            #[cfg(feature = "proto")]
            {
                let xml_bytes = rustgate_proto::proto_to_xml(&frame)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Bytes::from(xml_bytes)
            }
            #[cfg(not(feature = "proto"))]
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "TakProtobuf framing requires the `proto` feature",
                ));
            }
        } else {
            frame.freeze()
        };

        #[cfg(feature = "metrics")]
        metrics::messages_received().inc();

        // Per-client rate limiting -- drop excess messages
        if let Some(t) = &ctx.throttle
            && !t.allow()
        {
            tracing::debug!(cn = %ctx.identity.cn, "message dropped: rate limit exceeded");
            #[cfg(feature = "metrics")]
            metrics::messages_dropped().inc();
            continue;
        }

        let msg = msg_builder.build(ctx.identity, payload, "tcp");

        // Archive to JSONL if enabled
        if let Some(arch) = ctx.archiver {
            arch.record(&msg).await;
        }

        #[cfg(feature = "metrics")]
        {
            let dest_label = match msg.destination {
                Destination::Broadcast => "broadcast",
                Destination::Group(_) => "group",
                Destination::Direct(_) => "direct",
            };
            metrics::messages_routed()
                .with_label_values(&[dest_label])
                .inc();
        }

        ctx.router.route(msg.clone()).await;

        // Publish to NATS after local routing (fire-and-forget)
        if let Some(publisher) = ctx.nats_publisher {
            #[cfg(feature = "metrics")]
            metrics::nats_publishes().inc();
            publisher.publish(&msg).await;
        }

        // Forward to federation peers (fire-and-forget)
        if let Some(fwd) = ctx.fed_forward {
            let groups: Vec<String> = msg.source.groups.iter().cloned().collect();
            fwd(msg.payload.clone(), groups);
        }
    }

    Ok(())
}

async fn write_loop(
    writer: rustgate_transport::SessionWriter,
    mut rx: mpsc::Receiver<RoutableMessage>,
    framing: &FramingStrategy,
    encoder: &impl MessageEncoder,
) -> std::io::Result<()> {
    let mut framed = FramedWrite::new(writer, FramedCodec::from_strategy(framing));

    while let Some(msg) = rx.recv().await {
        let encoded = encoder.encode(&msg)?;
        let send_fut = framed.send(tokio_util::bytes::BytesMut::from(encoded.as_ref()));

        match tokio::time::timeout(WRITE_TIMEOUT, send_fut).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "write timeout: slow consumer",
                ));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Plaintext TCP
// ---------------------------------------------------------------------------

/// Configuration for the plaintext TCP accept loop, bundling arguments that
/// would otherwise require `#[allow(clippy::too_many_arguments)]`.
pub(crate) struct PlaintextTcpConfig<P: NatsPublish> {
    pub(crate) listener: rustgate_transport::PlaintextListener,
    pub(crate) router: Arc<Router>,
    pub(crate) connection_limit: Arc<Semaphore>,
    pub(crate) framing: Framing,
    pub(crate) encoding: Encoding,
    pub(crate) nats_publisher: Option<P>,
    pub(crate) fed_forward: Option<FedForwardFn>,
    pub(crate) shutdown: Arc<tokio::sync::Notify>,
}

/// Accept loop for plaintext TCP connections.
///
/// Mirrors the main TLS accept loop but operates on unencrypted sockets.
/// Each connection gets a synthetic identity and participates in the same
/// router, NATS bridge, and federation forwarding as TLS sessions.
pub(crate) async fn run_plaintext_tcp<P: NatsPublish + Send + Sync + 'static>(
    config: PlaintextTcpConfig<P>,
) {
    let PlaintextTcpConfig {
        listener,
        router,
        connection_limit,
        framing,
        encoding,
        nats_publisher,
        fed_forward,
        shutdown,
    } = config;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok(session) => {
                        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::warn!("plaintext TCP: connection limit reached, rejecting");
                                continue;
                            }
                        };

                        let identity = Arc::new(session.identity().clone());
                        let cn = identity.cn.clone();
                        let peer_addr = session.peer_addr();

                        tracing::info!(cn = %cn, peer = %peer_addr, "plaintext TCP connected");

                        let (tx, rx) = mpsc::channel::<RoutableMessage>(64);
                        let handle = SessionHandle::new(Arc::clone(&identity), tx);
                        let session_id = handle.id;
                        router.register(handle.clone()).await;
                        router.replay_positions(&handle).await;

                        let (reader, writer) = session.into_split();

                        let session_router = Arc::clone(&router);
                        let fs = FramingStrategy::from(framing);
                        #[allow(clippy::clone_on_copy)]
                        let session_nats = nats_publisher.clone();
                        let session_fed = fed_forward.clone();

                        drop(tokio::spawn(async move {
                            let _permit = permit;

                            let result = run_plaintext_session_loops(PlaintextSessionContext {
                                reader,
                                writer,
                                rx,
                                identity: &identity,
                                router: &session_router,
                                framing: &fs,
                                encoding,
                                nats_publisher: &session_nats,
                                fed_forward: &session_fed,
                            }).await;

                            if let Err(e) = result {
                                tracing::debug!(cn = %cn, error = %e, "plaintext TCP session error");
                            }

                            session_router.unregister(&cn, session_id).await;
                            tracing::info!(cn = %cn, "plaintext TCP disconnected");
                        }));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "plaintext TCP accept error");
                    }
                }
            }
            _ = shutdown.notified() => {
                tracing::info!("plaintext TCP listener stopping");
                break;
            }
        }
    }
}

/// Context for a plaintext TCP session's read/write loops.
struct PlaintextSessionContext<'a, P: NatsPublish> {
    reader: tokio::io::ReadHalf<tokio::net::TcpStream>,
    writer: tokio::io::WriteHalf<tokio::net::TcpStream>,
    rx: mpsc::Receiver<RoutableMessage>,
    identity: &'a Identity,
    router: &'a Router,
    framing: &'a FramingStrategy,
    encoding: Encoding,
    nats_publisher: &'a Option<P>,
    fed_forward: &'a Option<FedForwardFn>,
}

/// Read/write loops for a plaintext TCP session.
///
/// Uses the same codec and encoder pipeline as TLS sessions but operates
/// on a raw `TcpStream` split.
async fn run_plaintext_session_loops<P: NatsPublish>(
    ctx: PlaintextSessionContext<'_, P>,
) -> std::io::Result<()> {
    let PlaintextSessionContext {
        reader,
        writer,
        mut rx,
        identity,
        router,
        framing,
        encoding,
        nats_publisher,
        fed_forward,
    } = ctx;
    let codec = FramedCodec::from_strategy(framing);
    let mut framed_read = FramedRead::new(reader, codec);
    let mut msg_builder = MessageBuilder::new();

    let write_codec = FramedCodec::from_strategy(framing);
    let mut framed_write = FramedWrite::new(writer, write_codec);

    let encoder: Box<dyn MessageEncoder + Send + Sync> = match encoding {
        Encoding::Raw | Encoding::TakProtobuf => Box::new(RawEncoder),
        Encoding::Cot => Box::new(CotEncoder),
    };

    tokio::select! {
        r = async {
            loop {
                let frame = match tokio::time::timeout(READ_TIMEOUT, framed_read.next()).await {
                    Ok(Some(result)) => result?,
                    Ok(None) => break,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "read timeout",
                        ));
                    }
                };

                let payload = frame.freeze();
                let msg = msg_builder.build(identity, payload, "tcp-plaintext");
                router.route(msg.clone()).await;

                if let Some(publisher) = nats_publisher {
                    publisher.publish(&msg).await;
                }

                if let Some(fwd) = fed_forward {
                    let groups: Vec<String> = msg.source.groups.iter().cloned().collect();
                    fwd(msg.payload.clone(), groups);
                }
            }
            Ok(())
        } => r,
        r = async {
            while let Some(msg) = rx.recv().await {
                let encoded = encoder.encode(&msg)?;
                let send_fut = framed_write.send(tokio_util::bytes::BytesMut::from(encoded.as_ref()));
                match tokio::time::timeout(WRITE_TIMEOUT, send_fut).await {
                    Ok(result) => result?,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "write timeout: slow consumer",
                        ));
                    }
                }
            }
            Ok(())
        } => r,
    }
}

// ---------------------------------------------------------------------------
// PrefixedReader
// ---------------------------------------------------------------------------

/// AsyncRead wrapper that yields prefix bytes before delegating to the inner reader.
///
/// Used after protocol negotiation to feed the peeked byte back to the codec
/// when the client stays in XML mode.
pub(crate) struct PrefixedReader<R> {
    inner: R,
    prefix: Vec<u8>,
    prefix_pos: usize,
}

impl<R> PrefixedReader<R> {
    pub(crate) fn new(inner: R, prefix: Option<tokio_util::bytes::BytesMut>) -> Self {
        let prefix = prefix.map_or_else(Vec::new, |b| b.to_vec());
        Self {
            inner,
            prefix,
            prefix_pos: 0,
        }
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Drain prefix bytes first
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.prefix_pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
