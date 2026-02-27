use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures::{SinkExt, StreamExt};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing_subscriber::EnvFilter;

/// Maximum concurrent TLS sessions. Prevents resource exhaustion
/// from connection floods (even with mTLS, the TLS handshake is costly).
const MAX_CONNECTIONS: usize = 1024;

use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, Metadata, RoutableMessage};
use rustgate_core::protocol::{FramingStrategy, HeaderSize};
use rustgate_cot::{CotDestination, CotEvent};
use rustgate_transport::{
    AuthenticatedSession, CotEncoder, FramedCodec, MessageEncoder, RawEncoder, Router,
    SessionHandle, TlsConfig, TlsListener,
};

#[derive(Parser)]
#[command(name = "rustgate", about = "Secure tactical message router")]
struct Cli {
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    bind: String,

    #[arg(long)]
    cert: String,

    #[arg(long)]
    key: String,

    #[arg(long)]
    ca: String,

    #[arg(long, value_enum, default_value_t = Framing::Xml)]
    framing: Framing,

    #[arg(long, value_enum, default_value_t = Encoding::Raw)]
    encoding: Encoding,

    /// NATS server URL (enables NATS bridge when set). Requires --features nats.
    #[arg(long)]
    nats_url: Option<String>,

    /// Path to NATS credentials file for JWT/NKey auth.
    #[arg(long)]
    nats_credentials: Option<String>,

    /// Bind address for the enrollment HTTPS server (e.g. 0.0.0.0:8446).
    /// Requires --features enrollment.
    #[arg(long)]
    enrollment_bind: Option<String>,

    /// Path to the CA private key PEM file (used to sign client CSRs).
    #[arg(long)]
    ca_key: Option<String>,

    /// Username for enrollment HTTP Basic Auth.
    #[arg(long)]
    enrollment_user: Option<String>,

    /// Password for enrollment HTTP Basic Auth.
    #[arg(long)]
    enrollment_password: Option<String>,

    /// Organization name for issued client certificates.
    #[arg(long, default_value = "rustgate")]
    ca_organization: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Framing {
    Xml,
    LengthPrefixed,
    Line,
    /// TAK protobuf binary framing (0xBF + varint length). Requires --features proto.
    TakProtobuf,
    /// TAK protocol negotiation: starts XML, upgrades to protobuf if the client requests it.
    /// This is the mode real TAK clients expect. Requires --features proto.
    TakNegotiate,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Encoding {
    Raw,
    Cot,
    /// TAK protobuf encoding (proto <-> XML at session edge). Requires --features proto.
    TakProtobuf,
}

impl From<Framing> for FramingStrategy {
    fn from(f: Framing) -> Self {
        match f {
            Framing::Xml => FramingStrategy::XmlStream,
            Framing::LengthPrefixed => FramingStrategy::LengthPrefixed { header_size: HeaderSize::Four },
            Framing::Line => FramingStrategy::LineDelimited,
            Framing::TakProtobuf => FramingStrategy::TakProtobuf,
            // TakNegotiate starts as XML; negotiation determines the actual framing.
            // This mapping is used as the initial framing before negotiation runs.
            Framing::TakNegotiate => FramingStrategy::XmlStream,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    tracing::info!(bind = %cli.bind, "rustgate starting");

    tokio::runtime::Runtime::new()?.block_on(run(cli))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let cert_pem = tokio::fs::read_to_string(&cli.cert).await?;
    let key_pem = tokio::fs::read_to_string(&cli.key).await?;
    let ca_pem = tokio::fs::read_to_string(&cli.ca).await?;

    let tls_config = TlsConfig::from_pem(&cert_pem, &key_pem, &ca_pem)?;
    let listener = TlsListener::bind(&cli.bind, &tls_config).await?;
    let framing = cli.framing;
    let encoding = cli.encoding;

    #[cfg(not(feature = "proto"))]
    if matches!(cli.framing, Framing::TakProtobuf | Framing::TakNegotiate)
        || matches!(encoding, Encoding::TakProtobuf)
    {
        anyhow::bail!("TAK protobuf support requires --features proto");
    }

    tracing::info!(addr = %listener.local_addr()?, framing = ?cli.framing, encoding = ?encoding, "listening");

    let router = Arc::new(Router::new());
    let connection_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    // Optionally connect to NATS for cross-instance message delivery
    #[cfg(feature = "nats")]
    let nats_publisher = if let Some(ref nats_url) = cli.nats_url {
        let config = rustgate_nats::NatsConfig {
            url: nats_url.clone(),
            credentials_file: cli.nats_credentials.clone(),
            ..Default::default()
        };

        match rustgate_nats::NatsAdapter::connect(config).await {
            Ok(adapter) => {
                // Run JetStream replay to populate position cache before accepting clients
                let replay = adapter.jetstream_replay();
                match replay.replay(Arc::clone(&router)).await {
                    Ok(count) => tracing::info!(count, "JetStream SA replay loaded"),
                    Err(e) => tracing::warn!(error = %e, "JetStream replay failed (continuing without history)"),
                }

                // Spawn NATS subscriber as a background task
                let subscriber = adapter.subscriber();
                let sub_router = Arc::clone(&router);
                drop(tokio::spawn(async move {
                    if let Err(e) = subscriber.run(sub_router).await {
                        tracing::warn!(error = %e, "NATS subscriber ended with error");
                    }
                }));

                Some(adapter.publisher())
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to connect to NATS (continuing without bridge)");
                None
            }
        }
    } else {
        None
    };

    #[cfg(not(feature = "nats"))]
    let nats_publisher: Option<()> = {
        if cli.nats_url.is_some() {
            tracing::warn!("--nats-url requires --features nats; ignoring");
        }
        None
    };

    // Optionally start the enrollment HTTPS server for client certificate provisioning
    #[cfg(feature = "enrollment")]
    if let Some(ref enrollment_bind) = cli.enrollment_bind {
        let ca_key_path = cli.ca_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!("--ca-key is required when --enrollment-bind is set")
        })?;
        let enrollment_user = cli.enrollment_user.as_deref().ok_or_else(|| {
            anyhow::anyhow!("--enrollment-user is required when --enrollment-bind is set")
        })?;
        let enrollment_password = cli.enrollment_password.as_deref().ok_or_else(|| {
            anyhow::anyhow!("--enrollment-password is required when --enrollment-bind is set")
        })?;

        let ca_key_pem = tokio::fs::read_to_string(ca_key_path).await?;

        let signer = rustgate_enrollment::CsrSigner::from_pem(
            &ca_pem,
            &ca_key_pem,
            &cli.ca_organization,
        )?;
        let credentials = rustgate_enrollment::Credentials::new(
            enrollment_user.to_string(),
            enrollment_password.to_string(),
        );
        let enrollment_server = rustgate_enrollment::EnrollmentServer::new(signer, credentials);

        let bind_addr: std::net::SocketAddr = enrollment_bind.parse()
            .map_err(|e| anyhow::anyhow!("invalid --enrollment-bind address: {e}"))?;

        let enrollment_cert = cert_pem.clone();
        let enrollment_key = key_pem.clone();

        drop(tokio::spawn(async move {
            if let Err(e) = enrollment_server
                .run(bind_addr, &enrollment_cert, &enrollment_key)
                .await
            {
                tracing::error!(error = %e, "enrollment server failed");
            }
        }));

        tracing::info!(addr = %enrollment_bind, "enrollment server started");
    }

    #[cfg(not(feature = "enrollment"))]
    if cli.enrollment_bind.is_some() {
        tracing::warn!("--enrollment-bind requires --features enrollment; ignoring");
    }

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok(session) => {
                        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::warn!(max = MAX_CONNECTIONS, "connection limit reached, rejecting");
                                continue;
                            }
                        };
                        let router = Arc::clone(&router);
                        #[allow(clippy::clone_on_copy)] // Type varies by feature flag
                        let publisher = nats_publisher.clone();
                        drop(tokio::spawn(handle_session(session, router, framing, encoding, publisher, permit)));
                    }
                    Err(e) => tracing::warn!(error = %e, "accept error"),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown");
                break;
            }
        }
    }

    tracing::info!(sessions = router.session_count().await, "stopped");
    Ok(())
}

async fn handle_session<P: NatsPublish + Send + Sync + 'static>(
    session: AuthenticatedSession,
    router: Arc<Router>,
    framing: Framing,
    encoding: Encoding,
    nats_publisher: Option<P>,
    _permit: OwnedSemaphorePermit, // Held for session lifetime; released on drop
) {
    let identity = session.identity_arc();
    let cn = identity.cn.clone();

    tracing::info!(cn = %cn, peer = %session.peer_addr(), "connected");

    let (tx, rx) = mpsc::channel::<RoutableMessage>(64);
    let handle = SessionHandle::new(Arc::clone(&identity), tx);
    let session_id = handle.id;
    router.register(handle.clone()).await;
    router.replay_positions(&handle).await;

    #[allow(unused_mut)] // Mutable borrows needed for proto negotiation
    let (mut reader, mut writer) = session.split();

    // Run protocol negotiation for TakNegotiate mode.
    // This may upgrade both framing and encoding from XML to protobuf.
    let (final_framing, final_encoding, read_buf) = match framing {
        #[cfg(feature = "proto")]
        Framing::TakNegotiate => {
            match negotiate_tak_protocol(&mut reader, &mut writer, &cn).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::debug!(cn = %cn, error = %e, "negotiation failed");
                    router.unregister(&cn, session_id).await;
                    tracing::info!(cn = %cn, "disconnected");
                    return;
                }
            }
        }
        _ => {
            let fs = FramingStrategy::from(framing);
            (fs, encoding, tokio_util::bytes::BytesMut::new())
        }
    };

    let result = match final_encoding {
        Encoding::Raw => {
            run_session_loops(reader, writer, rx, &identity, &router, &final_framing, &RawEncoder, &nats_publisher, read_buf).await
        }
        Encoding::Cot => {
            run_session_loops(reader, writer, rx, &identity, &router, &final_framing, &CotEncoder, &nats_publisher, read_buf).await
        }
        #[cfg(feature = "proto")]
        Encoding::TakProtobuf => {
            run_session_loops(reader, writer, rx, &identity, &router, &final_framing, &rustgate_proto::TakProtobufEncoder, &nats_publisher, read_buf).await
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

    router.unregister(&cn, session_id).await;
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

        Ok((FramingStrategy::TakProtobuf, Encoding::TakProtobuf, tokio_util::bytes::BytesMut::new()))
    } else {
        // Client sent XML (legacy mode). Preserve the byte we already read.
        tracing::info!(cn = %cn, "client staying XML (no protobuf request)");

        let mut buf = tokio_util::bytes::BytesMut::with_capacity(64);
        buf.put_u8(peek[0]);
        Ok((FramingStrategy::XmlStream, Encoding::Cot, buf))
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_session_loops(
    reader: rustgate_transport::SessionReader,
    writer: rustgate_transport::SessionWriter,
    rx: mpsc::Receiver<RoutableMessage>,
    identity: &Identity,
    router: &Router,
    framing: &FramingStrategy,
    encoder: &impl MessageEncoder,
    nats_publisher: &Option<impl NatsPublish>,
    read_buf: tokio_util::bytes::BytesMut,
) -> std::io::Result<()> {
    tokio::select! {
        r = read_loop(reader, identity, router, framing, nats_publisher, read_buf) => r,
        r = write_loop(writer, rx, framing, encoder) => r,
    }
}

async fn read_loop(
    reader: rustgate_transport::SessionReader,
    identity: &Identity,
    router: &Router,
    framing: &FramingStrategy,
    nats_publisher: &Option<impl NatsPublish>,
    prefix: tokio_util::bytes::BytesMut,
) -> std::io::Result<()> {
    let is_proto = matches!(framing, FramingStrategy::TakProtobuf);
    let codec = FramedCodec::from_strategy(framing);

    // When negotiation consumed a peek byte and fell back to XML,
    // we need to feed that byte to the codec before reading from the socket.
    let mut framed = if prefix.is_empty() {
        FramedRead::new(PrefixedReader::new(reader, None), codec)
    } else {
        FramedRead::new(PrefixedReader::new(reader, Some(prefix)), codec)
    };

    // Track the session's group across messages. Position CoT carries
    // <__group name="Cyan"/> but chat and other types don't. Once we learn
    // the group from a position message, apply it to subsequent messages
    // from the same session so NATS routing stays correct.
    let mut session_group: Option<String> = None;

    while let Some(result) = framed.next().await {
        let frame = result?;

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

        let msg = match rustgate_cot::parse(&payload) {
            Ok(cot) => {
                if cot.source_group.is_some() {
                    session_group = cot.source_group.clone();
                }
                build_cot_message(identity, &session_group, payload, cot)
            }
            Err(_) => build_raw_message(identity, &session_group, payload),
        };

        router.route(msg.clone()).await;

        // Publish to NATS after local routing (fire-and-forget)
        if let Some(publisher) = nats_publisher {
            publisher.publish(&msg).await;
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
        framed.send(tokio_util::bytes::BytesMut::from(encoded.as_ref())).await?;
    }

    Ok(())
}

/// AsyncRead wrapper that yields prefix bytes before delegating to the inner reader.
///
/// Used after protocol negotiation to feed the peeked byte back to the codec
/// when the client stays in XML mode.
struct PrefixedReader<R> {
    inner: R,
    prefix: Vec<u8>,
    prefix_pos: usize,
}

impl<R> PrefixedReader<R> {
    fn new(inner: R, prefix: Option<tokio_util::bytes::BytesMut>) -> Self {
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

fn build_cot_message(
    source: &Identity,
    session_group: &Option<String>,
    payload: Bytes,
    cot: CotEvent,
) -> RoutableMessage {
    let destination = match cot.destination {
        CotDestination::Broadcast => Destination::Broadcast,
        CotDestination::Group(name) => Destination::Group(name),
        CotDestination::Callsign(cn) => Destination::Direct(Identity {
            cn,
            fingerprint: String::new(),
            groups: BTreeSet::new(),
        }),
    };

    // Enrich source identity with the group. Prefer the __group from this
    // message's CoT detail, fall back to the session's cached group (learned
    // from earlier position messages). Chat and other non-position CoT types
    // don't carry __group, so the fallback keeps NATS routing correct.
    let mut enriched_source = source.clone();
    let group = cot.source_group.as_ref().or(session_group.as_ref());
    if let Some(g) = group {
        let _ = enriched_source.groups.insert(g.clone());
    }

    RoutableMessage {
        source: enriched_source,
        destination,
        payload,
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "cot".into(),
            message_type: cot.message_type,
            ttl: cot.ttl,
        },
    }
}

/// Trait for optional NATS publishing. Allows the server to compile with or
/// without the `nats` feature by abstracting over the publisher type.
trait NatsPublish: Clone {
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

fn build_raw_message(
    source: &Identity,
    session_group: &Option<String>,
    payload: Bytes,
) -> RoutableMessage {
    let mut enriched_source = source.clone();
    if let Some(g) = session_group {
        let _ = enriched_source.groups.insert(g.clone());
    }
    RoutableMessage {
        source: enriched_source,
        destination: Destination::Broadcast,
        payload,
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "tcp".into(),
            message_type: rustgate_core::message::MessageType::Other("raw".into()),
            ttl: None,
        },
    }
}
