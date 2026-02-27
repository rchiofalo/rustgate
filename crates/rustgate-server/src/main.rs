use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing_subscriber::EnvFilter;

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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Framing {
    Xml,
    LengthPrefixed,
    Line,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Encoding {
    Raw,
    Cot,
}

impl From<Framing> for FramingStrategy {
    fn from(f: Framing) -> Self {
        match f {
            Framing::Xml => FramingStrategy::XmlStream,
            Framing::LengthPrefixed => FramingStrategy::LengthPrefixed { header_size: HeaderSize::Four },
            Framing::Line => FramingStrategy::LineDelimited,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
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
    let framing = FramingStrategy::from(cli.framing);
    let encoding = cli.encoding;

    tracing::info!(addr = %listener.local_addr()?, framing = ?cli.framing, encoding = ?encoding, "listening");

    let router = Arc::new(Router::new());

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

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok(session) => {
                        let router = Arc::clone(&router);
                        let framing = framing.clone();
                        #[allow(clippy::clone_on_copy)] // Type varies by feature flag
                        let publisher = nats_publisher.clone();
                        drop(tokio::spawn(handle_session(session, router, framing, encoding, publisher)));
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
    framing: FramingStrategy,
    encoding: Encoding,
    nats_publisher: Option<P>,
) {
    let identity = session.identity_arc();
    let cn = identity.cn.clone();

    tracing::info!(cn = %cn, peer = %session.peer_addr(), "connected");

    let (tx, rx) = mpsc::channel::<RoutableMessage>(64);
    let handle = SessionHandle::new(Arc::clone(&identity), tx);
    let session_id = handle.id;
    router.register(handle.clone()).await;
    router.replay_positions(&handle).await;

    let (reader, writer) = session.split();

    let result = match encoding {
        Encoding::Raw => {
            run_session_loops(reader, writer, rx, &identity, &router, &framing, &RawEncoder, &nats_publisher).await
        }
        Encoding::Cot => {
            run_session_loops(reader, writer, rx, &identity, &router, &framing, &CotEncoder, &nats_publisher).await
        }
    };

    if let Err(e) = result {
        tracing::debug!(cn = %cn, error = %e, "session error");
    }

    router.unregister(&cn, session_id).await;
    tracing::info!(cn = %cn, "disconnected");
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
) -> std::io::Result<()> {
    tokio::select! {
        r = read_loop(reader, identity, router, framing, nats_publisher) => r,
        r = write_loop(writer, rx, framing, encoder) => r,
    }
}

async fn read_loop(
    reader: rustgate_transport::SessionReader,
    identity: &Identity,
    router: &Router,
    framing: &FramingStrategy,
    nats_publisher: &Option<impl NatsPublish>,
) -> std::io::Result<()> {
    let mut framed = FramedRead::new(reader, FramedCodec::from_strategy(framing));

    while let Some(result) = framed.next().await {
        let frame = result?;
        let payload = frame.freeze();

        let msg = match rustgate_cot::parse(&payload) {
            Ok(cot) => build_cot_message(identity, payload, cot),
            Err(_) => build_raw_message(identity, payload),
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

fn build_cot_message(source: &Identity, payload: Bytes, cot: CotEvent) -> RoutableMessage {
    let destination = match cot.destination {
        CotDestination::Broadcast => Destination::Broadcast,
        CotDestination::Group(name) => Destination::Group(name),
        CotDestination::Callsign(cn) => Destination::Direct(Identity {
            cn,
            fingerprint: String::new(),
            groups: BTreeSet::new(),
        }),
    };

    RoutableMessage {
        source: source.clone(),
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

fn build_raw_message(source: &Identity, payload: Bytes) -> RoutableMessage {
    RoutableMessage {
        source: source.clone(),
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
