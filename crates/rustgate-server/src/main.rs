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
    AuthenticatedSession, FramedCodec, Router, SessionHandle, TlsConfig, TlsListener,
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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Framing {
    Xml,
    LengthPrefixed,
    Line,
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

    tracing::info!(addr = %listener.local_addr()?, framing = ?cli.framing, "listening");

    let router = Arc::new(Router::new());

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok(session) => {
                        let router = Arc::clone(&router);
                        let framing = framing.clone();
                        drop(tokio::spawn(handle_session(session, router, framing)));
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

async fn handle_session(session: AuthenticatedSession, router: Arc<Router>, framing: FramingStrategy) {
    let identity = session.identity_arc();
    let cn = identity.cn.clone();

    tracing::info!(cn = %cn, peer = %session.peer_addr(), "connected");

    let (tx, rx) = mpsc::channel::<RoutableMessage>(64);
    let handle = SessionHandle::new(Arc::clone(&identity), tx);
    let session_id = handle.id;
    router.register(handle).await;

    let (reader, writer) = session.split();

    tokio::select! {
        r = read_loop(reader, &identity, &router, &framing) => {
            if let Err(e) = r {
                tracing::debug!(cn = %cn, error = %e, "read error");
            }
        }
        r = write_loop(writer, rx, &framing) => {
            if let Err(e) = r {
                tracing::debug!(cn = %cn, error = %e, "write error");
            }
        }
    }

    router.unregister(&cn, session_id).await;
    tracing::info!(cn = %cn, "disconnected");
}

async fn read_loop(
    reader: rustgate_transport::SessionReader,
    identity: &Identity,
    router: &Router,
    framing: &FramingStrategy,
) -> std::io::Result<()> {
    let mut framed = FramedRead::new(reader, FramedCodec::from_strategy(framing));

    while let Some(result) = framed.next().await {
        let frame = result?;
        let payload = frame.freeze();

        let msg = match rustgate_cot::parse(&payload) {
            Ok(cot) => build_cot_message(identity, payload, cot),
            Err(_) => build_raw_message(identity, payload),
        };

        router.route(msg).await;
    }

    Ok(())
}

async fn write_loop(
    writer: rustgate_transport::SessionWriter,
    mut rx: mpsc::Receiver<RoutableMessage>,
    framing: &FramingStrategy,
) -> std::io::Result<()> {
    let mut framed = FramedWrite::new(writer, FramedCodec::from_strategy(framing));

    while let Some(msg) = rx.recv().await {
        framed.send(tokio_util::bytes::BytesMut::from(msg.payload.as_ref())).await?;
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
