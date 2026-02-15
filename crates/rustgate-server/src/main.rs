use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use clap::Parser;
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing_subscriber::EnvFilter;

use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{
    AuthenticatedSession, LengthPrefixedCodec, Router, SessionHandle, TlsConfig, TlsListener,
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

    tracing::info!(addr = %listener.local_addr()?, "listening");

    let router = Arc::new(Router::new());

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Some(Ok(session)) => {
                        let router = Arc::clone(&router);
                        drop(tokio::spawn(handle_session(session, router)));
                    }
                    Some(Err(e)) => tracing::warn!(error = %e, "accept error"),
                    None => break,
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

async fn handle_session(session: AuthenticatedSession, router: Arc<Router>) {
    let identity = Arc::new(session.identity().clone());
    let cn = identity.cn.clone();

    tracing::info!(cn = %cn, peer = %session.peer_addr(), "connected");

    let (tx, rx) = mpsc::channel::<RoutableMessage>(64);
    router.register(SessionHandle::new(Arc::clone(&identity), tx)).await;

    let (reader, writer) = session.split();

    tokio::select! {
        r = read_loop(reader, &identity, &router) => {
            if let Err(e) = r {
                tracing::debug!(cn = %cn, error = %e, "read error");
            }
        }
        r = write_loop(writer, rx) => {
            if let Err(e) = r {
                tracing::debug!(cn = %cn, error = %e, "write error");
            }
        }
    }

    router.unregister(&cn).await;
    tracing::info!(cn = %cn, "disconnected");
}

async fn read_loop(
    reader: rustgate_transport::SessionReader,
    identity: &Identity,
    router: &Router,
) -> std::io::Result<()> {
    let mut framed = FramedRead::new(reader, LengthPrefixedCodec::new(4));

    while let Some(result) = framed.next().await {
        let frame = result?;
        router.route(build_message(identity, frame.freeze())).await;
    }

    Ok(())
}

async fn write_loop(
    writer: rustgate_transport::SessionWriter,
    mut rx: mpsc::Receiver<RoutableMessage>,
) -> std::io::Result<()> {
    let mut framed = FramedWrite::new(writer, LengthPrefixedCodec::new(4));

    while let Some(msg) = rx.recv().await {
        framed.send(tokio_util::bytes::BytesMut::from(msg.payload.as_ref())).await?;
    }

    Ok(())
}

fn build_message(source: &Identity, payload: Bytes) -> RoutableMessage {
    RoutableMessage {
        source: source.clone(),
        destination: Destination::Broadcast,
        payload,
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "tcp".into(),
            message_type: MessageType::Other("raw".into()),
            ttl: None,
        },
    }
}
