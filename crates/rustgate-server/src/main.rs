use std::sync::Arc;

use clap::Parser;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

use rustgate_transport::{AuthenticatedSession, Router, SessionHandle};

#[derive(Parser)]
#[command(name = "rustgate", about = "Secure tactical message router")]
struct Cli {
    #[arg(short, long, default_value = "rustgate.toml")]
    config: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    tracing::info!(config = %cli.config, "rustgate starting");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run())?;

    Ok(())
}

#[allow(clippy::unused_async)]
async fn run() -> anyhow::Result<()> {
    let _router = Arc::new(Router::new());

    // TODO: load TLS config and create listener
    // let listener = TlsListener::bind(addr, tls_config).await?;

    // TODO: accept loop
    // while let Ok(session) = listener.accept().await {
    //     let router = Arc::clone(&router);
    //     tokio::spawn(handle_session(session, router));
    // }

    tracing::info!("runtime started");
    Ok(())
}

#[allow(dead_code)]
async fn handle_session(session: AuthenticatedSession, router: Arc<Router>) -> anyhow::Result<()> {
    let identity = Arc::new(session.identity().clone());
    let cn = identity.cn.clone();

    tracing::info!(%cn, "session connected");

    let (outbound_tx, mut outbound_rx) = mpsc::channel(64);
    let handle = SessionHandle::new(Arc::clone(&identity), outbound_tx);
    router.register(handle).await;

    // TODO: split session into reader/writer
    // TODO: spawn writer task to send outbound_rx messages
    // TODO: read loop: decode frames, build RoutableMessage, call router.route()

    let _ = &mut outbound_rx; // suppress unused warning for now

    router.unregister(&cn).await;
    tracing::info!(%cn, "session disconnected");

    Ok(())
}
