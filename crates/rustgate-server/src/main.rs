use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "rustgate", about = "Secure tactical message router")]
struct Cli {
    /// Path to config file
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
    rt.block_on(async {
        tracing::info!("runtime started");
        // TODO: load config, start listener, wire router
    });

    Ok(())
}
