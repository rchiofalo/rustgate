//! rustgate server binary — secure tactical message router.
//!
//! This module contains the entrypoint, async runtime orchestration, and
//! graceful shutdown logic. Subsystem initialization is delegated to [`setup`],
//! session handling to [`session`], and CLI parsing to [`cli`].

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use tokio::sync::Semaphore;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

mod acl_config;
mod archive;
mod audit;
mod cli;
#[cfg(feature = "metrics")]
mod metrics;
#[cfg(feature = "otel")]
mod otel;
mod session;
mod setup;

use cli::Cli;
use rustgate_transport::Router;
use session::{FedForwardFn, SessionDeps};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer().json();

    // Dedicated audit log sink: filters only target="audit" events and writes
    // JSON lines to the configured file (or stdout when "-").
    let audit_layer = if let Some(ref audit_path) = cli.audit_log {
        let writer: std::sync::Mutex<Box<dyn std::io::Write + Send>> = if audit_path == "-" {
            std::sync::Mutex::new(Box::new(std::io::stdout()))
        } else {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(audit_path)
                .map_err(|e| anyhow::anyhow!("failed to open audit log {audit_path}: {e}"))?;
            std::sync::Mutex::new(Box::new(file))
        };
        let filter =
            tracing_subscriber::filter::Targets::new().with_target("audit", tracing::Level::INFO);
        Some(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(writer)
                .with_filter(filter),
        )
    } else {
        None
    };

    #[cfg(feature = "otel")]
    let otel_layer = if let Some(ref endpoint) = cli.otel_endpoint {
        Some(otel::init_layer(endpoint, &cli.otel_service_name)?)
    } else {
        None
    };

    #[cfg(not(feature = "otel"))]
    let otel_layer: Option<tracing_subscriber::layer::Identity> = None;

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(audit_layer)
        .with(otel_layer)
        .init();

    #[cfg(feature = "otel")]
    if let Some(ref endpoint) = cli.otel_endpoint {
        tracing::info!(endpoint = %endpoint, "OpenTelemetry trace export enabled");
    }

    #[cfg(not(feature = "otel"))]
    if cli.otel_endpoint.is_some() {
        tracing::warn!(
            "--otel-endpoint provided but the otel feature is not compiled in; \
             rebuild with --features otel to enable trace export"
        );
    }

    // Install crypto provider. Only one can be active.
    // When both `post-quantum` and `fips` are enabled, the PQ provider
    // includes FIPS validation (same aws-lc-rs backend) plus PQ KX groups.
    #[cfg(feature = "post-quantum")]
    if let Some(ref groups) = cli.kx_groups {
        rustgate_transport::install_provider_with_kx_groups(groups)?;
    } else {
        rustgate_transport::install_pq_provider()?;
    }

    #[cfg(all(feature = "fips", not(feature = "post-quantum")))]
    rustgate_transport::install_fips_provider()?;

    if cli.fips_required && !rustgate_transport::is_fips_provider_active() {
        anyhow::bail!(
            "--fips-required is set but FIPS crypto provider is not active. \
             Build with --features fips to enable FIPS 140-3 mode."
        );
    }

    #[cfg(feature = "post-quantum")]
    if rustgate_transport::is_pq_provider_active() {
        tracing::info!("post-quantum key exchange available (X25519MLKEM768)");
    } else {
        tracing::warn!("post-quantum feature enabled but X25519MLKEM768 not found in provider");
    }

    #[cfg(not(feature = "post-quantum"))]
    if cli.prefer_post_quantum {
        tracing::warn!(
            "--prefer-post-quantum set but the post-quantum feature is not compiled in; \
             rebuild with --features post-quantum to enable PQ key exchange"
        );
    }

    #[cfg(not(feature = "post-quantum"))]
    if cli.kx_groups.is_some() {
        tracing::warn!(
            "--kx-groups set but the post-quantum feature is not compiled in; \
             rebuild with --features post-quantum to enable custom key exchange groups"
        );
    }

    tracing::info!(bind = %cli.bind, "rustgate starting");
    audit::server_started(&cli.bind, env!("CARGO_PKG_VERSION"));

    tokio::runtime::Runtime::new()?.block_on(run(cli))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    // ── TLS setup ───────────────────────────────────────────────────
    let (tls_config, _cert_pem, _key_pem, _ca_pem) = setup::build_tls_config(&cli).await?;
    let listener = setup::bind_tls_listener(&cli, &tls_config).await?;
    let framing = cli.framing;
    let encoding = cli.encoding;

    setup::validate_framing(&cli)?;

    let codec = cli::build_codec(framing, encoding);

    tracing::info!(addr = %listener.local_addr()?, framing = ?cli.framing, encoding = ?encoding, "listening");

    // Readiness flag for K8s health probes
    let ready = Arc::new(AtomicBool::new(true));

    // ── Metrics ─────────────────────────────────────────────────────
    #[cfg(all(feature = "metrics", feature = "federation"))]
    let fed_api_slot: Arc<std::sync::OnceLock<metrics::FedApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    #[cfg(feature = "metrics")]
    setup::start_metrics(
        &cli,
        &ready,
        #[cfg(feature = "federation")]
        &fed_api_slot,
    )?;

    #[cfg(not(feature = "metrics"))]
    setup::warn_metrics_disabled(&cli);

    // ── Connection limit ────────────────────────────────────────────
    // CLI validation ensures max_connections is 1..=u32::MAX
    let max_connections: u32 = cli.max_connections as u32;
    let group_acl = setup::load_group_acl(&cli).await?;
    let router = Arc::new(match group_acl {
        Some(acl) => Router::with_acl(acl),
        None => Router::new(),
    });
    let connection_limit = Arc::new(Semaphore::new(max_connections as usize));

    // ── NATS ────────────────────────────────────────────────────────
    #[cfg(feature = "nats")]
    let nats_publisher = setup::connect_nats(&cli, &router).await;

    #[cfg(not(feature = "nats"))]
    let nats_publisher: Option<()> = {
        setup::warn_nats_disabled(&cli);
        None
    };

    // ── Enrollment ──────────────────────────────────────────────────
    #[cfg(feature = "enrollment")]
    setup::start_enrollment(&cli, &_ca_pem, &_cert_pem, &_key_pem, &router).await?;

    #[cfg(not(feature = "enrollment"))]
    setup::warn_enrollment_disabled(&cli);

    // ── Federation ──────────────────────────────────────────────────
    #[cfg(feature = "federation")]
    let (fed_forward, fed_shutdown_handle): (
        Option<FedForwardFn>,
        Option<Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>>,
    ) = setup::start_federation(
        &cli,
        &router,
        #[cfg(feature = "metrics")]
        &fed_api_slot,
    )
    .await?;

    #[cfg(not(feature = "federation"))]
    let fed_forward: Option<FedForwardFn> = setup::warn_federation_disabled(&cli);

    #[cfg(not(feature = "federation-ha"))]
    setup::warn_federation_ha_disabled(&cli);

    // ── Per-client rate limiting ────────────────────────────────────
    let throttle_config = setup::build_throttle_config(&cli);

    // ── Anti-replay filter ─────────────────────────────────────────
    let replay_filter =
        rustgate_transport::ReplayFilter::from_secs(cli.replay_window).map(Arc::new);
    if replay_filter.is_some() {
        tracing::info!(
            window_secs = cli.replay_window,
            "anti-replay detection enabled"
        );
    }

    // ── WebSocket listener ──────────────────────────────────────────
    #[cfg(feature = "websocket")]
    let ws_shutdown = setup::start_websocket(setup::WebSocketSetup {
        cli: &cli,
        tls_config: &tls_config,
        router: &router,
        connection_limit: &connection_limit,
        codec: &codec,
        nats_publisher: &nats_publisher,
        fed_forward: &fed_forward,
        throttle_config,
        replay_filter: &replay_filter,
    })?;

    #[cfg(not(feature = "websocket"))]
    setup::warn_websocket_disabled(&cli);

    // ── CoT event archival ──────────────────────────────────────────
    let archiver = if let Some(ref dir) = cli.archive_dir {
        tracing::info!(dir = %dir, "CoT event archival enabled");
        Some(Arc::new(archive::CotArchiver::new(dir)))
    } else {
        None
    };

    // ── Plaintext TCP listener ──────────────────────────────────────
    let tcp_plaintext_shutdown = setup::start_plaintext_tcp(
        &cli,
        &router,
        &connection_limit,
        &codec,
        &nats_publisher,
        &fed_forward,
        throttle_config,
        &archiver,
        &replay_filter,
    )
    .await?;

    // ── UDP input listener ──────────────────────────────────────────
    let udp_shutdown =
        setup::start_udp(&cli, &router, &nats_publisher, &fed_forward, &replay_filter).await?;

    // ── Accept loop ─────────────────────────────────────────────────
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok(session) => {
                        #[cfg(feature = "metrics")]
                        {
                            metrics::connections_accepted().inc();
                            metrics::connections_active().inc();
                        }

                        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                #[cfg(feature = "metrics")]
                                {
                                    metrics::connections_rejected().inc();
                                    metrics::connections_active().dec();
                                }
                                tracing::warn!(max = max_connections, "connection limit reached, rejecting");
                                audit::connection_rejected(session.peer_addr(), "connection limit reached");
                                continue;
                            }
                        };
                        let router = Arc::clone(&router);
                        #[allow(clippy::clone_on_copy)] // Type varies by feature flag
                        let publisher = nats_publisher.clone();
                        let fed = fed_forward.clone();
                        let tc = throttle_config;
                        let arch = archiver.clone();
                        let rf = replay_filter.clone();
                        let deps = SessionDeps {
                            router,
                            framing,
                            codec: codec.clone(),
                            nats_publisher: publisher,
                            fed_forward: fed,
                            throttle_config: tc,
                            archiver: arch,
                            replay_filter: rf,
                            circuit_breaker_threshold: cli.circuit_breaker_threshold,
                        };
                        setup::spawn_background("tls-session", session::handle_session(session, deps, permit));
                    }
                    Err(e) => {
                        #[cfg(feature = "metrics")]
                        {
                            metrics::accept_errors().inc();
                            let reason = metrics::classify_handshake_error(&e.to_string());
                            metrics::handshake_failures()
                                .with_label_values(&[reason])
                                .inc();
                        }
                        tracing::warn!(error = %e, "accept error");
                    }
                }
            }
            _ = shutdown_signal() => {
                tracing::info!("shutdown signal received");
                ready.store(false, Ordering::Release);
                break;
            }
        }
    }

    // ── Shutdown ────────────────────────────────────────────────────
    // Stop listeners first so no new connections are accepted during drain.

    #[cfg(feature = "federation")]
    if let Some(ref rwlock) = fed_shutdown_handle {
        let mut mgr = rwlock.write().await;
        mgr.shutdown().await;
        tracing::info!("federation shut down");
    }

    #[cfg(feature = "websocket")]
    if let Some(handle) = ws_shutdown {
        setup::stop_subsystem("websocket", handle).await;
    }

    if let Some(handle) = tcp_plaintext_shutdown {
        setup::stop_subsystem("plaintext-tcp", handle).await;
    }
    if let Some(handle) = udp_shutdown {
        setup::stop_subsystem("udp", handle).await;
    }

    // ── Connection draining ─────────────────────────────────────────

    let active = router.session_count().await;
    tracing::info!(sessions = active, "draining connections");

    let drain_timeout = Duration::from_secs(110);
    let drain = connection_limit.acquire_many(max_connections);

    match tokio::time::timeout(drain_timeout, drain).await {
        Ok(Ok(_permits)) => tracing::info!("all sessions drained"),
        Ok(Err(_)) => tracing::warn!("semaphore closed during drain"),
        Err(_) => {
            tracing::warn!(
                sessions = router.session_count().await,
                "drain timeout reached, forcing exit"
            );
        }
    }

    // Flush pending OTel spans before exit.
    #[cfg(feature = "otel")]
    otel::shutdown();

    Ok(())
}

/// Wait for SIGTERM or SIGINT (Ctrl-C).
///
/// K8s sends SIGTERM during pod eviction; SIGINT covers local development.
/// On non-Unix platforms only Ctrl-C is available.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to register SIGTERM handler, falling back to Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
