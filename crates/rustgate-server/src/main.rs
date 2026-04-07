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

use tokio::sync::Semaphore;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

#[cfg(feature = "metrics")]
mod acl_api;
mod acl_config;
mod acl_reloader;
mod archive;
mod audit;
mod cli;
#[cfg(feature = "metrics")]
mod metrics;
#[cfg(feature = "otel")]
mod otel;
mod session;
mod setup;

use cli::{Cli, Command};
use rustgate_transport::Router;
use session::{FedForwardFn, SessionDeps};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse_with_config()?;

    // Handle subcommands before any tracing/runtime setup. These are pure
    // utilities: print or validate the merged configuration and exit.
    match cli.command {
        Some(Command::PrintConfig) => {
            let toml = cli.to_toml()?;
            print!("{toml}");
            return Ok(());
        }
        Some(Command::ValidateConfig) => {
            cli.validate()?;
            println!("configuration is valid");
            return Ok(());
        }
        None => {}
    }

    cli.validate()?;

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
    let tls_handle = setup::bind_tls_listener(&cli, &tls_config).await?;
    let setup::TlsListenerHandle {
        listener,
        cert_reloader,
        #[cfg(feature = "ocsp")]
        ocsp_stapler,
    } = tls_handle;
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
    let acl_api_slot: Arc<std::sync::OnceLock<metrics::AclApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    #[cfg(feature = "metrics")]
    let metrics_identity = setup::start_metrics(
        &cli,
        &ready,
        #[cfg(feature = "federation")]
        &fed_api_slot,
        &acl_api_slot,
    )?;

    #[cfg(not(feature = "metrics"))]
    setup::warn_metrics_disabled(&cli);

    // ── Connection limit ────────────────────────────────────────────
    // CLI validation ensures max_connections is 1..=u32::MAX
    let max_connections: u32 = cli.max_connections as u32;
    let (group_acl, acl_file_hash, acl_file_parsed) = setup::load_group_acl(&cli).await?;
    let router = Arc::new(match group_acl {
        Some(acl) => Router::with_acl(acl),
        None => Router::new(),
    });

    // ── ACL hot-reload ─────────────────────────────────────────────
    //
    // We always construct an `AclReloader` when an ACL file is configured
    // (even if the polling interval is zero) so that SIGHUP-driven reloads
    // can use the same code path. The polling watcher is only spawned when
    // `acl_reload_interval > 0`.
    let mut acl_reloader_handle: Option<Arc<acl_reloader::AclReloader>> = None;
    if let Some(ref acl_file) = cli.group_acl_file {
        let initial_hash =
            acl_file_hash.unwrap_or_else(|| acl_reloader::AclReloader::compute_hash(b""));
        let reloader =
            acl_reloader::AclReloader::new(acl_file.clone(), Arc::clone(&router), initial_hash);
        if cli.acl_reload_interval > 0 {
            let interval = Duration::from_secs(cli.acl_reload_interval);
            reloader.spawn_watcher(interval);
            tracing::info!(
                interval_secs = cli.acl_reload_interval,
                path = %acl_file,
                "ACL hot-reload enabled"
            );
        }
        acl_reloader_handle = Some(reloader);
    }
    #[cfg(feature = "metrics")]
    let acl_reloader_for_api: Option<Arc<acl_reloader::AclReloader>> = acl_reloader_handle.clone();

    // ── ACL REST API ───────────────────────────────────────────────
    //
    // Only registered when both `--group-acl-file` and
    // `--acl-api-token-file` are set. The API exposes mutation of
    // routing policy, so it must be explicitly opted into with a
    // bearer token and is always backed by an on-disk file to
    // persist mutations to.
    #[cfg(feature = "metrics")]
    {
        match (&cli.group_acl_file, &cli.acl_api_token_file) {
            (Some(acl_file), Some(token_file)) => {
                let token = std::fs::read_to_string(token_file).map_err(|e| {
                    anyhow::anyhow!("failed to read ACL API token file {token_file}: {e}")
                })?;
                let token = token.trim().as_bytes().to_vec();
                if token.is_empty() {
                    anyhow::bail!("ACL API token file {token_file} is empty");
                }
                let initial_file = acl_file_parsed.unwrap_or_default();
                let api_state = Arc::new(acl_api::AclApiState {
                    current: Arc::new(std::sync::RwLock::new(initial_file)),
                    router: Arc::clone(&router),
                    reloader: acl_reloader_for_api,
                    file_path: std::path::PathBuf::from(acl_file),
                    auth_token: token,
                });
                let handler: metrics::AclApiHandler = Arc::new(move |method, path, auth, body| {
                    acl_api::handle_request(method, path, auth, body, &api_state)
                });
                let _ = acl_api_slot.set(handler);
                tracing::warn!(
                    "ACL REST API enabled at /api/acl/ — exposes mutation of routing policy; \
                     bind the metrics endpoint to a trusted network only"
                );
            }
            (Some(_), None) => {
                tracing::info!(
                    "ACL REST API disabled: --acl-api-token-file is required to expose /api/acl/"
                );
                let _ = acl_file_parsed;
            }
            _ => {
                let _ = acl_file_parsed;
            }
        }
    }
    #[cfg(not(feature = "metrics"))]
    let _ = acl_file_parsed;

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
        #[cfg(feature = "metrics")]
        &metrics_identity,
    )
    .await?;

    // ── UDP input listener ──────────────────────────────────────────
    let udp_shutdown =
        setup::start_udp(&cli, &router, &nats_publisher, &fed_forward, &replay_filter).await?;

    // ── SIGHUP config reload (Unix only) ───────────────────────────
    //
    // On SIGHUP we reload the server certificate, the group ACL policy,
    // and re-validate the CRL file from disk. Each component is reloaded
    // independently — partial failures do not abort the others. SIGHUP
    // reload is Unix-only; on other platforms the handler is omitted.
    #[cfg(unix)]
    {
        let cert_for_hup = cert_reloader.clone();
        let acl_for_hup = acl_reloader_handle.clone();
        let crl_path_for_hup = cli.crl.clone();
        #[cfg(feature = "ocsp")]
        let ocsp_for_hup = ocsp_stapler.clone();
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(mut sighup) => {
                setup::spawn_background("sighup-reloader", async move {
                    while sighup.recv().await.is_some() {
                        tracing::info!("SIGHUP received, reloading config");
                        reload_all_configs(
                            cert_for_hup.as_ref(),
                            acl_for_hup.as_ref(),
                            crl_path_for_hup.as_deref(),
                            #[cfg(feature = "ocsp")]
                            ocsp_for_hup.as_ref(),
                        )
                        .await;
                    }
                });
                tracing::info!("SIGHUP config reload handler installed");
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to register SIGHUP handler");
            }
        }
    }

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
                            #[cfg(feature = "metrics")]
                            metrics_identity: Arc::clone(&metrics_identity),
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
                            // Tier 2 per-identity handshake failures: the
                            // peer identity is unknown at this point
                            // (handshake failed before client cert
                            // verification surfaced a CN), so all events
                            // bucket under the literal "other" label.
                            if let Some(c) = metrics::per_identity_handshake_failures() {
                                c.with_label_values(&["other"]).inc();
                            }
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

    // Stop the OCSP stapler background fetcher (if it was started). Done
    // early so the task wakes up and exits while other subsystems drain.
    #[cfg(feature = "ocsp")]
    if let Some(ref stapler) = ocsp_stapler {
        stapler.stop().await;
        tracing::info!("OCSP stapler stopped");
    }

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

/// Reload server config components in sequence on a SIGHUP-style signal.
///
/// Each component is reloaded independently — a failure in one does not
/// prevent the others from running. Structured audit events are emitted
/// per component so operators can correlate reload outcomes.
///
/// `crl_path` is best-effort: it re-reads and parses the CRL file from
/// disk and reports parse / freshness issues, but the live TLS listener
/// does not currently swap CRLs at runtime — applying CRL changes still
/// requires a server restart. Re-parsing on SIGHUP catches operator
/// errors before the next restart.
async fn reload_all_configs(
    cert_reloader: Option<&Arc<rustgate_transport::CertReloader>>,
    acl_reloader: Option<&Arc<acl_reloader::AclReloader>>,
    crl_path: Option<&str>,
    #[cfg(feature = "ocsp")] ocsp_stapler: Option<&Arc<rustgate_transport::ocsp::Stapler>>,
) {
    // 1. Server certificate
    if let Some(reloader) = cert_reloader {
        let r = Arc::clone(reloader);
        let join = tokio::task::spawn_blocking(move || r.reload()).await;
        match join {
            Ok(Ok(rotated)) => {
                #[cfg(feature = "ocsp")]
                if rotated
                    && let Some(stapler) = ocsp_stapler
                    && let Some(ckey) = reloader.certified_key()
                {
                    // Seed the stapler with the freshly rotated cert so the
                    // background fetcher refreshes the OCSP cache without
                    // waiting for the next inbound handshake to surface the
                    // new leaf. There is still a brief unstapled window
                    // until the fetcher completes its OCSP request.
                    rustgate_transport::ocsp::preload(stapler, ckey);
                }
                tracing::info!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "cert",
                    result = "success",
                    rotated = rotated,
                    "certificate reload completed"
                );
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "cert",
                    result = "failure",
                    error = %e,
                    "certificate reload failed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "cert",
                    result = "failure",
                    error = %e,
                    "certificate reload task panicked"
                );
            }
        }
    } else {
        tracing::debug!("SIGHUP: no cert reloader configured (cert_reload_interval=0)");
    }

    // 2. Group ACL policy
    if let Some(reloader) = acl_reloader {
        let r = Arc::clone(reloader);
        let join = tokio::task::spawn_blocking(move || r.reload()).await;
        match join {
            Ok(Ok(swapped)) => {
                tracing::info!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "acl",
                    result = "success",
                    swapped = swapped,
                    "ACL reload completed"
                );
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "acl",
                    result = "failure",
                    error = %e,
                    "ACL reload failed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "acl",
                    result = "failure",
                    error = %e,
                    "ACL reload task panicked"
                );
            }
        }
    } else {
        tracing::debug!("SIGHUP: no ACL reloader configured");
    }

    // 3. CRL file (re-parse only — see function docs)
    if let Some(path) = crl_path {
        let path_owned = path.to_string();
        let join = tokio::task::spawn_blocking(move || reload_crl_file(&path_owned)).await;
        match join {
            Ok(Ok(count)) => {
                tracing::info!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "crl",
                    result = "success",
                    crl_count = count as u64,
                    path = %path,
                    "CRL re-parsed (restart server to apply changes to active listener)"
                );
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "crl",
                    result = "failure",
                    path = %path,
                    error = %e,
                    "CRL reload failed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "crl",
                    result = "failure",
                    path = %path,
                    error = %e,
                    "CRL reload task panicked"
                );
            }
        }
    } else {
        tracing::debug!("SIGHUP: no CRL configured");
    }
}

/// Read and parse a CRL PEM file. Returns the number of CRL entries on success.
///
/// Used by [`reload_all_configs`] to validate CRL files on SIGHUP without
/// touching the live TLS listener.
fn reload_crl_file(path: &str) -> anyhow::Result<usize> {
    rustgate_transport::TlsConfig::validate_crl_file(path).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn reload_all_configs_tolerates_all_none() {
        // Should not panic when nothing is configured.
        reload_all_configs(
            None,
            None,
            None,
            #[cfg(feature = "ocsp")]
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn reload_all_configs_reports_crl_failure_without_aborting() {
        // Missing CRL path should produce a structured failure but return.
        reload_all_configs(
            None,
            None,
            Some("/definitely/not/a/real/path.pem"),
            #[cfg(feature = "ocsp")]
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn reload_all_configs_reloads_acl_and_continues_on_crl_failure() {
        use std::collections::HashMap;

        let dir = tempfile::tempdir().unwrap();
        let acl_path = dir.path().join("acl.json");
        let initial = r#"{"groups":{}}"#;
        std::fs::write(&acl_path, initial).unwrap();
        let initial_hash = acl_reloader::AclReloader::compute_hash(initial.as_bytes());

        let router = Arc::new(rustgate_transport::Router::with_acl(
            rustgate_transport::GroupAclPolicy::new(HashMap::new()),
        ));
        let reloader = acl_reloader::AclReloader::new(&acl_path, Arc::clone(&router), initial_hash);

        // Sanity-check pre-reload state: empty policy collapses to open mode (None).
        {
            let snap = router.acl_snapshot();
            assert!(
                snap.as_ref().is_none(),
                "expected initial empty policy to be open mode"
            );
        }

        // Update the ACL file so reload() returns Ok(true)
        let updated = r#"{"groups":{"alpha":{"send":["alice"],"receive":["alice"]}}}"#;
        std::fs::write(&acl_path, updated).unwrap();

        // Pass an invalid CRL path to verify partial failure tolerance.
        reload_all_configs(
            None,
            Some(&reloader),
            Some("/no/such/crl.pem"),
            #[cfg(feature = "ocsp")]
            None,
        )
        .await;

        // Verify the router actually swapped to the new policy.
        let snap = router.acl_snapshot();
        let policy = snap
            .as_ref()
            .as_ref()
            .expect("acl policy installed after reload");
        assert!(
            policy.groups().contains_key("alpha"),
            "expected reloaded ACL to contain group 'alpha', got {:?}",
            policy.groups().keys().collect::<Vec<_>>()
        );
    }
}
