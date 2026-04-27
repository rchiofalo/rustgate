// Copyright © 2026 Roberto Chiofalo.

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

use anyhow::Context as _;
use tokio::sync::Semaphore;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

#[cfg(feature = "metrics")]
mod acl_api;
mod acl_config;
mod acl_reloader;
mod archive;
mod archive_rotation;
mod audit;
mod authz_reloader;
mod cli;
mod diagnostics;
#[cfg(feature = "federation")]
mod federation_reloader;
#[cfg(feature = "metrics")]
mod metrics;
#[cfg(feature = "metrics")]
mod mgmt_api;
#[cfg(feature = "otel")]
mod otel;
#[cfg(all(feature = "otel", feature = "metrics"))]
mod otel_metrics;
mod session;
mod setup;

use cli::{Cli, Command};
use rustgate_core::tasks::{spawn_background, stop_subsystem};
use rustgate_transport::{BackpressureGate, Router};
use session::{FedForwardFn, SessionDeps};

/// Adapter that buffers `Write` calls and emits a single AEAD-sealed chunk
/// per `flush`. Used by the audit log layer so each tracing event becomes
/// one encrypted record on disk.
struct EncryptedLineWriter {
    inner: Arc<rustgate_core::encrypted::SharedEncryptedWriter>,
    buf: Vec<u8>,
}

impl EncryptedLineWriter {
    fn new(inner: Arc<rustgate_core::encrypted::SharedEncryptedWriter>) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(1024),
        }
    }
}

/// Carrier for the audit-log anchor lifecycle. Created during tracing setup
/// (before the subscriber is installed) and threaded into [`run`] so the
/// post-drain shutdown path can refresh `<audit_path>.anchor` with the final
/// hash-chain tip. A pending-break variant captures a discontinuity detected
/// at startup so the follow-up `audit.chain_discontinuity` record can be
/// emitted *after* tracing is live — otherwise the event would land on
/// stderr instead of in the audit log itself.
enum AuditAnchorHandle {
    /// A mismatch was detected between the persisted anchor and the live
    /// tip, and `--audit-allow-chain-break` was set. The break is recorded
    /// and forwarded to the Active variant once the chain writer is wired
    /// in so the event can land in the hash-chained audit trail.
    PendingBreak {
        path: std::path::PathBuf,
        anchor_tip: String,
        live_tip: String,
    },
    /// Writer is live; the observer reflects the chain tip after every
    /// record. `break_info` is set only on the first run after a
    /// `--audit-allow-chain-break` override so the post-tracing-init
    /// emission can include the expected/actual pair in the audit event.
    Active {
        path: std::path::PathBuf,
        tip_observer: Arc<arc_swap::ArcSwap<String>>,
        break_info: Option<(String, String)>,
    },
}

impl AuditAnchorHandle {
    fn pending_break(path: std::path::PathBuf, anchor_tip: String, live_tip: String) -> Self {
        Self::PendingBreak {
            path,
            anchor_tip,
            live_tip,
        }
    }
}

impl std::io::Write for EncryptedLineWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        self.inner
            .write_line(&self.buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.buf.clear();
        Ok(())
    }
}

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
        Some(Command::CheckConfig {
            ref config,
            strict,
            json,
        }) => {
            // Side-effect-free validation: the diagnostic builds and
            // prints its own report and then surfaces the exit-code
            // contract (0 ok, 1 invalid, 2 unreadable). We translate
            // `2` straight to `process::exit` so the caller's wrapper
            // can branch on the code without parsing stderr.
            let code = diagnostics::check_config::run(config, strict, json)?;
            if code != 0 {
                std::process::exit(code);
            }
            return Ok(());
        }
        Some(Command::DecryptArchive {
            ref input,
            ref output,
            ref key_file,
        }) => {
            let ring = rustgate_core::encrypted::KeyRing::load(key_file)
                .map_err(|e| anyhow::anyhow!("failed to load key file: {e}"))?;
            rustgate_core::encrypted::decrypt_file(input, output, &ring)
                .map_err(|e| anyhow::anyhow!("decrypt failed: {e}"))?;
            println!("decrypted {} -> {}", input.display(), output.display());
            return Ok(());
        }
        Some(Command::VerifyAudit { ref file }) => {
            match rustgate_core::audit_chain::verify_audit_log(std::path::Path::new(file)) {
                Ok(report) => {
                    println!(
                        "audit log OK: {} records verified, tip={}, tip_seq={}",
                        report.records, report.tip, report.tip_seq
                    );
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("audit log verification FAILED: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some(Command::CertInfo { ref file, json }) => {
            diagnostics::cert_info::run(file, json)?;
            return Ok(());
        }
        Some(Command::CrlInfo { ref file, json }) => {
            diagnostics::crl_info::run(file, json)?;
            return Ok(());
        }
        Some(Command::CheckCertExpiry {
            ref files,
            warn_days,
            json,
        }) => {
            let code = diagnostics::check_cert_expiry::run(files, warn_days, json)?;
            if code != 0 {
                std::process::exit(code);
            }
            return Ok(());
        }
        Some(Command::GenerateConfig) => {
            diagnostics::generate_config::run()?;
            return Ok(());
        }
        Some(Command::TestConnection {
            ref tcp,
            #[cfg(feature = "nats")]
            ref nats,
            #[cfg(feature = "http")]
            ref http,
            timeout_secs,
            json,
        }) => {
            // Translate the flag-style CLI into the probe's internal
            // `Target` enum. Exactly one target must be set — clap
            // enforces mutual exclusion, but we still need to catch
            // the all-none case (no flag supplied at all) with a
            // friendly error rather than a panic.
            let target = {
                #[cfg(all(feature = "nats", feature = "http"))]
                {
                    match (tcp, nats, http) {
                        (Some(t), None, None) => {
                            diagnostics::test_connection::Target::Tcp(t.clone())
                        }
                        (None, Some(u), None) => {
                            diagnostics::test_connection::Target::Nats(u.clone())
                        }
                        (None, None, Some(u)) => {
                            diagnostics::test_connection::Target::Http(u.clone())
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "test-connection requires exactly one of --tcp, --nats, --http"
                            ));
                        }
                    }
                }
                #[cfg(all(feature = "nats", not(feature = "http")))]
                {
                    match (tcp, nats) {
                        (Some(t), None) => diagnostics::test_connection::Target::Tcp(t.clone()),
                        (None, Some(u)) => diagnostics::test_connection::Target::Nats(u.clone()),
                        _ => {
                            return Err(anyhow::anyhow!(
                                "test-connection requires exactly one of --tcp, --nats"
                            ));
                        }
                    }
                }
                #[cfg(all(not(feature = "nats"), feature = "http"))]
                {
                    match (tcp, http) {
                        (Some(t), None) => diagnostics::test_connection::Target::Tcp(t.clone()),
                        (None, Some(u)) => diagnostics::test_connection::Target::Http(u.clone()),
                        _ => {
                            return Err(anyhow::anyhow!(
                                "test-connection requires exactly one of --tcp, --http"
                            ));
                        }
                    }
                }
                #[cfg(all(not(feature = "nats"), not(feature = "http")))]
                {
                    match tcp {
                        Some(t) => diagnostics::test_connection::Target::Tcp(t.clone()),
                        None => {
                            return Err(anyhow::anyhow!(
                                "test-connection requires --tcp HOST:PORT"
                            ));
                        }
                    }
                }
            };
            let code = diagnostics::test_connection::run(target, timeout_secs, json)?;
            if code != 0 {
                std::process::exit(code);
            }
            return Ok(());
        }
        None => {}
    }

    cli.validate()?;

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer().json();

    // Optional encryption key ring shared by the audit log and CoT archive.
    let archive_key_ring: Option<Arc<rustgate_core::encrypted::KeyRing>> =
        if let Some(ref kp) = cli.archive_key_file {
            let ring = rustgate_core::encrypted::KeyRing::load(kp).map_err(|e| {
                anyhow::anyhow!("failed to load --archive-key-file {}: {e}", kp.display())
            })?;
            tracing::debug!(active_key_id = %ring.active_key_id(), "loaded archive key ring");
            Some(Arc::new(ring))
        } else {
            None
        };

    // Handle persisted across startup → shutdown so the anchor file can be
    // refreshed on clean exit. Populated only on the plain-file audit-log
    // path (not "-" / stdout, not the encrypted-archive path — the latter
    // restarts at genesis each run because the on-disk record format is
    // opaque without the key). Issue #718.
    let mut audit_anchor_handle: Option<AuditAnchorHandle> = None;

    // Dedicated audit log sink: filters only target="audit" events and writes
    // JSON lines to the configured file (or stdout when "-"). When an archive
    // key file is configured and the path is not "-", events are encrypted
    // per-line using ChaCha20-Poly1305.
    let audit_layer = if let Some(ref audit_path) = cli.audit_log {
        let writer: std::sync::Mutex<Box<dyn std::io::Write + Send>> = if audit_path == "-" {
            // Stdout sinks start each process with a genesis chain since
            // there is no persistent file to resume from.
            let chain = rustgate_core::audit_chain::HashChainWriter::new(
                std::io::stdout(),
                rustgate_core::audit_chain::GENESIS_PREV.to_string(),
            );
            std::sync::Mutex::new(Box::new(chain))
        } else if let Some(ref ring) = archive_key_ring {
            // Encrypted audit log: wrap the encrypted line writer in the
            // hash chain so each line is hash-chained, then encrypted.
            // The chain restarts at genesis because the on-disk format is
            // opaque without the key; tip recovery is not supported here.
            let enc = rustgate_core::encrypted::SharedEncryptedWriter::create(
                std::path::Path::new(audit_path),
                ring,
            )
            .map_err(|e| anyhow::anyhow!("failed to open encrypted audit log {audit_path}: {e}"))?;
            let chain = rustgate_core::audit_chain::HashChainWriter::new(
                EncryptedLineWriter::new(Arc::new(enc)),
                rustgate_core::audit_chain::GENESIS_PREV.to_string(),
            );
            std::sync::Mutex::new(Box::new(chain))
        } else {
            let path = std::path::Path::new(audit_path);

            // Compare the persisted anchor (from last clean shutdown) with
            // the live tip recovered from the audit log itself. A mismatch
            // means either the log was rotated without carrying the anchor
            // forward, restored from backup, or tampered with — all three
            // cases warrant operator attention. The audit.chain_discontinuity
            // event below is emitted *after* tracing init so it lands in the
            // audit log, not in the early stderr stream. Issue #718.
            match rustgate_core::audit_chain::check_chain_continuity(path) {
                Ok(rustgate_core::audit_chain::ChainContinuity::NoAnchor) => {
                    // First run after enabling the audit log; benign. The
                    // anchor is persisted on the next clean shutdown.
                }
                Ok(rustgate_core::audit_chain::ChainContinuity::Match { .. }) => {
                    // Chain continuous across the last shutdown; all good.
                }
                Ok(rustgate_core::audit_chain::ChainContinuity::Mismatch {
                    anchor_tip,
                    live_tip,
                }) => {
                    if !cli.audit_allow_chain_break {
                        anyhow::bail!(
                            "audit chain discontinuity detected for {audit_path}: \
                             anchor tip `{anchor_tip}` does not match live tip \
                             `{live_tip}`. Investigate the log for tampering or \
                             rotation without anchor carry-forward, then rerun \
                             with --audit-allow-chain-break to continue from the \
                             current tip (the break will be recorded in the audit \
                             trail)."
                        );
                    }
                    // Operator opt-in: fall through; the audit.chain_discontinuity
                    // event is emitted below once tracing is live so the
                    // operational decision is captured in the audit trail
                    // itself.
                    audit_anchor_handle = Some(AuditAnchorHandle::pending_break(
                        path.to_path_buf(),
                        anchor_tip,
                        live_tip,
                    ));
                }
                Err(e) => {
                    anyhow::bail!("failed to evaluate audit log continuity for {audit_path}: {e}");
                }
            }

            let (prev, next_seq) =
                rustgate_core::audit_chain::read_chain_state(path).map_err(|e| {
                    anyhow::anyhow!("failed to read audit log chain state {audit_path}: {e}")
                })?;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(audit_path)
                .map_err(|e| anyhow::anyhow!("failed to open audit log {audit_path}: {e}"))?;
            let tip_observer = Arc::new(arc_swap::ArcSwap::from_pointee(prev.clone()));
            let chain = rustgate_core::audit_chain::HashChainWriter::new(file, prev)
                .with_next_seq(next_seq)
                .with_tip_observer(Arc::clone(&tip_observer));
            // Upgrade the handle (or create one) so shutdown knows which
            // path + observer to persist.
            audit_anchor_handle = Some(match audit_anchor_handle.take() {
                Some(AuditAnchorHandle::PendingBreak {
                    path: bp,
                    anchor_tip,
                    live_tip,
                }) => AuditAnchorHandle::Active {
                    path: bp,
                    tip_observer: Arc::clone(&tip_observer),
                    break_info: Some((anchor_tip, live_tip)),
                },
                _ => AuditAnchorHandle::Active {
                    path: path.to_path_buf(),
                    tip_observer: Arc::clone(&tip_observer),
                    break_info: None,
                },
            });
            std::sync::Mutex::new(Box::new(chain))
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

    // Dedicated access log sink: filters only target="access" events and
    // appends one JSON line per routed message. Opt-in via --access-log.
    let access_layer = if let Some(ref access_path) = cli.access_log {
        let writer: std::sync::Mutex<Box<dyn std::io::Write + Send>> = if access_path == "-" {
            std::sync::Mutex::new(Box::new(std::io::stdout()))
        } else {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(access_path)
                .map_err(|e| anyhow::anyhow!("failed to open access log {access_path}: {e}"))?;
            std::sync::Mutex::new(Box::new(file))
        };
        let filter = tracing_subscriber::filter::Targets::new()
            .with_target(rustgate_transport::ACCESS_LOG_TARGET, tracing::Level::INFO);
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
        .with(access_layer)
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

    // If the operator opted into a chain break via --audit-allow-chain-break,
    // record it in the audit log now that the subscriber is installed. This
    // ensures the break is cryptographically chained from the live tip
    // forward, with the anchor/live pair captured so a downstream SIEM can
    // correlate the skip with the subsequent anchor_persisted event on
    // clean shutdown.
    if let Some(AuditAnchorHandle::Active {
        path,
        break_info: Some((anchor_tip, live_tip)),
        ..
    }) = audit_anchor_handle.as_ref()
    {
        rustgate_core::audit::chain_discontinuity(
            &path.display().to_string(),
            anchor_tip,
            live_tip,
            "continue",
            "operator_opt_in_audit_allow_chain_break",
        );
    }

    tokio::runtime::Runtime::new()?.block_on(run(cli, audit_anchor_handle))
}

async fn run(cli: Cli, audit_anchor_handle: Option<AuditAnchorHandle>) -> anyhow::Result<()> {
    // ── TLS setup ───────────────────────────────────────────────────
    let tls_build = setup::build_tls_config(&cli).await?;
    let tls_config = tls_build.tls_config;
    let _cert_pem = tls_build.cert_pem;
    let _key_pem = tls_build.key_pem;
    let _ca_pem = tls_build.ca_pem;
    #[cfg(feature = "spiffe")]
    let tls_handle = setup::bind_tls_listener(&cli, &tls_config, tls_build.spiffe_identity).await?;
    #[cfg(not(feature = "spiffe"))]
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

    // Differentiated health probe state for K8s liveness/readiness/startup.
    // `live` flips on inside `metrics::serve` when the metrics server binds.
    // `ready` is set after listener + ACL + (optional) federation init.
    // `started` is a one-shot, flipped after the accept loop is reached.
    #[cfg(feature = "metrics")]
    let health = Arc::new(metrics::HealthState::new());
    // Legacy compatibility shim: a number of code paths still use a bare
    // `ready` AtomicBool to gate accept-loop behaviour. Keep it for now —
    // it shadows the readiness portion of `HealthState`.
    let ready = Arc::new(AtomicBool::new(true));

    // Readiness dependency state — holds handles to subsystems so the
    // `/readyz` endpoint can inspect their health.
    #[cfg(feature = "metrics")]
    let readiness = Arc::new(metrics::ReadinessState {
        cert_reloader: cert_reloader.as_ref().map(Arc::clone),
        #[cfg(feature = "nats")]
        nats_publisher: std::sync::Mutex::new(None),
        #[cfg(feature = "federation")]
        federation_manager: std::sync::Mutex::new(None),
        #[cfg(feature = "http")]
        http_publisher: std::sync::Mutex::new(None),
    });

    // ── Metrics ─────────────────────────────────────────────────────
    #[cfg(all(feature = "metrics", feature = "federation"))]
    let fed_api_slot: Arc<std::sync::OnceLock<metrics::FedApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    #[cfg(feature = "metrics")]
    let acl_api_slot: Arc<std::sync::OnceLock<metrics::AclApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    #[cfg(feature = "metrics")]
    let mgmt_api_slot: Arc<std::sync::OnceLock<metrics::MgmtApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    #[cfg(feature = "metrics")]
    let router_slot: metrics::RouterSlot = Arc::new(std::sync::OnceLock::new());

    #[cfg(feature = "metrics")]
    let metrics_identity = setup::start_metrics(
        &cli,
        &health,
        &readiness,
        #[cfg(feature = "federation")]
        &fed_api_slot,
        &acl_api_slot,
        &mgmt_api_slot,
        &router_slot,
    )
    .await?;

    #[cfg(not(feature = "metrics"))]
    setup::warn_metrics_disabled(&cli);

    // ── OTLP metrics export (optional) ──────────────────────────────
    //
    // When `--otlp-metrics` is set we install a second exporter that
    // scrapes the Prometheus default registry on an interval and pushes
    // the translated metrics to the same OTLP endpoint configured for
    // traces. The `/metrics` scrape target is unaffected — this is an
    // additive sink, not a replacement.
    #[cfg(all(feature = "otel", feature = "metrics"))]
    if cli.otlp_metrics {
        match cli.otel_endpoint.as_deref() {
            Some(endpoint) => {
                otel_metrics::init(
                    endpoint,
                    &cli.otel_service_name,
                    Duration::from_secs(cli.otlp_metrics_interval),
                )?;
                tracing::info!(
                    endpoint = %endpoint,
                    interval_secs = cli.otlp_metrics_interval,
                    "OTLP metrics export enabled"
                );
            }
            None => {
                anyhow::bail!(
                    "--otlp-metrics requires --otel-endpoint (or OTEL_EXPORTER_OTLP_ENDPOINT) \
                     to be set so traces and metrics can share the same OTLP collector URL"
                );
            }
        }
    }

    #[cfg(all(feature = "otel", not(feature = "metrics")))]
    if cli.otlp_metrics {
        tracing::warn!(
            "--otlp-metrics requires --features metrics; rebuild with --features metrics,otel \
             to enable OTLP metrics export"
        );
    }

    #[cfg(not(feature = "otel"))]
    if cli.otlp_metrics {
        anyhow::bail!(
            "--otlp-metrics requires --features otel; rebuild with --features otel,metrics \
             to enable OTLP metrics export"
        );
    }

    // ── Connection limit ────────────────────────────────────────────
    // CLI validation ensures max_connections is 1..=u32::MAX
    let max_connections: u32 = cli.max_connections as u32;
    let (group_acl, acl_file_hash, acl_file_parsed) = setup::load_group_acl(&cli).await?;
    // ── Global admission control / backpressure gate ─────────────
    let mut backpressure_gate = BackpressureGate::with_limits(
        cli.max_queued_bytes,
        cli.max_queued_bytes_low_water
            .unwrap_or_else(|| cli.max_queued_bytes.saturating_mul(9) / 10),
    );
    BackpressureGate::with_resume_dwell(
        &mut backpressure_gate,
        std::time::Duration::from_millis(cli.backpressure_resume_dwell_ms),
    )
    .context("configure backpressure resume dwell")?;
    #[cfg(feature = "metrics")]
    {
        BackpressureGate::set_on_deferred(
            &mut backpressure_gate,
            Arc::new(|| {
                metrics::admission_deferred_total().inc();
            }),
        )
        .context("install backpressure deferred-callback")?;
        BackpressureGate::set_on_bytes_changed(
            &mut backpressure_gate,
            Arc::new(|n| {
                metrics::queued_bytes().set(i64::try_from(n).unwrap_or(i64::MAX));
            }),
        )
        .context("install backpressure bytes-changed callback")?;
    }
    tracing::info!(
        max_queued_bytes = backpressure_gate.high_water(),
        low_water_bytes = backpressure_gate.low_water(),
        resume_dwell_ms = cli.backpressure_resume_dwell_ms,
        "admission control enabled"
    );

    let client_queue: Option<Arc<rustgate_transport::ClientQueue>> =
        if let Some(ref dir) = cli.client_queue_dir {
            // Choose the open mode: persistent-key > explicit-wipe > plain.
            // The plain `open` now fails closed if the on-disk queue has
            // entries and no persistent key was supplied (F-49 / #740).
            let open_result = if let Some(ref key_path) = cli.client_queue_key_file {
                let key = read_queue_key_file(key_path)
                    .map_err(|e| anyhow::anyhow!("--client-queue-key-file: {e}"))?;
                rustgate_transport::ClientQueue::open_with_hmac_key(
                    dir,
                    cli.client_queue_max_bytes,
                    Some(key),
                )
            } else if cli.client_queue_wipe_on_start {
                rustgate_transport::ClientQueue::open_with_wipe(dir, cli.client_queue_max_bytes)
            } else {
                rustgate_transport::ClientQueue::open(dir, cli.client_queue_max_bytes)
            };

            let q = open_result.map_err(|e| {
                anyhow::anyhow!(
                    "failed to open client store-and-forward queue at {}: {e}. \
                     Supply --client-queue-key-file to preserve stored messages, \
                     or --client-queue-wipe-on-start to explicitly discard them.",
                    dir.display()
                )
            })?;
            tracing::info!(
                dir = %dir.display(),
                max_bytes = cli.client_queue_max_bytes,
                persistent_key = cli.client_queue_key_file.is_some(),
                wipe_on_start = cli.client_queue_wipe_on_start,
                "per-client store-and-forward queue enabled"
            );
            Some(Arc::new(q))
        } else {
            None
        };
    // ── Per-tenant quota tracker ────────────────────────────────────
    let quota_tracker: Option<Arc<rustgate_transport::TenantQuotaTracker>> =
        if let Some(ref path) = cli.tenant_quota_file {
            match rustgate_transport::TenantQuotaTracker::load_config(path) {
                Ok(config) => {
                    let tracker = Arc::new(rustgate_transport::TenantQuotaTracker::new(config));
                    tracing::info!(
                        path = %path.display(),
                        "per-tenant quota tracker loaded"
                    );
                    Some(tracker)
                }
                Err(e) => {
                    anyhow::bail!("failed to load tenant quota file {}: {e}", path.display());
                }
            }
        } else {
            None
        };

    let router = Arc::new({
        let base = (match group_acl {
            Some(acl) => Router::with_acl(acl),
            None => Router::new(),
        })
        .with_backpressure(Arc::clone(&backpressure_gate))
        // Issue #728: apply the unknown-obligation policy at
        // construction time. Default (`false`) keeps the router in
        // fail-closed mode; operators opt into fail-open via
        // `--authz-allow-unknown-obligations` /
        // `RUSTGATE_AUTHZ_ALLOW_UNKNOWN_OBLIGATIONS`.
        .with_allow_unknown_obligations(cli.authz_allow_unknown_obligations)
        // Issue #724: cap per-CN position replay events with a
        // TokenBucket so a flap-looping client cannot drive the
        // authz engine at an uncapped rate. Defaults
        // (rate=100/sec, burst=200) are operator-safe.
        .with_position_replay_limit(rustgate_transport::PositionReplayLimitConfig::new(
            cli.position_replay_rate_per_sec,
            cli.position_replay_burst,
        ));
        // Issue #769: install the unknown-obligation rate limiter
        // with the metric callback so
        // `rustgate_authz_obligation_unknown_total{variant=...}`
        // observes every encounter regardless of audit-log
        // suppression. Without `metrics`, the default limiter (no
        // callback) still applies the audit-rate cap.
        #[cfg(feature = "metrics")]
        let base = {
            let limiter = rustgate_transport::obligations::ObligationRateLimiter::default()
                .with_on_unknown(std::sync::Arc::new(|variant: &str| {
                    metrics::authz_obligation_unknown()
                        .with_label_values(&[variant])
                        .inc();
                }));
            base.with_obligation_rate_limiter(std::sync::Arc::new(limiter))
        };
        let base = match client_queue.as_ref() {
            Some(q) => base.with_client_queue(Arc::clone(q)),
            None => base,
        };
        match quota_tracker {
            Some(tracker) => base.with_quota_tracker(tracker),
            None => base,
        }
    });

    // Populate the router slot so the metrics server can serve
    // /health/authz responses.
    #[cfg(feature = "metrics")]
    let _ = router_slot.set(Arc::clone(&router));

    // Feed the `rustgate_position_cache_size` gauge whenever the cache
    // mutates. The callback is a lock-free hot-swap via `ArcSwap`, so
    // this installs cheaply and fires on every `store`/`remove`/`sweep`.
    #[cfg(feature = "metrics")]
    router.cache().set_on_size(std::sync::Arc::new(|size| {
        metrics::position_cache_size().set(size as i64);
    }));

    #[cfg(feature = "metrics")]
    if let Some(ref q) = client_queue {
        metrics::spawn_client_queue_metrics_task(Arc::clone(q), Arc::clone(&metrics_identity));
        // Issue #729: per-message dwell observation. The callback is
        // invoked synchronously inside `ClientQueue::drain` once per
        // returned message, so a single drain of N messages produces
        // N histogram observations — characterizing per-message
        // experience, not per-batch.
        q.set_on_drain_observation(std::sync::Arc::new(|dwell_seconds| {
            metrics::store_forward_dwell_seconds().observe(dwell_seconds);
        }));
    }

    // ── Cross-path deduplication ───────────────────────────────────
    #[cfg_attr(not(feature = "metrics"), allow(unused_mut))]
    if let Some(mut dedup) =
        rustgate_transport::DedupCache::from_secs(cli.dedup_window_secs, cli.dedup_cache_size)
            .map(|d| d.with_cross_tenant(cli.dedup_cross_tenant))
    {
        #[cfg(feature = "metrics")]
        {
            dedup.set_on_duplicate(std::sync::Arc::new(|| {
                metrics::dedup_hits().inc();
            }));
            dedup.set_on_insert(std::sync::Arc::new(|len| {
                metrics::dedup_cache_size().set(len as i64);
            }));
        }
        router.set_dedup(Some(dedup));
        if cli.dedup_cross_tenant {
            tracing::warn!(
                window_secs = cli.dedup_window_secs,
                cache_size = cli.dedup_cache_size,
                "cross-path message deduplication enabled WITHOUT tenant \
                 isolation (--dedup-cross-tenant); cross-tenant timing \
                 side-channel is open (issue #722) — only use in \
                 single-tenant deployments or with explicit operator \
                 acceptance",
            );
        } else {
            tracing::info!(
                window_secs = cli.dedup_window_secs,
                cache_size = cli.dedup_cache_size,
                "cross-path message deduplication enabled (tenant-isolated)"
            );
        }
    }

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

    // ── Authz (RBAC/ABAC) policy + hot-reload ──────────────────────
    //
    // If `--authz-policy-file` is set, load it synchronously so startup
    // fails fast on a malformed policy (unless `--authz-fail-open` is
    // set, in which case we log a warning and continue without any
    // engine installed). On success, install the engine on the router,
    // wire the metrics observer, and spawn the polling reloader.
    if let Some(ref authz_path) = cli.authz_policy_file {
        let path = std::path::PathBuf::from(authz_path);

        // Cedar backend selection is mutually exclusive with the native
        // reloader path: the native polling watcher assumes a
        // `NativeEngine`, so Cedar loads once at startup without
        // hot-reload. Future follow-up can generalize the reloader.
        match cli.authz_policy_format {
            crate::cli::AuthzPolicyFormat::Cedar => {
                #[cfg(feature = "cedar")]
                {
                    match rustgate_authz::CedarBackend::from_file(&path) {
                        Ok(engine) => {
                            let arc_engine: Arc<dyn rustgate_authz::PolicyEngine> =
                                Arc::new(engine);
                            let policy_id = arc_engine.policy_id().to_string();
                            router.swap_authz(arc_engine);
                            #[cfg(feature = "metrics")]
                            {
                                router.set_authz_observer(Some(Arc::new(
                                    metrics::observe_authz_event,
                                )));
                                metrics::record_authz_reload(true, None);
                            }
                            rustgate_core::audit::authz_reload_success(authz_path, &policy_id, 0);
                            tracing::info!(
                                path = %authz_path,
                                policy_id = %policy_id,
                                backend = "cedar",
                                "authz policy loaded"
                            );
                        }
                        Err(e) if cli.authz_fail_open => {
                            rustgate_core::audit::authz_reload_failed(
                                authz_path,
                                "startup",
                                &e.to_string(),
                            );
                            // Fail-open startup is the operational
                            // equivalent of a rollback to "no policy
                            // installed" — no engine was previously
                            // loaded, so the rollback record carries
                            // `previous_policy_id = None`. Closes
                            // #818 (F-144).
                            rustgate_core::audit::authz_reload_rollback("startup", None);
                            #[cfg(feature = "metrics")]
                            {
                                metrics::record_authz_reload(false, None);
                                metrics::record_reload_rollback("authz");
                            }
                            tracing::warn!(
                                path = %authz_path,
                                error = %e,
                                "cedar authz policy failed to load; continuing in fail-open mode"
                            );
                        }
                        Err(e) => {
                            #[cfg(feature = "metrics")]
                            metrics::record_authz_reload(false, None);
                            return Err(anyhow::anyhow!(
                                "failed to load cedar policy {authz_path}: {e}"
                            ));
                        }
                    }
                }
                #[cfg(not(feature = "cedar"))]
                {
                    return Err(anyhow::anyhow!(
                        "--authz-policy-format=cedar requires building rustgate with --features cedar"
                    ));
                }
            }
            crate::cli::AuthzPolicyFormat::Native => match authz_reloader::load_once(&path) {
                Ok(loaded) => {
                    let rule_count = loaded.rule_count;
                    let initial_hash = loaded.hash;
                    let arc_engine: Arc<dyn rustgate_authz::PolicyEngine> = Arc::new(loaded.engine);
                    let policy_id = arc_engine.policy_id().to_string();
                    router.swap_authz(arc_engine);
                    #[cfg(feature = "metrics")]
                    {
                        router.set_authz_observer(Some(Arc::new(metrics::observe_authz_event)));
                        metrics::record_authz_reload(true, Some(rule_count));
                    }
                    rustgate_core::audit::authz_reload_success(authz_path, &policy_id, rule_count);
                    tracing::info!(
                        path = %authz_path,
                        policy_id = %policy_id,
                        rule_count,
                        "authz policy loaded"
                    );

                    let interval = Duration::from_secs(cli.authz_reload_interval);
                    let _reloader = authz_reloader::spawn_authz_reloader(
                        Arc::clone(&router),
                        path,
                        initial_hash,
                        interval,
                    );

                    // Background cache-stats scraper: every 10s, snapshot the
                    // currently installed engine's decision-cache counters and
                    // publish deltas to the Prometheus counters. Uses the
                    // router's `authz_snapshot()` so a reload naturally picks
                    // up the new engine on the next tick instead of pinning
                    // the old `Arc`.
                    #[cfg(feature = "metrics")]
                    {
                        let router_for_stats = Arc::clone(&router);
                        drop(tokio::spawn(async move {
                            let mut tick = tokio::time::interval(Duration::from_secs(10));
                            let mut last_hits: u64 = 0;
                            let mut last_misses: u64 = 0;
                            let _ = tick.tick().await;
                            loop {
                                let _ = tick.tick().await;
                                let Some(engine) = router_for_stats.authz_snapshot() else {
                                    continue;
                                };
                                if let Some(stats) = engine.cache_stats() {
                                    let hits = stats.hits;
                                    let misses = stats.misses;
                                    // Deltas vs last snapshot. A policy swap
                                    // resets the counters on the new engine,
                                    // so clamp to zero to avoid underflow.
                                    let hd = hits.saturating_sub(last_hits);
                                    let md = misses.saturating_sub(last_misses);
                                    metrics::record_authz_cache_stats(hd, md);
                                    last_hits = hits;
                                    last_misses = misses;
                                }
                            }
                        }));
                    }
                    tracing::info!(
                        interval_secs = cli.authz_reload_interval,
                        path = %authz_path,
                        "authz hot-reload enabled"
                    );
                }
                Err(e) if cli.authz_fail_open => {
                    rustgate_core::audit::authz_reload_failed(
                        authz_path,
                        "startup",
                        &e.to_string(),
                    );
                    // Fail-open startup is the operational equivalent
                    // of a rollback to "no policy installed". Closes
                    // #818 (F-144).
                    rustgate_core::audit::authz_reload_rollback("startup", None);
                    #[cfg(feature = "metrics")]
                    {
                        metrics::record_authz_reload(false, None);
                        metrics::record_reload_rollback("authz");
                    }
                    tracing::warn!(
                        path = %authz_path,
                        error = %e,
                        "authz policy failed to load; continuing in fail-open mode (no engine installed)"
                    );

                    // Even in fail-open mode, spawn the watcher so that
                    // once the operator fixes the policy file on disk the
                    // next poll cycle parses, compiles, and installs it
                    // without requiring a server restart. The sentinel
                    // hash `[0u8; 32]` can never match a real SHA-256
                    // digest of any file the reloader successfully reads,
                    // so the first successful parse+compile will swap
                    // the engine in.
                    #[cfg(feature = "metrics")]
                    router.set_authz_observer(Some(Arc::new(metrics::observe_authz_event)));
                    let interval = Duration::from_secs(cli.authz_reload_interval);
                    let _reloader = authz_reloader::spawn_authz_reloader(
                        Arc::clone(&router),
                        path,
                        [0u8; 32],
                        interval,
                    );
                    tracing::info!(
                        interval_secs = cli.authz_reload_interval,
                        path = %authz_path,
                        "authz hot-reload enabled (fail-open retry)"
                    );
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    metrics::record_authz_reload(false, None);
                    return Err(e);
                }
            },
        }
    }

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
                // Routed through the shared `read_secret_file` helper so
                // the ACL API token file is now subject to the unified
                // size cap, mode 0o077 perm gate, and empty-file
                // rejection (closes #797). Operators with overly-
                // permissive token files will see a hard error here
                // instead of a silent passthrough.
                let token_str = rustgate_core::read_secret_file(
                    token_file,
                    &rustgate_core::SecretFileOpts::default(),
                )
                .map_err(|e| {
                    anyhow::anyhow!("failed to read ACL API token file {token_file}: {e}")
                })?;
                let token = token_str.as_bytes().to_vec();
                acl_api::validate_bearer_token_length(&token, "ACL API")
                    .map_err(|e| anyhow::anyhow!("{e} (from {token_file})"))?;
                let initial_file = acl_file_parsed.unwrap_or_default();
                let api_state = Arc::new(acl_api::AclApiState {
                    current: Arc::new(std::sync::RwLock::new(initial_file)),
                    router: Arc::clone(&router),
                    reloader: acl_reloader_for_api,
                    file_path: std::path::PathBuf::from(acl_file),
                    auth_token: zeroize::Zeroizing::new(token),
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

    // Register NATS client with readiness state for health checks.
    #[cfg(all(feature = "nats", feature = "metrics"))]
    if let Some(ref publisher) = nats_publisher {
        readiness.set_nats_publisher(publisher.clone());
    }

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

    // Register federation manager with readiness state for health checks.
    #[cfg(all(feature = "federation", feature = "metrics"))]
    if let Some(ref mgr) = fed_shutdown_handle {
        readiness.set_federation_manager(Arc::clone(mgr));
    }

    #[cfg(not(feature = "federation"))]
    let fed_forward: Option<FedForwardFn> = setup::warn_federation_disabled(&cli);

    #[cfg(not(feature = "federation-ha"))]
    setup::warn_federation_ha_disabled(&cli);

    // ── Federation peer hot-reload ──────────────────────────────────
    //
    // When `--federation-peers-file` is set, install a reloader that
    // re-reads the file on SIGHUP (and optionally on a polling interval)
    // and reconciles the manager's active peer set. Adds/removes are
    // applied without disturbing existing connections.
    #[cfg(feature = "federation")]
    let fed_peer_reloader: Option<Arc<federation_reloader::FederationPeerReloader>> =
        if let (Some(peers_path), Some(rwlock)) = (
            cli.federation_peers_file.as_ref(),
            fed_shutdown_handle.as_ref(),
        ) {
            let initial = std::fs::read(peers_path).unwrap_or_default();
            let initial_hash = federation_reloader::FederationPeerReloader::compute_hash(&initial);
            let reloader = federation_reloader::FederationPeerReloader::new(
                std::path::PathBuf::from(peers_path),
                Arc::clone(rwlock),
                initial_hash,
            );
            if cli.federation_peers_reload_interval > 0 {
                reloader.spawn_watcher(Duration::from_secs(cli.federation_peers_reload_interval));
                tracing::info!(
                    interval_secs = cli.federation_peers_reload_interval,
                    path = %peers_path,
                    "federation peer hot-reload enabled"
                );
            }
            Some(reloader)
        } else {
            None
        };

    // ── Federation peer discovery (issue #571) ──────────────────────
    //
    // Spawned only when `--federation-peer-discovery` selects a backend
    // other than `none`. Returns a shutdown sender that's held here so
    // the reconciler exits cleanly during graceful shutdown. Mutually
    // exclusive with `--federation-peers-file` (enforced by clap's
    // `conflicts_with`).
    #[cfg(feature = "federation")]
    let _fed_discovery_shutdown: Option<tokio::sync::watch::Sender<bool>> =
        if let Some(rwlock) = fed_shutdown_handle.as_ref() {
            setup::start_federation_peer_discovery(&cli, rwlock)?
        } else {
            // Federation disabled at runtime — warn if the flag was set.
            use crate::cli::PeerDiscoveryBackend;
            if cli.federation_peer_discovery != PeerDiscoveryBackend::None {
                tracing::warn!(
                    "--federation-peer-discovery requires federation to be configured; ignoring"
                );
            }
            None
        };
    #[cfg(not(feature = "federation"))]
    setup::warn_federation_peer_discovery_disabled(&cli);

    // ── HTTP egress ─────────────────────────────────────────────────
    #[cfg(feature = "http")]
    let (http_forward, _http_publisher): (Option<session::HttpForwardFn>, _) = {
        match setup::connect_http(&cli).await {
            Some((fwd, publisher)) => {
                #[cfg(feature = "metrics")]
                readiness.set_http_publisher(publisher.clone());
                (Some(fwd), Some(publisher))
            }
            None => (None, None),
        }
    };

    #[cfg(not(feature = "http"))]
    setup::warn_http_disabled(&cli);

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
        #[cfg(feature = "http")]
        http_forward: &http_forward,
        throttle_config,
        replay_filter: &replay_filter,
    })?;

    #[cfg(not(feature = "websocket"))]
    setup::warn_websocket_disabled(&cli);

    // ── MQTT listener ──────────────────────────────────────────────
    #[cfg(feature = "mqtt")]
    let mqtt_shutdown = setup::start_mqtt(setup::MqttSetup {
        cli: &cli,
        tls_config: &tls_config,
        router: &router,
        connection_limit: &connection_limit,
        nats_publisher: &nats_publisher,
        fed_forward: &fed_forward,
        #[cfg(feature = "http")]
        http_forward: &http_forward,
    })?;

    #[cfg(not(feature = "mqtt"))]
    setup::warn_mqtt_disabled(&cli);

    // ── CoT event archival ──────────────────────────────────────────
    let archive_key_ring: Option<Arc<rustgate_core::encrypted::KeyRing>> =
        if let Some(ref kp) = cli.archive_key_file {
            Some(Arc::new(
                rustgate_core::encrypted::KeyRing::load(kp)
                    .map_err(|e| anyhow::anyhow!("failed to load archive key file: {e}"))?,
            ))
        } else {
            None
        };

    let archiver = if let Some(ref dir) = cli.archive_dir {
        if let Some(ref ring) = archive_key_ring {
            tracing::info!(
                dir = %dir,
                active_key_id = %ring.active_key_id(),
                "CoT event archival enabled (encrypted)"
            );
            Some(Arc::new(archive::CotArchiver::with_encryption(
                dir,
                Arc::clone(ring),
            )))
        } else {
            tracing::info!(dir = %dir, "CoT event archival enabled");
            Some(Arc::new(archive::CotArchiver::new(dir)))
        }
    } else {
        None
    };

    // ── CoT archive retention / rotation ───────────────────────────
    let archive_rotation_handle = if let Some(ref dir) = cli.archive_dir
        && (cli.archive_max_size > 0 || cli.archive_max_age > 0 || cli.archive_max_active_bytes > 0)
    {
        let cfg = archive_rotation::RotationConfig {
            dir: std::path::PathBuf::from(dir),
            max_bytes: cli.archive_max_size,
            max_active_bytes: cli.archive_max_active_bytes,
            max_age: std::time::Duration::from_secs(cli.archive_max_age),
            // `cli.validate()` enforces `archive_rotate_interval >= 60` when
            // rotation is enabled (F-69), so the `.max(1)` defense here is
            // redundant — the value is already safe at this point.
            interval: std::time::Duration::from_secs(cli.archive_rotate_interval),
            archiver: archiver.clone(),
        };
        tracing::info!(
            dir = %dir,
            max_bytes = cli.archive_max_size,
            max_active_bytes = cli.archive_max_active_bytes,
            max_age_secs = cli.archive_max_age,
            interval_secs = cli.archive_rotate_interval,
            "CoT archive rotation enabled",
        );
        Some(archive_rotation::spawn(cfg))
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
        #[cfg(feature = "http")]
        &http_forward,
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

    // ── Management REST API ────────────────────────────────────────
    //
    // Registered only when `--mgmt-api-token-file` is supplied. Exposes
    // read-only status endpoints (`/api/cert/status`, `/api/crl/status`,
    // `/api/dedup/stats`) and write endpoints (`/api/clients/{cn}/
    // disconnect`, `/api/reload`). All routes require
    // `Authorization: Bearer` and are constant-time compared.
    //
    // Deferred until after `fed_peer_reloader` is constructed so the
    // `/api/reload` callback can capture every component the SIGHUP
    // path reloads — cert, ACL, CRL, OCSP stapler, federation peers.
    // The metrics server dispatcher reads `mgmt_api_slot.get()` on each
    // request, so setting it this late is race-free.
    #[cfg(feature = "metrics")]
    {
        if let Some(ref token_file) = cli.mgmt_api_token_file {
            // Closes #797: route through the shared `read_secret_file`
            // helper so the management API token file is subject to the
            // unified perm/size/empty/UTF-8 discipline. The helper is
            // synchronous, but the read happens once at startup —
            // running it inside `tokio::task::spawn_blocking` would add
            // complexity for no measurable benefit in a single-shot
            // bring-up path.
            let token_path = token_file.clone();
            let token_str = tokio::task::spawn_blocking(move || {
                rustgate_core::read_secret_file(
                    &token_path,
                    &rustgate_core::SecretFileOpts::default(),
                )
            })
            .await
            .map_err(|e| anyhow::anyhow!("blocking task panic: {e}"))?
            .map_err(|e| {
                anyhow::anyhow!("failed to read management API token file {token_file}: {e}")
            })?;
            let token = token_str.as_bytes().to_vec();
            acl_api::validate_bearer_token_length(&token, "management API")
                .map_err(|e| anyhow::anyhow!("{e} (from {token_file})"))?;

            // Capture the same handles the SIGHUP reloader uses so the
            // HTTP-triggered reload path takes exactly the same code
            // path and emits the same audit events — operators should
            // not be able to tell the two surfaces apart by their
            // side-effects.
            let cert_for_reload = cert_reloader.clone();
            let acl_for_reload = acl_reloader_handle.clone();
            let crl_path_for_reload = cli.crl.clone();
            #[cfg(feature = "ocsp")]
            let ocsp_for_reload = ocsp_stapler.clone();
            #[cfg(feature = "federation")]
            let fed_peers_for_reload = fed_peer_reloader.clone();

            // Only build the reload callback if at least one reloadable
            // component is wired up — otherwise `POST /api/reload` has
            // nothing to do and should 503 rather than pretend success.
            let has_reloadable = cert_for_reload.is_some()
                || acl_for_reload.is_some()
                || crl_path_for_reload.is_some();
            #[cfg(feature = "federation")]
            let has_reloadable = has_reloadable || fed_peers_for_reload.is_some();

            let reload_fn: Option<mgmt_api::ReloadFn> = if has_reloadable {
                Some(Arc::new(move || {
                    let cert = cert_for_reload.clone();
                    let acl = acl_for_reload.clone();
                    let crl = crl_path_for_reload.clone();
                    #[cfg(feature = "ocsp")]
                    let ocsp = ocsp_for_reload.clone();
                    #[cfg(feature = "federation")]
                    let fed = fed_peers_for_reload.clone();
                    Box::pin(async move {
                        let report = reload_all_configs(
                            cert.as_ref(),
                            acl.as_ref(),
                            crl.as_deref(),
                            #[cfg(feature = "ocsp")]
                            ocsp.as_ref(),
                            #[cfg(feature = "federation")]
                            fed.as_ref(),
                        )
                        .await;
                        serde_json::to_value(&report).unwrap_or_else(|e| {
                            serde_json::json!({
                                "error": format!("serialize reload report: {e}")
                            })
                        })
                    })
                }))
            } else {
                None
            };

            let api_state = Arc::new(mgmt_api::MgmtApiState {
                router: Arc::clone(&router),
                cert_reloader: cert_reloader.as_ref().map(Arc::clone),
                crl_path: cli.crl.as_ref().map(std::path::PathBuf::from),
                reload: reload_fn,
                #[cfg(feature = "http")]
                http_publisher: _http_publisher.clone(),
                auth_token: zeroize::Zeroizing::new(token),
            });
            let handler: metrics::MgmtApiHandler = Arc::new(move |method, path, auth, body| {
                let api_state = Arc::clone(&api_state);
                let method = method.clone();
                let path = path.to_string();
                let auth = auth.map(|s| s.to_string());
                let body = body.to_vec();
                Box::pin(async move {
                    mgmt_api::handle_request(&method, &path, auth.as_deref(), &body, &api_state)
                        .await
                })
            });
            let _ = mgmt_api_slot.set(handler);
            tracing::info!(
                "management REST API enabled at /api/cert/, /api/crl/, /api/dedup/, \
                 /api/clients/, /api/dlq/, and /api/reload"
            );
        }
    }

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
        #[cfg(feature = "federation")]
        let fed_peers_for_hup = fed_peer_reloader.clone();
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(mut sighup) => {
                spawn_background("sighup-reloader", async move {
                    while sighup.recv().await.is_some() {
                        tracing::info!("SIGHUP received, reloading config");
                        let _ = reload_all_configs(
                            cert_for_hup.as_ref(),
                            acl_for_hup.as_ref(),
                            crl_path_for_hup.as_deref(),
                            #[cfg(feature = "ocsp")]
                            ocsp_for_hup.as_ref(),
                            #[cfg(feature = "federation")]
                            fed_peers_for_hup.as_ref(),
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
    // Initial init pass is complete: listener bound, ACL loaded, and
    // (when enabled) federation peers wired. Flip readiness on, then
    // mark startup as complete (one-shot — never flipped back).
    #[cfg(feature = "metrics")]
    {
        health.set_ready(true);
        // One-shot transition: never resets, even on shutdown.
        let _ = health.mark_started();
    }
    loop {
        // Global backpressure: park the accept loop while the router's
        // in-flight byte counter is over the high-water mark. Connections
        // are deferred (not errored) until the counter drops back below
        // the low-water mark.
        backpressure_gate.wait_for_capacity().await;

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
                        // justification: `nats_publisher` is `()` when the
                        // `nats` feature is off and `Option<NatsPublisher>`
                        // when it is on. `.clone()` is the one spelling that
                        // compiles in both configurations; dereferencing
                        // would break the featureless build.
                        #[allow(clippy::clone_on_copy)]
                        let publisher = nats_publisher.clone();
                        let fed = fed_forward.clone();
                        #[cfg(feature = "http")]
                        let http = http_forward.clone();
                        let tc = throttle_config;
                        let arch = archiver.clone();
                        let rf = replay_filter.clone();
                        let deps = SessionDeps {
                            router,
                            framing,
                            codec: codec.clone(),
                            nats_publisher: publisher,
                            fed_forward: fed,
                            #[cfg(feature = "http")]
                            http_forward: http,
                            throttle_config: tc,
                            archiver: arch,
                            replay_filter: rf,
                            circuit_breaker_threshold: cli.circuit_breaker_threshold,
                            delta_config: session::DeltaConfig {
                                enabled: cli.cot_delta_encoding,
                                cache_size: cli.cot_delta_cache_size,
                                epsilon_meters: cli.cot_delta_epsilon_meters,
                            },
                            negotiation_timeout: std::time::Duration::from_secs(
                                cli.negotiation_timeout_secs,
                            ),
                            #[cfg(feature = "metrics")]
                            metrics_identity: Arc::clone(&metrics_identity),
                        };
                        spawn_background("tls-session", session::handle_session(session, deps, permit));
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
                #[cfg(feature = "metrics")]
                health.set_ready(false);
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

    #[cfg(feature = "http")]
    if let Some(ref publisher) = _http_publisher {
        publisher.shutdown().await;
        tracing::info!("HTTP egress shut down");
    }

    #[cfg(feature = "websocket")]
    if let Some(handle) = ws_shutdown {
        stop_subsystem("websocket", handle).await;
    }

    #[cfg(feature = "mqtt")]
    if let Some(handle) = mqtt_shutdown {
        stop_subsystem("mqtt", handle).await;
    }

    if let Some(handle) = tcp_plaintext_shutdown {
        stop_subsystem("plaintext-tcp", handle).await;
    }
    if let Some(handle) = udp_shutdown {
        stop_subsystem("udp", handle).await;
    }
    if let Some(handle) = archive_rotation_handle {
        handle.abort();
    }

    // ── Connection draining ─────────────────────────────────────────

    let active = router.session_count().await;
    tracing::info!(
        sessions = active,
        drain_timeout_secs = cli.shutdown_drain_timeout,
        "draining connections"
    );

    // Close every session's outbound channels so write loops observe a
    // clean EOF after flushing whatever is currently buffered. The
    // session task itself still runs through its normal cleanup path,
    // releasing its semaphore permit when the writer returns.
    let closed = router.close_all_session_senders().await;
    tracing::debug!(closed_sessions = closed, "closed session outbound channels");

    let drain_timeout = Duration::from_secs(cli.shutdown_drain_timeout);
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

    // Persist the audit-chain tip to `<audit_path>.anchor` so the next
    // startup can detect tampering (truncation, log rotation without
    // anchor carry-forward, restore-from-backup) via a mismatch. Issue
    // #718. Emitted *before* the OTel/OTLP flushes so the anchor-persisted
    // audit record lands in the same chain as the tip it records — if the
    // anchor write fails the failure record is still the final entry in
    // the current chain.
    if let Some(AuditAnchorHandle::Active {
        path, tip_observer, ..
    }) = audit_anchor_handle.as_ref()
    {
        let tip: String = (**tip_observer.load()).clone();
        match rustgate_core::audit_chain::write_anchor(path, &tip) {
            Ok(()) => {
                rustgate_core::audit::chain_anchor_persisted(&path.display().to_string(), &tip);
            }
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "failed to persist audit chain anchor at shutdown"
                );
                rustgate_core::audit::chain_anchor_persist_failed(
                    &path.display().to_string(),
                    &e.to_string(),
                );
            }
        }
    }

    // Flush pending OTel spans before exit.
    #[cfg(feature = "otel")]
    otel::shutdown();

    // Flush pending OTLP metrics before exit so the last batch is
    // delivered to the collector rather than dropped on the floor.
    #[cfg(all(feature = "otel", feature = "metrics"))]
    otel_metrics::shutdown();

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

/// On-wire per-component result entry in [`ReloadReport`].
///
/// `changed` carries the component-specific "work was done" bit — for
/// `cert` it is the rotated flag, for `acl` and `federation_peers` it is
/// the swapped flag, and for `crl` it is always `None` (CRL is re-parsed
/// not hot-swapped). Keeping the field optional rather than e.g. a
/// defaulted `false` prevents operators from misreading "no cert
/// reloader configured" as "cert did not rotate."
#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct ComponentReloadOutcome {
    /// `"success"`, `"failure"`, or `"skipped"` when the component is
    /// not configured on this server.
    pub(crate) result: &'static str,
    /// Human-readable error when `result == "failure"`. `None` otherwise.
    pub(crate) error: Option<String>,
    /// Component-specific "something changed" bit.
    pub(crate) changed: Option<bool>,
    /// CRL-only: number of entries parsed at reload time.
    pub(crate) crl_count: Option<u64>,
    /// CRL-only: age in seconds of the stalest CRL's `thisUpdate`.
    pub(crate) crl_max_age_seconds: Option<i64>,
}

impl ComponentReloadOutcome {
    fn skipped() -> Self {
        Self {
            result: "skipped",
            ..Self::default()
        }
    }
    fn success(changed: Option<bool>) -> Self {
        Self {
            result: "success",
            changed,
            ..Self::default()
        }
    }
    fn failure(error: impl std::fmt::Display) -> Self {
        Self {
            result: "failure",
            error: Some(error.to_string()),
            ..Self::default()
        }
    }
}

/// Aggregate structured result of a single [`reload_all_configs`] pass.
///
/// SIGHUP fires this and discards the result (the audit log carries the
/// per-component outcomes). The HTTP `POST /api/reload` endpoint fires
/// the same path and serializes this struct to the caller, so operators
/// can tell from the response whether cert + ACL + CRL all reloaded
/// cleanly without scraping the audit stream.
#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct ReloadReport {
    pub(crate) cert: ComponentReloadOutcome,
    pub(crate) acl: ComponentReloadOutcome,
    pub(crate) crl: ComponentReloadOutcome,
    #[cfg(feature = "federation")]
    pub(crate) federation_peers: ComponentReloadOutcome,
}

/// Reload server config components in sequence on a SIGHUP-style signal.
///
/// Each component is reloaded independently — a failure in one does not
/// prevent the others from running. Structured audit events are emitted
/// per component so operators can correlate reload outcomes, and the
/// returned [`ReloadReport`] carries the same per-component status for
/// HTTP callers that want a structured response rather than a tail of
/// the audit log.
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
    #[cfg(feature = "federation")] fed_peer_reloader: Option<
        &Arc<federation_reloader::FederationPeerReloader>,
    >,
) -> ReloadReport {
    let mut report = ReloadReport::default();

    // 1. Server certificate
    if let Some(reloader) = cert_reloader {
        let r = Arc::clone(reloader);
        let join = tokio::task::spawn_blocking(move || r.reload()).await;
        report.cert = match join {
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
                ComponentReloadOutcome::success(Some(rotated))
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
                ComponentReloadOutcome::failure(e)
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
                ComponentReloadOutcome::failure(e)
            }
        };
    } else {
        tracing::debug!("SIGHUP: no cert reloader configured (cert_reload_interval=0)");
        report.cert = ComponentReloadOutcome::skipped();
    }

    // 2. Group ACL policy
    if let Some(reloader) = acl_reloader {
        let r = Arc::clone(reloader);
        let join = tokio::task::spawn_blocking(move || r.reload()).await;
        report.acl = match join {
            Ok(Ok(swapped)) => {
                tracing::info!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "acl",
                    result = "success",
                    swapped = swapped,
                    "ACL reload completed"
                );
                ComponentReloadOutcome::success(Some(swapped))
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
                ComponentReloadOutcome::failure(e)
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
                ComponentReloadOutcome::failure(e)
            }
        };
    } else {
        tracing::debug!("SIGHUP: no ACL reloader configured");
        report.acl = ComponentReloadOutcome::skipped();
    }

    // 3. CRL file (re-parse only — see function docs)
    if let Some(path) = crl_path {
        let path_owned = path.to_string();
        let join = tokio::task::spawn_blocking(move || reload_crl_file(&path_owned)).await;
        report.crl = match join {
            Ok(Ok(summary)) => {
                #[cfg(feature = "metrics")]
                if let Some(age) = summary.max_age_seconds {
                    metrics::crl_age_seconds().set(age);
                }
                tracing::info!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "crl",
                    result = "success",
                    crl_count = summary.count as u64,
                    crl_max_age_seconds = summary.max_age_seconds.unwrap_or_default(),
                    path = %path,
                    "CRL re-parsed (restart server to apply changes to active listener)"
                );
                ComponentReloadOutcome {
                    result: "success",
                    crl_count: Some(summary.count as u64),
                    crl_max_age_seconds: summary.max_age_seconds,
                    ..Default::default()
                }
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
                ComponentReloadOutcome::failure(e)
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
                ComponentReloadOutcome::failure(e)
            }
        };
    } else {
        tracing::debug!("SIGHUP: no CRL configured");
        report.crl = ComponentReloadOutcome::skipped();
    }

    // 4. Federation peers
    #[cfg(feature = "federation")]
    if let Some(reloader) = fed_peer_reloader {
        report.federation_peers = match reloader.reload().await {
            Ok(swapped) => {
                tracing::info!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "federation_peers",
                    result = "success",
                    swapped = swapped,
                    "federation peer reload completed"
                );
                ComponentReloadOutcome::success(Some(swapped))
            }
            Err(e) => {
                tracing::warn!(
                    target: "audit",
                    event_type = "config.reload",
                    component = "federation_peers",
                    result = "failure",
                    error = %e,
                    "federation peer reload failed"
                );
                ComponentReloadOutcome::failure(e)
            }
        };
    } else {
        #[cfg(feature = "federation")]
        {
            tracing::debug!("SIGHUP: no federation peer reloader configured");
            report.federation_peers = ComponentReloadOutcome::skipped();
        }
    }

    report
}

/// Read and parse a CRL PEM file. Returns a summary with the entry count
/// and the age in seconds of the stalest CRL on success.
///
/// Used by [`reload_all_configs`] to validate CRL files on SIGHUP without
/// touching the live TLS listener. The returned age is fed into the
/// `rustgate_crl_age_seconds` gauge so operators alert on stale CRLs.
fn reload_crl_file(path: &str) -> anyhow::Result<rustgate_transport::CrlFileSummary> {
    rustgate_transport::TlsConfig::validate_crl_file(path).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Maximum size of a client-queue HMAC key file (128 bytes — well above
/// the 65 bytes a 32-byte hex key + trailing newline needs). Prevents
/// mis-pointed paths from loading a log file as a key.
const MAX_QUEUE_KEY_FILE_BYTES: u64 = 128;

/// Read a client-queue HMAC key file and return the decoded 32-byte key
/// wrapped in [`zeroize::Zeroizing`]. The file must contain exactly
/// 64 hex characters (case-insensitive) with optional trailing
/// whitespace. On Unix, the file must be mode 0600/0400 and owned by
/// the running process's effective UID.
///
/// Delegates the perm/size/empty/UTF-8 discipline to the shared
/// [`rustgate_core::secrets::read_secret_file`] helper (closes #797);
/// only the hex-decode + length contract specific to the 32-byte HMAC
/// key remains here.
fn read_queue_key_file(path: &std::path::Path) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    let display = path.display().to_string();
    let mut opts = rustgate_core::SecretFileOpts {
        max_bytes: MAX_QUEUE_KEY_FILE_BYTES,
        ..rustgate_core::SecretFileOpts::default()
    };
    #[cfg(unix)]
    {
        opts.require_owner_uid = Some(rustix::process::geteuid().as_raw());
    }
    let trimmed = rustgate_core::read_secret_file(path, &opts)
        .map_err(|e| anyhow::anyhow!("client-queue key file `{display}`: {e}"))?;

    if trimmed.len() != 64 {
        anyhow::bail!(
            "client-queue key file `{display}` must contain exactly 64 hex \
             characters (got {})",
            trimmed.len()
        );
    }

    // Allocate the 32-byte output buffer zeroized; decode into it.
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(trimmed.as_bytes(), &mut *key)
        .map_err(|e| anyhow::anyhow!("client-queue key file `{display}` is not valid hex: {e}"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn reload_all_configs_tolerates_all_none() {
        // Should not panic when nothing is configured and every component
        // reports "skipped" rather than a masked failure.
        let report = reload_all_configs(
            None,
            None,
            None,
            #[cfg(feature = "ocsp")]
            None,
            #[cfg(feature = "federation")]
            None,
        )
        .await;
        assert_eq!(report.cert.result, "skipped");
        assert_eq!(report.acl.result, "skipped");
        assert_eq!(report.crl.result, "skipped");
        #[cfg(feature = "federation")]
        assert_eq!(report.federation_peers.result, "skipped");
    }

    #[tokio::test]
    async fn reload_all_configs_reports_crl_failure_without_aborting() {
        // Missing CRL path should produce a structured failure but return.
        let report = reload_all_configs(
            None,
            None,
            Some("/definitely/not/a/real/path.pem"),
            #[cfg(feature = "ocsp")]
            None,
            #[cfg(feature = "federation")]
            None,
        )
        .await;
        assert_eq!(
            report.crl.result, "failure",
            "expected failure for missing CRL path, got {:?}",
            report.crl
        );
        assert!(
            report.crl.error.is_some(),
            "failure must carry an error message"
        );
        // Other components stay skipped — a single failure must not
        // poison the aggregate report.
        assert_eq!(report.cert.result, "skipped");
        assert_eq!(report.acl.result, "skipped");
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
        let report = reload_all_configs(
            None,
            Some(&reloader),
            Some("/no/such/crl.pem"),
            #[cfg(feature = "ocsp")]
            None,
            #[cfg(feature = "federation")]
            None,
        )
        .await;
        assert_eq!(report.acl.result, "success");
        assert_eq!(report.acl.changed, Some(true));
        assert_eq!(report.crl.result, "failure");

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
