// Copyright © 2026 Roberto Chiofalo.

//! rustgate server binary — secure tactical message router.
//!
//! This module contains the entrypoint, async runtime orchestration, and
//! graceful shutdown logic. Subsystem initialization is delegated to [`setup`],
//! session handling to [`session`], and CLI parsing to [`cli`].

// `tikv-jemallocator` is POSIX-only and the dependency is target-gated
// under `cfg(not(target_os = "windows"))` in Cargo.toml. Mirror that
// gate here so a Windows build that nonetheless enables the `jemalloc`
// feature flag still compiles (it falls back to the system allocator on
// Windows). Refs #831 (F-B).
#[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
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

mod audit;
mod authz_reloader;
mod cli;
mod diagnostics;
#[cfg(feature = "federation")]
mod federation_reloader;
#[cfg(feature = "guard")]
mod guard;
mod mavlink;
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
mod tactical_ingress;

use cli::{Cli, Command};
use rustgate_core::tasks::{spawn_background, stop_subsystem};
use rustgate_router::Router;
use rustgate_transport::BackpressureGate;
use session::{FedForwardFn, SessionDeps};

/// Adapter that buffers `Write` calls and emits a single AEAD-sealed chunk
/// per `flush`. Used by the audit log layer so each tracing event becomes
/// one encrypted record on disk.
struct EncryptedLineWriter {
    inner: Arc<rustgate_archive::encrypted::SharedEncryptedWriter>,
    buf: Vec<u8>,
}

impl EncryptedLineWriter {
    fn new(inner: Arc<rustgate_archive::encrypted::SharedEncryptedWriter>) -> Self {
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
            let ring = rustgate_archive::encrypted::KeyRing::load(key_file)
                .map_err(|e| anyhow::anyhow!("failed to load key file: {e}"))?;
            rustgate_archive::encrypted::decrypt_file(input, output, &ring)
                .map_err(|e| anyhow::anyhow!("decrypt failed: {e}"))?;
            println!("decrypted {} -> {}", input.display(), output.display());
            return Ok(());
        }
        Some(Command::VerifyAudit { ref file }) => {
            match rustgate_archive::audit_chain::verify_audit_log(std::path::Path::new(file)) {
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
            // Translate the in-band exit-code contract (0 = ok, 2 =
            // stale; 1 = parse failure surfaced via the `?` above) to
            // a process exit so cron jobs and Ansible playbooks can
            // branch on `$?` without parsing stderr.
            let code = diagnostics::crl_info::run(file, json)?;
            if code != 0 {
                std::process::exit(code);
            }
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
        Some(Command::GenerateConfig { minimal }) => {
            diagnostics::generate_config::run(diagnostics::generate_config::BuildOpts { minimal })?;
            return Ok(());
        }
        Some(Command::TestConnection {
            ref tcp,
            ref tls,
            ref target_cert,
            ref target_key,
            ref target_ca,
            ref server_name,
            peer_cert_warn_days,
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
            let tls_target = if let Some(addr) = tls.as_ref() {
                Some(build_tls_target(
                    addr,
                    target_cert.as_deref(),
                    target_key.as_deref(),
                    target_ca.as_deref(),
                    server_name.as_deref(),
                    peer_cert_warn_days,
                )?)
            } else {
                None
            };

            let target = {
                #[cfg(all(feature = "nats", feature = "http"))]
                {
                    match (tcp, tls_target, nats, http) {
                        (Some(t), None, None, None) => {
                            diagnostics::test_connection::Target::Tcp(t.clone())
                        }
                        (None, Some(t), None, None) => diagnostics::test_connection::Target::Tls(t),
                        (None, None, Some(u), None) => {
                            diagnostics::test_connection::Target::Nats(u.clone())
                        }
                        (None, None, None, Some(u)) => {
                            diagnostics::test_connection::Target::Http(u.clone())
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "test-connection requires exactly one of --tcp, --tls, --nats, --http"
                            ));
                        }
                    }
                }
                #[cfg(all(feature = "nats", not(feature = "http")))]
                {
                    match (tcp, tls_target, nats) {
                        (Some(t), None, None) => {
                            diagnostics::test_connection::Target::Tcp(t.clone())
                        }
                        (None, Some(t), None) => diagnostics::test_connection::Target::Tls(t),
                        (None, None, Some(u)) => {
                            diagnostics::test_connection::Target::Nats(u.clone())
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "test-connection requires exactly one of --tcp, --tls, --nats"
                            ));
                        }
                    }
                }
                #[cfg(all(not(feature = "nats"), feature = "http"))]
                {
                    match (tcp, tls_target, http) {
                        (Some(t), None, None) => {
                            diagnostics::test_connection::Target::Tcp(t.clone())
                        }
                        (None, Some(t), None) => diagnostics::test_connection::Target::Tls(t),
                        (None, None, Some(u)) => {
                            diagnostics::test_connection::Target::Http(u.clone())
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "test-connection requires exactly one of --tcp, --tls, --http"
                            ));
                        }
                    }
                }
                #[cfg(all(not(feature = "nats"), not(feature = "http")))]
                {
                    match (tcp, tls_target) {
                        (Some(t), None) => diagnostics::test_connection::Target::Tcp(t.clone()),
                        (None, Some(t)) => diagnostics::test_connection::Target::Tls(t),
                        _ => {
                            return Err(anyhow::anyhow!(
                                "test-connection requires exactly one of --tcp, --tls"
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
        #[cfg(feature = "schema")]
        Some(Command::EmitSchema) => {
            diagnostics::emit_schema::run()?;
            return Ok(());
        }
        Some(Command::MigrateConfig {
            ref config,
            ref output,
            ref from,
        }) => {
            // Pure file rewrite. Runs offline, never opens listeners,
            // never validates the migrated output — pipe through
            // `validate-config` for that. The diagnostic propagates
            // its typed error variants so a CI wrapper can branch on
            // `unrecognized version` vs. `read failed` without
            // parsing stderr.
            diagnostics::migrate_config::run(config, output.as_deref(), from.as_deref())?;
            return Ok(());
        }
        Some(Command::DumpState {
            ref config,
            format,
            ref output,
        }) => {
            // dump-state runs offline against the same `--config` the
            // server consumes — it never opens a listener, so doing
            // the work here (before tracing init / runtime spin-up)
            // mirrors the other diagnostic subcommands.
            diagnostics::dump_state::run(config, format, output.as_deref())?;
            return Ok(());
        }
        None => {}
    }

    cli.validate()?;

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer().json();

    // Optional encryption key ring shared by the audit log and CoT archive.
    let archive_key_ring: Option<Arc<rustgate_archive::encrypted::KeyRing>> =
        if let Some(ref kp) = cli.archive_key_file {
            let ring = rustgate_archive::encrypted::KeyRing::load(kp).map_err(|e| {
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
            let chain = rustgate_archive::audit_chain::HashChainWriter::new(
                std::io::stdout(),
                rustgate_archive::audit_chain::GENESIS_PREV.to_string(),
            );
            std::sync::Mutex::new(Box::new(chain))
        } else if let Some(ref ring) = archive_key_ring {
            // Encrypted audit log: wrap the encrypted line writer in the
            // hash chain so each line is hash-chained, then encrypted.
            // The chain restarts at genesis because the on-disk format is
            // opaque without the key; tip recovery is not supported here.
            let enc = rustgate_archive::encrypted::SharedEncryptedWriter::create(
                std::path::Path::new(audit_path),
                ring,
            )
            .map_err(|e| anyhow::anyhow!("failed to open encrypted audit log {audit_path}: {e}"))?;
            let chain = rustgate_archive::audit_chain::HashChainWriter::new(
                EncryptedLineWriter::new(Arc::new(enc)),
                rustgate_archive::audit_chain::GENESIS_PREV.to_string(),
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
            match rustgate_archive::audit_chain::check_chain_continuity(path) {
                Ok(rustgate_archive::audit_chain::ChainContinuity::NoAnchor) => {
                    // First run after enabling the audit log; benign. The
                    // anchor is persisted on the next clean shutdown.
                }
                Ok(rustgate_archive::audit_chain::ChainContinuity::Match { .. }) => {
                    // Chain continuous across the last shutdown; all good.
                }
                Ok(rustgate_archive::audit_chain::ChainContinuity::Mismatch {
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
                rustgate_archive::audit_chain::read_chain_state(path).map_err(|e| {
                    anyhow::anyhow!("failed to read audit log chain state {audit_path}: {e}")
                })?;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(audit_path)
                .map_err(|e| anyhow::anyhow!("failed to open audit log {audit_path}: {e}"))?;
            let tip_observer = Arc::new(arc_swap::ArcSwap::from_pointee(prev.clone()));
            let chain = rustgate_archive::audit_chain::HashChainWriter::new(file, prev)
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
            .with_target(rustgate_router::ACCESS_LOG_TARGET, tracing::Level::INFO);
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
        // Air-gap enforcement: refuse OTEL endpoints that resolve to
        // public hostnames or addresses. The exporter is a long-lived
        // outbound stream, so a misconfigured endpoint here would
        // continually leak traces to an external destination — exactly
        // what air-gap mode is meant to prevent.
        if cli.air_gap {
            let host = rustgate_core::air_gap::extract_host(endpoint);
            let permitted = host
                .map(rustgate_core::air_gap::is_private_host)
                .unwrap_or(false);
            if !permitted {
                rustgate_core::audit::air_gap_violation(
                    "otel_exporter",
                    endpoint,
                    "non-private host",
                );
                anyhow::bail!(
                    "--air-gap rejects --otel-endpoint `{endpoint}`: host is not in the private/loopback/link-local set. \
                     Configure an in-cluster or loopback collector, or unset --air-gap."
                );
            }
        }
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
        rustgate_tls::install_provider_with_kx_groups(groups)?;
    } else {
        rustgate_tls::install_pq_provider()?;
    }

    #[cfg(all(feature = "fips", not(feature = "post-quantum")))]
    rustgate_tls::install_fips_provider()?;

    if cli.fips_required && !rustgate_tls::is_fips_provider_active() {
        anyhow::bail!(
            "--fips-required is set but FIPS crypto provider is not active. \
             Build with --features fips to enable FIPS 140-3 mode."
        );
    }

    #[cfg(feature = "post-quantum")]
    if rustgate_tls::is_pq_provider_active() {
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

    // CNSA 2.0 scaffolding flag (#504). The full convergence is
    // blocked on aws-lc-rs resolving its FIPS / ML-DSA mutual
    // exclusion ([aws-lc-rs #964]); this flag's runtime behavior
    // today is limited to (a) validating the build has the
    // post-quantum feature compiled in, and (b) logging the
    // phased-readiness state so operators understand what they
    // actually get versus the full CNSA 2.0 target.
    //
    // [aws-lc-rs #964]: https://github.com/aws/aws-lc-rs/issues/964
    if cli.cnsa2 {
        #[cfg(not(feature = "post-quantum"))]
        {
            tracing::error!(
                "--cnsa2 requires the post-quantum feature to be compiled in; \
                 rebuild with --features post-quantum (and --features fips when \
                 aws-lc-rs #964 ships)"
            );
            return Err(anyhow::anyhow!(
                "--cnsa2 requires --features post-quantum at build time"
            ));
        }
        #[cfg(feature = "post-quantum")]
        {
            // Log the gap between "operator asked for CNSA 2.0" and
            // "this build can actually deliver". The targets come
            // from the NSA CNSA 2.0 algorithm suite; the "available
            // today" column is the workspace's current reality.
            tracing::warn!(
                "--cnsa2 enabled (scaffolding mode). CNSA 2.0 target: \
                 ML-KEM-1024 (NIST L5) + ML-DSA-87 (NIST L5) + TLS 1.3. \
                 Available today: X25519MLKEM768 (NIST L3 hybrid) + \
                 classical certs. Full CNSA 2.0 blocks on rustls / \
                 aws-lc-rs ML-DSA + FIPS convergence. See \
                 docs/adr/0019-cnsa2-hybrid-mldsa.md and #504."
            );
        }
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
    // `live` flips on inside `rustgate_admin::serve` when the metrics server binds.
    // `ready` is set after listener + ACL + (optional) federation init.
    // `started` is a one-shot, flipped after the accept loop is reached.
    #[cfg(feature = "metrics")]
    let health = Arc::new(rustgate_admin::HealthState::new());
    // Legacy compatibility shim: a number of code paths still use a bare
    // `ready` AtomicBool to gate accept-loop behaviour. Keep it for now —
    // it shadows the readiness portion of `HealthState`.
    let ready = Arc::new(AtomicBool::new(true));

    // Readiness dependency state — holds handles to subsystems so the
    // `/readyz` endpoint can inspect their health.
    #[cfg(feature = "metrics")]
    let readiness = {
        let mut state = rustgate_admin::ReadinessState::new();
        state.cert_reloader = cert_reloader.as_ref().map(Arc::clone);
        // Wire jemalloc refresh as a pre-scrape hook so /metrics
        // returns current values rather than whatever was cached at
        // last gather. The hook is target-gated to non-Windows
        // mirroring the Cargo.toml gate on the allocator dep.
        #[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
        {
            state.pre_scrape = Some(Arc::new(metrics::refresh_jemalloc_stats));
        }
        Arc::new(state)
    };

    // ── Metrics ─────────────────────────────────────────────────────
    #[cfg(all(feature = "metrics", feature = "federation"))]
    let fed_api_slot: Arc<std::sync::OnceLock<rustgate_admin::FedApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    #[cfg(feature = "metrics")]
    let acl_api_slot: Arc<std::sync::OnceLock<rustgate_admin::AclApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    #[cfg(feature = "metrics")]
    let mgmt_api_slot: Arc<std::sync::OnceLock<rustgate_admin::MgmtApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    // Slot for the expanded management REST API (closes #875). Held
    // empty until the `start_management_api` wiring registers the
    // bag of provider callbacks; the dispatcher in
    // `rustgate-admin::server::serve` short-circuits to a generic
    // 404 if the slot is still empty when a `/api/config*` /
    // `/api/version` / `/api/audit/verify` request lands.
    #[cfg(all(feature = "metrics", feature = "management-api"))]
    let management_api_slot: Arc<std::sync::OnceLock<rustgate_admin::ManagementApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    #[cfg(all(feature = "metrics", feature = "video"))]
    let video_api_slot: Arc<std::sync::OnceLock<rustgate_admin::VideoApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    #[cfg(all(feature = "metrics", feature = "correlation"))]
    let correlation_api_slot: Arc<std::sync::OnceLock<rustgate_admin::CorrelationApiHandler>> =
        Arc::new(std::sync::OnceLock::new());

    // Shared shutdown notifier driven by either SIGTERM/Ctrl-C
    // (`shutdown_signal()`) or `POST /api/drain` (closes #791). The
    // accept loop awaits on `shutdown_signal()` which races a tokio
    // signal handler against a `notified()` future on this `Notify`,
    // so a `notify_one()` from the drain endpoint transitions the
    // server into the same SubsystemHandle drain path SIGTERM would.
    let drain_notify = Arc::new(tokio::sync::Notify::new());

    #[cfg(feature = "metrics")]
    let router_slot: rustgate_admin::RouterSlot = Arc::new(std::sync::OnceLock::new());

    #[cfg(feature = "metrics")]
    let metrics_identity = setup::start_metrics(
        &cli,
        &health,
        &readiness,
        #[cfg(feature = "federation")]
        &fed_api_slot,
        &acl_api_slot,
        &mgmt_api_slot,
        #[cfg(feature = "management-api")]
        &management_api_slot,
        #[cfg(feature = "video")]
        &video_api_slot,
        #[cfg(feature = "correlation")]
        &correlation_api_slot,
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

    let client_queue: Option<Arc<rustgate_router::ClientQueue>> =
        if let Some(ref dir) = cli.client_queue_dir {
            // Choose the open mode: persistent-key > explicit-wipe > plain.
            // The plain `open` now fails closed if the on-disk queue has
            // entries and no persistent key was supplied (F-49 / #740).
            let open_result = if let Some(ref key_path) = cli.client_queue_key_file {
                let key = read_queue_key_file(key_path)
                    .map_err(|e| anyhow::anyhow!("--client-queue-key-file: {e}"))?;
                rustgate_router::ClientQueue::open_with_hmac_key(
                    dir,
                    cli.client_queue_max_bytes,
                    Some(key),
                )
            } else if cli.client_queue_wipe_on_start {
                rustgate_router::ClientQueue::open_with_wipe(dir, cli.client_queue_max_bytes)
            } else {
                rustgate_router::ClientQueue::open(dir, cli.client_queue_max_bytes)
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
    let quota_tracker: Option<Arc<rustgate_router::TenantQuotaTracker>> =
        if let Some(ref path) = cli.tenant_quota_file {
            match rustgate_router::TenantQuotaTracker::load_config(path) {
                Ok(config) => {
                    let tracker = Arc::new(rustgate_router::TenantQuotaTracker::new(config));
                    // Issue #883 sub-item 4: wire the per-tenant
                    // throughput rejection / consumption callbacks to
                    // Prometheus so an operator can see drops and
                    // current bucket headroom per tenant.
                    #[cfg(feature = "metrics")]
                    {
                        tracker.set_on_throughput_rejection(Some(std::sync::Arc::new(
                            |tenant: &str| {
                                metrics::tenant_throughput_rejections()
                                    .with_label_values(&[tenant])
                                    .inc();
                            },
                        )));
                        tracker.set_on_throughput_consumed(Some(std::sync::Arc::new(
                            |tenant: &str, level: f64| {
                                if let Some(g) = metrics::tenant_throughput_bps() {
                                    g.with_label_values(&[tenant]).set(level);
                                }
                            },
                        )));
                    }
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

    // Closes #847. Build the EntityCodecRegistry once at startup with
    // every protocol crate that ships an EntityCodec — CoT XML
    // (#1289), MAVLink (#1292), ASTERIX (#1295), STANAG-4586 (#1300),
    // DIS (#867). The registry is held behind `Arc` so the router
    // (and any future hot-reload story) can share ownership without
    // allocation churn. Codec instances are zero-sized — the
    // per-protocol `Arc::new(...)` here is the canonical zero-cost
    // handle.
    let entity_codec_registry = {
        let mut registry = rustgate_core::entity::EntityCodecRegistry::new();
        registry.register(
            "cot",
            std::sync::Arc::new(rustgate_cot::entity::CotEntityCodec),
        );
        registry.register(
            rustgate_core::message::SOURCE_MAVLINK,
            std::sync::Arc::new(rustgate_mavlink::entity::MavlinkEntityCodec),
        );
        registry.register(
            "asterix",
            std::sync::Arc::new(rustgate_asterix::entity::AsterixEntityCodec),
        );
        registry.register(
            "stanag4586",
            std::sync::Arc::new(rustgate_stanag4586::entity::Stanag4586EntityCodec),
        );
        registry.register("dis", std::sync::Arc::new(rustgate_dis::DisCodec));
        registry.register("vmf", std::sync::Arc::new(rustgate_vmf::VmfCodec));
        Arc::new(registry)
    };

    let router = Arc::new({
        let base = (match group_acl {
            Some(acl) => Router::with_acl(acl),
            None => Router::new(),
        })
        .with_backpressure(Arc::clone(&backpressure_gate))
        // Closes #847. Install the EntityCodecRegistry so the routing
        // dispatch path can surface canonical Entity-kind tags to
        // audit (`message_delivered.entity_kind=…`) and the
        // `rustgate_messages_routed_by_kind_total` Prometheus counter.
        // Decode failures and unregistered protocols collapse to
        // `entity_kind="unknown"` so the metric label cardinality
        // stays bounded.
        .with_entity_codec_registry(Arc::clone(&entity_codec_registry))
        // Issue #728: apply the unknown-obligation policy at
        // construction time. Default (`false`) keeps the router in
        // fail-closed mode; operators opt into fail-open via
        // `--authz-allow-unknown-obligations` /
        // `RUSTGATE_AUTHZ_ALLOW_UNKNOWN_OBLIGATIONS`.
        .with_allow_unknown_obligations(cli.authz_allow_unknown_obligations)
        // Refs #849: when `--require-classification-marking` is set,
        // every inbound message that lacks a marking is rejected at
        // admission. Default `false` keeps pre-#849 behaviour for
        // legacy traffic that does not yet attach a marking.
        .with_require_classification_marking(cli.require_classification_marking)
        // Issue #724: cap per-CN position replay events with a
        // TokenBucket so a flap-looping client cannot drive the
        // authz engine at an uncapped rate. Defaults
        // (rate=100/sec, burst=200) are operator-safe.
        .with_position_replay_limit(rustgate_router::PositionReplayLimitConfig::new(
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
            let limiter = rustgate_router::obligations::ObligationRateLimiter::default()
                .with_on_unknown(std::sync::Arc::new(|variant: &str| {
                    metrics::authz_obligation_unknown()
                        .with_label_values(&[variant])
                        .inc();
                }))
                // Closes #768: wire the per-failure callback so each
                // `authz.obligation_failed` audit emission has a
                // matching `rustgate_obligation_failures_total{reason}`
                // increment. Same `reason` vocabulary across both.
                .with_on_failure(std::sync::Arc::new(|reason: &'static str| {
                    metrics::obligation_failures_total()
                        .with_label_values(&[reason])
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

    // Closes #741. Wire the multicast oversize-drop counter so
    // operators can dashboard / alert on the rate at which the router
    // drops messages that exceed `MAX_MULTICAST_GROUPS`. The callback
    // is `None` (i.e. the router falls back to its previous
    // tracing-only behaviour) for builds without `--features metrics`.
    #[cfg(feature = "metrics")]
    router.set_on_multicast_oversize_dropped(Some(std::sync::Arc::new(|| {
        metrics::multicast_oversize_dropped().inc();
    })));

    // Closes #768. First-class router/PEP/obligation observability.
    // Each callback bridges the transport's hot-path observation
    // points to the Prometheus exposition surface. The wiring is
    // operationally additive: builds without `--features metrics` see
    // the previous tracing-only behaviour because the callbacks are
    // never installed (the slots stay `None`).
    #[cfg(feature = "metrics")]
    {
        router.set_on_fanout(Some(metrics::router_fanout_callback()));
        router.set_on_dropped(Some(metrics::router_dropped_callback()));
        // #859: per-tenant slices of the fanout/dropped counters with
        // `MAX_TENANT_LABELS` cardinality cap on the `tenant` label.
        router.set_on_fanout_by_tenant(Some(metrics::router_fanout_by_tenant_callback()));
        router.set_on_dropped_by_tenant(Some(metrics::router_dropped_by_tenant_callback()));
        router.set_on_pep_decision(Some(metrics::router_pep_decision_callback()));
        router.set_on_obligation_applied(Some(metrics::router_obligation_applied_callback()));
        // Closes #721. Operator-visible drain signal for ArcSwap
        // policy hot-reloads — every authz evaluation increments the
        // gauge on entry and decrements on exit via the router's
        // RAII guard. After a `swap_authz`, the gauge returning to
        // its pre-swap baseline is the all-clear that every
        // evaluation that observed the previous engine has retired.
        router.set_on_authz_in_flight_changed(Some(metrics::router_authz_in_flight_callback()));
        // Closes #847. Per-kind routed-message observation — feeds
        // `rustgate_messages_routed_by_kind_total{kind, protocol}`.
        // Fires once per admitted message (not per recipient), with
        // `kind` drawn from the closed `EntityKind::as_str` vocabulary.
        router.set_on_routed_by_kind(Some(metrics::router_routed_by_kind_callback()));
        // MessageInterceptor SPI observability — feeds
        // `rustgate_router_interceptor_verdict_total{verdict}`. Fires
        // once per interceptor invocation; the closed
        // `InterceptorVerdict` enum bounds cardinality at three
        // (`allow`, `drop`, `modify`).
        router.set_on_interceptor_verdict(Some(metrics::router_interceptor_verdict_callback()));
    }

    // Closes #854. Per-recipient delivery audit is opt-in because a
    // single broadcast to N subscribers produces N records. When
    // `--audit-delivery` is set, install callbacks that bridge the
    // router's per-recipient `try_send` outcome to the
    // `rustgate_core::audit::message_delivered` /
    // `message_dropped` helpers. When unset (the default), the slots
    // stay `None` and the routing hot path pays only an
    // `ArcSwap::load` + `is_none` check per recipient.
    if cli.audit_delivery {
        router.set_on_message_delivered(Some(std::sync::Arc::new(
            |source_cn, dest_cn, msg_uid, msg_type, group, entity_kind, trace_id| {
                // entity_kind closes #847; trace_id closes #852 PR-C
                // (cross-service SIEM correlation via W3C traceparent).
                rustgate_core::audit::message_delivered(
                    source_cn,
                    dest_cn,
                    msg_uid,
                    msg_type,
                    group,
                    entity_kind,
                    trace_id,
                );
            },
        )));
        router.set_on_message_dropped(Some(std::sync::Arc::new(
            |source_cn, dest_cn, msg_uid, reason| {
                rustgate_core::audit::message_dropped(source_cn, dest_cn, msg_uid, reason);
            },
        )));
    }

    // ── Video stream catalog (#862) and correlation engine (#848) ───
    //
    // The router exposes a single `OnRouted` slot; both the video
    // stream catalog (passive `b-i-v` ingestion) and the correlation
    // engine (multi-sensor track fusion) want to ride on it. To avoid
    // mutually-exclusive feature flags, we compose the two callbacks
    // into a chain when both features are enabled — each callback
    // does its own filtering / decoding internally so chaining adds
    // negligible per-message cost beyond the inactive feature's
    // individual hot path.
    //
    // Behind `--features video,metrics`, install a passive catalog that
    // captures CoT `b-i-v` events as they flow through the router and
    // exposes them at `GET /api/video/streams` on the admin HTTP
    // surface. The router callback is a single `Arc<HashMap>` insert
    // per matching message; the route dispatch ladder in
    // `rustgate-admin::server::serve` short-circuits the path when the
    // slot is unset, so non-video builds pay zero cost.
    #[cfg(all(feature = "metrics", feature = "video"))]
    let video_callback: Option<rustgate_router::OnRouted> = {
        let catalog = std::sync::Arc::new(rustgate_admin::VideoStreamCatalog::new());
        let cb = rustgate_admin::video::router_callback(Arc::clone(&catalog));
        let h = rustgate_admin::video::handler(Arc::clone(&catalog));
        let handler: rustgate_admin::VideoApiHandler =
            std::sync::Arc::new(move |m, p, b| h(m, p, b));
        let _ = video_api_slot.set(handler);
        tracing::info!("video stream catalog enabled at /api/video/streams");
        Some(cb)
    };
    #[cfg(not(all(feature = "metrics", feature = "video")))]
    let video_callback: Option<rustgate_router::OnRouted> = None;

    // Behind `--features correlation,metrics`, install a stateful
    // correlation engine, wire its `OnRouted` callback, and expose
    // the live snapshot at `GET /api/correlation/fused-entities`.
    // The decode path uses the router-installed
    // `EntityCodecRegistry` so codec failures fall through silently
    // and routing stays on the un-fused critical path. Closes #848.
    #[cfg(all(feature = "metrics", feature = "correlation"))]
    let correlation_callback: Option<rustgate_router::OnRouted> = {
        let engine = std::sync::Arc::new(rustgate_correlation::CorrelationEngine::new());
        let cb = rustgate_correlation::router_callback(
            Arc::clone(&engine),
            Arc::clone(&entity_codec_registry),
        );
        let h = rustgate_admin::correlation::handler(Arc::clone(&engine));
        let handler: rustgate_admin::CorrelationApiHandler =
            std::sync::Arc::new(move |m, p, b| h(m, p, b));
        let _ = correlation_api_slot.set(handler);
        tracing::info!(
            "multi-sensor correlation engine enabled at \
             /api/correlation/fused-entities"
        );
        Some(cb)
    };
    #[cfg(not(all(feature = "metrics", feature = "correlation")))]
    let correlation_callback: Option<rustgate_router::OnRouted> = None;

    // Compose video + correlation callbacks into the single `OnRouted`
    // slot the router exposes. Both callbacks are `Arc<dyn Fn(...)>`,
    // so chaining is trivial — invoke each in turn.
    match (video_callback, correlation_callback) {
        (Some(v), Some(c)) => {
            router.set_on_routed(Some(std::sync::Arc::new(move |msg| {
                v(Arc::clone(&msg));
                c(msg);
            })));
        }
        (Some(v), None) => router.set_on_routed(Some(v)),
        (None, Some(c)) => router.set_on_routed(Some(c)),
        (None, None) => {}
    }

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
        rustgate_router::DedupCache::from_secs(cli.dedup_window_secs, cli.dedup_cache_size)
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
    let mut acl_reloader_handle: Option<Arc<rustgate_admin::AclReloader>> = None;
    if let Some(ref acl_file) = cli.group_acl_file {
        let initial_hash =
            acl_file_hash.unwrap_or_else(|| rustgate_admin::AclReloader::compute_hash(b""));
        let reloader =
            rustgate_admin::AclReloader::new(acl_file.clone(), Arc::clone(&router), initial_hash);
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
    let acl_reloader_for_api: Option<Arc<rustgate_admin::AclReloader>> =
        acl_reloader_handle.clone();

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
                        spawn_background("authz-cache-stats", async move {
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
                        });
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
                rustgate_admin::validate_bearer_token_length(&token, "ACL API")
                    .map_err(|e| anyhow::anyhow!("{e} (from {token_file})"))?;
                let initial_file = acl_file_parsed.unwrap_or_default();
                let api_state = Arc::new(rustgate_admin::AclApiState {
                    current: Arc::new(std::sync::RwLock::new(initial_file)),
                    router: Arc::clone(&router),
                    reloader: acl_reloader_for_api,
                    file_path: std::path::PathBuf::from(acl_file),
                    auth_token: zeroize::Zeroizing::new(token),
                });
                let handler: rustgate_admin::AclApiHandler =
                    Arc::new(move |method, path, auth, body| {
                        rustgate_admin::acl_api::handle_request(
                            method, path, auth, body, &api_state,
                        )
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
    //
    // The subscriber is constructed here but its background task is
    // deferred until federation + HTTP egress callbacks have been
    // wired further down — that way an inbound NATS-bridged message
    // hits `Router::route_for_egress` and reaches the same external
    // sinks (federation peers, webhook targets) the directly-connected
    // transports already feed (refs #737).
    #[cfg(feature = "nats")]
    let (nats_publisher, deferred_nats_subscriber) = match setup::connect_nats(&cli, &router).await
    {
        Some(outcome) => (Some(outcome.publisher), Some(outcome.subscriber)),
        None => (None, None),
    };

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

    // ── HTTP egress ─────────────────────────────────────────────────
    //
    // Wired BEFORE federation so the federation `on_inbound` callback
    // can fan inbound peer messages out to webhook / SIEM targets via
    // `Router::route_for_egress` (refs #737, the federation sub-item
    // that completes the umbrella alongside MQTT #1263 and the NATS
    // subscriber #1266). The HTTP publisher itself is independent of
    // both federation and the local router, so this reordering is
    // purely a wiring change — no behaviour relies on the previous
    // post-federation ordering.
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

    // ── Lattice (Anduril) ──────────────────────────────────────────
    //
    // Brings up the Lattice bidirectional adapter when `--features
    // lattice` is enabled and the operator has set
    // `--lattice-config`. The wiring is a no-op when no
    // `[lattice]` block is present in the config file. The actual
    // Lattice gRPC SDK is partner-NDA-gated and lives behind
    // `--features lattice-real`; the in-memory mock backend used by
    // integration tests is selected with `--features lattice-mock`.
    // Refs #850.
    #[cfg(feature = "lattice")]
    let _lattice_handles = setup::start_lattice(&cli, &router).await;

    #[cfg(not(feature = "lattice"))]
    setup::warn_lattice_disabled(&cli);

    // ── Foundry bridge (issue #851) ─────────────────────────────────
    //
    // The Foundry / Gotham bridge is partner-gated; today the wiring
    // is a scaffold (trait + config + mock + wiring tasks) and the
    // SDK adapter lands behind a future `foundry-real` feature flag.
    // Calling `init_foundry_scaffold` here gives operators who built
    // with `--features foundry` a one-line confirmation that the
    // scaffold is linked.
    #[cfg(feature = "foundry")]
    setup::init_foundry_scaffold();

    // ── DDS bridge (issue #870) ─────────────────────────────────────
    //
    // The DDS bridge is partner / SDK-gated; today the wiring is a
    // scaffold (trait + config + mock + wiring tasks) and the real
    // SDK adapter lands behind a future `dds-real` feature flag.
    // Calling `init_dds_scaffold` here gives operators who built with
    // `--features dds` a one-line confirmation that the scaffold is
    // linked.
    #[cfg(feature = "dds")]
    setup::init_dds_scaffold();

    // ── OGC SensorThings v1.0 polling client (issue #869) ───────────
    //
    // When `--features ogc-sensorthings` is enabled and the operator
    // has set `--ogc-sensorthings-config <path>`, the polling client
    // is started and observations from the configured datastreams
    // are routed into the live `Router` for normal cross-protocol
    // fan-out. The wiring is a no-op when no `[sensorthings]` block
    // is present.
    #[cfg(feature = "ogc-sensorthings")]
    let _ogc_sensorthings_handle = setup::start_ogc_sensorthings(&cli, &router).await;

    #[cfg(not(feature = "ogc-sensorthings"))]
    setup::warn_ogc_sensorthings_disabled(&cli);

    // Edge ML inference pipeline (closes #858). MVP — the helper
    // is a stub that logs the feature is compiled in. Binary-side
    // wiring of the back-annotation callback lands in a follow-up
    // once an operator deployment shape is selected.
    #[cfg(feature = "inference")]
    setup::start_inference();

    // ── Federation ──────────────────────────────────────────────────
    //
    // The `FedInboundForwardingHooks` carry the optional NATS-publish
    // and HTTP-forward callbacks that the federation `on_inbound`
    // path fires AFTER `Router::route_for_egress` has applied any
    // Send-PEP obligations to the envelope. This closes the federation
    // sub-item of #737 so a peer-sourced message reaches the same
    // external sinks (NATS bus, HTTP webhooks) that a directly-
    // connected client would feed. We do NOT wire a federation
    // self-forward — the V2 protocol's hop guard catches re-emitted
    // federation messages, and the right invariant is that the
    // forwarder never observes them in the first place.
    #[cfg(feature = "federation")]
    let fed_inbound_hooks: setup::FedInboundForwardingHooks = {
        // justification: `hooks` is mutated below only when `nats` and/or `http` features are
        // enabled; with `federation` alone no branch fires, so the `mut` is spurious in that
        // feature combination. `unused_mut` is `-D warning`-promoted, and adding the feature
        // gate to the `mut` keyword itself isn't expressible — so suppress just for the
        // disjoint case.
        #[cfg_attr(not(any(feature = "nats", feature = "http")), allow(unused_mut))]
        let mut hooks = setup::FedInboundForwardingHooks::default();
        #[cfg(feature = "nats")]
        if let Some(ref publisher) = nats_publisher {
            let publisher = publisher.clone();
            let cb: rustgate_core::egress::OnNatsPublish = std::sync::Arc::new(move |msg| {
                let publisher = publisher.clone();
                rustgate_core::tasks::spawn_background(
                    "federation-inbound-nats-publish",
                    async move {
                        publisher.publish(&msg).await;
                    },
                );
            });
            hooks.nats_publish = Some(cb);
        }
        #[cfg(feature = "http")]
        if let Some(ref fwd) = http_forward {
            hooks.http_forward = Some(fwd.clone());
        }
        hooks
    };

    #[cfg(feature = "federation")]
    let (fed_forward, fed_shutdown_handle): (
        Option<FedForwardFn>,
        Option<Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>>,
    ) = setup::start_federation(
        &cli,
        &router,
        fed_inbound_hooks,
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

    // ── NATS subscriber (deferred spawn) ────────────────────────────
    //
    // Wire the federation + HTTP egress forwarders that just landed
    // and spawn the consumer loop. Putting the spawn here means an
    // inbound NATS message routes through `route_for_egress` and
    // fans out to the same sinks every other transport feeds (refs
    // #737). Echo prevention is the publisher's case-insensitive
    // `source_protocol == "nats"` guard plus the
    // `metadata.source_protocol = "nats"` stamp the subscriber
    // applies via `WireEvent::into_routable`.
    #[cfg(feature = "nats")]
    if let Some(subscriber) = deferred_nats_subscriber {
        setup::start_nats_subscriber(
            subscriber,
            &router,
            nats_publisher.as_ref(),
            &fed_forward,
            #[cfg(feature = "http")]
            &http_forward,
        );
    }

    // ── Per-client rate limiting ────────────────────────────────────
    let throttle_config = setup::build_throttle_config(&cli);

    // ── Default classification marking (refs #849 item 4) ──────────
    // Parsed once at startup; the parsed marking is cloned into every
    // session's `MessageBuilder` so unmarked inbound traffic gets
    // stamped before reaching the router. Validation already ran in
    // `Cli::validate`, so a parse failure here means the validator
    // missed a case — bail rather than silently skip.
    let default_classification: Option<rustgate_core::classification::ClassificationMarking> =
        match cli.default_classification.as_ref() {
            Some(banner) => Some(banner.parse().map_err(|e| {
                anyhow::anyhow!(
                    "--default-classification ({banner:?}) parse failed at startup: {e}"
                )
            })?),
            None => None,
        };

    // ── Anti-replay filter ─────────────────────────────────────────
    let replay_filter = rustgate_router::ReplayFilter::from_secs(cli.replay_window).map(Arc::new);
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
    let archive_key_ring: Option<Arc<rustgate_archive::encrypted::KeyRing>> =
        if let Some(ref kp) = cli.archive_key_file {
            Some(Arc::new(
                rustgate_archive::encrypted::KeyRing::load(kp)
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
            Some(Arc::new(rustgate_archive::CotArchiver::with_encryption(
                dir,
                Arc::clone(ring),
            )))
        } else {
            tracing::info!(dir = %dir, "CoT event archival enabled");
            Some(Arc::new(rustgate_archive::CotArchiver::new(dir)))
        }
    } else {
        None
    };

    // ── CoT archive retention / rotation ───────────────────────────
    let archive_rotation_handle = if let Some(ref dir) = cli.archive_dir
        && (cli.archive_max_size > 0 || cli.archive_max_age > 0 || cli.archive_max_active_bytes > 0)
    {
        // Surface the per-pass `bytes_after` count to the existing
        // `rustgate_archive_bytes` Prometheus gauge via the
        // `OnRotationStats` callback. The metric registration stays in
        // the server binary so `rustgate-archive` does not need a
        // Prometheus dep — see #892.
        #[cfg(feature = "metrics")]
        let on_stats: Option<rustgate_archive::OnRotationStats> = Some(Arc::new(|stats| {
            metrics::archive_bytes().set(stats.bytes_after as i64);
        }));
        #[cfg(not(feature = "metrics"))]
        let on_stats: Option<rustgate_archive::OnRotationStats> = None;

        let cfg = rustgate_archive::RotationConfig {
            dir: std::path::PathBuf::from(dir),
            max_bytes: cli.archive_max_size,
            max_active_bytes: cli.archive_max_active_bytes,
            max_age: std::time::Duration::from_secs(cli.archive_max_age),
            // `cli.validate()` enforces `archive_rotate_interval >= 60` when
            // rotation is enabled (F-69), so the `.max(1)` defense here is
            // redundant — the value is already safe at this point.
            interval: std::time::Duration::from_secs(cli.archive_rotate_interval),
            archiver: archiver.clone(),
            on_stats,
        };
        tracing::info!(
            dir = %dir,
            max_bytes = cli.archive_max_size,
            max_active_bytes = cli.archive_max_active_bytes,
            max_age_secs = cli.archive_max_age,
            interval_secs = cli.archive_rotate_interval,
            "CoT archive rotation enabled",
        );
        Some(rustgate_archive::spawn(cfg))
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

    // ── UDP multicast listener (closes #861) ───────────────────────
    //
    // ATAK on tactical mesh radio uses IPv4 multicast for SA. When
    // `--udp-multicast-groups` is set, the listener joins each group,
    // tags incoming datagrams with `source_protocol = "udp-multicast"`,
    // and (if `--udp-multicast-rebroadcast` is on) re-emits routed CoT
    // back out the egress socket subject to the configured BPS cap.
    let udp_multicast_shutdown = setup::start_udp_multicast(&cli, &router).await?;

    // ── MAVLink UDP/TCP listeners (closes #731) ────────────────────
    //
    // Autonomous-vehicle telemetry/command over MAVLink. UDP is the
    // canonical transport; TCP serves tethered ground-control stations.
    // Identity comes from the v2 signing `link_id` resolved through the
    // `--mavlink-signing-key-file` manifest (ADR 0020), so ACL/authz
    // apply to MAVLink exactly as to every other transport.
    let mavlink_shutdowns = mavlink::start_mavlink(&cli, &router).await?;

    // ── Cross-domain egress guard (#1457) ──────────────────────────
    //
    // When `--guard-config` is set (and the `guard` feature is built),
    // install the cross-domain inspection boundary on the router's
    // egress chokepoint. Every message leaving toward an external sink
    // is then gated at the boundary; a denial drops it and is audited.
    // No background task — the gate is a synchronous hook inside
    // `route_for_egress`, so there is no shutdown handle to track.
    #[cfg(feature = "guard")]
    guard::start_guard(&cli, &router)?;

    // ── Tactical codec ingress: DIS / ASTERIX / VMF over UDP (#1473) ─
    //
    // For each protocol whose `--<proto>-bind` is set, bind a UDP
    // listener that validates each datagram with that protocol's
    // EntityCodec at the edge and routes accepted messages (tagged
    // `source_protocol`) through the normal ACL/authz path. All three
    // share the generic codec-ingress listener + admission gate.
    // Unauthenticated, trusted-network-only — see
    // `docs/tactical-ingress.md`.
    let dis_shutdown = tactical_ingress::start_dis(&cli, &router).await?;
    let asterix_shutdown = tactical_ingress::start_asterix(&cli, &router).await?;
    let vmf_shutdown = tactical_ingress::start_vmf(&cli, &router).await?;

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
            rustgate_admin::validate_bearer_token_length(&token, "management API")
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
                drain_notify: Arc::clone(&drain_notify),
                auth_token: zeroize::Zeroizing::new(token),
            });
            let handler: rustgate_admin::MgmtApiHandler =
                Arc::new(move |method, path, auth, body| {
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
                 /api/clients/, /api/dlq/, /api/v1/, /api/reload, and /api/drain"
            );

            // ── Expanded management REST API (closes #875) ─────────
            //
            // Reuses the same bearer token validated above so a single
            // `--mgmt-api-token-file` controls every operator surface
            // on the admin port. The registration is feature-gated on
            // `management-api` so a binary built without it stays
            // bit-for-bit compatible with the legacy surface.
            #[cfg(feature = "management-api")]
            {
                let mgmt_token_clone = token_str.as_bytes().to_vec();
                let providers = build_management_api_providers(&cli, &router);
                let audit_log_path = cli.audit_log.as_ref().and_then(|s| {
                    if s == "stdout" {
                        None
                    } else {
                        Some(std::path::PathBuf::from(s))
                    }
                });
                let management_state = Arc::new(rustgate_admin::ManagementApiState {
                    providers,
                    reload_notify: Arc::clone(&drain_notify),
                    audit_log_path,
                    auth_token: zeroize::Zeroizing::new(mgmt_token_clone),
                });
                let handler: rustgate_admin::ManagementApiHandler =
                    Arc::new(move |method, path, auth| {
                        let st = Arc::clone(&management_state);
                        let method = method.clone();
                        let path = path.to_string();
                        let auth = auth.map(|s| s.to_string());
                        Box::pin(async move {
                            rustgate_admin::management_api::handle_request(
                                &method,
                                &path,
                                auth.as_deref(),
                                &st,
                            )
                            .await
                        })
                    });
                let _ = management_api_slot.set(handler);
                tracing::info!(
                    "expanded management REST API enabled at /api/config, /api/config/reload, \
                     /api/clients, /api/clients/{{cn}}, /api/metrics/summary, /api/store-forward, \
                     /api/audit/verify, and /api/version (closes #875)"
                );
            }
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
                            default_classification: default_classification.clone(),
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
            _ = shutdown_signal(Arc::clone(&drain_notify)) => {
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
    if let Some(handle) = udp_multicast_shutdown {
        stop_subsystem("udp-multicast", handle).await;
    }
    for handle in mavlink_shutdowns {
        stop_subsystem("mavlink", handle).await;
    }
    if let Some(handle) = dis_shutdown {
        stop_subsystem("dis", handle).await;
    }
    if let Some(handle) = asterix_shutdown {
        stop_subsystem("asterix", handle).await;
    }
    if let Some(handle) = vmf_shutdown {
        stop_subsystem("vmf", handle).await;
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
        // Recover the seq high-water mark by scanning the live log tail.
        // The writer's in-memory next_seq is not exposed through the
        // tip_observer (which only carries the chain hash), and reaching
        // into the tracing subscriber to pull it out would couple the
        // server's shutdown path to the subscriber internals. The tail
        // scan is bounded by `REWIND_BUDGET` so the cost is the same
        // whether the log is 100 KB or 100 GB. On a legacy / empty log
        // the helper returns `(GENESIS_PREV, 1)` and we persist
        // `tip_seq = 0` (the high-water of records *already* on disk),
        // which the next startup interprets as "fall back to scanning
        // the log" via the read_anchor_with_seq backward-compat path.
        let tip_seq = match rustgate_archive::audit_chain::read_chain_state(path) {
            Ok((_, next_seq)) => next_seq.saturating_sub(1),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to recover audit chain seq for anchor; persisting tip with tip_seq=0"
                );
                0
            }
        };
        match rustgate_archive::audit_chain::write_anchor_with_seq(path, &tip, tip_seq) {
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
/// Block until either an OS-level shutdown signal arrives (SIGTERM /
/// Ctrl-C) or the management API fires the shared `drain_notify`
/// (`POST /api/drain`, closes #791). Returning unblocks the accept
/// loop's `tokio::select!`, which then drops into the existing
/// SubsystemHandle drain path — there is no separate "API drain code".
async fn shutdown_signal(drain_notify: Arc<tokio::sync::Notify>) {
    let api_drain = drain_notify.notified();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                    _ = api_drain => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to register SIGTERM handler, falling back to Ctrl-C only");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = api_drain => {}
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = api_drain => {}
        }
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
    cert_reloader: Option<&Arc<rustgate_tls::CertReloader>>,
    acl_reloader: Option<&Arc<rustgate_admin::AclReloader>>,
    crl_path: Option<&str>,
    #[cfg(feature = "ocsp")] ocsp_stapler: Option<&Arc<rustgate_tls::ocsp::Stapler>>,
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
                    rustgate_tls::ocsp::preload(stapler, ckey);
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
fn reload_crl_file(path: &str) -> anyhow::Result<rustgate_tls::CrlFileSummary> {
    rustgate_tls::TlsConfig::validate_crl_file(path).map_err(|e| anyhow::anyhow!("{e}"))
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

/// Read the on-disk PEM material for a `test-connection --tls` probe
/// and bundle it into the [`diagnostics::test_connection::TlsTarget`]
/// the probe consumes.
///
/// Required when `--tls` is set. Surfaces a precise filesystem error
/// (missing path, permission, empty file) instead of a generic
/// "handshake failed" — the diagnostic's whole purpose is to catch
/// configuration mistakes before they produce a stack of opaque TLS
/// errors at server startup.
fn build_tls_target(
    addr: &str,
    cert: Option<&std::path::Path>,
    key: Option<&std::path::Path>,
    ca: Option<&std::path::Path>,
    server_name: Option<&str>,
    warn_days: u32,
) -> anyhow::Result<diagnostics::test_connection::TlsTarget> {
    let cert_path =
        cert.ok_or_else(|| anyhow::anyhow!("test-connection --tls requires --target-cert <path>"))?;
    let key_path =
        key.ok_or_else(|| anyhow::anyhow!("test-connection --tls requires --target-key <path>"))?;
    let ca_path =
        ca.ok_or_else(|| anyhow::anyhow!("test-connection --tls requires --target-ca <path>"))?;

    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("read --target-cert {}", cert_path.display()))?;
    // The private key funnels through the shared `read_secret_file`
    // helper so it gets the unified perm / size / empty / UTF-8
    // discipline; we then re-encode the (already-validated) string back
    // into bytes for the rustls PEM parser. The 16 KiB cap matches the
    // value `rustgate-client::connect` uses for the same operation.
    let key_str = rustgate_core::read_secret_file(
        key_path,
        &rustgate_core::SecretFileOpts::with_max_bytes(16 * 1024),
    )
    .with_context(|| format!("read --target-key {}", key_path.display()))?;
    let mut key_str = key_str;
    let key_pem = zeroize::Zeroizing::new(std::mem::take(&mut *key_str).into_bytes());
    let ca_pem = std::fs::read(ca_path)
        .with_context(|| format!("read --target-ca {}", ca_path.display()))?;

    // Default the TLS server name to the host part of `addr` so an
    // operator who only types `--tls 10.0.0.5:4433` still gets an
    // SNI-bearing handshake. The host part is parsed lossily — a
    // malformed `addr` will be caught by the TCP connect step anyway.
    let resolved_server_name = match server_name {
        Some(n) => n.to_string(),
        None => addr
            .rsplit_once(':')
            .map(|(host, _)| host.to_string())
            .unwrap_or_else(|| addr.to_string()),
    };

    Ok(diagnostics::test_connection::TlsTarget {
        addr: addr.to_string(),
        server_name: resolved_server_name,
        cert_pem,
        key_pem,
        ca_pem,
        warn_days,
    })
}

/// Build the [`rustgate_admin::Providers`] bag for the expanded
/// management REST API (closes #875). The provider closures capture
/// shared handles to the running router and CLI snapshot, so each
/// callback is a cheap clone-and-read on the hot path.
///
/// The CLI snapshot is rendered with `serde_json::to_value(cli)` so
/// every `#[serde(skip_serializing)]` and
/// `#[serde(serialize_with = "redact_…")]` attribute already on the
/// CLI struct continues to govern what reaches the wire — there is no
/// separate redaction surface for this endpoint to drift against.
#[cfg(all(feature = "metrics", feature = "management-api"))]
fn build_management_api_providers(
    cli: &Cli,
    router: &Arc<rustgate_router::Router>,
) -> rustgate_admin::Providers {
    use rustgate_admin::{
        ClientDetail, ClientSnapshot, MetricsSummary, StoreForwardEntry, StoreForwardSnapshot,
        VersionInfo,
    };

    // Snapshot the CLI once at registration time. The wire shape is a
    // diagnostic: a true "live" config view requires a full
    // hot-reload-aware accessor that doesn't exist today; #875 only
    // promised "running config", which the post-merge snapshot
    // satisfies. A future PR can swap this for an `ArcSwap<Cli>`-
    // backed accessor if operators need to observe runtime mutations.
    let cli_json = serde_json::to_value(cli)
        .unwrap_or_else(|e| serde_json::json!({"error": format!("serialize cli: {e}")}));

    let router_for_clients = Arc::clone(router);
    let router_for_detail = Arc::clone(router);
    let router_for_metrics = Arc::clone(router);
    let router_for_storeforward = Arc::clone(router);

    let features: Vec<String> = compiled_features();
    let fips_active = cfg!(feature = "fips");
    let version_str = env!("CARGO_PKG_VERSION").to_string();
    // The git hash falls back to "unknown" when the build environment
    // does not set RUSTGATE_GIT_HASH; CI typically populates this.
    let git_hash = option_env!("RUSTGATE_GIT_HASH")
        .unwrap_or("unknown")
        .to_string();

    rustgate_admin::Providers {
        config: Some(Arc::new(move || cli_json.clone())),
        clients: Some(Arc::new(move || {
            let r = Arc::clone(&router_for_clients);
            Box::pin(async move {
                let identities = r.connected_clients().await;
                identities
                    .into_iter()
                    .map(|id| ClientSnapshot {
                        cn: id.cn.to_string(),
                        fingerprint: id.fingerprint.clone(),
                        connected_at: None,
                        bytes_rx: None,
                        bytes_tx: None,
                        source_protocol: None,
                        groups: id.groups.iter().cloned().collect(),
                        tenant: id.tenant.clone(),
                    })
                    .collect()
            })
        })),
        client_detail: Some(Arc::new(move |cn: String| {
            let r = Arc::clone(&router_for_detail);
            Box::pin(async move {
                let identities = r.connected_clients().await;
                identities
                    .into_iter()
                    .find(|id| id.cn.as_ref() == cn.as_str())
                    .map(|id| ClientDetail {
                        snapshot: ClientSnapshot {
                            cn: id.cn.to_string(),
                            fingerprint: id.fingerprint.clone(),
                            connected_at: None,
                            bytes_rx: None,
                            bytes_tx: None,
                            source_protocol: None,
                            groups: id.groups.iter().cloned().collect(),
                            tenant: id.tenant.clone(),
                        },
                        queue_depth: None,
                        rate_limit_per_sec: None,
                    })
            })
        })),
        metrics_summary: Some(Arc::new(move || {
            let r = Arc::clone(&router_for_metrics);
            Box::pin(async move {
                // Sum across all label values for the two counter
                // vecs. `metric_with_label_values` is not the right
                // API for a bulk read; instead, gather and walk the
                // metric family.
                let registry = prometheus::default_registry();
                let families = registry.gather();
                let sum_for = |name: &str| -> u64 {
                    families
                        .iter()
                        .find(|f| f.name() == name)
                        .map(|f| {
                            f.get_metric()
                                .iter()
                                .map(|m| m.get_counter().get_value() as u64)
                                .sum::<u64>()
                        })
                        .unwrap_or(0)
                };
                let dedup = r.dedup_full_stats();
                let connected_clients = r.session_count().await as u64;
                MetricsSummary {
                    router_fanout_total: sum_for("rustgate_router_fanout_total"),
                    router_dropped_total: sum_for("rustgate_router_dropped_total"),
                    store_forward_messages: dedup.as_ref().map(|s| s.entries as u64).unwrap_or(0),
                    store_forward_bytes: 0,
                    federation_peer_count: 0,
                    federation_connected_peers: 0,
                    connected_clients,
                }
            })
        })),
        store_forward: Some(Arc::new(move || {
            // The router exposes a per-CN view via the client_queue
            // accessor. When no queue is attached, the snapshot
            // reports `enabled: false` rather than a misleading
            // empty per-CN list.
            if let Some(q) = router_for_storeforward.client_queue() {
                let snapshot = q.snapshot();
                let total_bytes = q.total_bytes();
                let total_messages: u64 = snapshot.iter().map(|(_, s)| s.depth).sum();
                let entries = snapshot
                    .into_iter()
                    .map(|(cn, stats)| StoreForwardEntry {
                        cn,
                        messages: stats.depth,
                        bytes: stats.bytes,
                    })
                    .collect();
                StoreForwardSnapshot {
                    enabled: true,
                    total_bytes,
                    total_messages,
                    entries,
                }
            } else {
                StoreForwardSnapshot {
                    enabled: false,
                    total_bytes: 0,
                    total_messages: 0,
                    entries: vec![],
                }
            }
        })),
        version: Some(Arc::new(move || VersionInfo {
            version: version_str.clone(),
            git_hash: git_hash.clone(),
            features: features.clone(),
            fips_active,
        })),
    }
}

/// Returns the list of feature flags compiled into the running
/// binary. The list is generated at compile time from `cfg!()` so
/// the surface stays accurate across feature combinations the
/// release pipeline ships.
#[cfg(all(feature = "metrics", feature = "management-api"))]
fn compiled_features() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    macro_rules! push_if_on {
        ($flag:literal) => {
            if cfg!(feature = $flag) {
                v.push($flag.to_string());
            }
        };
    }
    push_if_on!("nats");
    push_if_on!("enrollment");
    push_if_on!("est");
    push_if_on!("proto");
    push_if_on!("full-detail");
    push_if_on!("metrics");
    push_if_on!("federation");
    push_if_on!("federation-ha");
    push_if_on!("websocket");
    push_if_on!("mqtt");
    push_if_on!("otel");
    push_if_on!("fips");
    push_if_on!("post-quantum");
    push_if_on!("jemalloc");
    push_if_on!("ocsp");
    push_if_on!("spiffe");
    push_if_on!("cedar");
    push_if_on!("http");
    push_if_on!("video");
    push_if_on!("management-api");
    v
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
        let initial_hash = rustgate_admin::AclReloader::compute_hash(initial.as_bytes());

        let router = Arc::new(rustgate_router::Router::with_acl(
            rustgate_router::GroupAclPolicy::new(HashMap::new()),
        ));
        let reloader =
            rustgate_admin::AclReloader::new(&acl_path, Arc::clone(&router), initial_hash);

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
