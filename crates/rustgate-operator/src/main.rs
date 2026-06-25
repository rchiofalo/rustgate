// Copyright © 2026 Roberto Chiofalo.

//! `rustgate-operator` — Kubernetes operator binary for the
//! `RustgateCluster` CRD.
//!
//! ## Subcommands
//!
//! * `render` — read a `RustgateCluster` manifest from a YAML file (or
//!   stdin), validate it, and emit the owned manifests as a multi-document
//!   YAML stream. This is the operator's reconcile output without the
//!   apply-loop, suitable for piping into `kubectl apply -f -` for
//!   one-shot deployments and CI smoke tests.
//! * `validate` — read a `RustgateCluster` manifest and exit with status
//!   0 on success, non-zero with a diagnostic on validation failure.
//! * `version` — print the operator's package version.
//! * `run` (controller feature only) — run the live cluster controller.
//!   Watches `RustgateCluster` resources, server-side applies the
//!   renderer's output, reads back observed status, and patches the
//!   parent. Leader-elects via `coordination.k8s.io/v1` Lease so
//!   multi-replica Deployments run hot-standby. SIGTERM drains
//!   in-flight reconciles and releases the lease.

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rustgate_operator::crd::RustgateCluster;
use rustgate_operator::render::render_all_yaml;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "rustgate-operator",
    version,
    about = "Kubernetes operator for the RustgateCluster CRD"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Render the manifests for a RustgateCluster YAML file.
    Render {
        /// Path to a YAML file containing a RustgateCluster, or `-` for
        /// stdin.
        #[arg(short, long, default_value = "-")]
        input: String,
    },
    /// Validate a RustgateCluster YAML file.
    Validate {
        /// Path to a YAML file containing a RustgateCluster, or `-` for
        /// stdin.
        #[arg(short, long, default_value = "-")]
        input: String,
    },
    /// Print the operator binary version.
    Version,
    /// Run the live cluster controller. Requires the `controller`
    /// build feature.
    Run(RunArgs),
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Watch a single namespace instead of cluster-wide. Recommended
    /// when the operator is RBAC-scoped to a single namespace.
    #[arg(long, env = "OPERATOR_NAMESPACE")]
    namespace: Option<String>,
    /// Bind address for the `/healthz`, `/readyz`, and `/metrics`
    /// HTTP endpoints.
    #[arg(long, env = "OPERATOR_HTTP_ADDR", default_value = "0.0.0.0:8080")]
    http_addr: std::net::SocketAddr,
    /// Override the leader-election identity. Defaults to
    /// `<HOSTNAME>_<random>`. Setting this is useful for tests but
    /// shouldn't normally be touched in production.
    #[arg(long, env = "OPERATOR_IDENTITY")]
    identity: Option<String>,
    /// Disable leader election. Only safe with `replicas: 1`. When
    /// enabled, the operator skips the lease loop and acts as if it
    /// holds the lease from startup.
    #[arg(long, env = "OPERATOR_NO_LEADER_ELECT")]
    no_leader_elect: bool,
}

fn main() -> ExitCode {
    if let Err(err) = init_tracing() {
        eprintln!("rustgate-operator: failed to initialise tracing: {err}");
        return ExitCode::from(2);
    }
    let cli = Cli::parse();
    match cli.command {
        Command::Render { input } => run_render(&input),
        Command::Validate { input } => run_validate(&input),
        Command::Version => {
            println!("rustgate-operator {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Run(args) => run_controller(args),
    }
}

fn init_tracing() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,rustgate_operator=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()?;
    Ok(())
}

fn run_render(input: &str) -> ExitCode {
    match read_cluster(input) {
        Ok(cluster) => match render_all_yaml(&cluster) {
            Ok(yaml) => {
                print!("{yaml}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                tracing::error!(error = %err, "manifest rendering failed");
                ExitCode::from(1)
            }
        },
        Err(err) => {
            tracing::error!(error = %err, "input parse failed");
            ExitCode::from(1)
        }
    }
}

fn run_validate(input: &str) -> ExitCode {
    match read_cluster(input) {
        Ok(cluster) => match cluster.validate() {
            Ok(()) => {
                tracing::info!(
                    name = cluster.metadata.name,
                    namespace = cluster.metadata.namespace,
                    "RustgateCluster spec is valid"
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                tracing::error!(error = %err, "validation failed");
                ExitCode::from(1)
            }
        },
        Err(err) => {
            tracing::error!(error = %err, "input parse failed");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(feature = "controller"))]
fn run_controller(_: RunArgs) -> ExitCode {
    tracing::error!(
        "the `run` subcommand requires the `controller` build feature \
         (rebuild with `cargo build --features controller`)"
    );
    ExitCode::from(2)
}

#[cfg(feature = "controller")]
fn run_controller(args: RunArgs) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!(error = %err, "tokio runtime build failed");
            return ExitCode::from(1);
        }
    };

    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = runtime.block_on(async {
        use std::sync::Arc;
        use tokio::sync::watch;

        use prometheus::Registry;
        use rustgate_operator::{
            ControllerContext, LeaderConfig, LeaderElector, LeaderGate, default_identity,
        };
        use rustgate_operator::{events, health, metrics, run_controller as controller_run};

        // Construct the kube client. Picks up in-cluster config when
        // running as a pod (via the projected ServiceAccount token);
        // falls back to `~/.kube/config` for local development.
        let client = kube::Client::try_default().await?;

        // Set up the Prometheus registry first so metrics are
        // registered before the controller starts incrementing them.
        let registry = Arc::new(Registry::new());
        let _ = metrics::init(&registry);

        // Resolve the operator's namespace for the leader Lease. We
        // need a concrete namespace (the Lease is namespaced); when
        // OPERATOR_NAMESPACE is unset we fall back to `default`.
        let lease_namespace = args
            .namespace
            .clone()
            .or_else(|| std::env::var("OPERATOR_NAMESPACE").ok())
            .unwrap_or_else(|| "default".to_string());
        let identity = args.identity.clone().unwrap_or_else(default_identity);

        let gate = if args.no_leader_elect {
            tracing::warn!(target: "operator", "leader election disabled — only safe with replicas=1");
            LeaderGate::new_held()
        } else {
            LeaderGate::new()
        };
        let leader_cfg = LeaderConfig::new(&lease_namespace, &identity);
        let event_recorder = events::EventRecorder::new(client.clone());

        let ctx = ControllerContext {
            client: client.clone(),
            leader: gate.clone(),
            events: event_recorder,
            namespace: args.namespace.clone(),
        };

        // Shutdown signal — flipped on SIGTERM / SIGINT.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // HTTP server task.
        let health_task = {
            let client = client.clone();
            let registry = registry.clone();
            let shutdown_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(e) = health::serve(args.http_addr, client, registry, shutdown_rx).await {
                    tracing::warn!(target: "operator", error = %e, "health/metrics server exited");
                }
            })
        };

        // Leader election task (skipped when --no-leader-elect).
        let leader_task = if args.no_leader_elect {
            None
        } else {
            let client = client.clone();
            let cfg = leader_cfg.clone();
            let gate = gate.clone();
            let shutdown_rx = shutdown_rx.clone();
            Some(tokio::spawn(async move {
                let elector = LeaderElector::new(client, cfg, gate);
                if let Err(e) = elector.run(shutdown_rx).await {
                    tracing::warn!(target: "operator", error = %e, "leader elector exited with error");
                }
            }))
        };

        // Signal handler task — flips the shutdown watch on SIGTERM /
        // SIGINT.
        let signal_task = {
            let shutdown_tx = shutdown_tx.clone();
            // Also watch the shutdown flag itself: if the controller returns
            // for a non-signal reason (error / natural completion) and flips
            // the watch, this task must stop waiting for a signal that may
            // never arrive — otherwise the `signal_task.await` below hangs the
            // process forever (#1505).
            let mut shutdown_rx = shutdown_tx.subscribe();
            tokio::spawn(async move {
                use tokio::signal::unix::{SignalKind, signal};
                let mut term = match signal(SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(target: "operator", error = %e, "SIGTERM handler install failed");
                        return;
                    }
                };
                let mut intr = match signal(SignalKind::interrupt()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(target: "operator", error = %e, "SIGINT handler install failed");
                        return;
                    }
                };
                tokio::select! {
                    _ = term.recv() => {
                        tracing::info!(target: "operator", "SIGTERM received; draining");
                        let _ = shutdown_tx.send(true);
                    }
                    _ = intr.recv() => {
                        tracing::info!(target: "operator", "SIGINT received; draining");
                        let _ = shutdown_tx.send(true);
                    }
                    // Shutdown already triggered elsewhere — exit so the outer
                    // `signal_task.await` can complete.
                    _ = shutdown_rx.changed() => {}
                }
            })
        };

        // Run the controller. Returns when the watch stream terminates
        // (e.g. on `shutdown_on_signal` inside kube_runtime).
        tracing::info!(target: "operator", identity = %identity, namespace = ?args.namespace, "starting controller");
        let controller_result = controller_run(ctx).await;
        let _ = shutdown_tx.send(true);

        // Drain background tasks before returning.
        let _ = health_task.await;
        if let Some(t) = leader_task {
            let _ = t.await;
        }
        let _ = signal_task.await;
        controller_result.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    });

    match result {
        Ok(()) => {
            tracing::info!(target: "operator", "controller exited cleanly");
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(error = %err, "controller exited with error");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum InputError {
    #[error("read failed for `{path}`: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("YAML parse failed: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

fn read_cluster(input: &str) -> Result<RustgateCluster, InputError> {
    let raw = if input == "-" {
        let mut buf = String::new();
        let _ = io::stdin()
            .read_to_string(&mut buf)
            .map_err(|source| InputError::Io {
                path: PathBuf::from("<stdin>"),
                source,
            })?;
        buf
    } else {
        fs::read_to_string(input).map_err(|source| InputError::Io {
            path: PathBuf::from(input),
            source,
        })?
    };
    Ok(serde_yaml::from_str::<RustgateCluster>(&raw)?)
}
