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
//!
//! The `run` subcommand (the live cluster controller) is documented in
//! the crate-level docs as a deferred follow-up so the bare binary stays
//! lean and the renderer is independently usable.

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
    /// Reserved subcommand for the live cluster controller — deferred.
    Run,
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
        Command::Run => {
            tracing::error!(
                "the `run` subcommand (live cluster controller) is deferred — \
                 use `render` to produce manifests for `kubectl apply -f -`"
            );
            ExitCode::from(2)
        }
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
