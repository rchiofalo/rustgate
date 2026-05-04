// Copyright © 2026 Roberto Chiofalo.

//! Operator-facing diagnostic subcommands.
//!
//! These are pure utilities run via CLI subcommands (`cert-info`,
//! `crl-info`, `test-connection`, …) that inspect on-disk TLS
//! artifacts or probe network endpoints without touching the running
//! server. Each entry point builds a stable, machine-readable report
//! and writes it to stdout — either a human-friendly key/value layout
//! or strict JSON for scripted pipelines.
//!
//! The modules here deliberately avoid shared state: every subcommand
//! can be invoked before tracing and before any configuration has
//! been loaded. `test-connection` builds its own single-threaded
//! tokio runtime on the fly; the file-inspection commands run
//! entirely synchronously. That keeps them usable in bootstrap and
//! break-glass scenarios (an operator diagnosing a handshake failure
//! on a host that cannot start the server at all).
//!
//! # Stability
//!
//! The JSON output is treated as a *public contract* — field names,
//! key ordering within objects, and the top-level shape are pinned by
//! the integration tests in this crate. Changing any of them is a
//! breaking change for downstream tooling. Human output is explicitly
//! *not* a contract and may evolve for readability.

pub(crate) mod cert_info;
pub(crate) mod check_cert_expiry;
pub(crate) mod check_config;
pub(crate) mod crl_info;
pub(crate) mod dump_state;
#[cfg(feature = "schema")]
pub(crate) mod emit_schema;
pub(crate) mod generate_config;
pub(crate) mod test_connection;
