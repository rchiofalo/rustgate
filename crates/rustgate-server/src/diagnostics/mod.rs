// Copyright © 2026 Roberto Chiofalo.

//! Operator-facing diagnostic subcommands.
//!
//! These are pure utilities run via CLI subcommands (`cert-info`,
//! `crl-info`, …) that inspect on-disk TLS artifacts without touching
//! the running server. Each entry point reads a file, parses it, and
//! writes a stable, machine-readable report to stdout — either a
//! human-friendly key/value layout or strict JSON for scripted
//! pipelines.
//!
//! The modules here deliberately avoid shared state: every subcommand
//! can be invoked before the tokio runtime, before tracing, and before
//! any configuration has been loaded. That keeps them usable in
//! bootstrap and break-glass scenarios (an operator diagnosing a
//! handshake failure on a host that cannot start the server at all).
//!
//! # Stability
//!
//! The JSON output is treated as a *public contract* — field names,
//! key ordering within objects, and the top-level shape are pinned by
//! the integration tests in this crate. Changing any of them is a
//! breaking change for downstream tooling. Human output is explicitly
//! *not* a contract and may evolve for readability.

pub(crate) mod cert_info;
pub(crate) mod crl_info;
