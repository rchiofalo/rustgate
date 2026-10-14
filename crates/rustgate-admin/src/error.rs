// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed error vocabulary for `rustgate-admin`.
//!
//! Per [ADR 0007](../../../docs/adr/0007-thiserror-everywhere-no-anyhow-in-libs.md)
//! library crates expose `thiserror`-derived enum errors rather than
//! `anyhow::Result`. This module collects the two surfaces that were
//! previously `anyhow`-typed ([`crate::acl_reloader::AclReloader::reload`]
//! and [`crate::server::serve`]) into discriminating enum variants so
//! callers can match on failure mode instead of inspecting string
//! `Display` output.

use std::path::PathBuf;

/// Failure modes for the on-disk ACL file reloader.
///
/// Each variant carries the structured context the audit-log writer
/// and the operator-facing `tracing::error!` already need — paths,
/// upstream IO/parse errors — without losing fidelity through an
/// `anyhow::anyhow!(...)` string concatenation.
#[derive(Debug, thiserror::Error)]
pub enum AclReloadError {
    /// `std::fs::read_to_string` failed for the configured ACL path.
    /// Most common cause is operator file-permission missteps after
    /// a config-management tool rewrites the file; second-most-common
    /// is the file being mid-rotation (rename-into-place) at the
    /// moment the polling tick fires.
    #[error("failed to read ACL file {path}: {source}")]
    Read {
        /// Path the reloader was configured with at construction.
        path: PathBuf,
        /// Underlying `std::io::Error`. Includes ENOENT, EACCES, etc.
        #[source]
        source: std::io::Error,
    },

    /// `serde_json::from_str` rejected the file content. Usually a
    /// trailing comma, an unbalanced brace, or a typo in a top-level
    /// key. The validator beyond JSON syntax (e.g. reserved sentinel
    /// group IDs `__*__`) reports via [`Self::ValidationRejected`].
    #[error("failed to parse ACL file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// The reload validator rejected the parsed-but-otherwise-syntactically-
    /// valid policy. The current trigger is reserved-sentinel group IDs
    /// (`__plaintext__`, `__federation__`, …) appearing in an operator-
    /// supplied file, which the startup loader rejects identically.
    /// Reload re-applies the same guardrail so a runtime config change
    /// cannot bypass startup invariants.
    #[error("refusing to reload ACL file {path}: {detail}")]
    ValidationRejected {
        path: PathBuf,
        /// Human-readable rejection reason from
        /// `GroupAclFile::validate_operator_policy()`.
        detail: String,
    },

    /// The reloader's internal `last_hash` mutex was poisoned by an
    /// earlier panic. Should be unreachable in a well-behaved server
    /// (the reload body holds no panicky guard); surfacing it as a
    /// typed variant means a forensic operator gets a discriminator
    /// rather than a stringified `PoisonError`.
    #[error("ACL reloader internal hash lock was poisoned")]
    HashLockPoisoned,
}

/// Failure modes for the HTTP admin / metrics server.
///
/// `serve` runs forever once bound; the `Result` variants describe
/// the startup-time failures (port bind) and the recoverable
/// per-connection failures the inner accept loop bubbles up.
#[derive(Debug, thiserror::Error)]
pub enum AdminServerError {
    /// The TCP bind to the configured admin address failed. Common
    /// causes: port already in use (another rustgate instance or a
    /// kube-proxy taking the same address), insufficient privilege
    /// to bind a low-numbered port, or address-family mismatch
    /// between `--admin-bind` and the host's networking.
    #[error("failed to bind admin server to {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// The accept call inside the connection loop failed. The loop
    /// continues (one accept failure does not bring the server down),
    /// but the error is logged + returned for the supervising task
    /// to record. Real-world triggers: file-descriptor exhaustion,
    /// kernel-level `EMFILE`.
    #[error("admin server accept loop failed: {source}")]
    Accept {
        #[source]
        source: std::io::Error,
    },
}
