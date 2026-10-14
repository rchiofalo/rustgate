// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Server-side wiring for the cross-domain egress guard (PR-C2 of #1457).
//!
//! The `rustgate-guard` crate provides the boundary-inspection logic
//! ([`GuardGate`], built from a [`GuardConfig`]) and the router exposes
//! the central seam ([`Router::set_on_egress_guard`], landed in PR-C1).
//! This module is the glue: it loads the operator's `[guard]` TOML,
//! builds the gate, and installs an [`OnEgressGuard`] closure on the
//! router so every external-egress message is gated at the single
//! chokepoint inside `route_for_egress` (ADR / design note
//! `docs/design/guard-server-wiring.md`).
//!
//! # Config
//!
//! ```toml
//! [guard]
//! low-to-high-max-bps = 1048576
//! high-to-low-max-bps = 262144      # tighter on the release direction
//! mandatory-marking = true          # fail-closed default
//! audit-log-path = "/var/log/rustgate/boundary-audit.jsonl"
//! direction = "bidirectional"       # deployment hint (v1: global)
//! ```
//!
//! `GuardConfig` is the single source of truth for this shape (it lives
//! in `rustgate-guard` with `deny_unknown_fields`); the server does not
//! shadow it. The file is read into [`Zeroizing`] memory — although the
//! guard config is not itself key material, the same secret-file
//! discipline the rest of the server uses applies (the audit-log path
//! and any future pre-shared marking secret must not linger in plaintext
//! buffers).
//!
//! # Direction (v1: global)
//!
//! Per the #1457 design note, v1 uses a single global direction from
//! `GuardConfig.direction`. The crate's `evaluate` requires a concrete
//! per-call `LowToHigh` / `HighToLow` (the `Bidirectional` config value
//! is a deployment hint, not a per-call direction); a `Bidirectional`
//! deployment maps to the least-restrictive `LowToHigh` for the per-call
//! evaluation, matching the crate's documented behavior. Per-sink
//! direction is a follow-up that layers on without a wire break.

use std::sync::Arc;

use anyhow::Context as _;
use rustgate_core::egress::{EgressGuardVerdict, OnEgressGuard};
use rustgate_guard::{GuardConfig, GuardDirection, GuardGate};
use rustgate_router::Router;
use zeroize::Zeroizing;

use crate::cli::Cli;

/// Map the configured deployment direction to the concrete per-call
/// direction `GuardGate::evaluate` requires.
///
/// `Bidirectional` is a config-only hint; the crate treats a per-call
/// `Bidirectional` as `LowToHigh` (least-restrictive), so we resolve it
/// here for the v1 single global gate.
fn per_call_direction(configured: GuardDirection) -> GuardDirection {
    match configured {
        GuardDirection::HighToLow => GuardDirection::HighToLow,
        GuardDirection::LowToHigh | GuardDirection::Bidirectional => GuardDirection::LowToHigh,
    }
}

/// Install the cross-domain egress guard on the router if `--guard-config`
/// is set.
///
/// Loads and validates the `[guard]` TOML, builds a [`GuardGate`], and
/// installs an [`OnEgressGuard`] closure via
/// [`Router::set_on_egress_guard`]. Emits `audit::guard_activated` once on
/// success. A no-op (returns `Ok(())`) when no guard is configured.
///
/// # Errors
///
/// Returns an error if the config file cannot be read, fails to parse,
/// fails [`GuardConfig::validate`], or the gate cannot open its audit
/// log.
pub(crate) fn start_guard(cli: &Cli, router: &Arc<Router>) -> anyhow::Result<()> {
    let Some(path) = cli.integrations.guard_config_file.as_ref() else {
        return Ok(());
    };

    let raw = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("reading guard config file `{path}`"))?,
    );

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wrapper {
        guard: GuardConfig,
    }
    let mut cfg: GuardConfig = toml::from_str::<Wrapper>(&raw)
        .with_context(|| format!("parsing `[guard]` block in `{path}`"))?
        .guard;

    // The CLI flag (env `RUSTGATE_GUARD_AUDIT_CHAIN_FAIL_OPEN`) overrides
    // the TOML `audit-chain-fail-open` key only when set to `true` — a
    // secure default cannot be re-tightened by omitting the flag, but an
    // operator can opt into fail-open at the command line without editing
    // the guard file (ADR 0024, H-2; the TOML block stays primary).
    if cli.integrations.guard_audit_chain_fail_open {
        cfg.audit_chain_fail_open = true;
    }
    if cfg.audit_chain_fail_open {
        tracing::warn!(
            "cross-domain guard audit-chain-fail-open is ENABLED — an unreadable audit chain will resume with a boundary.chain_break seam instead of aborting startup; the tamper-evident chain link restarts (seq carried forward)"
        );
    }

    cfg.validate().context("invalid `[guard]` configuration")?;

    let direction = per_call_direction(cfg.direction);
    let mandatory_marking = cfg.mandatory_marking;
    let configured_direction = cfg.direction.as_label();

    let gate = GuardGate::new(cfg).context("constructing cross-domain guard")?;

    let closure_gate = gate.clone();
    let cb: OnEgressGuard = Arc::new(move |msg| match closure_gate.evaluate(msg, direction) {
        Ok(_) => EgressGuardVerdict::Allow,
        Err(e) => EgressGuardVerdict::Deny {
            reason: e.reason_token(),
        },
    });
    router.set_on_egress_guard(Some(cb));

    rustgate_core::audit::guard_activated("egress", configured_direction, mandatory_marking);
    tracing::warn!(
        direction = configured_direction,
        mandatory_marking,
        "cross-domain egress guard ACTIVE — all external egress is gated at the boundary"
    );

    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    #[test]
    fn per_call_direction_resolves_bidirectional_to_low_to_high() {
        assert_eq!(
            per_call_direction(GuardDirection::Bidirectional),
            GuardDirection::LowToHigh
        );
        assert_eq!(
            per_call_direction(GuardDirection::LowToHigh),
            GuardDirection::LowToHigh
        );
        assert_eq!(
            per_call_direction(GuardDirection::HighToLow),
            GuardDirection::HighToLow
        );
    }

    #[test]
    fn guard_config_wrapper_parses_block_and_rejects_unknown() {
        let toml = r#"
            [guard]
            low-to-high-max-bps = 2048
            high-to-low-max-bps = 1024
            mandatory-marking = false
            audit-log-path = "/tmp/g.jsonl"
            direction = "high-to-low"
        "#;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wrapper {
            guard: GuardConfig,
        }
        let w: Wrapper = toml::from_str(toml).unwrap();
        assert_eq!(w.guard.high_to_low_max_bps, 1024);
        assert_eq!(w.guard.direction, GuardDirection::HighToLow);

        // An unknown top-level key is rejected (deny_unknown_fields).
        let bad = "[guard]\nlow-to-high-max-bps = 1\nbogus = 1\n";
        assert!(toml::from_str::<Wrapper>(bad).is_err());
    }
}
