// Copyright © 2026 Roberto Chiofalo.

//! Server wiring for DIS (IEEE 1278.1) UDP ingress — the first protocol on
//! the generic tactical-codec ingress seam (#1473).
//!
//! DIS Entity State PDUs arrive as UDP datagrams (one PDU per datagram) on
//! a simulation/exercise LAN with no transport authentication. This module
//! binds the socket and spawns the shared [`CodecUdpInput`] listener,
//! parameterized with [`rustgate_dis::DisCodec`] for edge validation and
//! the `"dis"` `source_protocol` tag (already registered in the router's
//! `EntityCodecRegistry`, so accepted datagrams route, dedup, and correlate
//! end-to-end). All admission controls (CIDR allowlist, rate limit,
//! identity cap, size cap) and the synthetic-identity / threat-model
//! posture live in the shared listener — see `docs/tactical-ingress.md`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use rustgate_core::entity::DynEntityCodec;
use rustgate_core::message::MessageType;
use rustgate_core::tasks::SubsystemHandle;
use rustgate_router::Router;
use rustgate_transport::CidrPrefix;
use rustgate_transport::codec_ingress::{CodecIngressConfig, CodecUdpInput};
use tokio::sync::Notify;

use crate::cli::Cli;

/// Start the DIS UDP ingress listener if `--dis-bind` is set.
///
/// Returns `Ok(None)` when DIS ingress is not configured; otherwise the
/// spawned [`SubsystemHandle`] for the server's graceful-shutdown set.
///
/// # Errors
///
/// Returns an error if `--dis-bind` or a `--dis-allowed-cidrs` entry fails
/// to parse, or the UDP socket cannot bind.
pub(crate) async fn start_dis(
    cli: &Cli,
    router: &Arc<Router>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let Some(bind) = cli.dis_bind.as_ref() else {
        return Ok(None);
    };
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("parsing --dis-bind `{bind}`"))?;

    let allowed_cidrs = parse_cidrs(cli.dis_allowed_cidrs.as_deref())?;
    let config = CodecIngressConfig {
        cn_prefix: "dis-anonymous".to_string(),
        group: cli.dis_group.clone(),
        // 0 means "secure default", not "off" — see CodecIngressConfig.
        max_pps: (cli.dis_rate_limit_pps > 0).then_some(cli.dis_rate_limit_pps as usize),
        allowed_cidrs,
        max_identities: cli.dis_max_identities,
        ..Default::default()
    };

    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .with_context(|| format!("binding DIS UDP socket on {addr}"))?;

    let codec: Arc<dyn DynEntityCodec> = Arc::new(rustgate_dis::DisCodec);
    let shutdown = Arc::new(Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    let router = Arc::clone(router);

    let task = tokio::spawn(async move {
        CodecUdpInput::run(
            socket,
            router,
            codec,
            "dis".to_string(),
            // DIS Entity State PDUs are kinematic position/state reports.
            MessageType::Position,
            config,
            shutdown_clone,
        )
        .await;
    });

    Ok(Some(SubsystemHandle::new(shutdown, task)))
}

/// Parse a comma-separated `--dis-allowed-cidrs` list. Empty entries are
/// skipped; an empty/whitespace-only list yields `None` (accept all, with
/// the listener's loud no-allowlist warning).
fn parse_cidrs(s: Option<&str>) -> anyhow::Result<Option<Vec<CidrPrefix>>> {
    let Some(s) = s else {
        return Ok(None);
    };
    let mut cidrs = Vec::new();
    for entry in s.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let cidr: CidrPrefix = trimmed
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --dis-allowed-cidrs entry '{trimmed}': {e}"))?;
        cidrs.push(cidr);
    }
    Ok((!cidrs.is_empty()).then_some(cidrs))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidrs_none_for_unset_or_empty() {
        assert!(parse_cidrs(None).unwrap().is_none());
        assert!(parse_cidrs(Some("")).unwrap().is_none());
        assert!(parse_cidrs(Some("  , ")).unwrap().is_none());
    }

    #[test]
    fn parse_cidrs_parses_list() {
        let cidrs = parse_cidrs(Some("10.0.0.0/8, 192.168.0.0/16"))
            .unwrap()
            .unwrap();
        assert_eq!(cidrs.len(), 2);
    }

    #[test]
    fn parse_cidrs_rejects_invalid_entry() {
        assert!(parse_cidrs(Some("10.0.0.0/8,not-a-cidr")).is_err());
    }
}
