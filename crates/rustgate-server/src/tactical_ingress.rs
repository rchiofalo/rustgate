// Copyright © 2026 Roberto Chiofalo.

//! Server wiring for tactical-codec UDP ingress (#1473).
//!
//! Datagram-oriented tactical protocols (DIS, ASTERIX, VMF, …) share one
//! generic, codec-pluggable listener — [`rustgate_transport::codec_ingress`]
//! — with the single shared admission gate
//! ([`rustgate_transport::udp_common::UdpAdmission`]). This module is the
//! thin per-protocol glue: parse the protocol's `--<proto>-*` flags, look up
//! the protocol's [`DynEntityCodec`] (the *same* codec the router's
//! `EntityCodecRegistry` uses for re-decode), and spawn the listener.
//!
//! Per the ingress design note (#1473) all three protocols route under a
//! synthetic, transport-derived identity — **no wire identifier ever
//! enters the CN or an authz decision**. Off by default; unauthenticated
//! and trusted-network-only (see `docs/tactical-ingress.md`).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use rustgate_core::entity::DynEntityCodec;
use rustgate_core::message::MessageType;
use rustgate_core::protocol::HeaderSize;
use rustgate_core::tasks::SubsystemHandle;
use rustgate_router::Router;
use rustgate_transport::codec_ingress::{CodecIngressConfig, CodecUdpInput};
use rustgate_transport::codec_tcp_ingress::{CodecTcpIngressConfig, CodecTcpInput, FramingFactory};
use rustgate_transport::{CidrPrefix, FramedCodec, HeaderLengthCodec, VarintDelimitedCodec};
use tokio::sync::Notify;

use crate::cli::Cli;

/// One protocol's resolved ingress parameters, assembled from its CLI flags.
struct ProtocolIngress {
    /// `--<proto>-bind` (unset ⇒ this protocol's ingress is disabled).
    bind: Option<String>,
    /// Destination group accepted datagrams route to.
    group: String,
    /// `--<proto>-rate-limit-pps`; `0` ⇒ the listener's secure default.
    rate_limit_pps: u32,
    /// `--<proto>-allowed-cidrs` (comma-separated); `None` ⇒ warn + accept all.
    allowed_cidrs: Option<String>,
    /// `--<proto>-max-identities` synthetic-identity LRU bound.
    max_identities: usize,
    /// Synthetic-identity CN prefix, e.g. `"dis-anonymous"`.
    cn_prefix: &'static str,
    /// `source_protocol` tag (must match the `EntityCodecRegistry` key).
    source_protocol: &'static str,
    /// Coarse routing/audit hint for accepted messages.
    message_type: MessageType,
    /// The protocol codec — the *same* type registered on the router, used
    /// here for edge validation so the edge and router cannot disagree.
    codec: Arc<dyn DynEntityCodec>,
}

/// Bind the socket and spawn the shared listener for one protocol, or return
/// `Ok(None)` when its `--<proto>-bind` is unset.
async fn spawn(
    p: ProtocolIngress,
    router: &Arc<Router>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let Some(bind) = p.bind.as_ref() else {
        return Ok(None);
    };
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("parsing --{}-bind `{bind}`", p.source_protocol))?;

    let allowed_cidrs = parse_cidrs(p.allowed_cidrs.as_deref(), p.source_protocol)?;
    let config = CodecIngressConfig {
        cn_prefix: p.cn_prefix.to_string(),
        group: p.group,
        // 0 means "secure default", not "off" — see CodecIngressConfig.
        max_pps: (p.rate_limit_pps > 0).then_some(p.rate_limit_pps as usize),
        allowed_cidrs,
        max_identities: p.max_identities,
        ..Default::default()
    };

    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .with_context(|| format!("binding {} UDP socket on {addr}", p.source_protocol))?;

    let shutdown = Arc::new(Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    let router = Arc::clone(router);
    let source_protocol = p.source_protocol.to_string();
    let codec = p.codec;
    let message_type = p.message_type;

    let task = tokio::spawn(async move {
        CodecUdpInput::run(
            socket,
            router,
            codec,
            source_protocol,
            message_type,
            config,
            shutdown_clone,
        )
        .await;
    });

    Ok(Some(SubsystemHandle::new(shutdown, task)))
}

/// Parse a comma-separated `--<proto>-allowed-cidrs` list. Empty entries are
/// skipped; an empty/whitespace-only list yields `None` (accept all, with
/// the listener's loud no-allowlist warning).
fn parse_cidrs(s: Option<&str>, proto: &str) -> anyhow::Result<Option<Vec<CidrPrefix>>> {
    let Some(s) = s else {
        return Ok(None);
    };
    let mut cidrs = Vec::new();
    for entry in s.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let cidr: CidrPrefix = trimmed.parse().map_err(|e| {
            anyhow::anyhow!("invalid --{proto}-allowed-cidrs entry '{trimmed}': {e}")
        })?;
        cidrs.push(cidr);
    }
    Ok((!cidrs.is_empty()).then_some(cidrs))
}

/// Start DIS (IEEE 1278.1) Entity State PDU ingress if `--dis-bind` is set.
pub(crate) async fn start_dis(
    cli: &Cli,
    router: &Arc<Router>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    spawn(
        ProtocolIngress {
            bind: cli.ingress.dis_bind.clone(),
            group: cli.ingress.dis_group.clone(),
            rate_limit_pps: cli.ingress.dis_rate_limit_pps,
            allowed_cidrs: cli.ingress.dis_allowed_cidrs.clone(),
            max_identities: cli.ingress.dis_max_identities,
            cn_prefix: "dis-anonymous",
            source_protocol: "dis",
            // DIS Entity State PDUs are kinematic position/state reports.
            message_type: MessageType::Position,
            codec: Arc::new(rustgate_dis::DisCodec),
        },
        router,
    )
    .await
}

/// Start ASTERIX (CAT-062) datablock ingress if `--asterix-bind` is set.
pub(crate) async fn start_asterix(
    cli: &Cli,
    router: &Arc<Router>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    spawn(
        ProtocolIngress {
            bind: cli.ingress.asterix_bind.clone(),
            group: cli.ingress.asterix_group.clone(),
            rate_limit_pps: cli.ingress.asterix_rate_limit_pps,
            allowed_cidrs: cli.ingress.asterix_allowed_cidrs.clone(),
            max_identities: cli.ingress.asterix_max_identities,
            cn_prefix: "asterix-anonymous",
            source_protocol: "asterix",
            // CAT-062 system tracks are surveillance position reports.
            message_type: MessageType::Position,
            codec: Arc::new(rustgate_asterix::entity::AsterixEntityCodec),
        },
        router,
    )
    .await
}

/// Start VMF (MIL-STD-6017 K05.1) position-report ingress if `--vmf-bind`
/// is set.
pub(crate) async fn start_vmf(
    cli: &Cli,
    router: &Arc<Router>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    spawn(
        ProtocolIngress {
            bind: cli.ingress.vmf_bind.clone(),
            group: cli.ingress.vmf_group.clone(),
            rate_limit_pps: cli.ingress.vmf_rate_limit_pps,
            allowed_cidrs: cli.ingress.vmf_allowed_cidrs.clone(),
            max_identities: cli.ingress.vmf_max_identities,
            cn_prefix: "vmf-anonymous",
            source_protocol: "vmf",
            // K05.1 is a position report.
            message_type: MessageType::Position,
            codec: Arc::new(rustgate_vmf::VmfCodec),
        },
        router,
    )
    .await
}

/// One stream (TCP) protocol's resolved ingress parameters.
struct TcpProtocolIngress {
    bind: Option<String>,
    group: String,
    rate_limit_pps: u32,
    allowed_cidrs: Option<String>,
    max_identities: usize,
    max_connections: usize,
    cn_prefix: &'static str,
    source_protocol: &'static str,
    message_type: MessageType,
    /// Per-frame validation codec (same instance the router re-decodes with).
    codec: Arc<dyn DynEntityCodec>,
    /// Produces a fresh per-connection frame delimiter.
    framing: FramingFactory,
}

/// Bind a TCP listener and spawn the shared stream-ingress listener, or
/// return `Ok(None)` when its `--<proto>-bind` is unset.
async fn spawn_tcp(
    p: TcpProtocolIngress,
    router: &Arc<Router>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let Some(bind) = p.bind.as_ref() else {
        return Ok(None);
    };
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("parsing --{}-bind `{bind}`", p.source_protocol))?;

    let allowed_cidrs = parse_cidrs(p.allowed_cidrs.as_deref(), p.source_protocol)?;
    let config = CodecTcpIngressConfig {
        cn_prefix: p.cn_prefix.to_string(),
        group: p.group,
        // 0 means "secure default", not "off".
        max_accepts_per_sec: (p.rate_limit_pps > 0).then_some(p.rate_limit_pps as usize),
        allowed_cidrs,
        max_identities: p.max_identities,
        max_connections: p.max_connections,
    };

    // Per-connection socket hardening (configure_tactical_socket) is applied
    // to every accepted stream inside CodecTcpInput::run, not here — this
    // call only binds the listening socket.
    let listener = tokio::net::TcpListener::bind(addr) // playbook-drift-ok: per-stream config in CodecTcpInput::run
        .await
        .with_context(|| format!("binding {} TCP socket on {addr}", p.source_protocol))?;

    let shutdown = Arc::new(Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    let router = Arc::clone(router);
    let source_protocol = p.source_protocol.to_string();
    let codec = p.codec;
    let framing = p.framing;
    let message_type = p.message_type;

    let task = tokio::spawn(async move {
        CodecTcpInput::run(
            listener,
            router,
            codec,
            framing,
            source_protocol,
            message_type,
            config,
            shutdown_clone,
        )
        .await;
    });

    Ok(Some(SubsystemHandle::new(shutdown, task)))
}

/// Start SAPIENT (BSI Flex 335) protobuf ingress over TCP if `--sapient-bind`
/// is set. Frames are varint length-delimited; each frame is validated with
/// the `SapientCodec` before routing.
pub(crate) async fn start_sapient(
    cli: &Cli,
    router: &Arc<Router>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    let framing: FramingFactory =
        Arc::new(|| FramedCodec::VarintDelimited(VarintDelimitedCodec::new()));
    spawn_tcp(
        TcpProtocolIngress {
            bind: cli.ingress.sapient_bind.clone(),
            group: cli.ingress.sapient_group.clone(),
            rate_limit_pps: cli.ingress.sapient_rate_limit_pps,
            allowed_cidrs: cli.ingress.sapient_allowed_cidrs.clone(),
            max_identities: cli.ingress.sapient_max_identities,
            max_connections: cli.ingress.sapient_max_connections,
            cn_prefix: "sapient-anonymous",
            source_protocol: "sapient",
            // SAPIENT detection reports carry a located entity.
            message_type: MessageType::Position,
            codec: Arc::new(rustgate_sapient::SapientCodec),
            framing,
        },
        router,
    )
    .await
}

/// Start Link 16 / JREAP-C (STANAG 5518) ingress over TCP if `--link16-bind`
/// is set. Frames are delimited by the 16-byte JREAP header's `body_length`
/// field (u32 BE at offset 12); each full frame is validated with the
/// `Link16Codec` before routing.
pub(crate) async fn start_link16(
    cli: &Cli,
    router: &Arc<Router>,
) -> anyhow::Result<Option<SubsystemHandle>> {
    // JREAP-C: 16-byte header, body_length u32 (HeaderSize::Four) at offset 12;
    // the delimited frame includes the header so Link16Codec can parse it.
    let framing: FramingFactory =
        Arc::new(|| FramedCodec::HeaderLength(HeaderLengthCodec::new(16, 12, HeaderSize::Four)));
    spawn_tcp(
        TcpProtocolIngress {
            bind: cli.ingress.link16_bind.clone(),
            group: cli.ingress.link16_group.clone(),
            rate_limit_pps: cli.ingress.link16_rate_limit_pps,
            allowed_cidrs: cli.ingress.link16_allowed_cidrs.clone(),
            max_identities: cli.ingress.link16_max_identities,
            max_connections: cli.ingress.link16_max_connections,
            cn_prefix: "link16-anonymous",
            source_protocol: "link16",
            // J-series air tracks are position reports.
            message_type: MessageType::Position,
            codec: Arc::new(rustgate_link16::Link16Codec),
            framing,
        },
        router,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidrs_none_for_unset_or_empty() {
        assert!(parse_cidrs(None, "dis").unwrap().is_none());
        assert!(parse_cidrs(Some(""), "dis").unwrap().is_none());
        assert!(parse_cidrs(Some("  , "), "dis").unwrap().is_none());
    }

    #[test]
    fn parse_cidrs_parses_list() {
        let cidrs = parse_cidrs(Some("10.0.0.0/8, 192.168.0.0/16"), "asterix")
            .unwrap()
            .unwrap();
        assert_eq!(cidrs.len(), 2);
    }

    #[test]
    fn parse_cidrs_rejects_invalid_entry() {
        let err = parse_cidrs(Some("10.0.0.0/8,not-a-cidr"), "vmf").unwrap_err();
        // The protocol name is threaded into the diagnostic.
        assert!(err.to_string().contains("vmf"));
    }
}
