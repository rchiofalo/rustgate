// Copyright © 2026 Roberto Chiofalo.

//! Generic UDP codec ingress for connectionless tactical protocols.
//!
//! A single, codec-pluggable UDP listener that turns datagram-oriented
//! tactical wire formats (DIS, ASTERIX, VMF today; more later) into routed
//! [`RoutableMessage`]s. It is the generalization of the CoT-specific
//! [`crate::udp::UdpInput`] called for by the tactical-codec ingress design
//! note (#1473): the only per-protocol part is *which codec validates the
//! datagram and what `source_protocol` tag it carries* — every security
//! control is shared via [`crate::udp_common::UdpAdmission`].
//!
//! # Per-datagram pipeline
//!
//! 1. **Admission** ([`UdpAdmission`]) — CIDR allowlist → per-IP rate limit
//!    → identity cap, each rejection audited by class.
//! 2. **Size cap** — datagrams larger than the configured bound are
//!    dropped before any decode (no unbounded work).
//! 3. **Validating decode** — the datagram is decoded with the *same*
//!    [`DynEntityCodec`] the router uses ([decision D2/Q3]); a datagram
//!    that does not decode to a valid `Entity` is dropped at the edge and
//!    audited. The decoded entity is **discarded** — the router re-decodes
//!    via its [`rustgate_core::entity::EntityCodecRegistry`] so it stays the
//!    single source of routing truth.
//! 4. **Build + route** — a [`RoutableMessage`] is built carrying the *raw*
//!    datagram bytes, a synthetic transport-derived identity (decision D3:
//!    wire identifiers never enter the CN), the protocol's `source_protocol`
//!    tag, and the configured destination group, then handed to
//!    [`Router::route`] (which applies ACL/authz and egress exactly as for
//!    every other transport).
//!
//! # Security posture
//!
//! No mTLS: identity is synthetic and the routed group is the only trust
//! decision (operator-assigned, never wire-derived). Same posture as the
//! plaintext/CoT-UDP listener — trusted-network deployment only. See
//! `docs/tactical-ingress.md`.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use rustgate_core::audit;
use rustgate_core::constants::MAX_FRAME_SIZE;
use rustgate_core::entity::DynEntityCodec;
use rustgate_core::identity::Identity;
use rustgate_core::masking::mask_ip;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::Router;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tracing::warn;

use crate::udp::CidrPrefix;
use crate::udp_common::{AdmitDecision, UdpAdmission};

/// Hard upper bound on a single UDP datagram (the theoretical max).
const MAX_UDP_DATAGRAM: usize = 65_535;

/// Default per-IP datagrams/sec applied when an operator does not set one.
///
/// Unlike the CoT-UDP listener (where the limit is optional), a tactical
/// codec ingress is **never** unlimited by default: every one of these
/// ports is an unauthenticated amplification/DoS surface, so "no limit" is
/// not a safe default (design note, Mandatory hardening).
pub const DEFAULT_INGRESS_MAX_PPS: usize = 10_000;

/// Default synthetic-identity LRU bound.
pub const DEFAULT_INGRESS_MAX_IDENTITIES: usize = 1024;

/// Configuration for a [`CodecUdpInput`] listener instance.
#[derive(Debug, Clone)]
pub struct CodecIngressConfig {
    /// CN prefix for the synthetic per-datagram identity. The peer address
    /// is appended for traceability; the wire identifier is **never** folded
    /// in (decision D3 — wire IDs are spoofable and must not steer authz).
    pub cn_prefix: String,
    /// Destination group every accepted datagram routes to. ACL/authz apply
    /// to this group exactly as for any other transport — it is the sole
    /// trust decision for an unauthenticated feed.
    pub group: String,
    /// Per-IP datagrams/sec. `None` applies [`DEFAULT_INGRESS_MAX_PPS`]
    /// (never truly unlimited).
    pub max_pps: Option<usize>,
    /// Source CIDR allowlist. `None` accepts all sources but triggers a
    /// loud startup warning (this is an unauthenticated feed).
    pub allowed_cidrs: Option<Vec<CidrPrefix>>,
    /// Synthetic-identity LRU bound.
    pub max_identities: usize,
    /// Maximum accepted datagram size in bytes (clamped to the UDP max and
    /// to [`MAX_FRAME_SIZE`]); larger datagrams are dropped before decode.
    pub max_datagram_size: usize,
    /// Optional IPv4 multicast group to join for ingress (decision D4). When
    /// `Some`, [`CodecIngressConfig::bind_socket`] binds with `SO_REUSEADDR`
    /// and `join_multicast_v4(group, interface)` so DIS/ASTERIX/VMF can be
    /// received on an exercise-LAN multicast address; admission and
    /// validate-and-drop apply identically. When `None` (the default) the
    /// listener does a plain unicast bind — behaviour is unchanged. The
    /// address must be in `224.0.0.0/4` and outside the reserved
    /// `224.0.0.0/24` link-local control block; an invalid address is
    /// rejected at bind time.
    pub multicast_group: Option<Ipv4Addr>,
    /// IPv4 interface address for the multicast join (the local NIC the
    /// kernel should join on). Only consulted when [`Self::multicast_group`]
    /// is `Some`. Defaults to `0.0.0.0` (let the kernel pick the default
    /// routed interface); operators on multi-NIC hosts can pin a specific
    /// interface.
    pub multicast_interface: Ipv4Addr,
}

impl Default for CodecIngressConfig {
    fn default() -> Self {
        Self {
            cn_prefix: "ingress-anonymous".to_string(),
            group: rustgate_core::constants::PLAINTEXT_GROUP.to_string(),
            max_pps: None,
            allowed_cidrs: None,
            max_identities: DEFAULT_INGRESS_MAX_IDENTITIES,
            max_datagram_size: MAX_UDP_DATAGRAM,
            multicast_group: None,
            multicast_interface: Ipv4Addr::UNSPECIFIED,
        }
    }
}

impl CodecIngressConfig {
    /// Effective per-IP rate limit, applying the secure default when unset.
    fn effective_max_pps(&self) -> usize {
        self.max_pps.unwrap_or(DEFAULT_INGRESS_MAX_PPS)
    }

    /// Effective datagram size cap, clamped to the UDP and frame maxima.
    fn effective_size_cap(&self) -> usize {
        self.max_datagram_size
            .min(MAX_UDP_DATAGRAM)
            .min(MAX_FRAME_SIZE)
    }

    /// Bind the ingress socket for `addr`, honouring the optional multicast
    /// join (decision D4).
    ///
    /// When [`Self::multicast_group`] is `Some`, the socket is bound with
    /// `SO_REUSEADDR` on `addr`'s port and joins the group via the shared
    /// [`crate::udp_common::bind_multicast_socket_v4`] helper (the same
    /// reviewed setup the CoT multicast listener uses); the group must be a
    /// valid `224.0.0.0/4` address outside the reserved `224.0.0.0/24`
    /// control block, or the bind is rejected. When `None`, a
    /// plain unicast [`UdpSocket::bind`] is performed and behaviour is
    /// identical to the pre-multicast listener.
    ///
    /// The returned socket feeds [`CodecUdpInput::run`]; admission and
    /// validate-and-drop are applied identically regardless of how the
    /// socket was bound.
    pub async fn bind_socket(&self, addr: SocketAddr) -> std::io::Result<UdpSocket> {
        match self.multicast_group {
            Some(group) => {
                if !group.is_multicast() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("multicast group `{group}` is not in 224.0.0.0/4"),
                    ));
                }
                // SEC-12: reject the reserved link-local control block
                // 224.0.0.0/24 (224.0.0.1 all-hosts, 224.0.0.2 all-routers,
                // 224.0.0.251 mDNS, …). Joining one of these subscribes the
                // listener to local control-plane chatter that floods it and
                // is never a valid tactical-data group. Stable Rust has no
                // `Ipv4Addr::is_reserved_multicast`, so test the octets.
                let o = group.octets();
                if o[0] == 224 && o[1] == 0 && o[2] == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "multicast group `{group}` is in the reserved link-local control block 224.0.0.0/24"
                        ),
                    ));
                }
                crate::udp_common::bind_multicast_socket_v4(
                    group,
                    addr.port(),
                    self.multicast_interface,
                )
            }
            None => UdpSocket::bind(addr).await,
        }
    }
}

/// A generic codec-pluggable UDP ingress listener.
#[derive(Debug)]
pub struct CodecUdpInput;

impl CodecUdpInput {
    /// Run the ingress loop until `shutdown` is notified.
    ///
    /// `codec` validates each datagram (the same `Arc<dyn DynEntityCodec>`
    /// the router holds for `source_protocol`); `source_protocol` tags the
    /// routed message so the router's registry can re-decode it; and
    /// `message_type` is the coarse routing/audit hint for the protocol.
    ///
    /// Decode is fallible and never panics on hostile input; every drop
    /// class is audited.
    pub async fn run(
        socket: UdpSocket,
        router: Arc<Router>,
        codec: Arc<dyn DynEntityCodec>,
        source_protocol: String,
        message_type: MessageType,
        config: CodecIngressConfig,
        shutdown: Arc<Notify>,
    ) {
        let local = socket.local_addr().ok();
        let size_cap = config.effective_size_cap();
        let max_pps = config.effective_max_pps();

        warn!(
            protocol = %source_protocol,
            local_addr = ?local,
            multicast_group = ?config.multicast_group,
            "tactical codec ingress active — datagrams are UNAUTHENTICATED and NOT encrypted"
        );
        if let Some(group) = config.multicast_group {
            tracing::info!(
                protocol = %source_protocol,
                local_addr = ?local,
                multicast_group = %group,
                multicast_interface = %config.multicast_interface,
                "tactical codec ingress joined IPv4 multicast group"
            );
        }
        if config.allowed_cidrs.is_none() {
            warn!(
                protocol = %source_protocol,
                local_addr = ?local,
                "tactical codec ingress has NO source CIDR allowlist — exposed to the whole \
                 reachable network; restrict to a trusted segment"
            );
        }

        let admission = UdpAdmission::new(
            Some(max_pps),
            config.allowed_cidrs.clone(),
            config.max_identities,
        );

        let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    let (len, peer) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(protocol = %source_protocol, error = %e, "ingress recv error");
                            continue;
                        }
                    };
                    if len == 0 {
                        continue;
                    }
                    let peer_ip: IpAddr = peer.ip();

                    // --- Size cap (before any decode) ---
                    if len > size_cap {
                        audit::connection_rejected(peer, "datagram_too_large");
                        tracing::debug!(
                            protocol = %source_protocol, peer = %mask_ip(&peer.to_string()),
                            bytes = len, cap = size_cap, "ingress datagram dropped: too large"
                        );
                        continue;
                    }

                    // --- Admission (CIDR / rate limit / identity cap) ---
                    match admission.admit(peer_ip) {
                        AdmitDecision::Accept => {}
                        AdmitDecision::DeniedCidr => {
                            audit::connection_rejected(peer, "cidr_not_allowed");
                            continue;
                        }
                        AdmitDecision::RateLimited => {
                            audit::rate_limit_triggered(
                                &mask_ip(&peer.to_string()), &source_protocol, max_pps,
                            );
                            continue;
                        }
                        AdmitDecision::IdentityCapReached => {
                            audit::connection_rejected(peer, "identity_cap_reached");
                            tracing::warn!(
                                protocol = %source_protocol, peer = %mask_ip(&peer.to_string()),
                                max_identities = config.max_identities,
                                "ingress datagram rejected: identity cap reached"
                            );
                            continue;
                        }
                    }

                    // --- Validating decode (edge admission, entity discarded) ---
                    if let Err(e) = codec.to_entity_dyn(&buf[..len]) {
                        audit::connection_rejected(peer, "malformed_datagram");
                        tracing::debug!(
                            protocol = %source_protocol, peer = %mask_ip(&peer.to_string()),
                            error = %e, "ingress datagram dropped: failed to decode"
                        );
                        continue;
                    }

                    // --- Build synthetic-identity message (wire IDs never in CN) ---
                    let payload = Bytes::copy_from_slice(&buf[..len]);
                    let cn = format!("{}-{}", config.cn_prefix, peer);
                    let mut groups = BTreeSet::new();
                    let _ = groups.insert(config.group.clone());
                    let identity = match Identity::plaintext(cn, groups) {
                        Ok(id) => id,
                        Err(e) => {
                            tracing::warn!(
                                protocol = %source_protocol, peer = %mask_ip(&peer.to_string()),
                                error = %e, "ingress datagram dropped: invalid synthetic identity"
                            );
                            continue;
                        }
                    };
                    let msg = RoutableMessage {
                        source: identity,
                        destination: Destination::Group(Arc::from(config.group.as_str())),
                        payload,
                        metadata: Metadata::new(
                            std::time::SystemTime::now(),
                            source_protocol.clone(),
                            message_type.clone(),
                        ),
                        entity: None,
                    };
                    router.route(msg).await;
                }
                _ = shutdown.notified() => {
                    tracing::info!(protocol = %source_protocol, "tactical codec ingress shutting down");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_secure() {
        let cfg = CodecIngressConfig::default();
        // No truly-unlimited default: an unset rate limit resolves to the
        // secure default, never "off".
        assert_eq!(cfg.effective_max_pps(), DEFAULT_INGRESS_MAX_PPS);
        assert_eq!(cfg.max_identities, DEFAULT_INGRESS_MAX_IDENTITIES);
    }

    #[test]
    fn explicit_rate_limit_overrides_default() {
        let cfg = CodecIngressConfig {
            max_pps: Some(50),
            ..Default::default()
        };
        assert_eq!(cfg.effective_max_pps(), 50);
    }

    #[test]
    fn size_cap_clamped_to_udp_and_frame_max() {
        let cfg = CodecIngressConfig {
            max_datagram_size: usize::MAX,
            ..Default::default()
        };
        let cap = cfg.effective_size_cap();
        assert!(cap <= MAX_UDP_DATAGRAM);
        assert!(cap <= MAX_FRAME_SIZE);
    }

    #[test]
    fn default_config_has_no_multicast_join() {
        // Multicast is opt-in: the default config does a plain unicast bind
        // so existing DIS/ASTERIX/VMF deployments are unaffected.
        let cfg = CodecIngressConfig::default();
        assert!(cfg.multicast_group.is_none());
        assert_eq!(cfg.multicast_interface, Ipv4Addr::UNSPECIFIED);
    }

    #[tokio::test]
    async fn bind_socket_unicast_when_no_group() {
        // No multicast group ⇒ plain unicast bind on an ephemeral port.
        let cfg = CodecIngressConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = cfg.bind_socket(addr).await.expect("unicast bind");
        assert!(socket.local_addr().is_ok());
    }

    #[tokio::test]
    async fn bind_socket_rejects_non_multicast_group() {
        // A non-multicast address configured as the group is a fail-closed
        // bind error, not a silent unicast fallback.
        let cfg = CodecIngressConfig {
            multicast_group: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let err = cfg
            .bind_socket(addr)
            .await
            .expect_err("must reject unicast group");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn bind_socket_rejects_reserved_control_block() {
        // SEC-12: 224.0.0.1 (all-hosts) IS a valid multicast address but sits
        // in the reserved link-local control block 224.0.0.0/24 — rejected
        // fail-closed so the ingress cannot subscribe to control-plane chatter.
        let cfg = CodecIngressConfig {
            multicast_group: Some(Ipv4Addr::new(224, 0, 0, 1)),
            ..Default::default()
        };
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let err = cfg
            .bind_socket(addr)
            .await
            .expect_err("must reject reserved control-block group");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("224.0.0.0/24"));
    }
}
