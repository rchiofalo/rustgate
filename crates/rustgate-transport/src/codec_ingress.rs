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
//!    that does not decode to a valid [`Entity`] is dropped at the edge and
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
use std::net::IpAddr;
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
            "tactical codec ingress active — datagrams are UNAUTHENTICATED and NOT encrypted"
        );
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
}
