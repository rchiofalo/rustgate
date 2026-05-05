// Copyright © 2026 Roberto Chiofalo.

//! Native IPv4 UDP multicast CoT input + optional rebroadcast egress.
//!
//! ATAK devices on tactical mesh radio networks (MPU5, Silvus) use IPv4
//! multicast (typically `239.2.3.1:6969` for SA, `239.2.3.1:17012` for
//! chat) for peer-to-peer Situational Awareness sharing. This module
//! lets `rustgate` participate in that fabric:
//!
//! 1. Bind a `tokio::net::UdpSocket` per configured `host:port` group.
//! 2. Call `join_multicast_v4(group, interface)` so the kernel forwards
//!    inbound multicast datagrams to the bound socket.
//! 3. For each received datagram, build a [`RoutableMessage`] tagged
//!    with `source_protocol = "udp-multicast"` and route it through the
//!    standard router. Existing forwarder echo guards already filter
//!    out messages they would have re-emitted (see the
//!    `SOURCE_FEDERATION` short-circuit in
//!    [`rustgate_core::message`] for the equivalent pattern).
//! 4. Optionally — gated by [`MulticastConfig::rebroadcast`] — the
//!    server installs an `OnMulticastForward` callback on the router so
//!    every routed CoT message is re-emitted out the multicast egress
//!    socket. A token bucket caps outbound bytes-per-second to avoid
//!    saturating the radio link.
//!
//! ## IPv4 only
//!
//! `join_multicast_v6` and source-specific multicast (SSM) are out of
//! scope for v1 — see #861 "Out of scope". A future PR can add the v6
//! path symmetrically.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use rustgate_core::audit;
use rustgate_core::constants::PLAINTEXT_GROUP;
use rustgate_core::identity::Identity;
use rustgate_core::message::RoutableMessage;
use rustgate_cot::MessageBuilder;
use rustgate_resilience::token_bucket::TokenBucket;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};

use crate::router::{Router, SessionHandle};

/// Source-protocol tag for messages received via UDP multicast.
///
/// Existing forwarders already key off `source_protocol` for echo
/// suppression — tagging multicast-ingress messages with the dedicated
/// `"udp-multicast"` value lets a single SIEM or audit rule
/// distinguish multicast traffic from unicast UDP without re-parsing
/// the payload.
pub const SOURCE_UDP_MULTICAST: &str = "udp-multicast";

/// Maximum UDP datagram size (theoretical IPv4 limit). CoT messages on
/// ATAK fit well under this, but we accept any datagram up to the
/// kernel's per-socket cap.
const MAX_DATAGRAM_SIZE: usize = 65_535;

/// Default IP_MULTICAST_TTL for outbound rebroadcast.
///
/// `1` keeps the datagram inside the local subnet — the safe default
/// for tactical mesh radio deployments where cross-subnet flooding is
/// almost always a misconfiguration. Operators with a routed multicast
/// fabric can override with `--udp-multicast-ttl`.
pub const DEFAULT_MULTICAST_TTL: u32 = 1;

/// Default outbound rebroadcast bytes-per-second cap.
///
/// 1 MiB/s is a sensible default for the tactical-radio links we
/// target: it leaves headroom on a typical Silvus 4-band link and
/// avoids saturating an MPU5 mesh under burst conditions.
pub const DEFAULT_MAX_BPS: u64 = 1_048_576;

/// Single multicast group / port to join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastGroup {
    /// IPv4 multicast address (must be in `224.0.0.0/4`).
    pub addr: Ipv4Addr,
    /// UDP port the senders are using on this group.
    pub port: u16,
}

impl MulticastGroup {
    /// Parse a `host:port` form (e.g. `"239.2.3.1:6969"`) into a
    /// validated multicast group. Returns an error if the address
    /// isn't a multicast-class IPv4 address (`224.0.0.0/4`).
    pub fn parse(s: &str) -> Result<Self, String> {
        let socket_addr: SocketAddr = s
            .parse()
            .map_err(|e| format!("invalid socket address '{s}': {e}"))?;
        let v4 = match socket_addr {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => {
                // IPv6 multicast (`ff00::/8`) is out of scope for v1
                // — see the module docs.
                return Err(format!("'{s}' is IPv6; only IPv4 multicast is supported"));
            }
        };
        let addr = *v4.ip();
        if !addr.is_multicast() {
            return Err(format!("'{addr}' is not in 224.0.0.0/4 (not multicast)"));
        }
        Ok(Self {
            addr,
            port: v4.port(),
        })
    }

    /// Render the group back to `host:port` form for log/audit.
    pub fn to_socket_string(&self) -> String {
        format!("{}:{}", self.addr, self.port)
    }
}

impl FromStr for MulticastGroup {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Configuration for the UDP multicast subsystem.
///
/// An empty [`Self::groups`] disables multicast entirely. The optional
/// `rebroadcast` flag enables the egress path; when off (the default),
/// only ingress runs.
#[derive(Debug, Clone)]
pub struct MulticastConfig {
    /// Multicast groups (with port) to join for ingress. An empty
    /// slice disables multicast entirely.
    pub groups: Vec<MulticastGroup>,
    /// Interface IPv4 address to bind for `join_multicast_v4` and the
    /// outbound socket's `IP_MULTICAST_IF`. `0.0.0.0` (the default)
    /// asks the kernel to pick the default routed interface.
    pub interface: Ipv4Addr,
    /// `IP_MULTICAST_LOOP`. Default `false` — tactical deployments
    /// don't want their own datagrams looped back.
    pub multicast_loop: bool,
    /// `IP_MULTICAST_TTL`. Default [`DEFAULT_MULTICAST_TTL`] — same
    /// subnet only.
    pub ttl: u32,
    /// Default CN for synthetic identities used by the multicast
    /// listener. Mirrors [`crate::UdpInputConfig::cn`].
    pub cn: String,
    /// Default group for synthetic identities. Mirrors
    /// [`crate::UdpInputConfig::default_group`].
    pub default_group: String,
    /// When `true`, the router fans every routed CoT message back out
    /// to every configured multicast group. Off by default.
    pub rebroadcast: bool,
    /// Outbound rebroadcast cap in bytes-per-second. Implemented as a
    /// 1-second-burst token bucket so a configuration of 1_048_576
    /// allows a 1 MiB burst followed by sustained 1 MiB/s.
    pub max_bps: u64,
}

impl Default for MulticastConfig {
    fn default() -> Self {
        Self {
            groups: Vec::new(),
            interface: Ipv4Addr::UNSPECIFIED,
            multicast_loop: false,
            ttl: DEFAULT_MULTICAST_TTL,
            cn: "udp-multicast-anonymous".to_string(),
            default_group: PLAINTEXT_GROUP.to_string(),
            rebroadcast: false,
            max_bps: DEFAULT_MAX_BPS,
        }
    }
}

impl MulticastConfig {
    /// Returns `true` when at least one multicast group is configured.
    pub fn enabled(&self) -> bool {
        !self.groups.is_empty()
    }
}

/// Callback invoked by the router (or any post-routing site) once per
/// routed [`RoutableMessage`] for which the operator has opted in to
/// multicast rebroadcast. The callback is responsible for token-bucket
/// gating, datagram splitting, and any per-group fan-out — the call
/// site only knows it routed a message and that the operator wants it
/// re-emitted.
///
/// Uses `Fn` (not `AsyncFn`) because `dyn AsyncFn` is not object-safe
/// as of Rust 1.93. Async work is dispatched via `spawn_background()`
/// inside the closure body.
pub type OnMulticastForward = Arc<dyn Fn(Arc<RoutableMessage>) + Send + Sync>;

// ---------------------------------------------------------------------------
// Inbound listener
// ---------------------------------------------------------------------------

/// Bind a UDP socket to `0.0.0.0:port`, set `SO_REUSEADDR`, then call
/// `join_multicast_v4(group, interface)`.
///
/// The `SO_REUSEADDR` flag lets multiple processes (e.g. ATAK + the
/// router on the same host during test) bind the same multicast port.
/// On Linux the equivalent `SO_REUSEPORT` would be stricter; we stay on
/// `SO_REUSEADDR` for portability.
///
/// Returns the bound socket on success; the caller is responsible for
/// applying additional options (`set_multicast_loop_v4`,
/// `set_multicast_ttl_v4`) before entering the receive loop.
fn bind_multicast_socket(
    group: &MulticastGroup,
    interface: Ipv4Addr,
) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = Domain::IPV4;
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    // Bind to `0.0.0.0:port`. Binding to the multicast address itself
    // is portable on Linux but rejected on Windows; binding to the
    // wildcard works everywhere and is what tokio examples use.
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, group.port);
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = UdpSocket::from_std(std_socket)?;
    tokio_socket.join_multicast_v4(group.addr, interface)?;
    Ok(tokio_socket)
}

/// Run the receive loop for one multicast group socket.
///
/// Each datagram is parsed as CoT XML, tagged with `source_protocol =
/// "udp-multicast"`, and routed through the shared router. Errors and
/// invalid datagrams are logged and dropped — this matches the existing
/// unicast UDP listener behaviour.
async fn run_one_group(
    socket: UdpSocket,
    router: Arc<Router>,
    config: MulticastConfig,
    shutdown: Arc<Notify>,
) {
    // Each group registers a session handle with the router so its
    // synthetic identity can participate in group membership lookups.
    // The handle's mpsc channels are intentionally tiny — the
    // multicast listener never receives outbound messages itself; the
    // rebroadcast egress is wired through `OnMulticastForward`.
    let mut groups = std::collections::BTreeSet::new();
    let _ = groups.insert(config.default_group.clone());
    let identity = match Identity::plaintext(config.cn.clone(), groups) {
        Ok(id) => Arc::new(id),
        Err(e) => {
            tracing::error!(error = %e, "invalid UDP multicast identity configuration");
            return;
        }
    };
    let (ptx, _prx) = mpsc::channel::<crate::RoutedMessage>(1);
    let (ntx, _nrx) = mpsc::channel::<crate::RoutedMessage>(1);
    let handle = SessionHandle::new(Arc::clone(&identity), ptx, ntx);
    let session_id = handle.id;
    let _ = router.register(handle).await;

    let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
    let mut msg_builder = MessageBuilder::new();

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, peer_addr)) => {
                        if len == 0 {
                            continue;
                        }
                        let payload = Bytes::copy_from_slice(&buf[..len]);
                        tracing::debug!(
                            peer = %peer_addr,
                            bytes = len,
                            "UDP multicast datagram received"
                        );

                        // Per-datagram identity carries the source
                        // address for traceability — same shape as the
                        // unicast UDP listener.
                        let dgram_cn = format!("{}-{}", config.cn, peer_addr);
                        let mut dgram_groups = std::collections::BTreeSet::new();
                        let _ = dgram_groups.insert(config.default_group.clone());
                        let dgram_identity = match Identity::plaintext(dgram_cn, dgram_groups) {
                            Ok(id) => id,
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    peer = %peer_addr,
                                    "invalid multicast datagram identity"
                                );
                                continue;
                            }
                        };

                        let msg = msg_builder.build(&dgram_identity, payload, SOURCE_UDP_MULTICAST);
                        // The post-Send-PEP form (returned by
                        // `route_for_egress`) is currently unused on
                        // the multicast inbound path — the rebroadcast
                        // egress reads its messages off the
                        // `OnMulticastForward` callback that fires
                        // from every router routing decision, not
                        // only from this one ingress.
                        let _ = router.route_for_egress(msg).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "UDP multicast recv error");
                    }
                }
            }
            _ = shutdown.notified() => {
                tracing::info!("UDP multicast listener shutting down");
                break;
            }
        }
    }

    router.unregister(&config.cn, session_id).await;
}

/// Spawn one inbound listener task per configured group.
///
/// Each group runs its own `tokio::spawn`'d receive loop. The single
/// `shutdown` `Notify` is shared so a single notification stops every
/// task. Returns the join handles so the caller can await them at
/// drain time.
///
/// This function is `pub` so the server crate can call it from
/// `start_udp_multicast`.
pub fn spawn_inbound(
    config: MulticastConfig,
    router: Arc<Router>,
    shutdown: Arc<Notify>,
) -> std::io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let mut handles = Vec::with_capacity(config.groups.len());
    let interface_str = if config.interface.is_unspecified() {
        "0.0.0.0".to_string()
    } else {
        config.interface.to_string()
    };
    for group in &config.groups {
        let socket = match bind_multicast_socket(group, config.interface) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    group = %group.to_socket_string(),
                    error = %e,
                    "UDP multicast bind/join failed",
                );
                return Err(e);
            }
        };
        // Apply the requested IP_MULTICAST_LOOP / TTL options. Errors
        // here are logged but non-fatal — the join already succeeded.
        if let Err(e) = socket.set_multicast_loop_v4(config.multicast_loop) {
            tracing::warn!(
                group = %group.to_socket_string(),
                error = %e,
                "set_multicast_loop_v4 failed",
            );
        }
        if let Err(e) = socket.set_multicast_ttl_v4(config.ttl) {
            tracing::warn!(
                group = %group.to_socket_string(),
                error = %e,
                "set_multicast_ttl_v4 failed",
            );
        }

        // Audit: one event per successful join.
        audit::udp_multicast_joined(&group.to_socket_string(), &interface_str);
        tracing::info!(
            group = %group.to_socket_string(),
            interface = %interface_str,
            "UDP multicast group joined"
        );

        let group_router = Arc::clone(&router);
        let group_config = config.clone();
        let group_shutdown = Arc::clone(&shutdown);
        let handle = tokio::spawn(async move {
            run_one_group(socket, group_router, group_config, group_shutdown).await;
        });
        handles.push(handle);
    }
    Ok(handles)
}

// ---------------------------------------------------------------------------
// Outbound rebroadcast
// ---------------------------------------------------------------------------

/// Worker payload sent from the [`OnMulticastForward`] callback to the
/// background egress task. A bounded mpsc decouples the routing hot
/// path from the actual `send_to` syscalls, mirroring the federation
/// and HTTP egress patterns.
#[derive(Debug)]
struct EgressItem {
    payload: Bytes,
    msg_uid: String,
}

/// Detect whether `payload` is plausibly CoT XML.
///
/// The check is intentionally cheap: skip leading whitespace, then
/// require the next non-space byte to be `<`. CoT events start with
/// `<event …>` (or rarely `<?xml … ?>`); MAVLink frames start with
/// `0xfd` / `0xfe`; protobuf frames carry a length prefix or a
/// non-ASCII tag byte. The boundary is "is it XML-shaped" rather than
/// "is it valid CoT" — the latter is what `MessageBuilder::build`
/// verifies on the inbound side.
fn looks_like_cot_xml(payload: &[u8]) -> bool {
    payload.iter().find(|&&b| !b.is_ascii_whitespace()) == Some(&b'<')
}

/// Best-effort extraction of `uid="…"` from CoT XML for audit.
///
/// Returns the empty string when no `uid="…"` is present or when the
/// scan would exceed `MAX_SCAN`. The bounded scan keeps the audit
/// emission cheap on hot paths.
fn extract_uid(payload: &[u8]) -> String {
    const MAX_SCAN: usize = 4096;
    let needle = b"uid=\"";
    let scan = &payload[..payload.len().min(MAX_SCAN)];
    let Some(start) = scan.windows(needle.len()).position(|w| w == needle) else {
        return String::new();
    };
    let value_start = start + needle.len();
    let Some(rel_end) = scan[value_start..].iter().position(|&b| b == b'"') else {
        return String::new();
    };
    let value = &scan[value_start..value_start + rel_end];
    String::from_utf8_lossy(value).into_owned()
}

/// Spawn the outbound rebroadcast egress task.
///
/// Returns a tuple `(callback, join_handle)`:
///   * `callback`: install on the router via
///     [`crate::router::Router::set_on_multicast_forward`]. Each call
///     enqueues the message into a bounded mpsc channel.
///   * `join_handle`: the background egress task that drains the
///     channel and writes datagrams to the multicast socket. Held by
///     the server's subsystem manager so it can await graceful drain.
///
/// The egress socket is bound once and shared across all configured
/// groups. The `IP_MULTICAST_TTL` and `IP_MULTICAST_LOOP` socket
/// options take effect for every send.
pub async fn spawn_egress(
    config: MulticastConfig,
    shutdown: Arc<Notify>,
) -> std::io::Result<(OnMulticastForward, tokio::task::JoinHandle<()>)> {
    // Bind an ephemeral source port for the egress socket.
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
    if let Err(e) = socket.set_multicast_loop_v4(config.multicast_loop) {
        tracing::warn!(error = %e, "egress set_multicast_loop_v4 failed");
    }
    if let Err(e) = socket.set_multicast_ttl_v4(config.ttl) {
        tracing::warn!(error = %e, "egress set_multicast_ttl_v4 failed");
    }
    if !config.interface.is_unspecified() {
        // tokio's `UdpSocket` doesn't expose `set_multicast_if_v4`, so
        // borrow the raw FD via socket2's `SockRef`. The borrowed
        // view does not own the FD — dropping `s2` is a no-op for the
        // underlying tokio socket.
        let s2 = socket2::SockRef::from(&socket);
        if let Err(e) = s2.set_multicast_if_v4(&config.interface) {
            tracing::warn!(
                interface = %config.interface,
                error = %e,
                "egress set_multicast_if_v4 failed",
            );
        }
    }

    // Channel between the routing hot path and the egress writer. A
    // bounded depth caps queueing under burst load — when full, the
    // forward callback drops the message and emits a debug log.
    let (tx, mut rx) = mpsc::channel::<EgressItem>(1024);

    // Token bucket caps outbound bytes-per-second. We measure cost by
    // datagram size (1 token = 1 byte) so a 100 KiB burst with a
    // 1 MiB/s cap leaves ~944 KiB of headroom.
    let max_bps_f = config.max_bps as f64;
    let bucket = Arc::new(TokenBucket::new(max_bps_f, Some(max_bps_f)));

    let groups = config.groups.clone();
    let bucket_for_task = Arc::clone(&bucket);
    let shutdown_clone = Arc::clone(&shutdown);
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(item) = rx.recv() => {
                    let bytes = item.payload.len();
                    // Each acquired "token" counts one byte.
                    let mut allowed = true;
                    for _ in 0..bytes {
                        if !bucket_for_task.try_acquire() {
                            allowed = false;
                            break;
                        }
                    }
                    if !allowed {
                        tracing::debug!(
                            bytes = bytes,
                            "UDP multicast rebroadcast dropped: rate limit exceeded"
                        );
                        continue;
                    }
                    for group in &groups {
                        let dst = SocketAddrV4::new(group.addr, group.port);
                        if let Err(e) = socket.send_to(&item.payload, dst).await {
                            tracing::warn!(
                                group = %group.to_socket_string(),
                                error = %e,
                                "UDP multicast send_to failed"
                            );
                            continue;
                        }
                        audit::udp_multicast_publish(
                            &group.to_socket_string(),
                            &item.msg_uid,
                        );
                    }
                }
                _ = shutdown_clone.notified() => {
                    tracing::info!("UDP multicast egress shutting down");
                    break;
                }
                else => {
                    // Channel closed and shutdown not signalled —
                    // unusual but exit cleanly.
                    break;
                }
            }
        }
    });

    let cb: OnMulticastForward = Arc::new(move |msg: Arc<RoutableMessage>| {
        // Only re-broadcast CoT-shaped payloads. Multicast is
        // primarily a CoT/SA fabric — pushing protobuf or MAVLink onto
        // it would confuse ATAK clients on the radio link. Don't echo
        // a message that arrived from multicast (we already saw it
        // and the kernel may even loop it back if `multicast_loop` is
        // true).
        if msg.metadata.source_protocol == SOURCE_UDP_MULTICAST {
            return;
        }
        if !looks_like_cot_xml(&msg.payload) {
            return;
        }
        let item = EgressItem {
            payload: msg.payload.clone(),
            msg_uid: extract_uid(&msg.payload),
        };
        // Best-effort enqueue. A full channel means the egress writer
        // is back-pressured; dropping is the right behaviour for a
        // rate-capped, lossy transport.
        if let Err(e) = tx.try_send(item) {
            tracing::debug!(error = ?e, "UDP multicast rebroadcast queue full or closed");
        }
    });

    Ok((cb, handle))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_v4_multicast() {
        let g = MulticastGroup::parse("239.2.3.1:6969").unwrap();
        assert_eq!(g.addr, Ipv4Addr::new(239, 2, 3, 1));
        assert_eq!(g.port, 6969);
        assert_eq!(g.to_socket_string(), "239.2.3.1:6969");
    }

    #[test]
    fn parse_rejects_unicast_address() {
        let err = MulticastGroup::parse("10.0.0.1:6969").expect_err("must reject unicast");
        assert!(err.contains("not multicast"), "unexpected: {err}");
    }

    #[test]
    fn parse_rejects_ipv6() {
        let err = MulticastGroup::parse("[ff02::1]:6969").expect_err("must reject v6");
        assert!(err.contains("IPv6"), "unexpected: {err}");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(MulticastGroup::parse("not-an-addr").is_err());
        assert!(MulticastGroup::parse("239.2.3.1").is_err());
        assert!(MulticastGroup::parse("239.2.3.1:not-a-port").is_err());
    }

    #[test]
    fn from_str_round_trip() {
        let g: MulticastGroup = "224.0.0.251:5353".parse().unwrap();
        assert_eq!(g.addr, Ipv4Addr::new(224, 0, 0, 251));
        assert_eq!(g.port, 5353);
    }

    #[test]
    fn default_config_disables_multicast() {
        let cfg = MulticastConfig::default();
        assert!(cfg.groups.is_empty());
        assert!(!cfg.enabled());
        assert!(!cfg.rebroadcast);
        assert!(!cfg.multicast_loop);
        assert_eq!(cfg.ttl, DEFAULT_MULTICAST_TTL);
        assert_eq!(cfg.max_bps, DEFAULT_MAX_BPS);
    }

    #[test]
    fn enabled_when_groups_present() {
        let cfg = MulticastConfig {
            groups: vec!["239.2.3.1:6969".parse().unwrap()],
            ..Default::default()
        };
        assert!(cfg.enabled());
    }

    #[test]
    fn looks_like_cot_xml_accepts_event_tag() {
        assert!(looks_like_cot_xml(b"<event uid=\"x\"/>"));
        assert!(looks_like_cot_xml(b"  \n<event/>"));
        assert!(looks_like_cot_xml(b"\t<?xml version=\"1.0\"?>"));
    }

    #[test]
    fn looks_like_cot_xml_rejects_binary() {
        assert!(!looks_like_cot_xml(&[0xfd, 0x00, 0x01]));
        assert!(!looks_like_cot_xml(&[0xfe]));
        assert!(!looks_like_cot_xml(b"raw text"));
    }

    #[test]
    fn extract_uid_returns_value_when_present() {
        let xml = br#"<event version="2.0" uid="ANDROID-1" type="a-f-G"/>"#;
        assert_eq!(extract_uid(xml), "ANDROID-1");
    }

    #[test]
    fn extract_uid_returns_empty_when_missing() {
        assert_eq!(extract_uid(b"<event type=\"a-f-G\"/>"), "");
    }

    #[test]
    fn extract_uid_caps_scan_at_max() {
        // A uid past the 4096-byte scan window must not be returned —
        // the bounded scan is the whole point of the helper.
        let mut padding = vec![b' '; 5000];
        padding.extend_from_slice(br#"uid="LATE""#);
        assert_eq!(extract_uid(&padding), "");
    }
}
