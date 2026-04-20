// Copyright © 2026 Roberto Chiofalo.

//! DNS-SD / mDNS peer discovery backend.
//!
//! Uses the pure-Rust `mdns-sd` crate to browse a configured service type
//! (default `_rustgate._tcp.local.`) on the local link. Each resolved
//! responder becomes a single [`PeerConfig`] whose `id` is derived from the
//! service fullname and whose `address` is the first IPv4 address + port
//! advertised in the SRV / A records.
//!
//! # Why a short cache window
//!
//! `mdns-sd` runs its own background thread and delivers events through a
//! `flume` channel. Every time [`DnsSdDiscovery::discover`] is called, we
//! drain whatever has already arrived on that channel, merge it into an
//! instance map, and return the current snapshot. Because mDNS responders
//! announce themselves periodically (and we browse continuously between
//! ticks), the snapshot converges quickly without needing a synchronous
//! "wait for responses" phase.
//!
//! Services that stop responding are eventually pruned when their
//! `ServiceRemoved` event arrives, so a peer that goes offline drops out of
//! the discovered set without operator intervention.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use mdns_sd::{Receiver as MdnsReceiver, ResolvedService, ServiceDaemon, ServiceEvent};
use tracing::{debug, warn};

use super::PeerDiscovery;
use crate::config::{PeerConfig, RoutingMode};

/// Default peer-discovery routing configuration applied to every peer
/// returned by this backend. Operators that need non-default groups or
/// non-outbound peers should continue to use `--federation-peers-file`.
const DEFAULT_GROUPS: &[&str] = &["__ANON__"];

/// DNS-SD / mDNS peer discovery source.
///
/// Spawns a `ServiceDaemon` on construction and begins browsing for the
/// configured service type. On every [`PeerDiscovery::discover`] call, the
/// backend drains any new events from the daemon's channel and returns the
/// current instance map as a `Vec<PeerConfig>`.
pub struct DnsSdDiscovery {
    service_type: String,
    daemon: ServiceDaemon,
    receiver: MdnsReceiver<ServiceEvent>,
    /// Map of service fullname to last-known `PeerConfig`. Mutated under a
    /// `std::sync::Mutex` because `discover` is called from async context but
    /// only holds the lock for non-awaiting drains.
    instances: Mutex<HashMap<String, PeerConfig>>,
}

impl std::fmt::Debug for DnsSdDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsSdDiscovery")
            .field("service_type", &self.service_type)
            .finish_non_exhaustive()
    }
}

impl DnsSdDiscovery {
    /// Construct a new DNS-SD discovery backend.
    ///
    /// Starts a background `ServiceDaemon` thread, begins browsing for
    /// `service_type`, and returns an error if either step fails. The
    /// daemon continues running until this struct is dropped.
    pub fn new(service_type: impl Into<String>) -> anyhow::Result<Self> {
        let service_type = service_type.into();
        let daemon = ServiceDaemon::new()
            .map_err(|e| anyhow::anyhow!("failed to start mdns-sd service daemon: {e}"))?;
        let receiver = daemon
            .browse(&service_type)
            .map_err(|e| anyhow::anyhow!("failed to browse {service_type} via mdns-sd: {e}"))?;
        Ok(Self {
            service_type,
            daemon,
            receiver,
            instances: Mutex::new(HashMap::new()),
        })
    }

    /// Convert a resolved mDNS service into a [`PeerConfig`].
    ///
    /// Picks the first IPv4 address (IPv6 is used only as a fallback) and
    /// constructs the address as `ip:port`. The peer id is derived from the
    /// service fullname (e.g. `my-host._rustgate._tcp.local.`) by stripping
    /// the trailing service-type domain, which gives operators a stable
    /// human-readable identifier that survives restarts.
    ///
    /// Kept as an associated function (takes `service_type: &str` rather
    /// than `&self`) so unit tests can exercise the conversion logic
    /// without starting a `ServiceDaemon` — matches the pattern used by
    /// `ConsulDiscovery::entry_to_peer` in the sibling backend.
    fn resolved_to_peer(service_type: &str, resolved: &ResolvedService) -> Option<PeerConfig> {
        let addr = resolved
            .addresses
            .iter()
            .find(|ip| ip.is_ipv4())
            .or_else(|| resolved.addresses.iter().next())?
            .to_ip_addr();
        let address = match addr {
            IpAddr::V4(v4) => format!("{v4}:{}", resolved.port),
            IpAddr::V6(v6) => format!("[{v6}]:{}", resolved.port),
        };
        let id = resolved
            .fullname
            .strip_suffix(&format!(".{service_type}"))
            .unwrap_or(&resolved.fullname)
            .to_string();

        Some(PeerConfig {
            id: id.into(),
            address,
            groups: DEFAULT_GROUPS.iter().map(|s| (*s).into()).collect(),
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        })
    }

    /// Drain any pending events from the daemon channel and update the
    /// in-memory instance map. Non-blocking: returns as soon as the channel
    /// is empty. This is the reason we can keep the `discover` method itself
    /// async without awaiting on any channel operation.
    fn drain_events(&self) {
        let Ok(mut instances) = self.instances.lock() else {
            warn!("dns-sd discovery instance map lock poisoned; skipping drain");
            return;
        };
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                ServiceEvent::ServiceResolved(resolved) => {
                    if let Some(peer) = Self::resolved_to_peer(&self.service_type, &resolved) {
                        debug!(
                            fullname = %resolved.fullname,
                            address = %peer.address,
                            "dns-sd resolved federation peer"
                        );
                        let _ = instances.insert(resolved.fullname.clone(), peer);
                    }
                }
                ServiceEvent::ServiceRemoved(_ty, fullname) => {
                    debug!(fullname = %fullname, "dns-sd removed federation peer");
                    let _ = instances.remove(&fullname);
                }
                other => {
                    debug!(event = ?other, "dns-sd non-resolved event ignored");
                }
            }
        }
    }
}

impl Drop for DnsSdDiscovery {
    fn drop(&mut self) {
        // Best-effort shutdown: if the daemon thread is already gone, this
        // simply errors out and is logged.
        if let Err(e) = self.daemon.shutdown() {
            warn!(error = %e, "failed to shutdown mdns-sd daemon on drop");
        }
    }
}

#[async_trait]
impl PeerDiscovery for DnsSdDiscovery {
    async fn discover(&self) -> anyhow::Result<Vec<PeerConfig>> {
        self.drain_events();
        let instances = self
            .instances
            .lock()
            .map_err(|_| anyhow::anyhow!("dns-sd discovery instance map lock poisoned"))?;
        Ok(instances.values().cloned().collect())
    }

    fn backend_name(&self) -> &'static str {
        "dns-sd"
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    //! Unit tests for [`DnsSdDiscovery::resolved_to_peer`] and the
    //! trait-level contract of the backend.
    //!
    //! The converter takes no `&self`, so the tests can exercise the
    //! interesting branches (IPv4-preference, IPv6 bracketing, fullname
    //! stripping) without starting a `ServiceDaemon`. Tests that need a
    //! live daemon are in `crates/rustgate-federation/tests/discovery.rs`
    //! and self-skip on CI runners where mDNS is blocked.
    use std::collections::HashMap;

    use mdns_sd::ServiceInfo;

    use super::*;

    /// Build a [`ResolvedService`] fixture by round-tripping a
    /// [`ServiceInfo`] — the only public path to construct the
    /// `#[non_exhaustive]` `ResolvedService` struct.
    fn make_resolved(
        service_type: &str,
        instance: &str,
        host: &str,
        ip: &str,
        port: u16,
    ) -> ResolvedService {
        ServiceInfo::new(
            service_type,
            instance,
            host,
            ip,
            port,
            HashMap::<String, String>::new(),
        )
        .expect("ServiceInfo::new should succeed for test fixtures")
        .as_resolved_service()
    }

    #[test]
    fn resolved_to_peer_builds_ipv4_address() {
        let resolved = make_resolved(
            "_rustgate._tcp.local.",
            "alpha",
            "alpha.local.",
            "10.0.0.1",
            9001,
        );
        let peer = DnsSdDiscovery::resolved_to_peer("_rustgate._tcp.local.", &resolved)
            .expect("IPv4 address should yield a PeerConfig");
        assert_eq!(peer.address, "10.0.0.1:9001");
    }

    #[test]
    fn resolved_to_peer_strips_service_type_suffix_from_id() {
        let resolved = make_resolved(
            "_rustgate._tcp.local.",
            "alpha",
            "alpha.local.",
            "10.0.0.1",
            9001,
        );
        let peer =
            DnsSdDiscovery::resolved_to_peer("_rustgate._tcp.local.", &resolved).expect("peer");
        // fullname is "alpha._rustgate._tcp.local." — stripping
        // ".{_rustgate._tcp.local.}" leaves just "alpha".
        assert_eq!(peer.id.as_str(), "alpha");
    }

    #[test]
    fn resolved_to_peer_falls_back_to_fullname_when_suffix_does_not_match() {
        // Build with one service_type, convert with a different one so
        // the strip_suffix fails — id should then be the full name.
        let resolved = make_resolved(
            "_rustgate._tcp.local.",
            "alpha",
            "alpha.local.",
            "10.0.0.1",
            9001,
        );
        let peer = DnsSdDiscovery::resolved_to_peer("_other._tcp.local.", &resolved).expect("peer");
        assert_eq!(peer.id.as_str(), "alpha._rustgate._tcp.local.");
    }

    #[test]
    fn resolved_to_peer_brackets_ipv6_address() {
        let resolved = make_resolved(
            "_rustgate._tcp.local.",
            "bravo",
            "bravo.local.",
            "fe80::1",
            9002,
        );
        let peer =
            DnsSdDiscovery::resolved_to_peer("_rustgate._tcp.local.", &resolved).expect("peer");
        assert_eq!(peer.address, "[fe80::1]:9002");
    }

    #[test]
    fn resolved_to_peer_prefers_ipv4_when_both_present() {
        let resolved = make_resolved(
            "_rustgate._tcp.local.",
            "charlie",
            "charlie.local.",
            "10.0.0.5,fe80::2",
            9003,
        );
        let peer =
            DnsSdDiscovery::resolved_to_peer("_rustgate._tcp.local.", &resolved).expect("peer");
        // With both address families present, the IPv4 entry wins.
        assert_eq!(peer.address, "10.0.0.5:9003");
    }

    #[test]
    fn resolved_to_peer_applies_default_peer_config() {
        let resolved = make_resolved(
            "_rustgate._tcp.local.",
            "delta",
            "delta.local.",
            "10.0.0.1",
            9001,
        );
        let peer =
            DnsSdDiscovery::resolved_to_peer("_rustgate._tcp.local.", &resolved).expect("peer");

        // Defaults that the DNS-SD backend applies to every resolved
        // peer. If these change, the operator-visible semantics change,
        // so pin them explicitly.
        assert!(peer.enabled);
        assert!(peer.is_outbound);
        assert_eq!(peer.protocol_version, 2);
        assert_eq!(peer.priority, 100);
        assert!(peer.inbound_groups.is_none());
        assert!(peer.outbound_groups.is_none());
        assert!(peer.trust_cert_cn.is_none());
        assert!(peer.jwt_token.is_none());
        assert!(peer.region.is_none());
        assert!(peer.zone.is_none());
        assert_eq!(peer.routing_mode, RoutingMode::default());
        assert_eq!(peer.groups, vec!["__ANON__".to_string()]);
    }

    #[test]
    fn default_groups_constant_is_anon_singleton() {
        // The ACL side of rustgate treats `__ANON__` as a sentinel for
        // peers whose group assignment is delegated to runtime config.
        // Pin both the value and the arity so a silent change is caught.
        assert_eq!(DEFAULT_GROUPS, &["__ANON__"]);
    }

    // ── Live-daemon tests (self-skip on CI without multicast) ──────

    /// Actually start a [`ServiceDaemon`] and confirm the trait-level
    /// constants. Skipped on runners where the daemon cannot be
    /// constructed (no loopback multicast, netfilter rules, container
    /// networking).
    #[test]
    fn backend_name_and_debug_when_daemon_available() {
        let Ok(discovery) = DnsSdDiscovery::new("_rustgate-test._tcp.local.") else {
            eprintln!("skipping: ServiceDaemon could not start");
            return;
        };
        // Pinned by [`crate::discovery::PeerDiscovery::backend_name`] —
        // operators match on this string for metrics labels.
        assert_eq!(discovery.backend_name(), "dns-sd");

        let debug = format!("{discovery:?}");
        assert!(debug.contains("DnsSdDiscovery"));
        // Service type appears verbatim in Debug so support logs can
        // correlate a failed backend with its configured browse target.
        assert!(debug.contains("_rustgate-test._tcp.local."));
    }

    #[tokio::test]
    async fn discover_returns_empty_before_any_service_resolved() {
        let Ok(discovery) = DnsSdDiscovery::new("_rustgate-empty._tcp.local.") else {
            eprintln!("skipping: ServiceDaemon could not start");
            return;
        };
        // Immediately after construction, no peers have been announced
        // so discover() should drain zero events and return an empty
        // vec. This pins that the converter map is initialised empty
        // and that an empty channel does not produce a spurious error.
        let peers = discovery.discover().await.expect("discover");
        assert!(peers.is_empty(), "expected empty peer list, got {peers:?}");
    }
}
