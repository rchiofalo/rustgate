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
    fn resolved_to_peer(&self, resolved: &ResolvedService) -> Option<PeerConfig> {
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
            .strip_suffix(&format!(".{}", self.service_type))
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
                    if let Some(peer) = self.resolved_to_peer(&resolved) {
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
