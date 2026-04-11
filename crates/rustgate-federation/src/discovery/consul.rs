//! Consul catalog peer discovery backend.
//!
//! Polls Consul's catalog HTTP API at
//! `GET <address>/v1/catalog/service/<service-name>` and converts the
//! returned node list into a `Vec<PeerConfig>`. This is a deliberately thin
//! wrapper around `reqwest` rather than a heavy `consul-rs` dep — the Consul
//! API is small and stable, and keeping it in-tree lets the backend share
//! the workspace's rustls-only TLS stack (no OpenSSL, no native-tls).
//!
//! Only the **catalog** endpoint is used (no health endpoint, no blocking
//! queries) because the reconciler already ticks on its own interval. A
//! future improvement could opportunistically upgrade to long-polling with
//! `?index=N` to react instantly to catalog changes, but that would
//! complicate error handling and is not required for v1.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use super::PeerDiscovery;
use crate::config::{PeerConfig, RoutingMode};

/// Default HTTP timeout for catalog requests.
///
/// Chosen to be well below the reconciler's default 30 s interval so a slow
/// Consul response cannot starve the discovery loop. Long-polling is not
/// used; every tick is a fresh GET.
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Consul catalog entry for a single service node, as returned by
/// `/v1/catalog/service/<name>`. Only the fields we care about are
/// deserialized; Consul may add more in future versions.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CatalogEntry {
    #[serde(rename = "ServiceID")]
    service_id: String,
    /// Service-level address. May be empty, in which case Consul fills it
    /// in from the agent's advertised node address.
    service_address: Option<String>,
    service_port: u16,
    address: String,
}

/// Consul peer discovery source.
///
/// Holds a `reqwest::Client` configured with rustls and the parameters
/// needed to query a specific service. Operators with multi-service
/// layouts should construct one `ConsulDiscovery` per service and compose
/// them with a future aggregator backend (out of scope for this PR).
pub struct ConsulDiscovery {
    base_url: String,
    service: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for ConsulDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsulDiscovery")
            .field("base_url", &self.base_url)
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

impl ConsulDiscovery {
    /// Construct a new Consul discovery backend.
    ///
    /// `base_url` should be the root of the Consul HTTP API — e.g.
    /// `http://127.0.0.1:8500` — without a trailing slash. `service` is the
    /// Consul service name to query; discovered nodes registered under that
    /// name become federation peers.
    pub fn new(base_url: impl Into<String>, service: impl Into<String>) -> anyhow::Result<Self> {
        let base_url = base_url.into();
        let service = service.into();
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build consul HTTP client: {e}"))?;
        Ok(Self {
            base_url,
            service,
            http,
        })
    }

    /// Build the catalog URL for the configured service. Split out so tests
    /// can assert that the path is correct without making a network call.
    fn catalog_url(&self) -> String {
        let trimmed = self.base_url.trim_end_matches('/');
        format!("{trimmed}/v1/catalog/service/{}", self.service)
    }

    /// Convert one catalog entry into a peer configuration. The peer id is
    /// the Consul `ServiceID` (unique per node), and the address uses
    /// `ServiceAddress` when set, falling back to the node's `Address`.
    fn entry_to_peer(entry: &CatalogEntry) -> PeerConfig {
        // Borrow the chosen host string to avoid allocating; only the final
        // `format!` produces a new String for the peer address.
        let host: &str = match entry.service_address.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => entry.address.as_str(),
        };
        let address = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{}", entry.service_port)
        } else {
            format!("{host}:{}", entry.service_port)
        };
        PeerConfig {
            id: entry.service_id.clone().into(),
            address,
            groups: vec!["__ANON__".into()],
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
        }
    }
}

#[async_trait]
impl PeerDiscovery for ConsulDiscovery {
    async fn discover(&self) -> anyhow::Result<Vec<PeerConfig>> {
        let url = self.catalog_url();
        debug!(url = %url, "querying consul catalog");
        let entries: Vec<CatalogEntry> = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("consul GET {url} failed: {e}"))?
            .error_for_status()
            .map_err(|e| anyhow::anyhow!("consul returned error for {url}: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("failed to parse consul catalog response: {e}"))?;

        Ok(entries.iter().map(Self::entry_to_peer).collect())
    }

    fn backend_name(&self) -> &'static str {
        "consul"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn catalog_url_strips_trailing_slash() {
        let d = ConsulDiscovery::new("http://consul:8500/", "rustgate").unwrap();
        assert_eq!(
            d.catalog_url(),
            "http://consul:8500/v1/catalog/service/rustgate"
        );
    }

    #[test]
    fn entry_to_peer_prefers_service_address() {
        let entry = CatalogEntry {
            service_id: "rustgate-1".into(),
            service_address: Some("10.0.0.5".into()),
            service_port: 9000,
            address: "consul-node.example".into(),
        };
        let peer = ConsulDiscovery::entry_to_peer(&entry);
        assert_eq!(peer.id.as_str(), "rustgate-1");
        assert_eq!(peer.address, "10.0.0.5:9000");
        assert!(peer.is_outbound);
    }

    #[test]
    fn entry_to_peer_falls_back_to_node_address() {
        let entry = CatalogEntry {
            service_id: "rustgate-2".into(),
            service_address: Some(String::new()),
            service_port: 9000,
            address: "consul-node.example".into(),
        };
        let peer = ConsulDiscovery::entry_to_peer(&entry);
        assert_eq!(peer.address, "consul-node.example:9000");
    }

    #[test]
    fn entry_to_peer_brackets_ipv6_hosts() {
        let entry = CatalogEntry {
            service_id: "rustgate-3".into(),
            service_address: Some("fe80::1".into()),
            service_port: 9000,
            address: String::new(),
        };
        let peer = ConsulDiscovery::entry_to_peer(&entry);
        assert_eq!(peer.address, "[fe80::1]:9000");
    }
}
