// Copyright © 2026 Roberto Chiofalo.

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
use crate::error::{FederationError, Result};

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
    pub fn new(base_url: impl Into<String>, service: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let service = service.into();
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .build()
            .map_err(|e| {
                FederationError::discovery(format!("failed to build consul HTTP client: {e}"))
            })?;
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
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
        }
    }
}

#[async_trait]
impl PeerDiscovery for ConsulDiscovery {
    async fn discover(&self) -> Result<Vec<PeerConfig>> {
        let url = self.catalog_url();
        debug!(url = %url, "querying consul catalog");
        let entries: Vec<CatalogEntry> = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| FederationError::discovery(format!("consul GET {url} failed: {e}")))?
            .error_for_status()
            .map_err(|e| {
                FederationError::discovery(format!("consul returned error for {url}: {e}"))
            })?
            .json()
            .await
            .map_err(|e| {
                FederationError::discovery(format!("failed to parse consul catalog response: {e}"))
            })?;

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

    #[test]
    fn catalog_url_without_trailing_slash_uses_single_separator() {
        // The doc-comment on `ConsulDiscovery::new` advertises "without
        // a trailing slash" as the canonical form — pin the no-slash
        // branch of `trim_end_matches` so a future refactor that
        // accidentally always appended a slash would produce
        // `http://consul:8500//v1/...` and fail this test.
        let d = ConsulDiscovery::new("http://consul:8500", "rustgate").unwrap();
        assert_eq!(
            d.catalog_url(),
            "http://consul:8500/v1/catalog/service/rustgate"
        );
    }

    #[test]
    fn catalog_entry_deserializes_pascal_case_wire_fields() {
        // `#[serde(rename_all = "PascalCase")]` + `#[serde(rename =
        // "ServiceID")]` are load-bearing — Consul's catalog API emits
        // PascalCase with `ServiceID` (all-caps ID) specifically, and
        // a regression that dropped either attribute would still
        // round-trip internally but fail to parse real Consul JSON.
        // Pin both by deserializing a minimal real-shaped payload.
        let json = r#"{
            "ServiceID": "rustgate-a",
            "ServiceAddress": "10.0.0.9",
            "ServicePort": 9100,
            "Address": "consul-node.example"
        }"#;
        let entry: CatalogEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.service_id, "rustgate-a");
        assert_eq!(entry.service_address.as_deref(), Some("10.0.0.9"));
        assert_eq!(entry.service_port, 9100);
        assert_eq!(entry.address, "consul-node.example");
    }

    #[test]
    fn catalog_entry_service_address_is_optional() {
        // `service_address` is `Option<String>` — Consul omits the
        // field when the service registered without an explicit
        // address. The deserializer must tolerate the missing key
        // (not require an explicit JSON null) or operators using
        // services registered via Connect / sidecar will see every
        // node fail to parse.
        let json = r#"{
            "ServiceID": "rustgate-b",
            "ServicePort": 9100,
            "Address": "consul-node.example"
        }"#;
        let entry: CatalogEntry = serde_json::from_str(json).unwrap();
        assert!(entry.service_address.is_none());
        // entry_to_peer must still succeed via the None -> Address
        // fallback branch.
        let peer = ConsulDiscovery::entry_to_peer(&entry);
        assert_eq!(peer.address, "consul-node.example:9100");
    }

    #[test]
    fn entry_to_peer_applies_documented_defaults() {
        // `entry_to_peer` hardcodes 10 peer-config fields — pin every
        // one of them so a silent flip (e.g. `enabled = false` during
        // a "let's disable peers by default until review" refactor,
        // or a bump of `protocol_version` to 3 that breaks mixed-
        // version fleets) fails a single focused test rather than
        // surfacing as a production federation outage.
        let entry = CatalogEntry {
            service_id: "rustgate-defaults".into(),
            service_address: Some("10.0.0.1".into()),
            service_port: 9000,
            address: "consul-node.example".into(),
        };
        let peer = ConsulDiscovery::entry_to_peer(&entry);

        // Identity + wire shape.
        assert_eq!(peer.id.as_str(), "rustgate-defaults");
        assert_eq!(peer.address, "10.0.0.1:9000");

        // Group plumbing: anon group, no overrides.
        assert_eq!(peer.groups, vec!["__ANON__".to_string()]);
        assert!(peer.inbound_groups.is_none());
        assert!(peer.outbound_groups.is_none());

        // Admission + direction.
        assert!(peer.enabled, "discovered peers ship enabled");
        assert!(peer.is_outbound, "Consul peers are outbound by default");

        // Trust + auth: no static overrides — cert verification uses the
        // federation trust store.
        assert!(peer.trust_cert_cn.is_none());
        assert!(peer.jwt_token.is_none());

        // Routing.
        assert_eq!(peer.routing_mode, RoutingMode::default());
        assert_eq!(peer.protocol_version, 2);

        // Locality + priority — all unset, standard priority.
        assert!(peer.region.is_none());
        assert!(peer.zone.is_none());
        assert_eq!(peer.priority, 100);
    }

    #[test]
    fn entry_to_peer_already_bracketed_ipv6_is_not_double_bracketed() {
        // The `!host.starts_with('[')` guard prevents double-bracketing
        // when the service address is already in literal IPv6 form.
        // Operators registering `[2001:db8::1]` as the service address
        // (the form the Consul HTTP API sometimes returns when the
        // node registered with an explicit `[...]` literal) must not
        // end up with `[[2001:db8::1]]:9000`, which would fail every
        // `SocketAddr::parse` downstream.
        let entry = CatalogEntry {
            service_id: "rustgate-ipv6".into(),
            service_address: Some("[2001:db8::1]".into()),
            service_port: 9000,
            address: String::new(),
        };
        let peer = ConsulDiscovery::entry_to_peer(&entry);
        assert_eq!(peer.address, "[2001:db8::1]:9000");
    }

    #[tokio::test]
    async fn backend_name_is_stable_consul_token() {
        // The reconciler tags log lines with `backend_name()` so
        // operators grep `"consul"` to filter for this backend's
        // lifecycle events. Pin the exact token and the `'static`
        // lifetime (so it lives in rodata, not an allocated String).
        let d = ConsulDiscovery::new("http://consul:8500", "rustgate").unwrap();
        // Delegate through the trait to pin both the inherent and
        // trait paths compile.
        let name: &'static str = (&d as &dyn PeerDiscovery).backend_name();
        assert_eq!(name, "consul");
    }

    #[test]
    fn debug_impl_redacts_http_client_and_renders_key_fields() {
        // `#[derive(Debug)]` on the struct would expand the
        // `reqwest::Client` into a dense render that leaks internal
        // configuration (pool size, connector state) into
        // `tracing::debug!(?backend, …)` output. The manual `Debug`
        // impl lists only `base_url` + `service` + the
        // `finish_non_exhaustive()` sentinel (`..`). Pin that contract
        // so a future refactor that accidentally swapped to
        // `#[derive(Debug)]` would fail this test.
        let d = ConsulDiscovery::new("http://consul:8500", "rustgate-primary").unwrap();
        let rendered = format!("{d:?}");
        assert!(
            rendered.contains("ConsulDiscovery"),
            "debug should name the struct: {rendered}",
        );
        assert!(
            rendered.contains("http://consul:8500"),
            "base_url must be visible for operators: {rendered}",
        );
        assert!(
            rendered.contains("rustgate-primary"),
            "service name must be visible: {rendered}",
        );
        assert!(
            rendered.contains(".."),
            "finish_non_exhaustive sentinel pins client redaction: {rendered}",
        );
        assert!(
            !rendered.contains("Client {"),
            "reqwest Client internals must not leak: {rendered}",
        );
    }

    #[test]
    fn default_http_timeout_is_ten_seconds() {
        // The reconciler's default interval is 30 s — pin the 10 s
        // timeout so a future refactor that bumped it past the
        // reconciler interval would fail here rather than silently
        // starving the discovery loop on every slow Consul response.
        assert_eq!(DEFAULT_HTTP_TIMEOUT, Duration::from_secs(10));
        assert!(
            DEFAULT_HTTP_TIMEOUT < Duration::from_secs(30),
            "timeout must stay under the reconciler interval",
        );
    }

    #[test]
    fn new_accepts_owned_string_and_str_slice() {
        // `base_url: impl Into<String>` + `service: impl Into<String>`
        // — pin both the `&str` and `String` call shapes compile so a
        // future narrowing to `&str` (which would break every owned-
        // String caller in the server bin) fails at test-compile.
        let _ = ConsulDiscovery::new("http://consul:8500", "rustgate").unwrap();
        let _ = ConsulDiscovery::new(String::from("http://consul:8500"), String::from("rustgate"))
            .unwrap();
    }
}
