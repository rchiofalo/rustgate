// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! etcd peer discovery backend.
//!
//! Scans an etcd v3 key prefix (default `rustgate/peers/`) and treats each
//! key-value pair as a federation peer descriptor. Two value formats are
//! accepted per key:
//!
//! 1. **JSON** — the value is a full `PeerConfig` serialized as JSON. Use
//!    this when you need fine-grained control (groups, protocol version,
//!    trust CN, JWT token, etc.).
//! 2. **Plain `host:port`** — a bare address string. The backend synthesizes
//!    a `PeerConfig` with the key suffix as the peer id, `__ANON__` groups,
//!    and V2 gRPC as the protocol.
//!
//! Parsing is lenient: if one key fails to decode, a warning is logged and
//! the remaining keys are still returned. This matches the file-based
//! reloader's behavior where one bad entry does not poison the whole set.

use async_trait::async_trait;
use etcd_client::{Client, GetOptions};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::PeerDiscovery;
use crate::config::{PeerConfig, RoutingMode};
use crate::error::{FederationError, Result};

/// etcd peer discovery source.
///
/// Holds a lazily-established `Client` (wrapped in an async `Mutex` because
/// etcd-client's `get` takes `&mut self`) and re-resolves the peer set on
/// every tick. A future optimization could replace the polling loop with
/// `Client::watch(prefix).with_prefix()` to react instantly to key changes,
/// but the fixed-interval model is simpler and matches the other backends.
pub struct EtcdDiscovery {
    endpoints: Vec<String>,
    prefix: String,
    /// `None` until the first successful `Client::connect` call; populated
    /// lazily so the constructor cannot fail on startup if etcd is down.
    client: Mutex<Option<Client>>,
}

impl std::fmt::Debug for EtcdDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtcdDiscovery")
            .field("endpoints", &self.endpoints)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl EtcdDiscovery {
    /// Construct a new etcd discovery backend.
    ///
    /// `endpoints` are etcd gRPC endpoints (e.g. `["http://127.0.0.1:2379"]`).
    /// `prefix` is scanned with `GetOptions::with_prefix()` on every
    /// reconcile tick. Connection to the etcd cluster is deferred to the
    /// first `discover` call so a transient cluster outage at rustgate
    /// startup does not prevent the process from launching.
    pub fn new(endpoints: Vec<String>, prefix: impl Into<String>) -> Self {
        Self {
            endpoints,
            prefix: prefix.into(),
            client: Mutex::new(None),
        }
    }

    /// Ensure a connected `Client` exists and return a locked mutable ref.
    /// On failure, the mutex is cleared so the next tick retries a fresh
    /// connect.
    async fn get_or_connect<'a>(
        &'a self,
        guard: &'a mut tokio::sync::MutexGuard<'_, Option<Client>>,
    ) -> Result<&'a mut Client> {
        if guard.is_none() {
            let client = Client::connect(self.endpoints.clone(), None)
                .await
                .map_err(|e| {
                    FederationError::discovery(format!("failed to connect to etcd: {e}"))
                })?;
            **guard = Some(client);
        }
        // Safe unwrap: we just inserted `Some` above if the slot was empty.
        guard
            .as_mut()
            .ok_or_else(|| FederationError::discovery("etcd client slot unexpectedly empty"))
    }

    /// Convert an etcd key-value pair into a [`PeerConfig`]. Supports both
    /// JSON-encoded full configs and plain `host:port` strings. Returns
    /// `None` on malformed input and emits a warning; callers use this so
    /// one bad entry cannot poison the entire discovery response.
    fn decode_entry(prefix: &str, key: &str, value: &str) -> Option<PeerConfig> {
        let trimmed_value = value.trim();
        if trimmed_value.starts_with('{') {
            match serde_json::from_str::<PeerConfig>(trimmed_value) {
                Ok(mut cfg) => {
                    // `discovered` is `#[serde(skip)]`, so the deserialized
                    // config always carries the `false` default. Stamp the
                    // provenance marker so the SEC-1 pin resolver treats this
                    // peer as discovered — an explicit `trust_cert_cn` in the
                    // JSON still pins, but a missing one is never derived from
                    // the id. See ADR 0029.
                    cfg.discovered = true;
                    Some(cfg)
                }
                Err(e) => {
                    warn!(key = %key, error = %e, "etcd peer entry is not valid JSON PeerConfig");
                    None
                }
            }
        } else if trimmed_value.is_empty() {
            warn!(key = %key, "etcd peer entry has empty value");
            None
        } else {
            let id = key.strip_prefix(prefix).unwrap_or(key).to_string();
            if id.is_empty() {
                warn!(key = %key, "etcd peer entry has empty id after prefix strip");
                return None;
            }
            // Bare-value form: `host:port` optionally followed by a
            // whitespace-separated `trust-cn=<CN>` token that carries the
            // operator-supplied trusted certificate CN. The first token is
            // always the address; the `trust-cn=` token, when present, pins
            // the peer's server certificate. Without it a discovered peer is
            // left unpinned (chain-only) by the SEC-1 pin resolver — the id
            // is never used as a CN pin. See ADR 0029.
            let mut tokens = trimmed_value.split_whitespace();
            let address = tokens.next().unwrap_or(trimmed_value).to_string();
            let trust_cert_cn = tokens
                .find_map(|tok| tok.strip_prefix("trust-cn="))
                .map(|cn| cn.trim().to_string())
                .filter(|cn| !cn.is_empty());
            Some(PeerConfig {
                id: id.into(),
                address,
                groups: vec!["__ANON__".into()],
                inbound_groups: None,
                outbound_groups: None,
                enabled: true,
                is_outbound: true,
                trust_cert_cn,
                routing_mode: RoutingMode::default(),
                protocol_version: 2,
                jwt_token: None,
                region: None,
                zone: None,
                priority: 100,
                compression: None,
                tenants: Default::default(),
                topology_role: Default::default(),
                discovered: true,
            })
        }
    }

    /// Parse a shared slice of `(key, value)` pairs into peer configs.
    /// Exposed as an associated function so unit tests can feed synthetic
    /// data without mocking an etcd server.
    fn parse_kvs(prefix: &str, kvs: &[(String, String)]) -> Vec<PeerConfig> {
        kvs.iter()
            .filter_map(|(k, v)| Self::decode_entry(prefix, k, v))
            .collect()
    }
}

#[async_trait]
impl PeerDiscovery for EtcdDiscovery {
    async fn discover(&self) -> Result<Vec<PeerConfig>> {
        let mut guard = self.client.lock().await;
        let result = async {
            let client = self.get_or_connect(&mut guard).await?;
            let opts = GetOptions::new().with_prefix();
            let resp = client
                .get(self.prefix.clone(), Some(opts))
                .await
                .map_err(|e| {
                    FederationError::discovery(format!("etcd GET {} failed: {e}", self.prefix))
                })?;
            let kvs: Vec<(String, String)> = resp
                .kvs()
                .iter()
                .filter_map(|kv| {
                    let key = kv.key_str().ok()?.to_string();
                    let value = kv.value_str().ok()?.to_string();
                    Some((key, value))
                })
                .collect();
            // Bound the peer set: a hostile or misconfigured etcd prefix could
            // hold an absurd number of keys, which would otherwise flow into
            // `swap_peers` unchecked (#1619). The etcd-client transport already
            // bounds the per-message body via tonic's decode limit, so the
            // entry count is the meaningful cap here.
            if kvs.len() > super::MAX_DISCOVERY_PEERS {
                return Err(FederationError::discovery(format!(
                    "etcd returned {} entries under prefix {}, exceeding the {} peer cap",
                    kvs.len(),
                    self.prefix,
                    super::MAX_DISCOVERY_PEERS
                )));
            }
            debug!(
                prefix = %self.prefix,
                count = kvs.len(),
                "etcd discovery returned peer entries"
            );
            Ok::<_, FederationError>(Self::parse_kvs(&self.prefix, &kvs))
        }
        .await;

        // On failure, drop the cached client so the next tick reconnects.
        if result.is_err() {
            *guard = None;
        }
        result
    }

    fn backend_name(&self) -> &'static str {
        "etcd"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn decode_entry_accepts_plain_host_port() {
        let cfg =
            EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/alpha", "10.0.0.1:9000")
                .expect("decode");
        assert_eq!(cfg.id.as_str(), "alpha");
        assert_eq!(cfg.address, "10.0.0.1:9000");
        assert!(cfg.is_outbound);
        assert_eq!(cfg.protocol_version, 2);
        // Provenance: bare-value entries are discovered peers, and without a
        // `trust-cn=` token they carry no pin.
        assert!(cfg.discovered);
        assert!(cfg.trust_cert_cn.is_none());
    }

    #[test]
    fn decode_entry_bare_value_reads_trust_cn_suffix() {
        // SEC-1: an operator can pin a discovered etcd peer by appending a
        // whitespace-separated `trust-cn=<CN>` token to the bare address.
        let cfg = EtcdDiscovery::decode_entry(
            "rustgate/peers/",
            "rustgate/peers/pinned",
            "10.0.0.1:9000 trust-cn=fed-prod-east",
        )
        .expect("decode");
        assert_eq!(cfg.address, "10.0.0.1:9000");
        assert_eq!(cfg.trust_cert_cn.as_deref(), Some("fed-prod-east"));
        assert!(cfg.discovered);
    }

    #[test]
    fn decode_entry_bare_value_blank_trust_cn_suffix_is_ignored() {
        // A `trust-cn=` token with no value must not produce an empty-string
        // pin; the address still parses.
        let cfg = EtcdDiscovery::decode_entry(
            "rustgate/peers/",
            "rustgate/peers/blank",
            "10.0.0.1:9000 trust-cn=",
        )
        .expect("decode");
        assert_eq!(cfg.address, "10.0.0.1:9000");
        assert!(cfg.trust_cert_cn.is_none());
    }

    #[test]
    fn decode_entry_json_branch_marks_discovered_and_honours_trust_cn() {
        // The JSON branch honours an explicit `trust_cert_cn` and stamps the
        // discovered provenance marker (which is `#[serde(skip)]`, so it must
        // be set after deserialize rather than carried on the wire).
        let json = r#"{
            "id": "gamma",
            "address": "10.0.0.3:9001",
            "groups": ["east"],
            "enabled": true,
            "is_outbound": true,
            "trust_cert_cn": "fed-west",
            "protocol_version": 2
        }"#;
        let cfg = EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/gamma", json)
            .expect("decode");
        assert_eq!(cfg.trust_cert_cn.as_deref(), Some("fed-west"));
        assert!(cfg.discovered, "JSON-sourced etcd peers are discovered");
    }

    #[test]
    fn decode_entry_accepts_json_peer_config() {
        let json = r#"{
            "id": "beta",
            "address": "10.0.0.2:9001",
            "groups": ["east"],
            "enabled": true,
            "is_outbound": true,
            "trust_cert_cn": null,
            "protocol_version": 1
        }"#;
        let cfg = EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/beta", json)
            .expect("decode");
        assert_eq!(cfg.id.as_str(), "beta");
        assert_eq!(cfg.address, "10.0.0.2:9001");
        assert_eq!(cfg.protocol_version, 1);
        assert_eq!(cfg.groups, vec!["east".to_string()]);
    }

    #[test]
    fn decode_entry_rejects_empty_value() {
        let cfg = EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/gamma", "");
        assert!(cfg.is_none());
    }

    #[test]
    fn decode_entry_rejects_invalid_json() {
        let cfg =
            EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/delta", "{not json");
        assert!(cfg.is_none());
    }

    #[test]
    fn parse_kvs_skips_bad_entries() {
        let prefix = "rustgate/peers/";
        let kvs = vec![
            (
                "rustgate/peers/ok1".to_string(),
                "10.0.0.1:9000".to_string(),
            ),
            ("rustgate/peers/bad".to_string(), String::new()),
            (
                "rustgate/peers/ok2".to_string(),
                "10.0.0.2:9001".to_string(),
            ),
        ];
        let out = EtcdDiscovery::parse_kvs(prefix, &kvs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id.as_str(), "ok1");
        assert_eq!(out[1].id.as_str(), "ok2");
    }

    #[test]
    fn decode_entry_with_key_not_matching_prefix_uses_full_key_as_id() {
        // `key.strip_prefix(prefix).unwrap_or(key)` is the fallback
        // branch when etcd returns a key that does not start with the
        // configured prefix. This can happen when the operator changes
        // the prefix mid-flight or when a future etcd quirk returns a
        // key that escaped the `with_prefix()` filter. The full key
        // must become the peer id so the entry is still usable rather
        // than being silently dropped.
        let cfg = EtcdDiscovery::decode_entry(
            "rustgate/peers/",
            "totally/unrelated/key",
            "10.0.0.99:9000",
        )
        .expect("decode should fall back to full key as id");
        assert_eq!(cfg.id.as_str(), "totally/unrelated/key");
        assert_eq!(cfg.address, "10.0.0.99:9000");
    }

    #[test]
    fn decode_entry_with_key_equal_to_prefix_returns_none() {
        // If the key is exactly the prefix (e.g. operator wrote
        // `etcdctl put rustgate/peers/ 10.0.0.1:9000` by mistake),
        // stripping yields an empty string — that must become `None`
        // with a warning, because an empty peer id would later cause
        // collisions in the federation manager's peer map.
        let cfg =
            EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/", "10.0.0.1:9000");
        assert!(
            cfg.is_none(),
            "empty id after prefix strip must be rejected",
        );
    }

    #[test]
    fn decode_entry_treats_whitespace_only_value_as_empty() {
        // `value.trim()` precedes both the `starts_with('{')` check
        // and the `is_empty()` check, so a value that is pure
        // whitespace (e.g. `"   \n"`) must route into the empty-value
        // warning branch, not the plain-`host:port` branch where it
        // would produce a peer with an empty address.
        let cfg = EtcdDiscovery::decode_entry(
            "rustgate/peers/",
            "rustgate/peers/whitespace",
            "   \n\t  ",
        );
        assert!(
            cfg.is_none(),
            "whitespace-only value must be treated as empty",
        );
    }

    #[test]
    fn decode_entry_trims_surrounding_whitespace_from_plain_host_port() {
        // The trim applies to the plain-`host:port` branch too —
        // operators who accidentally store `"  10.0.0.1:9000\n"` in
        // etcd (e.g. via a shell pipeline that preserves the
        // trailing newline) must still get a valid peer config, not a
        // silently-broken address that fails to parse.
        let cfg = EtcdDiscovery::decode_entry(
            "rustgate/peers/",
            "rustgate/peers/trim",
            "  10.0.0.1:9000\n",
        )
        .expect("decode should trim surrounding whitespace");
        assert_eq!(cfg.address, "10.0.0.1:9000");
    }

    #[test]
    fn decode_entry_plain_mode_applies_documented_defaults() {
        // Plain `host:port` mode hardcodes 11 peer-config fields
        // (everything except id and address). Pin every one so a
        // silent flip (e.g. `enabled = false` during a "disable peers
        // by default" refactor, or a bump of `protocol_version` to 3)
        // fails a focused test rather than surfacing as a production
        // federation outage.
        let cfg = EtcdDiscovery::decode_entry(
            "rustgate/peers/",
            "rustgate/peers/defaults",
            "10.0.0.5:9000",
        )
        .expect("decode");

        // Group plumbing: anon group, no overrides.
        assert_eq!(cfg.groups, vec!["__ANON__".to_string()]);
        assert!(cfg.inbound_groups.is_none());
        assert!(cfg.outbound_groups.is_none());

        // Admission + direction.
        assert!(cfg.enabled, "discovered peers ship enabled");
        assert!(cfg.is_outbound, "etcd peers are outbound by default");

        // Trust + auth.
        assert!(cfg.trust_cert_cn.is_none());
        assert!(cfg.jwt_token.is_none());

        // Routing.
        assert_eq!(cfg.routing_mode, RoutingMode::default());
        assert_eq!(cfg.protocol_version, 2);

        // Locality + priority.
        assert!(cfg.region.is_none());
        assert!(cfg.zone.is_none());
        assert_eq!(cfg.priority, 100);
    }

    #[test]
    fn decode_entry_json_id_is_taken_from_body_not_key_suffix() {
        // The JSON branch hands the serialized `PeerConfig` straight
        // to `serde_json::from_str` — it does **not** derive the id
        // from the key suffix. Operators who set `id: "fleet-a"` in
        // the JSON but store it under `rustgate/peers/node-42` must
        // get a peer whose id is `fleet-a`, not `node-42`. Pin this
        // so a future refactor that "helpfully" overrode the id with
        // the key suffix would be caught here.
        let json = r#"{
            "id": "fleet-a",
            "address": "10.0.0.2:9001",
            "groups": ["east"],
            "enabled": true,
            "is_outbound": true,
            "trust_cert_cn": null,
            "protocol_version": 1
        }"#;
        let cfg = EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/node-42", json)
            .expect("decode");
        assert_eq!(
            cfg.id.as_str(),
            "fleet-a",
            "JSON body's id wins over key suffix"
        );
    }

    #[test]
    fn parse_kvs_preserves_order_of_valid_entries() {
        // `parse_kvs` is a `filter_map` over the input slice in
        // iteration order, so the output order must match the input
        // order (minus bad entries). The reconciler uses this order
        // to drive stable peer diffs — a non-deterministic
        // reordering would manifest as bogus remove/add churn in the
        // federation manager every tick, even when the etcd contents
        // were unchanged.
        let prefix = "rustgate/peers/";
        let kvs = vec![
            (
                "rustgate/peers/charlie".to_string(),
                "10.0.0.3:9000".to_string(),
            ),
            (
                "rustgate/peers/alpha".to_string(),
                "10.0.0.1:9000".to_string(),
            ),
            (
                "rustgate/peers/bravo".to_string(),
                "10.0.0.2:9000".to_string(),
            ),
        ];
        let out = EtcdDiscovery::parse_kvs(prefix, &kvs);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].id.as_str(), "charlie");
        assert_eq!(out[1].id.as_str(), "alpha");
        assert_eq!(out[2].id.as_str(), "bravo");
    }

    #[tokio::test]
    async fn backend_name_is_stable_etcd_token() {
        // The reconciler tags log lines with `backend_name()` so
        // operators grep `"etcd"` to filter for this backend's
        // lifecycle events. Pin the exact token and the `'static`
        // lifetime (no allocated String).
        let d = EtcdDiscovery::new(vec!["http://127.0.0.1:2379".into()], "rustgate/peers/");
        let name: &'static str = (&d as &dyn PeerDiscovery).backend_name();
        assert_eq!(name, "etcd");
    }

    #[test]
    fn new_stores_endpoints_and_prefix_without_connecting() {
        // Connection is deliberately deferred to the first `discover`
        // call so a transient etcd outage at startup cannot prevent
        // rustgate from launching. Verify the constructor is
        // side-effect-free with an unreachable endpoint — if it
        // eagerly connected, this test would hang on the `connect`
        // future rather than completing instantly.
        let d = EtcdDiscovery::new(vec!["http://10.255.255.1:2379".into()], "rustgate/peers/");
        // Assert the Debug rendering shows the stored fields — this
        // both pins the manual Debug impl and proves new() did not
        // error on the unreachable endpoint.
        let rendered = format!("{d:?}");
        assert!(rendered.contains("http://10.255.255.1:2379"));
        assert!(rendered.contains("rustgate/peers/"));
    }

    #[test]
    fn debug_impl_redacts_client_slot_via_finish_non_exhaustive() {
        // Manual Debug impl: `endpoints` + `prefix` visible,
        // `client: Mutex<Option<Client>>` elided via
        // `finish_non_exhaustive()` (the `..` sentinel). A regression
        // that swapped to `#[derive(Debug)]` would leak the etcd
        // Client's internal gRPC connection state into
        // `tracing::debug!(?backend, …)` output.
        let d = EtcdDiscovery::new(
            vec!["http://etcd-a:2379".into(), "http://etcd-b:2379".into()],
            "rustgate/peers/",
        );
        let rendered = format!("{d:?}");
        assert!(
            rendered.contains("EtcdDiscovery"),
            "debug should name the struct: {rendered}",
        );
        assert!(
            rendered.contains("etcd-a:2379") && rendered.contains("etcd-b:2379"),
            "both endpoints must be visible: {rendered}",
        );
        assert!(
            rendered.contains("rustgate/peers/"),
            "prefix must be visible: {rendered}",
        );
        assert!(
            rendered.contains(".."),
            "finish_non_exhaustive sentinel pins client slot redaction: {rendered}",
        );
        assert!(
            !rendered.contains("Mutex"),
            "client-slot Mutex internals must not leak: {rendered}",
        );
    }
}
