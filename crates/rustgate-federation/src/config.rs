// Copyright © 2026 Roberto Chiofalo.

//! Federation configuration types and defaults.
//!
//! Defines [`FederationConfig`] (the top-level config struct) and
//! [`PeerConfig`] (per-peer connection settings including protocol version,
//! TLS paths, group filtering, and circuit breaker parameters).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use rustgate_core::PeerId;

/// Default V1 listen address: `0.0.0.0:9000`.
const DEFAULT_V1_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9000));

/// Default V2 listen address: `0.0.0.0:9001`.
const DEFAULT_V2_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9001));

/// Federation protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// V1: Length-prefixed XML over mTLS (legacy federation protocol).
    V1,
    /// V2: gRPC over mTLS (standard TAK Server federation).
    V2,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::V1 => write!(f, "v1"),
            Protocol::V2 => write!(f, "v2"),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "v1" => Ok(Protocol::V1),
            "v2" => Ok(Protocol::V2),
            other => Err(anyhow::anyhow!("unknown federation protocol: {other}")),
        }
    }
}

/// Routing mode for a federation peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    /// Messages sent only via per-peer NATS subscriptions (matrix routing).
    #[default]
    Matrix,
    /// Messages broadcast to all peers (default for backward compat).
    Broadcast,
}

/// Top-level federation configuration.
#[derive(Debug, Clone)]
pub struct FederationConfig {
    /// Unique identifier for this federation server instance.
    pub federate_id: String,

    // --- V1 (legacy) listener ---
    /// Whether V1 federation (length-prefixed XML over mTLS) is enabled.
    pub v1_enabled: bool,
    /// Address to listen for inbound V1 federation peers.
    /// TAK Server default port: 9000. Federation Hub default: 9101.
    pub v1_listen_addr: SocketAddr,

    // --- V2 (gRPC) listener ---
    /// Whether V2 federation (gRPC over mTLS) is enabled.
    pub v2_enabled: bool,
    /// Address to listen for inbound V2 federation peers.
    /// TAK Server default port: 9001. Federation Hub default: 9102.
    pub v2_listen_addr: SocketAddr,

    /// List of outbound peers to connect to.
    pub peers: Vec<PeerConfig>,
    /// Interval between V1 CoT heartbeat messages (t-x-c-t).
    pub heartbeat_interval: Duration,
    /// Timeout before considering a peer dead (no heartbeat received).
    pub heartbeat_timeout: Duration,
    /// Interval between V2 gRPC health checks.
    /// TAK Server default: 3s. Must be faster than `client_timeout`.
    pub health_check_interval: Duration,
    /// V2 gRPC client inactivity timeout.
    /// TAK Server default: 15s. If no health check arrives within this
    /// window, the connection is considered dead.
    pub client_timeout: Duration,
    /// Maximum message size in bytes.
    /// Standard TAK federation default: 10 MB.
    pub max_message_size: usize,
    /// Base delay before reconnecting to a disconnected peer.
    pub reconnect_delay: Duration,
    /// Maximum number of reconnection attempts (-1 = unlimited).
    pub max_reconnects: i32,
    /// Maximum number of federation hops before dropping a message.
    /// TAK Server default: -1 (unlimited). We use 10 as a safer default.
    pub max_hops: u32,
    /// Default group for messages without explicit group assignment.
    pub default_group: String,
    /// Path for persistent federate store (JSON file).
    pub store_path: Option<PathBuf>,
    /// Whether to skip TLS hostname verification for federation peers.
    /// Useful when peers use descriptive certificate CNs instead of hostnames.
    pub skip_hostname_verify: bool,
    /// TLS certificate file for this server.
    pub cert_file: PathBuf,
    /// TLS private key file for this server.
    pub key_file: PathBuf,
    /// TLS CA certificate file for peer verification.
    pub ca_file: PathBuf,
    /// Directory containing additional trusted CA certificates for federation.
    ///
    /// When set, PEM/CRT files in this directory are loaded into a [`crate::trust_store::TrustStore`]
    /// and merged with the base `ca_file` for all TLS verification (inbound and
    /// outbound, V1 and V2). Certificates added to this directory take effect
    /// on the next server restart.
    pub trust_store_dir: Option<PathBuf>,
    /// Shared secret for JWT federation authentication.
    /// When set, enables JWT token issuance and validation for federation peers.
    /// mTLS remains required for transport security.
    pub jwt_secret: Option<Vec<u8>>,
    /// JWT token expiration in seconds (default: 3600).
    pub jwt_expiry_secs: u64,
    /// Number of consecutive send failures before tripping the circuit breaker
    /// for a peer. Once open, messages are skipped until the recovery timeout
    /// elapses and a probe succeeds. Default: 5.
    pub circuit_breaker_threshold: u32,
    /// Seconds to wait after a circuit breaker trips before allowing a probe
    /// message (half-open state). Default: 60.
    pub circuit_breaker_timeout: Duration,
    /// Maximum messages retained per peer in the replay buffer.
    /// On reconnection, buffered messages are replayed before resuming live stream.
    /// Set to 0 to disable replay buffering.
    pub replay_buffer_capacity: usize,
    /// Directory to persist the per-peer replay buffer to disk (redb).
    /// When set, buffered messages survive server restarts so a peer
    /// reconnecting after a restart can resume replay from the last
    /// persisted point. When `None`, replay buffers live in RAM only.
    pub replay_buffer_dir: Option<PathBuf>,
    /// Global byte cap for the persisted replay buffer. Only honored
    /// when `replay_buffer_dir` is set. When inserting a record would
    /// exceed this cap, the oldest persisted entries (across all peers)
    /// are evicted until the new entry fits.
    pub replay_max_bytes: u64,

    // --- High-Availability (HA) ---
    /// Pod identifier for HA mode. When set together with `ha_nats_url`,
    /// enables distributed peer ownership via NATS KV claims so that
    /// only one pod manages each outbound peer in a multi-pod deployment.
    pub pod_id: Option<String>,
    /// NATS URL for HA coordination (claim manager + connection registry).
    /// Requires the `ha` feature.
    pub ha_nats_url: Option<String>,

    /// The region this server belongs to, for latency-aware routing.
    /// When set, matrix-mode forwarding prefers peers in the same region.
    pub local_region: Option<String>,

    /// Maximum groups a single V2 federation peer can advertise.
    pub max_groups_per_peer: usize,

    /// Maximum length of a V2 federation group name in bytes.
    pub max_group_name_length: usize,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            federate_id: String::from("rustgate-federation-1"),
            v1_enabled: true,
            v1_listen_addr: DEFAULT_V1_ADDR,
            v2_enabled: true,
            v2_listen_addr: DEFAULT_V2_ADDR,
            peers: Vec::new(),
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
            health_check_interval: Duration::from_secs(5),
            client_timeout: Duration::from_secs(15),
            max_message_size: 10_485_760, // 10 MB — standard TAK federation default
            reconnect_delay: Duration::from_secs(30),
            max_reconnects: -1,
            max_hops: 10,
            default_group: String::from("__ANON__"),
            store_path: None,
            skip_hostname_verify: false,
            trust_store_dir: None,
            cert_file: PathBuf::from("server.pem"),
            key_file: PathBuf::from("server-key.pem"),
            ca_file: PathBuf::from("ca.pem"),
            jwt_secret: None,
            jwt_expiry_secs: 3600,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout: Duration::from_secs(60),
            replay_buffer_capacity: crate::replay_buffer::DEFAULT_REPLAY_CAPACITY,
            replay_buffer_dir: None,
            replay_max_bytes: crate::replay_persist::DEFAULT_REPLAY_MAX_BYTES,
            pod_id: None,
            ha_nats_url: None,
            local_region: None,
            max_groups_per_peer: crate::v2::server::DEFAULT_MAX_GROUPS_PER_PEER,
            max_group_name_length: crate::v2::server::DEFAULT_MAX_GROUP_NAME_LENGTH,
        }
    }
}

/// Configuration for a single federation peer.
///
/// Uses `deny_unknown_fields` to reject peer config containing
/// unexpected properties — a typo like `"adress"` produces a clear
/// deserialization error instead of being silently ignored.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// Unique identifier for this peer.
    pub id: PeerId,
    /// Network address of the peer (host:port).
    pub address: String,
    /// Groups this peer participates in (bidirectional fallback).
    /// Used when neither `inbound_groups` nor `outbound_groups` is set.
    pub groups: Vec<String>,
    /// Groups accepted from this peer (inbound direction).
    /// Overrides `groups` for inbound filtering when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_groups: Option<Vec<String>>,
    /// Groups sent to this peer (outbound direction).
    /// Overrides `groups` for outbound filtering when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_groups: Option<Vec<String>>,
    /// Whether this peer connection is enabled.
    pub enabled: bool,
    /// Whether this is an outbound connection (we initiate) vs inbound (they connect to us).
    pub is_outbound: bool,
    /// Optional CN of the certificate to trust for this specific peer.
    pub trust_cert_cn: Option<String>,
    /// Routing mode for this peer.
    #[serde(default)]
    pub routing_mode: RoutingMode,
    /// Protocol version to use for outbound connections (1 or 2).
    /// Defaults to V2 (gRPC). V1 uses length-prefixed XML.
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
    /// Optional JWT token for this peer's authentication.
    /// Used as an alternative to certificate-only auth when the
    /// federation server has JWT authentication enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_token: Option<String>,
    /// Geographic region of this peer (e.g., "us-east", "eu-west").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Reserved for future same-zone preference within same-region routing.
    /// Availability zone within the region (e.g., "az-1", "az-2").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Routing priority — lower values are preferred. Default: 100.
    #[serde(default = "default_priority")]
    pub priority: u32,
}

impl PeerConfig {
    /// Groups used for inbound filtering (accepting messages from this peer).
    /// Returns `inbound_groups` if set, otherwise falls back to `groups`.
    pub fn effective_inbound_groups(&self) -> &[String] {
        self.inbound_groups.as_deref().unwrap_or(&self.groups)
    }

    /// Groups used for outbound filtering (sending messages to this peer).
    /// Returns `outbound_groups` if set, otherwise falls back to `groups`.
    pub fn effective_outbound_groups(&self) -> &[String] {
        self.outbound_groups.as_deref().unwrap_or(&self.groups)
    }
}

fn default_protocol_version() -> u32 {
    2
}

fn default_priority() -> u32 {
    100
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::V1.to_string(), "v1");
        assert_eq!(Protocol::V2.to_string(), "v2");
    }

    #[test]
    fn protocol_parse() {
        assert_eq!("v1".parse::<Protocol>().expect("parse"), Protocol::V1);
        assert_eq!("V1".parse::<Protocol>().expect("parse"), Protocol::V1);
        assert_eq!("v2".parse::<Protocol>().expect("parse"), Protocol::V2);
        assert_eq!("V2".parse::<Protocol>().expect("parse"), Protocol::V2);
        assert!("v3".parse::<Protocol>().is_err());
    }

    #[test]
    fn default_config_values() {
        let cfg = FederationConfig::default();
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(cfg.heartbeat_timeout, Duration::from_secs(90));
        assert_eq!(cfg.health_check_interval, Duration::from_secs(5));
        assert_eq!(cfg.client_timeout, Duration::from_secs(15));
        assert_eq!(cfg.max_message_size, 10_485_760);
        assert_eq!(cfg.reconnect_delay, Duration::from_secs(30));
        assert_eq!(cfg.max_reconnects, -1);
        assert_eq!(cfg.max_hops, 10);
        assert_eq!(cfg.default_group, "__ANON__");
        assert!(cfg.v1_enabled);
        assert!(cfg.v2_enabled);
        assert!(!cfg.skip_hostname_verify);
        assert!(cfg.trust_store_dir.is_none());
        assert!(cfg.pod_id.is_none());
        assert!(cfg.ha_nats_url.is_none());
    }

    #[test]
    fn routing_mode_serde() {
        let json = serde_json::to_string(&RoutingMode::Matrix).expect("serialize");
        assert_eq!(json, "\"matrix\"");

        let parsed: RoutingMode = serde_json::from_str("\"broadcast\"").expect("deserialize");
        assert_eq!(parsed, RoutingMode::Broadcast);
    }

    #[test]
    fn routing_mode_default() {
        assert_eq!(RoutingMode::default(), RoutingMode::Matrix);
    }

    #[test]
    fn peer_config_serde_round_trip() {
        let peer = PeerConfig {
            id: "peer-1".into(),
            address: "10.0.0.1:9001".into(),
            groups: vec!["Alpha".into(), "Bravo".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: Some("peer-1-ca".into()),
            routing_mode: RoutingMode::Broadcast,
            protocol_version: 1,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };
        let json = serde_json::to_string(&peer).expect("serialize");
        let parsed: PeerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id, "peer-1");
        assert_eq!(parsed.groups.len(), 2);
        assert_eq!(parsed.routing_mode, RoutingMode::Broadcast);
        assert_eq!(parsed.protocol_version, 1);
    }

    #[test]
    fn peer_config_default_routing_mode() {
        let json = r#"{"id":"p","address":"1.2.3.4:9001","groups":[],"enabled":true,"is_outbound":false,"trust_cert_cn":null}"#;
        let parsed: PeerConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(parsed.routing_mode, RoutingMode::Matrix);
    }

    #[test]
    fn protocol_parse_error_message_contains_input() {
        let err = "v3".parse::<Protocol>().expect_err("should fail for v3");
        assert!(err.to_string().contains("v3"));
    }

    #[test]
    fn protocol_parse_empty_string_fails() {
        assert!("".parse::<Protocol>().is_err());
    }

    #[test]
    fn protocol_parse_mixed_case() {
        assert_eq!("V1".parse::<Protocol>().expect("parse"), Protocol::V1);
        assert_eq!("v2".parse::<Protocol>().expect("parse"), Protocol::V2);
    }

    #[test]
    fn protocol_equality() {
        assert_eq!(Protocol::V1, Protocol::V1);
        assert_eq!(Protocol::V2, Protocol::V2);
        assert_ne!(Protocol::V1, Protocol::V2);
    }

    #[test]
    fn protocol_clone() {
        let p = Protocol::V1;
        let p2 = p;
        assert_eq!(p, p2);
    }

    #[test]
    fn protocol_debug_format() {
        let debug = format!("{:?}", Protocol::V1);
        assert_eq!(debug, "V1");
    }

    #[test]
    fn routing_mode_serde_matrix() {
        let json = serde_json::to_string(&RoutingMode::Matrix).expect("serialize");
        let parsed: RoutingMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, RoutingMode::Matrix);
    }

    #[test]
    fn routing_mode_serde_invalid_value() {
        let result = serde_json::from_str::<RoutingMode>("\"invalid\"");
        assert!(result.is_err());
    }

    #[test]
    fn routing_mode_equality() {
        assert_eq!(RoutingMode::Matrix, RoutingMode::Matrix);
        assert_eq!(RoutingMode::Broadcast, RoutingMode::Broadcast);
        assert_ne!(RoutingMode::Matrix, RoutingMode::Broadcast);
    }

    #[test]
    fn default_config_federate_id() {
        let cfg = FederationConfig::default();
        assert_eq!(cfg.federate_id, "rustgate-federation-1");
    }

    #[test]
    fn default_config_listen_addrs() {
        let cfg = FederationConfig::default();
        assert_eq!(cfg.v1_listen_addr.port(), 9000);
        assert_eq!(cfg.v1_listen_addr.to_string(), "0.0.0.0:9000");
        assert_eq!(cfg.v2_listen_addr.port(), 9001);
        assert_eq!(cfg.v2_listen_addr.to_string(), "0.0.0.0:9001");
    }

    #[test]
    fn default_config_tls_paths() {
        let cfg = FederationConfig::default();
        assert_eq!(cfg.cert_file, PathBuf::from("server.pem"));
        assert_eq!(cfg.key_file, PathBuf::from("server-key.pem"));
        assert_eq!(cfg.ca_file, PathBuf::from("ca.pem"));
    }

    #[test]
    fn default_config_no_peers() {
        let cfg = FederationConfig::default();
        assert!(cfg.peers.is_empty());
    }

    #[test]
    fn default_config_no_store_path() {
        let cfg = FederationConfig::default();
        assert!(cfg.store_path.is_none());
    }

    #[test]
    fn peer_config_with_no_trust_cert() {
        let peer = PeerConfig {
            id: "peer-1".into(),
            address: "10.0.0.1:9001".into(),
            groups: vec![],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: false,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };
        let json = serde_json::to_string(&peer).expect("serialize");
        let parsed: PeerConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.trust_cert_cn.is_none());
    }

    #[test]
    fn peer_config_empty_groups() {
        let peer = PeerConfig {
            id: "peer-1".into(),
            address: "10.0.0.1:9001".into(),
            groups: vec![],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: false,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };
        let json = serde_json::to_string(&peer).expect("serialize");
        let parsed: PeerConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.groups.is_empty());
    }

    #[test]
    fn peer_config_disabled() {
        let peer = PeerConfig {
            id: "peer-1".into(),
            address: "10.0.0.1:9001".into(),
            groups: vec![],
            inbound_groups: None,
            outbound_groups: None,
            enabled: false,
            is_outbound: false,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };
        assert!(!peer.enabled);
    }

    #[test]
    fn peer_config_multiple_groups_preserved() {
        let groups = vec![
            "Alpha".to_string(),
            "Bravo".to_string(),
            "Charlie".to_string(),
            "Delta".to_string(),
        ];
        let peer = PeerConfig {
            id: "peer-1".into(),
            address: "10.0.0.1:9001".into(),
            groups: groups.clone(),
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
        };
        let json = serde_json::to_string(&peer).expect("serialize");
        let parsed: PeerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.groups, groups);
    }

    #[test]
    fn peer_config_protocol_version_default() {
        let json = r#"{"id":"p","address":"1.2.3.4:9001","groups":[],"enabled":true,"is_outbound":false,"trust_cert_cn":null}"#;
        let parsed: PeerConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(parsed.protocol_version, 2);
    }

    #[test]
    fn peer_config_protocol_version_v1() {
        let peer = PeerConfig {
            id: "legacy-peer".into(),
            address: "10.0.0.1:9000".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 1,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };
        let json = serde_json::to_string(&peer).expect("serialize");
        let parsed: PeerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.protocol_version, 1);
    }

    #[test]
    fn effective_groups_fallback_to_groups() {
        let peer = PeerConfig {
            id: "p".into(),
            address: "1.2.3.4:9001".into(),
            groups: vec!["Alpha".into(), "Bravo".into()],
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
        };
        assert_eq!(peer.effective_inbound_groups(), &["Alpha", "Bravo"]);
        assert_eq!(peer.effective_outbound_groups(), &["Alpha", "Bravo"]);
    }

    #[test]
    fn effective_groups_directional_override() {
        let peer = PeerConfig {
            id: "p".into(),
            address: "1.2.3.4:9001".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: Some(vec!["Inbound1".into(), "Inbound2".into()]),
            outbound_groups: Some(vec!["Outbound1".into()]),
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };
        assert_eq!(peer.effective_inbound_groups(), &["Inbound1", "Inbound2"]);
        assert_eq!(peer.effective_outbound_groups(), &["Outbound1"]);
    }

    #[test]
    fn effective_groups_partial_override() {
        let peer = PeerConfig {
            id: "p".into(),
            address: "1.2.3.4:9001".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: Some(vec!["Inbound1".into()]),
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
        };
        assert_eq!(peer.effective_inbound_groups(), &["Inbound1"]);
        // outbound falls back to groups
        assert_eq!(peer.effective_outbound_groups(), &["Alpha"]);
    }

    #[test]
    fn directional_groups_serde_round_trip() {
        let peer = PeerConfig {
            id: "p".into(),
            address: "1.2.3.4:9001".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: Some(vec!["In1".into()]),
            outbound_groups: Some(vec!["Out1".into(), "Out2".into()]),
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
        };
        let json = serde_json::to_string(&peer).expect("serialize");
        assert!(json.contains("inbound_groups"));
        assert!(json.contains("outbound_groups"));

        let parsed: PeerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.inbound_groups, Some(vec!["In1".into()]));
        assert_eq!(
            parsed.outbound_groups,
            Some(vec!["Out1".into(), "Out2".into()])
        );
    }

    #[test]
    fn directional_groups_omitted_in_json_when_none() {
        let peer = PeerConfig {
            id: "p".into(),
            address: "1.2.3.4:9001".into(),
            groups: vec!["Alpha".into()],
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
        };
        let json = serde_json::to_string(&peer).expect("serialize");
        assert!(!json.contains("inbound_groups"));
        assert!(!json.contains("outbound_groups"));
    }

    #[test]
    fn federation_config_clone() {
        let cfg = FederationConfig::default();
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.federate_id, cfg.federate_id);
        assert_eq!(cfg2.v1_listen_addr, cfg.v1_listen_addr);
        assert_eq!(cfg2.v2_listen_addr, cfg.v2_listen_addr);
        assert_eq!(cfg2.v1_enabled, cfg.v1_enabled);
        assert_eq!(cfg2.v2_enabled, cfg.v2_enabled);
        assert_eq!(cfg2.max_hops, cfg.max_hops);
        assert_eq!(cfg2.max_message_size, cfg.max_message_size);
        assert_eq!(cfg2.health_check_interval, cfg.health_check_interval);
        assert_eq!(cfg2.client_timeout, cfg.client_timeout);
    }

    #[test]
    fn peer_config_rejects_unknown_field() {
        let json = r#"{"id":"p","address":"1.2.3.4:9001","groups":[],"enabled":true,"is_outbound":false,"trust_cert_cn":null,"bogus":42}"#;
        let result = serde_json::from_str::<PeerConfig>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field: {err}"
        );
    }
}
