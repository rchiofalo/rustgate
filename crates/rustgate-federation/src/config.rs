use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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
    /// TAK Server default: 268,435,456 (256 MB).
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
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            federate_id: String::from("rustgate-federation-1"),
            v1_enabled: true,
            v1_listen_addr: "0.0.0.0:9000".parse().expect("valid default addr"),
            v2_enabled: true,
            v2_listen_addr: "0.0.0.0:9001".parse().expect("valid default addr"),
            peers: Vec::new(),
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
            health_check_interval: Duration::from_secs(5),
            client_timeout: Duration::from_secs(15),
            max_message_size: 268_435_456, // 256 MB — TAK Server default
            reconnect_delay: Duration::from_secs(30),
            max_reconnects: -1,
            max_hops: 10,
            default_group: String::from("__ANON__"),
            store_path: None,
            skip_hostname_verify: false,
            cert_file: PathBuf::from("server.pem"),
            key_file: PathBuf::from("server-key.pem"),
            ca_file: PathBuf::from("ca.pem"),
        }
    }
}

/// Configuration for a single federation peer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerConfig {
    /// Unique identifier for this peer.
    pub id: String,
    /// Network address of the peer (host:port).
    pub address: String,
    /// Groups this peer participates in (bidirectional).
    /// TAK Server has separate inbound/outbound groups; we'll add that
    /// in a future PR. For now, a single list covers the common use case.
    pub groups: Vec<String>,
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
}

fn default_protocol_version() -> u32 {
    2
}

#[cfg(test)]
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
        assert_eq!(cfg.max_message_size, 268_435_456);
        assert_eq!(cfg.reconnect_delay, Duration::from_secs(30));
        assert_eq!(cfg.max_reconnects, -1);
        assert_eq!(cfg.max_hops, 10);
        assert_eq!(cfg.default_group, "__ANON__");
        assert!(cfg.v1_enabled);
        assert!(cfg.v2_enabled);
        assert!(!cfg.skip_hostname_verify);
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
            enabled: true,
            is_outbound: true,
            trust_cert_cn: Some("peer-1-ca".into()),
            routing_mode: RoutingMode::Broadcast,
            protocol_version: 1,
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
            enabled: true,
            is_outbound: false,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
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
            enabled: true,
            is_outbound: false,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
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
            enabled: false,
            is_outbound: false,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
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
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 2,
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
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 1,
        };
        let json = serde_json::to_string(&peer).expect("serialize");
        let parsed: PeerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.protocol_version, 1);
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
}
