use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Federation protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// V1: Length-prefixed XML over mTLS (legacy CNAK-to-CNAK federation).
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
    /// Address to listen for inbound federation peers.
    pub listen_addr: SocketAddr,
    /// Federation protocol version (V1 or V2).
    pub protocol: Protocol,
    /// List of outbound peers to connect to.
    pub peers: Vec<PeerConfig>,
    /// Interval between heartbeat messages.
    pub heartbeat_interval: Duration,
    /// Timeout before considering a peer dead (no heartbeat received).
    pub heartbeat_timeout: Duration,
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Base delay before reconnecting to a disconnected peer.
    pub reconnect_delay: Duration,
    /// Maximum number of reconnection attempts (-1 = unlimited).
    pub max_reconnects: i32,
    /// Maximum number of federation hops before dropping a message.
    pub max_hops: u32,
    /// Default group for messages without explicit group assignment.
    pub default_group: String,
    /// Path for persistent federate store (JSON file).
    pub store_path: Option<PathBuf>,
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
            listen_addr: "0.0.0.0:9001".parse().expect("valid default addr"),
            protocol: Protocol::V2,
            peers: Vec::new(),
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
            max_message_size: 10 * 1024 * 1024, // 10 MB
            reconnect_delay: Duration::from_secs(15),
            max_reconnects: -1,
            max_hops: 10,
            default_group: String::from("__ANON__"),
            store_path: None,
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
    /// Groups this peer participates in.
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
        assert_eq!(cfg.max_message_size, 10 * 1024 * 1024);
        assert_eq!(cfg.reconnect_delay, Duration::from_secs(15));
        assert_eq!(cfg.max_reconnects, -1);
        assert_eq!(cfg.max_hops, 10);
        assert_eq!(cfg.default_group, "__ANON__");
        assert_eq!(cfg.protocol, Protocol::V2);
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
        };
        let json = serde_json::to_string(&peer).expect("serialize");
        let parsed: PeerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id, "peer-1");
        assert_eq!(parsed.groups.len(), 2);
        assert_eq!(parsed.routing_mode, RoutingMode::Broadcast);
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
    fn default_config_listen_addr() {
        let cfg = FederationConfig::default();
        assert_eq!(cfg.listen_addr.port(), 9001);
        assert_eq!(cfg.listen_addr.to_string(), "0.0.0.0:9001");
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
        };
        let json = serde_json::to_string(&peer).expect("serialize");
        let parsed: PeerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.groups, groups);
    }

    #[test]
    fn federation_config_clone() {
        let cfg = FederationConfig::default();
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.federate_id, cfg.federate_id);
        assert_eq!(cfg2.listen_addr, cfg.listen_addr);
        assert_eq!(cfg2.protocol, cfg.protocol);
        assert_eq!(cfg2.max_hops, cfg.max_hops);
    }
}
