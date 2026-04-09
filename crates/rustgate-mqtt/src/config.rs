//! Configuration for the MQTT server.

use std::sync::Arc;

use rustgate_transport::Router;
use tokio::sync::{Notify, Semaphore};

use crate::listener::MqttListener;

/// Configuration for [`MqttServer::run`](crate::MqttServer::run).
#[derive(Debug)]
pub struct MqttServerConfig {
    /// The bound MQTT TLS listener.
    pub listener: MqttListener,

    /// Shared router for message delivery.
    pub router: Arc<Router>,

    /// Connection-limit semaphore shared across all transports.
    pub connection_limit: Arc<Semaphore>,

    /// Shutdown signal.
    pub shutdown: Arc<Notify>,

    /// Optional prefix to strip from MQTT topics before mapping to groups.
    ///
    /// For example, with `topic_prefix = Some("rustgate/".into())`, the MQTT
    /// topic `rustgate/alpha` maps to group `alpha`. Topics that do not start
    /// with the prefix are rejected.
    pub topic_prefix: Option<String>,

    /// Maximum MQTT packet size in bytes (default: 16 MiB).
    pub max_packet_size: usize,
}

impl MqttServerConfig {
    /// Default maximum packet size: 16 MiB (matches websocket frame cap).
    pub const DEFAULT_MAX_PACKET_SIZE: usize = 16 * 1024 * 1024;
}
