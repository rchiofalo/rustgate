// Copyright © 2026 Roberto Chiofalo.

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

    /// Minimum keep-alive interval in seconds. Clients requesting 0
    /// (disabled) or a value below this floor get this value imposed.
    pub min_keep_alive_secs: u16,

    /// Channel capacity for response packets flowing from read loop to
    /// write loop (per session).
    pub response_channel_capacity: usize,
}

impl MqttServerConfig {
    /// Default maximum packet size: 16 MiB (matches websocket frame cap).
    pub const DEFAULT_MAX_PACKET_SIZE: usize = 16 * 1024 * 1024;

    /// Default minimum keep-alive in seconds.
    pub const DEFAULT_MIN_KEEP_ALIVE_SECS: u16 = 30;

    /// Default response channel capacity per session.
    pub const DEFAULT_RESPONSE_CHANNEL_CAPACITY: usize = 64;
}
