//! MQTT server — accept loop, session spawning, and graceful shutdown.
//!
//! [`MqttServer::run`] is the main entry point. It accepts connections from
//! the [`MqttListener`](crate::MqttListener), enforces the connection limit,
//! spawns a session task per connection, and shuts down cleanly when the
//! shutdown signal fires.

use crate::config::MqttServerConfig;

/// The MQTT server that manages the accept loop and session lifecycle.
#[derive(Debug)]
pub struct MqttServer;

impl MqttServer {
    /// Run the MQTT server until the shutdown signal fires.
    pub async fn run(config: MqttServerConfig) {
        // Full implementation in a later commit.
        config.shutdown.notified().await;
    }
}
