//! MQTT server — accept loop, session spawning, and graceful shutdown.
//!
//! [`MqttServer::run`] is the main entry point. It accepts connections from
//! the [`MqttListener`](crate::MqttListener), enforces the connection limit,
//! spawns a session task per connection, and shuts down cleanly when the
//! shutdown signal fires.

use std::sync::Arc;

use tracing::{info, warn};

use crate::config::MqttServerConfig;
use crate::session::{ClientIdRegistry, handle_mqtt_session};

/// The MQTT server that manages the accept loop and session lifecycle.
#[derive(Debug)]
pub struct MqttServer;

impl MqttServer {
    /// Run the MQTT server until the shutdown signal fires.
    ///
    /// Accepts mTLS-authenticated connections, enforces the shared
    /// connection limit, and spawns a session handler per connection.
    pub async fn run(config: MqttServerConfig) {
        let MqttServerConfig {
            listener,
            router,
            connection_limit,
            shutdown,
            topic_prefix,
            max_packet_size,
        } = config;

        let client_id_registry = ClientIdRegistry::new();

        info!(addr = ?listener.local_addr().ok(), "MQTT server started");

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok(Some(pre_session)) => {
                            let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!("connection limit reached, rejecting MQTT client");
                                    continue;
                                }
                            };

                            let router = Arc::clone(&router);
                            let prefix = topic_prefix.clone();
                            let registry = Arc::clone(&client_id_registry);
                            drop(tokio::spawn(handle_mqtt_session(
                                pre_session,
                                router,
                                prefix,
                                max_packet_size,
                                registry,
                                permit,
                            )));
                        }
                        Ok(None) => {
                            // TLS handshake failed or cert invalid — already logged by listener.
                        }
                        Err(e) => {
                            warn!(error = %e, "MQTT accept error");
                        }
                    }
                }
                () = shutdown.notified() => {
                    info!("MQTT server shutting down");
                    break;
                }
            }
        }
    }
}
