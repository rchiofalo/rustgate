//! NATS adapter for rustgate.
//!
//! Bridges local TAK sessions to a NATS event bus, enabling stateless
//! horizontal scaling. Publishes inbound CoT to NATS subjects and
//! subscribes for outbound delivery to connected clients.

pub mod config;
pub mod jetstream;
pub mod publisher;
pub mod serde_compat;
pub mod subscriber;

pub use config::NatsConfig;
pub use jetstream::JetStreamReplay;
pub use publisher::NatsPublisher;
pub use serde_compat::WireEvent;
pub use subscriber::NatsSubscriber;

/// Top-level adapter that owns the NATS client and provides access to
/// the publisher, subscriber, and JetStream replay components.
#[derive(Debug)]
pub struct NatsAdapter {
    client: async_nats::Client,
    config: NatsConfig,
}

impl NatsAdapter {
    /// Connect to a NATS server and return an adapter ready for use.
    pub async fn connect(config: NatsConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = if let Some(ref creds) = config.credentials_file {
            async_nats::ConnectOptions::with_credentials_file(creds)
                .await?
                .connect(&config.url)
                .await?
        } else {
            async_nats::connect(&config.url).await?
        };

        tracing::info!(url = %config.url, instance_id = %config.instance_id, "connected to NATS");

        Ok(Self { client, config })
    }

    /// Create a publisher for sending messages to NATS.
    pub fn publisher(&self) -> NatsPublisher {
        NatsPublisher::new(self.client.clone(), self.config.clone())
    }

    /// Create a subscriber for receiving messages from NATS.
    pub fn subscriber(&self) -> NatsSubscriber {
        NatsSubscriber::new(self.client.clone(), self.config.clone())
    }

    /// Create a JetStream replay handle for SA bootstrap.
    pub fn jetstream_replay(&self) -> JetStreamReplay {
        JetStreamReplay::new(self.client.clone(), self.config.clone())
    }
}
