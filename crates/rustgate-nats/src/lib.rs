//! NATS adapter for rustgate.
//!
//! Bridges local sessions to a NATS event bus, enabling stateless
//! horizontal scaling. Publishes inbound messages to NATS subjects and
//! subscribes via JetStream pull consumers for outbound delivery to
//! connected clients with real backpressure.

pub mod config;
pub mod jetstream;
pub mod publisher;
pub mod serde_compat;
pub mod subscriber;

pub use config::{NatsConfig, NatsConfigError, NatsTlsConfig, NatsTlsConfigError};
pub use jetstream::JetStreamReplay;
pub use publisher::NatsPublisher;
pub use serde_compat::WireEvent;
pub use subscriber::{LagCallback, LagSnapshot, LatencyCallback, NatsSubscriber};

/// Top-level adapter that owns the NATS client and provides access to
/// the publisher, subscriber, and JetStream replay components.
#[derive(Debug)]
pub struct NatsAdapter {
    client: async_nats::Client,
    config: NatsConfig,
}

impl NatsAdapter {
    /// Connect to a NATS server and return an adapter ready for use.
    ///
    /// When TLS configuration is provided, the connection uses mTLS with
    /// client certificate authentication. Validates TLS config before
    /// attempting to connect.
    pub async fn connect(
        config: NatsConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        config.validate()?;

        let options = if let Some(ref creds) = config.credentials_file {
            async_nats::ConnectOptions::with_credentials_file(creds).await?
        } else {
            async_nats::ConnectOptions::new()
        };

        let options = apply_tls_options(options, &config.tls);

        let options = options
            .subscription_capacity(config.subscription_capacity)
            .event_callback(|event| async move {
                if let async_nats::Event::SlowConsumer(sid) = event {
                    tracing::warn!(
                        subscription_id = sid,
                        "NATS slow consumer detected: subscription buffer is full, messages may be dropped"
                    );
                }
            });

        let client = options.connect(&config.url).await?;

        tracing::info!(
            url = %config.url,
            instance_id = %config.instance_id,
            subscription_capacity = config.subscription_capacity,
            tls_required = config.tls.required,
            tls_client_auth = config.tls.has_client_auth(),
            "connected to NATS"
        );

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
    ///
    /// When the config has a `checkpoint_path` set, the replayer will
    /// persist and resume from the last processed sequence number.
    pub fn jetstream_replay(&self) -> JetStreamReplay {
        JetStreamReplay::new(
            self.client.clone(),
            self.config.clone(),
            self.config.checkpoint_path.clone(),
        )
    }
}

/// Apply TLS options to the NATS connect options based on configuration.
///
/// Configures client certificate authentication and CA verification when
/// the corresponding paths are provided. Sets the `require_tls` flag to
/// enforce TLS when configured.
fn apply_tls_options(
    options: async_nats::ConnectOptions,
    tls: &config::NatsTlsConfig,
) -> async_nats::ConnectOptions {
    let mut options = options.require_tls(tls.required);

    if let Some(ref ca_cert) = tls.ca_cert {
        options = options.add_root_certificates(ca_cert.clone());
    }

    if let (Some(cert), Some(key)) = (&tls.client_cert, &tls.client_key) {
        options = options.add_client_certificate(cert.clone(), key.clone());
    }

    options
}
