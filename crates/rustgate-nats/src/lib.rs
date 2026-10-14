// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! NATS adapter for rustgate.
//!
//! Bridges local sessions to a NATS event bus, enabling stateless
//! horizontal scaling. Publishes inbound messages to NATS subjects and
//! subscribes via JetStream pull consumers for outbound delivery to
//! connected clients with real backpressure.
//!
//! # Error handling
//!
//! This crate does not expose a single umbrella `NatsError`; each
//! submodule with a distinct failure surface defines its own typed enum
//! (e.g. [`NatsConfigError`], [`NatsTlsConfigError`], [`RequestError`]).
//! Binary callers in `rustgate-server` propagate these via `?` and
//! surface them through `anyhow::Error` at the orchestration layer;
//! [`rustgate_core::error::RustgateError`] is the boundary aggregator for
//! the `rustgate-core` / `rustgate-transport` slice and is not
//! automatically constructed from this crate's per-submodule errors.

pub mod config;
pub mod jetstream;
pub mod publisher;
pub mod request;
pub mod serde_compat;
pub mod subscriber;

pub use config::{NatsConfig, NatsConfigError, NatsTlsConfig, NatsTlsConfigError};
pub use jetstream::JetStreamReplay;
pub use publisher::NatsPublisher;
pub use request::{
    ERROR_HEADER, NatsRequestClient, NatsRequestHandler, NatsRequestResponder, RequestError,
};
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

    /// Create a request/reply client over the existing NATS connection.
    ///
    /// Always available — the client is a thin wrapper over
    /// [`async_nats::Client::send_request`] and does not require any
    /// configuration. See [`NatsRequestClient`] for the full API.
    pub fn request_client(&self) -> NatsRequestClient {
        NatsRequestClient::new(self.client.clone())
    }

    /// Create a request/reply responder bound to the configured
    /// `request_subject`.
    ///
    /// Returns `None` when the configuration does not set
    /// [`NatsConfig::request_subject`] — this is the signal that the
    /// operator did not opt in to running a responder, so the caller
    /// should skip wiring the handler.
    ///
    /// The returned responder has not yet subscribed — call
    /// [`NatsRequestResponder::run`] on a background task to start
    /// processing requests.
    pub fn request_responder(&self, handler: NatsRequestHandler) -> Option<NatsRequestResponder> {
        let subject = self.config.request_subject.clone()?;
        Some(NatsRequestResponder::new(
            self.client.clone(),
            subject,
            handler,
        ))
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
