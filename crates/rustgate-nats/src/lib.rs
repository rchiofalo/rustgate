//! NATS adapter for rustgate.
//!
//! Bridges local TAK sessions to a NATS event bus, enabling stateless
//! horizontal scaling. Publishes inbound CoT to NATS subjects and
//! subscribes for outbound delivery to connected clients.

mod publisher;
mod subscriber;

pub use publisher::NatsPublisher;
pub use subscriber::NatsSubscriber;
