//! Subscribes to NATS for messages destined to locally connected TAK clients.

/// Receives messages from NATS and delivers them to local sessions.
#[derive(Debug)]
pub struct NatsSubscriber;
