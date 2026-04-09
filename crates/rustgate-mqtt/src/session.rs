//! Per-connection MQTT session state machine.
//!
//! Handles the CONNECT handshake, PUBLISH/SUBSCRIBE/PINGREQ/DISCONNECT
//! packet processing, and read/write loops. Each session registers with
//! the [`Router`](rustgate_transport::Router) and receives routed messages
//! for delivery to the MQTT client.
