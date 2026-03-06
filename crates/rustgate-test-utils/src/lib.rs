//! Test utilities for rustgate.
//!
//! Provides X.509 certificate generation for integration tests.
//! CN maps to user identity, OU fields map to group membership.
//!
//! Enable the `nats` feature for [`TestNatsServer`](nats::TestNatsServer) —
//! a managed `nats-server` subprocess for NATS integration tests.

pub mod certs;

#[cfg(feature = "nats")]
pub mod nats;
