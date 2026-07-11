// Copyright © 2026 Roberto Chiofalo.

//! Test utilities for rustgate.
//!
//! Provides X.509 certificate generation for integration tests.
//! CN maps to user identity, OU fields map to group membership.
//!
//! Enable the `nats` feature for `TestNatsServer` —
//! a managed `nats-server` subprocess for NATS integration tests.

pub mod certs;
pub mod tls;

#[cfg(feature = "mldsa")]
pub mod mldsa;

#[cfg(feature = "nats")]
pub mod nats;
