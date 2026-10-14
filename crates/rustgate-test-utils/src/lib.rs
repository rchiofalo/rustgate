// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
