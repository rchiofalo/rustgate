// Copyright © 2026 Roberto Chiofalo.

//! Shared resilience primitives for rustgate.
//!
//! Consolidates the circuit-breaker, backoff, and rate-limiting building
//! blocks that were previously duplicated (or near-duplicated) across
//! `rustgate-http`, `rustgate-federation`, and `rustgate-core`. Every
//! primitive here is transport-agnostic: no `reqwest`, `tonic`, `rustls`,
//! or project-specific types leak in.
//!
//! ## Modules
//!
//! - [`backpressure`] — global byte-count admission gate with dwell-based
//!   resume semantics (moved from `rustgate-transport` so every egress
//!   publisher can share the same primitive without taking a transport
//!   dependency).
//! - [`circuit`] — three-state circuit breaker (Closed → Open → HalfOpen)
//!   with probe limiting and configurable recovery threshold.
//! - [`retry`] — exponential backoff with random jitter for request-level
//!   retry loops, plus a small helper for classifying retryable HTTP status
//!   codes.
//! - [`reconnect`] — exponential backoff without jitter for long-lived
//!   client reconnections, plus `should_stop_reconnecting` for bounded
//!   retry policies.
//! - [`token_bucket`] — per-target token-bucket rate limiter with lazy
//!   refill. Fail-open on mutex poisoning to match workspace convention.
//! - [`conn_rate_limiter`] — per-IP sliding-window connection rate limiter
//!   used by plaintext-protocol listeners (MQTT, WebSocket).
//!
//! ## Feature flags
//!
//! - `metrics` — exposes internal state accessors (e.g. the circuit
//!   breaker's current state as a `u8`) required by Prometheus gauges in
//!   consuming crates.

pub mod backpressure;
pub mod circuit;
pub mod conn_rate_limiter;
pub mod reconnect;
pub mod retry;
pub mod token_bucket;
