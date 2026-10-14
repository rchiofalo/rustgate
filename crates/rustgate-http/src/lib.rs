// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! HTTP/webhook egress bridge for rustgate.
//!
//! Forwards routable messages to configured HTTP endpoints (webhooks,
//! REST APIs, SIEM collectors) with per-target authentication, TLS,
//! filtering, retry with exponential backoff, and circuit breaking.
//!
//! # Architecture
//!
//! The [`HttpPublisher`] is the primary entry point. It accepts
//! [`RoutableMessage`](rustgate_core::message::RoutableMessage)s via a
//! fire-and-forget [`publish`](HttpPublisher::publish) method, dispatching
//! them through a bounded internal channel to a background worker task
//! that fans out to all matching targets.
//!
//! # Security
//!
//! - **Authentication**: Bearer token, HTTP Basic, or HMAC-SHA256 request
//!   signing (with timestamp binding for replay prevention). All secrets
//!   loaded from files, wrapped in [`Zeroizing`](zeroize::Zeroizing).
//! - **TLS**: Per-target custom CA, mTLS client certificates, and
//!   optional SHA-256 certificate pinning (defense against CA compromise).
//! - **SSRF protection**: Private/loopback IP addresses are rejected at
//!   both config validation time and DNS resolution time (rebinding defense).
//! - **Rate limiting**: Per-target token-bucket rate limiter prevents
//!   upstream flooding.
//! - **Dead-letter queue**: Undeliverable messages are encrypted with
//!   ChaCha20-Poly1305 and persisted for forensic recovery.
//!
//! # Feature Flags
//!
//! - `metrics` — Enables Prometheus metric collection for publish
//!   counts, error rates, request latency, and circuit breaker state.
//! - `proto` — Enables protobuf payload serialization via `rustgate-proto`.
//! - `otel` — Enables OpenTelemetry trace context propagation (`traceparent`
//!   / `tracestate` headers) on outbound requests.
//! - `fips` — Uses aws-lc-rs in FIPS mode for outbound TLS.
//! - `post-quantum` — Enables post-quantum key exchange (X25519MLKEM768)
//!   for outbound TLS connections.
//!
//! # Error handling
//!
//! This crate's error type is [`error::HttpError`]; binary callers in
//! `rustgate-server` propagate it via `?` and map it through
//! `anyhow::Error` at the orchestration layer.
//! [`rustgate_core::error::RustgateError`] is the boundary aggregator for
//! the `rustgate-core` / `rustgate-transport` slice and is not
//! automatically constructed from [`error::HttpError`].

pub(crate) mod auth;
pub(crate) mod batch;
pub mod config;
pub(crate) mod dlq;
pub mod dlq_reader;
pub mod error;
pub(crate) mod filter;
pub(crate) mod geojson;
#[cfg(feature = "metrics")]
pub mod metrics;
pub(crate) mod payload;
pub(crate) mod pinning;
mod publisher;
pub(crate) mod resolver;

pub use config::HttpConfig;
pub use error::HttpError;
pub use publisher::{HttpPublisher, TriggerDrainError};
