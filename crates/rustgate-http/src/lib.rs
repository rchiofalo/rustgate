// Copyright © 2026 Roberto Chiofalo.

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
//! # Feature Flags
//!
//! - `metrics` — Enables Prometheus metric collection for publish
//!   counts, error rates, request latency, and circuit breaker state.

pub(crate) mod circuit;
pub mod config;
pub mod error;
pub(crate) mod filter;
pub(crate) mod payload;
pub(crate) mod retry;

pub use config::HttpConfig;
pub use error::HttpError;

// Placeholder — publisher, auth, circuit, retry, metrics modules
// will be added in subsequent commits.

/// Placeholder publisher type for early compilation checks.
///
/// Will be replaced with the full implementation in a later commit.
#[derive(Debug, Clone)]
pub struct HttpPublisher;
