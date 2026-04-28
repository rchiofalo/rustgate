// Copyright © 2026 Roberto Chiofalo.

//! Shared types and utilities for the rustgate workspace.
//!
//! This crate provides the foundational types used across all rustgate crates:
//! [`identity::Identity`] for client authentication, [`message::RoutableMessage`]
//! for the internal message envelope, [`error`] types, [`audit`] logging, and
//! [`protocol`] framing definitions. No crate in the workspace depends on
//! anything above `rustgate-core`.
//!
//! # Error handling
//!
//! [`error::RustgateError`] is the boundary aggregator wrapping
//! [`error::TransportError`] / [`error::ConfigError`] / [`std::io::Error`].
//! It is the return type used inside the `rustgate-core` /
//! `rustgate-transport` / `rustgate-websocket` slice via the
//! [`error::Result`] alias. Other library crates (`rustgate-http`,
//! `rustgate-mqtt`, `rustgate-enrollment`, `rustgate-mavlink`,
//! `rustgate-stanag4586`, `rustgate-asterix`, `rustgate-cot`,
//! `rustgate-authz`, `rustgate-proto`, `rustgate-client`) define their
//! own typed `*Error` enums — [`error::RustgateError`] is **not**
//! automatically constructed from those per-crate types. Binary callers
//! in `rustgate-server` propagate every error via `?` and surface them
//! through `anyhow::Error` at the orchestration layer.

pub mod audit;
pub mod audit_chain;
pub mod b64;
pub mod callbacks;
pub mod codec;
pub mod config;
pub mod constants;
pub mod crypto;
pub mod egress;
pub mod encrypted;
pub mod error;
pub mod identity;
pub mod masking;
pub mod message;
#[cfg(feature = "metrics")]
pub mod metrics_util;
pub mod net;
pub mod peer_id;
#[cfg(feature = "pem")]
pub mod pem;
pub mod protocol;
pub mod sanitize;
pub mod secrets;
pub mod tasks;

pub use crypto::{HmacError, hmac_sha256_tag, hmac_sha256_verify};
pub use identity::AttrValue;
pub use masking::hash_cn;
pub use peer_id::{PeerId, ServerName};
pub use sanitize::sanitize_for_log;
pub use secrets::{SecretFileError, SecretFileOpts, read_secret_file};
