// Copyright © 2026 Roberto Chiofalo.

//! Shared types and utilities for the rustgate workspace.
//!
//! This crate provides the foundational types used across all rustgate crates:
//! [`identity::Identity`] for client authentication, [`message::RoutableMessage`]
//! for the internal message envelope, [`error`] types, [`audit`] logging, and
//! [`protocol`] framing definitions. No crate in the workspace depends on
//! anything above `rustgate-core`.

pub mod audit;
pub mod audit_chain;
pub mod b64;
pub mod codec;
pub mod constants;
pub mod encrypted;
pub mod error;
pub mod identity;
pub mod masking;
pub mod message;
pub mod net;
pub mod peer_id;
#[cfg(feature = "pem")]
pub mod pem;
pub mod protocol;
pub mod sanitize;
pub mod tasks;

pub use identity::AttrValue;
pub use peer_id::{PeerId, ServerName};
