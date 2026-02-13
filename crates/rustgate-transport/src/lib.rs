//! TLS/mTLS listener and connection management for rustgate.
//!
//! This crate provides mTLS-authenticated connections with identity extraction
//! from X.509 client certificates. CN becomes the user identity, and OU fields
//! become group memberships for authorization decisions.

mod config;
mod extract;
mod listener;
mod session;

pub use config::TlsConfig;
pub use extract::extract_identity;
pub use listener::TlsListener;
pub use session::{AuthenticatedSession, SessionReader, SessionWriter};
