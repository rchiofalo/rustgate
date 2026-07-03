// Copyright © 2026 Roberto Chiofalo.

//! Certificate enrollment for rustgate.
//!
//! HTTPS endpoint (no client cert required) that accepts a username/password
//! and PKCS#10 CSR, signs it with the server CA, and returns a client
//! certificate. Implements the Marti-compatible certificate signing flow
//! so TAK clients can self-provision without manual `.p12` distribution.
//!
//! # Error handling
//!
//! This crate's error type is [`error::EnrollmentError`]; binary callers
//! in `rustgate-server` propagate it via `?` and map it through
//! `anyhow::Error` at the orchestration layer.
//! [`rustgate_core::error::RustgateError`] is the boundary aggregator for
//! the `rustgate-core` / `rustgate-transport` slice and is not
//! automatically constructed from [`error::EnrollmentError`].

pub mod auth;
pub mod ca_algorithm;
#[cfg(feature = "est")]
pub mod cms_bag;
pub mod contacts;
pub mod datapackage;
pub mod error;
#[cfg(feature = "est")]
pub mod est;
mod handlers;
mod keypair;
pub mod pkcs12;
pub mod response;
pub mod revocation;
pub mod server;
pub mod signing;

pub use auth::Credentials;
pub use ca_algorithm::{CaAlgorithm, ParseCaAlgorithmError};
pub use contacts::{ContactInfo, ContactsProvider, cached_contacts_provider};
pub use datapackage::DataPackageStore;
pub use error::EnrollmentError;
pub use revocation::RevocationStore;
pub use server::{
    DEFAULT_SIGN_RATE_LIMIT, DEFAULT_SIGN_RATE_WINDOW, EnrollmentServer, RateLimitCallback,
};
pub use signing::{CsrSigner, fips_pq_conflict, issue_mldsa_unavailable};
