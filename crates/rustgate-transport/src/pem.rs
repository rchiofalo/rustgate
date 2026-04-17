// Copyright © 2026 Roberto Chiofalo.

//! PEM parsing helpers — re-exported from [`rustgate_core::pem`].
//!
//! This module used to own the `parse_certs` / `parse_key` /
//! `parse_ca_store` helpers. They now live in [`rustgate_core::pem`] so
//! `rustgate-client`, `rustgate-federation`, and `rustgate-enrollment`
//! can share the same error mapping. This module stays as a thin facade
//! for backward compatibility with existing imports.
//!
//! New callers should import directly from `rustgate_core::pem`.

pub use rustgate_core::pem::{parse_ca_store, parse_certs, parse_key};
