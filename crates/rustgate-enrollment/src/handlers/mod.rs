//! HTTP request handlers for the enrollment server.
//!
//! Each sub-module groups related endpoint handlers by domain:
//! - `sign` — CSR signing (v1 and v2)
//! - `api` — Marti API compatibility endpoints (contacts, groups, missions, etc.)
//! - `packages` — data package upload, download, and search
//! - `util` — shared response building and query parameter helpers

pub(crate) mod api;
pub(crate) mod packages;
pub(crate) mod sign;
pub(crate) mod util;
