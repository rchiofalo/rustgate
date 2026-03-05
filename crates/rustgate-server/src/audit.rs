//! Audit logging re-exports from `rustgate-core`.
//!
//! This module re-exports the shared audit functions so callers in
//! `rustgate-server` continue to use `audit::*` without path changes.

pub use rustgate_core::audit::*;
