// Copyright © 2026 Roberto Chiofalo.

//! Shared configuration utilities used across the workspace.
//!
//! This module is the home for cross-crate configuration concerns that
//! every crate that loads operator-supplied configuration would
//! otherwise reinvent. Today it exposes [`validate`] — a small set of
//! reusable validators (`validate_port`, `validate_duration_secs_in_range`,
//! `validate_path_exists`, `validate_non_empty`) that downstream crates
//! call from their own `validate()` methods so range / non-empty /
//! file-existence checks have one canonical implementation and one
//! canonical error shape.
//!
//! # When to use what
//!
//! - **Struct definition lives in your crate.** The shape of the config
//!   struct (field names, types, defaults, `serde` attributes) stays in
//!   the crate that owns it. This module never tries to homogenise that.
//! - **`#[serde(deny_unknown_fields)]` on every operator-facing config
//!   struct.** Reject typos at parse time. The discipline is workspace-
//!   wide and is enforced field-by-field in each crate's own struct.
//! - **Range / non-empty / existence checks delegate here.** Inside your
//!   `validate(&self)` method, call into [`validate::validate_port`],
//!   [`validate::validate_duration_secs_in_range`], etc., so a future
//!   tweak (e.g. tightening the message format) lands once and every
//!   downstream caller sees the new behaviour.
//!
//! See `rules/shared-infrastructure.md` for the broader workspace
//! discipline and the decision table for which helper to reach for.

pub mod validate;
