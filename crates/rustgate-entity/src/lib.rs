// Copyright © 2026 Roberto Chiofalo.

//! Canonical, protocol-agnostic entity model for rustgate.
//!
//! This crate is the standalone home the canonical [`Entity`] type is
//! migrating into. Today the model still lives in
//! [`rustgate_core::entity`] — where it began as an in-core scaffold
//! under closed issue #847 — and this crate is a **re-export shim**
//! that lets downstream code start depending on `rustgate-entity` at
//! the eventual import path *before* any type physically moves out of
//! core. See [ADR 0028](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0028-canonical-entity-crate.md)
//! for the decision and the phased migration plan (refs #1535).
//!
//! # What this crate is (and is not) today
//!
//! This is the **first slice** of a multi-PR migration. In this state
//! the crate moves **no** code out of `rustgate-core`: it simply
//! re-exports the existing seam
//! ([`Entity`], [`EntityKind`], [`Position`], [`Velocity`],
//! [`AttributeValue`], [`EntityCodec`], [`DynEntityCodec`],
//! [`EntityCodecRegistry`]) so the ~20 crates that consume the model
//! keep compiling unchanged while new code can begin importing from
//! `rustgate_entity::*`. When the type migration lands, the definitions
//! move here and `rustgate-core` re-exports them for backward
//! compatibility — the inverse of the shim direction today, with no
//! flag-day break for consumers either way.
//!
//! # Why a standalone crate at all
//!
//! The model is shared by 13 protocol codecs (CoT, MAVLink, ASTERIX,
//! STANAG-4586, Link 16, DIS, SAPIENT, NFFI, VMF, Meshtastic, and the
//! declarative `SchemaCodec`), the correlation/inference pipeline, and
//! the partner bridges. Two sources of fragmentation motivate lifting
//! it out of `rustgate-core`:
//!
//! - `rustgate-lattice` defines its **own** `Entity` / `EntityKind`
//!   in `bridge.rs` with no dependency on the core model.
//! - `rustgate-foundry` and `rustgate-dds` each duplicate an
//!   `EntityOverlay` mapper type.
//!
//! A dedicated crate gives those partner integrations a single,
//! dependency-light target to converge on without pulling in the whole
//! of `rustgate-core`. The convergence itself is deferred to follow-up
//! PRs tracked under the epic — this crate only establishes the seam.

// The canonical model still lives in `rustgate-core` for this slice.
// Re-export it verbatim so `rustgate_entity::Entity` (and the rest of
// the seam) resolves to the same types every existing consumer already
// uses — a zero-cost alias, not a fork. This is what keeps the two
// import paths interchangeable during the migration.
pub use rustgate_core::entity::{
    AttributeValue, DynEntityCodec, DynEntityCodecError, Entity, EntityCodec, EntityCodecRegistry,
    EntityKind, Position, Velocity,
};

/// Convenience re-exports for code adopting the canonical entity model.
///
/// Downstream crates migrating onto `rustgate-entity` import the whole
/// surface with `use rustgate_entity::prelude::*;`. Keeping the glob
/// import behind a `prelude` module (rather than at the crate root)
/// means the migration-target import path is stable even as individual
/// items move from `rustgate-core` into this crate: consumers pin the
/// `prelude`, and the module's contents are what shifts underneath.
///
/// # Migration target
///
/// The trait every protocol crate implements is [`EntityCodec`]; the
/// object-safe registry the router dispatches through is
/// [`EntityCodecRegistry`]. Both are re-exported here today from
/// `rustgate-core` and will resolve to the in-crate definitions once
/// the types move, without any change at the call site.
///
/// ```
/// use rustgate_entity::prelude::*;
///
/// // The canonical `Entity` shape resolves through the shim — this is
/// // the same type `rustgate_core::entity::Entity` names today, and it
/// // will keep resolving after the type migration lands.
/// fn takes_entity(_e: &Entity) {}
///
/// // An empty registry is the router's short-circuit state (no codecs
/// // registered means the entity-surface lookup is skipped entirely).
/// let registry = EntityCodecRegistry::new();
/// assert!(registry.is_empty());
/// ```
pub mod prelude {
    pub use rustgate_core::entity::{
        AttributeValue, DynEntityCodec, DynEntityCodecError, Entity, EntityCodec,
        EntityCodecRegistry, EntityKind, Position, Velocity,
    };
}
