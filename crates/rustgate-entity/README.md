# rustgate-entity

Canonical, protocol-agnostic entity model for rustgate — the standalone
home the shared `Entity` type is migrating into.

## Role in the workspace

Every protocol rustgate speaks decodes its native wire format into a
single normalized shape (`Entity`) and re-encodes from it, so the
router, position cache, dedup, ACL, and authz layers can operate on one
type regardless of inbound protocol. That model — `Entity`, its
supporting enums (`EntityKind`, `Position`, `Velocity`,
`AttributeValue`), the `EntityCodec` trait, its object-safe
`DynEntityCodec` form, and the `EntityCodecRegistry` — lives in
`rustgate-core` today, where it began as an in-core scaffold under
issue #847.

This crate lifts that model out of the foundation crate so it can evolve
(and eventually reabsorb the descoped #847 richness — a UUIDv7 `id`,
`Affiliation`, provenance, confidence, relationships) and give the
partner bridges a dependency-light convergence target, without dragging
in the whole of `rustgate-core`. See
[ADR 0028](../../docs/adr/0028-canonical-entity-crate.md) for the
decision and the phased migration plan.

## Current state — re-export skeleton

This is the **first slice** of a multi-PR migration (refs #1535). Today
the crate moves **no** code out of `rustgate-core`: it re-exports the
existing seam so downstream code can begin importing from
`rustgate_entity::*` at the eventual home path while the ~20 existing
consumers keep compiling unchanged.

```rust
use rustgate_entity::prelude::*;

let registry = EntityCodecRegistry::new();
assert!(registry.is_empty());
```

When the type migration lands, the definitions move here and
`rustgate-core` re-exports them for backward compatibility — the inverse
of the shim direction today, with no flag day for consumers either way.

## Migration phases

1. **Crate skeleton (this crate today).** Re-export shim; no type moves.
2. **Re-export shim in core.** Definitions move here; `rustgate-core`
   re-exports for compatibility.
3. **Codec migration.** Point the 13 codec crates at
   `rustgate_entity::EntityCodec` directly.
4. **Partner-bridge unification.** Converge the divergent
   `rustgate-lattice` `Entity` / `EntityKind` and the duplicated
   `rustgate-foundry` / `rustgate-dds` `EntityOverlay` onto the
   canonical model.
