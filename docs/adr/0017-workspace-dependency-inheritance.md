# ADR 0017: Workspace dependency inheritance for every crate

- **Status:** Accepted
- **Date:** 2026-05-06
- **Related:** root `Cargo.toml`,
  `.claude/rules/shared-infrastructure.md` "Workspace Dependencies"

## Context

A workspace with sixteen crates can declare its dependencies in two
shapes:

1. **Per-crate.** Each `crates/<crate>/Cargo.toml` carries the full
   `[dependencies]` block. Versions, features, and `default-features`
   are repeated per crate.
2. **Workspace inheritance.** The root `Cargo.toml` declares every
   external dependency once under `[workspace.dependencies]` with
   the canonical version, feature set, and `default-features`
   policy. Each crate references the dep with `dep = { workspace =
   true }`, optionally adding crate-local features via
   `dep = { workspace = true, features = ["..."] }`.

The per-crate shape is the historical default and the one Cargo
samples in introductory documentation. It works fine for a
single-crate project. It fails badly for a sixteen-crate workspace:

- **Version drift.** Two crates with different `tokio = "1.40"`
  / `tokio = "1.42"` lines compile, but the resolver picks one
  and the other crate gets a newer version than its author
  tested against. Subtle behaviour differences (a deprecated
  feature in one, a new lint in the other) ship without anyone
  noticing.
- **Feature drift.** `serde = { version = "1", features = ["derive"] }`
  in one crate and `serde = "1"` in another both compile, but
  the unified feature set is the union — every dependent silently
  gets `derive` even if their author intentionally avoided it.
  The drift surfaces as bigger binaries and slower builds, not
  as compile errors.
- **`default-features` discipline breaks down.** A common
  pattern is to disable default features on a security-relevant
  dep (e.g. `rustls = { version = "0.23", default-features =
  false, features = ["tls12", "ring"] }`). Per-crate
  declarations make this declarative discipline easy to forget
  on a new crate.
- **Cargo audit drift.** `cargo deny` and `cargo audit` parse the
  resolved tree, not the declared deps. Per-crate drift makes
  it hard for a reviewer to answer "what version of `tokio` are
  we shipping?" from the manifest alone.
- **Upgrade fan-out.** Bumping `serde` from 1.0.197 to 1.0.198
  in a sixteen-crate workspace touches sixteen files. Bumping
  it in a workspace-inheritance setup touches one.

Cargo's `[workspace.dependencies]` (stable since 1.64) is the
direct fix for all of the above.

## Decision

Every external dependency is declared exactly once in the root
`Cargo.toml` under `[workspace.dependencies]` with the canonical
version, feature set, and `default-features` policy. Per-crate
references are `dep = { workspace = true }`, optionally with
crate-local features added via `dep = { workspace = true, features
= ["extra"] }`.

Concretely:

- The root `Cargo.toml` lists ~120 external crates today, every
  one with a pinned version and a deliberate feature set.
- Per-crate `Cargo.toml` files contain only `dep = { workspace =
  true }` references plus the crate-internal sibling deps (e.g.
  `rustgate-core = { path = "../rustgate-core" }`).
- Optional dependencies in a crate use the same shape:
  `dep = { workspace = true, optional = true }`. The crate's
  feature flags (`[features]`) gate the dep just as they would
  for a per-crate declaration.
- The MSRV (`rust-version = "1.99"`) is declared once at the
  workspace root and inherited via `rust-version.workspace =
  true` in each crate. Same for `edition`, `license`, and
  `repository`.

The pattern is documented in
`.claude/rules/shared-infrastructure.md` "Workspace Dependencies":

> ALL deps use workspace inheritance. Never add deps directly to
> a crate.

Reviewers push back on PRs that introduce a per-crate `[dependencies]`
entry that bypasses the workspace declaration.

## Alternatives considered

- **Per-crate `[dependencies]` (status quo before workspace
  inheritance was stable).** Rejected for the drift reasons
  above. The friction of bumping a version in sixteen places is
  the small problem; the silent feature-set unification is the
  big problem.
- **A central `dependencies.toml` checked in alongside `Cargo.toml`.**
  This was the workaround in the pre-1.64 era. Rejected now
  that workspace inheritance is stable — there is no reason to
  reinvent a feature Cargo provides natively.
- **Allow per-crate overrides for "fast-moving" deps.** Rejected:
  the override path is exactly where drift creeps in. Crates
  that genuinely need a different version of a dep than the
  rest of the workspace are a smell — usually the right move is
  to upgrade the workspace, not fork the crate's dep tree.
- **Use a `cargo workspaces` external tool.** Workable but
  unnecessary. The native Cargo feature does what we need.

## Consequences

- Every dependency upgrade is one edit in the root manifest. The
  resolver picks the new version for every crate that imports it;
  CI runs the full test matrix once. Drift is impossible by
  construction — there is no second declaration to drift away
  from.
- The root manifest is the canonical answer to "what version of
  X are we shipping?". `cargo deny` and `cargo audit` consume
  the resolved tree directly, but a reviewer who wants to spot-
  check the declared version goes to one file.
- Adding a new external dep is a two-step diff: add the entry to
  `[workspace.dependencies]` in the root, then add the
  `{ workspace = true }` reference in the consuming crate. PRs
  that skip the first step fail at compile time with a clear
  "no such workspace dependency" diagnostic.
- Per-crate feature flags continue to work. A crate that wants
  the `tokio` `process` feature on top of the workspace-default
  feature set writes `tokio = { workspace = true, features =
  ["process"] }`. The `features` here are *added* to the
  workspace feature set; `default-features = false` at the
  workspace level remains in force unless the crate explicitly
  opts back in.
- Crate-internal sibling references (`rustgate-core = { path =
  "../rustgate-core" }`) are still per-crate. The workspace-
  inheritance pattern is for *external* dependencies; internal
  path references are inherently per-crate because the path is
  relative.
- If a future crate genuinely needs a divergent version of an
  external dep, the right move is a workspace-level `[patch]`
  entry plus a comment explaining why, not a per-crate
  override. We have not needed this in practice.
