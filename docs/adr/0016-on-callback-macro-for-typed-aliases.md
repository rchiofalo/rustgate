# ADR 0016: `on_callback!` macro for `Arc<dyn Fn>` callback type aliases

- **Status:** Accepted
- **Date:** 2026-05-06
- **Related:** `crates/rustgate-core/src/callbacks.rs`,
  `.claude/rules/shared-infrastructure.md` "Callback Type Aliases",
  PR #1261, issue #840 (F-107)

## Context

The rustgate workspace uses dozens of `Arc<dyn Fn(...) + Send + Sync>`
type aliases — `OnConnected`, `OnRouted`, `OnAuthzDenied`,
`OnHttpPublishFailed`, `OnFederationCircuitTripped`, and so on, plus
the various `*Fn` forwarding callbacks and `*Provider` factories.
The pattern is necessary because transport crates (`rustgate-transport`,
`rustgate-federation`, `rustgate-http`) hand off audit, metric, and
routing observers to the server binary without taking on a
`prometheus` or `tonic` dependency. Every alias has the identical
shape — only the parameter list changes:

```rust
pub type OnFoo = Arc<dyn Fn(Args...) + Send + Sync>;
```

Hand-writing each alias is a small but real source of drift:

- A missing `+ Send` makes the type unable to cross a
  `tokio::spawn` boundary, but the failure mode is a confusing
  `Send` bound error at the call site rather than a clear "the
  alias is wrong" diagnostic at definition time.
- An accidental `Box` instead of `Arc` breaks the workspace
  pattern of installing one observer and `Arc::clone`-ing it
  into each call site.
- A `'static` lifetime added "to make the borrow checker happy"
  silently changes the contract — the alias goes from "a callable
  observer" to "a borrowed callable observer that the caller has
  to keep alive". Reviewers do catch this, but only if they
  notice.
- A return type added in one alias but not the rest creates a
  family of "almost the same shape" types that subsequent
  refactors have to special-case.

Issue #840 (F-107) collected the 26+ aliases and proposed pinning
the shape with a declarative macro. PR #1261 landed the macro and
migrated the existing aliases to it.

## Decision

The `rustgate_core::on_callback!` macro is the canonical way to
declare a fire-and-forget observer alias. It produces exactly:

```rust
pub type Name = std::sync::Arc<dyn Fn(Args...) + Send + Sync>;
```

with three guarantees pinned at definition time:

- **`std::sync::Arc<...>`** — never `Box`. Callbacks are cloneable
  and shareable across tasks.
- **`dyn Fn(...)`** — never `FnMut` or `FnOnce`. Observers are
  pure functions of their arguments. Shared mutable state lives
  in an `Arc<Mutex<...>>` captured by the closure body, not in
  the trait.
- **`+ Send + Sync`** — required because callbacks routinely
  cross `tokio::spawn` boundaries and ride inside `ArcSwap`
  slots loaded from multiple worker threads.
- **No return type.** The macro is for fire-and-forget observers.

Aliases declared via the macro look like:

```rust
on_callback! {
    /// Fired when a federation peer transitions to connected.
    pub type OnFederationPeerConnected = Fn(&PeerId, &SocketAddr);
}
```

Hand-written aliases remain acceptable when the alias genuinely
needs a return type (a status snapshot, a future, a trust-store
provider) — for those, the macro is intentionally insufficient and
the hand-written form keeps the return type and any
`Pin<Box<dyn Future<Output = ...>>>` plumbing visible to readers.

The async question — "should the callback return a `Future`?" —
is answered by **no**. `dyn AsyncFn` is not object-safe as of Rust
1.94, and `Pin<Box<dyn Future>>` returning callbacks couple the
observer's lifetime to whatever runtime is awaiting it. Async
work inside a callback is dispatched via
[`spawn_background`](0010-spawn-background-and-subsystem-handle.md)
inside the closure body. The macro therefore produces only the
synchronous `Fn` form.

## Alternatives considered

- **Hand-written aliases (status quo before #1261).** The form
  this ADR replaces. Rejected because the drift listed above is
  what the macro exists to prevent — a single missing `+ Send`
  on one alias is a confusing failure mode at the call site, and
  the manual approach requires every reviewer to mentally pattern-
  match each alias against the workspace shape.
- **Procedural macro.** Rejected: a `proc_macro` crate would
  require its own `Cargo.toml` and a separate compilation unit,
  in exchange for behaviour the declarative macro already covers.
  The aliases all fit the declarative form.
- **A trait-based observer pattern** (`trait Observer { fn
  on_event(...) }`). Rejected: every observer would need a
  zero-sized impl type, and the workspace's preference for
  closures-with-captured-state would lose its ergonomics.
- **Allow `dyn AsyncFn` via a future Rust feature.** Out of
  scope: the language has not stabilised object-safe async
  closures, and the workspace targets stable Rust.

## Consequences

- New observer aliases use the macro. Existing aliases were
  migrated by PR #1261; the form is uniform across crates.
- The macro is exported from `rustgate-core` and re-exported by
  every crate that defines aliases. The import path is
  `rustgate_core::on_callback`.
- The macro does not produce trait impls — it is purely a type-
  alias generator. Authors who want to attach helper methods to a
  callback alias write a separate `impl` block on the alias name.
- Reviewers push back on hand-written aliases that do not need
  the escape hatch (return type, async future). Grep for
  `pub type On.*= Arc<dyn Fn` is the discriminator; every match
  outside the macro should be substantiated by a comment naming
  the reason.
- The macro's guarantees are documented at its declaration site
  in `crates/rustgate-core/src/callbacks.rs`. Future contributors
  who want to relax one of the guarantees (drop `+ Sync`, add a
  return type) should think carefully about whether the change
  belongs in the macro or in a hand-written escape-hatch alias.
- F-107 was tracked under issue #840 alongside F-109 (this ADR
  collection's reframing of `shared-infrastructure.md`) and
  F-113 (`PeerId` / `ServerName` discipline, shipped via #1248).
  All three are infrastructure-consistency items; the umbrella
  closes when the ADR migration lands.
