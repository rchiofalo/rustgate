# ADR 0008: `std::sync::OnceLock` over `once_cell::sync::Lazy`

- **Status:** Accepted
- **Date:** 2026-04-27
- **Related:** `clippy.toml`, `.claude/rules/shared-infrastructure.md`
  "Metrics Pattern"

## Context

rustgate has many static singletons: every Prometheus metric (one
per metric name across `rustgate-server`, `rustgate-federation`,
`rustgate-http`, etc.), the global tracing subscriber, and a
handful of cached configuration values. Two equally valid patterns
exist in modern Rust:

- **`once_cell::sync::Lazy<T>`** — a third-party crate that wraps
  the singleton with an init closure. The first access lazily
  evaluates the closure; subsequent accesses return the cached
  value.
- **`std::sync::OnceLock<T>`** — the standard library equivalent
  (stable since Rust 1.70). Uses an explicit `init()` function
  plus an accessor.

They are not interchangeable in style. `once_cell::sync::Lazy`
rolls the init into the static itself:

```rust
static METRIC: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new("name", "help")).expect("...")
});
```

`std::sync::OnceLock` separates declaration from initialization:

```rust
static METRIC: OnceLock<IntCounter> = OnceLock::new();

pub fn init() -> prometheus::Result<()> {
    let metric = IntCounter::with_opts(Opts::new("name", "help"))?;
    prometheus::default_registry().register(Box::new(metric.clone()))?;
    let _ = METRIC.set(metric);
    Ok(())
}

pub fn metric() -> &'static IntCounter {
    METRIC.get_or_init(|| /* fallback */)
}
```

The `OnceLock` shape returns a `Result` from `init()`. The `Lazy`
shape forces init failures to panic inside the closure, because the
closure has no `Result` return path. With `clippy::panic = "deny"`
and `clippy::unwrap_used = "deny"` in production code, that means
every `Lazy::new` closure has to bend around the lint with an
`expect()` and a justification — and even then, the failure mode
(panic on first metric access) is worse than the `OnceLock`
fallback shape (registration error returned at startup, accessor
falls back to a sane default).

## Decision

Static singletons in the workspace use `std::sync::OnceLock<T>`.
The canonical pattern, used identically by every Prometheus metric
module across the workspace, is:

1. Declare the singleton as `static FOO: OnceLock<T> = OnceLock::new();`
2. Provide a fallible `init()` function that registers the value
   and returns `prometheus::Result<()>` (or the analogous typed
   error for the surface).
3. Provide an `accessor() -> &'static T` that returns the value,
   using `get_or_init(|| /* fallback */)` for cases where the
   accessor may fire before `init()` has run.

`once_cell::sync::Lazy` and `once_cell::sync::OnceCell` are banned
workspace-wide via `clippy.toml`:

```toml
disallowed-types = [
    { path = "once_cell::sync::Lazy", reason = "use std::sync::OnceLock — see rules/shared-infrastructure.md metrics pattern" },
    { path = "once_cell::sync::OnceCell", reason = "use std::sync::OnceLock — see rules/shared-infrastructure.md metrics pattern" },
]
```

The clippy diagnostic surfaces the `reason` field, so a
contributor who reaches for `Lazy` without reading this ADR sees a
pointer to the workspace pattern.

## Alternatives considered

- **`once_cell::sync::Lazy`.** Rejected because (a) it forces panic
  on init failure, which fights `clippy::unwrap_used`, and (b) it
  is a third-party crate solving a problem the standard library
  already solves on stable.
- **A custom thread-safe singleton primitive.** Rejected: the
  workspace would gain a non-trivial maintenance burden in
  exchange for behaviour identical to `OnceLock`.
- **Global `Mutex<Option<T>>` initialised once at startup.**
  Workable but adds a lock to every read, which matters on the
  metrics hot path where some accessors fire per message.

## Consequences

- The "init + accessor" pattern is repeated across every metric
  module in the workspace. The `.claude/rules/shared-infrastructure.md`
  "Metrics Pattern" section is the canonical reference and the
  shape is mechanical to follow.
- Every metric module's `init()` is called once from the binary
  entry points (`rustgate-server::main` and the equivalent in
  `rustgate-client`). A registration failure surfaces at startup,
  not on first metric access.
- Metric accessors fall back to a sensible default when called
  before `init()` (typically because the `metrics` cargo feature
  is off). The fallback shape is part of every metric module's
  contract — see `crates/rustgate-server/src/metrics.rs` for the
  archetype.
- `once_cell` is no longer a workspace dependency. If it
  reappears via a transitive dep, that's tolerated; the lint only
  bans use of its types in our own code.
- Future singletons (config snapshots, cached SPIFFE bundles,
  etc.) follow the same pattern. A reviewer who sees a
  hand-rolled `static FOO: AtomicPtr<...>` will push back unless
  there's a clear reason `OnceLock` doesn't fit.
