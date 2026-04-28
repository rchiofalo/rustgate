# ADR 0007: `thiserror` everywhere; no `anyhow` at library boundaries

- **Status:** Accepted
- **Date:** 2026-04-27
- **Related:** `.claude/rules/shared-infrastructure.md` "Error Pattern"

## Context

A workspace with sixteen crates needs a consistent error story. Two
common patterns exist in the Rust ecosystem:

- **`anyhow`** — a single `anyhow::Error` type with rich context and
  backtraces. Excellent for application code where the caller just
  wants to know "something failed, here's what".
- **`thiserror`** — a derive macro that generates `std::error::Error`
  implementations for crate-defined enum types. Each variant carries
  its own context fields and the caller can match on the variant.

The two are not mutually exclusive — a binary can use `anyhow` at
the top level while libraries underneath expose `thiserror`-derived
error types — but mixing them at *library* boundaries is harmful:

- An `anyhow::Error` returned from a library forces every caller to
  treat it as opaque. They cannot match on a specific failure to
  retry, fall back, or downgrade — they can only stringify it.
- An `anyhow::Error` cannot easily participate in a typed error
  hierarchy. The caller cannot write `if let TransportError::Crl(_)
  = e` because the type was erased.
- Library tests that want to assert on a specific failure mode end
  up parsing error message strings, which is brittle.

The workspace also lints `clippy::panic = "deny"` and
`clippy::unwrap_used = "deny"` in production code, so error types
are not optional — every `Result` has to be propagated through `?`
into a typed error somewhere.

## Decision

Every library crate in the workspace defines its own `thiserror`-
derived error enum and exposes it as the crate's error type. The
canonical shape:

```rust
#[derive(Debug, thiserror::Error)]
pub enum FooError {
    #[error("what happened for `{target}`: {source}")]
    Variant { target: String, #[source] source: SomeError },
}
pub type Result<T> = std::result::Result<T, FooError>;
```

Conventions enforced across the workspace:

- Use the `thiserror::Error` derive macro; never write a manual
  `impl Display` or `impl Error`.
- Include context fields on every variant (target name, path,
  status code, identifier). The variant should be useful for
  debugging without consulting the call site.
- The crate-level error often wraps lower-level errors: a
  `RustgateError` in `rustgate-core` aggregates `TransportError`,
  `ConfigError`, and `Io` for cross-crate plumbing.

`anyhow` is acceptable only in the binary entry points
(`rustgate-server`, `rustgate-client`) where the top-level
orchestration genuinely wants opaque-with-context. Both are listed
as workspace dependencies but no library crate imports `anyhow`
today, and reviewers push back on PRs that introduce one.

## Alternatives considered

- **`anyhow` across the board.** Rejected at library boundaries
  for the reasons above. Acceptable inside binaries where the
  caller is the operator and a stringified chain is the right
  output.
- **A single workspace-wide error enum.** Rejected: the fan-in
  would be enormous (every variant from every crate in one type),
  and crates would gain transitive dependencies they don't need.
- **`snafu` or `error-stack`.** Both are reasonable choices.
  `thiserror` won by inertia — the workspace adopted it early and
  the ergonomics have not pushed us off it. Switching now would
  require a workspace-wide rewrite of error types.
- **Hand-rolled `impl Display + Error`.** Rejected: every variant
  becomes 20 lines of boilerplate, and reviewer attention drains
  into consistent formatting rather than the actual logic.

## Consequences

- Every library crate exports its own error type. Cross-crate
  composition is by `#[from]` conversions or explicit wrap.
- Library tests can assert on specific variants. The
  `match err { FooError::Variant { target, .. } => ... }` shape
  is the discriminator.
- Adding a new error variant is a public-API change. The workspace
  treats this as worth the friction — silently adding a new
  failure mode to an opaque error type is worse.
- The `rustgate-server` and `rustgate-client` binaries do use
  `anyhow` at the top level for orchestration. That is the only
  blessed location. Library crates that are tempted to depend on
  `anyhow` should instead introduce a typed error variant.
- The decision is reinforced by the `cargo deny` configuration and
  by the `docs/x509-stack.md` discipline (which spells out the
  "no anyhow in libs" rule for the EST surface specifically).
- If a future library crate has a genuinely good reason to expose
  `anyhow::Error` — for example, a debugging-only helper crate
  that is not in the production path — the right move is to mark
  the API `#[doc(hidden)]` and document the exception in the
  crate's README.
