# ADR 0011: `tracing` for structured logging; no `log` facade

- **Status:** Accepted
- **Date:** 2026-05-06
- **Related:** [ADR 0010](0010-spawn-background-and-subsystem-handle.md),
  `crates/rustgate-core/src/audit.rs`,
  `.claude/rules/shared-infrastructure.md` audit and logging conventions

## Context

A workspace with sixteen crates and a long-running server binary needs
one logging story. The Rust ecosystem has two:

- **`log`** — the original logging facade. Each call site emits a
  `Record` with a level, a target string, and a `format_args!` payload.
  Output is delegated to a separately-installed `log::Logger`
  implementation (`env_logger`, `simplelog`, etc.). Records are flat
  strings; structured fields are not part of the API.
- **`tracing`** — span-aware structured logging with typed fields. Each
  event carries a target, a level, and a list of typed key-value
  fields. Spans nest, so a per-request span can attach context that is
  inherited by every event recorded inside it. Subscribers
  (`tracing-subscriber`, `tracing-opentelemetry`,
  `tracing-journald`, etc.) consume the structured stream.

rustgate's operational model leans hard on structured fields:

- Every audit event renders to JSON at `tracing::info!` with target
  `"audit"`. SIEM pipelines (Splunk, Elastic, the operator's own
  collector) join across events on `peer_id`, `cn`, `msg_uid`, and the
  hashed identifiers from `rustgate_core::masking`. A flat string log
  line forces every consumer to re-parse, and grepping a stringified
  log loses the type information the producer had.
- The federation, NATS, and HTTP egress paths have per-recipient and
  per-target events that need the same field set repeated across many
  call sites. With `tracing`, a span attaches the common fields once and
  every event inside the span inherits them; with `log`, each call site
  has to format the same prefix.
- The OpenTelemetry export path (`otel` feature) bridges directly to
  `tracing` via `tracing-opentelemetry`. There is no equivalent bridge
  from `log` that preserves field types.

The `tracing` crate also provides `tracing-log` — a compatibility layer
that captures `log::Record`s and re-emits them as `tracing` events.
That bridge lets transitive dependencies which still use `log` (e.g.
`reqwest`, `tonic`'s internals) flow into the same subscriber pipeline.

## Decision

Every rustgate crate uses `tracing` for application logging. Imports
are `use tracing::{debug, info, warn, error};` and structured fields
are passed positionally with the `=` syntax:

```rust
tracing::info!(peer_id = %id, cn = %hash_cn(&cn), "peer connected");
```

The workspace pattern is documented in
`.claude/rules/shared-infrastructure.md` "Code Style":

> Use structured tracing fields: `info!(peer_id = %id, "connected")`
> not `info!("connected {}", id)`.

`log` is **not** a workspace dependency. The `tracing-log`
compatibility bridge picks up `log::Record`s emitted by transitive
deps when the binary calls `tracing_log::LogTracer::init()`. Direct
use of `log::info!` / `log::warn!` etc. inside rustgate crates is
treated as a review violation.

The audit subsystem (`rustgate_core::audit`) builds on `tracing` —
`audit::*` functions emit `tracing::info!` events with target
`"audit"` and the structured field set spelled out in
[ADR 0014](0014-hash-chained-audit-log.md) and the audit module docs.
Mixing `log` into the audit path would silently break the JSON
contract that SIEM rules depend on.

## Alternatives considered

- **`log` only.** Rejected: structured fields are second-class; every
  consumer has to re-parse strings; no span inheritance; no
  OpenTelemetry bridge that preserves field types. The audit pipeline
  alone makes this disqualifying.
- **`slog`.** A reasonable structured-logging alternative. Rejected
  because (a) `tracing` has won the ecosystem race in the
  tokio-centric Rust world, and (b) every async ecosystem crate we
  care about (`tonic`, `tower`, `hyper`, `tokio` itself) ships
  `tracing` instrumentation, not `slog`.
- **A custom logging facade.** Rejected: the workspace would gain a
  maintenance burden in exchange for no functionality the existing
  ecosystem doesn't already provide.

## Consequences

- `tracing` and `tracing-subscriber` are foundational workspace
  dependencies. The `otel` feature additionally pulls in
  `tracing-opentelemetry`. All three are MIT/Apache-2.0 and on the
  audit allowlist.
- The binary's `main()` installs a single `tracing-subscriber`
  filter and dispatch. Operators tune the filter via `RUST_LOG` or
  the `--log-filter` CLI flag; the `audit` target is enabled
  unconditionally so operators cannot accidentally turn off the
  compliance trail.
- Code reviewers push back on `format!`-based event messages
  (`info!("connected {}", id)`) and ask the author to switch to
  structured fields. Grep for `info!("` / `warn!("` with positional
  formatting is the discriminator.
- If a future contributor reaches for `log::info!` directly, the
  build still succeeds (the bridge swallows it), but the reviewer
  should flag it. The cost of allowing it is that the field
  structure of those events is whatever `format!` ended up producing,
  which is the loss this ADR exists to prevent.
- Migration target: there is no migration. The decision was made
  early enough that no `log`-using code exists in our crates. This
  ADR records the rule for future contributors.
