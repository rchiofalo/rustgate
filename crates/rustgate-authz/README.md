# rustgate-authz

Deny-by-default RBAC/ABAC policy engine evaluated on every routed message.

## Role in the workspace

`rustgate-authz` is the policy engine the router consults at the Send and
Receive Policy Enforcement Points. It depends only on
[rustgate-core](../rustgate-core/README.md) and is consumed by
[rustgate-transport](../rustgate-transport/README.md) (which hot-reloads the
engine via `ArcSwap` and calls into it on the message hot path) and by
[rustgate-server](../rustgate-server/README.md) (which loads policy files,
wires the obligation actuators, and exposes the Cedar backend behind a CLI
flag). The crate is intentionally self-contained: it owns the policy AST,
the JSON parser, the bucketed-decision-table compiler, and the runtime cache.

## Public API surface

- `PolicyEngine` — trait the router calls to evaluate a `(Subject, Action,
  Resource)` triple and receive a `Decision` plus obligations
- `NativeEngine` — built-in engine backed by the compiled bucketed decision
  table; sub-microsecond evaluation on the dataplane hot path
- `CedarBackend` — alternative engine bridging an existing Cedar policy
  corpus; selectable via `--authz-policy-format cedar` (gated by `cedar`)
- `Decision`, `DecisionOutcome` — `Allow | Deny | FailOpen` with per-decision
  obligations (mask, tag, audit-extend)
- `Subject`, `Resource`, `Action` — typed inputs to the engine; subjects are
  hashed into a 128-bit `SubjectHash` (dual-ahash) to defend against
  adversarial cache injection
- `Obligation` — the workspace-canonical obligation set (`MaskPoint`,
  `MaskPayload`, `TagClassified`, `AuditExtended`)
- `Rule`, `RuleSet`, `Effect`, `SubjectMatcher`, `ResourceMatcher` — the
  loaded-policy AST exposed for tooling and the Cedar bridge
- `CacheStats` — per-engine cache hit/miss counters surfaced by
  `--authz-stats`
- `AuthzError` — typed error enum for parser, compiler, and engine failures

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `cedar` | Compiles the `CedarBackend` and registers `--authz-policy-format cedar`; allows operators with an existing Cedar policy corpus to reuse it | No |

## Topology / deployment notes

The router holds the engine inside `ArcSwap<Option<Arc<dyn PolicyEngine>>>`,
so SIGHUP reloads are lock-free for readers and a misconfigured policy can be
fail-open by setting `--authz-fail-open` (allow when no engine is loaded).
See the workspace `docs/authorization.md` for the reload-window
eventual-consistency contract between Send and Receive PEP evaluations.

## Where to look first

- `crates/rustgate-authz/src/engine.rs` — `PolicyEngine` trait and the native
  engine's compile-once / evaluate-many loop
- `crates/rustgate-authz/src/policy.rs` — policy AST that downstream tooling
  and the Cedar backend share
