# Authz Runbook

Operational notes for the rustgate RBAC/ABAC policy engine
(`rustgate-authz`). This is a stub — the full runbook lands with PR 6.

## Evaluation latency

Every routed message runs through the Policy Enforcement Point (PEP) in
the router. Latency per evaluation is recorded in the
`rustgate_authz_eval_nanos` histogram. Normal steady state:

| Quantile | Budget |
|----------|--------|
| P50      | < 100ns |
| P99      | < 10µs  |

The P99 budget is enforced per-PR by an ignored integration test:

```bash
cargo nextest run -p rustgate-authz --run-ignored all perf_budget
```

If the histogram's P99 drifts above 10µs in production, suspect:

- Cache misses dominating the workload (subjects churning every message).
  Check `cache_stats()` on the engine via a debug endpoint, or the
  `rustgate_authz_cache_hits_total` / `_misses_total` counters.
- An unusually large rule set whose worst-case fallthrough dominates
  miss latency.
- Policy thrash — every `RuleSet::compile` mints a fresh epoch and
  implicitly invalidates the cache.

## Decision cache

The engine owns a sharded FIFO-LRU keyed on
`(subject_hash, resource_hash, action, policy_epoch)`:

- 16 shards × 4096 entries by default.
- Subject hashes are precomputed once per session in the transport
  layer (`SessionHandle::subject_hash()`), so the hot path performs
  zero hashing over the identity.
- Policy swaps auto-invalidate because the new `CompiledPolicy` carries
  a new epoch — no explicit `clear()` call is needed or possible.

### Resizing

Use `NativeEngine::with_cache_capacity(shards, per_shard)` when
constructing the engine. `shards` is rounded up to a power of two.

### Disabling (debug only)

There is intentionally no runtime kill-switch. To bypass the cache for
debugging, build with `NativeEngine::with_cache_capacity(1, 0)`, which
causes every insert to evict immediately and every lookup to miss.

## Related metrics

| Metric | Meaning |
|--------|---------|
| `rustgate_authz_decisions_total{decision}` | Allow / deny counts. |
| `rustgate_authz_eval_nanos` | Per-call eval latency histogram. |
| `rustgate_authz_policy_reload_total{outcome}` | Policy file reload results. |
