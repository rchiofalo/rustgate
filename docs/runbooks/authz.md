# Authz Runbook

Operational notes for the rustgate RBAC/ABAC policy engine
(`rustgate-authz`). For concept-level material and the JSON policy
format, see [docs/authorization.md](../authorization.md).

## Hot-reload workflow

1. Edit `${RUSTGATE_AUTHZ_POLICY_FILE}` on the host (or update the
   file's content via whatever configuration-management tool is in play).
2. Within `${RUSTGATE_AUTHZ_RELOAD_INTERVAL}` seconds (default 5), the
   background watcher re-reads the file, SHA-256-compares it to the
   last known-good content, and — on change — runs parse + compile on
   a worker thread.
3. On success: the new `NativeEngine` is swapped onto the router via
   `arc-swap`, a structured `authz.reload_success` audit event is
   emitted, `rustgate_authz_reloads_total{result="success"}` is
   incremented, and `rustgate_authz_policy_rules` is updated to the
   new rule count.
4. On failure: the **previous engine continues to serve**. The failing
   stage (`read`, `parse`, or `compile`) is logged in the
   `authz.reload_failed` audit event, and
   `rustgate_authz_reloads_total{result="failure"}` is incremented.

### Verifying a reload in production

```bash
# Tail the audit log for reload outcomes
jq 'select(.event_type=="authz.reload_success" or .event_type=="authz.reload_failed")' \
    /var/log/rustgate/audit.jsonl

# Check Prometheus for the most recent reload result
curl -s http://rustgate:9090/metrics | grep rustgate_authz_reloads_total
```

### Rolling a bad policy back

Because the reloader is fail-closed, a malformed edit does not require
any operator action — the previous engine is still serving. To roll
back an edit that parsed successfully but produced undesired decisions:

1. `git checkout` the previous version of the policy file.
2. Wait for the next reload tick (or send SIGHUP if your deployment
   wires it up).
3. Confirm via `rustgate_authz_decisions_total` that the allow/deny
   ratio returns to baseline.

## Reading deny audit events

Every `Deny` decision emits a structured audit record on the `authz`
target. When `--audit-log` is configured, records land on disk as JSON
lines:

```json
{
  "target": "audit",
  "event_type": "authz.denied",
  "subject_cn": "alpha",
  "subject_fingerprint": "9f86d0...",
  "action": "send",
  "resource_kind": "direct",
  "resource_id": "bravo",
  "rule_id": "deny-test-group-broadcast",
  "policy_id": "ab12...cd34",
  "result": "deny"
}
```

An empty `rule_id` means the deny came from `default_effect: "deny"`
rather than an explicit rule — expect to see these on any subject whose
identity was not matched by any allow rule.

### Querying recent denies

```bash
# Last 100 denies by rule id
jq -r 'select(.event_type=="authz.denied") | .rule_id // "default"' \
    /var/log/rustgate/audit.jsonl | tail -100 | sort | uniq -c | sort -rn
```

## Metric dashboard cheat sheet

Every metric registered under `--features metrics`:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `rustgate_authz_decisions_total` | counter | `action`, `decision` | Authz decisions emitted by the PEP. |
| `rustgate_authz_eval_nanos` | histogram | — | Per-call eval latency in nanoseconds. |
| `rustgate_authz_reloads_total` | counter | `result` | Hot-reload outcomes (`success` / `failure`). |
| `rustgate_authz_policy_rules` | gauge | — | Rule count in the currently installed policy. |
| `rustgate_authz_cache_hits_total` | counter | — | Decision-cache lookups that hit. |
| `rustgate_authz_cache_misses_total` | counter | — | Decision-cache lookups that missed and populated the cache. |

### Grafana queries

```promql
# Deny ratio over the last 5 minutes
sum(rate(rustgate_authz_decisions_total{decision="deny"}[5m]))
  / sum(rate(rustgate_authz_decisions_total[5m]))

# Eval latency P99
histogram_quantile(0.99, sum(rate(rustgate_authz_eval_nanos_bucket[5m])) by (le))

# Cache hit ratio
sum(rate(rustgate_authz_cache_hits_total[5m]))
  / (sum(rate(rustgate_authz_cache_hits_total[5m]))
     + sum(rate(rustgate_authz_cache_misses_total[5m])))

# Reload failures in the last hour
increase(rustgate_authz_reloads_total{result="failure"}[1h])
```

## Tuning the decision cache

The engine owns a sharded, fixed-capacity FIFO-eviction table keyed on
`(SubjectHash, resource_hash, action, policy_epoch)`:

- Default: 16 shards × 4096 entries = 65,536 cached decisions.
- `SubjectHash` is a 128-bit pair (two independently-seeded ahash
  outputs) precomputed once per session in the transport layer, so the
  hot path performs zero hashing over the identity. The double-width
  keeps collisions infeasible even when an attacker controls CN/SAN
  contents through enrollment.
- Policy swaps auto-invalidate because the new `CompiledPolicy` carries
  a new epoch; no explicit `clear()` call is needed or possible.
- Eviction is strict FIFO rather than LRU: entries are not reordered on
  hit, so a cache hit never writes to the per-shard queue. This keeps
  the lock critical section tiny on the hot path at the cost of a
  slightly cooler steady-state working set.

### When to bump the shard count

The shard count only matters for contention on the per-shard eviction
queue lock. If `rustgate_authz_eval_nanos` shows P99 tail latency
drifting above the 10µs budget while `rustgate_authz_cache_hits_total`
dominates `_misses_total`, more shards may reduce lock contention.
Shards are always a power of two; the builder rounds up.

### When to bump the per-shard capacity

If the hit ratio (`hits / (hits + misses)`) sits below 0.9 under
steady-state traffic, the cache is evicting entries that are still
being used. Causes:

- Large subject fan-out (thousands of distinct CNs). Raise the per-shard
  capacity until the hit ratio stabilises.
- Large resource fan-out (many distinct direct targets or NATS subjects).
- Frequent policy swaps — every swap mints a new epoch and silently
  invalidates the cache on the next lookup.

### Disabling the cache for debugging

There is intentionally no runtime kill-switch. To bypass the cache,
reconstruct the engine via `NativeEngine::with_cache_capacity(1, 0)`,
which causes every insert to evict immediately and every lookup to miss.

## Performance budget

| Quantile | Budget |
|---|---|
| P50 | < 100 ns |
| P99 | < 10 µs |

The P99 budget is enforced per-PR by a criterion-based integration test:

```bash
cargo nextest run -p rustgate-authz --run-ignored all perf_budget
```

If the histogram's P99 drifts above 10µs in production, suspect:

- Cache misses dominating the workload (subjects churning every message).
- An unusually large rule set whose worst-case fallthrough dominates
  miss latency — the compiler buckets rules by
  `(action, resource_kind)`, so fallthrough only scans same-bucket rules,
  but a degenerate policy with thousands of rules in a single bucket
  will still scan them all.
- Policy thrash — every compile mints a fresh epoch and implicitly
  invalidates the cache.

## Incident playbook: authz reload failures

**Symptom**: `rustgate_authz_reloads_total{result="failure"}` ticking
up; `authz.reload_failed` events in the audit log.

1. Identify the failing stage from the audit event's `stage` field:
   `read` (file I/O), `parse` (JSON or schema validation), or `compile`
   (rule consistency).
2. Pull the current on-disk contents:
   ```bash
   cat ${RUSTGATE_AUTHZ_POLICY_FILE}
   ```
3. Replay the same validation locally:
   ```bash
   # Parse check only
   python -m json.tool < policy.json > /dev/null
   ```
4. If the policy looks good on disk but the reload still fails, check
   for permission or inode-stability issues — file hash jitter will
   trigger needless reloads but should not produce parse failures.
5. **The dataplane is still serving with the previous engine.** Do
   not restart the server as a blind reaction; that would be the one
   action that replaces the known-good engine with the broken file.

## Switching backends

To migrate from the native backend to Cedar (or vice versa):

1. Deploy the new policy file alongside the old one.
2. Change `--authz-policy-format` to the new backend and restart
   (Cedar is not hot-reloadable; see
   [docs/authorization.md](../authorization.md)).
3. Watch the allow/deny ratio for the first five minutes; an unexpected
   jump in denies almost always means a principal/resource ID mismatch
   between the two formats.

## Related metrics and runbooks

- [docs/runbooks/certificate-rotation.md](certificate-rotation.md) —
  subject attributes flow from the cert; a rotation event can change
  the `subject_hash` and invalidate the decision cache.
- [docs/observability.md](../observability.md) — metric scraping and
  alerting setup.
