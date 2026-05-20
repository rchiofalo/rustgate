# Runbook: HTTP Egress Circuit Breaker Tripped

> **Important:** rustgate's HTTP egress uses a per-target three-state
> circuit breaker (Closed → Open → HalfOpen). When a target fails
> repeatedly the circuit opens and **subsequent messages are dropped or
> diverted to the per-target DLQ** until the cooldown elapses and the
> breaker probes recovery. A stuck-open circuit means an entire
> downstream consumer is silently missing data — page on it.

## Symptoms

- `rustgate_http_circuit_state{target=…}` is `1` (Open) or `2`
  (HalfOpen) on at least one target.
- Audit log shows `http.circuit_tripped` for the affected target.
- `rustgate_http_dlq_evicted_total{target=…}` is climbing — the DLQ
  is overflowing because the target is down longer than the
  per-target byte cap allows.
- Downstream consumers report missing or stale data.
- `rustgate_http_errors_total{target=…,reason=…}` rate spike preceded
  the circuit trip.

## Detection

1. Identify open or probing circuits:
   ```bash
   curl -s http://localhost:9090/metrics \
     | grep 'rustgate_http_circuit_state' \
     | awk -F'[{}]' '{print $2, $3}' \
     | awk '$NF != " 0" {print}'
   ```
   `state == 0` is closed (healthy); `1` is open; `2` is half-open.

2. Confirm with the audit trail:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=2000 \
     | grep -E '"event_type":"http\.(circuit_tripped|circuit_recovered|circuit_probing|publish_failed)"' \
     | tail -50
   ```

3. Get the leading cause from the per-reason error counter:
   ```bash
   curl -s http://localhost:9090/metrics \
     | grep 'rustgate_http_errors_total'
   ```
   The `reason` label classifies the failure (`timeout`,
   `connection_refused`, `dns_error`, `tls_error`, `http_5xx`,
   `http_4xx`, `serialize_error`, ...). Match it to the most likely
   downstream cause.

## Diagnosis

### Is the target reachable at all?

1. From a debug pod on the same network namespace, attempt a manual
   POST that mimics rustgate's request shape:
   ```bash
   kubectl run --rm -it debug --image=curlimages/curl --restart=Never -- \
     curl -sS -o /dev/null -w "%{http_code} %{time_total}s\n" \
     -X POST -H "Content-Type: application/json" \
     -d '{"probe":"rustgate-runbook"}' \
     https://target.example.com/ingest
   ```
   - 200/204: target is fine; the circuit is stale or rustgate
     has a misconfigured retry policy.
   - 4xx: target is rejecting the request shape; check the
     authentication / payload schema configured on the target.
   - 5xx: target is up but failing internally.
   - Timeout: target is unreachable or overloaded.

2. If the target uses an HMAC auth header, verify the secret
   matches the rustgate-side configuration — a rotated secret
   appears as `http_4xx` on the rustgate side.

### Is the breaker config sized correctly?

The breaker config per target sets:
- `failure_threshold` — consecutive failures before tripping
- `cooldown_seconds` — how long Open lasts before probing
- `probe_limit` — concurrent half-open probes allowed
- `success_threshold` — consecutive successes to close

1. Pull the active target config:
   ```bash
   kubectl get deploy rustgate -o yaml \
     | grep -A20 'http-targets'
   ```

2. Common misconfiguration: `failure_threshold = 1` against a
   target that has any natural error rate. Bump to ≥ 5.

3. If `cooldown_seconds` is too short (e.g. 5 s), the breaker
   bounces between Open and HalfOpen rapidly without ever
   accumulating enough successes to close. Bump to 60 s minimum
   for production.

### How much data is the DLQ holding?

The DLQ stores messages locally while the circuit is open. When the
total bytes exceed the per-target cap the oldest segments are
evicted — those messages are lost permanently:

1. Check the eviction counter:
   ```bash
   curl -s http://localhost:9090/metrics \
     | grep rustgate_http_dlq_evicted_total
   ```
   Non-zero rate ⇒ data is being silently dropped. Treat as a
   recoverable but real data-loss incident.

2. Look at the DLQ file count and total bytes per target on disk
   (segments are sealed `.dlq.enc` files):
   ```bash
   kubectl exec deploy/rustgate -- ls -la /var/lib/rustgate/dlq/
   ```

3. If the DLQ has segments queued, recovery (circuit close) will
   auto-trigger an `http.dlq_drain_started` audit event and replay
   them to the target.

### Is the failure rate downstream, upstream, or in rustgate?

- **Downstream**: high `http_errors_total{reason=timeout}` and the
  same target's other consumers also report errors — the target
  itself is the problem.
- **Upstream**: high error rate from one rustgate pod but other
  pods publish to the same target successfully — DNS, NAT, or
  egress-firewall problem on that pod.
- **In rustgate**: errors on every target with no common
  downstream cause; check `rustgate_http_queue_depth` for
  saturation, and look for retry/backoff misconfiguration.

## Resolution

### Wait for natural recovery

If the target is intermittently failing, the breaker is doing its
job:

1. Confirm `http.circuit_probing` audit events fire at the
   configured cooldown interval.
2. Watch for `http.circuit_recovered` and the subsequent
   `http.dlq_drain_started` / `http.dlq_drain_completed` pair.
3. Verify `rustgate_http_dlq_replayed_total{target=…,result=ok}`
   ticked up by the segment count from the drain-started event.

No action required if the breaker is cycling normally.

### Force-close a stuck-open circuit (after fixing downstream)

If the downstream is verified fixed but the breaker stays open
(this should be rare; cooldown is bounded):

1. The simplest unstick is a rolling restart — the breaker state
   is in-memory and resets to Closed on startup:
   ```bash
   kubectl rollout restart deploy/rustgate
   ```

2. Restart picks the DLQ back up — sealed segments survive
   restart and the auto-drain runs at startup as the circuit
   reaches Closed for the first time.

### Drain the DLQ manually

If you've fixed the downstream and want immediate drain rather than
waiting for natural circuit close:

1. Force-close via restart (above). The auto-drain worker spawns
   when the circuit transitions from any state to Closed.

2. Verify drain progress:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=200 \
     | grep -E '"event_type":"http\.dlq_drain_(started|completed)"'
   ```

3. Monitor the replay counter:
   ```bash
   curl -s http://localhost:9090/metrics \
     | grep rustgate_http_dlq_replayed_total
   ```

### Discard the DLQ (recoverable data loss)

If the DLQ has grown to a point where draining is undesirable
(e.g. stale data, target schema changed):

1. Confirm with stakeholders that the buffered data can be lost.
2. Stop the rustgate pod, delete the DLQ directory, restart:
   ```bash
   kubectl scale deploy/rustgate --replicas=0
   kubectl exec deploy/rustgate -- rm -rf /var/lib/rustgate/dlq/<target>
   kubectl scale deploy/rustgate --replicas=3
   ```
3. Audit-record this action — there is no built-in audit event
   for "operator wiped DLQ", so document it in your incident log.

### Reshape the breaker config

If the breaker is over- or under-tripping:

1. Update the per-target config in your Helm values:
   ```yaml
   http:
     targets:
       - name: events-sink
         url: https://sink.example.com/ingest
         circuit:
           failure_threshold: 5      # was 2
           cooldown_seconds: 60      # was 15
           probe_limit: 3
           success_threshold: 2
   ```

2. Roll out the change:
   ```bash
   helm upgrade rustgate ./charts/rustgate -f values-production.yaml
   ```

3. Verify the new thresholds take effect by watching the next
   breaker cycle in metrics + audit.

### Rate-limit the producer side instead

If the target is throttling rustgate explicitly (HTTP 429):

1. Configure per-target rate limits on the publisher side so the
   producer stops hammering the target:
   ```yaml
   http:
     targets:
       - name: throttled-sink
         rate_limit_per_second: 10
   ```

2. Tickrate excesses emit `http.rate_limited` audit events, which
   you can graph against the target's published rate-limit to
   confirm rustgate is no longer hot-loading.

## Prevention

- **Page on `max by (target) (rustgate_http_circuit_state) == 1`
  sustained > 5 minutes**. A circuit that stays open across a full
  cooldown without probing successfully is a real downstream outage,
  not a transient blip.
- Alert on `rate(rustgate_http_dlq_evicted_total[5m]) > 0`. Any
  eviction rate is silent data loss.
- Configure the breaker with `cooldown_seconds ≥ 60` and
  `failure_threshold ≥ 5`. Tighter values cause the breaker to
  oscillate without ever stabilising.
- Size the DLQ byte cap to cover the longest expected target
  outage at peak throughput. If you expect a 30-minute outage at
  500 msg/s × 2 KiB/msg ≈ 1.8 GiB, set the cap to at least 4 GiB.
- Validate target schemas at deployment time with a synthetic POST
  in your CI pipeline. Most "circuit-tripped" incidents are
  schema drift on the consumer side, not network failures.
- Use HTTP target health checks where the target supports them, so
  the producer gets early signal before the breaker trips.
- Treat HMAC/auth secret rotation as a coordinated change: rotate
  the rustgate side first, then the target, with overlap covered
  by both keys verifying.
