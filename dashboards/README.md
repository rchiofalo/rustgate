# dashboards/

Golden Grafana dashboards for rustgate. Plain JSON, no templating, no build
step. The files in this directory are intended to be imported directly into
a Grafana instance or copied into Grafana's dashboard provisioning
directory.

## rustgate-overview.json

Operator overview dashboard for a rustgate process. Six rows, 38 panels:

1. **System overview** — build info, total active connections across all
   transports, federation peer count, server certificate expiry (days
   remaining with red/orange/green thresholds), active sessions stacked by
   transport (TLS, MQTT, WebSocket), and connections accepted vs rejected
   vs accept errors.
2. **Throughput** — messages per second by protocol (MQTT, NATS,
   WebSocket, federation, HTTP egress), bytes per second (inbound vs
   outbound from the per-identity counters summed), messages routed by
   destination, and CoT parse rate split by `result=ok|err`.
3. **Authorization and latency** — authz decisions per second stacked
   by `decision`, engine evaluations per second, cache hit ratio over
   five minutes, in-flight evaluations gauge, p50/p95/p99 evaluation
   latency from the seconds histogram, and obligations emitted by type.
4. **Federation** — in/out traffic plus dropped and TTL-expired,
   circuit-breaker trips and recoveries per minute, reconnects per
   minute, per-peer queue bytes (template-filtered by `peer`), per-peer
   EWMA latency, and federation replay-buffer bytes on disk.
5. **Resilience and queues** — global backpressure queued bytes,
   top-10 store-and-forward queue depth per CN, enqueue/drain/drop/expired
   rates, dedup hit ratio over five minutes, position cache size, router
   drops by reason, tenant quota rejections per minute, and enrollment
   rate-limit triggers per minute.
6. **TLS and cert health** — handshake failures per minute by reason,
   handshake duration p50/p95/p99, OCSP cache hit ratio, CRL age
   (seconds, with one-day and seven-day thresholds), reload rollbacks per
   subsystem, SPIFFE SVID refresh by outcome, SPIFFE SVID notAfter, and
   recent negotiation outcomes.

### Templating variables

- `DS_PROMETHEUS` — Prometheus datasource picker. Defaults to a
  datasource named `Prometheus`.
- `peer` — federation peer label values from
  `rustgate_federation_peer_queue_bytes`. Multi-select with an `All`
  option; per-peer panels filter cleanly.
- `tenant` — tenant label values from
  `rustgate_tenant_quota_rejections_total`. Multi-select with an `All`
  option for per-tenant filtering when the metric is populated.

### How to import

Via the Grafana UI:

1. Grafana -> Dashboards -> New -> Import.
2. Click `Upload JSON file` and select
   `dashboards/rustgate-overview.json`.
3. Pick your Prometheus datasource at the prompt. The dashboard's
   `${DS_PROMETHEUS}` variable resolves to the chosen datasource.

Via provisioning, drop the file into the directory referenced by your
Grafana provisioning config (for example
`/etc/grafana/provisioning/dashboards/`) and reload Grafana.

### Datasource expectations

Every panel uses the `${DS_PROMETHEUS}` datasource variable so the
dashboard imports cleanly into any Grafana instance that has at least
one Prometheus datasource configured. Point Prometheus at the rustgate
process metrics endpoint (default `:9090/metrics` when the workspace
runs with `--features metrics`).

### Sibling dashboard

A smaller historic overview lives at
`ops/grafana/dashboards/rustgate-overview.json`. It uses the UID
`rustgate-overview` and ships a tighter set of panels for SRE rotation
use. The golden dashboard in this directory uses the UID
`rustgate-overview-golden` so the two coexist without import conflicts.

### Layout

```
+----------------------------------------------------------+
| Build info | Active conns | Fed peers | Cert expiry      |  System overview
+--------------------------------+-------------------------+
| Sessions by transport (stack)  | Conn accept vs reject   |
+--------------------------------+-------------------------+
| Messages/sec by protocol       | Bytes/sec in vs out     |  Throughput
+--------------------------------+-------------------------+
| Routed by destination          | CoT parse by result     |
+--------------------------------+-------------------------+
| Authz decisions (allow/deny)   | Engine evals by decision|  Authorization
+----------+----------+----------+-------------------------+
| Cache    | In-flght |          | Eval latency p50/p95/p99|
+----------+----------+----------+-------------------------+
| Obligations emitted            |                         |
+--------------------------------+-------------------------+
| Federation in/out/dropped/ttl  | Circuit trips/recoveries|  Federation
+--------------------------------+-------------------------+
| Reconnects/min                 | Per-peer queue bytes    |
+--------------------------------+-------------------------+
| Per-peer EWMA latency          | Replay buffer bytes     |
+--------------------------------+-------------------------+
| Global queued | Top-10 SF queue depth                    |  Resilience
+---------------+------------------------------------------+
| SF enqueue/drain/drop/expired  | Dedup ratio | Pos cache |
+--------------------------------+-------------------------+
| Tenant quota rejections        | Router drops by reason  |
+--------------------------------+-------------------------+
|                                | Enrollment rate-limited |
+--------------------------------+-------------------------+
| Handshake failures by reason   | Handshake duration pXX  |  TLS / cert
+----------+----------+----------+-------------------------+
| OCSP hit | CRL age  |          | Reload rollback subsys  |
+----------+----------+----------+-------------------------+
| SPIFFE refresh by outcome      | SPIFFE notAfter | Negot |
+--------------------------------+-------------------------+
```

### Validating before edits

Any change to the JSON should keep two checks passing:

```bash
python3 -m json.tool < dashboards/rustgate-overview.json > /dev/null
cargo nextest run -p rustgate-server --test grafana_dashboard
```

The Rust integration test parses the dashboard, walks every
`targets[].expr`, extracts `rustgate_*` metric names, and asserts each
one is also defined in the workspace's `crates/*/src/metrics.rs`. If a
PR removes a metric without updating the dashboard the test fails fast.
