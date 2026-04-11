# ops/

Operational assets for running rustgate in production: Grafana dashboards,
Prometheus alert rules, and Prometheus recording rules. These are plain JSON
and YAML files — no templating, no build step.

## Layout

```
ops/
├── grafana/
│   └── dashboards/
│       ├── rustgate-overview.json     # High-level RPS, sessions, handshakes, queue
│       ├── rustgate-transport.json    # Per-session queues, dedup, drops, per-identity
│       ├── rustgate-federation.json   # Peer queues, lag, circuit breaker, replay
│       ├── rustgate-nats.json         # Consumer pending, redeliveries, info latency
│       ├── rustgate-enrollment.json   # CSR rate limiting, failures
│       └── rustgate-security.json    # Authz decisions, store-forward, backpressure, dedup
└── prometheus/
    ├── alerts.yml                     # Alerting rules (warning / critical)
    └── recording-rules.yml            # Recording rules for SLO queries
```

## Grafana dashboards

All dashboards use a Prometheus datasource variable `${DS_PROMETHEUS}` so they
can be imported into any Grafana instance.

Import via UI:

1. Grafana -> Dashboards -> New -> Import.
2. Upload a `.json` file from `ops/grafana/dashboards/`.
3. Select your Prometheus datasource when prompted.

Or provision them by copying the files into Grafana's dashboard provisioning
directory (e.g. `/etc/grafana/provisioning/dashboards/`).

## Prometheus alerts and recording rules

Load the rule files from your Prometheus config:

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/rustgate-alerts.yml
  - /etc/prometheus/rules/rustgate-recording.yml
```

Validate locally with `promtool`:

```bash
promtool check rules ops/prometheus/alerts.yml ops/prometheus/recording-rules.yml
```

### Recording rule naming convention

Recording rules follow Prometheus best practice:
`level:metric:operations` — e.g. `rustgate:message_rate:5m`,
`rustgate:federation_peer_lag_seconds:max`. The `rustgate:` prefix
namespaces aggregated series produced by this repo.

### Alert severity

- `severity: warning` — actionable but not paging.
- `severity: critical` — page on-call.

Every alert carries a `runbook_url` annotation pointing to
`docs/runbooks/` in this repository. Runbooks that do not yet exist will be
added as the alerts are exercised in production.
