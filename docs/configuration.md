# Configuration Reference

All rustgate configuration is done through CLI flags or environment variables. CLI flags take precedence over environment variables. In Kubernetes, the Helm chart maps `values.yaml` entries to environment variables.

## CLI Flags and Environment Variables

### Core

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--bind` | `RUSTGATE_BIND` | `0.0.0.0:4433` | Client listen address |
| `--cert` | `RUSTGATE_CERT` | — | TLS certificate file (PEM) |
| `--key` | `RUSTGATE_KEY` | — | TLS private key file (PEM) |
| `--ca` | `RUSTGATE_CA` | — | CA certificate file (PEM) |
| `--crl` | `RUSTGATE_CRL` | — | PEM-encoded CRL file for certificate revocation |
| `--tls-min-version` | `RUSTGATE_TLS_MIN_VERSION` | `1.2` | Minimum TLS version (`1.2` or `1.3`) |
| `--framing` | `RUSTGATE_FRAMING` | `xml` | Framing mode (see below) |
| `--encoding` | `RUSTGATE_ENCODING` | `raw` | Encoding mode (see below) |
| `--max-connections` | `RUSTGATE_MAX_CONNECTIONS` | `1024` | Maximum concurrent connections |
| `--max-concurrent-handshakes` | `RUSTGATE_MAX_HANDSHAKES` | `100` | Max TLS handshakes in progress |
| `--fips-required` | `RUSTGATE_FIPS_REQUIRED` | `false` | Fail startup if FIPS provider is not active |
| `--cert-reload-interval` | `RUSTGATE_CERT_RELOAD_INTERVAL` | `0` | Seconds between certificate file polls (0 = disabled) |

### Certificate Hot-Reload

When `--cert-reload-interval` is set to a value greater than 0, the server periodically polls the `--cert` and `--key` files for changes. If the file contents differ (detected via SHA-256 digest comparison), the server certificate is atomically swapped for all subsequent TLS handshakes — no restart required. Audit events are emitted on rotation success or failure.

**Scope:** Hot-reload applies only to the server certificate (`--cert` and `--key`). Client CA changes (`--ca`) are **not** reloaded by this mechanism — use the dynamic TLS refresh feature (TrustStore) for runtime CA rotation. When both are active, they complement each other: one handles server cert rotation, the other handles client CA changes.

**File replacement:** For reliable rotation, replace certificate files atomically (e.g., write to a temporary file in the same directory and `mv`/rename into place). The cert and key files are read in two separate operations; if only one has been updated when the poll fires, the reload will fail with an error, emit an audit event, and self-heal on the next poll once both files are consistent.

### Certificate Revocation

The `--crl` flag loads a PEM-encoded Certificate Revocation List. Revoked certificates are rejected at the TLS handshake before any application-layer processing. CRL freshness is checked at startup — stale CRLs produce a warning by default (`--crl-warn-stale`).

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--crl` | `RUSTGATE_CRL` | — | Path to PEM-encoded CRL file |
| `--crl-warn-stale` | `RUSTGATE_CRL_WARN_STALE` | `true` | Warn if the CRL's `nextUpdate` is in the past |

### Plaintext Transport

> **Security warning:** Plaintext listeners accept unauthenticated, unencrypted TCP and UDP connections. Only enable these on trusted networks (e.g., localhost, a pod sidecar, or a physically isolated segment). Messages from plaintext sources are assigned a synthetic identity.

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--tcp-bind` | `RUSTGATE_TCP_BIND` | — | Plaintext TCP listen address (enables plaintext TCP) |
| `--udp-bind` | `RUSTGATE_UDP_BIND` | — | Plaintext UDP listen address (enables plaintext UDP) |
| `--plaintext-cn` | `RUSTGATE_PLAINTEXT_CN` | `anonymous` | CN assigned to plaintext connections |
| `--plaintext-group` | `RUSTGATE_PLAINTEXT_GROUP` | `__plaintext__` | Group assigned to plaintext connections |

### Rate Limiting

Per-client rate limiting uses a token bucket algorithm. When a client exceeds their message rate, excess messages are dropped silently. Disabled by default (`--client-message-rate 0`).

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--client-message-rate` | `RUSTGATE_CLIENT_MSG_RATE` | `0` (disabled) | Messages per second per client |
| `--client-burst` | `RUSTGATE_CLIENT_BURST` | `200` | Maximum burst size (token bucket capacity) |

### Anti-Replay

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--replay-window` | `RUSTGATE_REPLAY_WINDOW` | `300` | Replay detection window in seconds (0 to disable) |

### Data Packages and Archive

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--archive-dir` | `RUSTGATE_ARCHIVE_DIR` | — | Directory for JSONL CoT event archival |
| `--data-package-dir` | `RUSTGATE_DATA_PACKAGE_DIR` | — | Directory for client data packages |
| `--package-max-age-hours` | `RUSTGATE_PACKAGE_MAX_AGE_HOURS` | `0` (no expiration) | Maximum age for data packages |

### CoT Delta Encoding

Per-UID delta encoding reduces outbound bandwidth for CoT workloads where the same UID pings repeatedly with small changes (typically just a new timestamp and position). Each XML-framed writer task keeps a bounded LRU cache of the last full event sent for each `uid`; subsequent events are emitted as a compact `<delta>` wrapper carrying only the fields that changed. Disabled by default. See [cot-delta-encoding.md](cot-delta-encoding.md) for the wire format and tuning guidance.

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--cot-delta-encoding` | `RUSTGATE_COT_DELTA_ENCODING` | `false` | Enable per-UID delta encoding on XML sessions |
| `--cot-delta-cache-size` | `RUSTGATE_COT_DELTA_CACHE_SIZE` | `512` | Per-session LRU cache size (UIDs) |
| `--cot-delta-epsilon-meters` | `RUSTGATE_COT_DELTA_EPSILON_METERS` | `1.0` | Ground distance below which position-only updates are suppressed entirely (`0` = ship every event) |

### Authorization (RBAC / ABAC)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--authz-policy-file` | `RUSTGATE_AUTHZ_POLICY_FILE` | — | Path to a JSON rustgate-authz policy file (or Cedar source when paired with `--authz-policy-format cedar`). When set, the router enforces per-message RBAC/ABAC decisions via the PEP. |
| `--authz-policy-format` | `RUSTGATE_AUTHZ_POLICY_FORMAT` | `native` | Policy format: `native` (default JSON ruleset) or `cedar` (requires `--features cedar`). |
| `--authz-reload-interval` | `RUSTGATE_AUTHZ_RELOAD_INTERVAL` | `5` | Seconds between hot-reload polls of the policy file. Must be >= 1 when `--authz-policy-file` is set. Native backend only. |
| `--authz-fail-open` | `RUSTGATE_AUTHZ_FAIL_OPEN` | `false` | When the initial load fails, start without an engine instead of aborting. Default is fail-closed. |
| `--authz-no-policy-allow` | `RUSTGATE_AUTHZ_NO_POLICY_ALLOW` | `false` | Secure-by-default warm-up opt-out ([ADR 0036](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0036-secure-by-default-warmup.md)). Acknowledge that no routing policy is configured on purpose (router stays app-layer-open) and silence the no-policy warm-up warning. No behaviour change this release. |

See [docs/authorization.md](authorization.md) for the policy format and
[docs/runbooks/authz.md](runbooks/authz.md) for operational guidance.

### Secure-by-default warm-up (ADR 0036)

Three convenient-but-unsafe defaults are being tightened over two
releases. **This release only warns** — it names, at startup, what will
change and gives each an opt-out flag to pre-pin the current posture and
silence the warning. See
[ADR 0036](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0036-secure-by-default-warmup.md) for the full staging.

| Warm-up warning fires when… | Opt-out flag | Env Var |
|---|---|---|
| Neither `--group-acl-file` nor `--authz-policy-file` is set (routing is app-layer-open) | `--authz-no-policy-allow` | `RUSTGATE_AUTHZ_NO_POLICY_ALLOW` |
| `--metrics-bind` is set but `--metrics-token-file` is not (metrics endpoint unauthenticated) | `--metrics-no-auth` | `RUSTGATE_METRICS_NO_AUTH` |
| `--ws-max-frames-per-sec` / `--ws-max-bytes-per-sec` / `--udp-rate-limit` is `0`, or `--udp-bind` is set with no `--udp-allowed-cidrs` (unbounded rate limits) | `--insecure-unbounded-rate-limits` | `RUSTGATE_INSECURE_UNBOUNDED_RATE_LIMITS` |

A future enforcement release will make the no-policy case default-deny,
require a metrics token, and give the rate limits finite defaults —
each unless the matching opt-out above is set. Setting the opt-out now
makes that release a no-op for your deployment.

### NATS (requires `--features nats`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--nats-url` | `RUSTGATE_NATS_URL` | — | NATS server URL (enables NATS bridge) |
| `--nats-credentials` | `RUSTGATE_NATS_CREDENTIALS` | — | NATS credentials file path |
| `--nats-tls-cert` | `RUSTGATE_NATS_TLS_CERT` | — | Client certificate for NATS mTLS (PEM) |
| `--nats-tls-key` | `RUSTGATE_NATS_TLS_KEY` | — | Client private key for NATS mTLS (PEM) |
| `--nats-tls-ca` | `RUSTGATE_NATS_TLS_CA` | — | CA certificate for NATS server verification (PEM) |
| `--nats-tls-required` | `RUSTGATE_NATS_TLS_REQUIRED` | `false` | Require TLS for NATS connections |

### Enrollment (requires `--features enrollment`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--enrollment-bind` | `RUSTGATE_ENROLLMENT_BIND` | — | Enrollment HTTPS listen address |
| `--ca-key` | `RUSTGATE_CA_KEY` | — | CA private key for signing CSRs |
| `--enrollment-user` | `RUSTGATE_ENROLLMENT_USER` | — | HTTP Basic Auth username |
| `--enrollment-password` | `RUSTGATE_ENROLLMENT_PASSWORD` | — | HTTP Basic Auth password |
| `--ca-organization` | `RUSTGATE_CA_ORG` | `rustgate` | Organization for issued certs |

### WebSocket (requires `--features websocket`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--websocket-bind` | `RUSTGATE_WEBSOCKET_BIND` | — | WebSocket (wss://) listen address |

### MQTT (requires `--features mqtt`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--mqtt-bind` | `RUSTGATE_MQTT_BIND` | — | MQTT (mqtts://) listen address (e.g., `0.0.0.0:8883`) |
| `--mqtt-topic-prefix` | `RUSTGATE_MQTT_TOPIC_PREFIX` | — | Optional prefix stripped from MQTT topics before group mapping (e.g., `rustgate/`) |
| `--mqtt-max-packet-size` | `RUSTGATE_MQTT_MAX_PACKET_SIZE` | `16777216` (16 MiB) | Maximum MQTT packet size in bytes |

MQTT clients connect over mTLS (same CA as the core transport). Client identity is derived from the X.509 certificate. MQTT topics map to rustgate groups: a SUBSCRIBE to topic `alpha` joins the `alpha` group; a PUBLISH to topic `alpha` routes to the `alpha` group. MQTT 5.0 and 3.1.1 are both supported, with protocol version negotiated from the CONNECT packet. Only QoS 0 and QoS 1 are supported; QoS 2 is rejected. Clean sessions are required (persistent sessions are not supported).

### OCSP (requires `--features ocsp`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--ocsp-stapling` | `RUSTGATE_OCSP_STAPLING` | `false` | Enable OCSP stapling on the server certificate |
| `--client-ocsp` | `RUSTGATE_CLIENT_OCSP` | `false` | Check OCSP status for client certificates during handshake |

### SPIFFE (requires `--features spiffe`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--spiffe` | `RUSTGATE_SPIFFE` | `false` | Enable SPIFFE workload identity |
| `--spiffe-trust-domain` | `RUSTGATE_SPIFFE_TRUST_DOMAIN` | — | SPIFFE trust domain (e.g., `example.org`) |
| `--spiffe-workload-api-socket` | `RUSTGATE_SPIFFE_WORKLOAD_API_SOCKET` | `unix:///tmp/spire-agent/public/api.sock` | Path to the SPIRE Workload API socket |
| `--spiffe-refresh-interval` | `RUSTGATE_SPIFFE_REFRESH_INTERVAL` | `300` | Seconds between SVID refresh |

When SPIFFE is enabled, the server obtains its TLS identity (X.509 SVID) from a SPIRE agent via the Workload API instead of reading static `--cert`/`--key` files. The SVID is refreshed periodically.

### Metrics (requires `--features metrics`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--metrics-bind` | `RUSTGATE_METRICS_BIND` | — | Metrics HTTP listen address |

### Federation (requires `--features federation`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--federation-v1-bind` | `RUSTGATE_FEDERATION_V1_BIND` | — | V1 listen address (enables V1 federation) |
| `--federation-v2-bind` | `RUSTGATE_FEDERATION_V2_BIND` | — | V2 gRPC listen address (enables V2 federation) |
| `--federation-id` | `RUSTGATE_FEDERATION_ID` | `rustgate-federation-1` | Unique server identity |
| `--federation-peers-file` | `RUSTGATE_FEDERATION_PEERS_FILE` | — | Path to peers JSON config |
| `--federation-skip-hostname-verify` | `RUSTGATE_FEDERATION_SKIP_HOSTNAME_VERIFY` | `false` | Skip TLS hostname verification |
| `--federation-max-hops` | `RUSTGATE_FEDERATION_MAX_HOPS` | `10` | Max hops before message drop |
| `--federation-store-path` | `RUSTGATE_FEDERATION_STORE_PATH` | — | Persistent peer store path |
| `--federation-trust-store-dir` | `RUSTGATE_FEDERATION_TRUST_STORE_DIR` | — | Directory of trusted peer CA certificates |
| `--federation-circuit-breaker-threshold` | `RUSTGATE_FEDERATION_CIRCUIT_BREAKER_THRESHOLD` | `5` | Consecutive failures before circuit opens |
| `--federation-circuit-breaker-timeout` | `RUSTGATE_FEDERATION_CIRCUIT_BREAKER_TIMEOUT` | `60` | Seconds before recovery probe |

### Federation HA (requires `--features federation-ha`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--federation-ha-nats-url` | `RUSTGATE_FEDERATION_HA_NATS_URL` | — | NATS URL for HA peer discovery |
| `--federation-pod-id` | `RUSTGATE_FEDERATION_POD_ID` | — | Pod identifier for HA leader election |

See the [Federation REST API](federation.md) documentation for the `/api/federation/` management endpoints (requires `--features metrics` for the HTTP server).

### Peer Discovery (requires `--features peer-discovery`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--federation-peer-discovery` | `RUSTGATE_FEDERATION_PEER_DISCOVERY` | `none` | Discovery backend: `none`, `dns-sd`, `consul`, or `etcd` |
| `--federation-peer-discovery-interval` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_INTERVAL` | `30` | Seconds between discovery polls |
| `--federation-peer-discovery-dns-sd-service` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_DNS_SD_SERVICE` | `_rustgate._tcp.local.` | DNS-SD service name |
| `--federation-peer-discovery-consul-addr` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_CONSUL_ADDR` | `http://127.0.0.1:8500` | Consul agent address |
| `--federation-peer-discovery-consul-service` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_CONSUL_SERVICE` | `rustgate` | Consul service name |
| `--federation-peer-discovery-etcd-endpoints` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_ETCD_ENDPOINTS` | `http://127.0.0.1:2379` | Comma-separated etcd endpoints |
| `--federation-peer-discovery-etcd-prefix` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_ETCD_PREFIX` | `rustgate/peers/` | etcd key prefix for peer registration |

Individual backends can be enabled separately with `--features peer-discovery-dns-sd`, `--features peer-discovery-consul`, or `--features peer-discovery-etcd`. The umbrella `--features peer-discovery` enables all three.

### OpenTelemetry (requires `--features otel`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--otel-endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OTLP gRPC endpoint (enables trace export) |
| `--otel-service-name` | `OTEL_SERVICE_NAME` | `rustgate` | Service name reported in traces |

See [Observability](observability.md) for backend setup (Jaeger, Grafana Tempo).

## Framing Modes

| Value | Description | Typical Use |
|-------|-------------|-------------|
| `xml` | Raw XML stream with depth tracking | Testing, simple clients |
| `length-prefixed` | 4-byte big-endian length header | Custom integrations |
| `line` | Newline-delimited messages | Simple text-based clients |
| `tak-protobuf` | TAK binary framing (0xBF + varint) | Clients in protobuf mode |
| `tak-negotiate` | Auto-negotiate (XML or protobuf) | Production client deployments |

**Note:** `tak-protobuf` and `tak-negotiate` require `--features proto`.

## Encoding Modes

| Value | Description |
|-------|-------------|
| `raw` | Pass-through (no encoding translation) |
| `tak-protobuf` | TAK protobuf encoding |

## Helm Values

The Helm chart provides a YAML interface over the environment variables. See `helm/values.yaml` for all defaults.

### Key Sections

```yaml
# Container image
image:
  repository: ghcr.io/rchiofalo/rustgate
  tag: "0.8.0"
  pullPolicy: IfNotPresent

# Service configuration
service:
  type: ClusterIP        # or LoadBalancer
  port: 4433             # Client port

# TLS certificates (K8s Secret)
tls:
  secretName: rustgate-tls
  cert: /certs/server.crt
  key: /certs/server.key
  ca: /certs/ca.crt

# Protocol settings
framing: tak-negotiate    # Helm default (differs from CLI default of 'xml')
encoding: tak-protobuf    # Helm default (differs from CLI default of 'raw')
maxConnections: 1024

# NATS bridge
nats:
  enabled: true
  url: nats://nats:4222
  credentials: ""
  existingSecret: ""      # K8s Secret with RUSTGATE_NATS_CREDENTIALS key

# Certificate enrollment
enrollment:
  enabled: false
  bind: "0.0.0.0:8446"
  caKey: ""
  user: ""
  password: ""
  caOrganization: ""
  existingSecret: ""      # K8s Secret with RUSTGATE_ENROLLMENT_USER/PASSWORD keys

# Server-to-server federation
federation:
  enabled: false
  v1Bind: "0.0.0.0:9000"
  id: "rustgate-federation-1"
  maxHops: 10
  skipHostnameVerify: false
  storePath: ""
  peersFile: ""
  existingSecret: ""      # K8s Secret with RUSTGATE_FEDERATION_PEERS_FILE key

# Prometheus metrics
metrics:
  enabled: true
  port: 9090
  serviceMonitor:
    enabled: false
    interval: 30s
    scrapeTimeout: 10s
    additionalLabels: {}

# Pod resources
resources:
  requests:
    cpu: 500m
    memory: 256Mi
  limits:
    cpu: "2"
    memory: 512Mi

# Autoscaling
autoscaling:
  enabled: false
  minReplicas: 1
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

# Network policy
networkPolicy:
  enabled: false

# Shutdown
terminationGracePeriodSeconds: 120
```

### Helm vs CLI Defaults

The Helm chart uses different defaults than the CLI for framing and encoding, optimized for production deployments:

| Setting | CLI Default | Helm Default | Reason |
|---------|------------|-------------|--------|
| `framing` | `xml` | `tak-negotiate` | Production clients expect negotiation |
| `encoding` | `raw` | `tak-protobuf` | Protobuf is more efficient for production |

## Editor Autocomplete (JSON Schema)

A JSON Schema describing the `rustgate.toml` surface ships at
[`schemas/rustgate-v0.8.json`](https://github.com/rchiofalo/rustgate/blob/main/schemas/rustgate-v0.8.json)
in the repository root. Wire it into any JSON-Schema-aware editor for
autocomplete and inline validation while editing your config — every
key, type, allowed enum value, and default is generated from the same
`Cli` struct that powers the binary itself, so the schema cannot drift
from the actual server's expectations.

### VS Code (Even Better TOML)

1. Install the **Even Better TOML** extension (publisher `tamasfe`).
2. Add the schema association to your `.vscode/settings.json`:

   ```json
   {
     "evenBetterToml.schema.associations": {
       "**/rustgate.toml": "https://raw.githubusercontent.com/rchiofalo/rustgate/main/schemas/rustgate-v0.8.json"
     }
   }
   ```

3. Open `rustgate.toml`. Autocomplete on key names, hover-doc on each
   key (sourced from the CLI flag's help text), and inline diagnostics
   for unknown keys / wrong-type values become available.

### Other editors

The schema is plain JSON Schema 2020-12 and works with any editor that
consumes the format — Helix and IntelliJ TOML both pick up the schema
from a `# json.$schema = <url>` magic comment at the top of the file,
or via per-file association lists in their respective settings.

### Regenerating the schema

The schema is generated from the live `ConfigFile` mirror at build
time. Build the server with the optional `schema` feature and pipe the
`emit-schema` subcommand into the version-tagged file:

```bash
cargo run -p rustgate-server --features schema -- emit-schema \
  > schemas/rustgate-v0.8.json
```

The `schema` feature is opt-in so the default release image does not
carry the `schemars` dependency. A regression test in
`crates/rustgate-server/tests/schema_export.rs` re-runs the generator
in CI and fails with a hint pointing at the regen command above when a
new config field lands without a corresponding schema refresh.

## Environment Variable Examples

### Minimal

```bash
export RUSTGATE_CERT=/certs/server.pem
export RUSTGATE_KEY=/certs/server-key.pem
export RUSTGATE_CA=/certs/ca.pem
rustgate
```

### Full Production

```bash
export RUSTGATE_CERT=/certs/server.pem
export RUSTGATE_KEY=/certs/server-key.pem
export RUSTGATE_CA=/certs/ca.pem
export RUSTGATE_BIND=0.0.0.0:4433
export RUSTGATE_FRAMING=tak-negotiate
export RUSTGATE_MAX_CONNECTIONS=2048
export RUSTGATE_WEBSOCKET_BIND=0.0.0.0:8443
export RUSTGATE_MQTT_BIND=0.0.0.0:8883
export RUSTGATE_NATS_URL=nats://nats:4222
export RUSTGATE_METRICS_BIND=0.0.0.0:9090
export RUSTGATE_FEDERATION_V1_BIND=0.0.0.0:9000
export RUSTGATE_FEDERATION_ID=edge-server-1
export RUSTGATE_FEDERATION_PEERS_FILE=/etc/federation/peers.json
export RUSTGATE_FEDERATION_MAX_HOPS=10
rustgate
```
