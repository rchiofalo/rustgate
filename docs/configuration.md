# Configuration Reference

All rustgate configuration is done through CLI flags or environment variables. CLI flags take precedence over environment variables. In Kubernetes, the Helm chart maps `values.yaml` entries to environment variables.

## CLI Flags and Environment Variables

### Core

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--bind` | `RUSTGATE_BIND` | `0.0.0.0:4433` | TAK client listen address |
| `--cert` | `RUSTGATE_CERT` | — | TLS certificate file (PEM) |
| `--key` | `RUSTGATE_KEY` | — | TLS private key file (PEM) |
| `--ca` | `RUSTGATE_CA` | — | CA certificate file (PEM) |
| `--framing` | `RUSTGATE_FRAMING` | `xml` | Framing mode (see below) |
| `--encoding` | `RUSTGATE_ENCODING` | `raw` | Encoding mode (see below) |
| `--max-connections` | `RUSTGATE_MAX_CONNECTIONS` | `1024` | Maximum concurrent connections |

### NATS (requires `--features nats`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--nats-url` | `NATS_URL` | — | NATS server URL (enables NATS bridge) |
| `--nats-credentials` | `NATS_CREDENTIALS` | — | NATS credentials file path |

### Enrollment (requires `--features enrollment`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--enrollment-bind` | `ENROLLMENT_BIND` | — | Enrollment HTTPS listen address |
| `--ca-key` | `RUSTGATE_CA_KEY` | — | CA private key for signing CSRs |
| `--enrollment-user` | `ENROLLMENT_USER` | — | HTTP Basic Auth username |
| `--enrollment-password` | `ENROLLMENT_PASSWORD` | — | HTTP Basic Auth password |
| `--ca-organization` | `RUSTGATE_CA_ORG` | `rustgate` | Organization for issued certs |

### Metrics (requires `--features metrics`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--metrics-bind` | `METRICS_BIND` | — | Metrics HTTP listen address |

### Federation (requires `--features federation`)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--federation-v1-bind` | `FEDERATION_V1_BIND` | — | V1 listen address (enables federation) |
| `--federation-id` | `FEDERATION_ID` | `rustgate-federation-1` | Unique server identity |
| `--federation-peers-file` | `FEDERATION_PEERS_FILE` | — | Path to peers JSON config |
| `--federation-skip-hostname-verify` | `FEDERATION_SKIP_HOSTNAME_VERIFY` | `false` | Skip TLS hostname verification |
| `--federation-max-hops` | `FEDERATION_MAX_HOPS` | `10` | Max hops before message drop |
| `--federation-store-path` | `FEDERATION_STORE_PATH` | — | Persistent peer store path |

## Framing Modes

| Value | Description | Typical Use |
|-------|-------------|-------------|
| `xml` | Raw XML stream with depth tracking | Testing, simple clients |
| `length-prefixed` | 4-byte big-endian length header | Custom integrations |
| `line` | Newline-delimited messages | Simple text-based clients |
| `tak-protobuf` | TAK binary framing (0xBF + varint) | TAK clients (protobuf mode) |
| `tak-negotiate` | Auto-negotiate (XML or protobuf) | Production TAK client deployments |

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
  tag: "0.2.0"
  pullPolicy: IfNotPresent

# Service configuration
service:
  type: ClusterIP        # or LoadBalancer
  port: 4433             # TAK client port

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
  existingSecret: ""      # K8s Secret with NATS_CREDENTIALS key

# Certificate enrollment
enrollment:
  enabled: false
  bind: "0.0.0.0:8446"
  caKey: ""
  user: ""
  password: ""
  caOrganization: ""
  existingSecret: ""      # K8s Secret with ENROLLMENT_USER/PASSWORD keys

# Server-to-server federation
federation:
  enabled: false
  v1Bind: "0.0.0.0:9000"
  id: "rustgate-federation-1"
  maxHops: 10
  skipHostnameVerify: false
  storePath: ""
  peersFile: ""
  existingSecret: ""      # K8s Secret with FEDERATION_PEERS_FILE key

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

The Helm chart uses different defaults than the CLI for framing and encoding, optimized for production TAK client deployments:

| Setting | CLI Default | Helm Default | Reason |
|---------|------------|-------------|--------|
| `framing` | `xml` | `tak-negotiate` | Production TAK clients expect negotiation |
| `encoding` | `raw` | `tak-protobuf` | Protobuf is more efficient for production |

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
export NATS_URL=nats://nats:4222
export METRICS_BIND=0.0.0.0:9090
export FEDERATION_V1_BIND=0.0.0.0:9000
export FEDERATION_ID=edge-server-1
export FEDERATION_PEERS_FILE=/etc/federation/peers.json
export FEDERATION_MAX_HOPS=10
rustgate
```
