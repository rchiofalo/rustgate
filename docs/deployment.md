# Deployment

This page covers the **primary deployment modes**: standalone binary,
Docker Compose, and Kubernetes with the in-tree Helm chart. These work
on any cluster / host with no platform-specific dependencies.

**Two additional opt-in paths** exist for specialised environments:

- **Zarf package** for airgapped Kubernetes (no outbound internet)
- **UDS bundle** for the Defense Unicorns UDS Core platform (Istio
  mTLS mesh, Pepr admission, monitoring stack)

Both are documented in [`docs/uds-deployment.md`](uds-deployment.md);
neither is required to run rustgate. If your target cluster has
outbound internet to `ghcr.io` and you don't need UDS Core, this page
is the right reference and you can skip the UDS doc entirely.

## Quick Reference

| Feature | Binary | Docker Compose | Kubernetes |
|---------|--------|---------------|------------|
| Setup time | Minutes | Minutes | Depends on cluster |
| External deps | None (NATS optional) | Docker | K8s cluster, Helm |
| Scaling | Single instance | Single instance | Multi-replica HPA |
| TLS certs | Files on disk | Mounted volume | K8s Secret |
| NATS | Optional (external) | Included in compose | External or in-cluster |
| Federation | Supported | Supported | Supported (with HA) |
| Health checks | HTTP endpoint | Docker HEALTHCHECK | K8s probes |
| Metrics | Prometheus endpoint | Prometheus endpoint | ServiceMonitor |

## Binary

### Requirements

- Rust 1.94+ (to build from source) or a pre-built release binary
- TLS certificates (server cert, private key, CA cert)
- `protoc` (only if building with `--features proto` or `--features federation`)
- `nats-server` (optional, for NATS bridge)

### Building

```bash
# Minimal (mTLS transport only)
cargo build --release

# Recommended for production (all features)
cargo build --release --all-features
```

### Running

Minimal setup (mTLS transport only):
```bash
rustgate \
  --cert server.pem \
  --key server-key.pem \
  --ca ca.pem
```

With WebSocket listener:
```bash
rustgate \
  --cert server.pem \
  --key server-key.pem \
  --ca ca.pem \
  --websocket-bind 0.0.0.0:8443
```

Full setup with NATS, metrics, WebSocket, and protocol negotiation:
```bash
rustgate \
  --cert server.pem \
  --key server-key.pem \
  --ca ca.pem \
  --nats-url nats://localhost:4222 \
  --websocket-bind 0.0.0.0:8443 \
  --metrics-bind 0.0.0.0:9090 \
  --framing tak-negotiate
```

With federation:
```bash
rustgate \
  --cert server.pem \
  --key server-key.pem \
  --ca ca.pem \
  --nats-url nats://localhost:4222 \
  --metrics-bind 0.0.0.0:9090 \
  --federation-v1-bind 0.0.0.0:9000 \
  --federation-peers-file peers.json
```

### Verifying

```bash
# Liveness probe (requires --features metrics)
curl http://localhost:9090/health/live

# Readiness probe
curl http://localhost:9090/health/ready

# Startup probe
curl http://localhost:9090/health/startup

# Prometheus metrics
curl http://localhost:9090/metrics
```

### Ports

| Port | Service | Feature Gate |
|------|---------|-------------|
| 4433 | Client connections (mTLS) | always |
| 8443 | WebSocket connections (wss:// mTLS) | `websocket` |
| 8446 | Certificate enrollment (HTTPS) | `enrollment` |
| 8883 | MQTT connections (mqtts:// mTLS) | `mqtt` |
| 9000 | Federation V1 (mTLS) | `federation` |
| 9001 | Federation V2 gRPC (mTLS) | `federation` |
| 9090 | Metrics and health (HTTP) | `metrics` |

> **Security note:** The metrics endpoint (port 9090) serves unauthenticated HTTP. It exposes session counts, message routing statistics, and NATS/federation status — information useful for attacker reconnaissance. In hostile or shared environments, bind the metrics port to `127.0.0.1` or a private interface and firewall it from untrusted networks. In Kubernetes, use a `NetworkPolicy` to restrict scraper access.

### Running under systemd (bare-metal / edge)

For a tactical edge node running the binary directly under systemd (no
Kubernetes), a hardened unit file and setup guide ship in
[`deploy/systemd/`](../deploy/systemd/README.md). The unit uses
`Type=simple` (rustgate emits no `sd_notify` signal today), a `DynamicUser`
sandbox, `NoNewPrivileges` / `ProtectSystem=strict`, an `EnvironmentFile`
for secrets, and `Restart=on-failure`.

### Sizing

For how many clients an instance holds and how the admission-control knobs
(`--max-queued-bytes`, `--max-connections`, `--max-concurrent-handshakes`)
bound memory and CPU, see [`docs/capacity-planning.md`](capacity-planning.md)
— including a worked 5,000-client example and a client-count → resource
table.

## Docker Compose

### Quick Start

1. Place TLS certificates in `./certs/`:
   ```
   certs/
     server.crt
     server.key
     ca.crt
   ```

2. Start the stack:
   ```bash
   docker compose up -d
   ```

This starts:
- **nats-server** — NATS with JetStream on port 4222
- **nats-setup** — Creates the JetStream stream for SA replay (runs once and exits)
- **rustgate** — Message router on port 4433 with metrics on port 9090

### Configuration

Override rustgate settings by editing the `command` list in `docker-compose.yml`:

```yaml
rustgate:
  command:
    - --cert=/certs/server.crt
    - --key=/certs/server.key
    - --ca=/certs/ca.crt
    - --nats-url=nats://nats-server:4222
    - --framing=tak-negotiate
    - --metrics-bind=0.0.0.0:9090
    - --federation-v1-bind=0.0.0.0:9000
```

Or use environment variables:

```yaml
rustgate:
  environment:
    RUSTGATE_FRAMING: tak-negotiate
    RUSTGATE_METRICS_BIND: "0.0.0.0:9090"
    RUSTGATE_FEDERATION_V1_BIND: "0.0.0.0:9000"
```

### Adding Federation Peers

To add federation peers with Docker Compose, mount a peers JSON file:

```yaml
rustgate:
  volumes:
    - ./certs:/certs:ro
    - ./peers.json:/etc/federation/peers.json:ro
  command:
    # ... other flags ...
    - --federation-v1-bind=0.0.0.0:9000
    - --federation-peers-file=/etc/federation/peers.json
```

### Managing

```bash
docker compose up -d          # Start
docker compose down           # Stop
docker compose logs -f        # Follow logs
docker compose logs rustgate  # Single service logs
docker compose restart        # Restart
```

### Verifying

```bash
# Health check
docker exec rustgate wget -qO- http://localhost:9090/health/live

# Metrics
curl http://localhost:9090/metrics
```

## Kubernetes

### Requirements

- Kubernetes 1.27+
- Helm 3.12+
- TLS certificates as a K8s Secret

### Quick Start

```bash
# Create TLS secret
kubectl create secret generic rustgate-tls \
  --from-file=server.crt \
  --from-file=server.key \
  --from-file=ca.crt

# Install
helm install rustgate helm/
```

### Configuration

Override values at install time or via a values file:

```bash
# Custom values file
helm install rustgate helm/ -f my-values.yaml

# Inline overrides
helm install rustgate helm/ \
  --set service.type=LoadBalancer \
  --set framing=tak-negotiate \
  --set nats.url=nats://my-nats:4222
```

### Federation

Enable federation in Helm values:

```yaml
federation:
  enabled: true
  v1Bind: "0.0.0.0:9000"
  id: "my-federation-server"
  maxHops: 10
```

Provide peers via a K8s Secret:

```bash
# Create the peers secret
kubectl create secret generic federation-peers \
  --from-file=RUSTGATE_FEDERATION_PEERS_FILE=peers.json

# Reference in values
helm install rustgate helm/ \
  --set federation.enabled=true \
  --set federation.existingSecret=federation-peers
```

### Secret Management

Credentials should never be stored as plaintext in Helm values files. rustgate supports three secret management strategies, listed from most to least recommended.

#### External Secrets Operator (recommended)

The [External Secrets Operator](https://external-secrets.io/) syncs secrets from external backends (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager, Azure Key Vault, etc.) into Kubernetes Secrets automatically. rustgate includes optional ExternalSecret templates for NATS, enrollment, and federation secrets.

1. Install the External Secrets Operator in your cluster.
2. Create a `SecretStore` or `ClusterSecretStore` pointing to your backend.
3. Enable the ExternalSecret resources in your values:

```yaml
externalSecrets:
  enabled: true
  secretStoreRef:
    name: my-secret-store
    kind: ClusterSecretStore
  refreshInterval: 1h
  nats:
    enabled: true
    remoteRef:
      key: "production/rustgate/nats-credentials"
  enrollment:
    enabled: true
    remoteRefs:
      RUSTGATE_ENROLLMENT_USER:
        key: "production/rustgate/enrollment"
        property: "username"
      RUSTGATE_ENROLLMENT_PASSWORD:
        key: "production/rustgate/enrollment"
        property: "password"
  federation:
    enabled: true
    remoteRef:
      key: "production/rustgate/federation-peers"
```

The operator creates and refreshes Kubernetes Secrets automatically. The deployment template references these secrets without any manual `kubectl create secret` steps.

#### Existing Kubernetes Secrets

If you manage secrets outside of Helm (e.g., via `kubectl`, sealed-secrets, or a CI pipeline), reference them with `existingSecret`:

```yaml
nats:
  existingSecret: my-nats-secret        # must contain RUSTGATE_NATS_CREDENTIALS key

enrollment:
  existingSecret: my-enrollment-secret   # must contain RUSTGATE_ENROLLMENT_USER and RUSTGATE_ENROLLMENT_PASSWORD keys

federation:
  existingSecret: my-federation-secret   # must contain RUSTGATE_FEDERATION_PEERS_FILE key
```

#### Plaintext values (development only)

For local development and testing only, credentials can be set directly in values:

```yaml
nats:
  credentials: "my-nats-creds"

enrollment:
  user: "admin"
  password: "changeme"
```

**Do not use plaintext credentials in production.** Helm stores values in release metadata, which is readable by anyone with access to the Helm release secret or `helm get values`.

### Scaling

Horizontal scaling with HPA:

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

When running multiple replicas, NATS is required for cross-instance message delivery. Federation HA mode uses NATS KV for distributed peer ownership — only one pod connects to each outbound peer.

### Health Checks

The Helm chart configures three probes when metrics are enabled:

| Probe | Path | Purpose |
|-------|------|---------|
| Startup | `/health/startup` | Wait for the accept loop to be entered (30 retries, 2s apart). One-shot — never re-checked once it succeeds. |
| Liveness | `/health/live` | Restart if the metrics HTTP server is unresponsive |
| Readiness | `/health/ready` | Remove from LB during shutdown/drain |

### Network Policy

Enable network policy for pod-level firewall rules:

```yaml
networkPolicy:
  enabled: true
```

This restricts:
- **Ingress**: Only TAK (4433), metrics (9090), and federation (9000) ports
- **Egress**: Only DNS (53) and NATS (4222), plus federation peer ports (9000/9001) when enabled

By default the policy is **allow-all-on-ports**: any source may reach the
enabled ingress ports and egress to NATS/federation may go to any
destination. This preserves connectivity for existing deployments — enabling
`networkPolicy.enabled` alone does not flip the chart to deny-by-default.

To narrow *which peers* may connect, set `networkPolicy.ingressSelectors`
and/or `networkPolicy.egressSelectors`. Each is a list of Kubernetes
`NetworkPolicyPeer` objects. When non-empty they render a `from:` (ingress)
or `to:` (egress) stanza that restricts the rule to the matching peers; when
empty the allow-all-on-ports behavior is retained. The enabled ports stay
reachable in either case — only the allowed source/destination set changes.
DNS egress (UDP/TCP 53) is always left unrestricted so name resolution keeps
working.

```yaml
networkPolicy:
  enabled: true
  ingressSelectors:
    # Same-namespace pods only.
    - podSelector: {}
    # Plus pods in namespaces labeled team=tak.
    - namespaceSelector:
        matchLabels:
          team: tak
  egressSelectors:
    # Only reach the NATS pods (applies to NATS + federation egress).
    - podSelector:
        matchLabels:
          app: nats
```

### Managing

```bash
helm install rustgate helm/          # Install
helm upgrade rustgate helm/          # Upgrade
helm status rustgate                 # Status
helm uninstall rustgate              # Remove
kubectl logs -l app.kubernetes.io/name=rustgate -f  # Logs
```

### Troubleshooting

**Pod won't start:**
```bash
kubectl describe pod -l app.kubernetes.io/name=rustgate
kubectl logs -l app.kubernetes.io/name=rustgate --previous
```

Common causes:
- TLS secret missing or wrong key names (expected: `server.crt`, `server.key`, `ca.crt`)
- NATS not reachable at the configured URL
- Insufficient resources (check resource requests/limits)

**Federation peers not connecting:**
```bash
# Check federation logs
kubectl logs -l app.kubernetes.io/name=rustgate | grep federation

# Verify the peers secret is mounted
kubectl exec deploy/rustgate -- cat /etc/federation/peers.json
```

Common causes:
- Peers JSON file malformed
- Remote peer not reachable (check NetworkPolicy egress rules)
- TLS certificate CN mismatch (use `--federation-skip-hostname-verify` for testing)

**Readiness probe failing:**
The readiness probe returns 503 during graceful shutdown. This is expected — it removes the pod from the Service before connections drain.
