# Deployment

rustgate supports three deployment modes: standalone binary, Docker Compose, and Kubernetes with Helm.

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

- Rust 1.93+ (to build from source) or a pre-built release binary
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
# Health check (requires --features metrics)
curl http://localhost:9090/healthz

# Readiness check
curl http://localhost:9090/readyz

# Prometheus metrics
curl http://localhost:9090/metrics
```

### Ports

| Port | Service | Feature Gate |
|------|---------|-------------|
| 4433 | Client connections (mTLS) | always |
| 8443 | WebSocket connections (wss:// mTLS) | `websocket` |
| 8446 | Certificate enrollment (HTTPS) | `enrollment` |
| 9000 | Federation V1 (mTLS) | `federation` |
| 9001 | Federation V2 gRPC (mTLS) | `federation` |
| 9090 | Metrics and health (HTTP) | `metrics` |

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
    METRICS_BIND: "0.0.0.0:9090"
    FEDERATION_V1_BIND: "0.0.0.0:9000"
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
docker exec rustgate wget -qO- http://localhost:9090/healthz

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
  --from-file=FEDERATION_PEERS_FILE=peers.json

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
      ENROLLMENT_USER:
        key: "production/rustgate/enrollment"
        property: "username"
      ENROLLMENT_PASSWORD:
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
  existingSecret: my-nats-secret        # must contain NATS_CREDENTIALS key

enrollment:
  existingSecret: my-enrollment-secret   # must contain ENROLLMENT_USER and ENROLLMENT_PASSWORD keys

federation:
  existingSecret: my-federation-secret   # must contain FEDERATION_PEERS_FILE key
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
| Startup | `/healthz` | Wait for server to be ready (30 retries, 2s apart) |
| Liveness | `/healthz` | Restart if unresponsive |
| Readiness | `/readyz` | Remove from LB during shutdown/drain |

### Network Policy

Enable network policy for pod-level firewall rules:

```yaml
networkPolicy:
  enabled: true
```

This restricts:
- **Ingress**: Only TAK (4433), metrics (9090), and federation (9000) ports
- **Egress**: Only DNS (53) and NATS (4222), plus federation peer ports (9000/9001) when enabled

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
