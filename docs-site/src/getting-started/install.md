# Installation

rustgate ships as a single static binary, an OCI container image, and a Helm chart.

## From source

```bash
git clone https://github.com/rchiofalo/rustgate.git
cd rustgate
cargo build --release
```

The binary lands at `target/release/rustgate-server`. The default build enables only the core feature set; opt into NATS, federation, WebSocket, metrics, OpenTelemetry, FIPS, or post-quantum via Cargo features. See [Configuration](./configuration.md) and the [feature reference](../reference/configuration.md) for the complete list.

```bash
# Production-style build
cargo build --release --features nats,enrollment,proto,federation,federation-ha,websocket,metrics,full-detail,otel
```

The `fips` and `post-quantum` features additionally require **Go** and **cmake** because they pull in `aws-lc-rs`. CI does not exercise them in the default matrix; build them locally only when you need them.

## Container image

Pre-built images are published to GHCR:

```bash
docker pull ghcr.io/rchiofalo/rustgate:latest
```

The provided `Dockerfile` is a multi-stage build that produces a non-root, distroless-style image. CI validates that it builds on every PR.

## Helm

The Helm chart in `helm/` is the supported way to run rustgate on Kubernetes. Production overrides live in `helm/values-production.yaml`. CI runs `helm lint` on every change.

```bash
helm install rustgate ./helm \
  --values ./helm/values-production.yaml \
  --namespace rustgate --create-namespace
```

The chart wires the differentiated health probes (`/health/live`, `/health/ready`, `/health/startup`) so rolling updates and connection drains work cleanly with the cluster's load balancer.

## Prerequisites

| Component | Required for |
|---|---|
| Rust toolchain (pinned in `rust-toolchain.toml`) | Building from source |
| `protoc` | The `proto` and `federation` features |
| Go + cmake | The `fips` and `post-quantum` features |
| `nats-server` | NATS integration tests and the bridge runtime |
| Helm 3.x | Chart deployment |

See [Configuration](./configuration.md) to bring up your first instance.
