# Installation

rustgate ships as a single static binary, an OCI container image, and a Helm chart.

## From source

```bash
git clone https://github.com/rchiofalo/rustgate.git
cd rustgate
cargo build --release
```

The binary lands at `target/release/rustgate-server`. The default build enables only the core feature set; opt into NATS, federation, WebSocket, metrics, OpenTelemetry, or FIPS via Cargo features. Hybrid post-quantum key exchange is on in every build. See [Configuration](./configuration.md) and the [feature reference](../reference/configuration.md) for the complete list.

```bash
# Production-style build
cargo build --release --features nats,enrollment,proto,federation,federation-ha,websocket,metrics,full-detail,otel
```

Every build needs a C compiler, because the `aws-lc-rs` crypto provider compiles AWS-LC. The `fips` feature additionally requires **Go** and **cmake** to build the AWS-LC FIPS module.

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
| C compiler | Every build (`aws-lc-rs`) |
| Go + cmake | The `fips` feature |
| `nats-server` | NATS integration tests and the bridge runtime |
| Helm 3.x | Chart deployment |

See [Configuration](./configuration.md) to bring up your first instance.
