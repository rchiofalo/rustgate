# Observability

rustgate provides three observability pillars: structured JSON logs (always on), Prometheus metrics (`--features metrics`), and distributed tracing (`--features otel`).

For the full per-metric catalogue (154 Prometheus metrics across all crates, grouped by operational domain with recommended alerts), see [metrics-reference.md](metrics-reference.md).

For the audit-event catalogue (86 event types across 32 domains, with sanitization and hash-chain integrity guarantees), see [audit-events-reference.md](audit-events-reference.md).

## Distributed Tracing (OpenTelemetry)

When built with the `otel` feature, rustgate exports traces via the [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otlp/) over gRPC. Any OTLP-compatible backend works: Jaeger, Grafana Tempo, Honeycomb, Datadog, etc.

### Enabling

```bash
# Build with OTel support
cargo build --release --features otel

# Run with OTLP export
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
  --otel-endpoint http://localhost:4317
```

### Configuration

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--otel-endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | *(none — disabled)* | OTLP gRPC endpoint |
| `--otel-service-name` | `OTEL_SERVICE_NAME` | `rustgate` | Service name in traces |

When `--otel-endpoint` is not set, OTel tracing is disabled even if compiled with the feature — zero overhead.

### Instrumented Spans

All hot-path spans use `debug` level to avoid excessive trace volume under load.
Set `RUST_LOG=debug` (or a more targeted filter like `RUST_LOG=rustgate_transport=debug`)
to include them in traces.

| Span | Level | Crate | Description |
|------|-------|-------|-------------|
| `tls_handshake` | `info` | `rustgate-transport` | TLS handshake duration per connection |
| `route` | `debug` | `rustgate-transport` | Message routing (direct, group, broadcast) |
| `federation_forward` | `debug` | `rustgate-federation` | Message forwarding to federation peers |
| `nats_publish` | `debug` | `rustgate-nats` | NATS message publish |
| `nats_recv` | `debug` | `rustgate-nats` | NATS message receive and local delivery |

### Jaeger Setup

```yaml
# docker-compose.yml
services:
  jaeger:
    image: jaegertracing/all-in-one:1.58
    ports:
      - "4317:4317"   # OTLP gRPC
      - "16686:16686" # UI
    environment:
      COLLECTOR_OTLP_ENABLED: "true"
```

Then start rustgate with `--otel-endpoint http://localhost:4317` and open the Jaeger UI at `http://localhost:16686`.

### Grafana Tempo Setup

```yaml
# docker-compose.yml
services:
  tempo:
    image: grafana/tempo:2.6
    command: ["-config.file=/etc/tempo.yaml"]
    ports:
      - "4317:4317"   # OTLP gRPC
      - "3200:3200"   # Tempo API
    volumes:
      - ./tempo.yaml:/etc/tempo.yaml

  grafana:
    image: grafana/grafana:11
    ports:
      - "3000:3000"
    environment:
      GF_AUTH_ANONYMOUS_ENABLED: "true"
      GF_AUTH_ANONYMOUS_ORG_ROLE: Admin
```

Example `tempo.yaml`:

```yaml
server:
  http_listen_port: 3200

distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: "0.0.0.0:4317"

storage:
  trace:
    backend: local
    local:
      path: /tmp/tempo/blocks
```

### Performance

- Spans are batched before export (default `opentelemetry_sdk` batch settings).
- When the `otel` feature is not compiled, there is zero runtime cost — no span collection, no allocations.
- When compiled but `--otel-endpoint` is not set, span collection is not active.

### Kubernetes / Helm

Set the endpoint via environment variable in your values override:

```yaml
env:
  - name: OTEL_EXPORTER_OTLP_ENDPOINT
    value: "http://otel-collector.monitoring:4317"
```
