# rustgate

Rust-native secure message router with pluggable protocol support. Built for tactical edge deployment.

## Why

Existing tactical messaging servers are Java monoliths requiring 8GB+ RAM, multiple JVM processes, and complex module stacks. They work in garrison but fall apart at the edge where resources are constrained and reliability matters most. Federation-only alternatives exist but don't handle client connections.

rustgate is a lightweight alternative that handles mTLS client connections, routes messages by group membership derived from client certificates, and exposes a pluggable protocol interface for future adapters. Pure Rust, single binary, minimal footprint.

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                                rustgate-server                                │
│                                    (binary)                                   │
├──────────────┬──────────────┬──────────────┬──────────────┬──────────────┬──────────────┤
│  rustgate-   │  rustgate-   │  rustgate-   │  rustgate-   │  rustgate-   │  rustgate-   │
│  transport   │  websocket   │  nats        │  enrollment  │  proto       │  federation  │
│  TLS·codec   │  wss://mTLS  │  NATS pubsub │  HTTPS·CSR   │  TAK protobuf│  V1·V2·gRPC  │
│  router      │  WS sessions │  JetStream   │  Basic Auth  │  XML↔proto   │  peer mgmt   │
├──────────────┴──────────────┴──────────────┼──────────────┴──────────────┴──────────────┤
│                rustgate-cot                 │                rustgate-core               │
│        CoT XML parsing · MessageBuilder     │    Identity · RoutableMessage · framing    │
└─────────────────────────────────────────────┴────────────────────────────────────────────┘
```

**rustgate-core** — Shared types: `Identity` (CN + groups + fingerprint), `RoutableMessage`, `Destination` (Broadcast / Group / Direct), framing strategies.

**rustgate-cot** — Cursor on Target (CoT) XML parsing and `MessageBuilder` for converting raw CoT payloads into `RoutableMessage` with destination inference, group extraction, and position detection. Shared across transport and websocket layers.

**rustgate-transport** — mTLS listener with client certificate verification, X.509 identity extraction (CN → identity, OU → groups, SHA-256 → fingerprint), length-prefixed / XML stream / line-delimited codecs, and a routing engine that delivers messages by broadcast, group, or direct address. Sessions are managed with atomic IDs to prevent stale task eviction on reconnect.

**rustgate-websocket** — Optional WebSocket (wss://) listener with mTLS client authentication. `WsListener` binds a TCP socket with SO_REUSEADDR and TCP keepalive, then upgrades connections through TLS → WebSocket. `WsSession` extracts identity from the client certificate. `WebSocketServer` manages the accept loop and session lifecycle — sessions register with the `Router`, replay cached positions, and run split read/write loops with timeout enforcement and bounded channel backpressure. WebSocket and TCP clients are fully interoperable. Feature-gated behind `--features websocket`.

**rustgate-nats** — Optional NATS bridge for stateless horizontal scaling. Publishes position updates to NATS subjects, subscribes for cross-instance delivery, and replays JetStream history on startup for situational awareness bootstrap. Two-layer echo prevention ensures messages are never re-published to their origin. Feature-gated behind `--features nats`.

**rustgate-enrollment** — Optional HTTPS enrollment server for TAK client certificate self-provisioning. Implements the Marti v2 certificate signing protocol: clients authenticate with HTTP Basic Auth, submit a PKCS#10 CSR, and receive a signed client certificate + CA cert in JSON or XML. Server-only TLS (no client cert required). Subject DN is enforced from the authenticated username to prevent impersonation. Feature-gated behind `--features enrollment`.

**rustgate-proto** — Optional TAK protocol buffer translation. Bidirectional conversion between CoT XML and TAK protobuf (prost), with the `TakFrameCodec` for TAK binary framing (0xBF + varint length). Known `<detail>` children (`<contact>`, `<__group>`, `<precisionlocation>`, `<status>`, `<takv>`, `<track>`) map to typed protobuf fields; everything else roundtrips through the `xmlDetail` residual. Translation happens at session edges — XML stays canonical inside the router. Includes TAK protocol negotiation: server advertises `t-x-takp-v`, client can upgrade to protobuf with a TakControl handshake, or stay XML for legacy compatibility. Feature-gated behind `--features proto`. Requires `protoc` at build time.

**rustgate-federation** — Optional server-to-server federation for sharing situational awareness between independent TAK Server networks. Supports V1 (length-prefixed XML over mTLS) and V2 (gRPC over mTLS with FederatedChannel service). Includes provenance-based loop detection with configurable hop limits, CoT heartbeat monitoring, automatic reconnection with exponential backoff, dynamic CA trust store for runtime certificate management, persistent peer storage (JSON file or NATS KV), HA mode with distributed claims for multi-pod deployments, REST API for peer CRUD and certificate management, and Prometheus metrics. Feature-gated behind `--features federation`. Requires `protoc` at build time.

**rustgate-server** — Binary entry point. Accepts mTLS connections, spawns per-session read/write tasks, routes all traffic through the shared `Router`. Optionally accepts WebSocket clients when `--websocket-bind` is set. Optionally bridges to NATS when `--nats-url` is provided. Optionally runs enrollment when `--enrollment-bind` is set. Optionally federates with remote servers when `--federation-v1-bind` is set. Includes Prometheus metrics and health endpoints (feature-gated behind `--features metrics`), graceful shutdown with connection draining on SIGTERM, and configurable connection limits.

## Status

Core transport and routing are functional. The server accepts mTLS connections, extracts identity from client certificates, and routes messages between authenticated sessions.

**What works:**
- mTLS handshake with client certificate authentication
- Identity extraction from X.509 (CN, OU groups, SHA-256 fingerprint)
- Broadcast, group, and direct message routing
- Session lifecycle with reconnect handling
- Length-prefixed codec with overflow protection (16MB max frame)
- XML stream codec for TAK client connections
- Cursor on Target (CoT) message parsing
- Position cache with replay on connect
- NATS bridge for cross-instance message delivery (feature-gated)
- JetStream history replay for situational awareness bootstrap
- Two-layer echo prevention (protocol tag + instance header)
- Certificate enrollment (Marti v2 CSR signing, feature-gated)
- Subject DN enforcement from authenticated username (anti-impersonation)
- TLS handshake + HTTP request timeouts on enrollment server
- Streaming body size limits (pre-read rejection, not post-buffer)
- TAK protobuf translation (XML ↔ protobuf, feature-gated)
- TAK binary framing codec (0xBF + varint, 16MB max frame)
- Full CoT XML parser with typed detail field extraction
- ISO 8601 ↔ millis timestamp conversion (hand-rolled, no chrono dep)
- xmlDetail residual preservation for unknown detail elements
- TAK protocol negotiation (server advertises protobuf, client opts in or stays XML)
- NATS integration tests with embedded nats-server (publish/subscribe, echo prevention, JetStream replay, cross-instance delivery)
- Prometheus metrics: connection lifecycle, message routing, NATS bridge, protocol negotiation (feature-gated)
- Health endpoints: `/healthz` (liveness), `/readyz` (readiness), `/metrics` (Prometheus text format)
- Hardened HTTP metrics server: connection limit (128), per-connection timeout (15s), header read timeout (5s)
- Graceful shutdown: SIGTERM + SIGINT handling, readiness probe goes 503, connection draining with 110s timeout
- Environment variable configuration for all CLI flags (K8s-native)
- Configurable max connections (`--max-connections` / `RUSTGATE_MAX_CONNECTIONS`)
- Server-to-server federation with V1 (length-prefixed XML) and V2 (gRPC) protocol support (feature-gated)
- Provenance-based loop detection and configurable hop limits
- Automatic peer reconnection with exponential backoff
- CoT heartbeat monitoring (V1) and gRPC health checks (V2)
- Dynamic CA trust store for runtime certificate management
- Persistent peer storage (JSON file or NATS KV for multi-pod)
- HA mode with NATS KV distributed claims for outbound peer ownership
- Federation REST API for peer CRUD and certificate management
- Federation Prometheus metrics: connections, messages, errors, heartbeats
- NATS ↔ federation bridge with echo prevention
- WebSocket (wss://) listener with mTLS client authentication
- WebSocket session lifecycle with router integration (register, replay, route, unregister)
- WebSocket read/write timeout enforcement and bounded channel backpressure
- WebSocket + TCP client interoperability (same router, same groups)
- Audit logging for connection and federation events
- Marti contact API and data package upload/download/search
- Fuzz targets for XML codec, CoT parser, TAK frame codec, length-prefixed codec, and federation converter
- Criterion benchmarks for CoT parsing, codec throughput, and federation conversion
- Helm chart with Pod Security Standards (restricted), PDB, HPA, startup/liveness/readiness probes
- Multi-stage Dockerfile with OCI labels, HEALTHCHECK, STOPSIGNAL SIGTERM
- jemalloc allocator for production builds (avoids musl malloc contention, feature-gated)

**What's next:**
- Real TAK client compatibility testing (ATAK/iTAK/WinTAK)

## Building

```
cargo build --release
```

With NATS bridge support:
```
cargo build --release --features nats
```

With enrollment support:
```
cargo build --release --features enrollment
```

With TAK protobuf support (requires `protoc`):
```
cargo build --release --features proto
```

With Prometheus metrics and health endpoints:
```
cargo build --release --features metrics
```

With WebSocket support:
```
cargo build --release --features websocket
```

With federation support (requires `protoc`):
```
cargo build --release --features federation
```

With jemalloc (recommended for Alpine/musl production builds):
```
cargo build --release --features jemalloc
```

All optional features:
```
cargo build --release --all-features
```

Requires Rust 1.88+ (edition 2024).

## Running

```
rustgate --cert server.pem --key server-key.pem --ca ca.pem
```

With NATS bridge (requires `--features nats`):
```
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --nats-url nats://nats:4222
```

With enrollment (requires `--features enrollment`):
```
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --ca-key ca-key.pem \
    --enrollment-bind 0.0.0.0:8446 \
    --enrollment-user admin --enrollment-password changeme
```

With TAK protobuf framing (requires `--features proto`):
```
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --framing tak-protobuf --encoding tak-protobuf
```

With TAK protocol negotiation (recommended for real TAK clients, requires `--features proto`):
```
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --framing tak-negotiate
```

With WebSocket listener (requires `--features websocket`):
```
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --websocket-bind 0.0.0.0:8443
```

With metrics and health endpoints (requires `--features metrics`):
```
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --metrics-bind 0.0.0.0:9090
```

With federation (requires `--features federation`):
```
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --federation-v1-bind 0.0.0.0:9000
```

With federation and outbound peers from a JSON config file:
```
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --federation-v1-bind 0.0.0.0:9000 \
    --federation-peers-file peers.json \
    --federation-id my-server
```

All flags support environment variables (CLI takes precedence):

| Flag | Env Var | Default |
|------|---------|---------|
| `--bind` | `RUSTGATE_BIND` | `0.0.0.0:4433` |
| `--cert` | `RUSTGATE_CERT` | — |
| `--key` | `RUSTGATE_KEY` | — |
| `--ca` | `RUSTGATE_CA` | — |
| `--framing` | `RUSTGATE_FRAMING` | `xml` |
| `--encoding` | `RUSTGATE_ENCODING` | `raw` |
| `--max-connections` | `RUSTGATE_MAX_CONNECTIONS` | `1024` |
| `--metrics-bind` | `METRICS_BIND` | — |
| `--nats-url` | `NATS_URL` | — |
| `--nats-credentials` | `NATS_CREDENTIALS` | — |
| `--websocket-bind` | `WEBSOCKET_BIND` | — |
| `--enrollment-bind` | `ENROLLMENT_BIND` | — |
| `--ca-key` | `RUSTGATE_CA_KEY` | — |
| `--enrollment-user` | `ENROLLMENT_USER` | — |
| `--enrollment-password` | `ENROLLMENT_PASSWORD` | — |
| `--ca-organization` | `RUSTGATE_CA_ORG` | `rustgate` |
| `--federation-v1-bind` | `FEDERATION_V1_BIND` | — |
| `--federation-id` | `FEDERATION_ID` | `rustgate-federation-1` |
| `--federation-peers-file` | `FEDERATION_PEERS_FILE` | — |
| `--federation-skip-hostname-verify` | `FEDERATION_SKIP_HOSTNAME_VERIFY` | `false` |
| `--federation-max-hops` | `FEDERATION_MAX_HOPS` | `10` |
| `--federation-store-path` | `FEDERATION_STORE_PATH` | — |

## Docker

```
docker compose up
```

The Dockerfile builds all features (including jemalloc) and runs as UID 10001 with a read-only root filesystem. Health is checked via the `/healthz` endpoint on port 9090.

## Kubernetes

A Helm chart is provided in `helm/`:

```
helm install rustgate helm/ --set tls.secretName=my-tls-secret
```

The chart includes:
- Deployment with Pod Security Standards (restricted profile)
- Startup, liveness, and readiness probes via the metrics HTTP server
- PodDisruptionBudget (when replicas > 1 or HPA is enabled)
- HorizontalPodAutoscaler (opt-in via `autoscaling.enabled: true`)
- Pre-stop hook (5s sleep) for LB drain before SIGTERM
- `terminationGracePeriodSeconds: 120` with 110s drain timeout
- Optional federation support (`federation.enabled: true`) with peer config via Secret or values

TLS certificates must be provided as a Kubernetes Secret named by `tls.secretName` (default: `rustgate-tls`) containing `server.crt`, `server.key`, and `ca.crt`.

**Helm defaults vs CLI defaults:** The Helm chart defaults to `framing: tak-negotiate` and `encoding: tak-protobuf`, optimized for production TAK client deployments. The CLI defaults to `framing: xml` and `encoding: raw` for general-purpose use and testing. Override in Helm with `--set framing=xml,encoding=raw` if needed.

## Testing

```
cargo test
```

714 tests covering mTLS handshake, identity extraction, broadcast/group/direct routing, cross-group message rejection, position cache group scoping, session lifecycle, codec edge cases, frame size limits, XML stream codec (depth tracking, CDATA, self-closing tags, partial frames), line-delimited codec, NATS wire format serialization, subject sanitization, group extraction, echo prevention, CSR signing round-trips, CSR SAN stripping, subject DN enforcement, Basic Auth validation, response formatting, XML/JSON enrollment responses, enrollment HTTP integration (TLS handshake, content negotiation, auth rejection, body size limits), varint encode/decode, TAK frame codec round-trips, ISO 8601 timestamp conversion, full CoT XML parsing, XML↔protobuf bidirectional conversion with detail field preservation, TAK protocol negotiation message builders/validators, Prometheus metrics registration and HTTP serving, CLI environment variable configuration, federation provenance and loop detection, CoT heartbeat generation and detection, federation config and peer serialization, federate store persistence, federation V1/V2 protocol handling, gRPC FederatedChannel service, trust store certificate management, HA claim acquisition and release, connection registry, REST API endpoints, federation metrics, audit logging, Marti contact API, data package upload/download/search, directional group routing, WebSocket mTLS handshake and identity extraction, WebSocket session routing through the message router, and WebSocket connection limit enforcement. Unit tests use ephemeral certificates generated at runtime — no fixture files.

NATS integration tests (`cargo test -p rustgate-nats --test integration`) spin up a real `nats-server` subprocess with JetStream. Covers publish→subscribe round-trip, dual-layer echo prevention, cross-instance delivery, JetStream SA replay with LastPerSubject dedup, replay count limits, oversized payload rejection, group preservation, zero-position filtering, and wire format fidelity. Requires `nats-server` on PATH.

## License

Proprietary. See [LICENSE](LICENSE) for details.
