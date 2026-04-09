# Workspace Crates

The rustgate workspace contains 12 crates. Each has a single responsibility and inherits all version, edition, and lint settings from the workspace root via `[lints] workspace = true`.

| Crate | Purpose |
|---|---|
| `rustgate-authz` | Per-message RBAC/ABAC authorization with JSON and Cedar policy backends, sharded LRU cache, hot-reload. |
| `rustgate-core` | Shared types: `Identity`, `RoutableMessage`, error handling, hash-chained audit log, encrypted-at-rest archive. |
| `rustgate-cot` | Cursor-on-Target XML parsing and validation. The protocol-specific layer is isolated here so other codecs can be added without touching transport. |
| `rustgate-enrollment` | Certificate enrollment server: PKCS#12 bundle issuance and EST (RFC 7030) endpoints, with per-IP rate limiting. |
| `rustgate-federation` | Server-to-server federation (v1 framed and v2 gRPC), JWT auth, replay buffer with optional disk persistence, high-availability coordination, dynamic peer discovery (DNS-SD, Consul, etcd). |
| `rustgate-mqtt` | MQTT 5.0/3.1.1 transport adapter with mTLS client authentication and topic-to-group mapping. |
| `rustgate-nats` | NATS / JetStream bridge with consumer-lag metrics. |
| `rustgate-proto` | Protobuf message definitions (`prost` / `tonic`) and XML ↔ protobuf codecs. |
| `rustgate-transport` | TLS listener, mTLS handshake, CRL and OCSP enforcement, FIPS provider, codec, router, and admission control. |
| `rustgate-websocket` | WebSocket transport layer. |
| `rustgate-server` | Binary entrypoint, CLI, orchestration, ACL hot-reload, health probes, graceful drain, authorization wiring. |
| `rustgate-test-utils` | Test certificate generation (`TestCa`, CRL generation). Excluded from `unwrap_used`/`panic` lints since test failures should panic. |

## Hard rules

These constraints are enforced workspace-wide and apply to every crate:

1. **`unsafe_code = "forbid"`** — no exceptions.
2. **`clippy::panic = "deny"`** and **`clippy::unwrap_used = "deny"`** in production code. Use `Result`, `?`, `ok_or_else`, and `map_err`.
3. **Edition 2024**, `rust-version = "1.93"`.
4. **Workspace dependency inheritance** — every dependency is declared once in the root `Cargo.toml` and referenced as `{ workspace = true }` from each crate.
5. **Conventional commits** with type + scope: `feat(transport): …`, `fix(federation): …`, `docs(...): …`, etc.

See [`CONTRIBUTING.md`](https://github.com/rchiofalo/rustgate/blob/main/CONTRIBUTING.md) for the full lint policy and PR rules.
