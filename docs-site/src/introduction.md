# rustgate

**rustgate** is a tactical mTLS message router written in Rust. It is a single-binary, edge-ready alternative to heavyweight Java messaging servers — designed to run in resource-constrained environments without sacrificing security, observability, or operational rigor.

While the original motivating use case was Team Awareness Kit (TAK) traffic, the architecture is protocol-agnostic. It routes any message that fits its codec interface and authenticates clients via mutual TLS with group membership derived from X.509 certificates.

## What this site covers

This documentation is the canonical reference for operators, integrators, and contributors. It mirrors the in-repo `docs/` tree and is rebuilt automatically from `main` whenever documentation changes.

- **Getting Started** — install, run, and configure a single instance.
- **Architecture** — every workspace crate, the wire protocol, transport, federation, NATS bridging, and enrollment.
- **Operations** — deployment, observability, performance tuning, disaster recovery, graceful degradation, and a complete runbook library.
- **Security** — threat model, mTLS configuration, FIPS 140-3, post-quantum key exchange, and crypto agility.
- **Reference** — REST API and the full configuration surface.

## Project at a glance

- **Rust workspace** with 13 crates and edition 2024 (`rust-version = 1.94`)
- **`unsafe_code = "forbid"`** workspace-wide; `clippy::panic` and `clippy::unwrap_used` denied in production code
- **rustls + tokio-rustls** by default; **aws-lc-rs** under the `fips` feature for FIPS 140-3
- **Post-quantum** key exchange via X25519MLKEM768 (`post-quantum` feature)
- **Multi-transport** — TLS, WebSocket, MQTT 5.0/3.1.1, plaintext TCP/UDP
- **EST (RFC 7030)** enrollment alongside PKCS#12 certificate provisioning
- **Per-message authorization** — RBAC/ABAC with JSON and Cedar policy backends
- **Federation v2** server-to-server with JWT, HA coordination, and dynamic peer discovery (DNS-SD, Consul, etcd)
- **NATS / JetStream** bridge for horizontal scale
- **Hash-chained, tamper-evident audit log** and **encrypted-at-rest archive**

## Source

- Repository: <https://github.com/rchiofalo/rustgate>
- License: Proprietary — see [LICENSE](https://github.com/rchiofalo/rustgate/blob/main/LICENSE)
- Security policy: [SECURITY.md](https://github.com/rchiofalo/rustgate/blob/main/SECURITY.md)
