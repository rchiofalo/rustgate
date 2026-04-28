# rustgate-federation

Server-to-server federation for cross-network message routing.

## Role in the workspace

`rustgate-federation` connects rustgate instances into a mesh and forwards
routable messages across the wire while honouring loop-prevention and
per-peer authorization. It depends on
[rustgate-core](../rustgate-core/README.md),
[rustgate-resilience](../rustgate-resilience/README.md) (shared circuit
breaker), and [rustgate-transport](../rustgate-transport/README.md) (TLS
config and identity types). The gRPC-based V2 protocol pulls in
[rustgate-proto](../rustgate-proto/README.md) under `--features v2`. Wired
into [rustgate-server](../rustgate-server/README.md) under
`--features federation`.

## Public API surface

- `manager::FederationManager` — orchestrates peer connections, heartbeats,
  circuit breakers, peer-list hot-reload, and message forwarding
- `connector::PeerConnector` — outbound mTLS dialer with retry/backoff
- `peer::{PeerHandle, PeerStatus}` — per-peer state machine wrapping
  `rustgate_resilience::circuit::CircuitBreaker`
- `provenance` — hop-count + visited-peer tracking so a message cannot loop
  through more than `--federation-max-hops` (default 8)
- `replay_buffer`, `replay_persist::ReplayStoreError` — bounded in-memory
  buffer plus a `redb`-backed durable variant for offline-peer replay
- `store` — file-backed peer registry consumed by the SIGHUP reloader
- `trust_store::TrustStore` — dynamic CA bundle the verifier loads via
  `ArcSwap`, supporting per-peer trust roots
- `jwt::{JwtAuthority, JwtError}`, `jwks::JwkSet` — federation token issuer
  and `/.well-known/jwks.json` JWKS endpoint (HS256 / ES256 / EdDSA)
- `v1` / `v2` — protocol implementations: V1 is length-prefixed XML over
  mTLS, V2 is gRPC over mTLS via tonic
- `discovery` — DNS-SD / Consul / etcd peer-discovery backends behind
  per-backend feature flags
- `ha` — NATS-KV claim manager so multi-pod deployments distribute peer
  ownership without double-connections
- `api` — REST API for peer CRUD, certificate management, and JWKS
- `FederationError`, `Result` — typed error enum for connector, manager,
  and protocol failures

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `v2` | gRPC V2 protocol; pulls in `tonic`, `prost`, and the `rustgate-proto` codegen | No |
| `ha` | NATS-KV-backed claim manager for multi-pod peer ownership | No |
| `api` | REST API for peer CRUD + JWKS endpoint; pulls in `hyper` | No |
| `fips` | aws-lc-rs in FIPS mode for outbound TLS and tonic | No |
| `post-quantum` | X25519MLKEM768 hybrid key exchange | No |
| `peer-discovery-dns-sd` | DNS-SD / mDNS peer discovery | No |
| `peer-discovery-consul` | Consul catalog peer discovery | No |
| `peer-discovery-etcd` | etcd prefix-scan peer discovery | No |
| `peer-discovery` | Umbrella enabling all three discovery backends | No |

## Topology / deployment notes

Federation is server-to-server only — clients never speak federation
protocols. Both V1 and V2 require mutual TLS with peer-cert verification
against the configured trust store. The HA mode uses NATS KV to coordinate
which pod owns each outbound peer connection, so a horizontally scaled
deployment does not multiply the connection count by the replica count.

## Where to look first

- `crates/rustgate-federation/src/manager.rs` — top-level lifecycle and the
  hot-reload entry point
- `crates/rustgate-federation/src/v2/` — gRPC server, client, and
  conversion code (the authoritative protocol path)
