# Mental Model

This document explains *how rustgate thinks* — the abstractions, the message lifecycle, the trust model, and the extension points. After reading this you should be able to predict, given a configuration and a message, where that message ends up and why.

If you haven't run the [10-minute walkthrough](getting-started.md) yet, do that first. This document assumes you've seen rustgate route at least one message end to end.

## Table of contents

1. [The one-line definition](#the-one-line-definition)
2. [The message lifecycle](#the-message-lifecycle)
3. [Four fundamental abstractions](#four-fundamental-abstractions)
4. [The trust model](#the-trust-model)
5. [The four extension points](#the-four-extension-points)
6. [Feature flags, grouped by intent](#feature-flags-grouped-by-intent)
7. [Common failure modes — symptom → cause → fix](#common-failure-modes--symptom--cause--fix)
8. [Where to read source when curiosity strikes](#where-to-read-source-when-curiosity-strikes)

## The one-line definition

> rustgate accepts mTLS-authenticated clients, derives an identity from each client's certificate, and routes typed messages between identities, groups, peers, and external sinks under a policy engine.

Everything else is plumbing for that sentence.

## The message lifecycle

```
                    ┌─────────────────────────────────────────────────┐
                    │  Client connects (TLS, WebSocket, MQTT, MAVLink) │
                    └─────────────────────────────────────────────────┘
                                          │
                                          ▼
                    ┌─────────────────────────────────────────────────┐
                    │   mTLS handshake → extract Identity from cert    │
                    │   (rustgate-tls::extract_identity)               │
                    └─────────────────────────────────────────────────┘
                                          │
                                          ▼
                    ┌─────────────────────────────────────────────────┐
                    │   Codec decodes wire bytes → RoutableMessage     │
                    │   (CoT, MAVLink, MQTT, Meshtastic, VMF, DIS, …)  │
                    └─────────────────────────────────────────────────┘
                                          │
                                          ▼
                    ┌─────────────────────────────────────────────────┐
                    │   Router::route(msg)                             │
                    │     ↓ ACL check (group-based)                    │
                    │     ↓ Authz PEP/PDP (Cedar policy)               │
                    │     ↓ Dedup + replay filter                      │
                    │     ↓ Backpressure + per-tenant quota            │
                    │     ↓ Obligation application (egress envelopes)  │
                    └─────────────────────────────────────────────────┘
                                          │
                ┌────────────┬─────────────┼─────────────┬────────────┐
                ▼            ▼             ▼             ▼            ▼
        ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  Direct  │ │  Group     │ │ Federation│ │   NATS   │ │ HTTP /   │
        │  client  │ │  fanout    │ │   peer    │ │ JetStream│ │ webhook  │
        └──────────┘ └────────────┘ └──────────┘ └──────────┘ └──────────┘
                                          │
                                          ▼
                    ┌─────────────────────────────────────────────────┐
                    │  Audit log (hash-chained, tamper-evident)        │
                    │  Prometheus counters (per-identity, per-group)   │
                    └─────────────────────────────────────────────────┘
```

Every arrow is a place where something can be observed (metrics), enforced (policy), or rejected (typed audit event). When operators ask "why didn't my message get there?" the answer is always one of those steps.

## Four fundamental abstractions

If you understand these four types, you understand rustgate.

### 1. `Identity` — *who*

Defined in `rustgate-core::identity`. Derived from the client certificate during the TLS handshake by `rustgate-tls::extract_identity`. Carries:

- `cn: Arc<str>` — Common Name (the client's "name")
- `tenant: Option<String>` — Organization field (the multi-tenant key)
- `groups: Vec<GroupId>` — derived from cert SAN entries or operator policy
- `fingerprint: CertFingerprint` — SHA-256 hash of the full cert (stable over rotations)
- `attributes: HashMap<String, AttrValue>` — RBAC/ABAC attributes for Cedar policy

Identity is **immutable for the life of a connection**. A cert rotation requires a reconnect. This is intentional — identity is the security boundary, not a runtime mutable.

### 2. `RoutableMessage` — *what*

Defined in `rustgate-core::message`. Carries:

- `source: Identity` — the sender (proven by mTLS)
- `destination: Destination` — Group / Direct / Broadcast / Multicast
- `payload: Bytes` — opaque body (the wire format depends on the codec)
- `metadata: Metadata` — `received_at`, `source_protocol` ("cot", "mavlink", "nats", …), `message_type`, `tenant_id`, `trace_context`, `classification`, optional `ttl`

`Metadata` is `#[non_exhaustive]` with `with_*` builder methods. That's how we keep adding fields without churning every call site (we did this 6+ times this year).

### 3. `Destination` — *where*

Four variants in `rustgate-core::message`:

```rust
enum Destination {
    Group(GroupId),         // every connected member of the group
    Direct(CertFingerprint),// one specific client
    Broadcast,              // every connected client
    Multicast(Vec<GroupId>),// fan out to multiple groups (PEP per-group)
}
```

Most CoT traffic is `Group`. Direct messages and broadcasts are rare. Multicast is the interesting case — it's one inbound message, multiple outbound copies, each with potentially different obligations applied (e.g. classification re-marking per recipient group).

### 4. `EntityCodec` — *translation*

The seam between wire formats and the router's domain model. Each wire format ships its own crate (`rustgate-cot`, `rustgate-meshtastic`, `rustgate-vmf`, `rustgate-dis`, `rustgate-link16`, `rustgate-sapient`, `rustgate-nffi`, `rustgate-asterix`, `rustgate-stanag4586`, `rustgate-mavlink`). Each implements:

```rust
trait EntityCodec {
    fn name(&self) -> &str;
    fn decode(&self, payload: &[u8]) -> Result<Entity, CodecError>;
    fn encode(&self, entity: &Entity) -> Result<Bytes, CodecError>;
}
```

The router doesn't know about CoT XML or MAVLink heartbeats. It knows about `Entity`. The codec is the only place where wire-format specifics live, which is why we can fuzz each one independently and confidently — see `fuzz/fuzz_targets/`.

`Entity` is a canonical "thing in the world" — typically a track, position, sensor reading, or chat message. Two clients speaking different wire formats can interoperate because both ends decode to `Entity`, route through the same `Router`, and re-encode at the egress.

## The trust model

Five tenets, in order of strictness:

1. **Every connection is mTLS.** No plaintext fallback. No anonymous clients. Identity is proven, not asserted.
2. **Every routing decision is policy-evaluated.** ACL is the fast path (group-based, sub-microsecond); Cedar is the rich path (RBAC/ABAC with attributes). Both run before any message reaches its destination.
3. **Every authorized event is audit-logged.** The audit log is hash-chained (SHA-256 chain, see `rustgate-archive::audit_chain`) so insertion, deletion, or modification of past entries is detectable. The chain is sealed with a terminator on graceful shutdown.
4. **Every message has provenance.** `Metadata` carries the source identity and (for federated traffic) the chain of peer hops. Loop detection drops messages whose own peer ID appears in the provenance.
5. **Every secret is `Zeroizing`.** Bearer tokens, JWT secrets, certificate keys, encryption keys — all wrapped in `zeroize::Zeroizing<T>` so they're scrubbed from memory on drop. Comparisons use `subtle::ConstantTimeEq`. There's a CI gate (`scripts/check-playbook-drift.sh`) that catches regressions.

If you're auditing rustgate, those five tenets are the security argument.

## The four extension points

When you want to make rustgate do something new, you almost certainly want one of these four things — and exactly one of them.

### A. New wire format → new codec crate

Pattern: copy `rustgate-meshtastic` or `rustgate-asterix`. Implement `EntityCodec`. Register at startup in `rustgate-server::setup`. The router automatically dispatches inbound bytes to your codec by `source_protocol`. Outbound messages with matching `Entity` types get re-encoded by your codec before egress.

Recent examples: Meshtastic (#1321), VMF (#1322), DIS (#1323), JREAP/Link 16 (#1325), SAPIENT (#1327), NFFI (#1335), OGC SensorThings (#1336).

### B. New policy backend → new `PolicyEngine` impl

Pattern: see `rustgate-authz`. The default backend is the lightweight ACL; the optional `cedar` feature swaps in a full Cedar evaluator. To add a third (e.g. OPA/Rego), implement `PolicyEngine`, register behind a feature flag. The router calls your engine via the existing PEP hooks — no router changes needed.

### C. New peer-discovery backend → new `PeerDiscovery` impl

Pattern: see `rustgate-federation::discovery`. Today: DNS-SD, Consul, etcd. To add Kubernetes (via the operator's pod DNS), or a custom service mesh, implement `PeerDiscovery`. Hot-reload is built into the trait — your impl emits a `Vec<PeerConfig>` snapshot; the federation manager diffs.

### D. New external integration → new bridge crate

Pattern: see `rustgate-lattice`, `rustgate-foundry`, `rustgate-dds`, `rustgate-ogc-sensorthings`. Define a `Bridge` trait. Ship a `MockBridge` for tests. Wire two background tasks (outbound: subscribe to router, push to external system; inbound: subscribe to external system, push to router). The real SDK adapter goes behind a separate feature flag (`*-real`) so partner-NDA-gated dependencies don't bleed into the default build.

If your work doesn't fit one of these four patterns, you're probably over-engineering. The router itself almost never needs new code — most "new features" become a new codec or a new bridge.

## Feature flags, grouped by intent

There are 30+ feature flags. Grouping them by what they enable:

### Wire-format protocols
`mqtt`, `websocket`, `nats`, `enrollment`, `est`, `proto`, `full-detail`, `meshtastic`, `vmf`, `dis`, `link16`, `sapient`, `nffi`, `ogc-sensorthings`, `mavlink`

Pick by deployment. ATAK only? `default`. ATAK + drone fleet? `+mavlink`. NATO coalition? `+nffi`.

### Security
`fips`, `post-quantum`, `ocsp`, `spiffe`, `tenant-isolation` (default-on for multi-tenant deployments)

These compose. `fips` swaps to the AWS-LC FIPS-validated crypto provider. `post-quantum` enables hybrid key exchange. `ocsp` enables stapling for revocation. `spiffe` enables SVID workload identity. The compatibility matrix is in [`fips.md`](fips.md) and [`post-quantum.md`](post-quantum.md).

### External integrations
`federation`, `federation-ha`, `http`, `lattice`, `lattice-mock`, `foundry`, `foundry-mock`, `dds`, `dds-mock`, `marti-compat`, `missions`, `cjadc2`, `mesh-routing`, `inference`, `inference-mock`, `inference-onnx`

Most of these are partner-bridge crates with a `*-mock` companion. Ship `*-mock` in CI (deterministic, no SDK dependency). Ship `*-real` when the partner SDK is available.

### Operations
`metrics` (Prometheus), `otel` (OpenTelemetry tracing), `management-api`, `correlation` (multi-sensor track fusion), `peer-discovery`, `peer-discovery-dns-sd`, `peer-discovery-consul`, `peer-discovery-etcd`, `jemalloc`

Operations features rarely affect protocol behavior — they're observability and orchestration knobs.

### Documentation / scaffolding
`schema`, `cedar`, `video`

Niche. `schema` exposes JSON schema for the TOML config (used by the migrate-config CLI). `cedar` swaps the policy backend. `video` adds the in-memory video stream catalog.

## Common failure modes — symptom → cause → fix

| Symptom | Common cause | Where to look |
|---|---|---|
| ATAK shows red dot on first connect | Client cert not signed by the CA rustgate trusts | `--ca` flag points at the wrong CA; check `audit::client_tls_error` events |
| Messages disappear silently | ACL doesn't include the destination group | Run `GET /api/acl/groups`; check Cedar policy if `cedar` feature is on |
| `forbidden: identity not in any group` on connect | Client cert lacks `O=` field or SAN entries | Check the client cert subject; either fix the cert or add a fallback group in the ACL config |
| Federation peer drops every 90s | JWT issuer mismatch; clock skew >5min | Check `audit::federation_peer_disconnected`; `chrony` / `ntpd` on both ends |
| `rustgate_router_dropped_total` rising | Backpressure: client queue full | Slow consumer; raise `--max-queued-bytes` or fix the consumer |
| Authz allow rule does nothing | PolicyEngine swap stuck on old version | `POST /api/config/reload`; watch `rustgate_authz_reloads_total` |
| TLS handshake completes, no traffic | Codec mismatch (server expects CoT, client sends MAVLink) | Check `--framing` flag; the source protocol is in `Metadata.source_protocol` |
| FIPS build fails to start | `--fips-required` set but FIPS provider not active | Check the build was `cargo build --features fips`; check `audit::tls_handshake_failed` |
| Federation falls behind on bursts | Federation peer's queue is slower than ingress | Check `rustgate_federation_peer_queue_bytes`; bump per-peer queue cap |
| Audit log can't be verified | Disk full mid-write; chain torn | `audit_chain::verify_audit_log` returns the last good index; truncate-and-replay from there |
| Cert hot-reload fires but new cert isn't used | Reload polled mid-write of cert files | Use atomic `mv` rename to swap; the next poll will succeed |
| Position cache holds stale tracks | TTL not configured or too long | `--position-cache-ttl-secs`; default is 15s for tactical |
| Multi-tenant labels stuck at `_overflow` | Tenant cardinality exceeded `MAX_TENANT_LABELS = 256` | Audit which tenants are real vs spoofed; raise the cap or fix the cert OU population |

If your symptom isn't here, the structured tracing logs almost always say what happened. Filter by target: `audit` for security events, `rustgate_router::route` for routing, `rustgate_federation` for peering, `rustgate_tls` for handshake issues.

## Where to read source when curiosity strikes

| Question | File |
|---|---|
| What does the router do step by step? | `crates/rustgate-router/src/router.rs::Router::route_for_egress` |
| How is identity extracted from a cert? | `crates/rustgate-tls/src/extract.rs::extract_identity` |
| Where does an inbound TLS frame become a `RoutableMessage`? | `crates/rustgate-tls/src/listener.rs` + `crates/rustgate-transport/src/codec.rs` |
| How does the audit chain stay tamper-evident? | `crates/rustgate-archive/src/audit_chain.rs` |
| What does the policy hot-reload actually swap? | `crates/rustgate-router/src/router.rs` — search `ArcSwap` |
| Where does store-and-forward write to disk? | `crates/rustgate-router/src/store_forward.rs` (redb-backed) |
| How is multicast obligation evaluation distributed? | `crates/rustgate-router/src/router.rs::prepare_egress_envelope` |
| Where do new wire formats register? | `crates/rustgate-server/src/setup.rs` (search `EntityCodecRegistry`) |
| What's the federation peer state machine? | `crates/rustgate-federation/src/manager.rs::FederationManager` |
| How does the K8s operator render manifests? | `crates/rustgate-operator/src/render.rs` |

The architecture is layered: `rustgate-core` → `rustgate-tls`/`rustgate-archive`/`rustgate-metrics` → wire-format codecs and policy engines → `rustgate-router` → `rustgate-transport`/`rustgate-federation`/etc. → `rustgate-server` (binary). Cycles are forbidden; every layer-violation is caught at compile time. If you find yourself trying to import "downward," you're probably trying to extend in the wrong place — check the [four extension points](#the-four-extension-points) above.
