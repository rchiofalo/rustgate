# rustgate-transport

mTLS listener, codec library, router, and ACL / authz integration.

## Role in the workspace

`rustgate-transport` is the dataplane crate. It owns the TLS listener, the
identity-extraction path, the codec implementations, the message router
(with Send / Receive PEP, obligation actuators, dedup, position cache,
multicast egress, and store-and-forward), the per-tenant quota tracker, and
the dynamic CA verifier. It depends on
[rustgate-core](../rustgate-core/README.md),
[rustgate-cot](../rustgate-cot/README.md),
[rustgate-authz](../rustgate-authz/README.md), and
[rustgate-resilience](../rustgate-resilience/README.md). Optionally pulls in
[rustgate-proto](../rustgate-proto/README.md) and
[rustgate-mavlink](../rustgate-mavlink/README.md). Consumed by
[rustgate-server](../rustgate-server/README.md),
[rustgate-websocket](../rustgate-websocket/README.md),
[rustgate-mqtt](../rustgate-mqtt/README.md),
[rustgate-nats](../rustgate-nats/README.md), and
[rustgate-federation](../rustgate-federation/README.md).

## Public API surface

- `TlsListener`, `TlsConfig`, `TlsMinVersion`, `OnHandshakeError`,
  `OnHandshakeDuration` — the mTLS accept loop with per-IP rate limiting,
  CRL enforcement, and pluggable cert reloaders
- `Router`, `SessionHandle`, `RoutedMessage`, `AuthzObserver`,
  `AuthzEvent` — the routing engine; hot-reloadable ACL / authz / dedup
  via `ArcSwap`; Send + Receive PEP; obligation actuation
- `extract_identity`, `validate_key_usage`, `ExpectedKeyUsage` —
  certificate-to-`Identity` extraction, the trust boundary for every
  authenticated session
- `CertReloader`, `DynamicCertVerifier`, `RootStoreProvider` —
  zero-downtime certificate hot-reload and dynamic trust store
- `LengthPrefixedCodec`, `LineDelimitedCodec`, `XmlStreamCodec`,
  `RawLengthPrefixedCodec`, `RawLineCodec`, `TakXmlCodec`,
  `FramedCodec`, `FramedCodecError` — protocol codecs
- `GroupAcl`, `GroupAclPolicy` — group-based ACL evaluated alongside the
  authz engine
- `PositionCache`, `OnCacheSize` — per-CN latest-position cache with TTL
  sweep and clock-backwards tolerance
- `DedupCache`, `OnDuplicate`, `OnInsert` — bounded LRU dedup keyed by
  SHA-256 of `uid || time_le || payload`
- `MessageFilter`, `GeoBounds`, `ReplayFilter`, `EmergencyRepeater`,
  `ClientThrottle`, `ThrottleConfig` — auxiliary filters and throttles
- `ClientQueue`, `StoreForwardError`, `OnDrainObservation`, `QueueStats` —
  redb-backed durable per-client store-and-forward queue
- `TenantQuotaTracker`, `TenantQuota`, `QuotaConfig`, `DEFAULT_TENANT_KEY` —
  per-tenant connection / rate quotas keyed on cert Organization (O)
- `PlaintextListener`, `PlaintextSession`, `PlaintextIdentityConfig` —
  TCP plaintext input for trusted-network deployments
- `UdpInput`, `UdpInputConfig`, `CidrPrefix` — UDP plaintext input with
  per-IP rate limiting and CIDR allowlist
- `BackpressureGate`, `BackpressurePermit` (re-exports) — global egress
  byte-count admission gate
- `ClientOcspVerifier`, `OcspFetcher`, `OcspStaplerFetcher` — OCSP-cached
  client-cert verifier (gated by `ocsp`); SPIFFE workload-API identity
  (gated by `spiffe`)

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `proto` | Pulls in [rustgate-proto](../rustgate-proto/README.md) for the TAK protobuf codec and XML/protobuf negotiation | No |
| `mavlink` | Pulls in [rustgate-mavlink](../rustgate-mavlink/README.md) for the MAVLink frame codec | No |
| `fips` | aws-lc-rs in FIPS mode | No |
| `post-quantum` | X25519MLKEM768 hybrid key exchange | No |
| `ocsp` | OCSP stapling and client-cert OCSP verification | No |
| `spiffe` | SPIFFE / SPIRE workload-identity integration | No |

## Topology / deployment notes

The router is the single fan-out point: every transport adapter
(`rustgate-websocket`, `rustgate-mqtt`, etc.) registers a `SessionHandle`
with the same router instance, so messages from a TCP client can be
delivered to a WebSocket client and vice versa. ACL, authz engine, and
dedup cache are held inside `ArcSwap<Option<...>>` so SIGHUP reloads are
lock-free for readers. Store-and-forward queues are keyed per CN and
re-evaluated against the current ACL + authz on drain, so a policy change
while a client was offline is enforced on reconnect.

## Where to look first

- `crates/rustgate-transport/src/router.rs` — Send / Receive PEP, fan-out,
  obligation actuation, dedup
- `crates/rustgate-transport/src/listener.rs` — TLS accept loop, handshake
  rate limiting, identity extraction
