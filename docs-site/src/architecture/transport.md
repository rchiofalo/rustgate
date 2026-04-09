# Transport & mTLS

The transport crate (`rustgate-transport`) owns the TLS listener, mTLS handshake, CRL/OCSP enforcement, codec, router, and admission control. It is the lowest layer above the operating system socket and the only layer that ever touches raw bytes.

For TLS configuration, certificate rotation, and CRL/OCSP semantics see the dedicated security page: [TLS Certificates & mTLS](../security/mtls.md).

For the on-the-wire framing and message format see [Wire Protocol](./protocol.md).

## Responsibilities

- **TLS listener** — accepts mTLS connections via `rustls` (ring backend by default, `aws-lc-rs` under the `fips` feature).
- **Identity extraction** — derives the `Identity` (CN + group memberships) from the peer certificate during handshake.
- **CRL enforcement** — periodically loads CRLs from disk; revoked certificates are rejected on next connection attempt and may also trigger active disconnect of in-flight sessions.
- **OCSP stapling** — when enabled, validates server-stapled OCSP responses and optionally enforces client OCSP via Tier 1 client checks.
- **Codec** — frames inbound bytes into `RoutableMessage` envelopes; serializes outbound.
- **Router** — looks up destination identities in the in-memory routing table, deduplicates by message UID, and dispatches.
- **Admission control** — bounded backpressure gate (Tokio `Notify` + `AtomicUsize`) protects downstream queues from unbounded ingress.
- **Graceful drain** — on shutdown, stops accepting new connections, lets in-flight messages settle, then closes existing connections within the configured drain window.

## Feature flags

Features on the `rustgate-transport` crate itself:

| Feature | Effect |
|---|---|
| `fips` | Swaps the default `ring` crypto provider for `aws-lc-rs` in FIPS mode. |
| `post-quantum` | Enables X25519MLKEM768 hybrid key exchange. |
| `proto` | Enables protobuf codec support via `rustgate-proto`. |
| `ocsp` | Enables OCSP stapling validation. |
| `spiffe` | Enables SPIFFE workload identity extraction from URI SANs. |

Server-level features that add transport adapters (configured in `rustgate-server`):

| Feature | Effect |
|---|---|
| `metrics` | Publishes per-listener and per-identity Prometheus gauges. |
| `websocket` | Compiles in the WebSocket listener (`rustgate-websocket`). |
| `mqtt` | Compiles in the MQTT 5.0/3.1.1 transport adapter (`rustgate-mqtt`). |

## Additional Transport Layers

Beyond the core TLS listener, rustgate supports multiple transport adapters that all feed into the same router:

- **WebSocket** (`--websocket-bind`) — wss:// listener with mTLS, interoperable with TCP clients. See `rustgate-websocket`.
- **MQTT** (`--mqtt-bind`) — MQTT 5.0/3.1.1 adapter with topic-to-group mapping. See [MQTT Transport](./mqtt.md).
- **Plaintext TCP/UDP** (`--tcp-bind`, `--udp-bind`) — unencrypted transports for trusted network segments.

All transports share the same `Router`, deduplication cache, authorization policies, and federation pipeline.

See also [FIPS 140-3](../security/fips.md) and [Post-Quantum KEX](../security/post-quantum.md).
