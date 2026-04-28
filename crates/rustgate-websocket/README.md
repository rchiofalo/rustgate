# rustgate-websocket

WebSocket (`wss://`) listener with mandatory mTLS.

## Role in the workspace

`rustgate-websocket` accepts WebSocket connections, performs the mTLS
handshake, extracts client identity from the certificate, runs the
WebSocket upgrade, and registers each authenticated session with the shared
router. It depends on [rustgate-core](../rustgate-core/README.md),
[rustgate-cot](../rustgate-cot/README.md),
[rustgate-resilience](../rustgate-resilience/README.md) (for the per-IP
sliding-window connection limiter), and
[rustgate-transport](../rustgate-transport/README.md) (for `TlsConfig`, the
identity extractor, and the router). Wired into
[rustgate-server](../rustgate-server/README.md) under `--features websocket`.

## Public API surface

- `WsListener`, `WsListenerConfig` — WebSocket-over-TLS accept loop with
  per-IP rate limiting, configurable max frame / message size, the
  RFC 6455 §4.2.2 subprotocol negotiation, and RFC 7692
  `permessage-deflate` extension negotiation
- `compression::{CompressionConfig, PermessageDeflateConfig, NegotiatedExtension,
  Deflater, Inflater}` — `permessage-deflate` (RFC 7692) negotiation
  envelope and DEFLATE codec helpers
- `WebSocketServer`, `WsServerConfig`, `WsSessionHooks` — manages the
  accept loop and session lifecycle with router integration
- `WsSession`, `WsStream` — authenticated WebSocket session and the
  underlying TLS-over-tungstenite stream type
- `OnFederationForward`, `OnHttpForward`, `OnNatsPublish` — hooks the
  server binary uses to bridge WebSocket sessions into the federation /
  HTTP egress / NATS publish paths
- `OnWsAcceptFn`, `OnWsRejectFn` — connection lifecycle callbacks for
  metrics / audit
- `health` — liveness / readiness response helpers shared with the metrics
  endpoint
- `TRANSPORT_LABEL` (`"websocket"`) — canonical value of the `transport`
  field in this crate's structured-log events
- `DEFAULT_CONN_RATE_LIMIT`, `DEFAULT_CONN_RATE_WINDOW`,
  `DEFAULT_MAX_FRAME_SIZE`, `DEFAULT_MAX_MESSAGE_SIZE`,
  `DEFAULT_MAX_WRITE_BUFFER_BYTES` — operator-tunable defaults

## Feature flags

_None._

## Topology / deployment notes

mTLS is mandatory — identity is derived exclusively from the X.509 client
certificate and never from headers or query params. The accept order is
fixed: TCP accept → per-IP rate-limit check → TLS handshake → identity
extraction → WebSocket upgrade. Per-IP rate limiting uses the raw TCP peer
address and exists to mitigate slow-handshake DoS; behind NAT or a load
balancer all clients sharing one egress IP are limited together (see the
threat-model entry for D8).

### Subprotocol negotiation (RFC 6455 §1.9 / §4.2.2)

Subprotocol negotiation is opt-in via
`WsListenerConfig::supported_subprotocols`; when empty the handshake
proceeds with no `Sec-WebSocket-Protocol` response header (the historical
default). When non-empty, the server walks the client's offered tokens
in *client* preference order and picks the first match (case-sensitive
ABNF tokens per RFC 7230). On a no-match,
`WsListenerConfig::subprotocol_strict` controls behaviour: the **lenient**
default lets the upgrade complete with no header echoed (TAK and similar
tactical clients probe several subprotocols and fall back to native
non-subprotocol framing on no-match), and **strict** mode rejects with
400 Bad Request (the right choice for homogeneous-fleet deployments
where a config drift should surface in server-side logs). The CLI
exposes this as `--ws-subprotocol-strict`.

### `permessage-deflate` compression (RFC 7692)

Compression negotiation is enabled by default at the RFC 7692 maxima
(`server_max_window_bits=15`, `client_max_window_bits=15`,
`allow_server_no_context_takeover=true`,
`require_client_no_context_takeover=false`). The server inspects the
client's `Sec-WebSocket-Extensions` request header, picks the first
`permessage-deflate` offer whose parameters fit
`WsListenerConfig::compression`'s envelope, and echoes the agreed
parameter set back. Operators can disable the entire negotiation surface
via `CompressionConfig::Disabled` or `--ws-compression-disabled` —
useful where a CRIME/BREACH-style threat model is in scope (mTLS already
neutralises the standard CRIME attack against the TLS layer, but the
kill-switch ships nonetheless) or where an upstream deep-inspection
device rejects compressed frames.

The bandwidth-savings claim is pinned by a unit-level codec round-trip
that must compress a 64 KiB CoT-shaped XML payload to under 30% of its
original size; the typical observed ratio is around 1% (a 99% reduction
on repetitive XML). The on-wire per-frame compressed-payload codec is
gated on a future tokio-tungstenite release exposing the upstream
`deflate` feature — until that lands, this crate ships the negotiation
surface plus the codec helpers (`compression::Deflater` /
`compression::Inflater`) so the wire-up follow-up is mechanical rather
than design work. See `crates/rustgate-websocket/src/compression.rs`
module-level docs for the full rationale.

## Where to look first

- `crates/rustgate-websocket/src/lib.rs` — `WsListener::accept` and the
  RFC 6455 subprotocol negotiation logic
- `crates/rustgate-websocket/src/server.rs` — `WebSocketServer` lifecycle
  and the hooks the server binary wires for routing / federation / egress
