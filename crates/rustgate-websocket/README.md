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
  per-IP rate limiting, configurable max frame / message size, and the
  RFC 6455 §4.2.2 subprotocol negotiation
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
threat-model entry for D8). Subprotocol negotiation is opt-in via
`WsListenerConfig::supported_subprotocols`; when empty the handshake
proceeds with no `Sec-WebSocket-Protocol` response header (the historical
default).

## Where to look first

- `crates/rustgate-websocket/src/lib.rs` — `WsListener::accept` and the
  RFC 6455 subprotocol negotiation logic
- `crates/rustgate-websocket/src/server.rs` — `WebSocketServer` lifecycle
  and the hooks the server binary wires for routing / federation / egress
