# ADR 0005: `tokio-tungstenite` for the WebSocket layer

- **Status:** Documented
- **Date:** 2026-04-27
- **Related:** `crates/rustgate-websocket/Cargo.toml`

## Context

The `rustgate-websocket` crate provides a WebSocket (`wss://`)
listener that terminates mTLS, performs the WebSocket handshake,
and converts each session into a `Codec`-driven message stream that
plugs into the same routing fabric used by the TLS listener. The
crate has shipped since the project's early protocol work and uses
[`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite)
as its WebSocket implementation, layered over `tokio-rustls` for
the TLS portion.

The Rust async WebSocket ecosystem has two major implementations:

- **`tokio-tungstenite`** — the tokio-flavoured wrapper around the
  `tungstenite` synchronous WebSocket protocol crate. Mature,
  widely deployed, broad feature coverage including subprotocols
  and per-message deflate.
- **`soketto`** — Parity Tech's standalone async WebSocket crate.
  Smaller surface, fewer features, framework-agnostic.

The ADR is recorded as **Documented** rather than **Accepted**
because the original decision was not captured in a written
rationale at the time the crate was introduced. The codebase
reflects the choice and there is no compelling reason to revisit it,
but the reasoning below is partly retrospective.

## Decision

`rustgate-websocket` uses `tokio-tungstenite` for the WebSocket
protocol layer. The crate also depends on `tokio-rustls` for TLS
termination and on the workspace's own `rustgate-resilience`,
`rustgate-transport`, and `rustgate-cot` for routing and codec
glue.

This decision is recorded retrospectively. The crate has been
stable on `tokio-tungstenite` and we have not encountered a
limitation that would justify migration.

## Alternatives considered

- **`soketto`.** Has not been benchmarked against
  `tokio-tungstenite` for our workload. We have no evidence that a
  switch would deliver a measurable improvement, and the migration
  cost (rewriting the listener accept loop, the per-session codec
  glue, and the test harness) would be non-trivial. Documented as
  the alternative; not currently planned.
- **A bespoke WebSocket implementation.** Rejected: WebSocket has
  enough corner cases (close frames, ping/pong, text vs binary,
  subprotocol negotiation, fragmentation) that rolling our own is
  outside the project's scope. We benefit from the surface that an
  established crate has already worked through.
- **`hyper` plus a WebSocket upgrade crate.** Workable but adds a
  layer (`hyper`) that the current listener does not otherwise
  need. The `tokio-tungstenite` accept path is closer to the rest
  of the workspace's transport listeners.

## Consequences

- `rustgate-websocket` carries a `tokio-tungstenite` dependency
  (and transitively a `tungstenite` dependency). Both are tracked
  by `cargo-deny`'s license and advisory audits.
- The session loop in `rustgate-websocket::server` is
  `tokio-tungstenite`-shaped: the per-session task pulls
  `Message::Binary` / `Message::Text` from a `WebSocketStream`,
  hands the payload to the same `Codec` the TLS listener uses,
  and writes outbound frames back through the same stream.
- No bridge code needs to change at the routing layer: the router
  sees a `SessionHandle` regardless of which transport produced
  it. That remains a property of the workspace's transport
  abstraction, not of this crate's WebSocket-implementation
  choice.
- Status remains **Documented** rather than **Accepted** because
  this ADR is retrospective. If a future contributor revisits the
  WebSocket implementation choice — for instance, because of a
  protocol-level issue, a CVE, or a measurable performance gap —
  the ADR can be promoted to **Superseded** and a successor ADR
  can record the new decision with a current rationale.
