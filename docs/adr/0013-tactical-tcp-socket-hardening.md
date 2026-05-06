# ADR 0013: `configure_tactical_socket` for every accepted/dialed TCP stream

- **Status:** Accepted
- **Date:** 2026-05-06
- **Related:** `crates/rustgate-core/src/net.rs`,
  `scripts/check-playbook-drift.sh`,
  `.claude/rules/shared-infrastructure.md` "TCP Socket Hardening"

## Context

rustgate's primary traffic pattern is small, frequent, latency-
sensitive messages: tactical CoT position updates (200–800 bytes
emitted at 1–10 Hz per client), MAVLink heartbeats, NATS control
frames, federation gRPC unary RPCs, MQTT PUBLISH, WebSocket frames.
Two TCP-level defaults work against this pattern:

1. **Nagle's algorithm.** Enabled by default on every TCP socket.
   The kernel buffers small writes until either the buffer is full
   or an ACK arrives for the previous segment. Combined with the
   peer's delayed-ACK timer (`TCP_DELACK_MIN = 40 ms` on Linux),
   this adds a per-message latency stall that is invisible at the
   benchmark level (throughput looks fine) but agonising at the
   operator level (a position update issued at 10 Hz can lag by
   40 ms each before reaching the wire). Issue #745 (F-151)
   diagnosed this regression across every listener and the client
   dial path.
2. **No keepalive.** A NAT middlebox that loses connection state
   can silently strand a TCP connection. The application sees no
   error — reads block forever, writes succeed into a kernel buffer
   that no longer drains. With keepalive enabled, the kernel emits
   probe packets after a configurable idle period; a missed probe
   tears the connection down so the application can reconnect.

The fix for Nagle is `TCP_NODELAY = 1` (per-socket). The fix for
the dead-NAT case is `SO_KEEPALIVE` plus tuned probe parameters.
Both are one-line socket-option calls but they have to be applied
to *every* accepted stream and every dialed stream — missing a
single listener is enough to reintroduce the regression on that
listener alone.

The workspace has eight TCP listener / dial sites:
`rustgate-transport::listener` (TLS), `transport::plaintext`,
`websocket::lib`, `mqtt::listener`, `enrollment::server`,
`server::metrics`, `federation::connector` (dial side),
`client::connect` (dial side). Plus future listeners that have
not been written yet.

## Decision

Every accepted or dialed TCP stream is hardened by calling one of
the helpers in `rustgate_core::net` before the stream is handed
off to TLS, a codec, or a protocol adapter. The combined helper is
the default:

```rust
rustgate_core::net::configure_tactical_socket(&tcp_stream);
// = configure_tcp_keepalive + configure_tcp_nodelay
```

Where:

- `configure_tcp_keepalive` sets `SO_KEEPALIVE = 1`,
  `TCP_KEEPIDLE = 30s`, and `TCP_KEEPINTVL = 10s` via `socket2`.
- `configure_tcp_nodelay` sets `TCP_NODELAY = 1` via `socket2`.
- Both helpers log a `tracing::warn!` and return on `setsockopt`
  failure rather than propagating the error — the stream is still
  usable, merely with the underlying TCP defaults restored.

Individual helpers exist for the rare cases where Nagle batching
is intentionally desired (`configure_tcp_keepalive` only) or
keepalive is being managed elsewhere (`configure_tcp_nodelay`
only), but the decision table flags both as "rarely the right
choice".

A CI guardrail in `scripts/check-playbook-drift.sh` greps every
file using `tokio::net::TcpListener` or `TcpStream::connect` and
fails the build if it does not call one of the helpers. The drift
check is what prevents the F-151 regression from re-landing.

## Alternatives considered

- **Per-listener inlined `setsockopt` calls.** Rejected because
  drift across eight call sites is exactly the failure mode we
  are trying to prevent. Centralising the helpers in
  `rustgate-core` plus a CI lint moves the failure shape from
  "silently miss a listener" to "the lint catches it before
  merge."
- **Disable Nagle globally via a runtime flag.** Linux supports
  `TCP_NODELAY` only as a per-socket option (there is no
  workspace-wide kill switch). The closest substitute would be
  `TCP_QUICKACK` on the receive side, which addresses the
  delayed-ACK half of the latency stall but not the sender-side
  Nagle batching.
- **Different keepalive parameters.** The 30s idle / 10s probe
  interval is a tactical compromise: aggressive enough that a
  stranded NAT entry is detected within a minute, conservative
  enough that a brief network hiccup does not tear connections
  down. Operators on fast LANs sometimes want lower values; this
  ADR does not bake those in — the helper exposes the constants
  in `rustgate-core::net` so a future tuning ADR can change them
  in one place.
- **Use `tokio`'s `set_nodelay` / `set_keepalive` on the wrapped
  type.** `tokio::net::TcpStream::set_nodelay` works but the
  keepalive surface on `tokio::net::TcpStream` is more limited
  than `socket2` (no `TCP_KEEPIDLE` / `TCP_KEEPINTVL` control on
  stable). Using `socket2::SockRef::from(&stream)` consistently
  for both options keeps the call sites mechanical.

## Consequences

- Every accepted TCP stream has `TCP_NODELAY = 1` and
  `SO_KEEPALIVE = 1` before TLS or a codec sees it. The latency
  cost of Nagle is gone from the tactical traffic pattern.
- A stranded NAT or a hung peer is detected within ~60 seconds
  (idle 30s + 3 probes at 10s each) rather than never. This is
  not a substitute for application-level heartbeating — federation
  has its own 30s heartbeat and 90s timeout
  (`FEDERATION_HEARTBEAT_*` constants) — but it covers the
  application-silent case.
- Adding a new TCP listener or dial site means calling
  `configure_tactical_socket` at the same point the existing
  listeners do (immediately after `accept()` / `connect()`,
  before TLS). The CI drift check enforces this; reviewers also
  flag the omission.
- The `socket2` crate is a foundational workspace dependency. It
  is pure Rust on Unix and a thin wrapper over Winsock on Windows;
  the workspace has supported Windows as a tier-2 target since
  v0.7 and `socket2` covers both surfaces.
- If a future transport is intentionally non-tactical (e.g. a
  bulk file-transfer adapter where Nagle batching helps), the
  contributor uses `configure_tcp_keepalive` alone and adds a
  comment naming this ADR plus the rationale. The drift check
  still passes because keepalive is present; the omission of
  `TCP_NODELAY` is a deliberate choice, not a regression.
