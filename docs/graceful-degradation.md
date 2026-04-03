# Graceful Degradation

rustgate is designed so that subsystem failures degrade functionality without crashing the process or dropping existing client connections. This document describes what happens when each optional subsystem fails and how the system recovers.

## NATS Bridge Failure

**Trigger:** NATS broker disconnects, becomes unreachable, or rejects connections.

**Behavior:**
- Local message routing continues normally — all connected clients still exchange messages via the in-process router.
- Cross-instance delivery stops. Messages that would have been published to NATS are silently dropped with a warning log.
- JetStream SA history replay is unavailable for new connections on other instances.

**Recovery:** The NATS client library (`async-nats`) automatically reconnects when the broker becomes available. No manual intervention is required. Pending publishes during the outage are lost (fire-and-forget delivery model).

**Operator action:** Monitor the `rustgate_nats_publishes_total` Prometheus metric for drops. If the broker is permanently down, restart it or reconfigure `--nats-url`.

## Federation Peer Failure

**Trigger:** A remote federation peer becomes unreachable, closes the connection, or starts rejecting messages.

**Behavior:**
- The circuit breaker for that peer transitions from `Closed` to `Open` after the configured number of consecutive failures (`--federation-circuit-breaker-threshold`, default 5).
- While the circuit is open, messages destined for that peer are skipped — no connection attempts or sends are made.
- Other federation peers are unaffected and continue receiving messages.
- Local client routing is completely unaffected.

**Recovery:** After the circuit breaker timeout (`--federation-circuit-breaker-timeout`, default 60 seconds), the circuit transitions to `HalfOpen` and allows one probe message through. If it succeeds, the circuit closes and normal forwarding resumes. If it fails, the circuit reopens for another timeout period.

**Operator action:** Watch for `circuit breaker tripped` warning logs and the `rustgate_federation_circuit_breaker_trips_total` metric. Investigate the remote peer's health. The system will self-heal once the peer recovers.

## Certificate Enrollment CA Failure

**Trigger:** The enrollment server cannot access the CA key, or the enrollment HTTPS listener fails to bind.

**Behavior:**
- **Startup failure is fatal.** If `--enrollment-bind` is set and the enrollment subsystem fails to initialize (e.g., missing CA key, port conflict), the entire process exits with an error. This is intentional — a misconfigured enrollment server should be detected immediately, not silently ignored.
- Once the enrollment server is running, a transient CA key access failure during a CSR signing request returns an HTTP error to the enrolling client without affecting the rest of the system.

**Recovery:** Fix the CA key path or permissions and restart rustgate. If enrollment is not needed, omit `--enrollment-bind` entirely — the server runs without it.

**Operator action:** Ensure the CA key file exists and has correct permissions before starting rustgate with enrollment enabled.

## WebSocket Listener Failure

**Trigger:** The WebSocket listener fails to bind (e.g., port conflict) or encounters a runtime error.

**Behavior:**
- **Startup failure is fatal** if `--websocket-bind` is set and the listener cannot bind.
- Once running, individual WebSocket connection failures (handshake timeout, upgrade rejection) are handled per-connection — other WebSocket and TCP clients are unaffected.
- TCP (port 4433) client connections are completely independent of the WebSocket listener.

**Recovery:** Fix the port conflict or binding issue and restart. WebSocket clients will reconnect automatically.

## OpenTelemetry Collector Unreachable

**Trigger:** The OTLP collector configured via `--otel-endpoint` is unreachable or rejects connections.

**Behavior:**
- Message routing, federation, NATS, and all other functionality are completely unaffected.
- The OpenTelemetry batch exporter buffers spans internally. When the buffer fills, oldest spans are dropped silently.
- No error logs are produced for individual span export failures (this is standard OpenTelemetry SDK behavior to avoid log storms).

**Recovery:** Automatic. When the collector becomes reachable again, new spans are exported normally. Spans lost during the outage are not recoverable.

**Operator action:** Monitor the collector's health independently. If the collector is permanently down, the `otel` feature still has minimal overhead (span creation without export).

## TLS Certificate/Key Issues

**Trigger:** Server certificate or key file is missing, expired, or mismatched at startup.

**Behavior:** rustgate fails fast at startup with a clear error message. It does not start in a degraded mode with broken TLS.

**Recovery:** Fix the certificate/key files and restart.

## Position Cache Overflow

**Trigger:** The position cache exceeds its maximum entry count (default 100,000).

**Behavior:** The oldest entry (by `received_at` timestamp) is evicted to make room. No data loss for active clients — only stale positions from long-disconnected clients are removed.

**Recovery:** Automatic. Increase the cache size if the deployment regularly exceeds 100,000 concurrent position sources.

## Connection Limit Reached

**Trigger:** The number of active connections reaches `--max-connections`.

**Behavior:** New TCP connections are accepted at the OS level but immediately rejected at the application level with a warning log. Existing connections are unaffected.

**Recovery:** Automatic once existing connections close. Increase `--max-connections` or scale horizontally (multiple instances with NATS bridge).

## Summary

| Subsystem | Impact on Local Routing | Auto-Recovery | Metric to Watch |
|-----------|------------------------|---------------|-----------------|
| NATS broker | None | Yes (reconnect) | `rustgate_nats_publishes_total` |
| Federation peer | None | Yes (circuit breaker) | `rustgate_federation_circuit_breaker_trips_total` |
| Enrollment CA | Startup failure (fatal) | No (fix config, restart) | — |
| TLS cert/key | Startup failure (fatal) | No (fix files, restart) | — |
| Position cache | Oldest entries evicted | Yes | `rustgate_sessions_active` |
| Connection limit | New connections rejected | Yes | `rustgate_connections_rejected_total` |
