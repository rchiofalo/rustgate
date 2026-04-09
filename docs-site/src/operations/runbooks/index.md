# Runbooks

Operational runbooks for the most common rustgate failure modes. Each runbook is structured the same way: **symptoms → triage → diagnosis → remediation → verification**. They are written assuming you are paged at 03:00 and need to act with the minimum cognitive load.

| Runbook | When to use it |
|---|---|
| [Anti-Replay](./anti-replay.md) | Duplicate messages observed downstream, dedup gauges climbing, audit log shows replay attempts. |
| [Certificate Rotation](./certificate-rotation.md) | Server or client certs are approaching expiry, or you need an emergency rotation after a compromise. |
| [CRL Updates](./crl-updates.md) | A CRL must be reloaded out-of-cycle to revoke a compromised client. |
| [Federation Reconnect](./federation-reconnect.md) | A federation peer is stuck in `reconnecting`, queue lag is climbing, or replay buffer is filling. |
| [High Memory](./high-memory.md) | Resident memory is climbing without a corresponding increase in connection count or routing throughput. |
| [NATS Bridge Failure](./nats-bridge-failure.md) | The JetStream consumer is lagging, redeliveries are climbing, or the bridge keeps reconnecting. |
| [TLS Handshake Failures](./tls-handshake-failures.md) | Clients can't connect, handshake error rate is climbing, or a specific group is being rejected. |
| [WebSocket Storms](./websocket-storms.md) | A WebSocket flood is consuming connection slots or memory. |

All runbooks are mirrored from `docs/runbooks/` in the repository.
