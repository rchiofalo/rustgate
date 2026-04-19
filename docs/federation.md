# Federation

Federation enables multiple rustgate instances to share situational awareness across independent networks. Messages received from local clients are forwarded to connected federation peers, and messages from peers are delivered to local clients.

## Overview

rustgate supports two federation protocol versions:

| Protocol | Wire Format | Default Port | Use Case |
|----------|-------------|-------------|----------|
| V1 | 4-byte length-prefixed XML over mTLS | 9000 | Legacy server compatibility |
| V2 | gRPC FederatedChannel over mTLS | 9001 | gRPC interop |

Both protocols use mTLS for authentication. Peer identity is extracted from the certificate Common Name (CN).

## Quick Start

### Enable Federation

```bash
rustgate \
  --cert server.pem --key server-key.pem --ca ca.pem \
  --federation-v1-bind 0.0.0.0:9000
```

This starts the V1 federation listener on port 9000. Remote peers can connect inbound over mTLS.

### Add Outbound Peers

Create a `peers.json` file:

```json
[
  {
    "id": "remote-server-1",
    "address": "10.0.0.50:9000",
    "groups": ["Alpha", "Bravo"],
    "enabled": true,
    "is_outbound": true,
    "trust_cert_cn": null,
    "routing_mode": "broadcast",
    "protocol_version": 1
  }
]
```

Pass it to rustgate:

```bash
rustgate \
  --cert server.pem --key server-key.pem --ca ca.pem \
  --federation-v1-bind 0.0.0.0:9000 \
  --federation-peers-file peers.json
```

### Kubernetes

```yaml
federation:
  enabled: true
  v1Bind: "0.0.0.0:9000"
  id: "my-server"
  existingSecret: federation-peers
```

## Peer Configuration

Each peer in the JSON array has these fields:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | string | yes | — | Unique identifier for this peer |
| `address` | string | yes | — | Network address (host:port) |
| `groups` | string[] | yes | — | Groups this peer participates in |
| `enabled` | bool | yes | — | Whether the connection is active |
| `is_outbound` | bool | yes | — | `true` = we connect to them; `false` = they connect to us |
| `trust_cert_cn` | string? | no | null | Expected certificate CN for this peer |
| `routing_mode` | string | no | `"matrix"` | `"matrix"` or `"broadcast"` |
| `protocol_version` | int | no | `2` | `1` for V1 XML, `2` for V2 gRPC |

### Routing Modes

- **Broadcast** — all messages forwarded to this peer regardless of group membership
- **Matrix** — only messages matching the peer's configured groups are forwarded

### Example: Multi-Peer Setup

```json
[
  {
    "id": "hq-server",
    "address": "hq.example.com:9001",
    "groups": ["HQ", "Command"],
    "enabled": true,
    "is_outbound": true,
    "routing_mode": "matrix",
    "protocol_version": 2
  },
  {
    "id": "field-server",
    "address": "10.1.0.10:9000",
    "groups": ["Alpha", "Bravo"],
    "enabled": true,
    "is_outbound": true,
    "routing_mode": "broadcast",
    "protocol_version": 1
  }
]
```

## Protocol Details

### V1: Length-Prefixed XML

V1 federation uses 4-byte big-endian length-prefixed CoT XML messages over mTLS. This is the standard wire format for legacy TAK server federation.

**Wire format:**
```
[4 bytes: message length (big-endian)] [N bytes: CoT XML payload]
```

**Heartbeat:** Every 30 seconds, each side sends a CoT message with type `t-x-c-t` (heartbeat). If no heartbeat is received within 90 seconds, the connection is considered dead and will be closed.

**Reconnection:** On disconnect, outbound peers reconnect with exponential backoff (base 30s, capped at 5 minutes). Unlimited retries by default.

### V2: gRPC FederatedChannel

V2 federation uses the FederatedChannel gRPC service over mTLS (ALPN `h2`).

**Handshake sequence:**
1. Open TLS channel with client certificate
2. `server_federate_groups_stream()` — exchange group subscriptions
3. `client_federate_groups_stream()` — send our groups
4. `server_event_stream()` — open for sending events
5. `client_event_stream()` — open for receiving events

**Health check:** gRPC health checks every 5 seconds. If no response within 15 seconds, the connection is considered dead.

**Reconnection:** Same exponential backoff as V1.

## Loop Detection

Federation messages carry a provenance chain — a list of server IDs that have handled the message. Loop detection works in two stages:

1. **Server ID check** — if our server ID already appears in the provenance chain, the message is dropped (it has looped back to us)
2. **Hop limit** — if the current hop count exceeds `--federation-max-hops` (default 10), the message is dropped

This prevents infinite loops in mesh federation topologies (A ↔ B ↔ C ↔ A).

## NATS Integration

When NATS is enabled alongside federation:

- Messages from local clients are forwarded to both NATS and federation peers
- Messages arriving from federation peers are published to NATS for other rustgate instances
- Messages arriving from NATS are forwarded to federation peers

**Echo prevention:** Messages with `source_protocol == "federation"` are never re-forwarded to federation peers, preventing NATS → federation → NATS → federation loops.

## Trust Store

The dynamic trust store allows adding and removing trusted CA certificates at runtime without restarting rustgate. New CAs take effect on the next TLS handshake.

### REST API

When both `federation` and `metrics` features are enabled, the federation REST API is available on the metrics port:

```bash
# List trusted certificates
curl http://localhost:9090/api/federation/certificates

# Upload a new CA certificate
curl -X POST http://localhost:9090/api/federation/certificates \
  -H "Content-Type: application/x-pem-file" \
  --data-binary @new-ca.pem

# Remove a certificate by CN
curl -X DELETE http://localhost:9090/api/federation/certificates/my-ca-cn
```

### Peer Management

```bash
# List all configured peers
curl http://localhost:9090/api/federation/federates

# Add a new peer
curl -X POST http://localhost:9090/api/federation/federates \
  -H "Content-Type: application/json" \
  -d '{"id":"new-peer","address":"10.0.0.99:9000","groups":["Alpha"],"enabled":true,"is_outbound":true}'

# Enable/disable a peer
curl -X PUT http://localhost:9090/api/federation/federates/new-peer/enable
curl -X PUT http://localhost:9090/api/federation/federates/new-peer/disable

# Remove a peer
curl -X DELETE http://localhost:9090/api/federation/federates/new-peer

# View active connections
curl http://localhost:9090/api/federation/connections

# View aggregated stats
curl http://localhost:9090/api/federation/stats
```

## HA Mode

In multi-pod Kubernetes deployments, HA mode ensures that only one pod connects to each outbound federation peer. This is important because remote peers would see duplicate messages if multiple pods connected simultaneously.

HA mode requires NATS with JetStream (for KV store).

### How It Works

1. Each pod attempts to atomically claim ownership of each outbound peer via NATS KV
2. Claims have a 30-second TTL and are refreshed every 10 seconds
3. If a pod dies, its claims expire after 30 seconds
4. Surviving pods detect the expired claims and adopt the orphaned peers
5. A random jitter (0-5s) prevents all pods from racing for the same peer
6. After claiming, the adopting pod waits 30 seconds for the remote peer to clean up the stale connection before connecting

### NATS KV Buckets

| Bucket | Purpose |
|--------|---------|
| `federation-claims` | Peer ownership claims (pod → peer mapping) |
| `federation-connections` | Cross-pod connection registry |
| `federation-peers` | Shared peer configuration (replaces file store) |

## Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `federation_connections` | gauge | Active peer connection count |
| `federation_messages_in_total` | counter | Inbound messages from peers |
| `federation_messages_out_total` | counter | Outbound messages to peers |
| `federation_errors_total` | counter | Federation errors |
| `federation_heartbeats_total` | counter | Heartbeat messages (labels: `direction=in\|out`) |

## CLI Reference

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--federation-v1-bind` | `RUSTGATE_FEDERATION_V1_BIND` | — | V1 listen address (enables federation) |
| `--federation-id` | `RUSTGATE_FEDERATION_ID` | `rustgate-federation-1` | Server identity |
| `--federation-peers-file` | `RUSTGATE_FEDERATION_PEERS_FILE` | — | Path to peers JSON file |
| `--federation-skip-hostname-verify` | `RUSTGATE_FEDERATION_SKIP_HOSTNAME_VERIFY` | `false` | Skip TLS hostname verification |
| `--federation-max-hops` | `RUSTGATE_FEDERATION_MAX_HOPS` | `10` | Max hops before message drop |
| `--federation-store-path` | `RUSTGATE_FEDERATION_STORE_PATH` | — | Persistent store path |
| `--federation-v2-bind` | `RUSTGATE_FEDERATION_V2_BIND` | — | V2 gRPC listen address |
| `--federation-trust-store-dir` | `RUSTGATE_FEDERATION_TRUST_STORE_DIR` | — | Directory for CA trust store certificates |
| `--federation-circuit-breaker-threshold` | `RUSTGATE_FEDERATION_CIRCUIT_BREAKER_THRESHOLD` | `5` | Consecutive failures before circuit opens |
| `--federation-circuit-breaker-timeout` | `RUSTGATE_FEDERATION_CIRCUIT_BREAKER_TIMEOUT` | `60` | Seconds before half-open probe |
| `--federation-replay-buffer-size` | `RUSTGATE_FEDERATION_REPLAY_BUFFER_SIZE` | `1000` | In-memory replay ring buffer size |
| `--federation-replay-dir` | `RUSTGATE_FEDERATION_REPLAY_DIR` | — | Directory for persistent replay store |
| `--federation-peers-reload-interval` | `RUSTGATE_FEDERATION_PEERS_RELOAD_INTERVAL` | `0` | Seconds between peers file re-reads (0 = disabled) |
| `--federation-region` | `RUSTGATE_FEDERATION_REGION` | — | Local region for latency-aware routing |
| `--federation-trust-peer-groups` | `RUSTGATE_FEDERATION_TRUST_PEER_GROUPS` | `false` | Trust the peer's wire-claimed `federate_groups` field — **insecure default, see Threat Model** |

## Threat Model

### Peer authentication

Every federation peer authenticates via **mTLS client certificate**. The
peer's identity is the CN of that certificate; rustgate never falls back
to the remote IP address when CN extraction fails (see issue #759). An
attacker without a certificate signed by a trusted CA cannot reach any
federation RPC.

### Cross-origin group claims (issue #720)

The V2 wire protocol carries a `federate_groups` field on every federated
event, intended as the originating client's group memberships as seen by
the forwarding peer. The field is **advisory metadata** — it is not
covered by the federation JWT authority and cannot be independently
verified by the receiving server.

A Byzantine peer with a valid mTLS client certificate can forge any
`federate_groups` value for any origin CN. Absent defense, the
receiving server's authz engine would evaluate the forged claim,
allowing the Byzantine peer to elevate arbitrary origin CNs into
restricted groups and reach recipients that should otherwise be
inaccessible.

**Defense (default behavior):** `trust_peer_groups = false`. The
receiving server drops all wire-claimed groups, builds source
identities with the empty group set, and emits
`federation.group_claim_rejected` audit events for forensic traceability.
The XML payload forwarded to local clients does not carry
`federate_groups` — the CoT codec discards the field. Routing intent
expressed by a single-group destination is preserved, but the local
ACL/authz layer re-evaluates delivery.

**Opt-in trust:** `--federation-trust-peer-groups` (or
`RUSTGATE_FEDERATION_TRUST_PEER_GROUPS=true`). Only enable this flag
when every federation peer is fully trusted to speak for every origin
CN on its side of the federation — e.g. a single-operator multi-region
deployment where every peer shares one identity authority and one
operational team. Enabling this flag on a federation that spans
multiple trust domains is insecure.

### Cross-origin authz obligations (issue #719)

The V2 wire protocol does **not** carry authz `Obligation` metadata. When an
upstream peer's Send-PEP returns `MaskPoint`, `MaskPayload`, or any other
data-plane obligation, the payload is mutated in place *before* forwarding
(e.g. `<point>` coordinates zeroed for `MaskPoint`; body replaced with empty
bytes for `MaskPayload`). The obligation list itself is discarded.

On the receive side, the federation inbound handler builds a
`RoutableMessage` with `source_protocol = "federation"` and hands it to
the local router, which re-runs the full PEP chain:

1. **Send-PEP** with subject = the federation peer's CN. This admits or
   denies the message as a whole based on local policy applied to the
   peer's identity (not the origin client's identity on the other side
   of the federation).
2. **Per-recipient Receive-PEP** with subject = each local recipient's CN.
   Any obligations returned here are applied to a per-recipient copy of
   the envelope via the same dispatcher used for locally-originated
   traffic.

**Obligations produced by the local Receive-PEP are always applied**,
regardless of the message's upstream origin. Upstream obligations are
advisory only — the local receiver MUST NOT trust them, because:

- A less-strict upstream may deliver an unmasked payload, and the local
  policy still gets to say "`MaskPoint` required for group Y on Receive".
- A Byzantine upstream could otherwise elevate a message past local
  policy by claiming it was already "properly handled upstream".
- Bidirectional federation with asymmetric policies must not silently
  degrade to the less-strict peer.

This is the same defense-in-depth principle as `trust_peer_groups`:
wire-claimed metadata is untrusted, local policy is authoritative. The
guarantee is pinned by integration tests in
`crates/rustgate-transport/tests/authz_routing.rs` (`federated_broadcast_*`).

**Multicast caveat.** `Destination::Multicast` runs per-group Send-PEP
and Receive-PEP inside `send_to_group_excluding`. Federated messages
always arrive as `Destination::Broadcast` (the inbound handler never
constructs a multicast destination), so this caveat does not apply to
federation — but operators building custom ingestion paths that route
multicast should be aware that the top-level `route_for_egress` skips
the multicast Send-PEP in favour of per-group evaluation further down.

### Hop-count limits

Each event carries a `federate_hops.current_hops` counter incremented
by each forwarder. Events exceeding `--federation-max-hops` (default
`10`) are dropped on receive. Events at exactly the limit are
accepted; events over the limit are rejected. The streaming path
uses `continue` (not `break`) on rejection so a single bad event does
not tear down the stream (bounded by `MAX_CONSECUTIVE_VIOLATIONS`).

### Loop detection

Provenance metadata records every server that handled an event. If the
receiving server's own `federate_id` appears in the provenance chain,
the event is dropped at the receive side — preventing cycles and
amplification loops between federated peers.

### Replay prevention

Events have message UIDs and timestamps; a sliding-window replay
filter plus a persistent replay buffer (redb) prevents duplicate
delivery across reconnects.

## Troubleshooting

### Peer won't connect

1. Verify the remote address is reachable: `nc -zv <host> <port>`
2. Check that both sides trust each other's CA certificate
3. Verify the peers JSON is valid: `cat peers.json | jq .`
4. Check logs for TLS errors: `grep -i "tls\|handshake\|federation" <log>`
5. Try `--federation-skip-hostname-verify` to rule out CN mismatch issues

### Messages not forwarding

1. Check that groups overlap between the peer config and the message source
2. Verify the message isn't being dropped by loop detection (check logs for "provenance" or "hop")
3. Ensure `routing_mode` is set correctly (`broadcast` forwards everything, `matrix` filters by group)

### Heartbeat timeout

If peers disconnect after ~90 seconds:
1. Check for firewall rules or NAT timeouts between the servers
2. Verify both sides are running compatible protocol versions
3. Check system clock skew between servers
