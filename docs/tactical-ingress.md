# Tactical Codec Ingress

rustgate ships codecs for many tactical protocols, but most are only useful
once the server can actually **receive** them off the wire. The *tactical
codec ingress* is a pair of generic, codec-pluggable listeners that turn
tactical traffic into routed messages — subject to the same ACL/authz,
dedup, and egress as every other transport:

- a **UDP listener** for datagram-oriented protocols (1 datagram = 1
  message), and
- a **TCP listener** for stream-framed protocols (a byte stream the listener
  delimits into frames).

Wired today:

| Protocol | Transport | Framing |
|----------|-----------|---------|
| **DIS** (IEEE 1278.1 Entity State) | UDP | one PDU per datagram |
| **ASTERIX** (CAT-062 tracks) | UDP | one datablock per datagram |
| **VMF** (MIL-STD-6017 K05.1) | UDP | one message per datagram |
| **SAPIENT** (BSI Flex 335) | **TCP** | protobuf varint length-delimited |
| **Link 16 / JREAP-C** (STANAG 5518) | **TCP** | 16-byte JREAP header carrying the body length |

STANAG 4586 (stream-framed) and Meshtastic (LoRa) are separate
ingress paths still to come. See the design notes
(`docs/design/tactical-codec-ingress.md`,
`docs/design/tactical-stream-ingress.md`) and the tracking epic (#1473).

> **Security warning:** These are unauthenticated, unencrypted ingress
> paths (UDP datagrams and TCP connections alike). There is no mTLS — anyone
> who can reach the bound port can submit traffic, and identity is
> synthetic. Deploy **only on a trusted network
> segment**, always pair with a CIDR allowlist, and rely on group-level
> ACL/authz for trust. This is the same posture as the plaintext
> CoT-over-UDP listener.

## Security model

- **No transport authentication.** Each accepted datagram is routed under a
  synthetic, transport-derived identity (`dis-anonymous-<peer>`); the
  **destination group is the only trust decision**, and it is
  operator-assigned via `--dis-group`, never derived from the wire.
- **Wire identifiers are not credentials.** DIS entity/site/application IDs
  are spoofable and are **never** used for authorization or folded into the
  identity CN — they survive only inside the decoded entity for
  correlation/dedup.
- **Validate-and-drop at the edge.** Every datagram is decoded with the
  protocol's codec before routing; anything that does not decode to a valid
  entity is dropped at the boundary and audited — malformed/hostile input
  never enters the routing pipeline.
- **Mandatory admission controls** (in order): source CIDR allowlist →
  per-IP rate limit → synthetic-identity cap → datagram size cap. Each
  rejection is audited by class.
- **Secure-default rate limit.** Unlike the CoT-UDP listener, the rate
  limit is **never off**: an unset/`0` `--<proto>-rate-limit-pps` applies
  the built-in default (10000 pps/IP), not "unlimited."
- **No allowlist ⇒ loud warning.** Starting without
  `--<proto>-allowed-cidrs` logs a prominent warning that the port is
  exposed to the whole reachable network.

## Enabling ingress

Each protocol has the same five flags under its own `--<proto>-` prefix.
Set the `--<proto>-bind` to enable it; leaving it unset disables that
protocol (default-deny). All flags have matching `RUSTGATE_<PROTO>_*`
environment variables and TOML config-file keys.

```bash
rustgate-server \
  --dis-bind     0.0.0.0:3000  --dis-allowed-cidrs     10.20.0.0/16 \
  --asterix-bind 0.0.0.0:8600  --asterix-allowed-cidrs 10.20.0.0/16 \
  --vmf-bind     0.0.0.0:1581  --vmf-allowed-cidrs     10.20.0.0/16
```

| Protocol | `--<proto>` prefix | Wire input | Default group |
|----------|--------------------|------------|---------------|
| **DIS** (IEEE 1278.1) | `dis` | UDP Entity State PDUs (≈3000) | `dis` |
| **ASTERIX** (CAT-062) | `asterix` | UDP datablocks (≈8600) | `asterix` |
| **VMF** (MIL-STD-6017 K05.1) | `vmf` | UDP position reports (≈1581) | `vmf` |
| **SAPIENT** (BSI Flex 335) | `sapient` | **TCP** varint-delimited protobuf (≈8800) | `sapient` |
| **Link 16 / JREAP-C** (STANAG 5518) | `link16` | **TCP** JREAP-header-framed (≈4444) | `link16` |

Per-protocol UDP flags (shown for `dis`; identical for `asterix` / `vmf`):

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `--dis-bind` | `RUSTGATE_DIS_BIND` | *(unset → disabled)* | UDP bind address |
| `--dis-group` | `RUSTGATE_DIS_GROUP` | `dis` | Destination group accepted datagrams route to (ACL/authz apply) |
| `--dis-rate-limit-pps` | `RUSTGATE_DIS_RATE_LIMIT_PPS` | `0` → secure default | Per-IP datagrams/sec (`0` = built-in default, not off) |
| `--dis-allowed-cidrs` | `RUSTGATE_DIS_ALLOWED_CIDRS` | *(unset → warn)* | Comma-separated source CIDR allowlist |
| `--dis-max-identities` | `RUSTGATE_DIS_MAX_IDENTITIES` | `1024` | Synthetic-identity LRU bound (new IPs rejected at cap) |

### Stream protocols (TCP): SAPIENT, Link 16

SAPIENT and **Link 16 / JREAP-C** are **connection-oriented** (TCP), so their
listeners delimit a byte stream into frames — SAPIENT by a protobuf varint
length prefix, Link 16 by the body-length field inside the 16-byte JREAP
header — and add one extra knob over the UDP protocols: a
`--<proto>-max-connections` concurrent-connection cap. Both use the identical
`--<proto>-{bind,group,rate-limit-pps,allowed-cidrs,max-identities,max-connections}`
flag shape (`sapient` / `link16`); the SAPIENT flags below stand for both.

```bash
rustgate-server --sapient-bind 0.0.0.0:8800 --sapient-allowed-cidrs 10.20.0.0/16
```

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `--sapient-bind` | `RUSTGATE_SAPIENT_BIND` | *(unset → disabled)* | **TCP** bind address |
| `--sapient-group` | `RUSTGATE_SAPIENT_GROUP` | `sapient` | Destination group accepted frames route to |
| `--sapient-rate-limit-pps` | `RUSTGATE_SAPIENT_RATE_LIMIT_PPS` | `0` → secure default | Per-IP **connection-accept** rate (conn/sec) |
| `--sapient-allowed-cidrs` | `RUSTGATE_SAPIENT_ALLOWED_CIDRS` | *(unset → warn)* | Source CIDR allowlist (checked at accept) |
| `--sapient-max-identities` | `RUSTGATE_SAPIENT_MAX_IDENTITIES` | `1024` | Synthetic-identity LRU bound |
| `--sapient-max-connections` | `RUSTGATE_SAPIENT_MAX_CONNECTIONS` | `1024` | Max simultaneously-open connections |

A slow client that opens a connection but never completes a frame is closed
after the standard read timeout (slow-loris protection); a single malformed
frame is dropped (and audited) without killing the connection, while a
framing-level error (bad length prefix) closes it.

## How a datagram flows

1. **Receive** a UDP datagram on `--<proto>-bind`.
2. **Admission** — drop (and audit) if the source IP is outside the
   allowlist, over its rate budget, or new while the identity cap is full;
   drop if the datagram exceeds the size cap.
3. **Validate** — decode with that protocol's codec; drop + audit if it is
   not a well-formed message.
4. **Route** — build a message carrying the raw datagram bytes, the
   synthetic identity, the configured group, and `source_protocol`
   (`"dis"` / `"asterix"` / `"vmf"`), then hand it to the router. ACL/authz,
   dedup, multi-sensor correlation, and egress (NATS/federation/etc.) apply
   exactly as for any other source.

## Observability

- Startup logs a `warn` that the ingress is active and unencrypted, plus a
  second `warn` if no CIDR allowlist is configured.
- Drops are audited by class: `client.rejected` with reason
  `cidr_not_allowed` / `identity_cap_reached` / `datagram_too_large` /
  `malformed_datagram`, and `security.rate_limited` for rate-limit drops.
- Accepted datagrams appear in the access log and audit trail like any
  routed message (with their `source_protocol`), and the router's
  `EntityCodecRegistry` surfaces the canonical entity kind.

## Limitations

- **One canonical message per datagram.** Each protocol's codec decodes a
  single canonical entity per datagram: DIS **Entity State PDUs** only,
  ASTERIX the **first CAT-062 track** of the datablock, VMF **K05.1**
  position reports only, SAPIENT a **DetectionReport** (other message types
  decode to the forward-compatible opaque arm). Other PDU/category/message
  types are dropped at the validating decode until the codec maps them, and
  multi-record datagrams (e.g. several ASTERIX tracks in one datablock)
  surface only their first record for now.
- **Unicast only** so far; multicast ingress (ASTERIX / DIS on an exercise
  LAN, Link 16 JREAP-A) reuses the same controls and lands with the
  multicast follow-up.
- **Remaining stream protocols** (Link 16 JREAP-C, STANAG 4586) and
  **Meshtastic** (LoRa/serial) are distinct ingress paths, tracked under
  #1473.
