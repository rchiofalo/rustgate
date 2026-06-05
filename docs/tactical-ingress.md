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
| **STANAG 4586** (UCS/UAV) | UDP | one message per datagram |
| **SAPIENT** (BSI Flex 335) | **TCP** | protobuf varint length-delimited |
| **Link 16 / JREAP-C** (STANAG 5518) | **TCP** | 16-byte JREAP header carrying the body length |
| **NFFI** (STANAG 5527) | **TCP** | XML document boundary |

STANAG 4586 is wired over **UDP** (one message per datagram); its
**stream-framed** (TCP) variant and **Meshtastic** (LoRa) are separate
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

Each protocol has the same core flags under its own `--<proto>-` prefix
(the three UDP codecs add an optional `--<proto>-multicast-group`).
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
| **STANAG 4586** (UCS/UAV) | `stanag4586` | UDP messages (≈8586) | `stanag4586` |
| **SAPIENT** (BSI Flex 335) | `sapient` | **TCP** varint-delimited protobuf (≈8800) | `sapient` |
| **Link 16 / JREAP-C** (STANAG 5518) | `link16` | **TCP** JREAP-header-framed (≈4444) | `link16` |
| **NFFI** (STANAG 5527) | `nffi` | **TCP** XML-document-delimited (≈8500) | `nffi` |

Per-protocol UDP flags (shown for `dis`; identical for `asterix` / `vmf`):

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `--dis-bind` | `RUSTGATE_DIS_BIND` | *(unset → disabled)* | UDP bind address |
| `--dis-group` | `RUSTGATE_DIS_GROUP` | `dis` | Destination group accepted datagrams route to (ACL/authz apply) |
| `--dis-rate-limit-pps` | `RUSTGATE_DIS_RATE_LIMIT_PPS` | `0` → secure default | Per-IP datagrams/sec (`0` = built-in default, not off) |
| `--dis-allowed-cidrs` | `RUSTGATE_DIS_ALLOWED_CIDRS` | *(unset → warn)* | Comma-separated source CIDR allowlist |
| `--dis-max-identities` | `RUSTGATE_DIS_MAX_IDENTITIES` | `1024` | Synthetic-identity LRU bound (new IPs rejected at cap) |
| `--dis-multicast-group` | `RUSTGATE_DIS_MULTICAST_GROUP` | *(unset → unicast)* | IPv4 group to join on the `--dis-bind` port (`224.0.0.0/4`); inbound only |

#### Multicast ingress (UDP only)

DIS, ASTERIX, and VMF can be received on an IPv4 multicast group instead of
(or in addition to) unicast — useful when sensors flood tracks onto an
exercise-LAN multicast address rather than addressing the router directly.
Set `--<proto>-multicast-group` to a `224.0.0.0/4` address; the listener
then binds with `SO_REUSEADDR` on the **`--<proto>-bind` port** and joins
that group. The group address is validated at startup — a non-multicast
value is a hard configuration error, never a silent unicast fallback.

```bash
# Receive DIS on the exercise multicast group 239.2.3.1:3000.
rustgate-server \
  --dis-bind 0.0.0.0:3000 --dis-multicast-group 239.2.3.1 \
  --dis-allowed-cidrs 10.20.0.0/16
```

The port comes from `--<proto>-bind`; there is no separate multicast-port
flag. Source-CIDR allowlisting, per-IP rate limiting, the synthetic-identity
cap, and the validating decode all apply to multicast datagrams exactly as
they do to unicast — the only difference is how the socket is bound.
`SO_REUSEADDR` lets a co-located sensor app and the router share the port on
one host. The join happens on the kernel's default routed interface
(`0.0.0.0`); a per-protocol interface override is not exposed for the codec
ingress (the separate `--udp-multicast-interface` flag pins only the CoT
multicast listener). Multicast here is **inbound only** — the router never
re-broadcasts to a multicast destination from a codec ingress path. STANAG
4586 (also UDP) has no multicast flag.

### Stream protocols (TCP): SAPIENT, Link 16, NFFI

SAPIENT, **Link 16 / JREAP-C**, and **NFFI** (STANAG 5527) are
**connection-oriented** (TCP), so their listeners delimit a byte stream into
frames — SAPIENT by a protobuf varint length prefix, Link 16 by the
body-length field inside the 16-byte JREAP header, NFFI at the XML document
boundary (the same stream framing CoT-over-TCP uses) — and add one extra knob
over the UDP protocols: a `--<proto>-max-connections` concurrent-connection
cap. All three use the identical
`--<proto>-{bind,group,rate-limit-pps,allowed-cidrs,max-identities,max-connections}`
flag shape (`sapient` / `link16` / `nffi`); the SAPIENT flags below stand for
all three.

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
  decode to the forward-compatible opaque arm), NFFI the **first `<track>`**
  of the document. Other PDU/category/message types are dropped at the
  validating decode until the codec maps them, and multi-record datagrams
  (e.g. several ASTERIX tracks in one datablock, several NFFI tracks in one
  document) surface only their first record for now.
- **Multicast is inbound only.** The UDP codecs (DIS / ASTERIX / VMF) can
  *join* an IPv4 multicast group via `--<proto>-multicast-group` to receive
  on an exercise LAN (see above), but the server never re-broadcasts to a
  multicast destination from these paths. STANAG 4586 (also UDP) and the
  stream protocols (SAPIENT, Link 16 / JREAP-C, all TCP) have no multicast
  flag.
- **STANAG 4586 is UDP-only here.** One STANAG message per datagram.
  TCP-stream STANAG is deferred: its frame size is message-type-dependent
  (no self-delimiting length prefix), so a stream needs a per-deployment
  framing decision — tracked under #1473.
- **Meshtastic** (LoRa/serial) is a distinct radio ingress path, tracked
  under #1473.
