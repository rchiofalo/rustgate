# Tactical Codec Ingress

rustgate ships codecs for many tactical protocols, but most are only useful
once the server can actually **receive** them off the wire. The *tactical
codec ingress* is a generic, codec-pluggable **UDP listener** that turns
datagram-oriented tactical traffic into routed messages — subject to the
same ACL/authz, dedup, and egress as every other transport.

The first wave wires **DIS** (IEEE 1278.1 Entity State PDUs). **ASTERIX**
and **VMF** layer onto the same listener as follow-ups; Link 16 / STANAG
4586 / SAPIENT (stream-framed) and Meshtastic (LoRa) are separate ingress
paths. See the [design note](design/tactical-codec-ingress.md) and the
tracking epic (#1473).

> [!WARNING]
> **These are unauthenticated, unencrypted UDP ingress paths.** There is no
> mTLS — anyone who can reach the bound port can submit datagrams. Identity
> is synthetic. Deploy **only on a trusted network segment**, always pair
> with a CIDR allowlist, and rely on group-level ACL/authz for trust. This
> is the same posture as the plaintext CoT-over-UDP listener.

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
  limit is **never off**: an unset/`0` `--dis-rate-limit-pps` applies the
  built-in default (10000 pps/IP), not "unlimited."
- **No allowlist ⇒ loud warning.** Starting without `--dis-allowed-cidrs`
  logs a prominent warning that the port is exposed to the whole reachable
  network.

## Enabling DIS ingress

```bash
rustgate-server \
  --dis-bind 0.0.0.0:3000 \
  --dis-group dis-feed \
  --dis-allowed-cidrs 10.20.0.0/16 \
  --dis-rate-limit-pps 5000 \
  --dis-max-identities 1024
```

When `--dis-bind` is unset, DIS ingress is disabled (default-deny). All
flags have matching `RUSTGATE_DIS_*` environment variables and TOML
config-file keys.

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `--dis-bind` | `RUSTGATE_DIS_BIND` | *(unset → disabled)* | UDP bind address for DIS Entity State PDUs |
| `--dis-group` | `RUSTGATE_DIS_GROUP` | `dis` | Destination group accepted PDUs route to (ACL/authz apply) |
| `--dis-rate-limit-pps` | `RUSTGATE_DIS_RATE_LIMIT_PPS` | `0` → secure default | Per-IP datagrams/sec (`0` = built-in default, not off) |
| `--dis-allowed-cidrs` | `RUSTGATE_DIS_ALLOWED_CIDRS` | *(unset → warn)* | Comma-separated source CIDR allowlist |
| `--dis-max-identities` | `RUSTGATE_DIS_MAX_IDENTITIES` | `1024` | Synthetic-identity LRU bound (new IPs rejected at cap) |

## How a datagram flows

1. **Receive** a UDP datagram on `--dis-bind`.
2. **Admission** — drop (and audit) if the source IP is outside the
   allowlist, over its rate budget, or new while the identity cap is full;
   drop if the datagram exceeds the size cap.
3. **Validate** — decode with the DIS codec; drop + audit if it is not a
   well-formed Entity State PDU.
4. **Route** — build a message carrying the raw PDU bytes, the synthetic
   identity, the configured group, and `source_protocol = "dis"`, then hand
   it to the router. ACL/authz, dedup, multi-sensor correlation, and egress
   (NATS/federation/etc.) apply exactly as for any other source.

## Observability

- Startup logs a `warn` that the ingress is active and unencrypted, plus a
  second `warn` if no CIDR allowlist is configured.
- Drops are audited by class: `client.rejected` with reason
  `cidr_not_allowed` / `identity_cap_reached` / `datagram_too_large` /
  `malformed_datagram`, and `security.rate_limited` for rate-limit drops.
- Accepted PDUs appear in the access log and audit trail like any routed
  message (`source_protocol = "dis"`), with the canonical entity kind
  surfaced via the router's `EntityCodecRegistry`.

## Limitations (first wave)

- **DIS only** so far. ASTERIX and VMF use the same listener and config
  shape and land next; Link 16 / STANAG 4586 / SAPIENT (stream-framed) and
  Meshtastic (LoRa/serial) are distinct ingress paths.
- **Entity State PDUs only** for DIS (other PDU types are dropped at the
  validating decode until the codec supports them).
- **Unicast only** in this first wave; multicast ingress (ASTERIX / DIS on
  an exercise LAN) reuses the same controls and lands with the multicast
  follow-up.
