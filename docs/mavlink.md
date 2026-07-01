# MAVLink Integration

rustgate ingests [MAVLink](https://mavlink.io/) telemetry and command
traffic — the dominant wire protocol for UAVs, rovers, and boats — over
dedicated UDP and TCP listeners, applying the same identity, ACL, and
authorization boundary that CoT and chat traffic cross. Instead of
bolting a separate MAVLink proxy in front of rustgate, the router
terminates the MAVLink signing boundary itself.

The design is recorded in
[ADR 0020](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0020-mavlink-pq-rekey.md).

## Why a dedicated listener

MAVLink over UDP has no TLS, so rustgate's usual mTLS-certificate
identity is unavailable. The MAVLink v2 message-signing block carries a
1-byte `link_id`; rustgate treats each `link_id` as a distinct identity,
mapped to a CN and groups through an operator-provided **link manifest**.
A frame whose verified `link_id` is not in the manifest is dropped — there
is no anonymous-MAVLink path. This is what lets MAVLink traffic be
ACL- and authz-filtered exactly like every other transport.

## Quick start

1. Build the server (MAVLink support is always compiled in; the
   post-quantum rekey channel needs the extra `mavlink-pq` feature — see
   below):

   ```bash
   cargo build --release
   ```

2. Create a link manifest `mavlink-links.toml` mapping each v2 signing
   `link_id` to an identity and its 32-byte signing key:

   ```toml
   # link_id may be decimal (7) or hex (0x42), 0-255.
   [links.0x42]
   cn = "drone-007"
   groups = ["tactical/uav", "ops/team-alpha"]
   signing-key-hex = "0123…64 hex chars…cdef"   # 32 bytes

   [links.7]
   cn = "rover-12"
   groups = ["tactical/ugv"]
   signing-key-hex = "fedc…64 hex chars…3210"
   ```

   Keep this file `chmod 0400` — it holds raw signing keys. rustgate reads
   it into zeroized memory and wipes the hex strings after decoding.

3. Start a UDP listener, routing every frame to the `tactical/uav` group:

   ```bash
   rustgate \
     --bind 0.0.0.0:8089 --cert server.pem --key server.key --ca ca.pem \
     --mavlink-bind 0.0.0.0:14550 \
     --mavlink-group tactical/uav \
     --mavlink-signing-key-file mavlink-links.toml
   ```

   A ground-control station signing with `link_id 0x42` now appears to the
   router as `drone-007` in `tactical/uav` / `ops/team-alpha`.

## CLI flags

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--mavlink-bind` | `RUSTGATE_MAVLINK_BIND` | unset | UDP listener bind (the canonical MAVLink transport). |
| `--mavlink-tcp-bind` | `RUSTGATE_MAVLINK_TCP_BIND` | unset | TCP listener bind (tethered ground-control stations). |
| `--mavlink-group` | `RUSTGATE_MAVLINK_GROUP` | unset → broadcast | Destination group for every ingested frame. |
| `--mavlink-signing-key-file` | `RUSTGATE_MAVLINK_SIGNING_KEY_FILE` | unset | TOML link manifest (`link_id → {cn, groups, signing-key-hex}`). |
| `--mavlink-require-signing` | `RUSTGATE_MAVLINK_REQUIRE_SIGNING` | `true` | Reject v2 frames lacking the SIGNED INCOMPAT bit. |
| `--mavlink-allow-v1` | `RUSTGATE_MAVLINK_ALLOW_V1` | `false` | Admit legacy v1 frames (no signing — see below). |
| `--mavlink-v1-fallback-cn` | `RUSTGATE_MAVLINK_V1_FALLBACK_CN` | unset | Shared CN for admitted v1 frames; required with `--mavlink-allow-v1`. |
| `--mavlink-pq-bootstrap-file` | `RUSTGATE_MAVLINK_PQ_BOOTSTRAP_FILE` | unset | 32-byte PSK for the post-quantum rekey channel (`mavlink-pq` builds). |

At least one of `--mavlink-bind` / `--mavlink-tcp-bind` must be set for
MAVLink ingress to start. All flags are also accepted in the TOML config
file under their kebab-case names.

## Identity, signing, and replay

- **v2 signing.** Each accepted v2 frame's 13-byte signature trailer is
  verified against the per-`link_id` key from the manifest, using the real
  MAVLink algorithm `SHA-256(key ‖ frame_without_signature)[..6]` (not
  RFC 2104 HMAC), so frames interoperate with MAVProxy / pymavlink. The
  signature is compared in constant time.
- **Replay defence.** The 48-bit signing timestamp must strictly advance
  per `(system_id, component_id, link_id)` stream; a bounded LRU
  (default 1024 entries) tracks the high-water mark. A replayed or
  rewound timestamp is dropped.
- **v1 fallback.** MAVLink v1 has no signing block and therefore no
  per-link identity. v1 is rejected by default. To admit it (lab / legacy
  fleets), set `--mavlink-allow-v1` **and** `--mavlink-v1-fallback-cn`;
  all v1 traffic from that listener then shares the one fallback identity,
  with a startup warning and an audit event documenting the degraded
  posture. The fallback CN must be a configured shared identity, never a
  real client CN.

## Routing and obligations

Ingested frames become `RoutableMessage`s with `source_protocol =
"mavlink"` and `MessageType::Mavlink`, routed to the per-listener
destination (a group, or broadcast). Authorization obligations actuate on
the binary wire form:

- **`MaskPoint`** zeroes the `lat` / `lon` / `alt` of a
  `GLOBAL_POSITION_INT` frame and recomputes its CRC.
- **`MaskPayload`** replaces a redacted frame with a benign zeroed
  `HEARTBEAT`.
- **`MaskCommand`** refuses to forward actuation frames
  (`COMMAND_LONG`, `COMMAND_INT`, `MANUAL_CONTROL`) — telemetry still
  flows, but commands are neutralised.

## Post-quantum signing-key rekey (`mavlink-pq`)

Signing keys are symmetric and, by default, distributed out of band. The
optional `mavlink-pq` feature adds a post-quantum confidential
(harvest-now-decrypt-later resistant) rekey channel that wraps a new
signing key inside an ML-KEM-768 (FIPS 203) encapsulation, so an adversary
recording the distribution channel cannot recover the key
even with a future quantum computer. See ADR 0020 §4–§6 for the wire
format and key schedule.

```bash
cargo build --release --features mavlink-pq
```

`mavlink-pq` builds aws-lc from source and requires Go + cmake. The
rekey envelope and its cryptography are implemented and tested today;
`--mavlink-pq-bootstrap-file` loads the bootstrap PSK. The receive-socket
wiring that feeds live envelopes into the running key store is a planned
follow-up.

## Security notes

- **The link is not encrypted.** MAVLink rides UDP/TCP in the clear;
  signing authenticates frames but does not provide confidentiality. Run
  it on a trusted segment, or front it with a network-layer tunnel.
- **Protect the manifest.** It holds raw 32-byte signing keys. Use
  mode 0400 and treat rotation as a key-management event.
- **Prefer signed v2.** Leave `--mavlink-require-signing` at its default
  `true`; only relax it on a fully trusted link, and never combine a
  relaxed policy with `--mavlink-allow-v1` on an exposed segment.

## What is deliberately out of scope

- Hot-reload of the manifest on SIGHUP (planned).
- The live PQ rekey receive socket (planned; the crypto is shipped).
- MAVFTP, parameter-protocol proxying, and DDS / ROS 2 bridging.
