# rustgate Protocol Specification

This document is the normative reference for the rustgate wire protocol. It is
intended to give a competent engineer everything required to implement a
conforming client (or an interoperable peer) without reading the source.

The protocol layers, from bottom to top, are:

1. **Transport security** — TCP + mTLS (rustls), or WebSocket + mTLS.
2. **Framing** — pluggable byte-stream framing strategy.
3. **Message codec** — XML (Cursor-on-Target), TAK protobuf, or raw bytes.
4. **Routing** — direct, group, or broadcast destinations evaluated against
   identity-derived ACLs and a server-side dedup window.
5. **Federation** — gRPC FederatedChannel (V2) over a separate mTLS listener,
   with optional JWT authorization and HA coordination over NATS JetStream KV.

Sections below describe each layer, byte-level where it matters.

---

## 1. Transport Security

### 1.1 TLS versions

- **Minimum**: TLS 1.2 (default). Operators may pin to TLS 1.3 only via
  configuration (`tls_min_version = "1.3"`).
- **Maximum**: TLS 1.3.
- TLS 1.0 and 1.1 are not offered. SSLv3 is not offered.

A conforming client MUST support TLS 1.3 and SHOULD support TLS 1.2 for
backward compatibility with older deployments.

### 1.2 Cipher suites

The crypto provider is `rustls` with one of three backends:

| Backend       | Selected by              | Suites                                                                 |
|---------------|--------------------------|------------------------------------------------------------------------|
| `ring`        | default                  | rustls default suites for TLS 1.2/1.3                                  |
| `aws-lc-rs`   | `--features fips`        | FIPS 140-3 validated subset (TLS 1.2 + 1.3, AES-GCM, ECDHE only)       |
| `aws-lc-rs`   | `--features post-quantum`| Adds `X25519MLKEM768` hybrid key exchange for TLS 1.3                  |

Cipher suite selection is delegated to rustls — clients negotiate normally.
Under FIPS, only the FIPS-approved subset is offered; clients without an
overlapping FIPS suite will fail the handshake.

### 1.3 ALPN

rustgate does **not** require ALPN. The server does not advertise an ALPN
list, and clients SHOULD NOT send one for the primary mTLS listener. The
WebSocket listener relies on the HTTP `Upgrade` mechanism rather than ALPN.

(Federation V2 uses tonic/gRPC and therefore advertises `h2` per gRPC
convention; see §5.)

### 1.4 mTLS

Mutual TLS is **mandatory** on the primary listener. Specifically:

- The server presents a certificate chain configured at startup.
- The server REQUIRES a client certificate. A connection without one is
  rejected during the handshake.
- Client certificate validation uses `WebPkiClientVerifier` against a
  configured client CA root store. Path validation is full RFC 5280.
- If one or more CRLs are loaded, revoked client certificates are rejected
  during the handshake (before the application layer sees the connection).
  CRL `nextUpdate` freshness is checked at load time; stale CRLs are warned
  about but not rejected.
- TLS session resumption is **disabled** server-side
  (`NoServerSessionStorage`). Every connection performs a full handshake so
  that revocation and CA rotation take effect immediately. Clients MUST NOT
  rely on resumption.
- Concurrent handshakes are bounded by a server-side semaphore (default 100).
  Excess connections wait in the TCP accept queue.

### 1.5 Identity extraction

After a successful handshake the server extracts the client identity from
the leaf certificate:

- **Common Name (CN)** of the Subject becomes the session identity (used for
  `Destination::Direct` routing).
- **Organizational Unit (OU)** entries become the session's group set (used
  for `Destination::Group` routing and ACL evaluation). Multiple OUs are
  allowed and produce multiple group memberships.
- The certificate's `keyUsage` extension is validated against an
  `ExpectedKeyUsage` policy (typically `digitalSignature`).

A client whose leaf certificate has an empty CN, no OUs, or fails key-usage
validation will be disconnected immediately after the handshake.

### 1.6 FIPS / post-quantum notes

- **FIPS** (`--features fips`) installs the aws-lc-rs FIPS provider as the
  process-wide rustls default. All TLS connections — including federation —
  use FIPS-validated crypto. Tests for this mode live in
  `crates/rustgate-transport/tests/fips.rs`.
- **Post-quantum** (`--features post-quantum`) enables the X25519MLKEM768
  hybrid key exchange (NIST ML-KEM 768 + X25519) on TLS 1.3 only. Classical
  X25519 remains available for fallback. Both peers must support the hybrid
  group for it to be negotiated.

---

## 2. Framing

After the TLS handshake completes, the application byte stream is split into
discrete messages by a **framing strategy**. The strategy is configured per
listener; a single listener uses exactly one strategy. The defined strategies
are enumerated in `rustgate_core::protocol::FramingStrategy`:

```
LengthPrefixed { header_size: One | Two | Four }
XmlStream
LineDelimited
TakProtobuf                      // requires --features proto
```

### 2.1 Common limits

- **MAX_FRAME_SIZE** = 16 MiB (16 × 1024 × 1024 bytes). All framing strategies
  reject frames larger than this with an `InvalidData` error and close the
  connection.
- For `LengthPrefixed`, the per-listener limit is `min(header_max, MAX_FRAME_SIZE)`
  where `header_max` is `2^(8·header_size) − 1`. A 1-byte header therefore caps
  payloads at 255 bytes regardless of the global limit.

### 2.2 LengthPrefixed

Each frame is:

```
+----------------+----------------------+
| length header  |       payload        |
| (N bytes, BE)  |    (length bytes)    |
+----------------+----------------------+
```

- `header_size = One`  → 1-byte unsigned length, max payload 255 bytes.
- `header_size = Two`  → big-endian `u16`, max payload 65 535 bytes.
- `header_size = Four` → big-endian `u32`, max payload `min(2^32−1, MAX_FRAME_SIZE)`.

The length value counts the **payload only**, not the header. Length 0 is
legal and produces an empty frame. The decoder reads the header, validates
the length against `MAX_FRAME_SIZE`, then waits for the full payload before
delivering the frame to the codec layer.

### 2.3 XmlStream

For text-based clients (CoT producers) the framing is XML element boundaries.
The decoder scans for the first top-level element and returns it as a single
frame, including any leading XML processing instructions or comments at depth
0. Rules:

- Self-closing tags (`<x/>`) at depth 0 yield a one-element frame.
- Open/close pairs (`<a>...</a>`) yield a frame ending at the matching close.
- Quoted attribute values (single or double) may contain `>` and are not
  treated as tag terminators.
- `<!-- ... -->` comments and `<![CDATA[ ... ]]>` sections are passed through.
- Maximum nesting depth is **256**. Streams that nest deeper are rejected
  with `InvalidData`.
- Buffered bytes that exceed `MAX_FRAME_SIZE` before a frame completes also
  cause `InvalidData`.

Encoding is a pass-through: the codec writes the bytes the application
provides without adding delimiters. Producers must emit well-formed XML.

### 2.4 LineDelimited

Each frame is terminated by `\n`. A trailing `\r` immediately before the
`\n` is stripped (CRLF tolerated). Lines longer than `MAX_FRAME_SIZE` cause
`InvalidData`. The encoder appends a single `\n`.

### 2.5 TakProtobuf

This is the TAK Server "Protocol Version 1" framing. Each frame is:

```
+--------+----------------------+----------------------+
| 0xBF   | varint(payload_len)  |    protobuf bytes    |
| 1 byte | 1–5 bytes (LEB128)   |    (payload_len)     |
+--------+----------------------+----------------------+
```

- The magic byte is `0xBF`. A first byte that is not `0xBF` is `InvalidData`.
- The length is a protobuf-style varint (LEB128), maximum 5 bytes (covers
  the `u32` range). An invalid varint is `InvalidData`.
- The payload is a `TakMessage` protobuf as defined in
  `crates/rustgate-proto/proto/takmessage.proto`. See §3.2.
- `payload_len` is bounded by `MAX_FRAME_SIZE`.

The encoder writes `0xBF`, a varint length, then the payload bytes — in that
order, with no padding.

---

## 3. Message Codec

The framing layer yields opaque byte buffers. The codec layer interprets
those buffers as application messages.

### 3.1 Cursor-on-Target XML

- Crate: `rustgate-cot`.
- Wire form: a single `<event>` element with attributes (`uid`, `type`,
  `time`, `start`, `stale`, `how`) and nested `<point>` and `<detail>`
  children. See `crates/rustgate-cot/` for the parser.
- Validation rejects oversized documents and pathological nesting.
- Used with the `XmlStream` framing strategy.

### 3.2 TAK protobuf

- Crate: `rustgate-proto`.
- Schemas: `crates/rustgate-proto/proto/*.proto`. The top-level message is
  `TakMessage` (`takmessage.proto`); it contains a `TakControl` and a
  `CotEvent`, with nested `Detail`, `Group`, `PrecisionLocation`, `Status`,
  `Takv`, `Track`, and `Contact` messages.
- The `rustgate-proto` crate also provides bidirectional XML ⇄ protobuf
  conversion so that a single router can serve mixed-codec clients.
- Used with the `TakProtobuf` framing strategy.

### 3.3 Raw / line-delimited

`LineDelimited` framing delivers each line to the application as raw bytes.
This is intended for line-oriented test clients and bridge scenarios; no
schema is enforced at the codec layer.

---

## 4. Routing Semantics

After decoding, every message becomes a `RoutableMessage` with three pieces
of information that drive routing:

- **Source identity** — derived from the sender's mTLS certificate (§1.5).
- **Destination** — one of `Direct(Identity)`, `Group(GroupId)`, or
  `Broadcast`.
- **MessageType** — `Position`, `Chat`, `Alert`, `Status`, `File`, or other.

### 4.1 Destinations

| Destination       | Delivered to                                                                                  |
|-------------------|-----------------------------------------------------------------------------------------------|
| `Direct(id)`      | The single session whose certificate CN equals `id`. No-op if not connected.                  |
| `Group(g)`        | Every session whose certificate OU set contains `g`, except the sender.                       |
| `Broadcast`       | Every connected session except the sender.                                                    |

The sender is always excluded from `Group` and `Broadcast` deliveries to
prevent self-echo.

### 4.2 ACLs

A `GroupAclPolicy` is consulted before delivery:

- Groups may be configured `allow` or `deny`.
- A sender may only address groups it is a member of (no spoofing).
- A recipient only receives a group message if its OU set still includes
  the destination group at delivery time (group membership is re-checked,
  not cached).
- ACL configuration is hot-reloadable via SIGHUP and the admin API.

### 4.3 Deduplication

The router maintains a per-server `DedupCache` keyed by message UID +
content hash. A message that hashes to the same key as a recently routed
message (within the configured time window) is dropped before delivery.
This collapses retransmissions, federation echoes, and multi-path
duplicates without requiring sequence numbers from clients.

### 4.4 Backpressure and priority

- Each session has two outbound channels: a **priority** channel (capacity
  64) used for `Position` and `Alert` messages, and a **normal** channel
  (capacity 64) for everything else.
- A global `BackpressureGate` reserves bytes for in-flight messages. When
  the reservation cannot be satisfied, the producing session is paused.
- Per-session circuit breakers trip after `DEFAULT_MAX_CONSECUTIVE_DROPS`
  (10) consecutive failed sends and disconnect the session.

---

## 5. Federation V2 Protocol

Federation runs on a **separate** listener from the client mTLS listener,
with its own certificate and CA store. The wire protocol is gRPC over
HTTP/2 over TLS, generated from the upstream TAK Server `fig.proto`
descriptor (`com.atakmap.FederatedChannel`). It is implemented with `tonic`.

### 5.1 Service surface

The `FederatedChannel` service exposes (per `figpb`):

- `ServerFederatedChannel` — bidirectional event stream initiated by the
  remote peer.
- `ClientFederatedChannel` — bidirectional event stream initiated by us.
- `SendOneEvent` — unary helper for one-shot delivery.
- `Health` — health check exchange.
- `BinaryMessageStream` — out-of-band binary attachment transport.

The wire-level message types are also defined in `figpb` and include:

- `FederatedEvent` — top-level envelope: optional `event` (`GeoEvent`),
  optional `contact`, repeated `federate_groups`, repeated
  `federate_provenance`, optional `federate_hops`.
- `GeoEvent` — CoT-equivalent fields (`uid`, `type`, `lat`, `lon`, `hae`,
  `ce`, `le`, `start_time`, `send_time`, `stale_time`, `how`, `detail_xml`,
  `bloads`, etc.).
- `Identity` — peer identity exchanged during handshake (`name`, `uid`,
  `description`, `type`, `server_id`). `ConnectionType` enumerates
  `FederationHubServer = 0`, `FederationHubClient = 1`,
  `FederationTakServer = 2`, `FederationTakClient = 3`.
- `Subscription`, `ServerHealth`, `ClientHealth`, `FederateGroups`, `Rol`,
  `BinaryBlob`, `BinaryPayload` (from `gov.tak.cop.proto.v1`).

### 5.2 Handshake

1. mTLS handshake completes (same rules as §1, with the federation CA store).
2. The peer opens a bidirectional stream (`ServerFederatedChannel` or
   `ClientFederatedChannel`).
3. The first `FederatedEvent` SHOULD carry the local `Identity` and the
   advertised `federate_groups`. The server stores the peer's group set in a
   per-peer table keyed by federation ID.
4. The server enforces:
   - **`max_groups_per_peer`** — default 1 000.
   - **`max_group_name_length`** — default 256 bytes.
   - Peers exceeding these are disconnected.
5. After the handshake, both sides stream `FederatedEvent`s. Inbound events
   trigger an `OnEvent` callback that injects the message into the local
   router (subject to ACL and dedup, §4).

### 5.3 JWT authorization (optional)

When `--features federation-ha` is enabled, peers MAY authenticate with a
JWT in addition to mTLS. JWTs are HMAC-SHA256 signed and carry:

```jsonc
{
  "sub": "peer-federation-id",
  "iss": "issuing-server-id",
  "exp": 1700000000,           // unix seconds
  "iat": 1699999000,           // unix seconds
  "jti": "unique-token-id",    // optional, for revocation
  "groups": ["alpha", "bravo"] // optional, authorized groups
}
```

Constraints:

- HMAC secret MUST be at least **32 bytes**.
- A clock skew of **±60 seconds** is tolerated on `iat`.
- Tokens are revocable by `jti`; the revocation cache holds up to 10 000
  entries by default and entries are auto-pruned after `exp` passes.
- JWT is layered on top of mTLS; it does not replace it.

### 5.4 Message envelope, hops, and provenance

Every `FederatedEvent` carries:

- **`federate_provenance`** — append-only list of `FederateProvenance`
  records (`federation_server_id`, `federation_server_name`). Each server
  that forwards the event prepends its own record. A server that sees its
  own ID in the list MUST drop the event (loop suppression).
- **`federate_hops`** — `{max_hops, current_hops}`. Forwarding increments
  `current_hops`; if it would exceed `max_hops`, the event is dropped.
- **`federate_groups`** — the destination group set. A peer only receives
  events whose `federate_groups` intersect the groups it advertised.
- **`federate_group_hop_limits`** — optional per-group hop overrides.

### 5.5 Replay buffer

The federation manager keeps a bounded `ReplayBuffer` of recently sent
events per peer. On reconnect, replay is offered to the peer to bridge a
short outage without losing position updates. Combined with §4.3 dedup,
duplicates introduced by replay are discarded by the receiver.

### 5.6 Health and heartbeats

- The `Health` RPC exchanges `ServerHealth`/`ClientHealth` messages with a
  `ServingStatus` enum (`Unknown=0`, `Serving=1`, `NotServing=2`,
  `NotConnected=3` for `ServerHealth`).
- Application-level heartbeats run on a configurable interval; missed
  heartbeats trigger reconnect via the `ReconnectPolicy`.

---

## 6. HA Coordination

When `--features federation-ha` is enabled and a NATS JetStream cluster is
configured, multiple rustgate pods coordinate ownership of outbound
federation peers so that exactly one pod connects to a given remote at a
time.

### 6.1 Connection registry

- KV bucket: **`federation-connections`**.
- Key: `peer_id`. Value: `ConnectionInfo` (peer ID, owning pod ID,
  direction, `connected_at` unix seconds, optional `fencing_token`).
- TTL: **30 seconds**. Owners refresh their entries every **10 seconds**.
- Stale entries expire automatically; the next pod to attempt the peer
  takes over.

### 6.2 Leader election (per-peer)

- Ownership is acquired by writing the registry entry **conditionally** on
  the current revision. The KV revision returned on success becomes the
  pod's **fencing token** for that peer.
- A pod may only initiate or maintain an outbound connection while it
  holds a current fencing token. Operations are tagged with the token so
  that a stale owner whose lease has expired cannot mutate state.
- Inbound connections are not claimed (the remote chose us); they are
  recorded in the registry without a fencing token.
- Ownership is voluntary: pods relinquish their entry on graceful shutdown
  so failover is immediate.

### 6.3 Split-brain handling

Two pods that believe they own the same peer will hold different fencing
tokens. Writes from the older token are rejected by the conditional KV
update, and the losing pod tears down its connection and drops back to
candidate state.

---

## 7. Versioning and Conformance

- This document tracks the protocol implemented on `main`. Breaking
  changes are recorded in `CHANGELOG.md`.
- A conforming **client** MUST:
  - Complete an mTLS 1.2-or-1.3 handshake with a CA-issued certificate that
    has a non-empty CN and at least one OU (§1.4–1.5).
  - Use exactly the framing strategy the listener is configured for (§2).
  - Honor `MAX_FRAME_SIZE = 16 MiB`.
  - Tolerate server-initiated disconnects on ACL violations, frame errors,
    and circuit-breaker trips.
- A conforming **federation peer** MUST:
  - Use the `figpb.FederatedChannel` gRPC service over mTLS.
  - Append its `FederateProvenance` record on forward and drop events
    where its own ID is already present (§5.4).
  - Respect `max_hops` and per-group hop limits.

---

## 8. Cross-references

- `crates/rustgate-core/src/protocol.rs` — `FramingStrategy`, `HeaderSize`.
- `crates/rustgate-core/src/constants.rs` — `MAX_FRAME_SIZE`.
- `crates/rustgate-core/src/message.rs` — `Destination`, `MessageType`,
  `RoutableMessage`.
- `crates/rustgate-transport/src/codec.rs` — framing decoder/encoder.
- `crates/rustgate-transport/src/config.rs` — TLS configuration and
  `TlsMinVersion`.
- `crates/rustgate-transport/src/listener.rs` — mTLS listener, handshake
  semaphore, identity extraction.
- `crates/rustgate-transport/src/router.rs` — routing engine, dedup,
  backpressure, priority channels.
- `crates/rustgate-proto/src/codec.rs` — TAK protobuf framing (`0xBF` +
  varint).
- `crates/rustgate-proto/proto/takmessage.proto` — TAK message schema.
- `crates/rustgate-federation/src/v2/` — V2 federation client and server.
- `crates/rustgate-federation/src/jwt.rs` — JWT authority.
- `crates/rustgate-federation/src/ha/registry.rs` — HA connection registry.

For background and operations, see also `docs/architecture.md`,
`docs/federation.md`, `docs/tls-certificates.md`, `docs/fips.md`, and
`docs/post-quantum.md`.
