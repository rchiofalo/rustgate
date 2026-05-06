# ADR 0012: `bytes::Bytes` end-to-end; no `Vec<u8>` on the routing hot path

- **Status:** Accepted
- **Date:** 2026-05-06
- **Related:** `crates/rustgate-core/src/message.rs`,
  `crates/rustgate-core/src/codec.rs`,
  `.claude/rules/shared-infrastructure.md` "Code Style"

## Context

A routed message in rustgate is an envelope around a payload. The
payload arrives over a TLS, plaintext-TCP, WebSocket, MQTT, or
NATS connection, is decoded into a `RoutableMessage`, evaluated for
ACL / authz / dedup / TTL, and then fanned out to N recipients —
each of whom may serialise it onto a different transport, possibly
through store-and-forward, possibly through federation. On the hot
path, the same payload bytes traverse the system several times.

Two payload-buffer types are viable:

- **`Vec<u8>`** — the standard library owned byte buffer. Cloning
  copies every byte. Slicing borrows; carrying a slice across an
  ownership boundary requires either copying or wrapping in `Cow`.
- **`bytes::Bytes`** — a reference-counted, immutable byte buffer
  from the `bytes` crate. `Bytes::clone()` is `O(1)` (it bumps a
  refcount). Slicing returns a new `Bytes` that aliases the original
  allocation. Conversion from `Vec<u8>` is zero-copy in either
  direction (the `Vec`'s allocation becomes the `Bytes`'s).

The fan-out shape is the deciding factor. A broadcast to 100
subscribers with a `Vec<u8>` payload either copies 100 times (one
per `clone`) or pays for an `Arc<Vec<u8>>` indirection at every read
site. With `Bytes`, the underlying allocation is shared by all 100
recipients and freed when the last one finishes serialising the
payload onto its wire. The broadcast fan-out is the most common
shape on a tactical message bus — position updates often go to
every subscriber in a group.

`bytes` is also the buffer type used by every async networking crate
in the tokio ecosystem: `tokio::io::AsyncRead` returns `BytesMut`
into operator-supplied buffers, `tonic` (gRPC) frames carry
`Bytes` payloads, `hyper` (HTTP) bodies are `Bytes`-backed, and
`tokio-tungstenite` (WebSocket) emits `Bytes` for binary frames.
Choosing `Vec<u8>` would mean a copy at every protocol boundary.

## Decision

The canonical payload type on the hot path is `bytes::Bytes`.
`RoutableMessage::payload` is `Bytes`. Every codec
(`rustgate_core::codec::Codec`) decodes a frame into a `Bytes` and
encodes a `Bytes` into a frame. The federation envelope carries
`Bytes`. The store-and-forward queue serialises `Bytes` into its
on-disk form and reconstructs `Bytes` on drain. The MAVLink, CoT XML,
ASTERIX, and STANAG-4586 codecs all consume and produce `Bytes`.

Concretely:

- Public API surfaces (`Codec::decode_payload`, `Codec::encode`,
  `Router::route`) take or return `Bytes`. `Vec<u8>` shows up only
  at the very edges, where a `serde_json` document is being built or
  a reqwest body is being assembled, and is converted to `Bytes`
  before crossing into the routing core.
- The receive path constructs `Bytes` directly from the
  `BytesMut` buffer that the framed reader produced. There is no
  intermediate `Vec<u8>` copy.
- The transmit path slices a single `Bytes` into per-recipient
  views (cheap clones); each view carries the same backing
  allocation through to the wire write.

`.claude/rules/shared-infrastructure.md` "Code Style" lists the rule
as "Use let-chains, iterator chains, `Bytes` for payloads."

## Alternatives considered

- **`Vec<u8>` end-to-end.** Rejected: the broadcast fan-out alone
  makes per-recipient cloning unaffordable. An `Arc<Vec<u8>>`
  indirection at every read site recovers the cost but loses the
  zero-copy interop with the rest of the tokio ecosystem.
- **A custom `Payload` newtype around `Arc<[u8]>`.** Workable but
  reinvents `bytes::Bytes`. The `bytes` crate is already a transitive
  dependency through `tokio` and `hyper`, so adopting it directly
  costs nothing.
- **`Cow<'a, [u8]>`.** Rejected: lifetime-parametric payloads do not
  fit the cross-task fan-out shape — a `Cow` borrowed from a frame
  buffer cannot outlive the read loop that produced it without being
  upgraded to owned, at which point we are back to a copy.
- **`std::sync::Arc<[u8]>`.** Closer to `Bytes` than `Vec<u8>` is,
  but loses the zero-copy slice operations that `Bytes` provides.
  The federation envelope frequently slices a payload to extract a
  CoT XML body from a length-prefixed framing; `Bytes` makes that
  free, `Arc<[u8]>` does not.

## Consequences

- `bytes` is a foundational workspace dependency.
  `bytes::{Bytes, BytesMut}` are the canonical buffer types.
- Helper conversions are cheap: `Bytes::from(vec)` and
  `Bytes::from_static(b"...")` are both zero-copy. Authors writing
  test fixtures lean on `Bytes::from_static` for compile-time-known
  payloads.
- Reviewers push back on `Vec<u8>` in newly-introduced public APIs
  on the routing path. The exception is API surfaces that genuinely
  produce a fresh allocation that has no sharing pressure (e.g. the
  `serde_json` output of a Prometheus dump endpoint).
- The on-disk store-and-forward format embeds the payload bytes
  directly; there is no extra envelope layer between `Bytes` and the
  redb value. This is documented in
  [ADR 0006](0006-redb-over-sled-for-store-and-forward.md).
- Tests routinely write `Bytes::from_static(b"hello")` for
  fixed-content payloads and `Bytes::from(vec![0u8; N])` for
  size-parameterised ones. There is no `Vec<u8>` round-trip
  ceremony.
- If a future codec needs interior mutability over a payload (e.g. a
  speculative compression layer), the right shape is to receive
  `Bytes`, hand the buffer to a `BytesMut` for mutation, and re-
  freeze to `Bytes` before returning. The `BytesMut` lifetime is
  scoped to the codec — the routing core never sees a mutable
  buffer.
