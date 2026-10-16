# Bytes discipline on the message path

`bytes::Bytes` is the canonical zero-copy buffer type for payloads in the
rustgate workspace. Cloning a `Bytes` is a refcount bump on a shared heap
allocation, not a `memcpy`. The router fan-out, federation forward,
NATS publish, HTTP egress, MQTT publish, and WebSocket write paths all
propagate the same underlying allocation across every recipient.

The rule, in one line: **stay on `Bytes` end-to-end on the message path.
Use `Vec<u8>` only at FFI / serialization boundaries that genuinely need
ownership of a heap-resizable buffer.**

## What "on the message path" means

The message path is every code path that carries a payload from ingress
(TLS frame, plaintext frame, WebSocket frame, MQTT publish, HTTP webhook
inbound) through the router and onward to one or more egress sinks
(client session writers, federated peers, NATS subjects, HTTP webhooks,
MQTT subscribers, WebSocket clients). The concrete types involved are:

- `RoutableMessage::payload: Bytes`
- `Codec::encode_payload(...) -> io::Result<Bytes>`
- `SessionHandle::try_send(RoutedMessage)` (carries `Arc<RoutableMessage>`)
- Federation `forward(Bytes, &[String])`
- HTTP `publisher::serialize(&RoutableMessage, ...) -> Result<(Bytes, ...)>`

Any conversion to or from `Vec<u8>` inside this loop is a heap allocation
plus a `memcpy` of the payload — the exact cost rustgate is engineered
to avoid.

## Anti-patterns to grep for

These idioms convert `Bytes -> Vec<u8>` (or worse, `Bytes -> Vec<u8> ->
Bytes`) on the message path:

| Pattern | Why it costs | Fix |
|---|---|---|
| `bytes.to_vec()` returning `Vec<u8>` to a consumer | Allocates + memcpy. | If the consumer takes `&[u8]`, pass `bytes.as_ref()`. If it takes `Bytes`, pass `bytes.clone()` (refcount bump). |
| `Vec::from(bytes)` / `bytes.as_ref().to_vec()` | Same as above. | Same as above. |
| `Bytes::from(vec_built_from_bytes)` | Round-trip allocation. | Pass `Bytes` through directly, or change the upstream function to return `Bytes`. |
| `Message::Binary(bytes.to_vec().into())` (tungstenite WS) | tungstenite 0.29's `Message::Binary` takes `Bytes` — `to_vec().into()` does `Bytes -> Vec -> Bytes`. | `Message::Binary(bytes)`. |
| Function takes `&[u8]` and unconditionally returns `Vec<u8>` even on no-op | Forces a copy on every call, including the common no-op case. | Take `&Bytes` and return `Bytes` so the no-op path is `data.clone()` (refcount bump). |

## Where `Vec<u8>` is fine

- Outputs of `serde_json::to_vec`, `prost::Message::encode_to_vec`, or
  any other "build a fresh buffer from scratch" serializer. Wrap in
  `Bytes::from(vec)` once at the boundary.
- Cryptographic / certificate material handled by `rustls`, `rcgen`,
  `aws-lc-rs`, etc. Those APIs predate `Bytes` and round-trip
  through `Vec<u8>` is not a hot loop.
- Temporary scratch buffers inside a single function (e.g.
  `String::with_capacity(...).into_bytes()` for splice operations) —
  but convert to `Bytes` before returning.

## When in doubt, change the signature

If a function on the message path takes `&[u8]` and returns `Vec<u8>`,
prefer `&Bytes -> Bytes`. This lets callers benefit from refcount-clone
fast paths when the function's result is the same allocation as its
input (e.g. `add_flow_tag` returns the original payload unchanged when
no marker is found in the XML). The `&Bytes` argument still
deref-coerces to `&[u8]` for any internal slice operations.

## Related

- The `router_fanout` criterion benchmark in
  `crates/rustgate-transport/benches/router_fanout.rs` exercises the
  fanout hot path. Run before/after any change that touches the message
  path to detect allocation-profile regressions.
- The Tokio + `bytes` crate documentation explains the refcount-clone
  semantics in detail. See <https://docs.rs/bytes/latest/bytes/struct.Bytes.html>.
