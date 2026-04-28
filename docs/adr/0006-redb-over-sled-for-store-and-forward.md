# ADR 0006: `redb` for the per-client store-and-forward queue

- **Status:** Accepted
- **Date:** 2026-04-27
- **Related:** `crates/rustgate-transport/src/store_forward.rs`

## Context

When a client's per-session bounded `mpsc` channel fills up
(slow-consumer backpressure) and store-and-forward is enabled,
rustgate persists the overflow messages to disk so they can be
delivered when the client reconnects. The on-disk queue must:

- Preserve per-CN ordering with monotonic sequence numbers so a
  reconnecting client receives messages in send order.
- Cap total disk usage with FIFO drop-oldest eviction once a global
  byte budget is exhausted.
- Survive process crashes — a SIGKILL'd server must not corrupt
  the queue.
- HMAC-SHA256-tag each entry for integrity (a corrupted entry must
  surface as an error, not as a silently-replayed bogus message).
- Re-evaluate ACL and authz on drain — policy may have changed
  while the client was offline.
- Run inside the same Tokio process as the rest of the server. No
  external service dependency.

The viable embedded-KV stores for this shape in Rust are:

- **[`redb`](https://crates.io/crates/redb)** — pure-Rust
  embedded key-value store. Single file, MVCC, ACID, no `unsafe`
  in the public path. Maintained, on the audit allowlist.
- **[`sled`](https://crates.io/crates/sled)** — pure-Rust
  embedded KV. More feature-rich, but development cadence has
  stalled and the on-disk format has historically been unstable
  between versions.
- **`rocksdb` / `lmdb` C bindings.** Production-grade and battle-
  tested, but pull in a large C dependency, fight `unsafe_code =
  "forbid"`, and complicate cross-platform CI (FIPS, MUSL,
  Windows).

## Decision

The store-and-forward queue uses `redb` as its backing store. The
queue is stored in a single file `client_queue.redb` inside the
operator-configured `--client-queue-dir`, with two tables:

- A primary table keyed by big-endian `seq_u64` whose value is the
  binary envelope of one queued message (`StoredMessage`).
- A drained-sequence table that tracks which sequence numbers have
  been delivered, so a reconnecting client resumes from the right
  point.

Each envelope is HMAC-SHA256-tagged with a queue-local key derived
from the operator's archive key material; key rotation triggers a
`store_forward.key_rotated` audit event and re-tags the file.

## Alternatives considered

- **`sled`.** Active maintenance has slowed and the format has
  historically required migrations between major versions. For an
  on-disk artifact that must survive process restarts and cross-
  version upgrades, format stability matters more than feature
  surface. Rejected on stability grounds.
- **`rocksdb` / `lmdb`.** Both pull in a substantial C dependency
  with platform-specific build steps. The project's
  `unsafe_code = "forbid"` lint, MSRV gate, and FIPS / post-quantum
  CI matrix all multiply the cost of a C dependency. The
  store-and-forward workload is small enough that the additional
  performance headroom they offer is not worth the build matrix
  cost.
- **A bespoke append-only log file.** The basic shape (write
  records, replay on reconnect) is cheap to implement, but
  drop-oldest FIFO eviction with a global byte cap requires
  random-access deletion, which an append-only log does not
  natively support. Adding a compaction phase would replicate
  most of an embedded KV store, badly.
- **No persistent queue at all.** The original session bounded
  `mpsc` already drops messages when full. For tactical clients
  on intermittent links, that drop-on-full behaviour is operator-
  visible misery and the runbooks frequently land on "enable
  store-and-forward".

## Consequences

- `redb` is a workspace dependency only used by the
  `rustgate-transport::store_forward` module today. New consumers
  should reuse the same crate rather than introducing a parallel
  embedded KV.
- The per-client queue is a real on-disk artifact. Operators must
  size `--client-queue-max-bytes` and back up `--client-queue-dir`
  if continuity of stored messages matters across machine moves.
- The HMAC tag means corruption surfaces as a hard error on read,
  not as silent bogus replay. The cost is one HMAC evaluation per
  drained message — negligible compared to the routing cost.
- On the drain path, ACL and authz checks are re-applied. A client
  whose group membership shrank while offline cannot replay
  messages they would no longer be authorized to receive. This is
  documented in `docs/concurrency-model.md` and `docs/authorization.md`.
- If `redb` ever goes unmaintained, the migration target is most
  likely `sled` (assuming its situation stabilises) or a hand-
  rolled append-only log plus a segment-rotation compactor. The
  surface area is contained to a single module.
