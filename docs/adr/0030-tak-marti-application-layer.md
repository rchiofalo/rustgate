# ADR 0030: TAK Server application-layer compatibility roadmap and build order

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** rchiofalo
- **Related:** #1455 (TAK Server application-layer compatibility epic),
  #860 (Marti REST surface), #862 (video catalog), #863 (Marti compat shim),
  #1328 (video streams), #1329 (Data Packages store),
  ADR 0021 (clean-room TAK interop — the IP boundary this work sits inside),
  ADR 0018 (schema-first codec design)

> This ADR is a **design note**: it records the roadmap, the
> owner-locked build order, an honest DONE-vs-OPEN inventory, and the
> rationale for the *first* concrete slice (Enterprise Sync). It does
> not itself decide any new protocol shape beyond that first slice; the
> deeper Mission API / CoT-persistence pieces get their own ADRs when
> they are actually built.

## Context

rustgate already speaks the TAK **transport** layer — the v1 `0xBF`
protobuf handshake, CoT XML framing, and TAK Server v2 federation. The
2026 audit flagged the **application layer** (the Marti REST surface an
ATAK/WinTAK/iTAK client drives *over* that transport) as the single
largest remaining competitive gap for a drop-in TAK Server replacement.
Epic #1455 tracks closing it.

That application layer is externally defined by TAK Server, whose
reference implementations are GPLv3. **ADR 0021 already set the IP
boundary:** rustgate re-expresses the *protocol facts* (endpoint paths,
query params, JSON envelope field tuples) clean-room from public
protocol knowledge and observed wire behavior, and never copies TAK
Server / FreeTAKServer / taky *source expression*. Everything in this
roadmap inherits that constraint — it is non-negotiable and predates
this ADR.

The application layer is not one feature but four, with a hard
dependency ordering: several of them need a **persistent, replayable
store** that does not exist yet. Deciding the build order *before*
writing more endpoints prevents the trap of shipping a Mission API
whose data evaporates on restart.

### DONE vs OPEN inventory (audited 2026-07-03)

**Done — already in the tree:**

- **TAK v1 `0xBF` protobuf negotiation**, wired as a first-class
  transport. `negotiate_tak_protocol` in
  `crates/rustgate-server/src/session.rs` (the `Framing::TakNegotiate`
  path) peeks the client's first byte, completes the `TakControl`
  handshake on `0xBF`, and falls back to XML otherwise; selected via the
  `--framing tak-negotiate` CLI flag. #1455's prose implies this still
  needs wiring — it does not; that sub-box is complete.
- **Marti REST shim** — `crates/rustgate-admin/src/marti_compat.rs`
  exposes five endpoints (`POST /Marti/api/tls/signClient`,
  `GET /Marti/api/missions`, `GET /Marti/api/contacts/all`,
  `GET /Marti/api/video`, `GET /Marti/api/tls/config`) as thin adapters
  over existing subsystems, behind the `marti-compat` feature.
- **Data Package store** — `rustgate-missions::PackageStore`: a
  content-addressed (SHA-256), HMAC-sidecar-tagged, capacity-capped ZIP
  store with `upload` / `download` / `list` / `delete` / `metadata`.

**Open — not yet built:**

- **Enterprise Sync** (`/Marti/sync/*`) — the ATAK data-package
  search / fetch / upload surface. *This ADR's first slice.*
- **Mission API / data-sync** (`/Marti/mission/*`) — named missions,
  CoT change-feeds, subscriber deltas. Needs a replayable store.
- **CoT persistence + historical query** — durable CoT event log with
  time/bbox query. The prerequisite the epic itself flags first.
- **Marti contacts/groups roster** beyond the current connected-client
  snapshot (persistent group membership, roles).

## Decision

**Build the TAK application layer in the owner-locked order
`persistent store → CoT persistence → Enterprise Sync → Mission API`,
under the ADR 0021 clean-room boundary. Ship Enterprise Sync
(`/Marti/sync/*`) *first among the endpoint work* because — uniquely —
it needs no new persistence: the content-addressed
`rustgate-missions::PackageStore` already satisfies it.**

### The first slice — Enterprise Sync

Three routes are added to `route()` in `marti_compat.rs`, all behind the
existing `deny_unless_authorized` bearer gate and the `marti-compat`
feature. Each is a pure adapter over `PackageStore`; **no new crate, no
new store, no new persistence layer.**

| Route | Delegates to | Notes |
|-------|--------------|-------|
| `GET /Marti/sync/search` | `PackageStore::list()` | Re-emitted in the Marti sync `results` envelope (`{ resultCount, results: [...] }`). Empty `200` — never `500` — when no store is wired or listing fails, so a polling client sees "nothing yet", not an error to retry-spam. |
| `GET /Marti/sync/content?hash={h}` | `PackageStore::download(hash)` | Returns the raw ZIP body with `Content-Type: application/zip`. Missing `hash` → `400`; malformed hash → `400` (via `download`'s `is_valid_hex_hash`); well-formed-but-absent → `404`. |
| `POST /Marti/sync/missionupload` **or** `/Marti/sync/upload` | `PackageStore::upload()` | Accepts `multipart/form-data` (ZIP in the `assetfile` field, `file` as fallback) or a raw `application/zip` body. Returns the stored content hash. Both path spellings are accepted (see below). |

Multipart slicing reuses `rustgate-missions`'
`extract_boundary` / `extract_multipart_field` / `extract_multipart_filename`
rather than adding a new parser (the same helpers the native
`/api/packages` upload uses).

### Best-effort, pending live-client validation

The exact TAK Server wire shape — the `hash` vs `uid` query-param name,
the `results` JSON envelope keys, whether an ATAK build posts to
`missionupload` or `upload`, and the multipart field name for the ZIP —
is defined by TAK Server and must be re-expressed clean-room per ADR
0021 from protocol knowledge and observed behavior only, **never copied
from GPL TAK Server / FreeTAKServer source.** This environment can
round-trip the routes against rustgate's own tests but cannot verify
true ATAK-client interop. Therefore these routes are explicitly
**best-effort**:

- Both upload path spellings (`missionupload`, `upload`) are accepted so
  a real client's `POST` is never silently `404`'d on a spelling guess.
- The search envelope ships a **stable superset** of the fields ATAK is
  known to read (`UID`, `Name`, `Hash`, `SubmissionUser`, `Size`,
  `MIMEType`, …); an extra key is harmless to a tolerant client, a
  missing one is not.
- Everything stays behind `marti-compat` + `deny_unless_authorized`, so
  the scaffold adds **no unauthenticated exposure**.

**Acceptance gate for promoting Enterprise Sync from *best-effort* to
*supported*:** a successful search / fetch / upload round-trip against a
real ATAK client, captured as our own fixture per ADR 0021 §1. Until
that gate is met, these routes remain "Proposed" behavior.

## Alternatives considered

- **Mission API first.** #1455 calls the Mission API the single largest
  gap, so it is tempting to lead with it. Rejected: the Mission API
  needs the durable, replayable CoT store that does not exist yet;
  leading with it would either block on that store or ship an in-memory
  fake that loses missions on restart. Enterprise Sync needs no such
  store, so it is the correct first slice.
- **A new `rustgate-sync` crate.** Rejected: Enterprise Sync is a pure
  adapter over an existing store. A new crate would add surface with no
  new behavior. If the Mission API later needs its own persistence, that
  is where a new crate earns its place — not here.
- **Guess a single upload path spelling.** Rejected: a wrong guess
  fails real ATAK sync silently (`404`). Accepting both spellings costs
  one extra match arm and removes the guess.
- **Read FreeTAKServer/taky source to pin the exact envelope.** Rejected
  outright — prohibited as a *code* source by ADR 0021 §2. The protocol
  facts come from public documentation and our own observed wire
  behavior; the implementations may be read only to understand the
  public protocol, never transcribed.

## Consequences

**Enables.** ATAK/WinTAK/iTAK clients can search, fetch, and upload
mission data packages against a rustgate admin server with the
`marti-compat` feature — the first application-layer TAK capability
beyond the read-only shim. The build order is written down, so later
work on CoT persistence and the Mission API has a stated prerequisite
chain rather than an ad-hoc pick from the tracker.

**Constrains.** The `/Marti/sync/*` routes carry a documented
"best-effort, pending live-client validation" caveat until the ATAK
acceptance gate is met; that caveat lives in the `marti_compat.rs`
module docs and here. Any change to the sync envelope or param names
must state its public protocol source in the PR per ADR 0021 §5.

**Not yet decided.** CoT persistence, historical query, the Mission API
data-sync semantics, and the persistent contacts/groups roster are out
of scope for this slice and will get their own ADRs when built — each
gated on the persistent/replayable store this roadmap places first.
