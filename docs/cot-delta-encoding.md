# CoT Per-UID Delta Encoding

## Motivation

Most Cursor-on-Target (CoT) event streams carry a small number of long-lived
track UIDs that repeatedly emit position updates. A typical stream looks like:

- `uid="ANDROID-123"` pings every 2 seconds
- `version`, `type`, `how` are fixed for the lifetime of the track
- `time`, `start`, `stale` advance monotonically
- `<point>` moves by meters or tens of meters
- `<detail>` is often identical between updates (the same callsign, group, and
  status block)

Forwarding the full `<event>` on every ping wastes bandwidth on the
server-to-client fan-out path, especially on satellite, cellular, or
tactical links where uplink capacity is scarce. Per-UID delta encoding
keeps a small per-writer cache of the last-sent state and emits only the
fields that actually changed.

## When to use it

Delta encoding is **opt-in**. Enable it on deployments where:

- Clients run on bandwidth-constrained links (satcom, cellular, mesh).
- The dominant traffic shape is repeating CoT position updates with
  mostly-stable metadata.
- Downstream tooling either understands the `<delta>` wrapper or runs a
  rustgate-aware client library that reconstructs full events.

Leave it disabled when:

- Clients speak protobuf framing (the feature applies only to XML sessions
  and protobuf sessions always receive full events).
- Event bodies are dominated by unique payloads (e.g. chat, free-form alerts)
  where there is little to diff against.
- Downstream tooling strictly expects the full CoT schema on every frame and
  cannot run a decoder.

## Enabling

Three CLI flags control the feature:

| Flag | Env Var | Default | Notes |
|------|---------|---------|-------|
| `--cot-delta-encoding` | `RUSTGATE_COT_DELTA_ENCODING` | `false` | Master switch |
| `--cot-delta-cache-size` | `RUSTGATE_COT_DELTA_CACHE_SIZE` | `512` | Entries per writer task |
| `--cot-delta-epsilon-meters` | `RUSTGATE_COT_DELTA_EPSILON_METERS` | `1.0` | Suppression threshold |

Example:

```bash
rustgate \
  --cert ... --key ... --ca ... \
  --cot-delta-encoding \
  --cot-delta-cache-size 1024 \
  --cot-delta-epsilon-meters 2.5
```

Or via TOML:

```toml
cot-delta-encoding = true
cot-delta-cache-size = 1024
cot-delta-epsilon-meters = 2.5
```

The encoder is wired only onto writer tasks whose negotiated codec
`protocol_id()` is `"tak-xml"`. Protobuf, length-prefixed, and
line-delimited sessions pass every message through unchanged even when
the flag is enabled.

## Wire format

A delta wraps the changed fields inside a `<delta>` child of the original
`<event>`. The parent `<event>` retains the four immutable attributes so
consumers that only care about the outer tag still see a valid skeleton:

```xml
<event version="2.0" uid="ANDROID-123" type="a-f-G-U-C" how="m-g">
  <delta time="2026-04-08T12:34:56Z" start="2026-04-08T12:34:56Z" stale="2026-04-08T12:35:56Z">
    <point lat="34.123" lon="-118.456" hae="100.5" ce="9.9" le="9.9"/>
  </delta>
</event>
```

Rules:

1. **The outer `<event>` always carries `version`, `uid`, `type`, and
   `how`** (if the original event carried `how`). These four attributes
   identify the CoT track lineage and must not change inside a single
   stream. If any of them *does* change, the encoder treats it as the
   start of a new stream and emits a full event.
2. **`time`, `start`, `stale` live as attributes on the inner `<delta>`
   element** when they differ from the cached prior. In practice every
   update ships at least these three timestamps, so the inner `<delta>`
   is never empty unless suppression fires first.
3. **`<point>` is emitted inside `<delta>` only when it changed.** The
   full self-closing form is used (`<point lat=... lon=... hae=... ce=...
   le=.../>`); partial-point deltas are not emitted because `<point>` is
   cheap and the wire format is simpler to consume when it is either
   absent or complete.
4. **`<detail>` is emitted inside `<delta>` only when its bytes differ.**
   The inner contents are re-serialized verbatim from the current event;
   the encoder does not recurse into `<detail>` children. This keeps the
   encoder protocol-agnostic with respect to application-level schemas
   that mount custom children under `<detail>`.
5. **Unknown attributes and namespaces on `<event>` are not preserved**
   when the encoder emits a full event. The encoder is expected to run on
   well-formed CoT; exotic shapes should be routed around the encoder.

## Semantics

### First sighting

The first event for any `uid` observed by a given writer task is emitted
as a **full** event (unchanged bytes). The cache is then populated with
the parsed snapshot so subsequent updates can diff against it.

New subscribers therefore automatically receive a full event for every
active track they care about — their encoder cache starts empty. There
is no join-latency penalty and no need for periodic keyframes.

### Repeat update

If the parsed event matches the cached snapshot's immutable attributes
(`version`, `type`, `how`), the encoder computes the delta body:

- If **no field changed at all**, the update is suppressed (see below).
- Otherwise, a `<delta>` wrapper is emitted carrying only the changed
  timestamps, point, and/or detail subtree.

The cache is updated to the new snapshot on every delta emit.

### Immutable attribute drift

If `version`, `type`, or `how` change, the encoder refuses to emit a
delta and instead emits the new event in full, replacing the cache
entry. This prevents downstream drift when a device re-registers a track
under the same UID with different metadata.

### Epsilon suppression

When `--cot-delta-epsilon-meters` is greater than zero and the **only**
change between the prior and current event is the point coordinates
(detail subtree is byte-identical, timestamps aside), the encoder
computes an approximate ground distance using an equirectangular
projection with `R = 6_371_000` m:

```
d ≈ R · √(Δlat² + (cos(lat) · Δlon)²)
```

If that distance is below the configured epsilon **and** `hae`, `ce`,
and `le` are unchanged, the update is suppressed entirely — nothing is
written to the wire. The cache entry is **not** refreshed, so drift
cannot accumulate below the threshold across many suppressed updates.
An epsilon of `0.0` disables suppression; every update ships as either
`Full` or `Delta`.

### Empty delta body

If a repeat event produces an empty delta body (no timestamps to
override, no point change, no detail change), the update is suppressed
regardless of epsilon.

### Cache eviction

The cache is a bounded LRU keyed by `uid` with capacity
`--cot-delta-cache-size`. When the cache is full and a new UID is seen,
the least-recently-used entry is evicted. The next event for an evicted
UID is emitted as a full event because its prior state is no longer
available.

Operators can tune the cache size against the expected working set of
simultaneously-active track UIDs. 512 is a reasonable default for
small-to-medium deployments; increase it if you see the
`rustgate_cot_delta_full_total` counter growing faster than the
`rustgate_cot_delta_delta_total` counter on steady-state workloads
(which suggests cache thrashing).

### Non-CoT payloads

Any payload that fails to parse as CoT (no `<event>` root, no `uid`,
garbage bytes, exceeds the 64 KiB scan window) is passed through as a
full message unchanged. Deltas are never produced for non-CoT traffic,
so enabling the encoder on a mixed stream is safe.

## Observability

Under `--features metrics`, four counters are registered:

| Metric | Meaning |
|--------|---------|
| `rustgate_cot_delta_full_total` | Events emitted as full (first sighting, eviction, drift, non-CoT) |
| `rustgate_cot_delta_delta_total` | Events emitted as delta |
| `rustgate_cot_delta_suppressed_total` | Events suppressed (empty delta body or sub-epsilon position drift) |
| `rustgate_cot_delta_bytes_saved_total` | Cumulative `full_len - delta_len` across all emitted deltas |

Useful derived queries:

- **Compression ratio**:
  `rate(rustgate_cot_delta_bytes_saved_total[5m])` divided by the full-body
  byte rate (approximated from `rustgate_messages_routed_total` multiplied
  by average event size).
- **Delta effectiveness**:
  `rate(rustgate_cot_delta_delta_total[5m]) / (rate(rustgate_cot_delta_full_total[5m]) + rate(rustgate_cot_delta_delta_total[5m]) + rate(rustgate_cot_delta_suppressed_total[5m]))`.
- **Cache thrashing**: if `rustgate_cot_delta_full_total` grows steadily
  on a workload where the same UIDs repeat, the cache is probably
  undersized; increase `--cot-delta-cache-size`.
- **Over-suppression**: if `rustgate_cot_delta_suppressed_total`
  dominates and clients complain about missing position updates,
  decrease `--cot-delta-epsilon-meters`.

## Decoding

The `rustgate_cot::delta` module exposes a `DeltaDecoder` that mirrors
the encoder: it keeps a per-source LRU cache keyed by `uid` and merges
a received `<delta>` event with the cached prior snapshot to
reconstruct the full event. The decoder is provided for round-trip
testing and for Rust client libraries that want to consume the wire
format directly. Clients that cannot run the decoder should not enable
delta encoding on the server.

## Limitations and future work

- The encoder only diffs at the attribute and subtree level. A per-child
  diff inside `<detail>` (e.g. only the `<track>` child moved) is not
  implemented and would require agreeing on a child-identification
  scheme with downstream tooling.
- The suppression epsilon is a single global value. Per-track or
  per-type thresholds would be useful for mixing vehicle tracks
  (coarse) with drone tracks (fine), but the current implementation
  uses one knob for simplicity.
- The encoder ignores XML comments, processing instructions, and
  unusual namespacing on the outer `<event>` because CoT in the wild
  almost never uses them. Streams that do carry such constructs will
  lose them in the emitted delta (but will not be silently dropped —
  they will simply be emitted without the extra annotations on the
  outer shell).
