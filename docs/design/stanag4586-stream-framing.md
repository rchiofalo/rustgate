# Design note: STANAG 4586 stream framing via a per-deployment `StreamProfile` (#1492)

- **Status:** Decision resolved (security-first) — feature-flagged scaffold
  only, no server wiring. Companion to
  [`tactical-stream-ingress.md`](tactical-stream-ingress.md) (#1473) and
  ADR [`0023-tactical-codec-ingress-seam.md`](../adr/0023-tactical-codec-ingress-seam.md),
  whose **D7** deferred stream-framed STANAG 4586 for exactly the reason
  resolved here.
- **Date:** 2026-07-03
- **Issue:** #1492
- **Author:** rchiofalo

> **Inherited philosophy.** Every security decision from the datagram and
> stream ingress notes carries over verbatim — *fail-closed* admission,
> *default-deny*, a *single audited path*, *validate-and-drop with the
> router's own codec* (no parser differential, ADR 0023 D2), *wire
> identifiers never authorize* (D3), *bound the frame before allocating*
> (D5). This note resolves only what is new about the STANAG 4586 stream
> shape: **who supplies the frame delimitation parameters when the wire
> layout is NATO-restricted and not knowable at compile time.**

## Problem

`rustgate-stanag4586` ships a per-message `decode(&[u8])` /
`Stanag4586EntityCodec` that assumes the caller has *already* delimited
exactly one frame. To accept STANAG 4586 over a TCP **stream**, the
ingress layer must first delimit the byte stream into frames. Two facts
make that hard:

1. **STANAG 4586 frames are message-type-dependent in size and carry no
   self-describing, universally-agreed length prefix at a fixed offset.**
   The Edition 2 message wrapper that would let a generic parser find the
   body length is defined in the **NATO-restricted** specification, which
   is not publicly distributable and is not present in this repository.
   The crate's own `lib.rs` records this caveat for the payload layout;
   the same caveat applies — more sharply — to the *wrapper* header.

2. **A wrong framing guess on an unauthenticated, unencrypted TCP port is
   a security defect, not a cosmetic one.** ADR 0023 D2 forbids a parser
   differential between the edge and the router; a guessed universal
   wrapper parse would be exactly that. The length-collision the issue
   describes (a 32-byte message body whose leading bytes alias a 48-byte
   vehicle-position frame) is the concrete failure: without an
   operator-supplied layout, a generic delimiter cannot tell them apart
   and would mis-frame one as the other.

Shipping a guessed universal Edition-2 wrapper parser is therefore
**off the table** — it cannot be verified against the controlled spec in
this session, and a wrong guess reaches a live unauthenticated socket.

## Decision

**Frame delimitation for STANAG 4586 is driven by a per-deployment
`StreamProfile` the operator supplies from their own controlled
Interface Control Document (ICD), not guessed from the wire.** This is
the "documented deployment profile" half of the issue's own suggested
fix, made the design rather than a fallback.

Concretely:

- A `StreamProfile` names the four parameters a header-length delimiter
  needs — `header_len`, `length_field_offset`, `length_field_size`
  (1/2/4 bytes), and `big_endian` — plus a `max_frame_size` bound
  (defaulting to and clamped by `rustgate_core::constants::MAX_FRAME_SIZE`).
  These are precisely the parameters
  `rustgate_transport::HeaderLengthCodec` already consumes. The decoder
  reproduces that delimiter's **exact bounded semantics**
  (bound-before-reserve, length-field-must-fit-in-header, split header +
  body) rather than taking a `rustgate-transport` dependency from a leaf
  codec crate — the one deliberate deviation is that the profile also
  carries a `big_endian` flag, because `HeaderLengthCodec` is big-endian
  only and some vendor ICDs deviate from NATO's standard byte order. The
  scaffold does **not** invent new framing math; the delimit algorithm is
  byte-for-byte the transport delimiter's on the big-endian path, which is
  the same no-parser-differential discipline as D2 applied to framing.

- `Stanag4586StreamDecoder` **fails closed when no profile is
  configured.** With no profile it consumes **zero bytes** and returns a
  typed `Stanag4586StreamError::ProfileRequired` rather than attempting
  any guessed parse. There is no "best effort" default profile — a
  default would be a guess, and a guess is the defect.

- With a profile supplied, the decoder delegates delimitation to the
  existing `HeaderLengthCodec` (which bounds the body length against
  `max_frame_size` **before** reserving any buffer, per D5) and hands each
  delimited frame to the crate's existing per-message decode path
  (`Stanag4586EntityCodec`). The same codec the router uses re-decodes it
  — no parser differential (D2).

- The whole scaffold is behind a new `stream` cargo feature. It is **not
  wired** into `tactical_ingress.rs` or `main.rs`. No `start_stanag4586_tcp`
  ships in this change. A framer whose correctness depends on an
  operator-supplied ICD must not reach a live port until an operator has
  actually supplied and validated a profile against a real device.

### Why not guess the wrapper (alternatives considered)

- **Ship a universal Edition-2 wrapper parse.** Rejected: the wrapper
  layout is NATO-restricted and unverifiable here; a wrong guess is a
  parser differential on an unauthenticated port (the exact class ADR
  0023 D2/D3 forbid).
- **Default to the 48-byte vehicle-position frame as a fixed size.**
  Rejected: it silently mis-frames every other message type and re-creates
  the length-collision the issue reports. Fixed-size framing is a special
  case an operator can still express via a profile whose header carries
  the constant length, but it is not a safe universal default.
- **Derive the length from the decoded body.** Rejected: that is decode-
  before-delimit, which desynchronizes the stream on the first
  unrecognized message and violates the bound-before-allocate rule (D5).

## What this does NOT claim

Stream STANAG 4586 is **not "done."** The `StreamProfile` approach is the
honest resolution of the fork, but it is **unproven against a real device
until an operator supplies a profile from their controlled ICD and
validates it end-to-end.** This change ships the *type*, the *fail-closed
decoder*, and the *decision* — the server wiring
(`start_stanag4586_tcp`), the operator-facing `--stanag4586-*` profile
flags, and the live regression test against a real frame capture are a
deliberate follow-up so no half-verified framer reaches a live socket.
```
