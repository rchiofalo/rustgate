# rustgate-asterix

ASTERIX (Eurocontrol surveillance data exchange) binary codec.

## Role in the workspace

`rustgate-asterix` is a pure decode/encode library for the Eurocontrol
ASTERIX wire format used by air-traffic-control and surveillance systems
(primary radar, secondary radar, ADS-B, multilateration, fused trackers,
counter-UAS sensors). It deliberately depends on nothing else in the
workspace — only `bytes` and `thiserror` — so it can be reused outside
rustgate without dragging in transport / routing concerns. The
integration layer that maps decoded tracks into
`rustgate_core::message::RoutableMessage` is intentionally elsewhere
(future PR per issue #847).

## Public API surface

- `cat062::decode_cat062` / `cat062::Cat062Track` — CAT-062 ("SDPS Track
  Messages") decoder; system-track updates from Surveillance Data
  Processing Systems and counter-UAS radar trackers
- `cat062::{Mode3aCode, ModeCCode, TrackStatus, Cat062Error}` — typed
  field views and a `thiserror`-derived failure surface
- `cat021::decode_cat021` / `cat021::encode_cat021` /
  `cat021::encode_cat021_into` / `cat021::Cat021Report` — CAT-021
  ("ADS-B Reports") bidirectional codec for Mode-S Extended Squitter
  broadcasts; shipped with both directions because the ADS-B path needs
  forwarding-with-modification
- `cat021::{Cat021Error, Cat021EncodeError}` — directional error types
- `cat048::decode_cat048` / `cat048::Cat048Report` /
  `cat048::PolarPosition` / `cat048::Cat048Error` — CAT-048
  ("Monoradar Target Reports") decoder for interrogated Mode-S / SSR
  responses from ground primary / secondary radars

## Feature flags

_None._

## Topology / deployment notes

Spec versions: implements the wire format and Field Reference Numbers
(FRNs) defined by Eurocontrol SUR.ET1.ST05.2000-STD-12-01 Edition 1.20
(March 2017) for CAT-062, with matching edition pins for CAT-021 and
CAT-048 documented inline. The header structure (CAT byte, 16-bit
big-endian length, FSPEC bitmap per record) is invariant across ASTERIX
categories per Eurocontrol "Part 1: Generic ASTERIX Concept", so the
framing code is straightforward to lift if a later PR adds CAT-001/002,
CAT-034 (radar service), or CAT-150 (mil track). Encoder direction for
CAT-062 and CAT-048 is deliberately absent — production rustgate ingests
those categories rather than synthesising them, so a receive-only codec
halves the surface area.

## Where to look first

- `crates/rustgate-asterix/src/cat062.rs` — the CAT-062 decoder and the
  invariant header/FSPEC parsing pattern that other categories reuse
- `crates/rustgate-asterix/src/lib.rs` — module map and the per-category
  scope notes (what is and is not in scope, with spec references)
