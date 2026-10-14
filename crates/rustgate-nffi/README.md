# rustgate-nffi

NFFI (NATO Friendly Force Information, STANAG 5527) Blue Force
Tracking XML codec. NFFI is the standardised XML schema family
adopted across NATO command-and-control suites (Systematic
SitaWare, Norwegian NORCCIS, MIP-compliant national systems) for
exchanging friendly-force position, identification, and
operational status across coalition boundaries.

## What this crate does

- Decodes an NFFI XML payload (`&[u8]`) into a typed
  `NffiDocument` carrying one or more `NffiTrack` records.
- Encodes a typed `NffiDocument` back into wire-format bytes
  with same-codec lossless round-trip on the strict-subset
  fields and verbatim preservation of unrecognised siblings via
  `UnknownElement`.
- Implements the canonical `rustgate_core::entity::EntityCodec`
  trait so the workspace router can fan an entity out across
  NFFI alongside CoT XML, MAVLink, ASTERIX, STANAG-4586,
  Meshtastic, VMF, SAPIENT, DIS, and Link 16.
- Decodes the 15-character APP-6A Symbol Identification Code
  carried under `<identificationData><sidc>` into typed
  affiliation / battle-dimension / status fields, and exposes
  the dispatch from APP-6A battle dimension to canonical
  `EntityKind`.

## Wire form (STANAG 5527 v2.0)

```
<nffi xmlns="urn:nato:stanag:5527:nffi:2.0:1">
  <track>
    <positionalData>
      <wgs84Position lat="38.0" lon="-77.0" alt="100"/>
      <kinematics speed="12.5" course="270" accuracy="5"/>
      <datetime>2026-05-08T12:00:00Z</datetime>
    </positionalData>
    <identificationData>
      <sidc>SFGPUCI-----C--</sidc>
      <unitName>Alpha-1</unitName>
      <nationality>USA</nationality>
    </identificationData>
    <operStatusData>...</operStatusData>  <!-- carried opaque -->
  </track>
</nffi>
```

The `xmlns` attribute is preserved verbatim on decode (or
omitted if the source did not carry one) so a same-codec
round-trip emits the same root namespace declaration the
source supplied. Coordinate fields ride as IEEE-754 doubles —
same-codec round-trip is bit-exact for every wire-format scalar.

## APP-6A SIDC parsing

The 15-character SIDC body decomposes into:

| Position | Meaning              | Notes                                        |
|----------|----------------------|----------------------------------------------|
| 1        | Coding scheme        | `S` = warfighting (the only scheme in scope) |
| 2        | Affiliation          | `F` friend, `H` hostile, `N` neutral, `U` unknown, etc. |
| 3        | Battle dimension     | `A` air, `G` ground, `S`/`U` sea, …          |
| 4        | Status               | `P` present, `A` anticipated/planned         |
| 5..10    | Function ID          | Codec-opaque; preserved verbatim on the entity |
| 11..15   | Reserved             | Often `-----`                                |

The codec's `Entity::kind` dispatch consumes positions 1-4 only;
positions 5-15 ride opaque on `Entity::mil_std_2525_sidc` so a
downstream consumer with a full APP-6A taxonomy can decode them
without help from this crate.

## MVP scope

| Feature                                     | Status                 |
|---------------------------------------------|------------------------|
| `<nffi>` root + xmlns preservation          | Decoded + encoded      |
| `<track>` (multiple per document)           | Decoded + encoded      |
| `<wgs84Position lat lon alt>`               | Decoded + encoded      |
| `<kinematics speed course accuracy>`        | Decoded + encoded      |
| `<datetime>` (ISO-8601 body)                | Decoded + encoded      |
| `<sidc>` (15-char APP-6A)                   | Typed parse + encoded  |
| `<unitName>`, `<nationality>`               | Decoded + encoded      |
| `<operStatusData>` and other unknown siblings | Carried opaque (round-trippable) |
| Cross-protocol fan-out (`EntityCodec`)      | First track only       |

## Out of scope (deferred to follow-up issues)

- **Transport binding.** NFFI rides over DDS topics, SOAP over
  HTTP, or REST endpoints depending on the deployment. This
  crate consumes / emits the XML payload only; the listener
  wiring lands in a follow-up PR.
- **`<operStatusData>` typed decode.** Operational-status
  fields (fuel, ammunition, casualty count, mission state)
  round-trip verbatim through `UnknownElement`. A typed
  schema is deferred so the MVP wire shape stays small.
- **STANAG 5527 XSD validation.** The parser accepts
  well-formed XML but does not validate against the upstream
  XSD — strict validation belongs in a policy layer.
- **Multi-track entity fan-out.** `EntityCodec::to_entity`
  surfaces the first `<track>` in a multi-track document; a
  router-side iterate-all-tracks hook lands in a follow-up.

## Companion protocols

Tracked under issue #869 — autonomous-sensor / coalition-BFT
wire formats. Sister crates: SAPIENT (BSI Flex 335) ships in
`rustgate-sapient`. OGC SensorThings (REST + MQTT) ships in
a parallel PR that closes the issue.

## License

AGPL-3.0-only, same as the rest of the workspace. See the workspace `LICENSE`
and `NOTICE`.
