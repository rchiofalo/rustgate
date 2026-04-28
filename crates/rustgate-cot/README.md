# rustgate-cot

Cursor-on-Target (CoT) XML parser and message builder for rustgate.

## Role in the workspace

`rustgate-cot` is the workspace's CoT XML codec. It depends only on
[rustgate-core](../rustgate-core/README.md) and is consumed by
[rustgate-transport](../rustgate-transport/README.md),
[rustgate-nats](../rustgate-nats/README.md), and
[rustgate-websocket](../rustgate-websocket/README.md) to translate inbound
TAK XML into the workspace's internal `RoutableMessage` envelope. The parser
is the trust boundary for any payload whose declared content-type is CoT.

## Public API surface

- `parse(&[u8]) -> Result<CotEvent, ParseError>` — entry point that slices a
  CoT XML payload into the typed `CotEvent`
- `CotEvent` — parsed event with `uid`, `event_type`, `destination`,
  `message_type`, `position`, `ttl`, and `source_group`
- `CotDestination` — `Broadcast | Callsign(String) | Group(String)` extracted
  from `<dest callsign=...>` / `<dest group=...>`
- `Position` — geographic point with WGS-84 lat/lon range checks
- `MessageBuilder` — stateful builder that turns raw payload bytes plus the
  sender `Identity` into a `RoutableMessage`, caching the session group from
  the first position event so chat events without `<__group/>` still route
- `is_sa_event`, `sa_affiliation`, `SaAffiliation` — Situational-Awareness
  atom classifiers covering the 11 MITRE MP090284 Appendix A codes
- `how_origin`, `how_is_spec_conformant`, `HowOrigin` — `<event how>` taxonomy
- `auto_upgrade_sa_version`, `classify_legacy_sa_version`, `OnSaAutoUpgraded`,
  `CURRENT_SA_VERSION` — byte-level rewrite of legacy `<event version=...>`
  attributes to the canonical `2.0` form, with a metrics callback hook
- `delta::{DeltaEncoder, DeltaDecoder, DeltaError}` — per-UID delta
  compression with epsilon suppression for position-update-heavy traffic
- `mask::MaskError` — error type for the obligation-side payload masking path

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `fuzz` | `arbitrary::Arbitrary` derives for fuzz harnesses; activates the matching `rustgate-core/fuzz` feature | No |

## Topology / deployment notes

The parser uses `quick-xml` in streaming mode and does not resolve external
entities or process DTD declarations, so XXE is structurally impossible by
construction. The version-attribute rewrite is byte-level (not a parse +
re-serialize round-trip) so dedup caches that key on byte identity are not
churned by the upgrade path.

## Where to look first

- `crates/rustgate-cot/src/lib.rs` — `parse`, `MessageBuilder`, and the
  legacy-version auto-upgrade
- `crates/rustgate-cot/src/delta.rs` — per-UID delta encoder used when
  `--cot-delta-encoding` is enabled on the server
