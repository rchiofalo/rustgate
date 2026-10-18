# Defense-Technology Alignment Roadmap (2026–2035)

This is a **living status tracker**, not a work queue. It consolidates the
2–5 year defense-technology alignment horizon catalogued in the
[`#885` tracking umbrella](https://github.com/rchiofalo/rustgate/issues/885)
(Technical Analysis Vol. II, Parts 17–18) and maps each theme to where it
stands on `main` **today**.

Rows here assert what has landed, what is deliberately deferred, and what is
blocked on an upstream dependency. Nothing in this document authorizes new
work: an item appearing in "Tracked / Not Yet Built" is a *pointer* to a
future issue/ADR, not a commitment to build it in a given release. When a
theme moves between tables, update the row and the linked issue in lockstep
(the same discipline the [crate table](https://github.com/rchiofalo/rustgate/blob/main/docs/architecture.md) and
[`README.md`](https://github.com/rchiofalo/rustgate/blob/main/README.md) follow).

Verified against `main` at the time of writing. If a claim below drifts
(a crate is renamed, a flag changes semantics, a sub-issue closes), correct
the row — a status tracker that lies is worse than none.

## Landed

Themes whose foundational scaffolding already exists on `main` — a crate, a
flag, an ADR, or a codec — even where the surrounding capability is still
maturing. "Landed" means the seam is present and load-bearing, not that the
theme is exhaustively complete.

| Part 17/18 theme | Where it lives on `main` | Notes |
|---|---|---|
| 17.5 — Post-quantum crypto timeline (CNSA 2.0) | `--cnsa2` flag (`rustgate-server`) + [ADR 0019](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0019-cnsa2-hybrid-mldsa.md) | `--cnsa2` logs a readiness report; it does **not** change configuration. ML-KEM-1024 is available via `--kx-groups MLKEM1024`, and ML-DSA certificate verification is on in every build ([ADR 0037](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0037-aws-lc-rs-post-quantum-default.md)). Hybrid (composite) certs remain blocked; see "Blocked Upstream". |
| 17.5 — ML-DSA package signing | [ADR 0020](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0020-mavlink-pq-rekey.md), `mavlink-pq` feature (`rustgate-mavlink`) | Package-signature verification (#500) and the MAVLink ML-KEM-768 signing-key rekey path are landed; TLS-cert ML-DSA is not (below). |
| 17.9 — ABMS / CJADC2 codec breadth | 9 tactical codec crates + `rustgate-codec-schema` | `rustgate-{mavlink,meshtastic,vmf,sapient,nffi,dis,link16,stanag4586,asterix}`. Schema-first codec design is [ADR 0018](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0018-schema-first-codec-design.md); the ingress seam is [ADR 0023](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0023-tactical-codec-ingress-seam.md). OMS/UCI and JFN wire formats specifically are not yet mapped. |
| 17.10 — Replicator short-lived certs / auto-revocation | [ADR 0025](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0025-revocation-lifecycle.md) revocation lifecycle, `--crl-refresh-interval` | All three pieces of ADR 0025 have landed: live CRL refresh without restart, fail-closed staleness handling (`--crl-fail-closed`), and active disconnect of sessions whose certificate is revoked or expires (`--revocation-sweep-interval`). |
| 17.11 — Space domain awareness (entity model) | `rustgate-core::entity` protocol-agnostic entity model | The canonical entity representation that a future orbital/TLE type would extend already exists; an orbital element type is not built. |
| 18.1 — Palantir Foundry integration | `rustgate-foundry` | Partner/platform integration crate present. |
| 18.2 — Anduril Lattice integration | `rustgate-lattice` | gRPC/protobuf-over-mTLS partner integration crate present. |
| 18.3 — RTI Connext DDS | `rustgate-dds` | DDS/RTPS integration crate present. |
| 18.4 — European NATO C2 (NFFI) | `rustgate-nffi` + live NFFI/STANAG-5527 TCP ingress | Friendly-force-information ingest landed; the broader SitaWare/TORCH-X/TACNET surface is not a single crate. |
| 18.5 — TAK ecosystem (protobuf-first) | `TakProtobuf` framing ([ADR 0021](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0021-clean-room-tak-interop.md)), `rustgate-meshtastic` | Clean-room TAK protobuf interop and the Meshtastic codec are present. |
| 18.6 — Small UAS (STANAG 4586) | `rustgate-stanag4586` + live STANAG 4586 UDP ingress | LOI 2-3 telemetry ingest landed on the datagram path; TCP-stream STANAG 4586 is deferred on a per-deployment framing decision. |
| Cross-domain guard (17.3 / 17.4 classified data) | `rustgate-guard` + [ADR 0022](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0022-cross-domain-guard-egress-seam.md), [ADR 0024](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0024-guard-fail-closed.md) | Fail-closed egress guard seam present. Not a Part-17 item by name, but the mechanism the classified-EW / kill-chain-provenance themes lean on. |

## Tracked / Not Yet Built

Genuinely-unimplemented themes. Each is a candidate for its own issue and
(where it touches the wire or the trust boundary) its own ADR. Absence of a
row in "Landed" is deliberate — do **not** treat a bullet here as scoped
work for the current release.

| Part 17 theme | Status | Pointer |
|---|---|---|
| 17.7 — Neuromorphic edge (`FramingStrategy::EventStream`) | Not built. `FramingStrategy` on `main` is exactly `LengthPrefixed`, `XmlStream`, `LineDelimited`, `TakProtobuf`, `Mavlink` — there is **no** `EventStream` variant. | No issue yet. A new framing variant + codec, ADR-worthy. |
| 17.8 — Hypersonic "flash override" priority lane | Not built. No priority level that preempts backpressure controls exists; the two-tier backpressure gate is uniform across messages. | No issue yet. Touches the transport backpressure design; ADR-worthy. |
| 17.2 — Adaptive federation timeouts (LEO satellite mesh) | Not built. Federation heartbeat/timeout values are the fixed `FEDERATION_HEARTBEAT_INTERVAL` / `FEDERATION_HEARTBEAT_TIMEOUT` constants; they do not adapt to variable satellite latency. | No dedicated issue yet; folds into the 17.2 LEO-mesh theme. |
| 17.1 — CCA formation-aware routing / leader failover | Not built. | Under the 17.1 CCA theme; no dedicated issue. |
| 17.6 — 6G lock-free session delivery (SPSC ring buffers) | Not built. Session delivery uses bounded `mpsc`; the crossbeam/SPSC path is speculative. | Under the 17.6 theme; no dedicated issue. |
| 17.9 — OMS/UCI + Joint Fires Network codecs | Not built. The 9 tactical codecs do not yet include OMS/UCI or JFN formats. | Under the 17.9 ABMS/CJADC2 theme; would be new codec crates. |
| 17.11 — Orbital entity type (TLE/OMM, CCSDS CDM) | Not built. The entity model is protocol-agnostic but has no orbital-element type. | Under the 17.11 SDA theme; no dedicated issue. |

## Blocked Upstream

Themes whose implementation is gated by a dependency rustgate does not
control. These stay open for tracking; they are not actionable until the
upstream lands.

| Theme | Blocked-by | Sub-issues |
|---|---|---|
| ML-DSA (Dilithium) TLS certificate verification, issuance, and hybrid dual-signature certs | `aws-lc-rs` does not yet expose a stable ML-DSA signature API usable through `rustls`'s cert-verification path. | [#501](https://github.com/rchiofalo/rustgate/issues/501) (transport verification), [#502](https://github.com/rchiofalo/rustgate/issues/502) (enrollment issuance / CRL), [#503](https://github.com/rchiofalo/rustgate/issues/503) (hybrid certs) — all **open**. |
| Full CNSA 2.0 alignment (ML-KEM-1024 + ML-DSA cert enforcement) | Depends on the ML-DSA cert cluster above; the `--cnsa2` flag is scaffolding until it can enforce the real cert requirement. | [#873](https://github.com/rchiofalo/rustgate/issues/873) — **open**. |

## Already-resolved sub-issues

For continuity, sub-issues that spun out of the #885 horizon and have since
**closed** (so a reader does not re-file them):

- [#504](https://github.com/rchiofalo/rustgate/issues/504) — `--cnsa2` CLI flag (the compile-time scaffolding above).
- [#500](https://github.com/rchiofalo/rustgate/issues/500) — ML-DSA package signature verification.
- [#731](https://github.com/rchiofalo/rustgate/issues/731) — MAVLink post-quantum key distribution umbrella.
- [#871](https://github.com/rchiofalo/rustgate/issues/871) — DevSecOps packaging (Iron Bank, Zarf, cATO evidence).
