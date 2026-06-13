# Federation peer-certificate pinning (SEC-1)

*Design note — June 2026. Tracks the fix for SEC-1 (audit finding,
`audit/RUSTGATE-ANALYSIS.md` §6) and GitHub issue #1544.*

## Problem

Outbound federation connections validate the peer's certificate **chain**
to the federation CA, but never bind a connection to a **specific peer
identity**. `PeerConfig::trust_cert_cn` (`config.rs:354`) exists for exactly
this purpose but is wired nowhere — every connector is constructed with
`trust_cert_cn: None`, and the connector extracts the peer's cert CN for
*logging only* (`connector.rs:364`), never comparing it.

Consequence: **any holder of a valid federation-CA-issued certificate can
impersonate any peer.** Another peer, a compromised CA-sharing client, or a
mis-issued cert can stand up a server at a peer's address — or redirect one
via DNS / BGP / service-discovery poisoning — and be accepted as that peer,
then receive every message routed to the impersonated peer's groups.

Compounding factors (not fixed here, noted for the threat model):
- Peer addresses are frequently **IP literals**, for which rustls hostname
  verification is a no-op (and federation deliberately tolerates CN/SAN
  mismatch via `NoHostnameVerifier`).
- **Dynamic discovery** (Consul / DNS-SD / etcd) derives a peer `id` from the
  backend with no post-handshake certificate check.

## Decision

Pin the peer's **certificate CN** to a configured expected value, and refuse
any connection whose presented leaf-cert CN does not match.

**Expected CN resolution (per peer):**

| `peer.trust_cert_cn` | `--federation-require-peer-cn-match` | Pinned CN |
|---|---|---|
| `Some(cn)` | either | `cn` (explicit per-peer pin, **always** enforced) |
| `None` | `true` (strict) | `peer.id` |
| `None` | `false` (default) | *none* — not enforced |

So an explicit `trust_cert_cn` is always honoured (opt-in per peer, the
non-breaking default), and the global strict flag additionally pins every
remaining peer to its configured `id`. CN comparison is case-insensitive
(consistent with the ACL CN-normalization rule).

A mismatch is **fail-closed**: the connection is dropped before it joins the
active pool, an `audit::federation_peer_rejected` event is emitted (CNs
hashed via `hash_cn`), and the peer goes to the normal reconnect/backoff
path (a transient poisoning may clear; a persistent mismatch simply never
connects rather than silently impersonating).

### Enforcement point differs by transport

- **V1 (raw rustls, `rustgate-federation/src/v1/client.rs`):** the connector
  already returns the peer's extracted `Identity` post-handshake. The check
  is a **post-handshake comparison** in `connection_loop` — after
  `connector.connect()` returns `(stream, identity)` and **before**
  `peer.mark_connected()`. The pinned CN is carried per-connection on
  `V1ClientConfig.pinned_peer_cn` (the connector/`ClientConfig` is shared
  across peers, so the per-peer value cannot live in the connector). **This
  note's PR implements V1.**

- **V2 (tonic gRPC, the default protocol):** tonic's `ClientTlsConfig`
  (`manager.rs:621`, `.ca_certificate().identity()`) **does not surface the
  server's leaf certificate** to the client application, so the V1
  post-handshake comparison is not available. V2 enforcement must happen
  **inside the TLS layer** via a custom rustls `ServerCertVerifier` that
  performs chain validation *and* the CN-pin, installed on the channel. This
  requires either feeding tonic a raw `rustls::ClientConfig` (confirm tonic
  0.14 exposes this) or building the channel from a custom connector. **This
  is the tracked follow-up (#1544 part 2);** until it lands, V2 deployments
  must not assume CN pinning is active — surfaced loudly (see below).

### Honesty guard while V2 is pending

Because V2 is the default and is *not* yet enforced, the implementation must
not let an operator believe a V2 peer is pinned when it isn't. While the
follow-up is open, starting with `--federation-require-peer-cn-match` and any
V2 peer logs a prominent `warn!` that CN pinning is V1-only for now. (Once V2
lands, this warning is removed.)

## Alternatives considered

- **Bake the expected CN into the shared connector / `ClientConfig`.**
  Rejected: one connector serves all outbound peers, but the expected CN is
  per-peer. A per-peer `ClientConfig` (with a pinning verifier) is the V2
  mechanism but is wasteful for V1 where the post-handshake identity is
  already in hand.
- **Verifier-based enforcement for V1 too (uniform with V2).** Deferred: it
  would mean a per-peer `ClientConfig` rebuild on V1 as well; the
  post-handshake check is simpler, cheaper, and matches the audit's wording
  ("post-handshake before a connection joins the active pool"). The verifier
  built for V2 can later subsume V1 if uniformity is preferred.
- **Default `--federation-require-peer-cn-match` on.** Rejected as the
  default: existing deployments may run peers whose cert CN matches neither
  `trust_cert_cn` (unset) nor `peer.id`. Default off + per-peer
  `trust_cert_cn` opt-in is non-breaking; strict mode is one flag away and
  recommended for new deployments.

## Consequences

- Per-peer `trust_cert_cn` becomes load-bearing (was inert). Setting it now
  rejects impersonators for V1 peers.
- A new global `--federation-require-peer-cn-match` (off by default) pins
  every peer to its `id` when no explicit CN is set.
- V2 remains unpinned until the follow-up; the startup warning prevents a
  false sense of coverage.
- Once V2's verifier lands, document the seam in an ADR (sibling to ADR 0022
  guard / ADR 0023 ingress) and drop the V1-only warning.
