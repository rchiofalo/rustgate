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
  across peers, so the per-peer value cannot live in the connector).
  **Implemented** (first shipped V1-only, #1564).

- **V2 (tonic gRPC, the default protocol):** tonic's `ClientTlsConfig`
  (`.ca_certificate().identity()`) **does not surface the server's leaf
  certificate** to the client application, so the V1 post-handshake comparison
  is not available. V2 enforcement therefore happens **inside the TLS layer**:
  `connector::PinnedServerCertVerifier` wraps the CA-only `NoHostnameVerifier`
  (full chain validation, hostname tolerated) and adds the CN-pin, returning a
  rustls `ApplicationVerificationFailure` on mismatch so the gRPC channel never
  opens. It is installed via tonic 0.14's public
  `Endpoint::tls_config_with_verifier(tls_config, verifier)` — confirmed to
  accept an `Arc<dyn rustls::client::danger::ServerCertVerifier>` — so no
  custom connector is needed. The verifier is built per-peer by the manager
  (`build_pinned_server_cert_verifier`) from the federation CA PEM + the
  resolved CN, and carried on `V2ClientConfig.pin_verifier`. When no pin
  applies the channel keeps tonic's default verifier. **Implemented** (this
  PR) — the same `--federation-require-peer-cn-match` flag and per-peer
  `trust_cert_cn` drive both transports.

## Alternatives considered

- **Bake the expected CN into the shared connector / `ClientConfig`.**
  Rejected: one connector serves all outbound peers, but the expected CN is
  per-peer. A per-peer `ClientConfig` (with a pinning verifier) is the V2
  mechanism but is wasteful for V1 where the post-handshake identity is
  already in hand.
- **Verifier-based enforcement for V1 too (uniform with V2).** Not adopted:
  it would mean a per-peer `ClientConfig` rebuild on V1 as well; the V1
  post-handshake check is simpler, cheaper, and matches the audit's wording
  ("post-handshake before a connection joins the active pool"). The two
  transports share the CN-resolution logic (`resolve_pinned_peer_cn`) and the
  CA-only chain validator (`NoHostnameVerifier`), so the duplication is small;
  the V2 verifier could later subsume V1 if uniformity is preferred.
- **Default `--federation-require-peer-cn-match` on.** Rejected as the
  default: existing deployments may run peers whose cert CN matches neither
  `trust_cert_cn` (unset) nor `peer.id`. Default off + per-peer
  `trust_cert_cn` opt-in is non-breaking; strict mode is one flag away and
  recommended for new deployments.

## Consequences

- Per-peer `trust_cert_cn` becomes load-bearing (was inert). Setting it now
  rejects impersonators on **both** V1 and V2 peers.
- A new global `--federation-require-peer-cn-match` (off by default) pins
  every peer to its `id` when no explicit CN is set, across both transports.
- SEC-1 is fully closed: chain validation no longer stands alone — a
  connection is bound to a specific peer identity on V1 and V2 alike.
- V1 shipped first (#1564); V2 followed in the same `[Unreleased]` cycle. The
  short-lived "V2 not yet pinned" startup warning from the V1-only step is
  removed now that V2 is enforced.
