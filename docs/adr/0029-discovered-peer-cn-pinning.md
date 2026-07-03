# ADR 0029: Discovered federation peers are never CN-pinned to their discovery id

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** rchiofalo
- **Related:** #1612 (SEC-1, the trust-model gap this closes), #1619
  (discovery response bounding — the sibling hardening pass on the same
  backends), `resolve_pinned_peer_cn` in
  `crates/rustgate-federation/src/manager.rs`

## Context

Federation supports strict server-certificate CN pinning via the
`--federation-require-peer-cn-match` flag (`require_peer_cn_match` on the
manager). When the flag is on and a peer sets no explicit
`trust_cert_cn`, `resolve_pinned_peer_cn` historically pinned the peer's
server certificate to the peer's configured `id`. For a **static** peer
authored by an operator in a config file this is sound: the id is trusted
operator input.

Peer discovery (Consul, etcd, DNS-SD) synthesizes `PeerConfig`s at
runtime from backend data. The peer `id` for a discovered peer is
attacker-influenceable service metadata — a Consul `ServiceID`, an etcd
key suffix, an mDNS instance name. Whoever can register a service in the
discovery backend chooses that id. Feeding it into the CN pin means the
same actor who nominates the peer also nominates the certificate CN the
connection will trust, which defeats the point of pinning (SEC-1). Worse,
before this change the discovery backends had **no way at all** to carry
a trusted CN into `trust_cert_cn`, so simply refusing the id fallback
would have left every discovered peer permanently unpinnable via
discovery.

## Decision

Two coupled changes in `rustgate-federation`:

1. **Provenance marker.** `PeerConfig` gains a `#[serde(skip)] pub
   discovered: bool` field (default `false`). The three discovery backends
   set it to `true` on every peer they emit; static config peers keep the
   default. Because the field is skipped it never appears on the wire, and
   `deny_unknown_fields` still rejects a stray `discovered` key in a config
   file. `peers_equal` deliberately does **not** compare it, so a peer
   switching between static and discovered sourcing does not churn a live
   connection on hot-reload.

2. **Refuse the id pin for discovered peers.** `resolve_pinned_peer_cn`
   now, when `require_match` is set **and** `peer_config.discovered`,
   returns `None` (chain-only validation) instead of pinning to the id,
   and emits `audit::federation_discovered_peer_unpinned` plus a `warn!`
   so operators see the residual gap. An explicit, non-empty
   `trust_cert_cn` still pins — and each backend can now supply one from
   operator-controlled metadata:
   - **Consul:** the `rustgate-trust-cn` `ServiceMeta` entry.
   - **etcd:** a `trust-cn=<CN>` token appended to the bare `host:port`
     value, or `trust_cert_cn` in the JSON `PeerConfig` form.
   - **DNS-SD:** a `trust_cn=<CN>` TXT record.

   Static peers are unaffected: they keep the id fallback under
   `require_match`.

## Alternatives considered

- **Keep pinning discovered peers to their id.** Rejected: the id is
  attacker-influenced, so the pin adds no security over chain-only
  validation while giving a false sense of assurance.
- **Refuse the id pin but add no metadata channel.** Rejected: this
  leaves discovered peers permanently unpinnable via discovery, forcing
  operators back to static config and undermining the discovery feature
  for anyone who runs with `require_peer_cn_match`.
- **Fail the connection (fail-closed) when a discovered peer cannot be
  pinned under `require_match`.** Rejected for now: it would break every
  existing discovery deployment that runs with the flag on the moment they
  upgrade, with no warm-up. Chain validation (the federation CA) still
  applies, so the connection is not unauthenticated — it is merely not
  CN-pinned. The audit event gives operators the signal to add metadata
  pins; a future ADR could tighten this to fail-closed behind an opt-in
  once metadata pinning is widely adopted.

## Consequences

Running with `--federation-require-peer-cn-match` no longer silently pins
discovered peers to attacker-influenced ids. Operators who want a
discovered peer pinned must publish a trusted CN through their discovery
backend's metadata channel; until they do, the peer connects with
chain-only validation and each such peer produces one
`federation.discovered_peer_unpinned` audit record per pin-resolution.

The `discovered` marker is code-internal and must be set by any future
`PeerConfig` producer that is not a static config file. Any new discovery
backend must set `discovered = true` and should honor the same
`trust_cn`-style metadata convention. The decision is reversible: removing
the `discovered` gate restores the prior (insecure) behavior, but the
metadata channels would remain useful regardless.
