# Architecture Decision Records

This directory holds the project's architecture decision records (ADRs).
An ADR captures one architecturally significant decision, the
alternatives that were weighed against it, and the consequences the
project now lives with as a result.

We use the slim Michael Nygard format. Each ADR is a short markdown
file numbered with a four-digit prefix and a kebab-case slug
(`0001-parking-lot-mutexes-for-sync-paths.md`). Status, context,
decision, and consequences are spelled out so a new contributor can
read the ADR cold and understand why the workspace looks the way it
does.

## Status legend

- **Accepted** — the decision is in force and the codebase reflects it.
- **Proposed** — under discussion, not yet implemented.
- **Superseded by ADR XXXX** — the decision was reversed or replaced;
  the body remains for historical context, with a forward link to the
  replacement.
- **Deprecated** — no longer in force; the codebase is in the middle of
  migrating away from this decision.
- **Documented** — the decision shipped a long time ago without a
  written rationale; this ADR records the current state honestly,
  including the parts of the rationale that are unclear from the source.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0000](0000-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0001](0001-parking-lot-mutexes-for-sync-paths.md) | `parking_lot::Mutex` for sync hot paths | Accepted |
| [0002](0002-tokio-rwlock-across-await.md) | `tokio::sync` locks for state held across `.await` | Accepted |
| [0003](0003-arcswap-hot-reload.md) | `ArcSwap<Option<T>>` for hot-reloadable shared state | Accepted |
| [0004](0004-rcgen-over-x509-cert-for-tests.md) | `rcgen` for test certificate generation | Accepted |
| [0005](0005-tokio-tungstenite-over-soketto.md) | `tokio-tungstenite` for the WebSocket layer | Documented |
| [0006](0006-redb-over-sled-for-store-and-forward.md) | `redb` for the per-client store-and-forward queue | Accepted |
| [0007](0007-thiserror-everywhere-no-anyhow-in-libs.md) | `thiserror` everywhere; no `anyhow` at library boundaries | Accepted |
| [0008](0008-once-lock-not-once-cell-lazy.md) | `std::sync::OnceLock` over `once_cell::sync::Lazy` | Accepted |
| [0009](0009-zeroizing-and-subtle-for-secrets.md) | `Zeroizing<T>` + `subtle::ConstantTimeEq` for secrets | Accepted |
| [0010](0010-spawn-background-and-subsystem-handle.md) | `spawn_background` + `SubsystemHandle` for task lifecycle | Accepted |
| [0011](0011-tracing-not-log-workspace-wide.md) | `tracing` for structured logging; no `log` facade | Accepted |
| [0012](0012-bytes-end-to-end-no-vec-on-hot-path.md) | `bytes::Bytes` end-to-end on the routing hot path | Accepted |
| [0013](0013-tactical-tcp-socket-hardening.md) | `configure_tactical_socket` for every TCP stream | Accepted |
| [0014](0014-hash-chained-audit-log.md) | SHA-256 hash-chained audit log with sealed terminator | Accepted |
| [0015](0015-encrypted-archives-chacha20-poly1305.md) | ChaCha20-Poly1305 with per-chunk AAD for archive encryption | Accepted |
| [0016](0016-on-callback-macro-for-typed-aliases.md) | `on_callback!` macro for `Arc<dyn Fn>` callback aliases | Accepted |
| [0017](0017-workspace-dependency-inheritance.md) | Workspace dependency inheritance for every crate | Accepted |
| [0018](0018-schema-first-codec-design.md) | Schema-first codec design for tactical wire formats | Accepted |
| [0019](0019-cnsa2-hybrid-mldsa.md) | CNSA 2.0 with Composite ML-DSA hybrid certificates | Proposed |
| [0020](0020-mavlink-pq-rekey.md) | MAVLink integration with ML-KEM-768 rekey channel | Proposed |
| [0021](0021-clean-room-tak-interop.md) | Clean-room interoperability policy for TAK and third-party protocols | Accepted |
| [0022](0022-cross-domain-guard-egress-seam.md) | Cross-domain guard egress seam (central `OnEgressGuard` hook) | Accepted |
| [0023](0023-tactical-codec-ingress-seam.md) | Tactical codec ingress seam (generic UDP/TCP codec-pluggable listeners) | Accepted |
| [0024](0024-guard-fail-closed.md) | Fail-closed semantics for the cross-domain guard (unparseable markings, audit-chain load failures) | Proposed |
| [0025](0025-revocation-lifecycle.md) | Live certificate-revocation lifecycle (CRL refresh, fail-closed staleness, active mid-session disconnect) | Proposed |
| [0026](0026-archive-xchacha-v3.md) | Wider-nonce v3 archive format (XChaCha20-Poly1305) | Proposed |
| [0027](0027-maskpoint-fail-closed.md) | MaskPoint fails closed for unmaskable position protocols (DIS/Link 16/ASTERIX/…) | Proposed |
| [0028](0028-sharded-maps-for-contended-hot-path.md) | `dashmap` for the position cache; single mutex stays for LRU/window maps | Accepted |
| [0029](0029-discovered-peer-cn-pinning.md) | Discovered federation peers are never CN-pinned to their discovery id (SEC-1) | Proposed |
| [0030](0030-tak-marti-application-layer.md) | TAK Server application-layer roadmap + Enterprise Sync first slice | Proposed |
| [0031](0031-production-hardening-ha-and-edge.md) | Production hardening — HA direction, capacity, edge install, and SLOs | Proposed |
| [0032](0032-meshtastic-serial-ingress-seam.md) | Meshtastic LoRa / serial ingress seam (non-IP admission; transport-owned de-encapsulation/decryption; serial-vs-bridge transport deferred) | Proposed |
| [0033](0033-http-client-stack.md) | `reqwest` (rustls-only) as the sanctioned outbound-HTTP client; `hyper-util` migration deferred | Documented |

## Authoring a new ADR

1. Copy [`template.md`](template.md) to the next available number,
   e.g. `0011-my-decision.md`. Slugs are kebab-case and short.
2. Set the status to **Proposed** while the decision is under
   discussion. Once the corresponding code lands, flip it to
   **Accepted**.
3. Keep the body slim — the goal is one screen of context, the
   decision, and the consequences. Long architectural prose belongs
   in `docs/architecture.md` or one of the other long-form documents
   in `docs/`.
4. Add a row to the index table above and link the new ADR from any
   existing ADR it relates to (use a relative path:
   `[ADR 0001](0001-parking-lot-mutexes-for-sync-paths.md)`).
5. Reference the ADR file in the body of the commit that implements
   the decision so the rationale travels with the change.

## What does and does not belong here

ADRs are for non-obvious architectural choices that future
contributors will hit and ask "why was this picked?" — the kind of
decision whose rationale is otherwise only visible in a commit
message. The seed set in this directory is exactly those decisions:
locking primitives, dependency selection in places where alternatives
were viable, secret-handling discipline, the shutdown protocol.

ADRs are not the place for:

- Routine implementation details ("we extracted helper X").
- Bug fixes or refactors that do not change a load-bearing decision.
- Per-feature design notes — those belong in `docs/<feature>.md`.
- Operator guidance — that belongs in `docs/runbooks/`.

When in doubt, write the ADR. It is cheaper to retire a too-small ADR
than to lose the rationale for a decision the codebase quietly relies
on.
