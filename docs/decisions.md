# Workspace decisions cross-reference

Quick lookup for the "am I about to reinvent something?" moment. The
table lists each common task, the helper or pattern to reach for, and
the [Architecture Decision Record](adr/README.md) that captures the
rationale. The ADRs are the prescriptive standard; the table is the
quick lookup.

A row without an ADR link points at a workspace utility documented in
its own module rustdoc. If you find yourself wanting to add a new row
without a corresponding ADR, the right move is usually to write the
ADR — that is what this file is the index of.

## Concurrency and shared state

| I want to... | Reach for | ADR |
|---|---|---|
| Take a sync mutex on a hot path | `parking_lot::Mutex` | [ADR 0001](adr/0001-parking-lot-mutexes-for-sync-paths.md) |
| Take a lock across `.await` | `tokio::sync::RwLock` (read-heavy) or `tokio::sync::Mutex` (exclusive) | [ADR 0002](adr/0002-tokio-rwlock-across-await.md) |
| Hot-reload a config value at runtime | `arc_swap::ArcSwap<Option<T>>` with double-deref load | [ADR 0003](adr/0003-arcswap-hot-reload.md) |
| Implement a static singleton | `std::sync::OnceLock` + `init()` + accessor | [ADR 0008](adr/0008-once-lock-not-once-cell-lazy.md) |

## Errors and observability

| I want to... | Reach for | ADR |
|---|---|---|
| Return a crate error | `thiserror::Error` derive with context fields | [ADR 0007](adr/0007-thiserror-everywhere-no-anyhow-in-libs.md) |
| Log an event at any level | `tracing::{debug, info, warn, error}` with structured fields | [ADR 0011](adr/0011-tracing-not-log-workspace-wide.md) |
| Record a security-relevant event | `rustgate_core::audit::*` (e.g. `connection_rejected`, `tls_handshake_failed`) | [ADR 0011](adr/0011-tracing-not-log-workspace-wide.md), [ADR 0014](adr/0014-hash-chained-audit-log.md) |
| Open an append-only audit log | `rustgate_core::audit_chain::HashChainWriter` | [ADR 0014](adr/0014-hash-chained-audit-log.md) |

## Tasks and lifecycle

| I want to... | Reach for | ADR |
|---|---|---|
| Spawn a background task | `rustgate_core::tasks::spawn_background("name", async ...)` | [ADR 0010](adr/0010-spawn-background-and-subsystem-handle.md) |
| Start a drainable subsystem | `rustgate_core::tasks::SubsystemHandle` + `stop_subsystem(...)` | [ADR 0010](adr/0010-spawn-background-and-subsystem-handle.md) |
| Pass a cross-thread callback | `rustgate_core::on_callback!` macro | [ADR 0016](adr/0016-on-callback-macro-for-typed-aliases.md) |

## Networking and protocol

| I want to... | Reach for | ADR |
|---|---|---|
| Carry a payload through the routing core | `bytes::Bytes` (never `Vec<u8>`) | [ADR 0012](adr/0012-bytes-end-to-end-no-vec-on-hot-path.md) |
| Accept a tactical TCP stream | `rustgate_core::net::configure_tactical_socket(&stream)` | [ADR 0013](adr/0013-tactical-tcp-socket-hardening.md) |
| Accept a bulk-only TCP stream | `rustgate_core::net::configure_tcp_keepalive(&stream)` | [ADR 0013](adr/0013-tactical-tcp-socket-hardening.md) |
| Run a WebSocket listener | `tokio-tungstenite` over `tokio-rustls` | [ADR 0005](adr/0005-tokio-tungstenite-over-soketto.md) |
| Speak the canonical entity model | `rustgate_entity::{Entity, EntityCodec, EntityCodecRegistry}` (re-exports `rustgate_core::entity` during migration) | [ADR 0028](adr/0028-canonical-entity-crate.md) |

## Secrets and security

| I want to... | Reach for | ADR |
|---|---|---|
| Hold a secret in memory | `zeroize::Zeroizing<T>` | [ADR 0009](adr/0009-zeroizing-and-subtle-for-secrets.md) |
| Compare a credential | `subtle::ConstantTimeEq` (`ct_eq`, combine with `&`) | [ADR 0009](adr/0009-zeroizing-and-subtle-for-secrets.md) |
| Encrypt an archive on disk | `rustgate_core::encrypted::EncryptedWriter` + `KeyRing` | [ADR 0015](adr/0015-encrypted-archives-chacha20-poly1305.md) |

## Persistence

| I want to... | Reach for | ADR |
|---|---|---|
| Persist a per-client backlog | `redb` via `rustgate_transport::store_forward` | [ADR 0006](adr/0006-redb-over-sled-for-store-and-forward.md) |
| Generate test certificates | `rustgate_test_utils::TestCa` (uses `rcgen`) | [ADR 0004](adr/0004-rcgen-over-x509-cert-for-tests.md) |

## Workspace conventions

| I want to... | Reach for | ADR |
|---|---|---|
| Add an external dependency | Declare once in root `[workspace.dependencies]`, reference with `{ workspace = true }` | [ADR 0017](adr/0017-workspace-dependency-inheritance.md) |
| Record an architectural decision | Copy `docs/adr/template.md`, slim Nygard format | [ADR 0000](adr/0000-record-architecture-decisions.md) |

## What's not here

For utilities documented in `.claude/rules/shared-infrastructure.md`
that do not yet have an ADR — log sanitization, PII masking
(`hash_cn`, `mask_ip`, `mask_credential`), per-IP / per-target rate
limiters, circuit breakers, dedup cache, position cache, CoT delta
compression, peer discovery, SPIFFE workload identity, tenant
quotas, fail-open degradation — the shared-infrastructure document
remains the canonical reference. ADRs are added as those subsystems
acquire load-bearing decisions worth recording independently.
