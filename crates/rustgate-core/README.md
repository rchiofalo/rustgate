# rustgate-core

Foundational types, traits, and utilities shared across the rustgate workspace.

## Role in the workspace

`rustgate-core` sits at the bottom of the dependency graph — every other crate
in the workspace depends on it, and it depends on nothing else local. It owns
the cross-crate vocabulary (`Identity`, `RoutableMessage`, `Codec`, `PeerId`),
the structured audit-event API, the hash-chained audit-log writer, the
ChaCha20-Poly1305 streaming archive format, the secret-file reader, the
cross-platform TCP keepalive helpers, and the timeout/frame-size constants
every transport in the workspace shares.

## Public API surface

- `identity::Identity`, `identity::AttrValue` — client identity (CN, fingerprint,
  groups, tenant, SPIFFE ID, RBAC/ABAC attributes)
- `message::{RoutableMessage, Destination, MessageType, Metadata}` — the
  internal message envelope routed by `rustgate-transport`
- `codec::Codec` — protocol transformation trait (decode / encode / framing /
  detect) implemented by every transport adapter
- `error::{RustgateError, TransportError, ConfigError, Result}` — boundary
  aggregator wrapping transport, config, and `io::Error`
- `audit::*` — 28+ structured audit event helpers (`client_rejected`,
  `tls_handshake_failed`, `authz_denied`, `security_rate_limited`, etc.)
- `audit_chain::HashChainWriter`, `audit_chain::verify_audit_log` —
  tamper-evident SHA-256-chained append-only log
- `encrypted::{EncryptedWriter, KeyRing, decrypt_file}` — AEAD streaming
  archive format (per-chunk AAD, sealed terminator, key rotation by id)
- `secrets::{read_secret_file, SecretFileOpts}` — single secret-file reader
  with size cap, Unix permissions gate, owner-uid check, `Zeroizing<String>`
  return type
- `net::{configure_tactical_socket, configure_tcp_keepalive, configure_tcp_nodelay}` —
  TCP socket-option helpers applied to every accepted stream
- `tasks::{spawn_background, SubsystemHandle, stop_subsystem}` — background-task
  panic logging and drainable subsystem lifecycle (5s graceful drain)
- `sanitize::sanitize_for_log`, `masking::{hash_cn, mask_ip, mask_credential, mask_cert_serial}` —
  log-forging defense and PII masking
- `crypto::{hmac_sha256_tag, hmac_sha256_verify}` — unified HMAC-SHA256
  helper used by store-and-forward, HTTP HMAC auth, and federation JWT
- `constants::*` — `MAX_FRAME_SIZE`, `READ_TIMEOUT`, `HANDSHAKE_TIMEOUT`,
  `FEDERATION_HEARTBEAT_INTERVAL`, `PLAINTEXT_GROUP`, etc.

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `pem` | PEM parsing helpers (certificates, private keys, CA trust stores) for crates that previously rolled their own | No |
| `metrics` | Shared Prometheus fallback constructors for the workspace's `OnceLock` + `init()` + accessor pattern | No |
| `fuzz` | `arbitrary::Arbitrary` impls for fuzz harnesses | No |

## Where to look first

- `crates/rustgate-core/src/lib.rs` — module map and re-export surface
- `crates/rustgate-core/src/identity.rs` — `Identity` and `AttrValue`, the
  shape of every authenticated session in the workspace
