# rustgate-test-utils

Shared test-only certificate generation and ephemeral NATS server helpers.

## Role in the workspace

`rustgate-test-utils` is consumed exclusively by the `[dev-dependencies]`
of the other workspace crates. It exists so every integration test in the
workspace generates its own ephemeral PKI at runtime — no fixture files
under version control, no shared expiry dates, no leak of private keys
into git history. The crate's clippy lints are intentionally relaxed
(`unwrap_used = "deny"` is kept, but `panic = "allow"`) because test
setup failures should be loud rather than silently masked behind error
plumbing. Depended on by
[rustgate-transport](../rustgate-transport/README.md),
[rustgate-enrollment](../rustgate-enrollment/README.md),
[rustgate-federation](../rustgate-federation/README.md),
[rustgate-websocket](../rustgate-websocket/README.md),
[rustgate-mqtt](../rustgate-mqtt/README.md),
[rustgate-http](../rustgate-http/README.md),
[rustgate-nats](../rustgate-nats/README.md), and
[rustgate-server](../rustgate-server/README.md).

## Public API surface

- `certs::TestCa::new(cn)` — generate a fresh CA for a single test
- `certs::TestCa::issue_client_cert(cn, groups)` — sign a client cert
  carrying `cn` as `CN` and `groups` as `OU` entries
- `certs::TestCa::issue_server_cert(cn, san_dns)` — sign a server cert
  with the given DNS SANs
- `certs::TestCa::issue_expired_client_cert()` — issue an already-expired
  cert for rejection-path tests
- `certs::TestCa::issue_crl(serials)` — produce a CRL revoking the given
  serials, signed by the CA
- `certs::generate_server_keypair()` — fresh server key pair when a test
  needs to model "same key, different cert" (e.g. SPKI-pinning round-trips)
- `tls::{parse_certs, parse_key, build_client_tls_config}` — parse PEM
  blobs and assemble a rustls `ClientConfig` against a TestCa
- `nats::TestNatsServer::start()` — managed `nats-server` subprocess for
  NATS integration tests; only readable when JetStream is fully accepting
  KV operations (gated on the `nats` feature)

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `nats` | Compiles `TestNatsServer` and the JetStream readiness probe; pulls in `tempfile`, `tokio`, and `async-nats` (with `kv`) | No |

## Topology / deployment notes

Not for production use — this crate is test-support only. Nothing here
links into the `rustgate` binary. Crypto-provider installation uses `ring`
unconditionally; FIPS tests must call
`rustgate_transport::install_fips_provider()` BEFORE constructing any
`TestCa` instance because the install-default call here silently no-ops
when a provider is already in place.

## Where to look first

- `crates/rustgate-test-utils/src/certs.rs` — `TestCa` and the cert /
  CRL issuance helpers
- `crates/rustgate-test-utils/src/nats.rs` — `TestNatsServer` (under
  `--features nats`)
