# rustgate-tls

TLS / mTLS configuration, certificate handling, OCSP stapling, SPIFFE
workload identity, and TCP listeners.

## Role in the workspace

`rustgate-tls` owns the **cryptography boundary**: every TLS handshake,
every certificate verification, every CRL load, every OCSP fetch, every
SPIFFE SVID rotation. Extracted from `rustgate-transport` in #890 to
scope the cross-cutting `fips` / `post-quantum` / `ocsp` / `spiffe`
feature matrix to a single crate so security-sensitive code lives in
one auditable place.

`rustgate-transport` now focuses on routing, session management,
codecs, store-and-forward, throttling, ACL, and UDP — purely
post-handshake concerns. **Anything that touches an X.509 cert, a
private key, an OCSP responder, or a Workload API SVID lives here.**

## Public API surface

### Configuration + setup

- `TlsConfig` / `TlsConfigBuilder` — assemble the rustls
  `ServerConfig` with mTLS, CRL, hot-reload, and OCSP options
- `TlsMinVersion` — `1.2` / `1.3` enum (CNSA 2.0 paths require `1.3`)
- `install_provider_with_kx_groups` — install the rustls
  `CryptoProvider` with a per-deployment key-exchange-group preference
- `install_fips_provider` (feature `fips`) — install the FIPS 140-3
  aws-lc-rs provider
- `install_pq_provider` (feature `post-quantum`) — install the
  X25519MLKEM768 hybrid PQ provider

### Listeners

- `TlsListener` — accepts mTLS connections, runs the handshake, calls
  back with `(stream, identity)` on success
- `DEFAULT_MAX_HANDSHAKES` — bound on concurrent handshakes (default
  256)
- `OnHandshakeError = Arc<dyn Fn(SocketAddr, &str) + Send + Sync>` —
  workspace-standard `On*` callback for handshake failure reporting
- `PlaintextListener` / `PlaintextIdentityConfig` /
  `PlaintextSession` — unauthenticated TCP/UDP listeners for trusted-
  network bridges (CoT relays, UDP multicast ingress)

### Identity extraction

- `extract_identity(cert)` — pulls `Identity { cn, groups, fingerprint, tenant, spiffe_id, attributes }` from an X.509 certificate
- `ExpectedKeyUsage` — the key-usage extension policy applied to client certs
- `validate_key_usage(cert, expected)` — enforce the policy on accepted certs

### Hot-reload

- `CertReloader` — file-system-watcher-driven atomic cert swap
  (matches the polling-and-hash pattern used by
  `rustgate-admin::AclReloader` and `rustgate-server::AuthzReloader`)

### Verifier

- `DynamicCertVerifier` — wraps a `rustls::WebPkiClientVerifier` with
  hot-swappable root store; CRL hot-reload triggers a verifier rebuild
- `RootStoreProvider` — pluggable source of the trust anchors

### Session

- `AuthenticatedSession` — wraps a server-side mTLS stream with the
  identity extracted at handshake; consumers reach for `SessionReader`
  / `SessionWriter` for I/O
- `SessionReader` / `SessionWriter` — split-direction halves for
  per-direction backpressure

### OCSP (feature `ocsp`)

- `ClientOcspVerifier` — Tier-1 fail-open OCSP for client certificates
  via the workspace's `WebPkiClientVerifier` wrapper
- `OcspStaplerFetcher` — server-side stapling via the `ocsp-stapler`
  crate
- `OcspFetcher` / `FetchFuture` — pluggable fetcher trait for tests

### SPIFFE (feature `spiffe`)

- `SpiffeIdentity` (re-exported under the `spiffe` module) — workload-
  identity wrapper that drives `CertReloader` on SVID rotation events
  from the SPIFFE Workload API

## Feature flags

| Feature | Description |
|---|---|
| `fips` | Uses the AWS-LC FIPS module (`rustls/fips`). Requires Go + cmake. |
| `post-quantum`, `mldsa-certs` | No effect; kept so existing feature lists still build. Hybrid PQ key exchange and ML-DSA verification are on in every build (ADR 0037). |
| `ocsp` | OCSP stapling (server) + client-side OCSP verification via the `ocsp-stapler` crate. Adds a background fetcher task. |
| `spiffe` | SPIFFE Workload API integration via the `spiffe` crate. Subscribes to SVID rotation events and feeds them through `CertReloader`. |

`fips` and `post-quantum` both pull in `aws-lc-rs` — they are
**mutually exclusive in their stable provider variants** today.
`post-quantum` uses aws-lc-rs's `unstable` module which is gated as
`not(feature = "fips")` upstream
([aws-lc-rs #964](https://github.com/aws/aws-lc-rs/issues/964) — the
critical-path blocker for full CNSA 2.0 in rustgate).

## Topology / deployment notes

### Hot-reload triggers

- **Certificate file change** (`CertReloader` polling tick) → new
  rustls `ServerConfig` constructed → atomic `ArcSwap::store`
- **CRL file change** → verifier rebuild via `DynamicCertVerifier`
  (the verifier's root store is hot-swapped; existing connections
  keep their already-verified identity)
- **SPIFFE SVID rotation** (`spiffe` feature) → Workload API event
  triggers a synthetic cert-reload tick

All three paths are lock-free on the read path
([ADR 0003](../../docs/adr/0003-arcswap-hot-reload.md)
`ArcSwap<Option<T>>`).

### Listener tactical-socket hardening

`TlsListener` calls `rustgate_core::net::configure_tactical_socket` on
every accepted TCP stream before TLS negotiation
([ADR 0013](../../docs/adr/0013-tactical-tcp-socket-hardening.md)) —
TCP keepalive (idle=30s, interval=10s) + `TCP_NODELAY` to keep dead
NAT middleboxes from hanging connection slots and to avoid the
~40 ms Nagle + DELACK stall on tactical traffic.

### Connection limits

`DEFAULT_MAX_HANDSHAKES = 256` bounds the in-flight handshake count
behind a semaphore. Misbehaving clients that connect-and-never-finish
the TLS handshake can't exhaust file descriptors past this cap.

### Where this crate does NOT go

- **Routing** — handled by `rustgate-router` (post-handshake)
- **Codecs / framing** — handled by `rustgate-transport`
- **Federation** — `rustgate-federation` uses `rustgate-tls`'s
  config but owns the peer-mTLS lifecycle separately
- **Enrollment / cert issuance** — `rustgate-enrollment` owns CSR
  signing and PKCS#12 issuance; `rustgate-tls` is decode-only

## Testing

Inline unit tests cover the per-module contracts. Smoke-level
integration coverage lives in `tests/handshake_smoke.rs` — exercises
an end-to-end mTLS handshake against a `TestCa`-issued client + server
cert, verifies the identity extraction recovers the cert's CN and OUs,
and confirms the listener rejects revoked certs.

Full OCSP / SPIFFE / hot-reload integration coverage is out of scope
for the smoke layer; see the integration tests in
`rustgate-transport` and `rustgate-federation` for those flows in
their natural context.
