# Reqwest HTTP Client Usage Audit

The workspace uses `reqwest` as its outbound HTTP client in two production
sites: the HTTP egress publisher (`rustgate-http`) and the Consul peer-discovery
backend (`rustgate-federation` under `peer-discovery-consul`). Reqwest is a
"fat" client — it pulls in `hyper`, `h2`, `rustls`, `tokio-rustls`, a DNS
resolver, and a connection pool — and the question this document answers is
whether each call site actually needs that surface area or could be served by
a leaner alternative (`hyper` directly, `ureq` for synchronous calls, or
`tonic`'s embedded HTTP path for gRPC-adjacent code).

This document is the contribution gate: pulling `reqwest` into a new crate
must come with a row in the per-site table below explaining why the leaner
options were rejected. Removing `reqwest` from a documented site requires
updating the table, not just the code.

## Workspace dependency

```toml
# root Cargo.toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "http2"] }
```

`default-features = false` is load-bearing: it disables `native-tls` /
`default-tls`, the cookie store, the brotli/gzip body decoders, and the
charset transcoder. Only the three features the workspace actively uses are
opted in:

| Feature | Why we need it |
|---|---|
| `json` | The egress publisher serializes payloads via `RequestBuilder::json()` for JSON targets and the Consul backend deserializes the catalog response with `Response::json()` |
| `rustls-tls` | Aligns with the workspace's rustls-only TLS posture (no `native-tls`, no `openssl`) and makes `aws-lc-rs` / `prefer-post-quantum` swaps feature-gated through the same crate everyone else uses |
| `http2` | TLS-fronted webhook receivers (Splunk HEC, Elastic, generic load balancers) negotiate ALPN `h2`; without this feature reqwest negotiates `http/1.1` only and we lose request multiplexing on long-lived connections |

Any new feature added to this list must come with a justification entry in
this table — `default-features = false` is intentional dependency hygiene
and CI's `cargo-hack` matrix is sized around the current feature surface.

## Per-site audit

### `rustgate-http` — egress publisher

| Field | Value |
|---|---|
| Files | `crates/rustgate-http/src/publisher.rs`, `crates/rustgate-http/src/auth.rs`, `crates/rustgate-http/src/resolver.rs`, `crates/rustgate-http/src/config.rs`, `crates/rustgate-http/src/error.rs` |
| HTTP operations | POST / PUT / PATCH per-target (configurable), with optional Bearer / Basic / HMAC-SHA256 auth and per-target client TLS, certificate pinning, mTLS client identity, optional W3C trace-context propagation |
| Concurrency profile | One persistent `reqwest::Client` per configured target, kept for the lifetime of the publisher; the per-target circuit breaker, token bucket, and DLQ drain worker all reach into the same client |
| Why reqwest | (1) **Connection pooling** is required: targets see steady delivery cadence and the cost of TCP + TLS handshake per message would be prohibitive (Splunk HEC, ELK, Loki, and webhook fan-outs all expect keep-alive). (2) **HTTP/2 multiplexing** matters for the same reason — a single connection carries hundreds of in-flight requests against ALPN-negotiated `h2` receivers without head-of-line blocking. (3) The **DNS resolver hook** (`ClientBuilder::dns_resolver()`) is the only stable Rust ecosystem surface for SSRF-safe resolution that validates resolved IPs at connect time (`resolver.rs::SsrfSafeResolver`) — going hyper-direct would mean reimplementing the `dns::Resolve` trait against `hyper-util`'s pre-1.0 connector API, which is not currently stable. (4) The **TLS preconfigured-config hook** (`ClientBuilder::use_preconfigured_tls()`) is the only ergonomic way to attach a custom rustls verifier (`pinning::PinnedCertVerifier`) for SHA-256 certificate pinning — pre-built `hyper-rustls::HttpsConnector` does not expose a verifier-replacement seam without owning the entire connector stack. (5) The **redirect policy** + **min-TLS-version** + **connect-timeout** + **per-request timeout** + **identity** knobs are first-class on `ClientBuilder`; the equivalent on hyper requires composing four separate middleware layers. |
| Leaner alternative | Theoretically `hyper` 1.x + `hyper-util` + `hyper-rustls` would work, but the seams listed above (custom DNS resolver, custom TLS verifier, redirect policy, identity loading from PEM) would each require ~50–150 LOC of glue, plus a bespoke retry/timeout middleware. The combined surface would meaningfully overlap with what `reqwest` already provides on top of the same `hyper` core. The project deliberately keeps `reqwest` here because the per-target `Client` is constructed once at startup (no hot-path cost) and the surface area saved by a hand-rolled hyper stack would be paid back in glue code. |
| Decision | Keep reqwest. The egress publisher is the dominant reqwest consumer, and the feature surface (custom DNS, custom verifier, mTLS client identity, redirect policy, ALPN h2, per-target timeouts, response body capture with content-length guard) is exactly what the workspace would have to reimplement against hyper. |

### `rustgate-federation::discovery::consul` — Consul catalog poller

| Field | Value |
|---|---|
| Files | `crates/rustgate-federation/src/discovery/consul.rs` |
| Feature flag | `peer-discovery-consul` (optional dep `reqwest = { workspace = true, optional = true }`) |
| HTTP operations | One `GET <base_url>/v1/catalog/service/<service-name>` per reconciler tick (default 30 s), parsed as `Vec<CatalogEntry>` via `Response::json()` |
| Concurrency profile | One persistent `reqwest::Client` per `ConsulDiscovery` instance, held for the lifetime of the federation manager; the reconciler ticks against the same client every interval |
| Why reqwest | (1) **Already a workspace dep** — bringing in the full `reqwest::Client` for Consul is free given the egress publisher already pays the transitive cost. Adding a second HTTP client (`ureq`, `hyper`-direct) would expand the dependency graph for a single endpoint. (2) **rustls feature alignment** — when Consul is fronted by TLS (production deployments behind a reverse proxy with mTLS), the client picks up the workspace's rustls-only TLS posture without a separate TLS configuration path. (3) **JSON deserialization** uses the same `serde_json` integration the rest of the workspace uses, no second JSON parser. (4) The default reqwest connection pool keep-alives the Consul agent connection across reconciler ticks, avoiding handshake cost on every poll. |
| Leaner alternative | `ureq` (synchronous, ~5x smaller dep tree) would technically work for the single GET, but the reconciler is async (`async fn discover()`), so a synchronous client would force a `spawn_blocking` per tick and lose connection reuse across the async boundary. `hyper` direct would require hand-rolling the URL building (`Url::parse` → `Uri`), the `Accept: application/json` negotiation, and the response body draining. The conditional `dep:reqwest` gate already keeps the cost confined to deployments that opt into Consul discovery. |
| Decision | Keep reqwest. The cost is conditional (opt-in feature flag), the reconciler is async, and the Consul agent is one of several optional discovery backends — see "What does NOT use reqwest" below. |

## What does NOT use reqwest

For completeness — these sites would superficially look like reqwest
candidates and intentionally use something else:

| Site | What it uses | Why not reqwest |
|---|---|---|
| `rustgate-federation::discovery::etcd` | `etcd-client` (gRPC) | etcd's API is gRPC-native; reqwest would require speaking the JSON gateway, which is a second-class etcd surface and incurs translation overhead at the etcd server |
| `rustgate-federation::discovery::dns_sd` | `mdns-sd` (multicast DNS) | DNS-SD is not HTTP — it is RFC 6762 / RFC 6763 multicast DNS over UDP |
| `rustgate-federation::v2` (gRPC client / server) | `tonic` (uses `hyper` + `tower` directly) | gRPC over HTTP/2 with protobuf; reqwest cannot serve the streaming `prost`-encoded path |
| `rustgate-federation::jwks` | (no HTTP client) | This module is a JWKS *publisher* — it serializes the local key set to be served at `/.well-known/jwks.json`; it does not fetch remote JWKS. Future remote-JWKS fetch would land in this site as a new reqwest call |
| `rustgate-server::diagnostics` health/probe endpoints | `hyper` (server side, via the management API) | Server-side HTTP, not a client |
| `rustgate-enrollment::server` (EST endpoints) | `hyper` (server side) | EST is server-side; the workspace has no in-tree EST client |

## Decision tree

"I need to make an outbound HTTP call from a new crate. What do I reach for?"

| Task | Use |
|---|---|
| Long-lived publisher with connection pooling, per-target TLS, custom verifier, async | `reqwest` (extend `rustgate-http` patterns) |
| One-shot GET against a JSON endpoint, async, already in a crate that depends on `reqwest` | `reqwest` (use the existing client) |
| One-shot GET against a JSON endpoint, async, in a crate that does NOT yet depend on `reqwest` | Open a discussion issue first. Adding a second reqwest consumer is acceptable; adding a third or fourth concurrent HTTP client is not |
| gRPC | `tonic` (already in the workspace) |
| Server-side HTTP endpoint | `hyper` (already in the workspace, used by the management API and EST server) |
| Multicast DNS / DNS-SD | `mdns-sd` (already gated under `peer-discovery-dns-sd`) |
| Synchronous, fire-and-forget, no concurrency | Discussion issue. A synchronous HTTP call from within an async runtime is a `spawn_blocking` smell; the right fix is usually to async-ify the surrounding code, not to introduce `ureq` |

If none of the above match the task, that is the cue to open a discussion
issue before introducing a new HTTP client.

## Constraints

1. **Scoped use only.** `reqwest` may be used in `rustgate-http` (always)
   and in `rustgate-federation` (only behind the `peer-discovery-consul`
   feature). Adding `reqwest` to a third crate requires prior discussion
   and a row in the per-site table above.
2. **Workspace inheritance, no per-crate features.** Every consumer pulls
   `reqwest` from the workspace `[workspace.dependencies]` block with
   `{ workspace = true }` (or `{ workspace = true, optional = true }`).
   No crate may add `features = [...]` to its own reqwest declaration —
   the workspace feature set is the single source of truth.
3. **`default-features = false` is mandatory.** New features added to the
   workspace declaration require an entry in the feature-table above.
   `native-tls`, `cookies`, `brotli`, and `default-tls` are explicitly
   off and stay off.
4. **No second async HTTP client.** Do not introduce `surf`, `isahc`,
   `awc`, or `ureq` (when used inside an async context) — pick reqwest
   or pick `hyper` direct, not a third option.
5. **No synchronous client in async code.** `ureq` is acceptable in
   *purely synchronous* tooling that does not run inside a tokio runtime
   (build scripts, offline CLIs); it is not acceptable inside an async
   path with a `spawn_blocking` wrapper.

## Migration notes

If `reqwest` ever needs to be replaced workspace-wide, the realistic
landing zone is `hyper` 1.x + `hyper-util` + `hyper-rustls` + a thin
in-tree wrapper that re-exports the same builder shape (`Client::builder()`,
`dns_resolver(...)`, `use_preconfigured_tls(...)`, `redirect(...)`,
`min_tls_version(...)`). The migration would touch roughly 1500 LOC across
`rustgate-http` and ~50 LOC in `rustgate-federation::discovery::consul`,
and would need a parallel `rustgate-http-client` crate to host the
shared builder seam. That work is intentionally deferred — there is no
soundness, security, or maintenance argument for replacing reqwest
today; the audit's purpose is to document why the choice stays put.

The remaining sub-item of #803 (F-94, dep isolation) is a separate
follow-up that focuses on whether `peer-discovery-consul` can be carved
out into its own crate so that `rustgate-federation` itself does not
carry an optional `reqwest` dep at all. That is a build-graph change,
not an HTTP-client change.

Refs: #803 (F-93 — this document), #803 (F-94 — dep isolation, open).
