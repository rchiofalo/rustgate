# ADR 0033: `reqwest` is the sanctioned outbound-HTTP client stack

- **Status:** Documented
- **Date:** 2026-07-03
- **Deciders:** rchiofalo
- **Related:** #1521 (the dependency audit that flagged the outbound HTTP
  stack — F-94), ADR 0017 (workspace dependency inheritance), ADR 0009
  (`Zeroizing` + `subtle` for secrets — bearer/JWKS auth built on this
  client), `deny.toml` (bans `openssl`/`native-tls`; the client must stay
  rustls-only)

## Context

Every outbound HTTP call rustgate makes — webhook egress, federation JWKS
fetches and Consul catalog polls, and OGC SensorThings subscription polls
— goes through `reqwest`. The June 2026 dependency audit (#1521, finding
F-94) asked whether this dependency could be dropped in favour of a
thinner `hyper` + `hyper-util` + `tower` stack, on the stated premise that
`reqwest` was used in only "the HTTP publisher and `consul.rs`."

That premise is stale. The current construction sites are:

- `rustgate-http` — `publisher.rs` (`build_client`/`build_pinned_client`
  via `reqwest::Client::builder()`), `resolver.rs` (a custom
  `reqwest::dns::Resolve` implementation attached with
  `ClientBuilder::dns_resolver()`), and `auth.rs` (bearer/OAuth token
  exchange).
- `rustgate-federation` — `jwks_client.rs` (`build_http_client`, JWKS key
  fetch for HA-federation JWT verification) and
  `discovery/consul.rs` (Consul catalog HTTP API).
- `rustgate-ogc-sensorthings` — `client.rs` (per-subscription polling).

Each of these depends on `reqwest` conveniences that `hyper-util` does not
provide for free:

- **rustls `ClientConfig` injection** via `use_preconfigured_tls()`, so the
  workspace's single rustls provider, custom certificate verifier, and cert
  pinning flow straight into the client. `hyper-util`'s
  `HttpsConnector` is a separate wiring exercise per site.
- **Custom DNS resolution** via `dns_resolver(Arc<dyn Resolve>)` — the HTTP
  publisher pins resolution to prevent SSRF/rebinding; there is no drop-in
  `hyper-util` equivalent.
- **Per-target `timeout()` / `connect_timeout()`**, redirect policy, and a
  fixed user agent, all configured per client. With bare `hyper` these
  become `tower` layers the caller assembles by hand.

`reqwest` is already pinned to a minimal, rustls-only feature set in the
root `Cargo.toml`:

```toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "http2"] }
```

No `gzip`, `multipart`, `cookies`, or blocking client is enabled. (The
"multipart" handling elsewhere in the tree — enrollment and missions — is
hand-rolled body parsing, unrelated to `reqwest::multipart`.) The
`default-features = false` guard keeps `openssl`/`native-tls` — both banned
by `deny.toml` — out of the tree; `rustls-tls` is the only TLS backend.

## Decision

**`reqwest` (rustls-only, `json` + `rustls-tls` + `http2`) is the sanctioned
outbound-HTTP client for the workspace.** New code that needs an HTTP client
uses `reqwest` and inherits it via workspace dependency inheritance
(ADR 0017); it must not add a bare version or enable a wider feature set
without review. Any new TLS-adjacent feature is a `deny.toml` review item.

**A `hyper-util` migration is deferred, not adopted.** Consolidating the
six-plus construction sites onto `hyper-util` would mean re-deriving, per
site, the rustls-config injection, custom DNS resolver, and per-target
timeout/redirect wiring that `reqwest` supplies today. That is an L/XL,
security-sensitive change (the SSRF-guarding DNS resolver and cert-pinned
TLS are exactly the paths a rewrite could regress), not the near-free
dependency trim the audit's stale premise implied. It is not undertaken as
part of #1521.

## Alternatives considered

- **Migrate to `hyper` + `hyper-util` + `tower`.** The audit's suggestion.
  Deferred: the win (one fewer mid-level dependency) does not justify
  hand-reassembling rustls injection, custom DNS, and timeout/redirect
  policy across four crates, each a place a regression could reopen an SSRF
  or TLS-verification hole. Revisit only if `reqwest` itself becomes a
  maintenance or supply-chain liability.
- **Split the client per crate (e.g. `ureq` for federation, `reqwest` for
  egress).** Rejected — multiplying HTTP stacks widens the audit surface
  and the rustls-config plumbing has to be reinvented per stack anyway.
- **Keep `reqwest` but widen features (gzip, retry middleware).** Rejected
  as a default: retry/backoff already lives in `rustgate-resilience`, and
  every added feature is a new transitive-dependency review. Features stay
  at the current `json` + `rustls-tls` + `http2` minimum.

## Consequences

The dependency stays. `reqwest` remains a shared workspace dependency with
a fixed, rustls-only feature set; adding an HTTP client elsewhere is a
one-line workspace reference, not a fresh stack decision. The audit finding
F-94 is recorded as **deferred with rationale** rather than actioned — a
future contributor reading #1521 will find this ADR instead of an open
"drop reqwest" task. Reversible: if a `hyper-util` migration is ever taken
up, it supersedes this ADR and the construction sites enumerated above are
the checklist of what must be re-wired.
