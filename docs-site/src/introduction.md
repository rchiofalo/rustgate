# rustgate

**rustgate** is a tactical mutual-TLS message router written in Rust. It
provides secure, authenticated communication using mTLS, certificate
enrollment, message routing, federation, and NATS bridging.

While originally designed for tactical use cases, rustgate is
protocol-agnostic: the core transport, routing, and federation layers do
not assume any particular message format.

```admonish info
This site is the authoritative source for rustgate documentation,
operational runbooks, security analysis, and research. It is built from
the `docs-site/` directory of the [rustgate repository][repo] and
published to GitHub Pages on every push to `main`.

[repo]: https://github.com/rchiofalo/rustgate
```

## What rustgate gives you

- **Mutually-authenticated transport** — every client presents an X.509
  certificate, validated against a configurable CA bundle with CRL
  enforcement and hot-reload.
- **Pluggable crypto backends** — default `ring`, opt-in FIPS 140-3
  (`aws-lc-rs`), opt-in post-quantum key exchange (X25519MLKEM768).
- **Federation** — server-to-server links with JWT peer authentication,
  persistent replay buffers, and per-peer lag metrics.
- **Admission control** — global byte-budget backpressure, per-session
  circuit breakers, and bounded per-client store-and-forward queues.
- **Tamper-evident audit log** — hash-chained audit records with a
  `verify-audit` CLI for integrity proofs.
- **No unsafe code** — `#![forbid(unsafe_code)]` is set workspace-wide.
- **No panics in production code** — clippy denies `unwrap`, `panic`,
  and `dbg!` across every crate.

## How the docs are organized

- **Getting Started** walks you from `cargo install` to a running
  router with a test client.
- **Architecture** documents the 10-crate workspace and how the pieces
  fit together.
- **Operations** covers deployment (Docker, Helm), metrics, health
  probes, and runbooks for incident response.
- **API Reference** is the CLI, REST endpoints, and auto-generated
  rustdoc.
- **Security** describes the threat model, mTLS configuration, audit
  log guarantees, FIPS and post-quantum modes, and a structured matrix
  of attacks rustgate is immune or resistant to.
- **Research** is long-form advocacy: why rustgate exists, how it
  compares to alternatives, attack-class analysis, benchmarks, and
  downloadable papers.
