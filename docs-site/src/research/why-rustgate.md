# Why rustgate

> A structured argument for why an mTLS-first, memory-safe, auditable
> message router is the right foundation for tactical and regulated
> communications — and why existing routers do not meet that bar.

```admonish note
This is a living document. The goal is to accumulate a defensible
position, backed by the exploit-resistance matrix, the benchmarks
page, and the papers section.
```

## The thesis

Most deployed tactical message routers share a common lineage: C or
C++ codebases written before modern TLS libraries existed, bolted
onto by a decade of patches, with authentication added as a layer
rather than a foundation. The result is a class of software that:

1. **Trusts the network perimeter** — clients are considered
   authenticated because they are "inside" the VPN.
2. **Treats audit as logging** — records are appended to a file with
   no tamper-evidence guarantees.
3. **Has unsafe code on every message path** — a single parser bug in
   C is a remote code execution primitive.
4. **Lacks admission control** — a slow or malicious client can
   exhaust server memory without triggering any breaker.
5. **Cannot be updated in regulated environments** — FIPS 140-3 and
   post-quantum migration are not configuration flags, they are
   multi-year engineering projects.

rustgate takes the opposite position on every point: mTLS is
mandatory, audit is a hash chain with a verification CLI, `unsafe`
is forbidden workspace-wide, admission control is built into the
router, and FIPS / post-quantum are feature flags.

## Claims this document will defend

Each claim links to the evidence that supports it.

1. **Memory-safety eliminates an entire class of CVEs that affect
   incumbent routers.** See the [Exploit Resistance Matrix].
2. **Mandatory mTLS + CRL hot-reload gives stronger identity
   guarantees than perimeter trust or bearer tokens.** See
   [mTLS] and [Threat Model].
3. **Hash-chained audit logs convert audit from "logging" to a
   cryptographic artifact an auditor can verify offline.** See
   [Audit Log].
4. **Global admission control + per-session circuit breakers make
   slowloris and memory-exhaustion attacks observable and bounded.**
   See [Benchmarks] (forthcoming).
5. **Feature-gated FIPS and post-quantum crypto make regulated and
   future-proof deployments a configuration decision, not a fork.**
   See [FIPS] and [Post-Quantum KEX].
6. **No `unsafe` + no `panic` in production code is a stronger
   guarantee than "we ran the fuzzer."** See the workspace lints in
   the root `Cargo.toml`.

## What this document is not

- **Not a marketing piece.** Every claim must cite code, a test, a
  benchmark, or a CVE.
- **Not a comparison hit-piece.** The [comparison page][compare]
  will be evidence-based: features present, absent, or partially
  implemented, with sources.
- **Not finished.** Each section will expand as benchmarks run and
  papers are published in the [research papers][papers] section.

[Exploit Resistance Matrix]: ../security/cve-resistance.md
[mTLS]: ../security/mtls.md
[Threat Model]: ../security/threat-model.md
[Audit Log]: ../security/audit-log.md
[Benchmarks]: ./benchmarks.md
[FIPS]: ../security/fips.md
[Post-Quantum KEX]: ../security/post-quantum.md
[compare]: ./comparison.md
[papers]: ./papers/index.md
