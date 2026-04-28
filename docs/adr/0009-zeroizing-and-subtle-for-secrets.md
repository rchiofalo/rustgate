# ADR 0009: `Zeroizing<T>` + `subtle::ConstantTimeEq` for secret material

- **Status:** Accepted
- **Date:** 2026-04-27
- **Related:** `.claude/rules/shared-infrastructure.md`
  "Secret Handling" and "Constant-Time Credential Comparison"

## Context

rustgate handles a non-trivial amount of secret material: TLS
private keys, NATS credentials, federation HMAC keys and JWT
secrets, EST CMS private keys, archive encryption keys, the
enrollment HTTP basic-auth password, and the ACL API token.
Default Rust string and byte handling does not protect this
material against two distinct categories of attack:

1. **Memory disclosure.** A `String` or `Vec<u8>` is dropped by
   freeing its allocation. The bytes remain in memory until the
   allocator overwrites them — possibly minutes or hours later.
   Heap dumps, swap, core dumps, and same-process leaks (panic
   handlers stringifying state) all expose those bytes.
2. **Timing side-channels on credential comparison.** A naive
   `==` over byte slices short-circuits on the first mismatch.
   The time difference between "wrong on byte 0" and "wrong on
   byte 30" is measurable on a fast network. An attacker can use
   this to recover a credential prefix-by-prefix.

The Rust ecosystem has well-maintained crates for both: `zeroize`
(memory wipe on drop) and `subtle` (constant-time comparison).
Both are pure-Rust, audit-allowlisted, and dependency-light.

## Decision

**All secret material is wrapped in `zeroize::Zeroizing<T>` from
the moment it enters the workspace until it leaves.**

Concretely:

- TLS private keys read from disk are wrapped in
  `Zeroizing<String>` (PEM) or `Zeroizing<Vec<u8>>` (DER) before
  being parsed.
- HMAC and JWT secrets, archive keys, NATS credentials, and the
  enrollment password are wrapped at the read boundary
  (`rustgate_core::secrets::read_secret_file` returns the buffer
  inside a `Zeroizing`).
- Intermediate buffers that hold key-derivation output (HKDF or
  Argon2id IKM) are wiped via `zeroize::Zeroize::zeroize(...)` as
  soon as derivation completes; only the derived 32-byte working
  key persists.
- Types holding secrets implement a custom `Debug` that prints
  `[REDACTED]` instead of the actual bytes — see
  `crates/rustgate-http/src/auth.rs::AuthState`,
  `crates/rustgate-federation/src/jwt.rs::JwtAuthority`,
  `crates/rustgate-core/src/encrypted.rs::KeyRing`. This
  prevents accidental exposure via `{:?}` in error chains or
  log lines.

**All credential comparisons go through `subtle::ConstantTimeEq`.**

The canonical pattern compares both username and password (or both
HMAC values, or both bearer tokens) regardless of which mismatches:

```rust
use subtle::ConstantTimeEq;
let user_ok = user.as_bytes().ct_eq(self.username.as_bytes());
let pass_ok = pass.as_bytes().ct_eq(self.password.as_bytes());
if (user_ok & pass_ok).into() { /* authenticated */ }
```

Bitwise `&` (not short-circuit `&&`) is required: short-circuit
evaluation reintroduces the timing leak at the boolean-combine
step. Both comparisons must execute regardless of which one fails,
so an attacker cannot distinguish "wrong username" from "wrong
password" by timing.

`==` on byte slices is forbidden in any path that touches
credential material. Reviewers push back on PRs that introduce one.

## Alternatives considered

- **Native `String` and `Vec<u8>` for secrets.** Rejected: the
  memory-disclosure surface is unacceptable for the threat model
  documented in `docs/threat-model.md`.
- **A custom `SecretBox<T>` wrapper.** Rejected: `zeroize` already
  exists, is audited, and the workspace has standardised on it.
  Building our own would re-litigate solved problems.
- **Rolling our own constant-time compare.** Rejected: the
  textbook `for` loop with bitwise OR-accumulation is easy to get
  wrong (compilers can re-introduce branches under optimization)
  and `subtle` is the reference implementation in the Rust
  ecosystem.

## Consequences

- Both `zeroize` and `subtle` are foundational workspace
  dependencies. Both are pure-Rust, MIT/Apache-2.0, and on the
  audit allowlist.
- Secret-bearing types implement custom `Debug`. The list is
  enumerated in `.claude/rules/shared-infrastructure.md` and grows
  as new secret-bearing surfaces are added.
- Extracting a secret out of a `Zeroizing` wrapper is intentional
  friction. The pattern is `std::mem::take(&mut *wrapped)` —
  `Zeroizing` has no `into_inner()` because that would defeat the
  drop-time wipe. The friction makes contributors think about the
  lifetime of the secret bytes.
- Tests are exempt from the credential-compare-with-ct discipline
  in spirit (test fixtures are not secrets), but in practice the
  pattern is the same — there is no value in writing tests
  differently from production code.
- Future secrets must enter the workspace through a wrapping path.
  `rustgate_core::secrets::read_secret_file` is the canonical
  entry point; it enforces the workspace-wide `mode 0o077` Unix
  permission gate, the 16 KiB size cap, and the ownership-UID
  check on the file before handing back a `Zeroizing<Vec<u8>>`.
- A reviewer who sees `==` on a byte slice in an authentication
  path will push back. The shared-infrastructure rules document
  is the canonical reference.
