# ADR 0028: Hardware-rooted identity — trait in transport, drivers in rustgate-tpm

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** rchiofalo
- **Related:** #856 (the trait, resolver, and reference stub that shipped in
  `rustgate-transport::hw_identity`), #1539 (this scaffold + the follow-up
  driver bodies), #885 (parent zero-trust epic), `docs/zero-trust-alignment.md`
  (Device pillar, Gap-remediation roadmap)

## Context

rustgate's zero-trust **Device** pillar requires that a device's TLS identity
private key be rooted in hardware — a TPM2, a PKCS#11 token, a YubiKey — rather
than living as bytes on disk. #856 delivered the foundational seam for this:

- `crates/rustgate-transport/src/hw_identity.rs` — the object-safe
  `HardwareIdentity` trait (`cert_chain`, `sign`, `is_available`,
  `backend_name`, `certified_key`), the typed `HardwareIdentityError`
  (`Unavailable`, `PinRequired`, `Rejected`, `Io`), the fail-closed
  `HardwareIdentityResolver` (a `rustls::server::ResolvesServerCert` adapter),
  and the software reference `Pkcs11StubBackend` used by the integration test
  rig without hardware.
- Three audit events in `crates/rustgate-core/src/audit.rs`:
  `hw_identity_loaded`, `hw_identity_unavailable`, `hw_identity_sign_failed`.
- An mTLS integration test (`crates/rustgate-transport/tests/hw_identity.rs`).

What #856 did **not** deliver — and what #1539 tracks — is the set of *real*
driver bodies: the PKCS#11 C-library wrap, the TPM2 attestation/sealing flow,
and the YubiKey PIV/PIN path. Those pull in heavy, platform-specific
toolchains. The forcing question this ADR answers: **where do those driver
crates live, and how do consumers name the hardware-identity surface without
coupling every TLS listener to a hardware toolchain?**

The constraint that is non-negotiable: `rustgate-transport` is linked by every
listener in the workspace (TLS, WebSocket, MQTT, plaintext). It must **not**
grow a dependency on a PKCS#11 / TPM2 / YubiKey toolchain, and it must stay the
single definition of the trait so no two hardware-identity trait shapes can
diverge.

## Decision

Keep the `HardwareIdentity` trait, its error type, the resolver, and the
reference stub **in `rustgate-transport`** (where they already are). Introduce
a new crate, **`rustgate-tpm`**, as the *driver home*:

1. `rustgate-tpm` re-exports the transport trait surface unchanged —
   `HardwareIdentity`, `HardwareIdentityError`, `HardwareIdentityResolver`,
   `Pkcs11StubBackend`, and `SignatureAlgorithm` (re-exported by transport as
   `HardwareSignatureAlgorithm`). There is exactly **one** trait definition,
   in transport; `rustgate-tpm` does not redeclare it. Downstream driver code
   and consumers depend on `rustgate_tpm::{…}` from a single roadmap crate.
2. `rustgate-tpm` reserves three feature flags — `tpm`, `pkcs11`, `yubikey` —
   each gating a stub module (`tpm.rs`, `pkcs11.rs`, `yubikey.rs`). Today each
   module exposes only a stable `BACKEND_NAME` constant (`"tpm2"`, `"pkcs11"`,
   `"yubikey"`) and a fail-closed `load()` constructor. The real driver bodies
   land in follow-up PRs under #1539.
3. The dependency edge is one-way: `rustgate-tpm` → `rustgate-transport`.
   `rustgate-transport` must never depend on `rustgate-tpm`, so a hardware
   toolchain enabled via a `rustgate-tpm` feature never reaches the base
   transport that every listener links.

The load-bearing code is `crates/rustgate-tpm/src/lib.rs` (the `pub use`
facade) and the three stub modules beside it.

## Fail-closed contract

Every stub constructor returns `HardwareIdentityError::Rejected`. This mirrors,
at the driver-construction boundary, the fail-closed contract the resolver
already enforces at handshake time (when `HardwareIdentity::is_available()`
returns `false`, `HardwareIdentityResolver` fires `hw_identity_unavailable`,
returns `None`, and rustls rejects the handshake — no silent software
fallback). The consequence is that a deployment which enables a driver feature
but has not yet wired its hardware body **cannot** silently substitute a
software key: the backend simply fails to construct. Absence of a real
hardware backend is a hard error, never a downgrade.

## Alternatives considered

- **Put the trait in `rustgate-tpm` and re-export it from transport.** Rejected:
  it inverts the dependency so `rustgate-transport` — linked by every listener —
  would depend on the driver crate, dragging any future PKCS#11/TPM2 toolchain
  into the base transport. It also moves the seam away from the code that
  consumes it (`rustgate_tls::TlsConfig::build_reloadable_server_config`).
- **Put the drivers directly in `rustgate-transport` behind features.** Rejected:
  the heavy, platform-specific hardware toolchains (a PKCS#11 C wrap, a TPM2
  stack) would live in the crate with the widest fan-in in the workspace, and
  the `check-features` powerset job would have to build those toolchains across
  the transport feature matrix. A dedicated crate isolates that build cost.
- **Skip the scaffold; add `rustgate-tpm` only when the first real driver
  lands.** Rejected: the roadmap issue (#1539) and the Device-pillar gap row in
  `docs/zero-trust-alignment.md` need a concrete home to point at, and reserving
  the feature names + the fail-closed stubs now fixes the public API shape so
  the follow-up driver PRs are additive, not API-breaking.
- **Re-implement the trait fresh in `rustgate-tpm`.** Rejected as actively
  harmful: two divergent trait definitions could drift, and the resolver +
  reference stub already exercised by the transport test rig would be orphaned.

## Consequences

- The workspace grows from 39 to 40 crates. The crate tables in `README.md`,
  `docs/architecture.md`, and the count references in `docs/mosa-osmp.md` are
  updated in lockstep (the `cargo-toml-drift` / playbook-drift CI checks
  enforce this).
- New consumers and the future driver PRs import the hardware-identity surface
  from `rustgate_tpm::{…}`. The transport re-exports remain valid, so existing
  code is unaffected.
- The scaffold is purely additive: no existing runtime path changes, and the
  stub constructors fail closed, so nothing can regress at runtime.
- Follow-up driver PRs under #1539 implement `TpmBackend::load` /
  `Pkcs11Backend::load` / `YubiKeyBackend::load` by returning a real
  `impl HardwareIdentity`, add their toolchain dependencies to `rustgate-tpm`
  only (behind the matching feature), and wire the resolver at the server
  setup site. Each such PR should extend this ADR's status or supersede it if
  the trait shape needs to change.
- Maintenance burden to name: the `BACKEND_NAME` constants (`"tpm2"`,
  `"pkcs11"`, `"yubikey"`) must stay stable across the stub→driver transition
  so SIEM correlation rules written against them keep working.

The decision is reversible: because `rustgate-tpm` only re-exports and reserves
feature names, collapsing it back into transport (or relocating the trait)
would be a mechanical move with no behavioral change — but doing so would
reintroduce the toolchain-fan-in problem this ADR exists to avoid.
