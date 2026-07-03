# rustgate-tpm

Hardware-rooted device-identity **driver home** for rustgate's zero-trust
Device pillar.

## Role in the workspace

The [`HardwareIdentity`](../rustgate-transport/src/hw_identity.rs) trait, its
typed error surface, the fail-closed `HardwareIdentityResolver`, and the
software reference `Pkcs11StubBackend` already ship in
[rustgate-transport](../rustgate-transport/README.md) (delivered under #856).
That placement is deliberate: the trait is a TLS-listener seam and lives next
to the transport it plugs into, so `rustgate-transport` carries no dependency
on a driver crate.

`rustgate-tpm` is the crate where the **real** PKCS#11, TPM2, and YubiKey
backends will land — each behind its own feature flag — without dragging
heavy hardware toolchains into the transport crate that every listener links.

Today it is a thin facade:

1. It **re-exports** the trait surface from `rustgate-transport`
   (`HardwareIdentity`, `HardwareIdentityError`, `HardwareIdentityResolver`,
   `Pkcs11StubBackend`, `HardwareSignatureAlgorithm`) so downstream driver
   code and consumers depend on a single roadmap crate. There is exactly one
   trait definition (in transport) — this crate does not redeclare it, so the
   two can never diverge.
2. It **reserves** the `tpm`, `pkcs11`, and `yubikey` feature flags. Each
   gates a stub module exposing only a stable backend-name constant and a
   fail-closed constructor. The real driver bodies land in follow-up PRs
   under [#1539](https://github.com/rchiofalo/rustgate/issues/1539).

See [ADR 0028](../../docs/adr/0028-hardware-rooted-identity.md) for the
architecture decision behind the trait/driver split.

## Feature flags

| Feature | Gates | Status |
|---|---|---|
| `tpm` | `tpm::TpmBackend` | Reserved stub — `load()` fails closed |
| `pkcs11` | `pkcs11::Pkcs11Backend` | Reserved stub — `load()` fails closed |
| `yubikey` | `yubikey::YubiKeyBackend` | Reserved stub — `load()` fails closed |

All three are empty/no-op today. Enabling one and calling `load()` returns
`HardwareIdentityError::Rejected` — a build with the feature on but the driver
unimplemented **fails closed** rather than silently substituting a software
key.

## Public API surface

- `pub use` re-exports: `HardwareIdentity`, `HardwareIdentityError`,
  `HardwareIdentityResolver`, `Pkcs11StubBackend`, `HardwareSignatureAlgorithm`
- `tpm::{TpmBackend, BACKEND_NAME}` (feature `tpm`)
- `pkcs11::{Pkcs11Backend, BACKEND_NAME}` (feature `pkcs11`)
- `yubikey::{YubiKeyBackend, BACKEND_NAME}` (feature `yubikey`)
