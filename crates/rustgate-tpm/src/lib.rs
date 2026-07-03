// Copyright © 2026 Roberto Chiofalo.

//! Hardware-rooted device identity — the driver home for rustgate's
//! zero-trust Device pillar.
//!
//! # Why this crate exists
//!
//! The [`HardwareIdentity`] trait, its typed error surface, the
//! fail-closed [`HardwareIdentityResolver`], and the software
//! reference [`Pkcs11StubBackend`] already ship in
//! [`rustgate_transport::hw_identity`] (delivered under #856). That
//! placement is deliberate: the trait is a TLS-listener seam and lives
//! next to the transport it plugs into, so `rustgate-transport` has no
//! dependency on a driver crate.
//!
//! `rustgate-tpm` is the **driver home** — the crate where the real
//! PKCS#11, TPM2, and YubiKey backends will land, each behind its own
//! feature flag, without dragging heavy hardware toolchains into the
//! transport crate that every listener links. Today it is a thin
//! facade:
//!
//! 1. It **re-exports** the trait surface from `rustgate-transport` so
//!    downstream driver code and consumers can depend on
//!    `rustgate_tpm::{HardwareIdentity, HardwareIdentityError,
//!    HardwareIdentityResolver, Pkcs11StubBackend,
//!    HardwareSignatureAlgorithm}` from a single roadmap crate. There
//!    is exactly one trait definition (in transport) — this crate does
//!    not redeclare it, so the two can never diverge.
//! 2. It **reserves** the `tpm`, `pkcs11`, and `yubikey` feature flags.
//!    Each gates a stub module ([`tpm`], [`pkcs11`], [`yubikey`]) that
//!    currently exposes only a stable backend-name constant and a
//!    fail-closed constructor. The real driver bodies land in
//!    follow-up PRs under #1539.
//!
//! See [`docs/adr/0028-hardware-rooted-identity.md`](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0028-hardware-rooted-identity.md)
//! for the architecture decision behind the trait/driver split.
//!
//! # Fail-closed contract
//!
//! Every stub constructor in this crate returns
//! [`HardwareIdentityError::Rejected`]. A build that has enabled a
//! driver feature but not yet wired its hardware body therefore
//! **fails closed** — it can never silently substitute a software key
//! for a hardware-rooted one. This mirrors the fail-closed resolver
//! contract in [`rustgate_transport::hw_identity`]: absence of a real
//! backend is a hard error, not a fallback.

// The public facade: one re-export of the trait surface that already
// ships in the transport crate. Consumers and future driver modules
// depend on these names from here.
pub use rustgate_transport::{
    HardwareIdentity, HardwareIdentityError, HardwareIdentityResolver, HardwareSignatureAlgorithm,
    Pkcs11StubBackend,
};

#[cfg(feature = "tpm")]
pub mod tpm;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

#[cfg(feature = "yubikey")]
pub mod yubikey;

#[cfg(test)]
mod tests {
    use super::*;

    /// The re-exported reference stub still round-trips a PEM identity
    /// through the facade — proves the facade wires the transport
    /// trait surface, not a divergent copy.
    #[test]
    fn facade_reexports_reference_stub() {
        // A malformed PEM must be rejected (fail-closed), exercising
        // the re-exported constructor and error type without needing a
        // real key-pair or a rustls crypto provider.
        let err = Pkcs11StubBackend::from_pem("not-a-pem", "not-a-pem")
            .expect_err("garbage PEM must not construct a backend");
        assert!(
            matches!(err, HardwareIdentityError::Rejected { .. }),
            "expected Rejected, got {err:?}"
        );
        // The re-exported slug is stable for SIEM correlation.
        assert_eq!(Pkcs11StubBackend::BACKEND_NAME, "pkcs11-stub");
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn tpm_stub_fails_closed() {
        let err = tpm::TpmBackend::load().expect_err("tpm driver stub must fail closed");
        assert!(matches!(err, HardwareIdentityError::Rejected { .. }));
        assert_eq!(tpm::BACKEND_NAME, "tpm2");
    }

    #[cfg(feature = "pkcs11")]
    #[test]
    fn pkcs11_stub_fails_closed() {
        let err = pkcs11::Pkcs11Backend::load().expect_err("pkcs11 driver stub must fail closed");
        assert!(matches!(err, HardwareIdentityError::Rejected { .. }));
        assert_eq!(pkcs11::BACKEND_NAME, "pkcs11");
    }

    #[cfg(feature = "yubikey")]
    #[test]
    fn yubikey_stub_fails_closed() {
        let err =
            yubikey::YubiKeyBackend::load().expect_err("yubikey driver stub must fail closed");
        assert!(matches!(err, HardwareIdentityError::Rejected { .. }));
        assert_eq!(yubikey::BACKEND_NAME, "yubikey");
    }
}
