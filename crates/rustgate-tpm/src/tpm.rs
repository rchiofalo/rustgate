// Copyright © 2026 Roberto Chiofalo.

//! TPM2-backed hardware identity — reserved stub.
//!
//! Gated behind the `tpm` feature. The real body (TPM2 key sealing and
//! attestation via the platform TPM stack) lands in a follow-up PR
//! under #1539. Until then [`TpmBackend::load`] is a documented no-op
//! that **fails closed**: it returns
//! [`HardwareIdentityError::Rejected`] so an operator who enables the
//! feature without the driver cannot silently fall back to a software
//! key.

use crate::HardwareIdentityError;

/// Backend slug emitted to audit events once the driver lands. Kept
/// stable here so SIEM correlation rules can be written against it
/// before the implementation exists.
pub const BACKEND_NAME: &str = "tpm2";

/// TPM2 hardware-identity backend (reserved).
///
/// Constructing one is not yet possible: [`Self::load`] fails closed.
/// The struct is intentionally empty — the real fields (TPM context
/// handle, sealed key blob, PCR policy) arrive with the driver body.
#[derive(Debug)]
#[non_exhaustive]
pub struct TpmBackend;

impl TpmBackend {
    /// Attempt to open the platform TPM2 and load the sealed device
    /// identity.
    ///
    /// # Errors
    ///
    /// Always returns [`HardwareIdentityError::Rejected`] in this
    /// scaffold — the driver is not yet implemented, and failing
    /// closed is the correct behavior for a hardware-rooted identity
    /// that cannot be produced.
    pub fn load() -> Result<Self, HardwareIdentityError> {
        Err(HardwareIdentityError::Rejected {
            detail: "TPM2 backend not yet implemented (tracked under #1539); \
                     failing closed rather than substituting a software key"
                .to_string(),
        })
    }
}
