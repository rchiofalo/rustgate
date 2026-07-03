// Copyright © 2026 Roberto Chiofalo.

//! PKCS#11-backed hardware identity — reserved stub.
//!
//! Gated behind the `pkcs11` feature. The real body (loading a PKCS#11
//! C library, opening a session against a token slot, and signing in
//! the HSM) lands in a follow-up PR under #1539. Until then
//! [`Pkcs11Backend::load`] is a documented no-op that **fails closed**:
//! it returns [`HardwareIdentityError::Rejected`]. The software
//! reference implementation used by the test rig is
//! [`crate::Pkcs11StubBackend`] — this module is the *real-driver*
//! seat, distinct from that stub.

use crate::HardwareIdentityError;

/// Backend slug emitted to audit events once the driver lands. Distinct
/// from the reference stub's `"pkcs11-stub"` slug so SIEM rules can
/// tell a real token apart from the software mirror.
pub const BACKEND_NAME: &str = "pkcs11";

/// PKCS#11 token-backed hardware-identity backend (reserved).
///
/// Constructing one is not yet possible: [`Self::load`] fails closed.
/// The struct is intentionally empty — the real fields (loaded module
/// handle, session, key object handle) arrive with the driver body.
#[derive(Debug)]
#[non_exhaustive]
pub struct Pkcs11Backend;

impl Pkcs11Backend {
    /// Attempt to load the PKCS#11 module and open a session against
    /// the configured token slot.
    ///
    /// # Errors
    ///
    /// Always returns [`HardwareIdentityError::Rejected`] in this
    /// scaffold — the driver is not yet implemented, and failing
    /// closed is the correct behavior for a hardware-rooted identity
    /// that cannot be produced.
    pub fn load() -> Result<Self, HardwareIdentityError> {
        Err(HardwareIdentityError::Rejected {
            detail: "PKCS#11 backend not yet implemented (tracked under #1539); \
                     failing closed rather than substituting a software key"
                .to_string(),
        })
    }
}
