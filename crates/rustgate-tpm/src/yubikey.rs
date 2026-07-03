// Copyright © 2026 Roberto Chiofalo.

//! YubiKey-backed hardware identity — reserved stub.
//!
//! Gated behind the `yubikey` feature. The real body (PIV applet
//! selection, PIN entry, and on-key signing over the CCID interface)
//! lands in a follow-up PR under #1539. Until then
//! [`YubiKeyBackend::load`] is a documented no-op that **fails
//! closed**: it returns [`HardwareIdentityError::Rejected`] so a build
//! that enables the feature without the driver cannot silently fall
//! back to a software key.

use crate::HardwareIdentityError;

/// Backend slug emitted to audit events once the driver lands. Kept
/// stable here so SIEM correlation rules can be written against it
/// before the implementation exists.
pub const BACKEND_NAME: &str = "yubikey";

/// YubiKey PIV-backed hardware-identity backend (reserved).
///
/// Constructing one is not yet possible: [`Self::load`] fails closed.
/// The struct is intentionally empty — the real fields (CCID handle,
/// PIV slot id, cached PIN policy) arrive with the driver body.
#[derive(Debug)]
#[non_exhaustive]
pub struct YubiKeyBackend;

impl YubiKeyBackend {
    /// Attempt to select the PIV applet on an attached YubiKey and
    /// bind the configured signing slot.
    ///
    /// # Errors
    ///
    /// Always returns [`HardwareIdentityError::Rejected`] in this
    /// scaffold — the driver is not yet implemented, and failing
    /// closed is the correct behavior for a hardware-rooted identity
    /// that cannot be produced.
    pub fn load() -> Result<Self, HardwareIdentityError> {
        Err(HardwareIdentityError::Rejected {
            detail: "YubiKey backend not yet implemented (tracked under #1539); \
                     failing closed rather than substituting a software key"
                .to_string(),
        })
    }
}
