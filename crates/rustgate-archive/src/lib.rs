// Copyright © 2026 Roberto Chiofalo.

//! Encrypted hash-chained archives for tamper-evident audit and
//! store-and-forward.
//!
//! Extracted from `rustgate-core` and `rustgate-server` (#892) to scope
//! the ChaCha20-Poly1305 / Argon2 / HKDF / SHA-256 dependency footprint
//! to the consumers that actually use it (the server binary, the HTTP
//! egress DLQ, and the cross-domain guard).
//!
//! Modules:
//!
//! * [`audit_chain`] — SHA-256 hash-chained append-only writer and
//!   verifier (forensic trail when SIEM is unavailable or compromised).
//! * [`encrypted`] — streaming ChaCha20-Poly1305 AEAD writer/reader with
//!   per-chunk AAD and a sealed terminator.
//! * [`archive`] — JSONL CoT event archiver with optional encryption.
//! * [`archive_rotation`] — size- and time-based retention task for the
//!   archive directory.
//! * `siem` — (feature `siem`, off by default) pure ArcSight CEF
//!   payload formatter for shipping the audit trail to an enterprise
//!   SIEM (ADR 0028, Phase 1a). No I/O; the syslog transport that
//!   consumes it is deferred to Phase 1b.
//!
//! ## Wire format
//!
//! Every on-disk byte sequence (encrypted archive header + chunks,
//! audit-log JSON record shape, anchor-file format) is unchanged from
//! the pre-extraction layout — this crate is a pure relocation. Files
//! written by `rustgate-server` ≤ 0.7 remain readable.

pub mod archive;
pub mod archive_rotation;
pub mod audit_chain;
pub mod encrypted;
#[cfg(feature = "siem")]
pub mod siem;

pub use archive::*;
pub use archive_rotation::*;
pub use audit_chain::*;
pub use encrypted::*;
#[cfg(feature = "siem")]
pub use siem::{AuditEvent, Severity, format_cef};

#[cfg(test)]
mod tests {
    //! Compile-only re-export shape pin (closes #892). Verifies that
    //! the public types from each child module are reachable through
    //! the crate root, which is what consumer crates rely on after
    //! the move from `rustgate_core::{encrypted,audit_chain}` and
    //! `rustgate_server::{archive,archive_rotation}`.

    #[test]
    fn re_exports_compose_into_a_single_archive_namespace() {
        use crate::{HashChainWriter, KeyRing};
        let _ = std::mem::size_of::<KeyRing>();
        let _ = std::mem::size_of::<HashChainWriter<std::fs::File>>();
    }
}
