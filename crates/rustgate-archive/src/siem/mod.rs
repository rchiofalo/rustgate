// Copyright © 2026 Roberto Chiofalo.

//! SIEM forwarding primitives (ADR 0028, Phase 1a).
//!
//! This module holds the payload-format layer for shipping the
//! `rustgate-core::audit` trail into an enterprise SIEM. The current
//! slice is a **pure, dependency-free** ArcSight Common Event Format
//! (CEF) formatter — no socket, no TLS, no `tracing-subscriber` layer,
//! no network I/O. Those live in the deferred syslog-transport slice
//! (ADR 0028, Phase 1b).
//!
//! The whole module is gated behind the off-by-default `siem` feature,
//! so a default build and every existing feature combination are
//! unchanged.
//!
//! # Mapping from the audit trail
//!
//! [`AuditEvent`] mirrors the shape that `rustgate-core::audit` emits:
//! a dot-notation `event_type` (e.g. `"client.rejected"`), an `action`
//! verb, a `result` outcome, and a bounded ordered map of per-event
//! fields (the `extension`). A caller in the Phase 1b transport builds
//! an `AuditEvent` from an intercepted `target="audit"` tracing record
//! and hands it to [`cef::format_cef`].
//!
//! # Log-injection posture
//!
//! `rustgate-core::audit` already sanitizes user-controlled strings at
//! the emission boundary. This formatter re-applies escaping at *its*
//! boundary (CEF header and extension escaping in [`cef`]) so a value
//! that reaches it unescaped still cannot forge a CEF line or inject a
//! newline — defense in depth, matching the house posture.

pub mod cef;

pub use cef::{Severity, format_cef};

/// A structured audit event ready to be rendered into a SIEM payload.
///
/// This is a direct mirror of the field set `rustgate-core::audit`
/// emits: a dot-notation [`Self::event_type`], a human-readable
/// [`Self::name`], an [`Self::action`] verb, a [`Self::result`] outcome,
/// and a bounded ordered list of per-event key/value [`Self::extension`]
/// fields. It is intentionally owned (`String`) so a caller in the
/// deferred transport slice can build it from a borrowed tracing record
/// without lifetime gymnastics.
///
/// The map is a `Vec<(String, String)>` rather than a `HashMap` so the
/// rendered extension is **deterministic** (insertion order preserved),
/// which keeps golden-string tests stable and makes SIEM-side field
/// parsing predictable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditEvent {
    /// Dot-notation audit event type, e.g. `"client.rejected"`. Maps to
    /// the CEF header `signature` (device event class id) field.
    pub event_type: String,
    /// Human-readable event name for the CEF `name` header field. When
    /// empty, [`cef::format_cef`] falls back to [`Self::event_type`].
    pub name: String,
    /// The action verb from the audit record (e.g. `"connect"`).
    /// Emitted as the `act` extension field when non-empty.
    pub action: String,
    /// The outcome string from the audit record (e.g. `"success"`,
    /// `"rejected"`, `"failure"`). Drives the CEF severity mapping via
    /// [`Severity::from_result`] and is emitted as the `outcome`
    /// extension field when non-empty.
    pub result: String,
    /// Ordered per-event fields rendered into the CEF extension, in
    /// insertion order. Keys and values are escaped by the formatter.
    pub extension: Vec<(String, String)>,
}

impl AuditEvent {
    /// Construct an [`AuditEvent`] from the three mandatory audit
    /// fields, with an empty extension. Chain [`Self::with_field`] to
    /// add per-event fields.
    #[must_use]
    pub fn new(
        event_type: impl Into<String>,
        action: impl Into<String>,
        result: impl Into<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            name: String::new(),
            action: action.into(),
            result: result.into(),
            extension: Vec::new(),
        }
    }

    /// Set the human-readable CEF `name` header field. When unset the
    /// formatter falls back to the `event_type`.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Append one extension key/value pair, preserving insertion order.
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extension.push((key.into(), value.into()));
        self
    }
}

#[cfg(all(test, feature = "siem"))]
mod tests {
    use super::*;

    #[test]
    fn builder_preserves_extension_insertion_order() {
        let event = AuditEvent::new("client.rejected", "connect", "rejected")
            .with_name("Client rejected")
            .with_field("peer", "203.0.113.7:44100")
            .with_field("reason", "connection limit reached");

        assert_eq!(event.event_type, "client.rejected");
        assert_eq!(event.name, "Client rejected");
        assert_eq!(event.action, "connect");
        assert_eq!(event.result, "rejected");
        assert_eq!(
            event.extension,
            vec![
                ("peer".to_string(), "203.0.113.7:44100".to_string()),
                ("reason".to_string(), "connection limit reached".to_string()),
            ]
        );
    }
}
