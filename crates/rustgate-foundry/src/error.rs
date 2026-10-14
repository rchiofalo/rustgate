// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed failure modes for the Foundry bridge.
//!
//! Every fallible boundary in this crate returns one of these
//! variants. The `Offline` variant is load-bearing — the outbound
//! wiring distinguishes it from other errors and queues the affected
//! upsert for replay rather than dropping the message. All other
//! variants are surfaced to the caller without retry.

use std::time::Duration;

/// Failure modes for the [`crate::bridge::FoundryBridge`] trait and
/// the wiring tasks.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FoundryError {
    /// The bridge is currently disconnected from the Foundry
    /// tenant. The outbound wiring catches this variant
    /// specifically and queues the failed upsert in the offline
    /// replay buffer; every other error variant is surfaced to the
    /// caller without retry.
    #[error("Foundry bridge is offline: {reason}")]
    Offline {
        /// Operator-readable reason — captured from the SDK's
        /// transport-layer error, the WebSocket close frame, the
        /// most recent failed health probe, etc.
        reason: String,
    },

    /// The configured object-type mapping does not list a Foundry
    /// counterpart for the entity-type emitted by the router. The
    /// outbound task surfaces this so unmapped entity types are
    /// visible in metrics rather than silently dropped.
    #[error("no Foundry mapping configured for entity type `{entity_type}`")]
    UnmappedEntityType {
        /// The entity-type tag the router presented (matches
        /// [`rustgate_core::entity::EntityKind::as_str`] or a
        /// codec-specific label for `EntityKind::Unknown`).
        entity_type: String,
    },

    /// Property-map evaluation failed because a configured dotted
    /// path could not be resolved against the entity. Surfaced from
    /// the mapper rather than swallowed so a config typo is visible
    /// at startup the first time a real entity flows through.
    #[error("property path `{path}` did not resolve against the entity")]
    PathNotFound {
        /// The full dotted path that failed (e.g. `position.lat`).
        path: String,
    },

    /// The Foundry SDK reported a typed failure that is neither
    /// `Offline` nor a 4xx-equivalent. Carries the SDK's error
    /// message verbatim — translation is the SDK adapter's
    /// responsibility.
    #[error("Foundry SDK error: {message}")]
    Backend {
        /// SDK message captured at the boundary.
        message: String,
    },

    /// The Foundry tenant rejected the request with the equivalent
    /// of a 4xx — the upsert payload, action arguments, or
    /// subscription filter is structurally invalid. Distinct from
    /// `Backend` so the caller can avoid retry.
    #[error("Foundry rejected the request: {message}")]
    BadRequest {
        /// SDK / HTTP message captured at the boundary.
        message: String,
    },

    /// The action invocation timed out before the Foundry tenant
    /// returned a result. The action MAY still execute on the
    /// Foundry side — callers should treat this as a "result
    /// unknown" rather than as a definite failure.
    #[error("Foundry action timed out after {elapsed:?}")]
    ActionTimeout {
        /// How long the wiring waited before giving up.
        elapsed: Duration,
    },
}

impl FoundryError {
    /// Returns `true` when the variant indicates that a retry on
    /// reconnect is the right next step. Drives the outbound
    /// wiring's offline-queue admission.
    pub fn is_offline(&self) -> bool {
        matches!(self, Self::Offline { .. })
    }
}
