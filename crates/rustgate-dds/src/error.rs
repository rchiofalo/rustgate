// Copyright © 2026 Roberto Chiofalo.

//! Typed failure modes for the DDS bridge.
//!
//! Every fallible boundary in this crate returns one of these
//! variants. The `ParticipantUnavailable` variant is load-bearing —
//! the outbound wiring distinguishes it from other errors and queues
//! the affected sample for replay rather than dropping it. All other
//! variants are surfaced to the caller without retry.

/// Failure modes for the [`crate::bridge::DdsBridge`] trait and the
/// wiring tasks.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DdsError {
    /// The DDS domain participant is currently unavailable — the
    /// underlying implementation has lost its handle, the discovery
    /// stack has not finished initialising, or every matched reader
    /// / writer has been deleted. The outbound wiring catches this
    /// variant specifically and queues the failed publish in the
    /// offline replay buffer; every other error variant is surfaced
    /// to the caller without retry.
    #[error("DDS participant unavailable: {reason}")]
    ParticipantUnavailable {
        /// Operator-readable reason — captured from the SDK's
        /// transport-layer error, the most recent failed health
        /// probe, or the participant-deleted lifecycle event.
        reason: String,
    },

    /// The configured subscription does not list a rustgate counterpart
    /// for the topic the wiring observed on the change stream. Surfaced
    /// from the inbound task so unmapped topics are visible in metrics
    /// rather than silently dropped.
    #[error("no rustgate mapping configured for DDS topic `{topic}`")]
    UnmappedTopic {
        /// The topic name the inbound stream surfaced.
        topic: String,
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

    /// The DDS sample payload could not be decoded as the expected
    /// JSON shape. Today the wiring carries DDS samples as
    /// JSON-encoded property bags so the property-map machinery is
    /// portable across SDKs; a real SDK adapter MAY widen this to
    /// CDR (Common Data Representation) by translating CDR ↔ JSON in
    /// the implementation.
    #[error("failed to decode DDS sample payload: {message}")]
    PayloadDecode {
        /// Decode-error message captured at the boundary.
        message: String,
    },

    /// The DDS SDK reported a typed failure that is neither
    /// `ParticipantUnavailable` nor a malformed-payload class. Carries
    /// the SDK's error message verbatim — translation is the SDK
    /// adapter's responsibility.
    #[error("DDS SDK error: {message}")]
    Backend {
        /// SDK message captured at the boundary.
        message: String,
    },
}

impl DdsError {
    /// Returns `true` when the variant indicates that a retry on
    /// reconnect is the right next step. Drives the outbound
    /// wiring's offline-queue admission.
    pub fn is_participant_unavailable(&self) -> bool {
        matches!(self, Self::ParticipantUnavailable { .. })
    }
}
