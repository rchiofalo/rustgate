// Copyright © 2026 Roberto Chiofalo.

//! The [`DdsBridge`] trait — integration boundary between the
//! rustgate router and a DDS domain participant.
//!
//! The trait is intentionally small. Three method shapes cover the
//! integration surface this crate ships:
//!
//! - [`DdsBridge::subscribe_topic`] for inbound topic → entity
//!   injection (the NGVA `Navigation` / `Video` / `Alarms` /
//!   `Weapons` topics flow in this direction),
//! - [`DdsBridge::publish_sample`] for outbound entity → topic
//!   projection,
//! - [`DdsBridge::shutdown`] for orderly tear-down so domain
//!   participants do not leak across reconfiguration.
//!
//! Implementors live behind a feature flag: today
//! `crate::mock::MockDdsBridge` (under `dds-mock`) is the reference
//! implementation; a real DDS SDK adapter lands under `dds-real`
//! in a follow-up.

use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::error::DdsError;

/// One sample observed on (or destined for) a DDS topic.
///
/// `payload` is the raw wire body — for the MVP the wiring emits and
/// expects a JSON-encoded property bag so the
/// [`crate::mapper::PropertyMapper`] dotted-path projection is
/// portable across SDKs. A real SDK adapter is free to translate
/// CDR (the canonical DDS wire format) ↔ JSON inside the
/// implementation; the property-map layer above stays unchanged.
///
/// `source_guid` is the DDS DataWriter GUID that produced the
/// sample. Carried through verbatim so the inbound wiring can
/// dedup against the local participant's own GUID and so audit
/// trails can correlate a fanned-out CoT event back to the
/// originating DDS publisher.
#[derive(Debug, Clone)]
pub struct DdsSample {
    /// Topic name (matches a [`crate::config::Subscription::topic`]
    /// entry).
    pub topic: String,
    /// 16-byte DDS GUID of the DataWriter that produced this
    /// sample. The MVP carries it as a raw byte slice so SDK
    /// adapters do not have to depend on a particular GUID type;
    /// the canonical DDS shape is `{prefix: [u8; 12], entityId:
    /// [u8; 4]}`.
    pub source_guid: [u8; 16],
    /// Source timestamp from the DDS sample-info, falling back to
    /// `SystemTime::now()` if the underlying SDK does not surface
    /// one.
    pub timestamp: SystemTime,
    /// Wire body — JSON-encoded property bag for the MVP.
    pub payload: Bytes,
}

/// DDS Reliability QoS policy.
///
/// Mirrors the DDS Reliability kind: best-effort fire-and-forget vs.
/// reliable acknowledged delivery with sample-count tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Reliability {
    /// Samples MAY be dropped on the wire — the publisher does not
    /// retry. Default for telemetry-class topics where stale data
    /// is worthless and a missed sample is replaced by the next.
    #[default]
    BestEffort,
    /// Samples are acknowledged and re-transmitted as needed — the
    /// publisher tracks per-reader history. Default for
    /// command-class topics where a missed sample is a fault.
    Reliable,
}

/// DDS Durability QoS policy.
///
/// Determines whether late-joining readers see prior samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Durability {
    /// Late-joining readers do NOT see samples published before
    /// they joined. The MVP default — minimises participant memory.
    #[default]
    Volatile,
    /// Samples persist on the publisher across reader join /
    /// rejoin within the participant's lifetime. The classical
    /// "session cache" durability level.
    TransientLocal,
    /// Samples persist across publisher restarts (typically backed
    /// by an external durability service). Usually unused in
    /// in-vehicle deployments; included for completeness.
    Transient,
    /// Strongest durability — samples persist indefinitely. Rare
    /// in tactical deployments.
    Persistent,
}

/// DDS History QoS policy.
///
/// Determines how many samples the publisher buffers per writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum History {
    /// Keep only the most-recent N samples. The MVP default for
    /// position telemetry — older samples are stale.
    KeepLast {
        /// Number of samples retained per instance (typically 1
        /// for telemetry, larger for command-class topics where
        /// no sample may be lost).
        depth: u32,
    },
    /// Keep every sample. Combined with `Reliable` reliability
    /// this is the durable-queue shape.
    KeepAll,
}

impl Default for History {
    fn default() -> Self {
        Self::KeepLast { depth: 1 }
    }
}

/// QoS profile applied to a single subscription / publication.
///
/// The shape mirrors the canonical DDS QoS bag — Reliability,
/// Durability, and History are the three policies that matter for
/// in-vehicle telemetry / command traffic. Other DDS QoS policies
/// (Deadline, Liveliness, OwnershipStrength, ResourceLimits, …) live
/// behind future extensions of this struct so a config from this MVP
/// continues to parse against the extended schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct QosProfile {
    /// Reliability kind.
    #[serde(default)]
    pub reliability: Reliability,
    /// Durability kind.
    #[serde(default)]
    pub durability: Durability,
    /// History policy — applied per-instance on the writer side.
    #[serde(default)]
    pub history: History,
}

impl QosProfile {
    /// Convenience constructor for `BestEffort + Volatile + KeepLast(1)`
    /// — the right shape for high-rate telemetry topics
    /// (`Navigation`, `Video`).
    pub const TELEMETRY: Self = Self {
        reliability: Reliability::BestEffort,
        durability: Durability::Volatile,
        history: History::KeepLast { depth: 1 },
    };

    /// Convenience constructor for `Reliable + TransientLocal +
    /// KeepAll` — the right shape for command-class topics
    /// (`Weapons`, `Alarms`) where no sample may be lost.
    pub const COMMAND: Self = Self {
        reliability: Reliability::Reliable,
        durability: Durability::TransientLocal,
        history: History::KeepAll,
    };
}

/// Bidirectional bridge to a DDS domain.
///
/// Implementors MUST be `Send + Sync` so the wiring tasks can hold
/// the bridge as `Arc<dyn DdsBridge>` and dispatch concurrently. The
/// async trait is used here (rather than impl-trait return position)
/// because the wiring stores the bridge in `Arc<dyn DdsBridge>`
/// slots that need to be object-safe.
///
/// Failure-mode contract:
///
/// - Transport-layer failures (participant deleted, every reader /
///   writer torn down) surface as
///   [`DdsError::ParticipantUnavailable`] so the outbound wiring's
///   offline queue is engaged. Implementors that distinguish
///   "currently disconnected, will reconnect" from "permanent
///   failure" SHOULD use `ParticipantUnavailable` for the former.
/// - Malformed payloads surface as [`DdsError::PayloadDecode`].
/// - Anything else, including SDK-internal panics that the adapter
///   has caught, surface as [`DdsError::Backend`].
#[async_trait]
pub trait DdsBridge: Send + Sync {
    /// Subscribe to a single DDS topic.
    ///
    /// Returns an asynchronous stream of [`DdsSample`] events the
    /// inbound wiring drains and converts into routable messages.
    /// The stream is expected to remain open across transient
    /// disconnects — implementors handle reconnection internally
    /// rather than terminating the stream.
    ///
    /// `qos` declares the QoS profile the underlying reader is
    /// created with — implementations match it against the
    /// publisher-side QoS to satisfy the DDS subscription-matching
    /// contract.
    ///
    /// The returned stream is `'static` so the wiring can hand it
    /// to a spawned task that outlives this method's `&self`
    /// borrow.
    async fn subscribe_topic(
        &self,
        topic: &str,
        qos: QosProfile,
    ) -> Result<BoxStream<'static, DdsSample>, DdsError>;

    /// Publish a single DDS sample.
    ///
    /// `topic` selects the DataWriter and `sample` carries the wire
    /// payload (JSON-encoded property bag for the MVP). The
    /// `source_guid` field on the sample is overridden by the
    /// implementation if the underlying SDK uses an internal GUID
    /// scheme — the MVP wiring does not depend on that field on the
    /// outbound path.
    ///
    /// On `DdsError::ParticipantUnavailable` the outbound wiring
    /// queues the sample for replay on reconnect. Every other error
    /// variant is surfaced to the caller and emitted at
    /// `tracing::warn!`.
    async fn publish_sample(&self, topic: &str, sample: DdsSample) -> Result<(), DdsError>;

    /// Tear down the underlying DDS participant.
    ///
    /// Idempotent — calling on an already-shutdown bridge is a
    /// no-op that returns `Ok(())`. The wiring tasks observe their
    /// shutdown notify before calling this so no further publish /
    /// subscribe traffic flows through the bridge after shutdown.
    async fn shutdown(&self) -> Result<(), DdsError>;
}
