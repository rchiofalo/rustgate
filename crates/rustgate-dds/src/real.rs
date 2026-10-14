// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Real DDS bridge backed by the pure-Rust **rustdds** RTPS stack.
//!
//! Implements the [`crate::bridge::DdsBridge`] trait against
//! `rustdds::DomainParticipant`, giving rustgate a production wire
//! connection to any DDS-RTPS interoperable peer — NGVA / VICTORY
//! vehicle buses, Eclipse Cyclone DDS, RTI Connext, FastDDS, and any
//! ROS 2 graph (see [`crate::ros2`] for the ROS 2-flavoured surface).
//!
//! ## Wire format
//!
//! Samples ride a CDR-encoded wrapper struct ([`DdsPayloadWire`])
//! around the property-bag bytes the [`crate::mapper::PropertyMapper`]
//! emits. The wrapper preserves the source GUID and source timestamp
//! so the inbound wiring can dedup against its own publishes and the
//! audit trail can correlate a fanned-out CoT event back to the
//! originating publisher.
//!
//! ## QoS
//!
//! The [`QosProfile`] supplied by the wiring is mapped onto rustdds's
//! `QosPolicies` bag at participant + publisher + subscriber + topic
//! creation time. Reliability, Durability, and History are the three
//! policies that matter for in-vehicle telemetry / command traffic;
//! other DDS QoS policies (Deadline, Liveliness, OwnershipStrength,
//! ResourceLimits) ride through with rustdds's defaults and are a
//! contained follow-up.
//!
//! ## Lifecycle
//!
//! Participants are dropped when the [`RealDdsBridge`] is dropped —
//! rustdds's `DomainParticipant` is a smart-pointer handle that tears
//! down the underlying transport when the last clone is released.
//! [`DdsBridge::shutdown`] clears the per-topic state map so the topic
//! / publisher / subscriber / reader / writer chain is dropped
//! eagerly; the participant itself follows when no further clones
//! exist (the wiring tasks hold their own clones via the streams they
//! were handed).
//!
//! ## What is deliberately absent
//!
//! - **DDS Security plugin configuration.** Deferred to a follow-up;
//!   rustdds's Security plugin is pre-1.0 and the in-vehicle deployments
//!   we target today rely on link-layer security (IPsec / MACsec / RF
//!   crypto) rather than DDS-level auth.
//! - **DataReader filtering predicates and content-filtered topics.**
//!   The mapping layer handles filtering on the rustgate side rather
//!   than pushing it into the DDS subscription matching contract.
//! - **DDS instance lifecycle on keyed topics.** Every topic this
//!   bridge creates is [`TopicKind::NoKey`] — keyed topics with
//!   per-instance history are a future extension when a deployment
//!   needs them.

#![cfg(feature = "dds-real")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration as StdDuration, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use parking_lot::RwLock;
use rustdds::dds::CreateError;
use rustdds::no_key::{DataReader, DataWriter};
use rustdds::policy::{Durability, History, Reliability};
use rustdds::serialization::{CDRDeserializerAdapter, CDRSerializerAdapter};
use rustdds::{DomainParticipant, QosPolicies, QosPolicyBuilder, Topic, TopicKind};
use serde::{Deserialize, Serialize};

use crate::bridge::{
    DdsBridge, DdsSample, Durability as BridgeDurability, History as BridgeHistory, QosProfile,
    Reliability as BridgeReliability,
};
use crate::error::DdsError;

/// DDS type-name advertised on every topic this bridge creates.
///
/// Distinct from the rustgate JSON-property-bag shape because DDS
/// requires the type name be registered on the topic before any
/// reader / writer can attach. Keeping it stable means a future
/// schema migration (CDR-IDL-shaped payloads, ROS 2 message types)
/// can land as a parallel topic-type advertisement rather than a
/// breaking wire change.
pub const TYPE_NAME: &str = "rustgate::DdsSample";

/// CDR-serialised wire wrapper for a [`DdsSample`].
///
/// Encodes the source GUID (split into two `u64`s so CDR's natural
/// alignment is honoured without a length-prefix gymnastics), source
/// timestamp split into seconds + nanos, and the property-bag bytes
/// the property mapper emits. The byte-slice payload rides a single
/// CDR length prefix; readers do not have to know the inner JSON
/// shape to unmarshal.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DdsPayloadWire {
    /// High 8 bytes of the 16-byte source GUID.
    source_guid_high: u64,
    /// Low 8 bytes of the 16-byte source GUID.
    source_guid_low: u64,
    /// Source timestamp — seconds since Unix epoch.
    timestamp_secs: u64,
    /// Source timestamp — sub-second fraction in nanoseconds.
    timestamp_nanos: u32,
    /// Property-bag bytes (the JSON encoding emitted by
    /// [`crate::mapper::PropertyMapper::project`]).
    payload: Vec<u8>,
}

impl DdsPayloadWire {
    fn from_sample(sample: &DdsSample) -> Self {
        let mut hi = [0u8; 8];
        let mut lo = [0u8; 8];
        hi.copy_from_slice(&sample.source_guid[..8]);
        lo.copy_from_slice(&sample.source_guid[8..]);
        let elapsed = sample
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            source_guid_high: u64::from_be_bytes(hi),
            source_guid_low: u64::from_be_bytes(lo),
            timestamp_secs: elapsed.as_secs(),
            timestamp_nanos: elapsed.subsec_nanos(),
            payload: sample.payload.to_vec(),
        }
    }

    fn into_sample(self, topic: String) -> DdsSample {
        let mut guid = [0u8; 16];
        guid[..8].copy_from_slice(&self.source_guid_high.to_be_bytes());
        guid[8..].copy_from_slice(&self.source_guid_low.to_be_bytes());
        let timestamp =
            SystemTime::UNIX_EPOCH + StdDuration::new(self.timestamp_secs, self.timestamp_nanos);
        DdsSample {
            topic,
            source_guid: guid,
            timestamp,
            payload: Bytes::from(self.payload),
        }
    }
}

/// Map our [`QosProfile`] shape to rustdds's `QosPolicies` bag.
///
/// Pulled out as a free function so the same mapping serves the
/// participant, publisher, subscriber, and topic creation calls
/// (rustdds applies QoS at every level and the four uses must agree
/// for subscription matching to fire).
pub(crate) fn map_qos(qos: QosProfile) -> QosPolicies {
    let reliability = match qos.reliability {
        BridgeReliability::BestEffort => Reliability::BestEffort,
        BridgeReliability::Reliable => Reliability::Reliable {
            max_blocking_time: rustdds::Duration::ZERO,
        },
    };
    let durability = match qos.durability {
        BridgeDurability::Volatile => Durability::Volatile,
        BridgeDurability::TransientLocal => Durability::TransientLocal,
        BridgeDurability::Transient => Durability::Transient,
        BridgeDurability::Persistent => Durability::Persistent,
    };
    let history = match qos.history {
        BridgeHistory::KeepLast { depth } => History::KeepLast {
            depth: depth as i32,
        },
        BridgeHistory::KeepAll => History::KeepAll,
    };
    QosPolicyBuilder::new()
        .reliability(reliability)
        .durability(durability)
        .history(history)
        .build()
}

/// Lazy per-topic state inside the participant.
///
/// A [`Topic`] is created at first reference and reused across every
/// subscribe / publish on the same topic name. The reader is
/// per-`subscribe_topic` call (rustdds streams consume the reader,
/// so a second subscriber needs its own DataReader). The writer is
/// per-topic and cached after the first publish so the topic-and-
/// writer creation handshake is paid once per topic across the
/// lifetime of the bridge.
struct TopicHandle {
    topic: Topic,
    qos: QosProfile,
    writer: RwLock<Option<DataWriter<DdsPayloadWire, CDRSerializerAdapter<DdsPayloadWire>>>>,
}

/// Real DDS bridge backed by rustdds.
///
/// Construct with [`RealDdsBridge::new`] supplying the DDS domain ID
/// (ROS 2 defaults to 0; NGVA / VICTORY deployments typically
/// allocate a domain per platform).
pub struct RealDdsBridge {
    participant: DomainParticipant,
    domain_id: u16,
    topics: RwLock<HashMap<String, Arc<TopicHandle>>>,
}

impl std::fmt::Debug for RealDdsBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `TopicHandle` holds a `DataWriter` whose Debug isn't
        // straightforward to forward; print the topic-count summary
        // and the domain ID instead.
        let topic_count = self.topics.read().len();
        f.debug_struct("RealDdsBridge")
            .field("domain_id", &self.domain_id)
            .field("topic_count", &topic_count)
            .finish_non_exhaustive()
    }
}

impl RealDdsBridge {
    /// Construct a new bridge attached to the given DDS domain.
    ///
    /// Returns [`DdsError::ParticipantUnavailable`] if rustdds cannot
    /// bring up the domain participant — typically because the
    /// configured discovery port is in use, multicast is disabled on
    /// the loopback interface, or the system has run out of UDP
    /// sockets.
    pub fn new(domain_id: u16) -> Result<Self, DdsError> {
        let participant =
            DomainParticipant::new(domain_id).map_err(|e| DdsError::ParticipantUnavailable {
                reason: format!("participant create failed on domain {domain_id}: {e}"),
            })?;
        Ok(Self {
            participant,
            domain_id,
            topics: RwLock::new(HashMap::new()),
        })
    }

    /// DDS domain ID this bridge is bound to.
    #[must_use]
    pub fn domain_id(&self) -> u16 {
        self.domain_id
    }

    /// Borrow the underlying rustdds participant.
    ///
    /// Exposed so the [`crate::ros2`] module can construct a
    /// `ros2_client::Context::from_domain_participant(...)` without
    /// the bridge having to know what a ROS 2 Node is.
    #[must_use]
    pub fn participant(&self) -> &DomainParticipant {
        &self.participant
    }

    fn get_or_create_topic(
        &self,
        name: &str,
        qos: QosProfile,
    ) -> Result<Arc<TopicHandle>, DdsError> {
        if let Some(handle) = self.topics.read().get(name) {
            return Ok(handle.clone());
        }
        let mut topics = self.topics.write();
        if let Some(handle) = topics.get(name) {
            return Ok(handle.clone());
        }
        let topic = self
            .participant
            .create_topic(
                name.to_string(),
                TYPE_NAME.to_string(),
                &map_qos(qos),
                TopicKind::NoKey,
            )
            .map_err(|e: CreateError| DdsError::Backend {
                message: format!("create_topic `{name}`: {e}"),
            })?;
        let handle = Arc::new(TopicHandle {
            topic,
            qos,
            writer: RwLock::new(None),
        });
        let _ = topics.insert(name.to_string(), handle.clone());
        Ok(handle)
    }

    fn ensure_writer(&self, handle: &TopicHandle) -> Result<(), DdsError> {
        if handle.writer.read().is_some() {
            return Ok(());
        }
        let mut guard = handle.writer.write();
        if guard.is_some() {
            return Ok(());
        }
        let publisher = self
            .participant
            .create_publisher(&map_qos(handle.qos))
            .map_err(|e: CreateError| DdsError::Backend {
                message: format!("create_publisher: {e}"),
            })?;
        let writer = publisher
            .create_datawriter_no_key::<DdsPayloadWire, CDRSerializerAdapter<DdsPayloadWire>>(
                &handle.topic,
                None,
            )
            .map_err(|e: CreateError| DdsError::Backend {
                message: format!("create_datawriter: {e}"),
            })?;
        *guard = Some(writer);
        Ok(())
    }
}

#[async_trait]
impl DdsBridge for RealDdsBridge {
    async fn subscribe_topic(
        &self,
        topic: &str,
        qos: QosProfile,
    ) -> Result<BoxStream<'static, DdsSample>, DdsError> {
        let handle = self.get_or_create_topic(topic, qos)?;
        let subscriber =
            self.participant
                .create_subscriber(&map_qos(qos))
                .map_err(|e: CreateError| DdsError::Backend {
                    message: format!("create_subscriber: {e}"),
                })?;
        let reader: DataReader<DdsPayloadWire, CDRDeserializerAdapter<DdsPayloadWire>> = subscriber
            .create_datareader_no_key(&handle.topic, None)
            .map_err(|e: CreateError| DdsError::Backend {
                message: format!("create_datareader: {e}"),
            })?;
        let topic_name = topic.to_string();
        let stream = reader.async_bare_sample_stream();
        // `async_bare_sample_stream` yields `Result<DdsPayloadWire,
        // ReadError>`. A decode error here means the wire schema
        // changed under us (or a non-rustgate publisher landed on
        // the topic); log it and drop the sample so the stream
        // stays open across transient malformed traffic.
        let mapped = stream.filter_map(move |item| {
            let topic_name = topic_name.clone();
            async move {
                match item {
                    Ok(wire) => Some(wire.into_sample(topic_name)),
                    Err(e) => {
                        tracing::warn!(target: "dds", topic = %topic_name, error = ?e, "real DDS sample decode failed");
                        None
                    }
                }
            }
        });
        Ok(Box::pin(mapped))
    }

    async fn publish_sample(&self, topic: &str, sample: DdsSample) -> Result<(), DdsError> {
        // Use the QoS recorded for the topic. If the topic has not
        // been seen before (publish-only deployment), create it with
        // the default profile.
        let handle = self.get_or_create_topic(topic, QosProfile::default())?;
        self.ensure_writer(&handle)?;
        let wire = DdsPayloadWire::from_sample(&sample);
        // Use the synchronous `write` path so we don't hold the
        // parking_lot read guard across an await point — rustdds'
        // `write` is fire-and-forget (the publisher queues the
        // sample and the RTPS worker thread fans it out), which is
        // the right shape for the property-bag use case. Reliable
        // QoS still backs writes by the per-reader history buffer
        // inside rustdds, so reliability is preserved without
        // blocking the caller here.
        let writer_guard = handle.writer.read();
        let writer = writer_guard.as_ref().ok_or_else(|| DdsError::Backend {
            message: "writer slot empty after ensure_writer".to_string(),
        })?;
        writer.write(wire, None).map_err(|e| DdsError::Backend {
            message: format!("write on `{topic}`: {e:?}"),
        })?;
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), DdsError> {
        // Drop per-topic state so the topic / writer / reader chain
        // closes immediately. The participant itself is reference-
        // counted internally by rustdds and tears down its transport
        // when the last clone (held by any in-flight streams) drops.
        self.topics.write().clear();
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn payload_wire_round_trip_preserves_fields() {
        let original = DdsSample {
            topic: "rustgate.test.Topic".to_string(),
            source_guid: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
            timestamp: SystemTime::UNIX_EPOCH + StdDuration::new(1_700_000_000, 123_456_789),
            payload: Bytes::from_static(b"{\"lat\":40.0,\"lon\":-74.0}"),
        };
        let wire = DdsPayloadWire::from_sample(&original);
        let back = wire.into_sample(original.topic.clone());
        assert_eq!(back.topic, original.topic);
        assert_eq!(back.source_guid, original.source_guid);
        assert_eq!(back.timestamp, original.timestamp);
        assert_eq!(back.payload, original.payload);
    }

    #[test]
    fn map_qos_telemetry_profile() {
        let qos = map_qos(QosProfile::TELEMETRY);
        // We can't introspect rustdds's QosPolicies fields here
        // because they're not all `pub`, but we can at least confirm
        // the builder accepts the shape without panicking.
        let _ = qos;
    }

    #[test]
    fn map_qos_command_profile() {
        let qos = map_qos(QosProfile::COMMAND);
        let _ = qos;
    }

    #[test]
    fn map_qos_keep_all_history() {
        let profile = QosProfile {
            reliability: BridgeReliability::Reliable,
            durability: BridgeDurability::TransientLocal,
            history: BridgeHistory::KeepAll,
        };
        let _ = map_qos(profile);
    }
}
