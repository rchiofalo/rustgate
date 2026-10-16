// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! ROS 2 wire compatibility on top of [`crate::real::RealDdsBridge`].
//!
//! ROS 2 nodes communicate over DDS-RTPS with two ROS 2-specific
//! conventions:
//!
//! 1. **Topic name mangling.** A ROS 2 topic `/chatter` is published
//!    on the DDS topic `rt/chatter` (`rt` = ROS Topic). Services and
//!    actions use `rq` / `rr` / `rs` prefixes.
//! 2. **Message wire format.** Payloads are CDR-encoded structures
//!    matching the corresponding `.msg` IDL definition. The
//!    serialization is identical to plain DDS CDR; the only
//!    discriminator is the structure layout.
//!
//! The [`ros2-client`] crate handles both conventions on top of
//! `rustdds::DomainParticipant`. This module wires that crate into
//! rustgate so an operator can publish from rustgate into a ROS 2
//! graph and subscribe to ROS 2 topics back into rustgate, all
//! sharing the same DDS participant as the raw DDS path.
//!
//! ## Sharing one participant
//!
//! Both raw DDS and ROS 2 paths share a single
//! `rustdds::DomainParticipant` (see [`Ros2Bridge::from_real`]). This
//! is required for discovery — two participants in the same process
//! cannot reliably discover each other on the same machine when the
//! loopback multicast group is also used by the rest of the host's
//! DDS traffic. Sharing the participant also halves the discovery
//! traffic on the wire.
//!
//! ## Wire-format restriction
//!
//! ROS 2 messages are typed at compile time — every published or
//! subscribed message must round-trip through a `Serialize +
//! Deserialize` struct whose CDR layout matches the ROS 2 IDL
//! definition. The [`Ros2Bridge`] wiring uses a simple
//! [`Ros2RawMessage`] wrapper that carries an opaque byte payload;
//! operators interoperating with a specific ROS 2 message type
//! (e.g. `geometry_msgs/Twist`) define a matching Rust struct in
//! their own crate and use the `ros2-client` API directly. The
//! wrapper is enough for the property-bag bridge mode rustgate uses
//! today.

#![cfg(feature = "dds-real")]

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use ros2_client::{
    Context, DEFAULT_PUBLISHER_QOS, MessageTypeName, Name, Node, NodeName, NodeOptions, Publisher,
    Subscription,
};
use rustdds::{DomainParticipant, Topic};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::bridge::{DdsBridge, DdsSample, QosProfile};
use crate::error::DdsError;
use crate::real::RealDdsBridge;

/// ROS 2 wire-format payload used by rustgate's ROS 2 bridge.
///
/// Carries a single opaque byte field so a property-bag-shaped
/// payload (the same JSON encoding the raw-DDS path uses) rides
/// through unchanged. Operators that want strongly-typed ROS 2
/// message interop define their own matching Rust struct and use
/// `ros2-client` directly — the bridge in this module is the
/// shared-participant glue, not a universal type adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ros2RawMessage {
    /// Opaque payload bytes.
    pub data: Vec<u8>,
}

/// Per-topic ROS 2 configuration.
///
/// A ROS 2 topic is identified by its name + message type name; the
/// `ros2-client` crate concatenates the two into the DDS topic name
/// and DDS type name respectively, applying the mandatory `rt/`
/// prefix on the topic and the standard ROS 2 IDL type name on the
/// type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ros2TopicConfig {
    /// ROS 2 topic name including the leading `/` (e.g. `/chatter`).
    pub topic: String,
    /// ROS 2 message package (e.g. `std_msgs`).
    pub package: String,
    /// ROS 2 message type name (e.g. `String`).
    pub message_type: String,
}

impl Ros2TopicConfig {
    /// Construct a config for `/chatter` carrying `std_msgs/String` —
    /// the canonical ROS 2 "hello world" topic.
    #[must_use]
    pub fn chatter() -> Self {
        Self {
            topic: "/chatter".to_string(),
            package: "std_msgs".to_string(),
            message_type: "String".to_string(),
        }
    }
}

/// Internal handle for one ROS 2 publisher and subscriber pair on
/// the same topic.
struct TopicSlot {
    publisher: Publisher<Ros2RawMessage>,
}

/// ROS 2 bridge — a [`DdsBridge`] implementation that routes through
/// a `ros2_client::Node` so messages appear on the wire under the
/// `rt/` prefix and are discoverable by every ROS 2 graph tool
/// (`ros2 node list`, `ros2 topic echo`, `ros2 bag record`).
///
/// Construction goes through [`Ros2Bridge::from_real`] so the bridge
/// shares its DDS participant with the raw [`RealDdsBridge`] — that
/// way a single rustgate process can serve both DDS-native peers and
/// ROS 2 graph tools without running two parallel RTPS stacks.
pub struct Ros2Bridge {
    /// Owned ROS 2 context. Held to keep the underlying participant
    /// alive for the bridge's lifetime even if no callers retain a
    /// handle to the `Node`; an `_context` prefix would suppress the
    /// dead-code warning but the field needs to be a real Drop owner.
    // justification: lifetime anchor for the ROS 2 graph context.
    // `Context` must outlive `Node` per ros2-client's drop order
    // contract, so the field is genuinely live as a Drop-on-Self
    // owner even though no method reads it after construction.
    #[allow(dead_code)]
    context: Context,
    node: Arc<RwLock<Node>>,
    topics: RwLock<std::collections::HashMap<String, Arc<TopicSlot>>>,
    node_name: String,
    namespace: String,
}

impl std::fmt::Debug for Ros2Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ros2Bridge")
            .field("node_name", &self.node_name)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl Ros2Bridge {
    /// Construct a ROS 2 bridge sharing the rustdds participant
    /// owned by `real`. The node appears in the ROS 2 graph as
    /// `<namespace>/<node_name>` (default `/rustgate/rustgate-router`
    /// when `namespace` and `node_name` are empty).
    pub fn from_real(
        real: &RealDdsBridge,
        namespace: impl Into<String>,
        node_name: impl Into<String>,
    ) -> Result<Self, DdsError> {
        let participant = real.participant().clone();
        Self::from_participant(participant, namespace, node_name)
    }

    /// Construct a ROS 2 bridge wrapping an existing rustdds
    /// participant. Useful when the caller has its own
    /// participant-management story (cluster-wide singleton, FFI
    /// boundary, …) and wants to layer a ROS 2 surface on top.
    pub fn from_participant(
        participant: DomainParticipant,
        namespace: impl Into<String>,
        node_name: impl Into<String>,
    ) -> Result<Self, DdsError> {
        let ns = {
            let raw = namespace.into();
            if raw.is_empty() {
                "/rustgate".to_string()
            } else {
                raw
            }
        };
        let name_str = {
            let raw = node_name.into();
            if raw.is_empty() {
                "rustgate_router".to_string()
            } else {
                raw
            }
        };

        let context =
            Context::from_domain_participant(participant).map_err(|e| DdsError::Backend {
                message: format!("ros2-client Context from participant: {e:?}"),
            })?;
        let node_id = NodeName::new(&ns, &name_str).map_err(|e| DdsError::Backend {
            message: format!("invalid ROS 2 node name `{ns}/{name_str}`: {e}"),
        })?;
        let node =
            context
                .new_node(node_id, NodeOptions::new())
                .map_err(|e| DdsError::Backend {
                    message: format!("ros2-client new_node: {e:?}"),
                })?;
        Ok(Self {
            context,
            node: Arc::new(RwLock::new(node)),
            topics: RwLock::new(std::collections::HashMap::new()),
            node_name: name_str,
            namespace: ns,
        })
    }

    /// Spawn the ROS 2 node's spinner task. ROS 2 discovery,
    /// parameters, and rosout require the spinner to run for the
    /// node to be visible to other ROS 2 graph nodes.
    ///
    /// The returned handle resolves when the spinner exits — drop
    /// it to terminate the spinner alongside the bridge.
    pub async fn spawn_spinner(&self) -> Result<tokio::task::JoinHandle<()>, DdsError> {
        let mut node = self.node.write().await;
        let spinner = node.spinner().map_err(|e| DdsError::Backend {
            message: format!("ros2-client spinner: {e:?}"),
        })?;
        Ok(tokio::spawn(async move {
            if let Err(e) = spinner.spin().await {
                tracing::warn!(target: "dds", error = ?e, "ros2 spinner exited with error");
            }
        }))
    }

    /// Build a ROS 2 topic handle from a [`Ros2TopicConfig`].
    fn build_topic(&self, node: &mut Node, cfg: &Ros2TopicConfig) -> Result<Topic, DdsError> {
        let name =
            Name::new("/", cfg.topic.trim_start_matches('/')).map_err(|e| DdsError::Backend {
                message: format!("ros2 topic name `{}`: {e}", cfg.topic),
            })?;
        let ty = MessageTypeName::new(&cfg.package, &cfg.message_type);
        node.create_topic(&name, ty, &DEFAULT_PUBLISHER_QOS)
            .map_err(|e| DdsError::Backend {
                message: format!("ros2 create_topic: {e:?}"),
            })
    }

    /// Get-or-create a ROS 2 publisher for the given config.
    async fn get_or_create_publisher(
        &self,
        cfg: &Ros2TopicConfig,
    ) -> Result<Arc<TopicSlot>, DdsError> {
        let key = format!("{}/{}/{}", cfg.topic, cfg.package, cfg.message_type);
        if let Some(slot) = self.topics.read().await.get(&key) {
            return Ok(slot.clone());
        }
        let mut node = self.node.write().await;
        let topic = self.build_topic(&mut node, cfg)?;
        let publisher: Publisher<Ros2RawMessage> =
            node.create_publisher(&topic, None)
                .map_err(|e| DdsError::Backend {
                    message: format!("ros2 create_publisher: {e:?}"),
                })?;
        drop(node);
        let slot = Arc::new(TopicSlot { publisher });
        let _ = self.topics.write().await.insert(key, slot.clone());
        Ok(slot)
    }

    /// Subscribe to a ROS 2 topic. Returns a sample stream identical
    /// in shape to [`DdsBridge::subscribe_topic`] so the wiring tasks
    /// treat a ROS 2 subscription identically to a raw-DDS one.
    ///
    /// The returned stream owns the underlying `Subscription` — the
    /// `async_stream()` method on ros2-client's `Subscription` borrows
    /// `&self` and so cannot be returned past the function boundary;
    /// we use `futures::stream::unfold` over `async_take()` to fold
    /// the subscription into the stream state.
    pub async fn subscribe_ros2(
        &self,
        cfg: &Ros2TopicConfig,
        _qos: QosProfile,
    ) -> Result<BoxStream<'static, DdsSample>, DdsError> {
        let mut node = self.node.write().await;
        let topic = self.build_topic(&mut node, cfg)?;
        let subscription: Subscription<Ros2RawMessage> = node
            .create_subscription(&topic, None)
            .map_err(|e| DdsError::Backend {
                message: format!("ros2 create_subscription: {e:?}"),
            })?;
        drop(node);

        let topic_name = cfg.topic.clone();
        let stream = futures::stream::unfold(
            (subscription, topic_name),
            |(sub, topic_name)| async move {
                match sub.async_take().await {
                    Ok((msg, info)) => {
                        let sample = DdsSample {
                            topic: topic_name.clone(),
                            source_guid: guid_to_bytes(rustdds::GUID::from(info.publisher_gid())),
                            timestamp: ros2_timestamp_to_system(info.source_timestamp()),
                            payload: Bytes::from(msg.data),
                        };
                        Some((sample, (sub, topic_name)))
                    }
                    Err(e) => {
                        tracing::warn!(target: "dds", topic = %topic_name, error = ?e, "ros2 subscription read error; terminating stream");
                        None
                    }
                }
            },
        );
        Ok(Box::pin(stream))
    }
}

#[async_trait]
impl DdsBridge for Ros2Bridge {
    /// `topic` is interpreted as the ROS 2 topic name. The package
    /// and message type are read from the topic config registered
    /// out-of-band via [`Ros2Bridge::subscribe_ros2`] — operators that
    /// only need the canonical `std_msgs/String` shape can call
    /// `subscribe_topic` with a topic like `/chatter` and the bridge
    /// falls back to that default.
    async fn subscribe_topic(
        &self,
        topic: &str,
        qos: QosProfile,
    ) -> Result<BoxStream<'static, DdsSample>, DdsError> {
        let cfg = Ros2TopicConfig {
            topic: topic.to_string(),
            package: "std_msgs".to_string(),
            message_type: "String".to_string(),
        };
        self.subscribe_ros2(&cfg, qos).await
    }

    async fn publish_sample(&self, topic: &str, sample: DdsSample) -> Result<(), DdsError> {
        let cfg = Ros2TopicConfig {
            topic: topic.to_string(),
            package: "std_msgs".to_string(),
            message_type: "String".to_string(),
        };
        let slot = self.get_or_create_publisher(&cfg).await?;
        let msg = Ros2RawMessage {
            data: sample.payload.to_vec(),
        };
        slot.publisher
            .async_publish(msg)
            .await
            .map_err(|e| DdsError::Backend {
                message: format!("ros2 async_publish on `{topic}`: {e:?}"),
            })?;
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), DdsError> {
        self.topics.write().await.clear();
        Ok(())
    }
}

fn guid_to_bytes(guid: rustdds::GUID) -> [u8; 16] {
    guid.to_bytes()
}

fn ros2_timestamp_to_system(ts: Option<ros2_client::ROSTime>) -> SystemTime {
    // ROSTime is signed nanoseconds since the Unix epoch. Out-of-range values
    // (and a missing source timestamp) fall back to the local clock, as before.
    ts.and_then(|t| {
        let nanos = t.to_nanos();
        let offset = std::time::Duration::from_nanos(nanos.unsigned_abs());
        if nanos >= 0 {
            SystemTime::UNIX_EPOCH.checked_add(offset)
        } else {
            SystemTime::UNIX_EPOCH.checked_sub(offset)
        }
    })
    .unwrap_or_else(SystemTime::now)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ros_time_converts_to_system_time() {
        let t = ros2_client::ROSTime::from_nanos(1_700_000_000_123_456_789);
        assert_eq!(
            ros2_timestamp_to_system(Some(t)),
            SystemTime::UNIX_EPOCH + std::time::Duration::new(1_700_000_000, 123_456_789)
        );
        let before_epoch = ros2_client::ROSTime::from_nanos(-1_500_000_000);
        assert_eq!(
            ros2_timestamp_to_system(Some(before_epoch)),
            SystemTime::UNIX_EPOCH - std::time::Duration::from_millis(1_500)
        );
    }

    #[test]
    fn chatter_config_has_canonical_shape() {
        let cfg = Ros2TopicConfig::chatter();
        assert_eq!(cfg.topic, "/chatter");
        assert_eq!(cfg.package, "std_msgs");
        assert_eq!(cfg.message_type, "String");
    }

    #[test]
    fn ros2_raw_message_round_trip() {
        let original = Ros2RawMessage {
            data: vec![1, 2, 3, 4, 5],
        };
        let bytes = serde_json::to_vec(&original).unwrap();
        let back: Ros2RawMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.data, original.data);
    }
}
