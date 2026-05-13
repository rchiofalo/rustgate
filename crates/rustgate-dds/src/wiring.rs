// Copyright © 2026 Roberto Chiofalo.

//! Outbound and inbound wiring between the rustgate router and a
//! [`crate::bridge::DdsBridge`] implementation.
//!
//! The wiring is intentionally split into two background tasks so a
//! real DDS SDK adapter can be plugged in without restructuring
//! either:
//!
//! - **Inbound** ([`spawn_inbound`]) — for every configured
//!   `[[dds.subscriptions]]` entry, the wiring opens a topic
//!   subscription via
//!   [`crate::bridge::DdsBridge::subscribe_topic`], reverses the
//!   property-map projection through
//!   [`crate::mapper::PropertyMapper::dds_to_entity_overlay`],
//!   builds a [`rustgate_core::message::RoutableMessage`], and calls
//!   [`rustgate_router::Router::route`]. The exact `RoutableMessage`
//!   shape is intentionally minimal — the inbound side does not
//!   have a sender identity from DDS, so the `source` is synthesised
//!   as a service identity tagged `"dds"` and the destination is
//!   `Broadcast`. Tightening that to a per-mapping configurable
//!   destination is a contained follow-up.
//! - **Outbound** ([`spawn_outbound`]) — the server hands the wiring
//!   an `mpsc::Receiver<RoutableMessage>` that the router feeds via
//!   a `set_on_message_delivered` (or equivalent) observer. The task
//!   drains the receiver, looks up the per-`entity-kind` mapping,
//!   projects the entity onto a JSON property bag via
//!   [`crate::mapper::PropertyMapper`], and invokes
//!   [`crate::bridge::DdsBridge::publish_sample`]. On
//!   [`crate::error::DdsError::ParticipantUnavailable`] the publish
//!   is queued in the in-memory FIFO; on the next successful publish
//!   the queue drains in order with last-writer-wins semantics.
//!
//! # Offline-replay queue
//!
//! The outbound task carries an in-memory FIFO of pending publishes
//! capped at [`OFFLINE_QUEUE_CAPACITY`]. On overflow the oldest
//! entry is dropped — no on-disk persistence today (deferred until
//! the real SDK lands; the existing
//! `rustgate_router::store_forward` machinery is the natural sink
//! and the swap is a contained change once the SDK is wired). The
//! queue is drained at the head of each successful publish: if the
//! current publish succeeds, the wiring iterates the queue and
//! re-issues each entry. Last-writer-wins is enforced by collapsing
//! entries whose `(topic, uid)` matches an entry later in the queue.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::entity::{Entity, EntityKind};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::tasks::{SubsystemHandle, spawn_background};
use rustgate_router::Router;
use serde_json::Value;
use tokio::sync::{Notify, mpsc};
use tokio_stream::StreamExt;
use tracing::{debug, info, warn};

use crate::bridge::{DdsBridge, DdsSample};
use crate::config::{DdsConfig, Subscription};
use crate::error::DdsError;
use crate::mapper::{EntityOverlay, PropertyMapper};

/// Maximum number of pending publishes the in-memory offline replay
/// queue holds before evicting the oldest entry.
///
/// Sized for the single-vehicle deployment shape described by the
/// MVP — operator deployments that need a larger window swap to the
/// `rustgate_router::store_forward` redb-backed queue when the
/// real SDK lands. The capacity is a public constant so tests
/// (and the real-SDK adapter) can pin against it without
/// reaching for an internal field.
pub const OFFLINE_QUEUE_CAPACITY: usize = 4096;

/// Source-protocol tag emitted on every inbound RoutableMessage so
/// downstream filters / dedup / audit can distinguish DDS-originated
/// traffic from CoT, MAVLink, etc. Mirrors the
/// `SOURCE_FEDERATION` / `SOURCE_FOUNDRY` constants used elsewhere.
pub const SOURCE_DDS: &str = "dds";

/// Synthetic identity emitted on every inbound RoutableMessage. The
/// router's audit and dedup paths expect a non-empty `cn`; the
/// `"dds"` value is the service-identity convention used elsewhere
/// in the workspace for non-mTLS-authenticated ingress.
pub const DDS_SERVICE_CN: &str = "dds";

/// Handle for the outbound task. Carries the channel the router
/// pushes routed messages onto and the subsystem handle for
/// graceful shutdown.
#[derive(Debug)]
pub struct OutboundHandle {
    /// Sender the router (or test harness) clones and pushes
    /// routed messages onto. Bounded — backpressure is intentional.
    pub tx: mpsc::Sender<RoutableMessage>,
    /// Subsystem handle for graceful shutdown.
    pub subsystem: SubsystemHandle,
}

/// Spawn the outbound wiring task.
///
/// Returns an [`OutboundHandle`] whose `tx` is the channel the
/// caller wires into the router's egress observer. The `subsystem`
/// field drives graceful shutdown via
/// [`rustgate_core::tasks::stop_subsystem`].
///
/// The task is parameterised on the channel capacity so deployments
/// that route a heavy entity firehose can bias the bounded channel
/// upward without re-compiling.
pub fn spawn_outbound(
    bridge: Arc<dyn DdsBridge>,
    config: DdsConfig,
    channel_capacity: usize,
) -> OutboundHandle {
    let (tx, rx) = mpsc::channel(channel_capacity.max(1));
    let shutdown = Arc::new(Notify::new());
    let shutdown_task = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        run_outbound(bridge, config, rx, shutdown_task).await;
    });
    OutboundHandle {
        tx,
        subsystem: SubsystemHandle::new(shutdown, task),
    }
}

/// Spawn the inbound wiring task.
///
/// One subscription is opened per configured `[[dds.subscriptions]]`
/// entry. The returned [`SubsystemHandle`] is canonical: drive
/// shutdown via [`rustgate_core::tasks::stop_subsystem`].
pub fn spawn_inbound(
    bridge: Arc<dyn DdsBridge>,
    config: DdsConfig,
    router: Arc<Router>,
) -> SubsystemHandle {
    let shutdown = Arc::new(Notify::new());
    let shutdown_task = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        run_inbound(bridge, config, router, shutdown_task).await;
    });
    SubsystemHandle::new(shutdown, task)
}

/// Internal: outbound loop. Drains the receiver until shutdown,
/// projecting and publishing each message. On `ParticipantUnavailable`
/// the sample is queued; on success the queue is drained.
async fn run_outbound(
    bridge: Arc<dyn DdsBridge>,
    config: DdsConfig,
    mut rx: mpsc::Receiver<RoutableMessage>,
    shutdown: Arc<Notify>,
) {
    let bindings = build_outbound_bindings(&config.subscriptions);
    let mut offline_queue: VecDeque<PendingPublish> = VecDeque::new();
    info!(bindings = bindings.len(), "dds outbound task started");
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => {
                info!(pending = offline_queue.len(), "dds outbound task draining");
                break;
            }
            msg = rx.recv() => {
                let Some(msg) = msg else { break };
                handle_outbound(&bridge, &bindings, &mut offline_queue, msg).await;
            }
        }
    }
}

/// Build the per-`entity-kind` binding table from the config.
///
/// The lookup is by `entity-kind` (the
/// [`rustgate_core::entity::EntityKind::as_str`] tag), so the
/// outbound dispatch is a single hash + clone. Bindings are cheap
/// to construct (a `Vec<PropertyMap>` clone) so we materialise
/// them at startup. The first matching subscription wins on
/// duplicate `entity-kind` entries; documented as deliberate so an
/// operator who configures two subscriptions for the same kind on
/// different topics gets deterministic dispatch.
fn build_outbound_bindings(subs: &[Subscription]) -> HashMap<String, BoundTopic> {
    let mut table: HashMap<String, BoundTopic> = HashMap::new();
    for s in subs {
        let _ = table
            .entry(s.entity_kind.clone())
            .or_insert_with(|| BoundTopic {
                topic: s.topic.clone(),
                mapper: PropertyMapper::new(s.property_map.clone()),
            });
    }
    table
}

/// Per-`entity-kind` mapper plus the DDS topic it dispatches to.
/// Exposed as `pub` because the test-only [`testing`] re-export
/// surfaces it across the crate boundary — the ordinary call path
/// goes through [`dispatch_entity`] and callers do not interact with
/// this type directly.
#[derive(Debug, Clone)]
pub struct BoundTopic {
    topic: String,
    mapper: PropertyMapper,
}

/// One queued publish. Held in the offline replay buffer until the
/// bridge transitions back to available and the head of the queue
/// can be re-issued. Exposed as `pub` for the same reason as
/// [`BoundTopic`]: the test-only [`testing`] module surfaces the
/// queue type across the crate boundary.
#[derive(Debug, Clone)]
pub struct PendingPublish {
    topic: String,
    /// Stable key used for last-writer-wins collapse. Matches the
    /// entity's `uid` at the moment the message was processed.
    uid: String,
    properties: Value,
}

/// Project a single message through the binding table and either
/// publish or queue.
//
// The function is `async` even though the body has no awaits today
// because the `Entity` attach (#847 step 2) will turn the body into
// a `dispatch_entity(...).await` call. Keeping the async signature
// here avoids a churn-only diff later. The `unused_async` lint is
// suppressed with a justification accordingly.
// justification: scaffold awaiting #847 step 2 — once `Entity` is
// attached to `RoutableMessage`, this function awaits
// `dispatch_entity` and the lint becomes self-clearing. Suppressing
// here keeps the function shape stable through that landing.
#[allow(clippy::unused_async)]
async fn handle_outbound(
    bridge: &Arc<dyn DdsBridge>,
    bindings: &HashMap<String, BoundTopic>,
    offline_queue: &mut VecDeque<PendingPublish>,
    msg: RoutableMessage,
) {
    // The wiring expects an Entity to ride alongside the message.
    // Today the router does not yet attach an `Entity` to
    // `RoutableMessage` (#847 step 2 — the registry exists, the
    // attach lands separately). Until then, the wiring is a
    // pass-through: the test harness drives the outbound task
    // directly with manufactured `Entity` envelopes via
    // `dispatch_entity`. The router-driven path goes through this
    // function and produces a `tracing::debug!` until the attach
    // lands.
    let _ = (bridge, bindings, offline_queue, msg);
    debug!(
        "dds outbound received a RoutableMessage without an attached Entity; \
         this code path is the deliberate scaffold awaiting #847 step 2"
    );
}

/// Project an `Entity` and dispatch it through the bridge. This is
/// the function the test harness calls to drive end-to-end behaviour
/// today. Once the router attaches an `Entity` to every
/// `RoutableMessage`, the wiring's per-message handler dispatches
/// into here.
pub async fn dispatch_entity(
    bridge: &Arc<dyn DdsBridge>,
    bindings: &HashMap<String, BoundTopic>,
    offline_queue: &mut VecDeque<PendingPublish>,
    entity: &Entity,
) -> Result<(), DdsError> {
    let kind_tag = entity.kind.as_str().to_string();
    let Some(bound) = bindings.get(&kind_tag) else {
        return Err(DdsError::UnmappedTopic { topic: kind_tag });
    };
    let properties = bound.mapper.entity_to_dds(entity)?;
    let topic = bound.topic.clone();
    let uid = entity.uid.clone();
    let payload = serde_json::to_vec(&properties).map_err(|e| DdsError::PayloadDecode {
        message: e.to_string(),
    })?;
    let sample = DdsSample {
        topic: topic.clone(),
        source_guid: [0; 16],
        timestamp: entity.timestamp,
        payload: Bytes::from(payload),
    };
    match bridge.publish_sample(&topic, sample).await {
        Ok(()) => {
            // Successful publish — drain any queued offline work
            // before returning so the next message is processed
            // against an empty queue. Failure inside the drain
            // re-queues the head; the loop ends as soon as the
            // bridge returns ParticipantUnavailable again.
            drain_offline_queue(bridge, offline_queue).await;
            Ok(())
        }
        Err(DdsError::ParticipantUnavailable { reason }) => {
            warn!(
                topic = %topic,
                uid = %uid,
                reason = %reason,
                queue_depth = offline_queue.len(),
                "dds publish queued; participant unavailable"
            );
            enqueue_with_lww(
                offline_queue,
                PendingPublish {
                    topic,
                    uid,
                    properties,
                },
            );
            Ok(())
        }
        Err(other) => {
            warn!(error = %other, "dds publish failed");
            Err(other)
        }
    }
}

/// Push a pending publish onto the queue, applying last-writer-wins
/// against any earlier entry with the same `(topic, uid)`. On
/// overflow the oldest entry is evicted.
fn enqueue_with_lww(queue: &mut VecDeque<PendingPublish>, pending: PendingPublish) {
    queue.retain(|existing| !(existing.topic == pending.topic && existing.uid == pending.uid));
    while queue.len() >= OFFLINE_QUEUE_CAPACITY {
        let _ = queue.pop_front();
    }
    queue.push_back(pending);
}

/// Drain queued publishes until the queue is empty or the bridge
/// returns ParticipantUnavailable again. Re-queues the failing head
/// before returning.
async fn drain_offline_queue(bridge: &Arc<dyn DdsBridge>, queue: &mut VecDeque<PendingPublish>) {
    while let Some(head) = queue.pop_front() {
        let payload = match serde_json::to_vec(&head.properties) {
            Ok(b) => Bytes::from(b),
            Err(e) => {
                warn!(error = %e, "dds replay payload encode failed; dropping");
                continue;
            }
        };
        let sample = DdsSample {
            topic: head.topic.clone(),
            source_guid: [0; 16],
            timestamp: SystemTime::now(),
            payload,
        };
        match bridge.publish_sample(&head.topic, sample).await {
            Ok(()) => {
                debug!(
                    topic = %head.topic,
                    uid = %head.uid,
                    remaining = queue.len(),
                    "dds offline-queue drained one"
                );
            }
            Err(DdsError::ParticipantUnavailable { reason }) => {
                warn!(
                    topic = %head.topic,
                    uid = %head.uid,
                    reason = %reason,
                    "dds still unavailable; re-queueing"
                );
                queue.push_front(head);
                return;
            }
            Err(other) => {
                warn!(error = %other, "dds replay publish failed; dropping");
                // Non-Unavailable errors are not retried — the
                // payload is malformed (PayloadDecode) or the SDK
                // is rejecting it (Backend). Logging at warn keeps
                // the visibility without the queue ballooning
                // indefinitely.
            }
        }
    }
}

/// Internal: inbound loop. Opens one subscription per configured
/// topic and routes every sample.
async fn run_inbound(
    bridge: Arc<dyn DdsBridge>,
    config: DdsConfig,
    router: Arc<Router>,
    shutdown: Arc<Notify>,
) {
    info!("dds inbound task started");
    for sub in &config.subscriptions {
        let mapper = PropertyMapper::new(sub.property_map.clone());
        let topic = sub.topic.clone();
        let entity_kind = sub.entity_kind.clone();
        let qos = sub.qos;
        let bridge_for_sub = Arc::clone(&bridge);
        let router_for_sub = Arc::clone(&router);
        let shutdown_for_sub = Arc::clone(&shutdown);
        spawn_background("dds-inbound-subscription", async move {
            run_inbound_subscription(
                bridge_for_sub,
                topic,
                entity_kind,
                qos,
                mapper,
                router_for_sub,
                shutdown_for_sub,
            )
            .await;
        });
    }
    shutdown.notified().await;
    info!("dds inbound task stopping");
}

async fn run_inbound_subscription(
    bridge: Arc<dyn DdsBridge>,
    topic: String,
    entity_kind: String,
    qos: crate::bridge::QosProfile,
    mapper: PropertyMapper,
    router: Arc<Router>,
    shutdown: Arc<Notify>,
) {
    let mut stream = match bridge.subscribe_topic(&topic, qos).await {
        Ok(s) => s,
        Err(e) => {
            warn!(topic = %topic, error = %e, "dds subscribe failed");
            return;
        }
    };
    info!(topic = %topic, "dds inbound subscription opened");
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => break,
            sample = stream.next() => {
                let Some(sample) = sample else {
                    debug!(topic = %topic, "dds sample stream closed");
                    break;
                };
                if let Some(msg) = sample_to_message(&sample, &entity_kind, &mapper) {
                    router.route(msg).await;
                }
            }
        }
    }
}

/// Project a single DDS sample into a `RoutableMessage` the router
/// can fan out.
///
/// The destination is `Broadcast` and the source identity is the
/// service-identity convention `DDS_SERVICE_CN`. Tightening to a
/// per-mapping `Destination::Group(...)` is a follow-up.
fn sample_to_message(
    sample: &DdsSample,
    entity_kind: &str,
    mapper: &PropertyMapper,
) -> Option<RoutableMessage> {
    let props: Value = match serde_json::from_slice(&sample.payload) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                topic = %sample.topic,
                error = %e,
                "dds inbound dropped: payload not valid JSON"
            );
            return None;
        }
    };
    let overlay = mapper.dds_to_entity_overlay(&props);
    let entity = build_entity_from_overlay(entity_kind, sample, overlay);
    let payload = serde_json::to_vec(&entity).unwrap_or_default();
    // `Identity::plaintext` is the right constructor here — DDS-
    // ingested traffic has no client certificate fingerprint, and
    // the service-identity convention used elsewhere in the
    // workspace (federation inbound, NATS bridge, Foundry inbound)
    // is the same shape. `DDS_SERVICE_CN` is a 3-byte ASCII constant
    // so validation cannot fail in practice; the wiring still
    // propagates the `Result` and drops the message rather than
    // panicking if a future change to the constant ever violates
    // the contract.
    let source = match Identity::plaintext(DDS_SERVICE_CN.to_string(), Default::default()) {
        Ok(id) => id,
        Err(e) => {
            // playbook-drift-ok: this is an internal-invariant
            // diagnostic, not an external rejection — dropping a
            // message because the synthetic service-identity
            // constant could not be reconstructed is a never-fires
            // contract failure, not an authn / authz / rate-limit
            // event that belongs in the audit trail.
            warn!(error = %e, "dds inbound dropped: synthetic identity could not be constructed");
            return None;
        }
    };
    Some(RoutableMessage {
        source,
        destination: Destination::Broadcast,
        payload: Bytes::from(payload),
        metadata: Metadata::new(
            SystemTime::now(),
            SOURCE_DDS.to_string(),
            // `MessageType::Other` carries a free-form label so the
            // router's audit / metrics layers can distinguish
            // DDS-injected traffic from CoT / chat / position
            // shapes without dropping it into the catch-all
            // `unknown` bucket.
            MessageType::Other("dds".to_string()),
        ),
    })
}

/// Compose an `Entity` from the overlay produced by the property
/// map plus fall-backs derived from the sample itself (the
/// hex-rendered source GUID when the property map did not bind
/// `uid`).
fn build_entity_from_overlay(
    entity_kind: &str,
    sample: &DdsSample,
    overlay: EntityOverlay,
) -> Entity {
    let kind = match entity_kind {
        "aircraft" => EntityKind::Aircraft,
        "ground" => EntityKind::Ground,
        "marine" => EntityKind::Marine,
        "sensor" => EntityKind::Sensor,
        "track" => EntityKind::Track,
        "munition" => EntityKind::Munition,
        other => EntityKind::Unknown(other.to_string()),
    };
    let uid = overlay
        .uid
        .unwrap_or_else(|| guid_to_hex(&sample.source_guid));
    Entity {
        uid,
        kind,
        position: overlay.position,
        velocity: overlay.velocity,
        timestamp: sample.timestamp,
        callsign: overlay.callsign,
        mil_std_2525_sidc: overlay.mil_std_2525_sidc,
        attributes: overlay.attributes,
        taskings: Default::default(),
        files: Default::default(),
    }
}

/// Render a 16-byte DDS GUID as a 32-char lowercase hex string. Used
/// as the fallback UID when no `uid` rule is bound on the property
/// map. Format matches the canonical DDSI-RTPS GUID rendering.
fn guid_to_hex(guid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in guid {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Test-only re-export so `tests/wiring.rs` can drive the offline-
/// queue + LWW path directly without owning a router.
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// Construct a wiring-internal binding table directly from the
    /// config slice. Mirrors the in-task path but is reachable from
    /// integration tests.
    pub fn build_bindings_for_test(subs: &[Subscription]) -> HashMap<String, BoundTopic> {
        super::build_outbound_bindings(subs)
    }

    /// Fresh empty offline queue for tests.
    pub fn fresh_queue() -> VecDeque<PendingPublish> {
        VecDeque::new()
    }

    /// Re-export of the dispatch helper.
    pub async fn dispatch_for_test(
        bridge: &Arc<dyn DdsBridge>,
        bindings: &HashMap<String, BoundTopic>,
        offline_queue: &mut VecDeque<PendingPublish>,
        entity: &Entity,
    ) -> Result<(), DdsError> {
        super::dispatch_entity(bridge, bindings, offline_queue, entity).await
    }

    /// Inspect the current queue depth.
    pub fn queue_depth(queue: &VecDeque<PendingPublish>) -> usize {
        queue.len()
    }

    /// Inspect the queue contents (topic, uid) pairs in order.
    pub fn queue_keys(queue: &VecDeque<PendingPublish>) -> Vec<(String, String)> {
        queue
            .iter()
            .map(|p| (p.topic.clone(), p.uid.clone()))
            .collect()
    }

    /// Render a GUID exactly as the wiring does for fallback UIDs.
    pub fn guid_to_hex_for_test(guid: &[u8; 16]) -> String {
        super::guid_to_hex(guid)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_collapses_lww_on_same_uid() {
        let mut q = VecDeque::new();
        enqueue_with_lww(
            &mut q,
            PendingPublish {
                topic: "t".into(),
                uid: "1".into(),
                properties: Value::Null,
            },
        );
        enqueue_with_lww(
            &mut q,
            PendingPublish {
                topic: "t".into(),
                uid: "2".into(),
                properties: Value::Null,
            },
        );
        // Re-queue uid=1 → first entry retained order-wise becomes
        // the (newer) version; the previous uid=1 is dropped.
        enqueue_with_lww(
            &mut q,
            PendingPublish {
                topic: "t".into(),
                uid: "1".into(),
                properties: serde_json::json!("newer"),
            },
        );
        assert_eq!(q.len(), 2);
        // Order: uid=2 (older queued), then the newer uid=1.
        assert_eq!(q[0].uid, "2");
        assert_eq!(q[1].uid, "1");
        assert_eq!(q[1].properties, serde_json::json!("newer"));
    }

    #[test]
    fn enqueue_evicts_oldest_on_overflow() {
        let mut q = VecDeque::new();
        for i in 0..OFFLINE_QUEUE_CAPACITY {
            enqueue_with_lww(
                &mut q,
                PendingPublish {
                    topic: "t".into(),
                    uid: format!("{i}"),
                    properties: Value::Null,
                },
            );
        }
        assert_eq!(q.len(), OFFLINE_QUEUE_CAPACITY);
        // One more — should evict the oldest.
        enqueue_with_lww(
            &mut q,
            PendingPublish {
                topic: "t".into(),
                uid: "overflow".into(),
                properties: Value::Null,
            },
        );
        assert_eq!(q.len(), OFFLINE_QUEUE_CAPACITY);
        assert_eq!(q.front().unwrap().uid, "1"); // "0" was evicted
        assert_eq!(q.back().unwrap().uid, "overflow");
    }

    #[test]
    fn guid_to_hex_renders_canonical_lowercase() {
        let guid = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0xff,
        ];
        assert_eq!(guid_to_hex(&guid), "000102030405060708090a0b0c0d0eff");
    }

    #[test]
    fn build_outbound_bindings_first_wins_on_duplicate_kind() {
        let subs = vec![
            Subscription {
                topic: "first".into(),
                entity_kind: "ground".into(),
                qos: Default::default(),
                property_map: vec![],
            },
            Subscription {
                topic: "second".into(),
                entity_kind: "ground".into(),
                qos: Default::default(),
                property_map: vec![],
            },
        ];
        let table = build_outbound_bindings(&subs);
        assert_eq!(table.len(), 1);
        assert_eq!(table["ground"].topic, "first");
    }
}
