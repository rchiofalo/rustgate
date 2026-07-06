// Copyright © 2026 Roberto Chiofalo.

//! Outbound and inbound wiring between the rustgate router and a
//! [`crate::bridge::FoundryBridge`] implementation.
//!
//! The wiring is intentionally split into two background tasks so
//! the partner-gated SDK adapter can be plugged in without
//! restructuring either:
//!
//! - **Outbound** ([`spawn_outbound`]) — the server hands the
//!   wiring an `mpsc::Receiver<RoutableMessage>` that the router
//!   feeds via a `set_on_message_delivered` (or equivalent)
//!   observer. The task drains the receiver, looks up the
//!   per-`entity-type` mapping, projects the entity onto a Foundry
//!   property bag via [`crate::mapper::PropertyMapper`], and
//!   invokes [`crate::bridge::FoundryBridge::upsert_object`]. On
//!   [`crate::error::FoundryError::Offline`] the upsert is queued
//!   in the in-memory FIFO; on the next successful upsert the
//!   queue drains in order with last-writer-wins semantics.
//! - **Inbound** ([`spawn_inbound`]) — for every configured
//!   `[[object-types]]` entry, the wiring opens a change-stream
//!   subscription via
//!   [`crate::bridge::FoundryBridge::subscribe_changes`], reverses
//!   the property-map projection through
//!   [`crate::mapper::PropertyMapper::foundry_to_entity_overlay`],
//!   builds a [`rustgate_core::message::RoutableMessage`], and
//!   calls [`rustgate_router::Router::route`]. The exact
//!   `RoutableMessage` shape is intentionally minimal — the
//!   inbound side does not have a sender identity from Foundry, so
//!   the `source` is synthesised as a service identity tagged
//!   `"foundry"` and the destination is `Broadcast`. Tightening
//!   that to a per-mapping configurable destination is a
//!   contained follow-up.
//!
//! # Offline-replay queue
//!
//! The outbound task carries an in-memory FIFO of pending upserts
//! capped at [`OFFLINE_QUEUE_CAPACITY`]. On overflow the oldest
//! entry is dropped — no on-disk persistence today (deferred until
//! the real SDK lands; the existing
//! `rustgate_router::store_forward` machinery is the natural sink
//! and the swap is a contained change once the SDK is wired). The
//! queue is drained at the head of each successful upsert: if the
//! current upsert succeeds, the wiring iterates the queue and
//! re-issues each entry. Last-writer-wins is enforced by
//! collapsing entries whose `(type_id, uid)` matches an entry
//! later in the queue.

use std::collections::VecDeque;
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

use crate::bridge::{ChangeType, FoundryBridge, ObjectChange};
use crate::config::{FoundryConfig, ObjectTypeMapping};
use crate::error::FoundryError;
use crate::mapper::{EntityOverlay, PropertyMapper};

/// Maximum number of pending upserts the in-memory offline replay
/// queue holds before evicting the oldest entry.
///
/// Sized for the single-server deployment shape described by the
/// MVP — operator deployments that need a larger window swap to the
/// `rustgate_router::store_forward` redb-backed queue when the
/// real SDK lands. The capacity is a public constant so tests
/// (and the real-SDK adapter) can pin against it without
/// reaching for an internal field.
pub const OFFLINE_QUEUE_CAPACITY: usize = 4096;

/// Source-protocol tag emitted on every inbound RoutableMessage so
/// downstream filters / dedup / audit can distinguish Foundry-
/// originated traffic from CoT, MAVLink, etc. Mirrors the
/// `SOURCE_FEDERATION` / `SOURCE_MAVLINK` constants on
/// [`rustgate_core::message`].
pub const SOURCE_FOUNDRY: &str = "foundry";

/// Synthetic identity emitted on every inbound RoutableMessage. The
/// router's audit and dedup paths expect a non-empty `cn`; the
/// `"foundry"` value is the service-identity convention used
/// elsewhere in the workspace for non-mTLS-authenticated ingress.
pub const FOUNDRY_SERVICE_CN: &str = "foundry";

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
    bridge: Arc<dyn FoundryBridge>,
    config: FoundryConfig,
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
/// One subscription is opened per configured `[[object-types]]`
/// entry. The returned [`SubsystemHandle`] is canonical: drive
/// shutdown via [`rustgate_core::tasks::stop_subsystem`].
pub fn spawn_inbound(
    bridge: Arc<dyn FoundryBridge>,
    config: FoundryConfig,
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
/// projecting and upserting each message. On `Offline` the message
/// is queued; on success the queue is drained.
async fn run_outbound(
    bridge: Arc<dyn FoundryBridge>,
    config: FoundryConfig,
    mut rx: mpsc::Receiver<RoutableMessage>,
    shutdown: Arc<Notify>,
) {
    let mappers = build_mapper_table(&config.object_types);
    let mut offline_queue: VecDeque<PendingUpsert> = VecDeque::new();
    info!(mappings = mappers.len(), "foundry outbound task started");
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => {
                info!(pending = offline_queue.len(), "foundry outbound task draining");
                break;
            }
            msg = rx.recv() => {
                let Some(msg) = msg else { break };
                handle_outbound(&bridge, &mappers, &mut offline_queue, msg).await;
            }
        }
    }
}

/// Build the per-`entity-type` mapper table from the config.
///
/// The lookup is by `entity-type` (the
/// [`rustgate_core::entity::EntityKind::as_str`] tag), so the
/// outbound dispatch is a single hash + clone. Mappers are cheap
/// to construct (a `Vec<PropertyMap>` clone) so we materialise
/// them at startup.
fn build_mapper_table(
    types: &[ObjectTypeMapping],
) -> std::collections::HashMap<String, BoundMapper> {
    let mut table = std::collections::HashMap::new();
    for t in types {
        let _ = table.insert(
            t.entity_type.clone(),
            BoundMapper {
                foundry_type: t.foundry_type.clone(),
                mapper: PropertyMapper::new(t.property_map.clone()),
            },
        );
    }
    table
}

/// Per-`entity-type` mapper plus the Foundry object-type identifier
/// it dispatches to. Exposed as `pub` because the test-only
/// [`testing`] re-export surfaces it across the crate boundary —
/// the ordinary call path goes through [`dispatch_entity`] and
/// callers do not interact with this type directly.
#[derive(Debug, Clone)]
pub struct BoundMapper {
    foundry_type: String,
    mapper: PropertyMapper,
}

/// One queued upsert. Held in the offline replay buffer until the
/// bridge transitions Online and the head of the queue can be
/// re-issued. Exposed as `pub` for the same reason as
/// [`BoundMapper`]: the test-only [`testing`] module surfaces the
/// queue type across the crate boundary.
#[derive(Debug, Clone)]
pub struct PendingUpsert {
    type_id: String,
    /// Stable key used for last-writer-wins collapse. Matches the
    /// entity's `uid` at the moment the message was processed.
    uid: String,
    properties: Value,
}

/// Project a single message through the mapper table and either
/// upsert or queue.
///
/// When the envelope carries an attached [`Entity`] (the #1540 attach
/// seam — see ADR 0035), the message is projected and dispatched
/// through [`dispatch_entity`]. A dispatch error is logged and
/// swallowed: the outbound loop must not abort on a single unmapped or
/// malformed entity. When no entity is attached — the shape at every
/// router ingress today, since no codec populates the attach yet — the
/// message is logged at `debug` and dropped. That branch is the
/// deliberate scaffold until an ingress codec starts attaching entities;
/// the router-driven live-registration path (`spawn_outbound` wiring)
/// remains a documented follow-up.
async fn handle_outbound(
    bridge: &Arc<dyn FoundryBridge>,
    mappers: &std::collections::HashMap<String, BoundMapper>,
    offline_queue: &mut VecDeque<PendingUpsert>,
    msg: RoutableMessage,
) {
    match msg.entity.as_ref() {
        Some(entity) => {
            if let Err(e) = dispatch_entity(bridge, mappers, offline_queue, entity).await {
                // A single unmapped / malformed entity must not tear
                // down the outbound loop; `dispatch_entity` already
                // logs offline-queueing and warns on hard failures.
                debug!(error = %e, "foundry outbound: dispatch_entity failed for attached entity");
            }
        }
        None => {
            // No attached entity — the shape at every router ingress
            // today, since no codec populates the #1540 attach yet.
            // Drop with a debug trace; the router-driven live path is a
            // documented follow-up in ADR 0035.
            let _ = (bridge, mappers, offline_queue);
            debug!(
                "foundry outbound received a RoutableMessage without an attached Entity; \
                 this code path is the deliberate scaffold until an ingress codec attaches one"
            );
        }
    }
}

/// Project an `Entity` and dispatch it through the bridge. This is
/// the function the test harness calls to drive end-to-end
/// behaviour today. Once the router attaches an `Entity` to every
/// `RoutableMessage`, the wiring's per-message handler dispatches
/// into here.
pub async fn dispatch_entity(
    bridge: &Arc<dyn FoundryBridge>,
    mappers: &std::collections::HashMap<String, BoundMapper>,
    offline_queue: &mut VecDeque<PendingUpsert>,
    entity: &Entity,
) -> Result<(), FoundryError> {
    let type_tag = entity.kind.as_str().to_string();
    let Some(bound) = mappers.get(&type_tag) else {
        return Err(FoundryError::UnmappedEntityType {
            entity_type: type_tag,
        });
    };
    let properties = bound.mapper.entity_to_foundry(entity)?;
    let type_id = bound.foundry_type.clone();
    let uid = entity.uid.clone();
    match bridge.upsert_object(&type_id, properties.clone()).await {
        Ok(_id) => {
            // Successful upsert — drain any queued offline work
            // before returning so the next message is processed
            // against an empty queue. Failure inside the drain
            // re-queues the head; the loop ends as soon as the
            // bridge returns Offline again.
            drain_offline_queue(bridge, offline_queue).await;
            Ok(())
        }
        Err(FoundryError::Offline { reason }) => {
            warn!(
                target_type = %type_id,
                uid = %uid,
                reason = %reason,
                queue_depth = offline_queue.len(),
                "foundry upsert offline; queuing for replay"
            );
            enqueue_with_lww(
                offline_queue,
                PendingUpsert {
                    type_id,
                    uid,
                    properties,
                },
            );
            Ok(())
        }
        Err(other) => {
            warn!(error = %other, "foundry upsert failed");
            Err(other)
        }
    }
}

/// Push a pending upsert onto the queue, applying last-writer-wins
/// against any earlier entry with the same `(type_id, uid)`. On
/// overflow the oldest entry is evicted.
fn enqueue_with_lww(queue: &mut VecDeque<PendingUpsert>, pending: PendingUpsert) {
    queue.retain(|existing| !(existing.type_id == pending.type_id && existing.uid == pending.uid));
    while queue.len() >= OFFLINE_QUEUE_CAPACITY {
        let _ = queue.pop_front();
    }
    queue.push_back(pending);
}

/// Drain queued upserts until the queue is empty or the bridge
/// returns Offline again. Re-queues the failing head before
/// returning.
async fn drain_offline_queue(bridge: &Arc<dyn FoundryBridge>, queue: &mut VecDeque<PendingUpsert>) {
    while let Some(head) = queue.pop_front() {
        match bridge
            .upsert_object(&head.type_id, head.properties.clone())
            .await
        {
            Ok(_id) => {
                debug!(
                    target_type = %head.type_id,
                    uid = %head.uid,
                    remaining = queue.len(),
                    "foundry offline-queue drained one"
                );
            }
            Err(FoundryError::Offline { reason }) => {
                warn!(
                    target_type = %head.type_id,
                    uid = %head.uid,
                    reason = %reason,
                    "foundry still offline; re-queueing"
                );
                queue.push_front(head);
                return;
            }
            Err(other) => {
                warn!(error = %other, "foundry replay upsert failed; dropping");
                // Non-Offline errors are not retried — the
                // payload is malformed (BadRequest) or the
                // tenant is rejecting it (Backend). Logging at
                // warn keeps the visibility without the queue
                // ballooning indefinitely.
            }
        }
    }
}

/// Internal: inbound loop. Opens one subscription per configured
/// type and routes every change.
async fn run_inbound(
    bridge: Arc<dyn FoundryBridge>,
    config: FoundryConfig,
    router: Arc<Router>,
    shutdown: Arc<Notify>,
) {
    info!("foundry inbound task started");
    for mapping in &config.object_types {
        let mapper = PropertyMapper::new(mapping.property_map.clone());
        let foundry_type = mapping.foundry_type.clone();
        let bridge_for_sub = Arc::clone(&bridge);
        let router_for_sub = Arc::clone(&router);
        let shutdown_for_sub = Arc::clone(&shutdown);
        let entity_type = mapping.entity_type.clone();
        spawn_background("foundry-inbound-subscription", async move {
            run_inbound_subscription(
                bridge_for_sub,
                foundry_type,
                entity_type,
                mapper,
                router_for_sub,
                shutdown_for_sub,
            )
            .await;
        });
    }
    shutdown.notified().await;
    info!("foundry inbound task stopping");
}

async fn run_inbound_subscription(
    bridge: Arc<dyn FoundryBridge>,
    foundry_type: String,
    entity_type: String,
    mapper: PropertyMapper,
    router: Arc<Router>,
    shutdown: Arc<Notify>,
) {
    let mut stream = match bridge.subscribe_changes(&foundry_type).await {
        Ok(s) => s,
        Err(e) => {
            warn!(target_type = %foundry_type, error = %e, "foundry subscribe failed");
            return;
        }
    };
    info!(target_type = %foundry_type, "foundry inbound subscription opened");
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => break,
            change = stream.next() => {
                let Some(change) = change else {
                    debug!(target_type = %foundry_type, "foundry change stream closed");
                    break;
                };
                if let Some(msg) = change_to_message(&change, &entity_type, &mapper) {
                    router.route(msg).await;
                }
            }
        }
    }
}

/// Project a single Foundry change into a `RoutableMessage` the
/// router can fan out.
///
/// The destination is `Broadcast` and the source identity is the
/// service-identity convention `FOUNDRY_SERVICE_CN`. Tightening to
/// a per-mapping `Destination::Group(...)` is a follow-up.
fn change_to_message(
    change: &ObjectChange,
    entity_type: &str,
    mapper: &PropertyMapper,
) -> Option<RoutableMessage> {
    // A `Deleted` ontology change must NOT be re-projected as a live
    // Broadcast entity — re-injecting the last-seen property bag
    // resurrects the object downstream (#1499). rustgate has no
    // cross-protocol delete/tombstone convention yet (the `Entity`
    // shape carries no deleted marker), so the conservative fix is to
    // drop the change here; downstream consumers age the entity out via
    // its own stale-time. Emitting a typed delete is a follow-up that
    // needs a delete-message design across the codec layer.
    if change.change_type == ChangeType::Deleted {
        debug!(
            entity_type,
            "foundry inbound: dropping Deleted change (not re-injected as a live entity)"
        );
        return None;
    }
    let overlay = mapper.foundry_to_entity_overlay(&change.properties);
    let entity = build_entity_from_overlay(entity_type, change, overlay);
    let payload = serde_json::to_vec(&entity).unwrap_or_default();
    // `Identity::plaintext` is the right constructor here — Foundry-
    // ingested traffic has no client certificate fingerprint, and the
    // service-identity convention used elsewhere in the workspace
    // (federation inbound, NATS bridge) is the same shape.
    // `FOUNDRY_SERVICE_CN` is a 7-byte ASCII constant so validation
    // cannot fail in practice; the wiring still propagates the
    // `Result` and drops the message rather than panicking if a
    // future change to the constant ever violates the contract.
    let source = match Identity::plaintext(FOUNDRY_SERVICE_CN.to_string(), Default::default()) {
        Ok(id) => id,
        Err(e) => {
            // playbook-drift-ok: this is an internal-invariant
            // diagnostic, not an external rejection — dropping a
            // message because the synthetic service-identity
            // constant could not be reconstructed is a never-fires
            // contract failure, not an authn / authz / rate-limit
            // event that belongs in the audit trail.
            warn!(error = %e, "foundry inbound dropped: synthetic identity could not be constructed");
            return None;
        }
    };
    Some(RoutableMessage {
        source,
        destination: Destination::Broadcast,
        payload: Bytes::from(payload),
        metadata: Metadata::new(
            SystemTime::now(),
            SOURCE_FOUNDRY.to_string(),
            // `MessageType::Other` carries a free-form label so the
            // router's audit / metrics layers can distinguish
            // Foundry-injected traffic from CoT / chat / position
            // shapes without dropping it into the catch-all
            // `unknown` bucket.
            MessageType::Other("foundry".to_string()),
        ),
        entity: None,
    })
}

/// Compose an `Entity` from the overlay produced by the property
/// map plus fall-backs derived from the change itself (the
/// object-id when the property map did not bind `uid`).
fn build_entity_from_overlay(
    entity_type: &str,
    change: &ObjectChange,
    overlay: EntityOverlay,
) -> Entity {
    let kind = match entity_type {
        "aircraft" => EntityKind::Aircraft,
        "ground" => EntityKind::Ground,
        "marine" => EntityKind::Marine,
        "sensor" => EntityKind::Sensor,
        "track" => EntityKind::Track,
        "munition" => EntityKind::Munition,
        other => EntityKind::Unknown(other.to_string()),
    };
    let uid = overlay.uid.unwrap_or_else(|| change.object_id.0.clone());
    Entity {
        uid,
        kind,
        position: overlay.position,
        velocity: overlay.velocity,
        timestamp: SystemTime::now(),
        callsign: overlay.callsign,
        mil_std_2525_sidc: overlay.mil_std_2525_sidc,
        attributes: overlay.attributes,
        taskings: Default::default(),
        files: Default::default(),
    }
}

/// Test-only re-export so `tests/wiring.rs` can drive the offline-
/// queue + LWW path directly without owning a router.
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// Construct a wiring-internal mapper table directly from the
    /// config slice. Mirrors the in-task path but is reachable from
    /// integration tests.
    pub fn build_mapper_table_for_test(
        types: &[ObjectTypeMapping],
    ) -> std::collections::HashMap<String, BoundMapper> {
        super::build_mapper_table(types)
    }

    /// Fresh empty offline queue for tests.
    pub fn fresh_queue() -> VecDeque<PendingUpsert> {
        VecDeque::new()
    }

    /// Re-export of the dispatch helper.
    pub async fn dispatch_for_test(
        bridge: &Arc<dyn FoundryBridge>,
        mappers: &std::collections::HashMap<String, BoundMapper>,
        offline_queue: &mut VecDeque<PendingUpsert>,
        entity: &Entity,
    ) -> Result<(), FoundryError> {
        super::dispatch_entity(bridge, mappers, offline_queue, entity).await
    }

    /// Re-export of the per-message outbound handler so integration
    /// tests can drive the #1540 attached-entity dispatch path (and the
    /// no-entity scaffold branch) exactly as the router-fed outbound
    /// loop would. See ADR 0035.
    pub async fn handle_outbound_for_test(
        bridge: &Arc<dyn FoundryBridge>,
        mappers: &std::collections::HashMap<String, BoundMapper>,
        offline_queue: &mut VecDeque<PendingUpsert>,
        msg: RoutableMessage,
    ) {
        super::handle_outbound(bridge, mappers, offline_queue, msg).await;
    }

    /// Inspect the current queue depth.
    pub fn queue_depth(queue: &VecDeque<PendingUpsert>) -> usize {
        queue.len()
    }

    /// Inspect the queue contents (type_id, uid) pairs in order.
    pub fn queue_keys(queue: &VecDeque<PendingUpsert>) -> Vec<(String, String)> {
        queue
            .iter()
            .map(|p| (p.type_id.clone(), p.uid.clone()))
            .collect()
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
            PendingUpsert {
                type_id: "t".into(),
                uid: "1".into(),
                properties: Value::Null,
            },
        );
        enqueue_with_lww(
            &mut q,
            PendingUpsert {
                type_id: "t".into(),
                uid: "2".into(),
                properties: Value::Null,
            },
        );
        // Re-queue uid=1 → first entry retained order-wise becomes
        // the (newer) version; the previous uid=1 is dropped.
        enqueue_with_lww(
            &mut q,
            PendingUpsert {
                type_id: "t".into(),
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
        // Pin the cap behaviour without exhausting `OFFLINE_QUEUE_CAPACITY`
        // entries — the eviction logic is order-dependent and the constant
        // is documented as load-bearing.
        let mut q = VecDeque::new();
        for i in 0..OFFLINE_QUEUE_CAPACITY {
            enqueue_with_lww(
                &mut q,
                PendingUpsert {
                    type_id: "t".into(),
                    uid: format!("{i}"),
                    properties: Value::Null,
                },
            );
        }
        assert_eq!(q.len(), OFFLINE_QUEUE_CAPACITY);
        // One more — should evict the oldest.
        enqueue_with_lww(
            &mut q,
            PendingUpsert {
                type_id: "t".into(),
                uid: "overflow".into(),
                properties: Value::Null,
            },
        );
        assert_eq!(q.len(), OFFLINE_QUEUE_CAPACITY);
        assert_eq!(q.front().unwrap().uid, "1"); // "0" was evicted
        assert_eq!(q.back().unwrap().uid, "overflow");
    }

    fn change_with_type(change_type: ChangeType) -> ObjectChange {
        ObjectChange {
            type_id: "mil-track".into(),
            object_id: crate::bridge::ObjectId("obj-1".into()),
            change_type,
            properties: serde_json::json!({}),
        }
    }

    #[test]
    fn deleted_change_is_not_reinjected_as_live_entity() {
        // #1499: a Foundry `Deleted` change must not resurrect the object as a
        // live Broadcast entity. The inbound projection drops it.
        let mapper = PropertyMapper::new(vec![]);
        assert!(
            change_to_message(&change_with_type(ChangeType::Deleted), "track", &mapper).is_none(),
            "a Deleted change must not produce a live-entity RoutableMessage",
        );
    }

    #[test]
    fn created_and_updated_changes_still_project_to_broadcast() {
        // Control: non-Deleted changes still project to a Broadcast live
        // entity, so the Deleted guard does not over-reach.
        let mapper = PropertyMapper::new(vec![]);
        for ct in [ChangeType::Created, ChangeType::Updated] {
            let msg = change_to_message(&change_with_type(ct), "track", &mapper)
                .expect("Created/Updated must still project to a message");
            assert!(matches!(msg.destination, Destination::Broadcast));
        }
    }
}
