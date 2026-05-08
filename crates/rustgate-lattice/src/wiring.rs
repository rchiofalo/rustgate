// Copyright © 2026 Roberto Chiofalo.

//! Background-task helpers that plug a `LatticeBridge` into a
//! `rustgate_router::Router`.
//!
//! Two tasks are exposed:
//!
//! - [`spawn_outbound_task`] — drains a `tokio::sync::mpsc::Receiver`
//!   that the server binary fills from an `OnMessageDelivered`
//!   callback (or any other source) and calls
//!   `LatticeBridge::publish_entity` for each `MessageType::Position
//!   | Track`-style message. Bounded by an internal flush cadence so
//!   the bridge always sees backpressure semantics it understands.
//! - [`spawn_inbound_task`] — calls
//!   `LatticeBridge::subscribe_entities` once at startup, then
//!   pumps every yielded `Entity` into `Router::route` as a
//!   `RoutableMessage`.
//!
//! Both helpers return a [`tokio::task::JoinHandle<()>`] that the
//! server binary owns — the caller is responsible for `.abort()`-ing
//! the handle on shutdown. The tasks never panic; on terminal errors
//! they log at `tracing::warn!` and exit cleanly.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::Router;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::bridge::{Entity, EntityFilter, EntityKind, GeoPosition, HealthStatus, SharedBridge};
use crate::config::LatticeConfig;

/// Symbolic source-protocol tag injected on the inbound side so the
/// router (and downstream audit) can distinguish Lattice-fed messages
/// from CoT XML, MAVLink, etc.
pub const SOURCE_LATTICE: &str = "lattice";

/// Group used for inbound-routed Lattice messages.
///
/// Lattice does not carry CoT-style group routing on its inbound
/// stream, so the wiring task surfaces every consumed entity as
/// `Destination::Group("lattice")` and lets the operator's ACL
/// decide which clients see it.
pub const DEFAULT_LATTICE_GROUP: &str = "lattice";

/// CN used for inbound-routed Lattice messages whose source CN is
/// not known.
const ANONYMOUS_LATTICE_CN: &str = "lattice-anonymous";

/// Spawn the outbound publish task.
///
/// `messages` is a receiver the server binary fills from a router
/// hook (typically `rustgate_router::Router::set_on_message_delivered`
/// or a custom send-side observer). The task drains it, maps each
/// admitted `RoutableMessage` to a [`Entity`], and calls
/// `LatticeBridge::publish_entity` for it. Health reports are
/// emitted on a timer driven by `cfg.health_interval_secs`.
///
/// The task exits when the receiver closes (e.g. on shutdown when
/// the server drops the matching `Sender`). It logs at `warn` on
/// publish failures and continues — Lattice may be transiently
/// unreachable and dropping every subsequent message until the
/// channel drains is the wrong tradeoff for a sensor feed.
#[must_use]
pub fn spawn_outbound_task(
    bridge: SharedBridge,
    cfg: LatticeConfig,
    mut messages: mpsc::Receiver<RoutableMessage>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let backend = bridge.backend_name();
        let mut published: u64 = 0;
        let consumed: u64 = 0; // outbound task does not consume; reported as 0
        let mut health_timer = tokio::time::interval(Duration::from_secs(cfg.health_interval_secs));
        // The first tick fires immediately by default; skip it so the
        // first health report waits one full cadence rather than
        // emitting at startup before any traffic has flowed.
        let _ = health_timer.tick().await;

        info!(
            backend = backend,
            endpoint = %cfg.endpoint,
            batch_size = cfg.batch_size,
            "lattice outbound task started"
        );

        loop {
            tokio::select! {
                maybe_msg = messages.recv() => {
                    let Some(msg) = maybe_msg else {
                        info!(backend = backend, "lattice outbound task: input channel closed, exiting");
                        break;
                    };
                    if !is_position_or_track(&msg) {
                        continue;
                    }
                    let entity = message_to_entity(&msg);
                    match bridge.publish_entity(entity).await {
                        Ok(()) => {
                            published = published.saturating_add(1);
                        }
                        Err(err) => {
                            warn!(
                                backend = backend,
                                error = %err,
                                "lattice publish_entity failed; continuing",
                            );
                        }
                    }
                }
                _ = health_timer.tick() => {
                    let status = HealthStatus {
                        source: format!("rustgate/{backend}"),
                        published_count: published,
                        consumed_count: consumed,
                        detail: "healthy".to_string(),
                    };
                    if let Err(err) = bridge.report_health(status).await {
                        warn!(
                            backend = backend,
                            error = %err,
                            "lattice report_health failed; continuing",
                        );
                    }
                }
            }
        }
    })
}

/// Spawn the inbound subscription task.
///
/// The task calls `LatticeBridge::subscribe_entities` once at
/// startup and then drains the returned stream into the router by
/// calling `Router::route` on a `RoutableMessage` reconstructed
/// from each [`Entity`]. The geo / kind filter is taken from
/// `cfg.geo_bbox` and `cfg.entity_types` so a deployment can scope
/// what it pulls from Lattice without rebuilding the bridge.
///
/// The task exits when the bridge stream closes. It logs and exits
/// (rather than retrying) if `subscribe_entities` itself fails — a
/// real-SDK impl is expected to handle reconnection internally.
#[must_use]
pub fn spawn_inbound_task(
    bridge: SharedBridge,
    cfg: LatticeConfig,
    router: Arc<Router>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let backend = bridge.backend_name();
        let filter = EntityFilter {
            geo_bbox: cfg.geo_bbox,
            types: cfg.entity_types.unwrap_or_default(),
        };

        info!(
            backend = backend,
            endpoint = %cfg.endpoint,
            "lattice inbound task started"
        );

        let mut stream = match bridge.subscribe_entities(filter).await {
            Ok(s) => s,
            Err(err) => {
                warn!(
                    backend = backend,
                    error = %err,
                    "lattice subscribe_entities failed; inbound task exiting",
                );
                return;
            }
        };

        while let Some(entity) = stream.next().await {
            let entity_id = entity.entity_id.clone();
            match entity_to_message(entity) {
                Some(msg) => {
                    debug!(
                        backend = backend,
                        entity_id = %entity_id,
                        "routing inbound lattice entity",
                    );
                    router.route(msg).await;
                }
                None => {
                    debug!(
                        backend = backend,
                        entity_id = %entity_id,
                        "skipping inbound lattice entity: identity construction failed",
                    );
                }
            }
        }

        info!(
            backend = backend,
            "lattice inbound task: stream closed, exiting"
        );
    })
}

/// Returns `true` for messages that the outbound task should publish
/// to Lattice.
///
/// The MVP scope is sensor-feed fidelity, which means
/// position-and-track traffic. CoT chat / alerts / status reports are
/// out of scope until the partner side confirms they want them on
/// the same RPC.
fn is_position_or_track(msg: &RoutableMessage) -> bool {
    matches!(msg.metadata.message_type, MessageType::Position)
}

/// Build a [`Entity`] from a [`RoutableMessage`].
///
/// The MVP does not parse the payload — every published entity carries
/// the original wire bytes in `Entity::payload` and the partner-side
/// SDK is expected to reach into the protobuf or XML body itself if
/// it wants typed fields. Lattice's `Entity.kind` is set to
/// [`EntityKind::Track`] for `MessageType::Position` (the only branch
/// `is_position_or_track` admits today) so a follow-up that broadens
/// the filter only has to extend the match.
fn message_to_entity(msg: &RoutableMessage) -> Entity {
    Entity {
        entity_id: format!("rustgate:{}", msg.source.cn),
        kind: EntityKind::Track,
        position: None,
        observed_at: msg.metadata.received_at,
        payload: msg.payload.clone(),
        source_cn: Some(msg.source.cn.to_string()),
    }
}

/// Build a [`RoutableMessage`] from a [`Entity`].
///
/// Returns `None` only when [`Identity::plaintext`] rejects the
/// constructed CN — the inbound stream is otherwise authoritative
/// and rustgate's job is to fan the entity out, not to second-guess
/// it. The constructed identity uses the synthetic
/// `lattice-anonymous` CN when the upstream entity does not carry a
/// `source_cn`, so audit records and access logs can distinguish
/// a Lattice-injected message from a locally-authored one.
fn entity_to_message(entity: Entity) -> Option<RoutableMessage> {
    let cn = entity
        .source_cn
        .clone()
        .unwrap_or_else(|| ANONYMOUS_LATTICE_CN.to_string());
    let mut groups = BTreeSet::new();
    let _ = groups.insert(DEFAULT_LATTICE_GROUP.to_string());

    let identity = match Identity::plaintext(cn, groups) {
        Ok(id) => id,
        Err(err) => {
            debug!(error = %err, "rejecting lattice entity: invalid CN");
            return None;
        }
    };

    let metadata = Metadata::new(
        entity.observed_at,
        SOURCE_LATTICE.to_string(),
        match entity.kind {
            EntityKind::Track | EntityKind::Platform | EntityKind::Annotation => {
                MessageType::Position
            }
            EntityKind::Signal => MessageType::Status,
            EntityKind::Other(ref s) => MessageType::Other(s.clone()),
        },
    );

    Some(RoutableMessage {
        source: identity,
        destination: Destination::Group(Arc::<str>::from(DEFAULT_LATTICE_GROUP)),
        payload: entity.payload,
        metadata,
    })
}

/// Construct a [`GeoPosition`] from a `(lat, lon)` pair, dropping
/// non-finite values. Helper exposed so a future real-SDK impl that
/// reconstructs entities from typed protobuf can share the same
/// validation surface as the mock backend.
#[must_use]
pub fn geo_position_from_pair(lat: f64, lon: f64, alt_m: Option<f64>) -> Option<GeoPosition> {
    if !lat.is_finite() || !lon.is_finite() {
        return None;
    }
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some(GeoPosition {
        latitude: lat,
        longitude: lon,
        altitude_m: alt_m.filter(|a| a.is_finite()),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::time::SystemTime;

    use bytes::Bytes;

    use super::*;

    fn position_msg() -> RoutableMessage {
        let identity =
            Identity::plaintext("alice".to_string(), BTreeSet::from(["alpha".to_string()]))
                .unwrap();
        let meta = Metadata::new(
            SystemTime::UNIX_EPOCH,
            "tcp".to_string(),
            MessageType::Position,
        );
        RoutableMessage {
            source: identity,
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event/>"),
            metadata: meta,
        }
    }

    #[test]
    fn position_messages_are_published_track_messages_too() {
        let msg = position_msg();
        assert!(is_position_or_track(&msg));
    }

    #[test]
    fn chat_messages_are_filtered_out() {
        let mut msg = position_msg();
        msg.metadata.message_type = MessageType::Chat;
        assert!(!is_position_or_track(&msg));
    }

    #[test]
    fn message_to_entity_preserves_payload() {
        let msg = position_msg();
        let entity = message_to_entity(&msg);
        assert_eq!(entity.entity_id, "rustgate:alice");
        assert_eq!(entity.kind, EntityKind::Track);
        assert_eq!(entity.payload.as_ref(), b"<event/>");
        assert_eq!(entity.source_cn.as_deref(), Some("alice"));
    }

    #[test]
    fn entity_to_message_uses_anonymous_cn_when_missing() {
        let entity = Entity {
            entity_id: "x".to_string(),
            kind: EntityKind::Track,
            position: None,
            observed_at: SystemTime::UNIX_EPOCH,
            payload: Bytes::new(),
            source_cn: None,
        };
        let msg = entity_to_message(entity).expect("anonymous cn must round-trip");
        assert_eq!(&*msg.source.cn, ANONYMOUS_LATTICE_CN);
        assert_eq!(msg.metadata.source_protocol, SOURCE_LATTICE);
    }

    #[test]
    fn entity_to_message_kind_mapping() {
        for (kind, expected) in [
            (EntityKind::Track, MessageType::Position),
            (EntityKind::Platform, MessageType::Position),
            (EntityKind::Annotation, MessageType::Position),
            (EntityKind::Signal, MessageType::Status),
        ] {
            let entity = Entity {
                entity_id: "x".to_string(),
                kind,
                position: None,
                observed_at: SystemTime::UNIX_EPOCH,
                payload: Bytes::new(),
                source_cn: Some("a".to_string()),
            };
            let msg = entity_to_message(entity).unwrap();
            assert_eq!(msg.metadata.message_type, expected);
        }
    }

    #[test]
    fn geo_position_from_pair_rejects_out_of_range() {
        assert!(geo_position_from_pair(91.0, 0.0, None).is_none());
        assert!(geo_position_from_pair(0.0, 181.0, None).is_none());
        assert!(geo_position_from_pair(f64::NAN, 0.0, None).is_none());
    }

    #[test]
    fn geo_position_from_pair_accepts_within_range() {
        let pos = geo_position_from_pair(37.0, -122.0, Some(50.0)).unwrap();
        assert_eq!(pos.latitude, 37.0);
        assert_eq!(pos.longitude, -122.0);
        assert_eq!(pos.altitude_m, Some(50.0));
    }
}
