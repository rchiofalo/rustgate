// Copyright © 2026 Roberto Chiofalo.

//! In-memory `MockLatticeBridge` — feature-gated under `lattice-mock`.
//!
//! The mock backend is a `tokio::sync::mpsc` round trip with no
//! network, no SDK, and no auth. It exists so the integration tests
//! and `cargo nextest -p rustgate-lattice --features lattice-mock`
//! can drive the full router → bridge → router path without an
//! actual Lattice endpoint, and so the `wiring.rs` task helpers
//! can be exercised end-to-end before the real-SDK PR lands.
//!
//! The mock is also a useful blueprint for the real-SDK
//! `LatticeBridge` implementation — it enumerates every contract
//! point (publish, subscribe, health) in the simplest possible
//! form so the partner-side PR has a concrete reference.

use std::sync::{Arc, Mutex};

use futures::StreamExt;
use futures::stream::BoxStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::bridge::{Entity, EntityFilter, GeoBbox, HealthStatus, LatticeBridge};
use crate::error::{LatticeError, Result};

/// Capacity of the in-memory inbound queue.
///
/// Sized so a typical integration test can publish hundreds of
/// entities without backing up. Real backends will not use this
/// constant.
pub const MOCK_INBOUND_CAPACITY: usize = 256;

/// Test bridge backed by `tokio::sync::mpsc` channels.
///
/// `published` keeps every outbound publish so a test can assert
/// "rustgate emitted N entities to Lattice"; `inbound_tx` is the
/// channel a test (or a fixture) uses to inject entities that the
/// inbound subscription will surface.
#[derive(Debug)]
pub struct MockLatticeBridge {
    published: Mutex<Vec<Entity>>,
    health_reports: Mutex<Vec<HealthStatus>>,
    inbound_tx: mpsc::Sender<Entity>,
    inbound_rx: Mutex<Option<mpsc::Receiver<Entity>>>,
}

impl MockLatticeBridge {
    /// Construct a fresh mock bridge with an empty publish log and
    /// a single-consumer inbound channel.
    pub fn new() -> Arc<Self> {
        let (tx, rx) = mpsc::channel(MOCK_INBOUND_CAPACITY);
        Arc::new(Self {
            published: Mutex::new(Vec::new()),
            health_reports: Mutex::new(Vec::new()),
            inbound_tx: tx,
            inbound_rx: Mutex::new(Some(rx)),
        })
    }

    /// Drop a synthetic inbound entity into the bridge's queue.
    ///
    /// Test fixtures use this to simulate "Lattice told us about an
    /// entity" — the entity will surface on whatever stream
    /// [`MockLatticeBridge::subscribe_entities`] returned.
    pub async fn inject_inbound(&self, entity: Entity) -> Result<()> {
        self.inbound_tx
            .send(entity)
            .await
            .map_err(|e| LatticeError::PublishFailed {
                backend: "mock",
                entity_id: e.0.entity_id.clone(),
                reason: "inbound channel closed".to_string(),
            })
    }

    /// Snapshot of every entity published outbound so far.
    ///
    /// Returns a clone so the caller can hold the slice without
    /// keeping the internal mutex locked.
    pub fn published_snapshot(&self) -> Vec<Entity> {
        match self.published.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Snapshot of every health report submitted so far.
    pub fn health_snapshot(&self) -> Vec<HealthStatus> {
        match self.health_reports.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

#[async_trait::async_trait]
impl LatticeBridge for MockLatticeBridge {
    fn backend_name(&self) -> &'static str {
        "mock"
    }

    async fn publish_entity(&self, entity: Entity) -> Result<()> {
        match self.published.lock() {
            Ok(mut g) => g.push(entity),
            Err(poisoned) => poisoned.into_inner().push(entity),
        }
        Ok(())
    }

    async fn subscribe_entities(&self, filter: EntityFilter) -> Result<BoxStream<'static, Entity>> {
        // The mock supports a single subscriber by design — taking
        // the receiver out of the Option ensures a second subscribe
        // call returns an audit-friendly error instead of silently
        // sharing the queue.
        let mut guard = match self.inbound_rx.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let rx = guard
            .take()
            .ok_or_else(|| LatticeError::SubscriptionClosed {
                backend: "mock",
                reason: "subscribe_entities can only be called once on the mock bridge".to_string(),
            })?;
        drop(guard);

        let stream = ReceiverStream::new(rx).filter(move |entity| {
            let pass = filter_matches(&filter, entity);
            async move { pass }
        });
        Ok(Box::pin(stream))
    }

    async fn report_health(&self, status: HealthStatus) -> Result<()> {
        match self.health_reports.lock() {
            Ok(mut g) => g.push(status),
            Err(poisoned) => poisoned.into_inner().push(status),
        }
        Ok(())
    }
}

/// Returns true when `entity` passes `filter`.
///
/// An empty `types` list means "accept any kind"; a `None` `geo_bbox`
/// means "accept any location". An entity with `position == None`
/// passes when no geo filter is set, otherwise it is rejected — a
/// non-positional entity has no coordinates to test against the box.
fn filter_matches(filter: &EntityFilter, entity: &Entity) -> bool {
    let kind_ok = filter.types.is_empty() || filter.types.contains(&entity.kind);
    let geo_ok = match (&filter.geo_bbox, &entity.position) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(bbox), Some(pos)) => GeoBbox::contains(bbox, pos),
    };
    kind_ok && geo_ok
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::time::SystemTime;

    use bytes::Bytes;
    use futures::StreamExt;

    use super::*;
    use crate::bridge::EntityKind;

    fn track(id: &str) -> Entity {
        Entity {
            entity_id: id.to_string(),
            kind: EntityKind::Track,
            position: None,
            observed_at: SystemTime::UNIX_EPOCH,
            payload: Bytes::new(),
            source_cn: None,
        }
    }

    #[tokio::test]
    async fn publish_records_every_entity() {
        let bridge = MockLatticeBridge::new();
        bridge.publish_entity(track("a")).await.unwrap();
        bridge.publish_entity(track("b")).await.unwrap();
        let log = bridge.published_snapshot();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].entity_id, "a");
        assert_eq!(log[1].entity_id, "b");
    }

    #[tokio::test]
    async fn subscribe_yields_injected_entities() {
        let bridge = MockLatticeBridge::new();
        let mut stream = bridge
            .subscribe_entities(EntityFilter::default())
            .await
            .unwrap();
        bridge.inject_inbound(track("x")).await.unwrap();
        bridge.inject_inbound(track("y")).await.unwrap();

        let first = stream.next().await.expect("first");
        let second = stream.next().await.expect("second");
        assert_eq!(first.entity_id, "x");
        assert_eq!(second.entity_id, "y");
    }

    #[tokio::test]
    async fn double_subscribe_returns_error() {
        let bridge = MockLatticeBridge::new();
        let first = bridge.subscribe_entities(EntityFilter::default()).await;
        assert!(first.is_ok(), "first subscribe must succeed");
        // `BoxStream` does not impl `Debug`, so we cannot call
        // `.unwrap_err()` directly — pattern-match instead.
        let err = match bridge.subscribe_entities(EntityFilter::default()).await {
            Ok(_) => panic!("second subscribe must fail"),
            Err(e) => e,
        };
        assert!(matches!(err, LatticeError::SubscriptionClosed { .. }));
    }

    #[test]
    fn filter_matches_empty_filter() {
        let filter = EntityFilter::default();
        let entity = track("a");
        assert!(filter_matches(&filter, &entity));
    }

    #[test]
    fn filter_kind_mismatch_rejects() {
        let filter = EntityFilter {
            geo_bbox: None,
            types: vec![EntityKind::Platform],
        };
        let entity = track("a");
        assert!(!filter_matches(&filter, &entity));
    }
}
