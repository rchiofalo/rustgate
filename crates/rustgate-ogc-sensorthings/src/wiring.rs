// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Background polling task that drives the
//! [`crate::SensorThingsClient`] and feeds resulting observations
//! into a [`rustgate_router::Router`].
//!
//! For every configured `[[sensorthings.subscriptions]]` entry the
//! wiring spawns one tokio task that polls the upstream server on
//! the configured cadence, projects each returned observation onto
//! a canonical [`rustgate_core::entity::Entity`] via
//! [`crate::observation_to_entity`], wraps the entity in a
//! [`rustgate_core::message::RoutableMessage`], and calls
//! [`rustgate_router::Router::route`].
//!
//! # Source identity
//!
//! Every emitted message carries a synthetic
//! `Identity::plaintext("ogc-sensorthings", …)` source. SensorThings
//! observations have no client certificate; the service-identity
//! convention used elsewhere in the workspace (federation inbound,
//! NATS bridge, Foundry inbound) is the same shape. The CN is a
//! 16-byte ASCII constant ([`SOURCE_OGC_SENSORTHINGS`]) so identity
//! construction never fails in practice; the wiring still propagates
//! the `Result` and drops the message rather than panicking if a
//! future change to the constant ever violates the contract.
//!
//! # Source-protocol tag
//!
//! Every emitted [`rustgate_core::message::Metadata`] carries
//! `source_protocol = SOURCE_OGC_SENSORTHINGS` so audit consumers
//! and per-protocol metrics can distinguish SensorThings-ingested
//! traffic from CoT, MAVLink, or federation.
//!
//! # Backoff
//!
//! On a transient failure ([`crate::SensorThingsError::is_transient`]
//! returns `true`) the task waits the configured poll interval
//! before the next attempt. On a non-transient failure (e.g. 401,
//! 404, decode error) the task waits the same interval — there is
//! no exponential backoff in the MVP because the operator is the
//! right entity to fix the underlying problem (rotate the token,
//! correct the datastream id, fix the schema mismatch). The
//! task continues to log the failure on every retry so the
//! operator-facing telemetry stays loud.
//!
//! # Cursor advancement
//!
//! After every successful poll the task records the maximum
//! `phenomenonTime` from the returned page and uses it as the
//! `since` argument on the next poll. This both provides exactly-
//! once semantics across polls (assuming the upstream
//! `phenomenonTime` is strictly monotonic per stream) and reduces
//! the wire footprint since the server is asked only for newer
//! observations. When the page is empty (no new observations) the
//! cursor is unchanged and the next poll re-issues the same
//! `?$filter=phenomenonTime gt …` clause.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::entity::Entity;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::tasks::{SubsystemHandle, spawn_background};
use rustgate_router::Router;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::client::SensorThingsClient;
use crate::config::{SensorThingsConfig, Subscription};
use crate::error::SensorThingsError;
use crate::mapper::observation_to_entity;
use crate::types::Observation;

/// Source-protocol tag emitted on every inbound RoutableMessage so
/// downstream filters / dedup / audit can distinguish
/// SensorThings-originated traffic. Mirrors the `SOURCE_FEDERATION`
/// / `SOURCE_MAVLINK` constants on
/// [`rustgate_core::message`].
pub const SOURCE_OGC_SENSORTHINGS: &str = "ogc-sensorthings";

/// Synthetic CN emitted on every inbound RoutableMessage. The
/// router's audit and dedup paths expect a non-empty `cn`; this
/// 16-byte ASCII value follows the workspace's service-identity
/// convention (`"foundry"`, `"federation"`, …).
pub const OGC_SENSORTHINGS_SERVICE_CN: &str = "ogc-sensorthings";

/// Spawn one polling task per configured subscription.
///
/// Returns a single [`SubsystemHandle`] that drives graceful
/// shutdown for the entire SensorThings subsystem. Calling
/// [`rustgate_core::tasks::stop_subsystem`] on it requests every
/// per-subscription task to stop and waits for them to drain.
///
/// `client` is shared across every per-subscription task — the
/// `reqwest::Client` inside is `Clone` and pools connections.
///
/// `config.subscriptions` may be empty; in that case the supervisor
/// returns immediately and shutdown is a no-op.
pub fn spawn_polling_task(
    client: SensorThingsClient,
    config: SensorThingsConfig,
    router: Arc<Router>,
) -> SubsystemHandle {
    let shutdown = Arc::new(Notify::new());
    let shutdown_task = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        run_supervisor(client, config, router, shutdown_task).await;
    });
    SubsystemHandle::new(shutdown, task)
}

async fn run_supervisor(
    client: SensorThingsClient,
    config: SensorThingsConfig,
    router: Arc<Router>,
    shutdown: Arc<Notify>,
) {
    info!(
        target: "rustgate.ogc-sensorthings",
        subscriptions = config.subscriptions.len(),
        "OGC SensorThings polling supervisor started"
    );
    if config.subscriptions.is_empty() {
        // Nothing to drive — block on shutdown so the supervisor's
        // SubsystemHandle still drains cleanly.
        shutdown.notified().await;
        return;
    }
    for sub in &config.subscriptions {
        let client_clone = client.clone();
        let router_clone = Arc::clone(&router);
        let shutdown_clone = Arc::clone(&shutdown);
        let cfg_clone = config.clone();
        let sub_clone = sub.clone();
        spawn_background("ogc-sensorthings-poll", async move {
            run_subscription(
                client_clone,
                cfg_clone,
                sub_clone,
                router_clone,
                shutdown_clone,
            )
            .await;
        });
    }
    shutdown.notified().await;
    info!(
        target: "rustgate.ogc-sensorthings",
        "OGC SensorThings polling supervisor stopping"
    );
}

async fn run_subscription(
    client: SensorThingsClient,
    config: SensorThingsConfig,
    sub: Subscription,
    router: Arc<Router>,
    shutdown: Arc<Notify>,
) {
    let interval = config.effective_poll_interval(&sub);
    let page_size = config.effective_page_size(&sub);
    let entity_kind = sub.entity_kind.to_entity_kind();
    let datastream_id = sub.datastream_id;
    let mut cursor: Option<String> = None;

    info!(
        target: "rustgate.ogc-sensorthings",
        datastream_id = datastream_id,
        interval_secs = interval.as_secs(),
        page_size = page_size,
        entity_kind = entity_kind.as_str(),
        "starting SensorThings polling task"
    );

    loop {
        // Drive one poll, then await either the next interval tick
        // or shutdown — whichever comes first.
        match poll_once(
            &client,
            &router,
            &sub,
            datastream_id,
            page_size,
            entity_kind.clone(),
            cursor.as_deref(),
        )
        .await
        {
            Ok(Some(latest)) => {
                cursor = Some(latest);
            }
            Ok(None) => {
                debug!(
                    target: "rustgate.ogc-sensorthings",
                    datastream_id = datastream_id,
                    "no new observations on this poll"
                );
            }
            Err(err) => {
                let transient = err.is_transient();
                warn!(
                    target: "rustgate.ogc-sensorthings",
                    datastream_id = datastream_id,
                    error = %err,
                    transient = transient,
                    "SensorThings poll failed"
                );
            }
        }
        tokio::select! {
            biased;
            () = shutdown.notified() => {
                info!(
                    target: "rustgate.ogc-sensorthings",
                    datastream_id = datastream_id,
                    "polling task stopping"
                );
                break;
            }
            () = tokio::time::sleep(interval) => {}
        }
    }
}

/// Drive one polling round. Returns the maximum `phenomenonTime`
/// from the returned page (so the caller can advance its cursor)
/// or `None` when the page was empty. Errors propagate to the
/// caller for backoff decision.
///
/// Visible at `pub(crate)` so the integration test can drive a
/// single round without spinning up the supervisor.
pub(crate) async fn poll_once(
    client: &SensorThingsClient,
    router: &Arc<Router>,
    sub: &Subscription,
    datastream_id: u64,
    page_size: u32,
    entity_kind: rustgate_core::entity::EntityKind,
    since: Option<&str>,
) -> Result<Option<String>, SensorThingsError> {
    let page = client.poll(datastream_id, page_size, since).await?;
    if page.value.is_empty() {
        return Ok(None);
    }
    for observation in &page.value {
        if let Some(msg) = observation_to_message(observation, entity_kind.clone(), sub) {
            router.route(msg).await;
        }
    }
    // Advance the cursor to the maximum *parseable* `phenomenonTime` in the
    // page rather than the last entry. The previous code trusted the server's
    // `phenomenonTime asc` ordering pin, so a server that returned events out
    // of order could drive the cursor backwards (re-delivery) or skip ahead
    // (M-5). Each candidate is also validated as RFC 3339 before it can
    // become the cursor (M-4): the cursor is interpolated into the next
    // request's `$filter` clause, so an unvalidated server-supplied string
    // would be an OData-injection sink. When no value parses, returning `None`
    // holds the prior cursor — fail-safe, since the `gt` filter re-delivers
    // rather than skips.
    let cursor = max_parseable_cursor(&page.value);
    if cursor.is_none() {
        debug!(
            target: "rustgate.ogc-sensorthings",
            datastream_id = datastream_id,
            count = page.value.len(),
            "no parseable phenomenonTime in non-empty page; holding prior cursor"
        );
    }
    Ok(cursor)
}

/// Return the maximum *parseable* RFC 3339 `phenomenonTime` across a page,
/// in its original string form, for use as the next poll cursor.
///
/// Order-independent (does not trust the server's claimed ordering) and
/// injection-safe (only an RFC-3339-valid value can ever be returned, so it
/// is a timestamp literal rather than free-form server text when it lands in
/// the `$filter` clause). Returns `None` when no observation carries a
/// parseable timestamp, which keeps the caller's prior cursor.
fn max_parseable_cursor(observations: &[Observation]) -> Option<String> {
    let mut max: Option<(OffsetDateTime, &str)> = None;
    for obs in observations {
        if let Ok(parsed) = OffsetDateTime::parse(&obs.phenomenon_time, &Rfc3339)
            && max.as_ref().is_none_or(|(m, _)| parsed > *m)
        {
            max = Some((parsed, &obs.phenomenon_time));
        }
    }
    max.map(|(_, s)| s.to_string())
}

/// Project an [`Observation`] onto a [`RoutableMessage`].
///
/// Returns `None` only when the synthetic identity construction
/// fails (a never-fires invariant — the CN constant is fixed ASCII).
/// Surfacing the failure as `None` rather than panicking keeps the
/// polling loop alive.
fn observation_to_message(
    observation: &Observation,
    kind: rustgate_core::entity::EntityKind,
    sub: &Subscription,
) -> Option<RoutableMessage> {
    let entity = observation_to_entity(observation, kind);
    let payload = serde_json::to_vec(&entity).unwrap_or_default();
    let source = match Identity::plaintext(OGC_SENSORTHINGS_SERVICE_CN.to_string(), BTreeSet::new())
    {
        Ok(id) => id,
        Err(e) => {
            // playbook-drift-ok: synthetic-identity construction
            // failure is an internal-invariant diagnostic, not an
            // authn / authz / rate-limit event that belongs in the
            // audit trail. Mirrors the foundry wiring's identical
            // diagnostic path (see crates/rustgate-foundry/src/wiring.rs).
            warn!(
                target: "rustgate.ogc-sensorthings",
                error = %e,
                "SensorThings inbound dropped: synthetic identity could not be constructed"
            );
            return None;
        }
    };
    let destination = match sub.group.as_deref() {
        Some(g) if !g.is_empty() => Destination::Group(Arc::<str>::from(g)),
        _ => Destination::Broadcast,
    };
    Some(RoutableMessage {
        source,
        destination,
        payload: Bytes::from(payload),
        metadata: Metadata::new(
            SystemTime::now(),
            SOURCE_OGC_SENSORTHINGS.to_string(),
            // SensorThings observations are by convention
            // "status updates" rather than "position reports" —
            // they ride as Status so the router's position-cache
            // does not consume them. A subscription whose entity
            // kind is `Track` etc. still rides as Status here;
            // the entity kind controls downstream classification,
            // not the routing-time message type.
            MessageType::Status,
        ),
        entity: None,
    })
}

/// Test-only helper that reaches into `observation_to_message` so
/// integration tests can pin the wire shape without owning a
/// `Router`. Re-exported behind `pub mod testing` rather than via
/// `#[cfg(test)]` so the integration tests in `tests/polling.rs`
/// can use it.
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// Public-test-only wrapper around the private
    /// `observation_to_message`. Hidden from rustdoc so it does
    /// not leak into the public API.
    pub fn observation_to_message_for_test(
        observation: &Observation,
        kind: rustgate_core::entity::EntityKind,
        sub: &Subscription,
    ) -> Option<RoutableMessage> {
        super::observation_to_message(observation, kind, sub)
    }

    /// Decode the `Entity` payload from a [`RoutableMessage`] the
    /// wiring emitted. The payload is a JSON-serialised
    /// [`Entity`] — the test asserts on the decoded shape.
    pub fn decode_entity_payload(msg: &RoutableMessage) -> Entity {
        // justification: tests are exempt from `unwrap_used` /
        // `panic` denial; this helper is exposed under a `testing`
        // module that is only consumed from the integration tests.
        let _ = msg;
        serde_json::from_slice::<Entity>(msg.payload.as_ref())
            .expect("payload must be JSON-serialised Entity")
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::EntityKindTag;

    fn observation() -> Observation {
        serde_json::from_str(
            r#"{
                "@iot.id": 7,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": 23.5
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn observation_to_message_uses_broadcast_when_no_group() {
        let obs = observation();
        let sub = Subscription {
            datastream_id: 42,
            entity_kind: EntityKindTag::Sensor,
            group: None,
            poll_interval_secs: None,
            page_size: None,
        };
        let msg = observation_to_message(&obs, rustgate_core::entity::EntityKind::Sensor, &sub)
            .expect("identity built");
        assert!(matches!(msg.destination, Destination::Broadcast));
        assert_eq!(msg.metadata.source_protocol, SOURCE_OGC_SENSORTHINGS);
        assert_eq!(msg.source.cn.as_ref(), OGC_SENSORTHINGS_SERVICE_CN);
        assert_eq!(msg.metadata.message_type, MessageType::Status);
    }

    #[test]
    fn observation_to_message_uses_group_destination_when_configured() {
        let obs = observation();
        let sub = Subscription {
            datastream_id: 42,
            entity_kind: EntityKindTag::Sensor,
            group: Some("weather".into()),
            poll_interval_secs: None,
            page_size: None,
        };
        let msg = observation_to_message(&obs, rustgate_core::entity::EntityKind::Sensor, &sub)
            .expect("identity built");
        match msg.destination {
            Destination::Group(g) => assert_eq!(g.as_ref(), "weather"),
            other => panic!("expected Group destination, got {:?}", other),
        }
    }

    #[test]
    fn observation_to_message_treats_empty_group_as_broadcast() {
        let obs = observation();
        let sub = Subscription {
            datastream_id: 42,
            entity_kind: EntityKindTag::Sensor,
            group: Some("".into()),
            poll_interval_secs: None,
            page_size: None,
        };
        let msg = observation_to_message(&obs, rustgate_core::entity::EntityKind::Sensor, &sub)
            .expect("identity built");
        assert!(matches!(msg.destination, Destination::Broadcast));
    }

    #[test]
    fn observation_to_message_payload_is_serialised_entity() {
        let obs = observation();
        let sub = Subscription {
            datastream_id: 42,
            entity_kind: EntityKindTag::Sensor,
            group: None,
            poll_interval_secs: None,
            page_size: None,
        };
        let msg =
            observation_to_message(&obs, rustgate_core::entity::EntityKind::Sensor, &sub).unwrap();
        let entity: Entity = serde_json::from_slice(msg.payload.as_ref()).unwrap();
        assert_eq!(entity.uid, "sensorthings-observation-7");
    }

    #[test]
    fn cursor_is_max_not_last_and_rejects_unparseable() {
        fn obs_at(t: &str) -> Observation {
            serde_json::from_str(&format!(
                r#"{{"@iot.id": 1, "phenomenonTime": "{t}", "result": 1}}"#
            ))
            .unwrap()
        }

        // Out-of-order page: the LAST entry is not the maximum. Trusting the
        // server's claimed ordering (the old behaviour) would drive the cursor
        // backwards to 11:00 and re-deliver 12:00 every poll; max-tracking
        // pins it to 12:00 regardless of order (M-5).
        let page = vec![
            obs_at("2026-05-08T10:00:00Z"),
            obs_at("2026-05-08T12:00:00Z"),
            obs_at("2026-05-08T11:00:00Z"),
        ];
        assert_eq!(
            max_parseable_cursor(&page).as_deref(),
            Some("2026-05-08T12:00:00Z")
        );

        // An injection-shaped / non-RFC-3339 value can never become the
        // cursor — it is skipped, and the max of the valid values is used
        // (M-4): the cursor reaches the next request's `$filter` clause.
        let page = vec![
            obs_at("2026-05-08T09:00:00Z"),
            obs_at("2026-01-01T00:00:00Z or 1 eq 1"),
        ];
        assert_eq!(
            max_parseable_cursor(&page).as_deref(),
            Some("2026-05-08T09:00:00Z")
        );

        // All-unparseable page → None, which holds the prior cursor
        // (fail-safe: the `gt` filter re-delivers rather than skips).
        let page = vec![obs_at("not-a-timestamp")];
        assert_eq!(max_parseable_cursor(&page), None);
    }
}
