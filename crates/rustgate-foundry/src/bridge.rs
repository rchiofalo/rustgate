// Copyright © 2026 Roberto Chiofalo.

//! The [`FoundryBridge`] trait — integration boundary between the
//! rustgate router and the Palantir Foundry / Gotham tenant.
//!
//! The trait is intentionally small. Three method shapes cover the
//! integration surface this crate ships:
//!
//! - [`FoundryBridge::upsert_object`] for outbound entity → object
//!   projection,
//! - [`FoundryBridge::subscribe_changes`] for inbound object →
//!   entity injection,
//! - [`FoundryBridge::invoke_action`] for action relay (operator
//!   button-press in a Foundry workspace dispatches a typed message
//!   back to the edge).
//!
//! Implementors live behind a feature flag: today
//! [`crate::mock::MockFoundryBridge`] (under `foundry-mock`) is the
//! reference implementation; the partner-gated SDK adapter lands
//! under `foundry-real` in a follow-up.

use async_trait::async_trait;
use futures::stream::BoxStream;
use serde_json::Value;

use crate::error::FoundryError;

/// Stable identifier for an object in the Foundry ontology.
///
/// Format is opaque to this crate — Foundry surfaces RIDs (Resource
/// Identifiers) of the form `ri.ontology.…` for objects and the SDK
/// implementation captures the canonical form. The wiring carries
/// the value through verbatim so the round-trip from upsert →
/// change-stream → action-callback can be correlated by `ObjectId`
/// without parsing it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ObjectId(pub String);

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for ObjectId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ObjectId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// A single change observed on a Foundry change stream.
///
/// Carried over the bridge's [`FoundryBridge::subscribe_changes`]
/// stream; the inbound wiring task reverses the property-map and
/// produces a [`rustgate_core::message::RoutableMessage`] for the
/// router. Foundry's wire form distinguishes object creates,
/// updates, and deletes — the [`change_type`](Self::change_type)
/// field carries the discriminator so the wiring can emit the right
/// shape downstream.
///
/// `properties` is the Foundry-side property bag verbatim; the
/// inbound wiring projects it back into an entity via
/// [`crate::mapper::PropertyMapper::foundry_to_entity_overlay`].
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectChange {
    /// Foundry object-type ID this change refers to (e.g.
    /// `mil-track-dismount`). Matches the `foundry-type` field on a
    /// configured [`crate::config::ObjectTypeMapping`].
    pub type_id: String,
    /// Foundry RID of the changed object.
    pub object_id: ObjectId,
    /// Whether this change was a create, update, or delete.
    pub change_type: ChangeType,
    /// The Foundry property bag at the moment of the change. For
    /// `Delete`, this is the last-seen property bag.
    pub properties: Value,
}

/// Discriminator for a Foundry change-stream event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeType {
    /// New ontology object materialised in the Foundry tenant.
    Created,
    /// Existing ontology object's properties were modified.
    Updated,
    /// Ontology object was retracted from the tenant.
    Deleted,
}

/// Operator-fired Action invocation. Foundry "Actions" are typed
/// operations a workspace user triggers (a button on the UI, a
/// scripted batch); the action body is forwarded to the bridge so
/// the rustgate side can fan it out to the edge as a
/// [`rustgate_core::message::RoutableMessage`].
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequest {
    /// Foundry-side identifier for the action type (e.g.
    /// `mil-action-dispatch`). Determines how the wiring renders
    /// the resulting RoutableMessage.
    pub action_id: String,
    /// Action arguments verbatim. The wiring's responsibility is to
    /// project this back into entity-shape via the property-map (or
    /// pass through opaque to the action handler).
    pub arguments: Value,
}

/// Result of an action invocation. `output` is opaque JSON — Foundry
/// actions return arbitrary structured data and the wiring forwards
/// it to whichever consumer requested the action. Actions whose only
/// effect is to publish a RoutableMessage will typically return
/// [`Value::Null`].
#[derive(Debug, Clone, PartialEq)]
pub struct ActionResult {
    /// Whether Foundry accepted and committed the action.
    pub committed: bool,
    /// Free-form structured output. JSON `null` when the action has
    /// no payload to return.
    pub output: Value,
}

/// Bidirectional bridge to a Palantir Foundry / Gotham tenant.
///
/// Implementors MUST be `Send + Sync` so the wiring tasks can hold
/// the bridge as `Arc<dyn FoundryBridge>` and dispatch concurrently.
/// The async trait is used here (rather than impl-trait return
/// position) because the wiring stores the bridge in
/// `Arc<dyn FoundryBridge>` slots that need to be object-safe.
///
/// Failure-mode contract:
///
/// - Transport-layer failures (WebSocket dropped, REST timeout)
///   surface as [`FoundryError::Offline`] so the outbound wiring's
///   offline-queue is engaged. Implementors that distinguish
///   "currently disconnected, will reconnect" from "permanent
///   failure" SHOULD use `Offline` for the former.
/// - Tenant-side rejections (4xx, schema mismatch) surface as
///   [`FoundryError::BadRequest`].
/// - Anything else, including SDK-internal panics that the adapter
///   has caught, surface as [`FoundryError::Backend`].
#[async_trait]
pub trait FoundryBridge: Send + Sync {
    /// Upsert a single ontology object.
    ///
    /// `type_id` is the Foundry object-type identifier and
    /// `properties` is the property bag the wiring assembled via
    /// [`crate::mapper::PropertyMapper::entity_to_foundry`]. The
    /// implementation returns the resulting [`ObjectId`] — Foundry
    /// allocates the RID, this crate does not.
    ///
    /// On `FoundryError::Offline` the outbound wiring queues the
    /// upsert for replay on reconnect. Every other error variant is
    /// surfaced to the caller and emitted at `tracing::warn!`.
    async fn upsert_object(
        &self,
        type_id: &str,
        properties: Value,
    ) -> Result<ObjectId, FoundryError>;

    /// Subscribe to the change stream for a single object type.
    ///
    /// Returns an asynchronous stream of [`ObjectChange`] events the
    /// inbound wiring drains and converts back into routable
    /// messages. The stream is expected to remain open across
    /// transient disconnects — implementors handle reconnection
    /// internally rather than terminating the stream.
    ///
    /// The returned stream is `'static` so the wiring can hand it
    /// to a spawned task that outlives this method's `&self`
    /// borrow.
    async fn subscribe_changes(
        &self,
        type_id: &str,
    ) -> Result<BoxStream<'static, ObjectChange>, FoundryError>;

    /// Invoke a Foundry Action.
    ///
    /// Actions are operator-fired; this method exists on the trait
    /// so the wiring shape is final ahead of the partner-gated SDK
    /// integration. The mock implementation echoes the request as
    /// the result so end-to-end tests can drive the action path.
    async fn invoke_action(&self, request: ActionRequest) -> Result<ActionResult, FoundryError>;
}
