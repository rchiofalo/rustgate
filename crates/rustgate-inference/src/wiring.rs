// Copyright © 2026 Roberto Chiofalo.

//! Router back-annotation wiring.
//!
//! [`router_callback`] returns a [`rustgate_router::OnRouted`]
//! callback that the server binary plugs into
//! `Router::set_on_routed`. The callback decodes the routed message's
//! payload via the supplied
//! [`rustgate_core::entity::EntityCodecRegistry`], runs the resulting
//! entity through a [`crate::Pipeline`], and emits one annotated
//! `RoutableMessage` per produced [`crate::InferenceResult`] via the
//! supplied re-injection sink.
//!
//! # Provenance loop avoidance
//!
//! The annotated messages are tagged with `metadata.source_protocol =
//! "inference"` (the [`SOURCE_INFERENCE`] constant). The callback's
//! first action on every
//! invocation is to short-circuit when the inbound message already
//! carries that source — without this guard, every annotated event
//! would itself be routed and re-inferred, producing an infinite
//! loop on the local node. The guard is structurally identical to
//! the federation crate's `SOURCE_FEDERATION` discipline.

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustgate_core::entity::EntityCodecRegistry;
use rustgate_core::message::RoutableMessage;
use rustgate_router::OnRouted;

use crate::pipeline::Pipeline;

/// `metadata.source_protocol` value attached to every annotated
/// message produced by the back-annotation task. Used by the
/// callback's loop-avoidance guard.
pub const SOURCE_INFERENCE: &str = "inference";

/// Sink that re-injects an annotated message into the routing
/// pipeline. The server binary supplies a closure that hands the
/// message to `Router::route` (or to a per-tenant fan-out — wiring
/// is the caller's responsibility).
///
/// The sink is invoked from inside the `OnRouted` callback, so it
/// MUST NOT block the routing critical path; implementors typically
/// dispatch onto a `tokio::spawn` or a bounded channel.
pub type InferenceSink = Arc<dyn Fn(Arc<RoutableMessage>) + Send + Sync>;

/// Build an `OnRouted` callback wired against the given pipeline,
/// codec registry, and re-injection sink.
///
/// The callback is intentionally infallible — it logs at `debug`
/// level on codec failure, missing entity attributes, and model
/// errors, rather than propagating an error that the router has no
/// channel for.
pub fn router_callback(
    pipeline: Arc<ArcSwap<Pipeline>>,
    registry: Arc<EntityCodecRegistry>,
    sink: InferenceSink,
) -> OnRouted {
    Arc::new(move |msg: Arc<RoutableMessage>| {
        // Loop guard: skip messages we ourselves produced.
        if msg.metadata.source_protocol == SOURCE_INFERENCE {
            return;
        }
        let Some(codec) = registry.get(&msg.metadata.source_protocol) else {
            return;
        };
        let entity = match codec.to_entity_dyn(&msg.payload) {
            Ok(e) => e,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    proto = %msg.metadata.source_protocol,
                    "inference: codec rejected payload",
                );
                return;
            }
        };
        let pipeline_snapshot = pipeline.load_full();
        let sink = Arc::clone(&sink);
        let msg_for_task = Arc::clone(&msg);
        rustgate_core::tasks::spawn_background("inference-back-annotate", async move {
            let results = pipeline_snapshot.run(&entity).await;
            for result in results {
                let annotated = annotate_message(&msg_for_task, &result);
                sink(Arc::new(annotated));
            }
        });
    })
}

/// Build the annotated message for one [`crate::InferenceResult`].
///
/// The annotated message preserves the original source identity and
/// destination so authorization and ACL still apply to the
/// re-injected event. Only the payload and `source_protocol` are
/// rewritten:
///
/// - The new payload is a JSON envelope `{ "model": …, "label": …,
///   "confidence": …, "attributes": … }` so downstream subscribers
///   can consume it without an inference-crate dependency.
/// - `source_protocol` is set to [`SOURCE_INFERENCE`] for the loop
///   guard.
fn annotate_message(
    original: &RoutableMessage,
    result: &crate::InferenceResult,
) -> RoutableMessage {
    use serde_json::json;

    // Convert the result's AttrValue bag into a JSON object via the
    // serde derive on AttrValue. The wire format here is intentionally
    // separate from the AttrValue tagged enum form so downstream
    // consumers don't need to depend on rustgate-core; re-emit as a
    // flat string-keyed JSON map.
    let attributes_json: serde_json::Map<String, serde_json::Value> = result
        .attributes
        .iter()
        .map(|(k, v)| (k.clone(), attr_to_json(v)))
        .collect();

    let envelope = json!({
        "model": result.model_name,
        "label": result.label,
        "confidence": result.confidence,
        "attributes": attributes_json,
    });

    // serde_json::to_vec on a serde_json::Value cannot fail without
    // an OOM that would also have killed `json!` above; the
    // unwrap_or_default keeps `clippy::unwrap_used` happy and yields
    // an empty payload as a benign fallback.
    let payload = serde_json::to_vec(&envelope).unwrap_or_default();

    let mut metadata = original.metadata.clone();
    metadata.source_protocol = SOURCE_INFERENCE.into();

    RoutableMessage {
        source: original.source.clone(),
        destination: original.destination.clone(),
        payload: payload.into(),
        metadata,
    }
}

fn attr_to_json(v: &rustgate_core::identity::AttrValue) -> serde_json::Value {
    use rustgate_core::identity::AttrValue;
    match v {
        AttrValue::Str(s) => serde_json::Value::String(s.clone()),
        AttrValue::Int(i) => serde_json::Value::Number((*i).into()),
        AttrValue::Bool(b) => serde_json::Value::Bool(*b),
        AttrValue::Set(values) => serde_json::Value::Array(
            values
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    }
}
