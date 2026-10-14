// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
        // Attached-entity fast path (#1540): when an upstream codec has
        // already decoded the payload into a canonical `Entity` and
        // attached it to the envelope, use it directly and skip the
        // redundant registry decode. This is observably equivalent to
        // decoding `msg.payload` with the registered codec — the attach
        // carries the same entity the registry would produce — but
        // avoids a second parse. Falls back to the codec decode when no
        // entity is attached (the shape at every ingress today). See
        // ADR 0035.
        let entity = if let Some(attached) = msg.entity.as_ref() {
            (**attached).clone()
        } else {
            let Some(codec) = registry.get(&msg.metadata.source_protocol) else {
                return;
            };
            match codec.to_entity_dyn(&msg.payload) {
                Ok(e) => e,
                Err(err) => {
                    tracing::debug!(
                        error = %err,
                        proto = %msg.metadata.source_protocol,
                        "inference: codec rejected payload",
                    );
                    return;
                }
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
        entity: None,
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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};

    use async_trait::async_trait;
    use rustgate_core::entity::{
        DynEntityCodec, DynEntityCodecError, Entity, EntityCodecRegistry, EntityKind,
    };
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata};

    use super::*;
    use crate::model::{InferenceResult, ModelMetadata};
    use crate::{InferenceError, InferenceModel};

    /// A codec that fails on every decode and records whether it was
    /// consulted. The fast-path test asserts this is NEVER called when
    /// the envelope already carries an attached entity — proving the
    /// registry decode is skipped.
    #[derive(Debug, Default)]
    struct ExplodingCodec {
        consulted: AtomicBool,
    }

    impl DynEntityCodec for ExplodingCodec {
        fn to_entity_dyn(&self, _payload: &[u8]) -> Result<Entity, DynEntityCodecError> {
            self.consulted.store(true, Ordering::SeqCst);
            Err("exploding codec: to_entity_dyn must not be reached on the fast path".into())
        }

        fn from_entity_dyn(&self, _entity: &Entity) -> Result<bytes::Bytes, DynEntityCodecError> {
            Err("unused".into())
        }
    }

    /// A trivial model that emits one fixed classification per entity.
    #[derive(Debug)]
    struct FixedModel {
        meta: ModelMetadata,
    }

    #[async_trait]
    impl InferenceModel for FixedModel {
        fn name(&self) -> &str {
            "fixed"
        }
        fn metadata(&self) -> &ModelMetadata {
            &self.meta
        }
        async fn infer(&self, _entity: &Entity) -> Result<InferenceResult, InferenceError> {
            Ok(InferenceResult::classification("fixed", "vehicle", 0.99))
        }
    }

    fn pipeline_with_one_model() -> Arc<ArcSwap<Pipeline>> {
        let pipeline = Pipeline::new(0.5);
        let model: Arc<dyn InferenceModel> = Arc::new(FixedModel {
            meta: ModelMetadata {
                input_shape: vec![],
                output_shape: vec![],
                expected_attributes: vec![],
            },
        });
        pipeline.reload(vec![model]);
        Arc::new(ArcSwap::from_pointee(pipeline))
    }

    fn sample_entity() -> Entity {
        Entity {
            uid: "track-1".into(),
            kind: EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: std::collections::BTreeMap::new(),
            taskings: Vec::new(),
            files: Vec::new(),
        }
    }

    fn message(proto: &str) -> RoutableMessage {
        RoutableMessage {
            source: Identity::plaintext("alice".to_string(), Default::default())
                .expect("plaintext identity"),
            destination: Destination::Broadcast,
            payload: bytes::Bytes::from_static(b"<event/>"),
            metadata: Metadata::new(SystemTime::now(), proto.to_string(), MessageType::Position),
            entity: None,
        }
    }

    /// Sink that counts how many annotated messages were re-injected.
    fn counting_sink() -> (InferenceSink, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let count_for_sink = Arc::clone(&count);
        let sink: InferenceSink = Arc::new(move |_msg| {
            let _ = count_for_sink.fetch_add(1, Ordering::SeqCst);
        });
        (sink, count)
    }

    #[tokio::test]
    async fn attached_entity_fast_path_skips_codec_and_still_infers() {
        // With an attached entity, the callback must use it directly and
        // NOT consult the registry codec. The registered codec explodes
        // if reached, so a passing run proves the fast path fired; the
        // sink counter proves inference still ran end-to-end.
        let pipeline = pipeline_with_one_model();
        let codec = Arc::new(ExplodingCodec::default());
        let mut registry = EntityCodecRegistry::new();
        registry.register("cot", Arc::clone(&codec) as Arc<dyn DynEntityCodec>);
        let (sink, count) = counting_sink();
        let cb = router_callback(pipeline, Arc::new(registry), sink);

        let msg = message("cot").with_entity(sample_entity());
        cb(Arc::new(msg));

        // The back-annotation runs on a spawned task; give it a beat.
        for _ in 0..50 {
            if count.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !codec.consulted.load(Ordering::SeqCst),
            "attached-entity fast path must NOT consult the registry codec"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "inference must still run and re-inject exactly one annotated message"
        );
    }

    #[tokio::test]
    async fn no_attached_entity_falls_back_to_codec_decode() {
        // Control: with no attached entity, the callback consults the
        // registry codec. Our codec errors, so the callback bails before
        // inference and the sink never fires — proving the fallback path
        // is the one taken when `entity` is None.
        let pipeline = pipeline_with_one_model();
        let codec = Arc::new(ExplodingCodec::default());
        let mut registry = EntityCodecRegistry::new();
        registry.register("cot", Arc::clone(&codec) as Arc<dyn DynEntityCodec>);
        let (sink, count) = counting_sink();
        let cb = router_callback(pipeline, Arc::new(registry), sink);

        cb(Arc::new(message("cot")));

        // Nothing should be spawned/inferred; wait briefly to be sure.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            codec.consulted.load(Ordering::SeqCst),
            "fallback path must consult the registry codec when no entity is attached"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "a codec-decode failure must short-circuit before inference"
        );
    }
}
