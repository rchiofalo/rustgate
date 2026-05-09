// Copyright © 2026 Roberto Chiofalo.

//! Public model trait and value types.
//!
//! [`InferenceModel`] is the extension point — backends in third-party
//! crates implement it, register the model with a [`crate::Pipeline`],
//! and the pipeline drives every registered model through a uniform
//! `infer` call once per routed entity. The trait is async so a
//! backend can offload heavy work to a thread pool, a remote model
//! server, or a hardware accelerator without exposing that
//! concurrency model in the trait surface.
//!
//! [`InferenceResult`] is intentionally narrow — a label, a confidence,
//! and a flat attribute bag. Backends that produce richer outputs
//! (bounding boxes, class probability vectors, keypoints) are
//! expected to flatten those into the attribute bag with a
//! consistent prefix (e.g. `"bbox.x"`, `"class.0.prob"`) so the
//! consumer can reconstruct without a backend-specific dependency.

use std::collections::BTreeMap;

use rustgate_core::entity::Entity;
use rustgate_core::identity::AttrValue;

use crate::error::InferenceError;

/// A single model's classification / regression output for one entity.
///
/// Returned by [`InferenceModel::infer`] and surfaced on the routed
/// `RoutableMessage` by the back-annotation task. Carries enough
/// metadata for a downstream consumer to filter by model, threshold
/// the confidence, and correlate with the source entity.
#[derive(Debug, Clone, PartialEq)]
pub struct InferenceResult {
    /// Logical model name as registered with the pipeline.
    pub model_name: String,

    /// Optional human-readable class label. `None` for
    /// regression-style models that emit a continuous score with no
    /// discrete class.
    pub label: Option<String>,

    /// Confidence in `[0.0, 1.0]`. Backends that produce raw logits
    /// MUST apply softmax / sigmoid before returning so the consumer
    /// can compare across models.
    pub confidence: f32,

    /// Free-form attribute bag for backend-specific outputs. Keys
    /// SHOULD be namespaced (`"bbox.x"`, `"keypoint.0.y"`, etc.) to
    /// avoid collision with other models in the same pipeline.
    pub attributes: BTreeMap<String, AttrValue>,
}

impl InferenceResult {
    /// Convenience constructor for the common classification case.
    pub fn classification(
        model_name: impl Into<String>,
        label: impl Into<String>,
        confidence: f32,
    ) -> Self {
        Self {
            model_name: model_name.into(),
            label: Some(label.into()),
            confidence,
            attributes: BTreeMap::new(),
        }
    }
}

/// Static metadata describing a loaded model's input/output contract.
///
/// Returned by [`InferenceModel::metadata`] so the pipeline can
/// validate compatibility (entity attributes provide the inputs the
/// model expects) before the first call. Backends that do not know
/// their tensor shapes upfront (text models, dynamic-batch models)
/// MAY return empty vectors; the pipeline does not require these to
/// be populated.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelMetadata {
    /// Input tensor shape (e.g. `[1, 3, 224, 224]` for an image
    /// classifier). `-1` SHOULD be used for dynamic dimensions.
    pub input_shape: Vec<i64>,

    /// Output tensor shape.
    pub output_shape: Vec<i64>,

    /// Names of [`Entity::attributes`] keys the model expects to be
    /// populated on the input entity. The pipeline does NOT enforce
    /// this — the backend's `infer` call is the authority — but
    /// the list is surfaced via the metadata API for operator
    /// dashboards.
    pub expected_attributes: Vec<String>,
}

/// Bidirectional contract between a model file format and the
/// pipeline's `Entity → InferenceResult` flow.
///
/// Implementors are stateless from the pipeline's perspective — once
/// loaded, the model accepts arbitrary entities and returns
/// independent results. Backends that maintain mutable state
/// (LSTM hidden cells, KV cache) MUST encapsulate that state behind
/// interior mutability and a synchronization primitive so the trait
/// surface stays `Send + Sync` without leaking the locking model.
#[async_trait::async_trait]
pub trait InferenceModel: Send + Sync + std::fmt::Debug {
    /// The logical model name as known to operators and the config
    /// file. The pipeline uses this to namespace results in the
    /// outbound metadata bag (`inference.<name>.confidence`).
    fn name(&self) -> &str;

    /// Static metadata about the model. Cheap — should not perform
    /// I/O. Returned by reference to avoid an allocation on the
    /// hot path.
    fn metadata(&self) -> &ModelMetadata;

    /// Run the model against one entity. The pipeline does not
    /// retry; an `Err` here causes the result to be dropped from the
    /// pipeline output for that entity, with a debug log.
    async fn infer(&self, entity: &Entity) -> Result<InferenceResult, InferenceError>;
}
