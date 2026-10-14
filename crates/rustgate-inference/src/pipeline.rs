// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! In-process inference pipeline.
//!
//! [`Pipeline`] holds an ordered list of registered models behind an
//! [`arc_swap::ArcSwap`] so the model set can be hot-reloaded
//! without restarting the back-annotation task. The pipeline's `run`
//! method walks every registered model, invokes its `infer` call,
//! and collects the results into a `Vec<InferenceResult>`. Errors
//! from individual models are downgraded to a debug log so a single
//! misbehaving model does not poison the whole pipeline.
//!
//! Confidence-threshold flagging is applied at result-collection
//! time: if a result's `confidence` is below the per-model threshold
//! (or the pipeline default when no per-model override is set), the
//! result is still returned but with a `low_confidence = true` entry
//! injected into its `attributes` bag. The downstream consumer is
//! free to filter on this attribute or surface it as a UI hint.

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustgate_core::entity::Entity;
use rustgate_core::identity::AttrValue;

use crate::config::DEFAULT_CONFIDENCE_THRESHOLD;
use crate::model::{InferenceModel, InferenceResult};

/// Sentinel attribute key marking a result whose confidence fell
/// below the configured threshold. Downstream consumers SHOULD treat
/// these results as informational rather than authoritative.
pub const LOW_CONFIDENCE_KEY: &str = "low_confidence";

type ModelList = Arc<Vec<Arc<dyn InferenceModel>>>;

/// Hot-reloadable inference pipeline.
///
/// Cloning a `Pipeline` is cheap — clones share the underlying
/// `ArcSwap` so a `reload` on one clone is observed by every other
/// clone. The back-annotation task holds one clone; an admin or
/// reload task holds another.
#[derive(Clone, Debug)]
pub struct Pipeline {
    models: Arc<ArcSwap<Vec<Arc<dyn InferenceModel>>>>,
    threshold: f32,
}

impl Pipeline {
    /// Build a new pipeline with the given default confidence
    /// threshold. The threshold MUST be in `[0.0, 1.0]`; values
    /// outside that range are clamped.
    pub fn new(threshold: f32) -> Self {
        let clamped = threshold.clamp(0.0, 1.0);
        Self {
            models: Arc::new(ArcSwap::from_pointee(Vec::new())),
            threshold: clamped,
        }
    }

    /// Pipeline with the workspace default threshold.
    pub fn with_default_threshold() -> Self {
        Self::new(DEFAULT_CONFIDENCE_THRESHOLD)
    }

    /// Replace the registered model list. Subsequent calls to
    /// [`Self::run`] see the new set; in-flight calls observe a
    /// consistent snapshot of the previous set.
    pub fn reload(&self, models: Vec<Arc<dyn InferenceModel>>) {
        self.models.store(Arc::new(models));
    }

    /// Snapshot the currently registered model names. Useful for
    /// admin endpoints that surface "what is loaded right now".
    pub fn registered_names(&self) -> Vec<String> {
        self.models
            .load()
            .iter()
            .map(|m| m.name().to_string())
            .collect()
    }

    /// The configured pipeline-wide default threshold.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Run every registered model against `entity` and collect the
    /// results. Models whose `infer` call returns an `Err` are
    /// dropped from the output with a `tracing::debug!` log; one
    /// model failing does not abort the rest.
    ///
    /// Results below the configured threshold are still returned
    /// with [`LOW_CONFIDENCE_KEY`] injected into their attribute
    /// bag.
    pub async fn run(&self, entity: &Entity) -> Vec<InferenceResult> {
        let snapshot: ModelList = self.models.load_full();
        let mut out = Vec::with_capacity(snapshot.len());
        for model in snapshot.iter() {
            match model.infer(entity).await {
                Ok(mut result) => {
                    if result.confidence < self.threshold {
                        let _ = result
                            .attributes
                            .insert(LOW_CONFIDENCE_KEY.into(), AttrValue::Bool(true));
                    }
                    out.push(result);
                }
                Err(err) => {
                    tracing::debug!(
                        model = %model.name(),
                        entity_uid = %entity.uid,
                        error = %err,
                        "inference: model rejected entity",
                    );
                }
            }
        }
        out
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::with_default_threshold()
    }
}
