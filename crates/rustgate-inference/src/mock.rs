// Copyright © 2026 Roberto Chiofalo.

//! Deterministic in-memory mock backend for tests and local dev.
//!
//! Feature-gated behind `inference-mock`. The mock returns a fixed
//! label and confidence on every call, optionally synthesising a
//! per-entity attribute (`mock.entity_uid`) so test assertions can
//! distinguish results across multiple entities. The mock never
//! fails the `infer` call — error-path testing is the responsibility
//! of `error.rs` unit tests, not this backend.

use std::collections::BTreeMap;

use rustgate_core::entity::Entity;
use rustgate_core::identity::AttrValue;

use crate::error::InferenceError;
use crate::model::{InferenceModel, InferenceResult, ModelMetadata};

/// Deterministic mock model used in tests and local development.
#[derive(Debug, Clone)]
pub struct MockInferenceModel {
    name: String,
    fixed_label: Option<String>,
    fixed_confidence: f32,
    metadata: ModelMetadata,
}

impl MockInferenceModel {
    /// Build a mock that emits a fixed label and confidence on
    /// every `infer` call.
    pub fn new(
        name: impl Into<String>,
        fixed_label: Option<String>,
        fixed_confidence: f32,
    ) -> Self {
        Self {
            name: name.into(),
            fixed_label,
            fixed_confidence,
            metadata: ModelMetadata {
                input_shape: Vec::new(),
                output_shape: Vec::new(),
                expected_attributes: Vec::new(),
            },
        }
    }
}

#[async_trait::async_trait]
impl InferenceModel for MockInferenceModel {
    fn name(&self) -> &str {
        &self.name
    }

    fn metadata(&self) -> &ModelMetadata {
        &self.metadata
    }

    async fn infer(&self, entity: &Entity) -> Result<InferenceResult, InferenceError> {
        let mut attributes = BTreeMap::new();
        let _ = attributes.insert("mock.entity_uid".into(), AttrValue::Str(entity.uid.clone()));
        Ok(InferenceResult {
            model_name: self.name.clone(),
            label: self.fixed_label.clone(),
            confidence: self.fixed_confidence,
            attributes,
        })
    }
}
