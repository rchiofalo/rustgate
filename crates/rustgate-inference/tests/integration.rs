// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the inference pipeline using the mock backend.

#![cfg(feature = "inference-mock")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use rustgate_core::entity::{Entity, EntityKind};
use rustgate_inference::mock::MockInferenceModel;
use rustgate_inference::pipeline::{LOW_CONFIDENCE_KEY, Pipeline};
use rustgate_inference::{InferenceModel, InferenceResult};

fn make_entity(uid: &str) -> Entity {
    Entity {
        uid: uid.into(),
        kind: EntityKind::Ground,
        position: None,
        velocity: None,
        timestamp: SystemTime::UNIX_EPOCH,
        callsign: None,
        mil_std_2525_sidc: None,
        attributes: BTreeMap::new(),
        taskings: Default::default(),
        files: Default::default(),
    }
}

#[tokio::test]
async fn pipeline_runs_one_result_per_registered_model() {
    let pipeline = Pipeline::new(0.5);
    let m1: Arc<dyn InferenceModel> = Arc::new(MockInferenceModel::new(
        "classifier-a",
        Some("vehicle".into()),
        0.9,
    ));
    let m2: Arc<dyn InferenceModel> = Arc::new(MockInferenceModel::new(
        "classifier-b",
        Some("person".into()),
        0.8,
    ));
    pipeline.reload(vec![m1, m2]);

    let entity = make_entity("ent-1");
    let results: Vec<InferenceResult> = pipeline.run(&entity).await;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].model_name, "classifier-a");
    assert_eq!(results[0].label.as_deref(), Some("vehicle"));
    assert_eq!(results[1].model_name, "classifier-b");
}

#[tokio::test]
async fn low_confidence_results_are_flagged() {
    let pipeline = Pipeline::new(0.7);
    let low: Arc<dyn InferenceModel> =
        Arc::new(MockInferenceModel::new("low", Some("maybe".into()), 0.3));
    let high: Arc<dyn InferenceModel> =
        Arc::new(MockInferenceModel::new("high", Some("yes".into()), 0.95));
    pipeline.reload(vec![low, high]);

    let results = pipeline.run(&make_entity("ent-2")).await;
    assert_eq!(results.len(), 2);

    // The low-confidence result is returned but flagged.
    let low_result = &results[0];
    assert_eq!(low_result.model_name, "low");
    assert!(low_result.attributes.contains_key(LOW_CONFIDENCE_KEY));

    // The high-confidence result is not flagged.
    let high_result = &results[1];
    assert_eq!(high_result.model_name, "high");
    assert!(!high_result.attributes.contains_key(LOW_CONFIDENCE_KEY));
}

#[tokio::test]
async fn empty_pipeline_returns_no_results() {
    let pipeline = Pipeline::new(0.5);
    let results = pipeline.run(&make_entity("ent-3")).await;
    assert!(results.is_empty());
}

#[tokio::test]
async fn reload_swaps_observable_model_set() {
    let pipeline = Pipeline::new(0.5);
    let m1: Arc<dyn InferenceModel> =
        Arc::new(MockInferenceModel::new("v1", Some("a".into()), 0.9));
    pipeline.reload(vec![m1]);

    let r1 = pipeline.run(&make_entity("ent-4")).await;
    assert_eq!(r1.len(), 1);
    assert_eq!(r1[0].model_name, "v1");

    // Hot-reload to a different model set.
    let m2: Arc<dyn InferenceModel> =
        Arc::new(MockInferenceModel::new("v2", Some("b".into()), 0.9));
    let m3: Arc<dyn InferenceModel> =
        Arc::new(MockInferenceModel::new("v3", Some("c".into()), 0.9));
    pipeline.reload(vec![m2, m3]);

    let r2 = pipeline.run(&make_entity("ent-5")).await;
    assert_eq!(r2.len(), 2);
    assert_eq!(r2[0].model_name, "v2");
    assert_eq!(r2[1].model_name, "v3");

    let names = pipeline.registered_names();
    assert_eq!(names, vec!["v2".to_string(), "v3".to_string()]);
}

#[tokio::test]
async fn default_pipeline_threshold_is_clamped() {
    // Pipeline::new clamps out-of-range thresholds.
    let p = Pipeline::new(2.0);
    assert!((p.threshold() - 1.0).abs() < f32::EPSILON);
    let p = Pipeline::new(-0.5);
    assert!((p.threshold() - 0.0).abs() < f32::EPSILON);
}
