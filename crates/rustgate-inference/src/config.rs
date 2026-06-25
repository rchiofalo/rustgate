// Copyright © 2026 Roberto Chiofalo.

//! Configuration types for the inference pipeline.
//!
//! [`InferenceConfig`] is the top-level config block, intended to be
//! deserialized from a TOML section in the rustgate server config:
//!
//! ```toml
//! [inference]
//! models-dir = "/var/lib/rustgate/models"
//! reload-interval-secs = 60
//!
//! [[inference.pipeline]]
//! model-name = "vehicle-classifier"
//! model-path = "vehicle_v3.onnx"
//! target = "classify"
//! confidence-threshold = 0.65
//! ```
//!
//! Field names use kebab-case at the TOML layer
//! (`model-name`, `confidence-threshold`) and are renamed via serde
//! attributes to the standard snake_case Rust field names. The
//! `deny_unknown_fields` attribute catches typos at parse time.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::InferenceError;

/// Default reload interval in seconds. The pipeline does not poll on
/// its own — this is the cadence the server's optional reload task
/// uses when watching the models directory.
pub const DEFAULT_RELOAD_INTERVAL_SECS: u64 = 60;

/// Default confidence threshold below which a result is flagged
/// `low_confidence = true`.
pub const DEFAULT_CONFIDENCE_THRESHOLD: f32 = 0.5;

/// What the model's output represents. Used by the back-annotation
/// task to namespace the outbound metadata key (`classify.label`,
/// `anomaly.score`, `predict.next`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelTarget {
    /// Discrete classification — the result `label` is the predicted
    /// class.
    Classify,
    /// Anomaly score — the result `confidence` is the anomaly score
    /// in `[0.0, 1.0]` and `label` is `None` (or `Some("anomaly")` /
    /// `Some("nominal")` if the backend chose to discretise).
    Anomaly,
    /// Predictive output — e.g. next state, projected position. The
    /// `attributes` bag carries the structured prediction.
    Predict,
}

impl ModelTarget {
    /// Stable string tag for log fields and metric labels.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classify => "classify",
            Self::Anomaly => "anomaly",
            Self::Predict => "predict",
        }
    }
}

/// One pipeline stage — a single model with its load path and per-
/// model threshold override.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PipelineEntry {
    /// Logical model name used for log fields, metric labels, and
    /// the namespaced metadata bag entries.
    pub model_name: String,

    /// Path to the model file. Resolved relative to
    /// [`InferenceConfig::models_dir`] when relative.
    pub model_path: PathBuf,

    /// What the model produces. Drives metadata namespacing.
    pub target: ModelTarget,

    /// Per-model confidence threshold override. When absent, the
    /// pipeline-wide default ([`DEFAULT_CONFIDENCE_THRESHOLD`]) is
    /// used.
    #[serde(default)]
    pub confidence_threshold: Option<f32>,
}

/// Top-level inference pipeline configuration.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct InferenceConfig {
    /// Base directory containing model files. Relative
    /// `pipeline[].model_path` values resolve against this.
    pub models_dir: PathBuf,

    /// How often the optional reload task should re-scan the models
    /// directory.
    #[serde(default = "default_reload_interval_secs")]
    pub reload_interval_secs: u64,

    /// Ordered list of pipeline stages. Models run in sequence per
    /// entity. An empty list is permitted (the pipeline becomes a
    /// no-op).
    #[serde(default)]
    pub pipeline: Vec<PipelineEntry>,
}

impl InferenceConfig {
    /// Validate the config. Returns
    /// [`InferenceError::ConfigInvalid`] on any of:
    ///
    /// - Empty `models_dir` path.
    /// - More than [`rustgate_core::constants::MAX_PIPELINE_ENTRIES`]
    ///   pipeline entries (bounds per-message task / memory fan-out so a
    ///   hostile config cannot trigger a DoS).
    /// - Duplicate `model_name` across pipeline entries.
    /// - `confidence_threshold` outside `[0.0, 1.0]`.
    pub fn validate(&self) -> Result<(), InferenceError> {
        if self.models_dir.as_os_str().is_empty() {
            return Err(InferenceError::ConfigInvalid {
                reason: "models_dir must not be empty".into(),
            });
        }
        // Reject an oversized pipeline before allocating anything sized to
        // it — each entry fans out into one task per model per message, so
        // an unbounded list is a task / memory DoS vector (#1528).
        if self.pipeline.len() > rustgate_core::constants::MAX_PIPELINE_ENTRIES {
            return Err(InferenceError::ConfigInvalid {
                reason: format!(
                    "pipeline has {} entries, exceeds the limit of {}",
                    self.pipeline.len(),
                    rustgate_core::constants::MAX_PIPELINE_ENTRIES
                ),
            });
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.pipeline.len());
        for entry in &self.pipeline {
            if seen.contains(&entry.model_name.as_str()) {
                return Err(InferenceError::ConfigInvalid {
                    reason: format!("duplicate model name `{}`", entry.model_name),
                });
            }
            seen.push(entry.model_name.as_str());
            if let Some(t) = entry.confidence_threshold
                && !(0.0..=1.0).contains(&t)
            {
                return Err(InferenceError::ConfigInvalid {
                    reason: format!(
                        "confidence_threshold for `{}` must be in [0.0, 1.0], got {t}",
                        entry.model_name
                    ),
                });
            }
        }
        Ok(())
    }
}

const fn default_reload_interval_secs() -> u64 {
    DEFAULT_RELOAD_INTERVAL_SECS
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_model_names_rejected() {
        let cfg = InferenceConfig {
            models_dir: PathBuf::from("/models"),
            reload_interval_secs: 60,
            pipeline: vec![
                PipelineEntry {
                    model_name: "m".into(),
                    model_path: PathBuf::from("a.onnx"),
                    target: ModelTarget::Classify,
                    confidence_threshold: None,
                },
                PipelineEntry {
                    model_name: "m".into(),
                    model_path: PathBuf::from("b.onnx"),
                    target: ModelTarget::Anomaly,
                    confidence_threshold: None,
                },
            ],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn out_of_range_threshold_rejected() {
        let cfg = InferenceConfig {
            models_dir: PathBuf::from("/models"),
            reload_interval_secs: 60,
            pipeline: vec![PipelineEntry {
                model_name: "m".into(),
                model_path: PathBuf::from("a.onnx"),
                target: ModelTarget::Classify,
                confidence_threshold: Some(1.5),
            }],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn empty_pipeline_is_valid() {
        let cfg = InferenceConfig {
            models_dir: PathBuf::from("/models"),
            reload_interval_secs: 60,
            pipeline: vec![],
        };
        assert!(cfg.validate().is_ok());
    }

    fn pipeline_of(len: usize) -> Vec<PipelineEntry> {
        (0..len)
            .map(|i| PipelineEntry {
                model_name: format!("model-{i}"),
                model_path: PathBuf::from(format!("m{i}.onnx")),
                target: ModelTarget::Classify,
                confidence_threshold: None,
            })
            .collect()
    }

    #[test]
    fn pipeline_exceeding_max_entries_rejected() {
        // One past the cap → rejected, bounding per-message task fan-out (#1528).
        let cfg = InferenceConfig {
            models_dir: PathBuf::from("/models"),
            reload_interval_secs: 60,
            pipeline: pipeline_of(rustgate_core::constants::MAX_PIPELINE_ENTRIES + 1),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn pipeline_at_max_entries_accepted() {
        // Exactly the cap is allowed (boundary, all names unique).
        let cfg = InferenceConfig {
            models_dir: PathBuf::from("/models"),
            reload_interval_secs: 60,
            pipeline: pipeline_of(rustgate_core::constants::MAX_PIPELINE_ENTRIES),
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn target_round_trip() {
        for t in [
            ModelTarget::Classify,
            ModelTarget::Anomaly,
            ModelTarget::Predict,
        ] {
            let s = serde_json::to_string(&t).unwrap();
            let back: ModelTarget = serde_json::from_str(&s).unwrap();
            assert_eq!(t, back);
        }
    }
}
