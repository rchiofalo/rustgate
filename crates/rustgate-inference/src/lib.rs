// Copyright © 2026 Roberto Chiofalo.

//! Edge ML inference pipeline for rustgate — closes #858.
//!
//! This crate scaffolds the model-execution surface that lets a
//! rustgate node attach machine-learning–derived attributes
//! (classification, anomaly score, predicted intent) to entities as
//! they flow through the router. The router stays vendor- and
//! framework-agnostic; only this crate knows about model formats and
//! tensor shapes.
//!
//! # Pipeline
//!
//! 1. The router fires its `OnRouted` callback per admitted message
//!    after the Send-PEP allow path.
//! 2. The callback (built via [`wiring::router_callback`]) decodes
//!    the payload via the supplied `EntityCodecRegistry` and submits
//!    the resulting [`rustgate_core::entity::Entity`] to a
//!    [`Pipeline`].
//! 3. The pipeline runs every registered model in order. Each model
//!    produces an [`InferenceResult`] containing the model name, an
//!    optional label, a confidence in `[0.0, 1.0]`, and a free-form
//!    attribute bag.
//! 4. Results below the configured confidence threshold are still
//!    returned but flagged with a `low_confidence = true` attribute
//!    so the downstream consumer can decide whether to surface them.
//!
//! # Hot reload
//!
//! [`Pipeline`] is held behind an [`arc_swap::ArcSwap`] so the
//! registered model set can be swapped without restarting the
//! callback or stopping the router. See [`Pipeline::reload`].
//!
//! # Backends
//!
//! The trait surface ([`InferenceModel`]) is the public extension
//! point. The crate ships one in-tree backend today:
//!
//! - `inference-mock` (feature-gated) — a deterministic backend used
//!   in tests and local development. The module is named `mock`;
//!   doc-link plain-backticked because feature-gated module links
//!   break the workspace `rustdoc::broken-intra-doc-links` gate.
//!
//! An ONNX runtime backend is tracked as future work — see the PR
//! body for the deferred scope.
//!
//! # Provenance loop avoidance
//!
//! The back-annotation task tags messages it produces with a
//! `metadata.source_protocol` value of [`SOURCE_INFERENCE`] so a
//! downstream invocation of the same callback skips them; without
//! this guard, every routed inference event would itself be routed
//! and re-inferred, producing an infinite loop on the local node.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod config;
pub mod error;
pub mod model;
pub mod pipeline;
pub mod wiring;

#[cfg(feature = "inference-mock")]
pub mod mock;

pub use config::{InferenceConfig, ModelTarget, PipelineEntry};
pub use error::InferenceError;
pub use model::{InferenceModel, InferenceResult, ModelMetadata};
pub use pipeline::Pipeline;
pub use wiring::SOURCE_INFERENCE;
