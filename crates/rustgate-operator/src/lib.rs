// Copyright © 2026 Roberto Chiofalo.

//! Kubernetes operator for the `RustgateCluster` CRD — closes #874.
//!
//! This crate ships the Rust types, manifest renderer, and reconcile
//! contract for a Kubernetes operator that manages a `RustgateCluster`
//! resource (`rustgate.io/v1alpha1`). The operator's job is to translate
//! the user-supplied desired state (replicas, image, cert-manager issuer,
//! federation auto-discovery, storage sizes) into the Kubernetes
//! primitives that run a rustgate fleet:
//!
//! * a `StatefulSet` for the replicas,
//! * a headless `Service` for stable pod DNS,
//! * a client-facing `ClusterIP` `Service` for tactical traffic,
//! * a `ConfigMap` carrying the rendered `rustgate.toml`,
//! * (optional) a `cert-manager.io/v1/Certificate` per cluster.
//!
//! ## Architecture
//!
//! The crate intentionally separates three concerns:
//!
//! 1. **`crd`** — the Rust projection of the CRD shape. Hand-rolled serde
//!    types so the build does not depend on the `kube::CustomResource`
//!    procedural macro (which churns more often than the rest of the
//!    operator and pulls in a heavy toolchain).
//! 2. **`render`** — pure functions that translate a `RustgateCluster`
//!    into a deterministic vector of [`render::RenderedManifest`]
//!    entries. This is the source of truth for *what* the operator owns.
//! 3. **`reconcile`** — the contract a live controller would call:
//!    validate, render, and produce a status patch. Stays free of
//!    `kube::Api`/`kube::Client` calls so the renderer stays easy to test.
//!
//! The live cluster controller (which would call the Kubernetes API to
//! apply, observe, and update status) is documented as a deferred
//! follow-up in [`mod@reconcile`]: the renderer is the source of truth
//! for *what* gets created, and the apply-loop is mechanical glue.
//!
//! ## Usage
//!
//! ```no_run
//! use rustgate_operator::crd::RustgateCluster;
//! use rustgate_operator::render::render_all_yaml;
//!
//! let cluster = RustgateCluster::new("my-cluster", "rustgate");
//! let yaml = render_all_yaml(&cluster).expect("render");
//! println!("{yaml}");
//! ```

#![forbid(unsafe_code)]

pub mod crd;
pub mod error;
pub mod reconcile;
pub mod render;

pub use crd::{RustgateCluster, RustgateClusterSpec, RustgateClusterStatus};
pub use error::{OperatorError, Result};
pub use reconcile::{ReconcileOutcome, reconcile};
pub use render::{RenderedManifest, render_all, render_all_yaml};
