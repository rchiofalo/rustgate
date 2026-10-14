// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
//! * a `ConfigMap` carrying the rendered `rustgate.toml` (and, with
//!   federation auto-discovery on, a `federation-peers.json` peer file),
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
//! Behind the `controller` feature flag the crate also ships the live
//! cluster controller — the kube-runtime harness that watches
//! `RustgateCluster` resources, server-side-applies the renderer's
//! output, reads back the owned `StatefulSet.status`, and patches the
//! parent `RustgateCluster.status`. Default builds omit `controller` so
//! the pure-render binary stays lean; the release Docker image opts in.
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

// Controller-only modules. Each one gates itself on
// `#[cfg(feature = "controller")]` at the top, so this re-export block
// only needs to gate the `pub mod` declaration.
#[cfg(feature = "controller")]
pub mod apply;
#[cfg(feature = "controller")]
pub mod controller;
#[cfg(feature = "controller")]
pub mod events;
#[cfg(feature = "controller")]
pub mod health;
#[cfg(feature = "controller")]
pub mod kube_types;
#[cfg(feature = "controller")]
pub mod leader;
#[cfg(feature = "controller")]
pub mod metrics;

#[cfg(feature = "controller")]
pub use controller::{Context as ControllerContext, run as run_controller};
pub use crd::{RustgateCluster, RustgateClusterSpec, RustgateClusterStatus};
pub use error::{OperatorError, Result};
#[cfg(feature = "controller")]
pub use leader::{LeaderConfig, LeaderElector, LeaderGate, default_identity};
pub use reconcile::{ReconcileOutcome, reconcile};
pub use render::{RenderedManifest, render_all, render_all_yaml};
