// Copyright © 2026 Roberto Chiofalo.

//! HTTP management server: Prometheus exposition, health/readiness probes,
//! and federation/mgmt/ACL APIs.
//!
//! Extracted from `rustgate-server` (#895) so the long-running HTTP
//! microservice that fronts `/metrics`, the Kubernetes liveness/readiness
//! probes, and the operator REST APIs can evolve independently from the
//! Prometheus metric definitions themselves. The metric statics still
//! live with their owning domain crates; this crate is the
//! exposition/management surface.
//!
//! Modules:
//!
//! * [`server`] — HTTP listener, request dispatcher, health/readiness
//!   types, dependency checks, and the moved `cert_expiry_seconds`
//!   gauge that the readiness probe maintains as a side effect.
//! * [`acl_config`] — JSON deserialization for the group ACL policy file.
//! * [`acl_reloader`] — Polling-driven hot-reload for the on-disk ACL file.
//! * [`acl_api`] — REST API for runtime ACL CRUD mounted under `/api/acl/`.
//! * `missions_api` — REST API for the lightweight TAK Data Packages
//!   endpoint (Feature 17 of #860) mounted under `/api/packages/`.
//!   Compiled only with the `missions` feature.
//! * `video` — In-memory CoT `b-i-v` video stream catalog (feature-gated
//!   on the `video` feature) exposed at `GET /api/video/streams`. Closes #862.

#![forbid(unsafe_code)]

pub mod acl_api;
pub mod acl_config;
pub mod acl_reloader;
#[cfg(feature = "correlation")]
pub mod correlation;
#[cfg(feature = "missions")]
pub mod missions_api;
pub mod server;
#[cfg(feature = "video")]
pub mod video;

pub use acl_api::{AclApiState, validate_bearer_token_length};
pub use acl_config::{GroupAclEntry, GroupAclFile};
pub use acl_reloader::AclReloader;
#[cfg(feature = "missions")]
pub use missions_api::{MissionsApiHandler, MissionsApiState};
#[cfg(feature = "correlation")]
pub use server::CorrelationApiHandler;
#[cfg(feature = "federation")]
pub use server::FedApiHandler;
#[cfg(feature = "video")]
pub use server::VideoApiHandler;
pub use server::{
    AclApiHandler, CheckStatus, DEFAULT_MAX_HTTP_CONNECTIONS, DependencyCheck, HealthState,
    MgmtApiHandler, ReadinessReport, ReadinessState, RouterSlot, cert_expiry_seconds, init,
    register_metrics, serve,
};
#[cfg(feature = "video")]
pub use video::{DEFAULT_VIDEO_TTL, VideoEntry, VideoStreamCatalog};
