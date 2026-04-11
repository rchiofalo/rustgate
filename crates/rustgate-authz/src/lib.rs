// Copyright © 2026 Roberto Chiofalo.

//! rustgate-authz — RBAC/ABAC policy engine for rustgate.
//!
//! Provides a deny-by-default policy model evaluated on every routed message.
//! Designed for sub-microsecond evaluation in the dataplane hot path.
//!
//! This crate is intentionally self-contained: it defines the policy AST,
//! a JSON parser, a compiler that produces a bucketed decision table, and
//! a [`NativeEngine`] implementation of the [`PolicyEngine`] trait. It is
//! not yet wired into the router — integration lands in a follow-up change.

mod cache;
#[cfg(feature = "cedar")]
pub mod cedar_backend;
pub mod compile;
pub mod engine;
pub mod error;
pub mod model;
pub mod parser;
pub mod policy;

#[cfg(feature = "cedar")]
pub use cedar_backend::CedarBackend;
pub use engine::{NativeEngine, PolicyEngine};
pub use error::AuthzError;
pub use model::{
    Action, CacheStats, Decision, DecisionOutcome, Obligation, Resource, Subject, SubjectHash,
};
pub use policy::{Effect, ResourceMatcher, Rule, RuleSet, SubjectMatcher};
