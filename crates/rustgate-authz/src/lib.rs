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
pub mod compile;
pub mod engine;
pub mod error;
pub mod model;
pub mod parser;
pub mod policy;

pub use engine::{CacheStats, NativeEngine, PolicyEngine};
pub use error::AuthzError;
pub use model::{Action, Decision, DecisionOutcome, Obligation, Resource, Subject, SubjectHash};
pub use policy::{Effect, ResourceMatcher, Rule, RuleSet, SubjectMatcher};
