// Copyright © 2026 Roberto Chiofalo.

//! Pre-routing message interception SPI.
//!
//! Third parties (plugins, integration adapters, on-prem policy
//! shims) hook the router's forward path here to **inspect**,
//! **drop**, or **modify** messages without forking
//! [`crate::Router`]. Interceptors fire AFTER tenant-stamping but
//! BEFORE ACL / dedup / PEP / fanout, so they see the canonical
//! pre-routing form of the message and can replace it before any
//! downstream policy or dispatch runs.
//!
//! ## Wire shape
//!
//! Each interceptor is an [`Arc<dyn Fn>`] closure matching the
//! workspace's [`On*`] callback pattern (object-safe via `Fn`, not
//! `AsyncFn`; async work happens via
//! [`rustgate_core::tasks::spawn_background`] inside the closure
//! body). The router holds a chain of them in declaration order;
//! the first [`InterceptorVerdict::Drop`] wins, and
//! [`InterceptorVerdict::Modify`] replaces the in-flight message
//! for every subsequent interceptor in the same evaluation.
//!
//! ## Verdict semantics
//!
//! - [`InterceptorVerdict::Allow`] — pass through unchanged;
//!   continue to the next interceptor (or to ACL / PEP if this is
//!   the last one).
//! - [`InterceptorVerdict::Drop`] — terminate the route immediately.
//!   The static reason is folded into the existing `dropped` audit
//!   trail with `dropped_reason = "interceptor:<reason>"`; the
//!   router's per-tenant `on_dropped_by_tenant` callback also
//!   fires so the metrics layer captures the loss.
//! - [`InterceptorVerdict::Modify`] — replace the message with the
//!   supplied value. The router clones the modification into the
//!   forward path and continues to the next interceptor. Modifying
//!   the source identity or the tenant id is allowed but operators
//!   should be aware that downstream policy (ACL on the source
//!   group, tenant-scoped store-and-forward) runs against the
//!   *modified* form.
//!
//! ## Composition
//!
//! Multiple interceptors compose in declaration order. The router
//! holds the chain in a single [`arc_swap::ArcSwap`] for lock-free
//! hot-reload — operators can swap the entire chain at runtime
//! without re-creating the router. [`Router::with_interceptor`]
//! appends at construction; [`Router::replace_interceptors`]
//! atomically swaps the whole chain.
//!
//! ## What is intentionally NOT in this SPI
//!
//! - Async interceptor bodies (returning `Future`). The closure is
//!   sync because `dyn AsyncFn` is not object-safe as of Rust 1.93.
//!   Interceptors that need to call out (e.g. an external policy
//!   service) spawn the work via
//!   [`rustgate_core::tasks::spawn_background`] in the closure
//!   body and return [`InterceptorVerdict::Allow`] / `Drop` based
//!   on the closure's cached state. Real-time policy lookups are
//!   the wrong shape for an inline router hook; that pattern is
//!   the existing [`rustgate_authz::PolicyEngine`].
//! - Per-tenant chain filtering. Every interceptor sees every
//!   routed message; interceptors that only care about a subset
//!   of tenants do their own `if` on
//!   [`rustgate_core::message::Metadata::tenant_id`] inside the
//!   closure.
//! - Egress-only interception. The interceptor fires once per
//!   `route_for_egress` call, which is shared by both
//!   internal-fanout and external-sink paths. To intercept only
//!   one direction, use the existing per-direction
//!   [`OnMulticastForward`] / [`OnRouted`] post-route hooks
//!   instead.
//!
//! [`On*`]: crate#callback-conventions
//! [`OnMulticastForward`]: crate::OnMulticastForward
//! [`OnRouted`]: crate::OnRouted

use std::sync::Arc;

use rustgate_core::message::RoutableMessage;

/// Context handed to each interceptor closure. Currently just
/// the message reference; future fields (e.g. a per-evaluation
/// trace span, an admission timestamp) can be added without
/// breaking the closure signature because the context struct is
/// non-exhaustive.
///
/// `'a` ties the context to the borrow of the message — the
/// router does not keep the context across `.await` points, so
/// the lifetime is sound for the inline-evaluation model.
#[non_exhaustive]
#[derive(Debug)]
pub struct InterceptorContext<'a> {
    /// The message about to be routed. Already tenant-stamped;
    /// the source identity, destination, and payload all reflect
    /// the canonical pre-routing form.
    pub message: &'a RoutableMessage,
}

impl<'a> InterceptorContext<'a> {
    /// Construct a context for a borrowed message. Public so
    /// downstream test harnesses can synthesise contexts without
    /// going through the router; the router itself uses this
    /// internally in `route_for_egress`.
    #[must_use]
    pub fn new(message: &'a RoutableMessage) -> Self {
        Self { message }
    }
}

/// What an interceptor decided about the message it inspected.
///
/// Does not derive `PartialEq` because [`RoutableMessage`] does
/// not — tests pattern-match on the variant rather than
/// `assert_eq!`-ing the whole verdict.
#[derive(Debug, Clone)]
pub enum InterceptorVerdict {
    /// Pass through. The router continues to the next interceptor
    /// in the chain, or to ACL / PEP if this was the last one.
    Allow,
    /// Drop the message immediately. The reason is folded into
    /// the existing `dropped` audit trail and the
    /// per-tenant `on_dropped_by_tenant` callback fires with the
    /// reason `interceptor:<reason>`. Subsequent interceptors do
    /// NOT see this message.
    Drop(&'static str),
    /// Replace the in-flight message with this one. Subsequent
    /// interceptors see the modified form; downstream policy
    /// (ACL on source group, tenant-scoped store-and-forward)
    /// runs against the modified form. The owned
    /// [`RoutableMessage`] is moved into the forward path —
    /// interceptors that want to keep a snapshot of the original
    /// must clone it explicitly inside the closure.
    ///
    /// Boxed because [`RoutableMessage`] is a moderately wide
    /// payload struct and the enum would otherwise dominate
    /// every `InterceptorVerdict::Allow` return (the hot path
    /// for the no-op chain). Boxing the rare variant keeps
    /// the `Allow` return at one machine word.
    Modify(Box<RoutableMessage>),
}

/// Type alias for an interceptor closure. Matches the workspace's
/// [`On*`] callback pattern: object-safe `Fn` (not `AsyncFn`),
/// `Send + Sync` so the router can hold the chain across
/// `.await` points and concurrent `route_for_egress` calls.
///
/// Interceptors that need to call out asynchronously do so via
/// [`rustgate_core::tasks::spawn_background`] inside the closure
/// body and return [`InterceptorVerdict::Allow`] /
/// [`InterceptorVerdict::Drop`] based on closure-local state.
///
/// [`On*`]: crate#callback-conventions
pub type MessageInterceptor =
    Arc<dyn Fn(InterceptorContext<'_>) -> InterceptorVerdict + Send + Sync>;
