// Copyright © 2026 Roberto Chiofalo.

//! Transport-agnostic egress forwarding callback aliases.
//!
//! When a session crate (WebSocket, MQTT, future adapters) accepts an
//! inbound message and pushes it through the local router for egress,
//! the server binary wants to fan that same post-Send-PEP message out
//! to optional sinks that live outside the router:
//!
//! - the NATS bridge (horizontal scale-out to peer instances),
//! - the federation layer (server-to-server mesh),
//! - the HTTP egress bridge (webhooks / external SIEMs).
//!
//! Every session crate needs the same three callback shapes. Defining
//! them here keeps the aliases in one place and lets new transports
//! (MAVLink, MQTT, etc.) reuse them without depending on any sibling
//! transport crate. The aliases intentionally use `Fn` — not
//! `AsyncFn` — because `dyn AsyncFn` is not object-safe as of
//! Rust 1.94. Closures dispatch their async work internally via
//! [`spawn_background`](crate::tasks::spawn_background).
//!
//! The router type itself lives in the `rustgate-transport` crate,
//! which depends on this crate — these aliases sit at the lowest
//! common dependency layer so every transport crate and the server
//! binary can reuse the same callback shapes.

use bytes::Bytes;

use crate::message::{Metadata, RoutableMessage};
use crate::on_callback;

on_callback!(
    /// Callback fired after a successful local route to hand the message
    /// off to the NATS publisher.
    ///
    /// The closure spawns async work internally (fire-and-forget). A
    /// `None` value at the call site means "no NATS bridge is wired" and
    /// the transport MUST skip the fan-out.
    pub OnNatsPublish,
    RoutableMessage
);

on_callback!(
    /// Callback fired after a successful local route to hand the payload
    /// off to the federation forwarder.
    ///
    /// Receives `(payload_bytes, source_groups, metadata)` — the payload
    /// is already in post-Send-PEP form (obligations such as `MaskPoint`
    /// applied), and `source_groups` is the set of the client's groups
    /// that the router considered eligible. Downstream peers use this to
    /// make their own deny/allow decisions without having to re-run the
    /// full PEP.
    pub OnFederationForward,
    Bytes,
    Vec<String>,
    Metadata
);

on_callback!(
    /// Callback fired after a successful local route to hand the message
    /// off to the HTTP egress publisher.
    ///
    /// Same shape as [`OnNatsPublish`] — the HTTP bridge drives its own
    /// per-target channel + retry + DLQ path internally.
    pub OnHttpForward,
    RoutableMessage
);

/// Outcome of a cross-domain egress-guard evaluation.
///
/// Distinct from the fire-and-forget `on_callback!` aliases above: a
/// guard is a **gate**, not an observer, so it returns a verdict the
/// router acts on. Deliberately minimal — the guard's own dedicated
/// hash-chained audit log records the full forensic detail; this verdict
/// only tells the router whether the message may continue to external
/// sinks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressGuardVerdict {
    /// The message may continue to external egress sinks.
    Allow,
    /// The message is blocked at the cross-domain boundary and MUST NOT
    /// reach any external sink. `reason` is a stable, low-cardinality
    /// token (`rate_limit` / `missing_marking` /
    /// `unauthorized_classification` / `audit_error`) suitable for the
    /// `audit::guard_rejected` `reason` field and a Prometheus label.
    Deny {
        /// Stable rejection-reason token.
        reason: &'static str,
    },
}

/// Cross-domain egress guard hook (issue #1457).
///
/// Installed on the router via `Router::set_on_egress_guard` and invoked
/// inside `Router::route_for_egress` **after** Send-PEP obligations and
/// the local same-domain session fan-out, and **before** the message's
/// post-route `Arc` is handed to any external sink (NATS / federation /
/// HTTP / MQTT). This is the single egress chokepoint, so one installed
/// guard covers every external sink — present and future — by
/// construction (ADR for #1457; design note
/// `docs/design/guard-server-wiring.md`).
///
/// The closure receives the post-Send-PEP message (full
/// [`RoutableMessage`], so the source CN, classification, and tenant are
/// available for a complete `audit::guard_rejected` record) and returns
/// an [`EgressGuardVerdict`]. A `Deny` verdict causes the router to drop
/// the message from external egress — the guard is **fail-closed** by
/// design.
///
/// `None` (the default) means no guard is wired and the egress path is
/// unchanged; the hot path on the un-installed build is a single
/// `ArcSwap::load` + `is_none()` check, matching the other optional
/// router hooks.
///
/// Uses `Fn` (not `AsyncFn`) for the same object-safety reason as the
/// `on_callback!` aliases; the guard's evaluation is synchronous (token-
/// bucket arithmetic + one audit-log append), so no async dispatch is
/// needed inside the closure.
pub type OnEgressGuard =
    std::sync::Arc<dyn Fn(&RoutableMessage) -> EgressGuardVerdict + Send + Sync>;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::identity::Identity;
    use crate::message::{Destination, MessageType};

    /// Assert the callback alias types satisfy `Send + Sync + Clone`
    /// at compile time. A regression that silently narrowed the
    /// bounds would fail here rather than at the first
    /// `tokio::spawn(async move { cb(msg) })` site in a session
    /// crate.
    #[test]
    fn callback_aliases_are_send_sync_and_clone() {
        fn assert_bounds<T: Send + Sync + Clone>() {}
        assert_bounds::<OnNatsPublish>();
        assert_bounds::<OnFederationForward>();
        assert_bounds::<OnHttpForward>();
    }

    fn sample_message() -> RoutableMessage {
        let mut groups = BTreeSet::new();
        let _ = groups.insert("grp".to_string());
        let id = Identity::plaintext("egress-tests".to_string(), groups)
            .expect("plaintext identity must build");
        RoutableMessage {
            source: id,
            destination: Destination::Group("grp".into()),
            payload: Bytes::from_static(b"hi"),
            metadata: Metadata::new(
                std::time::SystemTime::UNIX_EPOCH,
                "test".into(),
                MessageType::Other("test".into()),
            ),
        }
    }

    #[test]
    fn on_nats_publish_fires_and_forwards_routable_message() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let cb: OnNatsPublish = Arc::new(move |msg| {
            assert_eq!(msg.payload.as_ref(), b"hi");
            let _ = c.fetch_add(1, Ordering::SeqCst);
        });
        cb(sample_message());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn on_http_forward_fires_and_forwards_routable_message() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let cb: OnHttpForward = Arc::new(move |msg| {
            assert_eq!(msg.payload.as_ref(), b"hi");
            let _ = c.fetch_add(1, Ordering::SeqCst);
        });
        cb(sample_message());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn on_federation_forward_receives_payload_groups_and_metadata() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let cb: OnFederationForward = Arc::new(move |payload, groups, meta| {
            assert_eq!(payload.as_ref(), b"hi");
            assert_eq!(groups, vec!["grp".to_string()]);
            assert_eq!(meta.source_protocol.as_str(), "test");
            let _ = c.fetch_add(1, Ordering::SeqCst);
        });
        cb(
            Bytes::from_static(b"hi"),
            vec!["grp".to_string()],
            sample_message().metadata,
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Cloning a callback alias must share the same underlying
    /// closure target — the inner `Arc` is reference-counted, so
    /// invoking either handle must hit the same counter. A
    /// misguided future refactor that replaced the alias with a
    /// `Box<dyn Fn>` or allocated a second `Arc::new(move || {})`
    /// on clone would silently double-count or drop observations;
    /// this test pins the shallow-clone contract.
    #[test]
    fn cloning_a_callback_alias_preserves_shared_state() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let cb: OnNatsPublish = Arc::new(move |_| {
            let _ = c.fetch_add(1, Ordering::SeqCst);
        });
        let cb2 = Arc::clone(&cb);
        cb(sample_message());
        cb2(sample_message());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
