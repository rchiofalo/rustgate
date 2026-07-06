// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the [`prepare_egress_envelope`] helper extracted
//! from `route_for_egress` (closes #746 first half — the helper itself
//! plus migration of the multicast call site).
//!
//! The helper renders a single post-Send-PEP `Arc<RoutableMessage>` for
//! a sink fan-out, runs obligation actuation exactly once per envelope,
//! and emits one `egress.obligation.applied` audit event per applied
//! obligation per envelope. This file pins the externally-observable
//! contract through `Router::route_for_egress`:
//!
//! 1. **Deny-first across multicast groups** — a single per-group deny
//!    on a multicast destination suppresses the egress envelope so no
//!    external sink observes a partially-masked or unmasked copy.
//! 2. **Audit-event emission** — a tracing subscriber capturing the
//!    `audit` target sees one `egress.obligation.applied` record per
//!    applied obligation per envelope, with the documented field
//!    vocabulary (`sink`, `obligation_type`, `recipient_class`).
//!
//! [`prepare_egress_envelope`]:
//!     rustgate_router::egress::prepare_egress_envelope

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_authz::{
    Action, Decision, DecisionOutcome, Obligation, PolicyEngine, Resource, Subject,
};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::{RecipientClass, Router, SessionHandle};
use tokio::sync::mpsc;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

const SAMPLE_COT: &[u8] = br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;

fn identity(cn: &str, groups: &[&str]) -> Arc<Identity> {
    Arc::new(
        Identity::new(
            cn.to_string(),
            format!("{cn}-fp"),
            groups
                .iter()
                .map(|g| g.to_string())
                .collect::<BTreeSet<_>>(),
        )
        .expect("valid identity"),
    )
}

#[allow(clippy::type_complexity)]
fn channels() -> (
    mpsc::Sender<rustgate_router::RoutedMessage>,
    mpsc::Sender<rustgate_router::RoutedMessage>,
    mpsc::Receiver<rustgate_router::RoutedMessage>,
    mpsc::Receiver<rustgate_router::RoutedMessage>,
) {
    let (ptx, prx) = mpsc::channel(16);
    let (ntx, nrx) = mpsc::channel(16);
    (ptx, ntx, prx, nrx)
}

fn position(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(SAMPLE_COT),
        metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Position),
        entity: None,
    }
}

/// Engine that denies one specific group on Send and allows everything
/// else. Use this to drive the deny-first arm of
/// `prepare_egress_envelope` through a multicast envelope.
struct DenyOneGroup {
    deny_group: &'static str,
}

impl PolicyEngine for DenyOneGroup {
    fn evaluate(&self, _s: &Subject<'_>, r: &Resource<'_>, _a: Action) -> DecisionOutcome {
        let denied = matches!(r, Resource::Group { group } if *group == self.deny_group);
        if denied {
            DecisionOutcome {
                decision: Decision::Deny,
                rule_id: None,
                obligations: Vec::new(),
            }
        } else {
            DecisionOutcome {
                decision: Decision::Allow,
                rule_id: None,
                obligations: Vec::new(),
            }
        }
    }
    fn policy_id(&self) -> &str {
        "test-746-deny-one"
    }
}

/// Engine that allows everything and attaches `MaskPoint` on Send. Used
/// by the audit-emission test to drive the helper through the
/// payload-mutating path.
struct AllowWithMaskPoint;
impl PolicyEngine for AllowWithMaskPoint {
    fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, a: Action) -> DecisionOutcome {
        let obligations = if a == Action::Send {
            vec![Obligation::MaskPoint]
        } else {
            Vec::new()
        };
        DecisionOutcome {
            decision: Decision::Allow,
            rule_id: None,
            obligations,
        }
    }
    fn policy_id(&self) -> &str {
        "test-746-allow-mask"
    }
}

#[tokio::test]
async fn multicast_envelope_is_denied_when_any_group_denies() {
    // Deny-first across the multicast groups: the engine denies the
    // single group `bravo`, the rest allow. The egress envelope must
    // be suppressed (`route_for_egress` returns `None`) so no external
    // sink observes a partial or unmasked copy. Local fanout still
    // delivers to allow-side groups via the per-group local pass.
    let router = Router::new().with_authz(Arc::new(DenyOneGroup {
        deny_group: "bravo",
    }));
    let alice = identity("alice", &["alpha", "bravo"]);
    let bob = identity("bob", &["alpha"]);
    let charlie = identity("charlie", &["bravo"]);

    let (ptx_a, ntx_a, _pa, _na) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    let (ptx_c, ntx_c, _pc, _nc) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
        .await;

    let routed = router
        .route_for_egress(position(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        ))
        .await;

    assert!(
        routed.is_none(),
        "egress envelope must be denied when any addressed group denies"
    );
}

/// Tracing layer that captures every audit event emitted at target
/// `"audit"` for inspection in the asserting test.
#[derive(Default)]
struct AuditCapture {
    records: Arc<Mutex<Vec<AuditRecord>>>,
}

#[derive(Debug, Clone)]
struct AuditRecord {
    event_type: String,
    fields: Vec<(String, String)>,
}

impl AuditCapture {
    fn snapshot(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap().clone()
    }
    fn handle(&self) -> Arc<Mutex<Vec<AuditRecord>>> {
        Arc::clone(&self.records)
    }
}

struct AuditLayer {
    sink: Arc<Mutex<Vec<AuditRecord>>>,
}

impl<S> tracing_subscriber::Layer<S> for AuditLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "audit" {
            return;
        }
        let mut visitor = AuditFieldVisitor::default();
        event.record(&mut visitor);
        self.sink.lock().unwrap().push(AuditRecord {
            event_type: visitor.event_type,
            fields: visitor.fields,
        });
    }
}

#[derive(Default)]
struct AuditFieldVisitor {
    event_type: String,
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for AuditFieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "event_type" {
            self.event_type = value.to_string();
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let formatted = format!("{value:?}");
        // tracing's `Display` capture surfaces strings with surrounding
        // quotes via `record_debug` when no `record_str` impl claims the
        // field; trim them so the assertion sees the bare value.
        let trimmed = formatted.trim_matches('"').to_string();
        if field.name() == "event_type" {
            self.event_type = trimmed;
        } else {
            self.fields.push((field.name().to_string(), trimmed));
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn egress_obligation_applied_audit_event_fires_with_expected_fields() {
    // Install a tracing subscriber that captures every audit event into
    // a shared sink, then route a multicast message that triggers the
    // payload-mutating path (MaskPoint applied to the egress envelope).
    // Assert exactly one `egress.obligation.applied` record fires per
    // applied obligation per envelope, with the documented field
    // vocabulary.
    let capture = AuditCapture::default();
    let sink = capture.handle();
    let subscriber = tracing_subscriber::registry().with(AuditLayer { sink });
    let _guard = tracing::subscriber::set_default(subscriber);

    let router = Router::new().with_authz(Arc::new(AllowWithMaskPoint));
    let alice = identity("alice", &["alpha", "bravo"]);

    let (ptx_a, ntx_a, _pa, _na) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;

    let routed = router
        .route_for_egress(position(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        ))
        .await
        .expect("envelope must be produced when every group allows");

    // Sanity: the rendered envelope is masked (contract from #738),
    // so the obligation actually ran on the egress side.
    let s = std::str::from_utf8(&routed.payload).expect("egress payload is UTF-8");
    assert!(
        s.contains(r#"lat="0.0""#),
        "egress envelope must have MaskPoint applied: {s}"
    );

    // Locate the egress.obligation.applied record. Exactly one fires
    // for the envelope (not one per recipient — that's the central
    // #746 cadence improvement).
    let records = capture.snapshot();
    let egress: Vec<&AuditRecord> = records
        .iter()
        .filter(|r| r.event_type == "egress.obligation.applied")
        .collect();
    assert_eq!(
        egress.len(),
        1,
        "exactly one egress.obligation.applied event per envelope, got {records:?}"
    );

    let fields: std::collections::BTreeMap<&str, &str> = egress[0]
        .fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        fields.get("sink").copied(),
        Some("multicast"),
        "sink field must be the multicast sink label, got fields={fields:?}"
    );
    assert_eq!(
        fields.get("obligation_type").copied(),
        Some("mask_point"),
        "obligation_type must be the MaskPoint label, got fields={fields:?}"
    );
    let recipient_class = fields
        .get("recipient_class")
        .copied()
        .expect("recipient_class field must be present");
    assert!(
        recipient_class.starts_with("multicast:["),
        "recipient_class must render the multicast group list, got {recipient_class:?}"
    );
    assert!(
        recipient_class.contains("alpha") && recipient_class.contains("bravo"),
        "recipient_class must include every addressed group, got {recipient_class:?}"
    );
    assert_eq!(
        fields.get("action").copied(),
        Some("apply_obligation"),
        "action field must be apply_obligation, got fields={fields:?}"
    );
    assert_eq!(
        fields.get("result").copied(),
        Some("success"),
        "result field must be success, got fields={fields:?}"
    );
}

/// Engine that allows everything and attaches `MaskPoint` only to the
/// HTTP sink class (Broadcast resource). Used to pin the per-sink fold
/// behaviour of [`Router::prepare_egress_envelope_for_sink`] — different
/// sinks observe different obligation outcomes for the same inbound
/// message.
struct MaskHttpOnly;
impl PolicyEngine for MaskHttpOnly {
    fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, a: Action) -> DecisionOutcome {
        // Every send obligates `MaskPoint`; non-Send actions pass
        // through unmodified. The single-recipient sinks (NATS, HTTP,
        // federation) all evaluate against `Resource::Broadcast` — they
        // are not group-aware — so this engine emits `MaskPoint` for
        // every wired sink, exercising the audit-event-per-sink fold
        // that `prepare_egress_envelope_for_sink` is documented to
        // produce.
        let obligations = if a == Action::Send {
            vec![Obligation::MaskPoint]
        } else {
            Vec::new()
        };
        DecisionOutcome {
            decision: Decision::Allow,
            rule_id: None,
            obligations,
        }
    }
    fn policy_id(&self) -> &str {
        "test-746-mask-http-only"
    }
}

#[tokio::test(flavor = "current_thread")]
async fn per_sink_envelope_renders_mask_point_for_each_sink_class() {
    // Pin the public-API contract of
    // `Router::prepare_egress_envelope_for_sink` — closes #746. For a
    // single inbound message the helper must produce one envelope per
    // sink class, each carrying its own audit-event emission. With
    // every sink-side rule attaching `MaskPoint`, three wired sinks
    // (NATS, HTTP, federation) MUST surface three independent
    // `egress.obligation.applied` events with distinct `sink` labels.
    let capture = AuditCapture::default();
    let sink = capture.handle();
    let subscriber = tracing_subscriber::registry().with(AuditLayer { sink });
    let _guard = tracing::subscriber::set_default(subscriber);

    let router = Router::new().with_authz(Arc::new(MaskHttpOnly));
    let alice = identity("alice", &["alpha"]);

    let nats_envelope = router
        .prepare_egress_envelope_for_sink(
            Arc::new(position(&alice, Destination::Group("alpha".into()))),
            RecipientClass::NatsSink("rg.alpha".to_string()),
        )
        .expect("nats sink envelope must render under an allow-with-MaskPoint policy");
    let http_envelope = router
        .prepare_egress_envelope_for_sink(
            Arc::new(position(&alice, Destination::Group("alpha".into()))),
            RecipientClass::HttpSink("siem".to_string()),
        )
        .expect("http sink envelope must render under an allow-with-MaskPoint policy");
    let fed_envelope = router
        .prepare_egress_envelope_for_sink(
            Arc::new(position(&alice, Destination::Group("alpha".into()))),
            RecipientClass::FederationPeer(rustgate_core::PeerId::new("peer-1".to_string())),
        )
        .expect("federation envelope must render under an allow-with-MaskPoint policy");

    // Every sink envelope is masked — `MaskPoint` ran once per
    // envelope, not per recipient.
    for envelope in [&nats_envelope, &http_envelope, &fed_envelope] {
        let s =
            std::str::from_utf8(&envelope.message.payload).expect("rendered payload must be UTF-8");
        assert!(
            s.contains(r#"lat="0.0""#),
            "envelope must have MaskPoint applied: {s}"
        );
        assert_eq!(
            envelope.applied_obligations.len(),
            1,
            "exactly one obligation per sink envelope: {:?}",
            envelope.applied_obligations
        );
    }

    // Audit log carries one `egress.obligation.applied` per sink
    // class. The `sink` field renders the small fixed-vocabulary
    // label so SIEM correlation can group by sink without parsing the
    // recipient label.
    let records = capture.snapshot();
    let by_sink: Vec<&str> = records
        .iter()
        .filter(|r| r.event_type == "egress.obligation.applied")
        .filter_map(|r| {
            r.fields
                .iter()
                .find(|(k, _)| k == "sink")
                .map(|(_, v)| v.as_str())
        })
        .collect();
    assert!(
        by_sink.contains(&"nats"),
        "expected nats sink event in {by_sink:?}"
    );
    assert!(
        by_sink.contains(&"http"),
        "expected http sink event in {by_sink:?}"
    );
    assert!(
        by_sink.contains(&"federation"),
        "expected federation sink event in {by_sink:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn per_sink_envelope_passthrough_when_no_engine_installed() {
    // No authz engine means no Send-PEP, so the helper hands back the
    // input arc verbatim — same allocation, same payload, no audit
    // events. The `applied_obligations` vector is empty so callers can
    // detect the no-op path without inspecting the message body.
    let router = Router::new();
    let alice = identity("alice", &["alpha"]);
    let inbound = Arc::new(position(&alice, Destination::Group("alpha".into())));

    let envelope = router
        .prepare_egress_envelope_for_sink(
            Arc::clone(&inbound),
            RecipientClass::NatsSink("rg.alpha".to_string()),
        )
        .expect("no-engine path must always succeed");

    assert!(
        Arc::ptr_eq(&envelope.message, &inbound),
        "no-engine path must return the input arc verbatim (no clone)"
    );
    assert!(
        envelope.applied_obligations.is_empty(),
        "no-engine path must report empty applied obligations: {:?}",
        envelope.applied_obligations
    );
}
