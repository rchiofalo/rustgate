// Copyright © 2026 Roberto Chiofalo.

//! Egress envelope rendering for sink fan-out.
//!
//! This module hosts `prepare_egress_envelope` and the supporting
//! [`EgressEnvelope`] / [`RecipientClass`] / [`EgressError`] types.
//! Splitting these out of `router.rs` keeps the routing-engine file
//! anchored to ingress / fanout dispatch and gives the sinks-side
//! obligation rendering its own cohesive home.
//!
//! # Why a dedicated helper
//!
//! The pre-#746 routing engine produced exactly *one* `Arc<RoutableMessage>`
//! per admitted message and handed the same arc to every sink:
//! local fanout, NATS, federation, HTTP, and MQTT. That arc was the
//! result of the **local** Send-PEP path. For destinations whose policy
//! is the same for every recipient (Direct, Group, Broadcast) this is
//! safe — every consumer sees the post-obligation form. For
//! [`rustgate_core::message::Destination::Multicast`] the assumption
//! breaks: per-group obligations are applied recipient-side inside the
//! local fanout, so the `Arc` returned for an external sink is the
//! *unmasked* source form. Closes #738: the egress copy must apply the
//! union of allow-side Send obligations across the addressed groups.
//!
//! `prepare_egress_envelope` generalises that one-shot rendering into
//! a function each sink calls with its own [`RecipientClass`]. The
//! return value caches the post-obligation `Arc` so an N-recipient
//! multicast pays the obligation-actuation cost exactly once. The
//! audit emission (`egress.obligation.applied`) fires per applied
//! obligation per envelope — N=1 per multicast, *not* N=recipients.
//!
//! # Scope of this PR (#746 first half)
//!
//! This PR delivers the helper and migrates the **multicast** call site
//! inside [`crate::router::Router::route_for_egress`]. The companion
//! issue #737 wires the individual sinks (MQTT publisher,
//! NATS-subscriber bridge, federation-inbound) through this helper in
//! follow-up PRs. Until those PRs land the only call site that exercises
//! `prepare_egress_envelope` is the multicast egress arm — but the
//! function is `pub(crate)` because each sink crate (federation, HTTP,
//! NATS, MQTT) calls into the router through the public re-export and
//! the helper itself is part of the transport crate's internal API.

use std::collections::HashSet;
use std::sync::Arc;

use rustgate_authz::{
    Obligation, PolicyEngine, Resource as AuthzResource, Subject as AuthzSubject,
};
use rustgate_core::identity::GroupId;
use rustgate_core::masking::hash_cn;
use rustgate_core::message::RoutableMessage;
use rustgate_core::{PeerId, audit};
use tracing::debug;

// `GroupId` is the workspace-canonical group identifier (`String`); the
// multicast variant of `Destination` carries `Arc<str>` for cheap
// per-fanout sharing. The helper accepts the borrowed `Arc<str>` form
// so the multicast call site does not pay a per-group allocation just
// to bridge into the helper.
use crate::obligations::{
    ObligationRateLimiter, UnknownObligationPolicy, apply_obligations_with_limiter,
    obligations_mutate_payload,
};
use crate::router::obligation_kind_label;

/// Sink class for the egress envelope. Each variant identifies a
/// distinct egress consumer so the policy engine can address it as an
/// `AuthzResource` (for single-recipient sinks) and so the
/// `egress.obligation.applied` audit event carries enough context for
/// SIEM correlation.
///
/// # Variants
///
/// - [`RecipientClass::Multicast`] — a multicast envelope addressed
///   to a list of groups. Obligations are folded across the addressed
///   groups deny-first / most-restrictive: any group whose Send rule
///   denies removes the entire envelope, and the surviving allow-side
///   obligations are unioned so any masking obligation applies to the
///   single rendered copy.
/// - [`RecipientClass::LocalSession`] — a local-session sink keyed by
///   the receiving group (used for parity with the existing
///   `Destination::Group` semantics; today the router still routes
///   local groups via the per-recipient path, so this variant is a
///   forward placeholder for the second half of #746).
/// - [`RecipientClass::NatsSink`] — the NATS publisher addressed by
///   subject. Wired by #737 follow-up PR; today this PR exposes the
///   variant so the NATS side compiles against the same enum.
/// - [`RecipientClass::FederationPeer`] — a federated peer addressed
///   by [`PeerId`]. Wired by #737 follow-up PR.
/// - [`RecipientClass::HttpSink`] — the HTTP webhook publisher
///   addressed by endpoint name. Wired by #737 follow-up PR.
/// - [`RecipientClass::MqttSink`] — the MQTT publisher addressed by
///   topic. Wired by #737 follow-up PR.
#[derive(Debug, Clone)]
pub enum RecipientClass {
    /// Multicast envelope across the listed groups. The vector mirrors
    /// the `Vec<Arc<str>>` carried by
    /// [`rustgate_core::message::Destination::Multicast`] so the call
    /// site does not pay a per-group allocation just to bridge into
    /// the helper. Order is preserved verbatim from the source
    /// message so the audit-log `recipient_class` field renders
    /// deterministically.
    Multicast(Vec<Arc<str>>),
    /// Local in-process session keyed by the receiving group. Reserved
    /// for the second half of #746 — the multicast call site does not
    /// produce this variant today.
    LocalSession(GroupId),
    /// NATS sink keyed by subject.
    NatsSink(String),
    /// Federation peer keyed by [`PeerId`].
    FederationPeer(PeerId),
    /// HTTP sink keyed by endpoint name.
    HttpSink(String),
    /// MQTT sink keyed by topic.
    MqttSink(String),
}

impl RecipientClass {
    /// Small fixed-vocabulary sink label used for the
    /// `egress.obligation.applied` audit event's `sink` field and for
    /// any future Prometheus counters keyed on the sink class. Bounded
    /// so cardinality stays predictable.
    pub fn sink_label(&self) -> &'static str {
        match self {
            Self::Multicast(_) => "multicast",
            Self::LocalSession(_) => "local",
            Self::NatsSink(_) => "nats",
            Self::FederationPeer(_) => "federation",
            Self::HttpSink(_) => "http",
            Self::MqttSink(_) => "mqtt",
        }
    }

    /// Render a single human-readable recipient label suitable for the
    /// `recipient_class` field of the `egress.obligation.applied`
    /// audit event. The format is `<sink>:<key>` where the key
    /// disambiguates which exact recipient inside the sink class the
    /// envelope is addressed to. For [`Self::Multicast`] the key is
    /// the comma-separated group list in source order so an operator
    /// can reconstruct the multicast envelope from a single audit
    /// line.
    fn recipient_label(&self) -> String {
        match self {
            Self::Multicast(groups) => format!("multicast:[{}]", groups.join(",")),
            Self::LocalSession(group) => format!("local:{group}"),
            Self::NatsSink(subject) => format!("nats:{subject}"),
            Self::FederationPeer(peer_id) => format!("federation:{peer_id}"),
            Self::HttpSink(endpoint) => format!("http:{endpoint}"),
            Self::MqttSink(topic) => format!("mqtt:{topic}"),
        }
    }
}

/// Post-Send-PEP envelope produced by `prepare_egress_envelope`.
///
/// `message` is an `Arc<RoutableMessage>` that callers clone once per
/// recipient — the obligation actuation has already run, so the
/// per-recipient send path pays only the cost of an `Arc::clone` and
/// a channel `try_send`. `applied_obligations` records exactly which
/// obligations were folded into the rendered copy, and
/// `recipient_class` echoes the input class so the caller does not
/// have to thread the class separately through its dispatch loop.
#[derive(Debug, Clone)]
pub struct EgressEnvelope {
    /// Post-Send-PEP message, ready for sink dispatch. Cloning is
    /// `Arc::clone`, not a `RoutableMessage::clone` — the obligation
    /// rendering cost is paid exactly once per envelope.
    pub message: Arc<RoutableMessage>,
    /// Obligations that were folded into [`Self::message`]. Empty when
    /// the envelope passed through unmodified (no engine, or no
    /// payload-mutating obligations across the addressed recipients).
    pub applied_obligations: Vec<Obligation>,
    /// Sink class the envelope was prepared for. Echoed so callers can
    /// keep a single value flowing through the dispatch loop.
    pub recipient_class: RecipientClass,
}

/// Failure mode for `prepare_egress_envelope`.
///
/// `Denied` is the deny-first multicast outcome: at least one group's
/// Send rule denied the message, so the entire envelope is denied and
/// no sink should observe it. `ObligationFailed` is the fail-closed
/// outcome under [`UnknownObligationPolicy::FailClosed`]: an
/// obligation actuation surfaced an error (e.g. an unknown variant
/// the build cannot process) and the envelope is suppressed rather
/// than letting an unmasked payload leak to an external sink.
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    /// At least one of the addressed recipients' policies denied the
    /// envelope. For multicast this is deny-first — any per-group
    /// deny vetoes the whole envelope, so the sink does not observe a
    /// partially-masked or unmasked copy.
    #[error("egress envelope denied for sink {sink_label}: {reason}")]
    Denied {
        /// Sink-class label (`"multicast"`, `"nats"`, etc.).
        sink_label: &'static str,
        /// Operator-friendly reason. For deny-first multicast, the
        /// label is `"per_group_deny"` — the per-group `authz_denied`
        /// audit record was already emitted at the local-fanout site
        /// and is not duplicated here.
        reason: &'static str,
    },
    /// Obligation actuation surfaced an error under the configured
    /// [`UnknownObligationPolicy`] (default fail-closed). The
    /// underlying `apply_obligations_with_limiter` call already
    /// emitted the forensic audit record.
    #[error("egress envelope obligation actuation failed for sink {sink_label}")]
    ObligationFailed {
        /// Sink-class label.
        sink_label: &'static str,
    },
}

/// Inputs `prepare_egress_envelope` borrows from the router.
///
/// Bundled into a struct so the helper has a single sourcing point for
/// the policy engine handle, the unknown-obligation policy, and the
/// rate-limiter handle. The router owns these and re-fetches them per
/// call (the `engine` field is the authz engine `Arc` cloned out of
/// the router's `ArcSwap` slot for the lifetime of the rendering call,
/// so a SIGHUP-driven hot-swap does not strand the rendering with a
/// half-fresh engine).
pub(crate) struct EgressContext<'a> {
    /// Currently-installed policy engine. `None` short-circuits the
    /// rendering: the input `arc_msg` is the correct egress form
    /// because no engine produced any obligations.
    pub engine: Option<&'a Arc<dyn PolicyEngine>>,
    /// Snapshot of the unknown-obligation policy. Plain copy (the
    /// policy is a deployment decision fixed at startup, not a
    /// runtime-reloadable knob).
    pub unknown_policy: UnknownObligationPolicy,
    /// Rate-limiter handle for obligation-actuation audit emission.
    pub rate_limiter: &'a Arc<ObligationRateLimiter>,
}

/// Render the post-Send-PEP egress envelope for a given sink class.
///
/// # Behaviour
///
/// 1. **No engine installed** — the helper returns `arc_msg` unchanged
///    in an envelope with empty `applied_obligations`. This is the
///    "no policy" path; sinks dispatch the unmodified message.
/// 2. **`Multicast` class** — runs the Send PEP per group, folds the
///    per-group outcomes deny-first / most-restrictive, and applies
///    the union of allow-side obligations to a single owned clone of
///    `*arc_msg`. Per-group denies surface as
///    [`EgressError::Denied`]; the per-group `authz_denied` audit
///    record was already emitted by `send_to_group_excluding` on the
///    local-fanout path so this site does not double-audit. A group
///    that the sender is not a member of is skipped (mirrors the
///    membership gate inside the local fanout).
/// 3. **Single-recipient classes** — runs the Send PEP exactly once
///    against the recipient's [`AuthzResource`]. A deny surfaces as
///    [`EgressError::Denied`]; a deny here MUST be audited by the
///    sink call site (the helper itself stays silent on per-deny
///    audits because the sink knows its own context for the
///    `authz_denied` record). The single-recipient classes are wired
///    by #737 follow-ups; this PR delivers the variants for the
///    sinks that need them but exercises only [`Self::Multicast`].
/// 4. **Audit emission** — when the helper applies one or more
///    obligations, it emits one
///    [`audit::egress_obligation_applied`] event per applied
///    obligation. For a multicast whose union is `{MaskPoint,
///    TagClassified}` this is **two** events — *not* two per
///    recipient. The cadence is the central forensic improvement of
///    #746 over the pre-existing per-recipient duplicate emission.
/// 5. **Performance contract** — the rendered `Arc<RoutableMessage>`
///    is paid for exactly once per call. Sinks clone the `Arc` per
///    recipient; obligation actuation does not run again on the
///    fan-out path.
///
/// # Errors
///
/// - [`EgressError::Denied`] when the per-group fold (multicast) or
///   the single-recipient evaluation produces a deny.
/// - [`EgressError::ObligationFailed`] when
///   `apply_obligations_with_limiter` returns an error under
///   [`UnknownObligationPolicy::FailClosed`]. The forensic audit
///   record was emitted by the underlying call.
pub(crate) fn prepare_egress_envelope(
    arc_msg: Arc<RoutableMessage>,
    class: RecipientClass,
    ctx: &EgressContext<'_>,
    evaluator: &dyn EnvelopeEvaluator,
) -> Result<EgressEnvelope, EgressError> {
    let sink_label = class.sink_label();

    let Some(engine) = ctx.engine else {
        // No policy engine installed → the unmodified message is the
        // correct egress form. Empty obligations vector — no audit
        // events fire because no obligation was applied.
        return Ok(EgressEnvelope {
            message: arc_msg,
            applied_obligations: Vec::new(),
            recipient_class: class,
        });
    };

    // Fold per-recipient outcomes into a single envelope-wide set.
    // `denied` short-circuits the rendering: deny-first across the
    // addressed recipients (today only the multicast variant produces
    // multi-recipient outcomes; single-recipient variants either deny
    // outright or pass through with a single outcome).
    let fold = match &class {
        RecipientClass::Multicast(groups) => fold_multicast(&arc_msg, groups, engine, evaluator),
        RecipientClass::LocalSession(group) => {
            fold_single(&arc_msg, AuthzResource::Group { group }, engine, evaluator)
        }
        RecipientClass::NatsSink(_) | RecipientClass::HttpSink(_) | RecipientClass::MqttSink(_) => {
            // These sinks are not group-aware; they observe whatever
            // the Send PEP would have produced for a Broadcast
            // resource. A future PR (#737) may refine this with a
            // dedicated sink-typed AuthzResource variant.
            fold_single(&arc_msg, AuthzResource::Broadcast, engine, evaluator)
        }
        RecipientClass::FederationPeer(_) => {
            fold_single(&arc_msg, AuthzResource::Broadcast, engine, evaluator)
        }
    };

    let outcome = match fold {
        FoldOutcome::Allowed(set) => set,
        FoldOutcome::Denied => {
            return Err(EgressError::Denied {
                sink_label,
                reason: "per_group_deny",
            });
        }
    };

    if outcome.is_empty() {
        // No obligations to apply — the unmodified `arc_msg` is the
        // correct egress form. Empty `applied_obligations` so the
        // caller can detect the no-op path without inspecting the
        // message body.
        return Ok(EgressEnvelope {
            message: arc_msg,
            applied_obligations: Vec::new(),
            recipient_class: class,
        });
    }

    let obligations: Vec<Obligation> = outcome.into_iter().collect();

    if !obligations_mutate_payload(&obligations) {
        // Pure audit-shaped union (e.g. `TagClassified`-only). No
        // payload mutation, so the caller forwards the unmodified
        // `arc_msg`. Audit-shaped obligations *are* still emitted
        // through `egress.obligation.applied` so the forensic trail
        // shows the envelope tagged the recipient class.
        for ob in &obligations {
            audit::egress_obligation_applied(
                sink_label,
                obligation_kind_label(ob),
                &class.recipient_label(),
            );
        }
        return Ok(EgressEnvelope {
            message: arc_msg,
            applied_obligations: obligations,
            recipient_class: class,
        });
    }

    let policy_id = engine.policy_id().to_owned();
    let mut egress_msg = (*arc_msg).clone();
    if let Err(e) = apply_obligations_with_limiter(
        &mut egress_msg,
        &obligations,
        ctx.unknown_policy,
        &policy_id,
        Some(ctx.rate_limiter),
    ) {
        debug!(
            err = %e,
            sink = %sink_label,
            source = %hash_cn(&arc_msg.source.cn),
            "egress obligation actuation failed; suppressing envelope"
        );
        return Err(EgressError::ObligationFailed { sink_label });
    }

    // Emit one audit event per applied obligation. The rendered
    // envelope is shared across N recipients; the cadence is per
    // envelope, not per recipient — that's the central #746 fix.
    let recipient_label = class.recipient_label();
    for ob in &obligations {
        audit::egress_obligation_applied(sink_label, obligation_kind_label(ob), &recipient_label);
    }

    Ok(EgressEnvelope {
        message: Arc::new(egress_msg),
        applied_obligations: obligations,
        recipient_class: class,
    })
}

/// Outcome of the per-recipient policy fold inside
/// `prepare_egress_envelope`.
enum FoldOutcome {
    /// All addressed recipients allowed the envelope; the wrapped set
    /// is the union of allow-side obligations.
    Allowed(HashSet<Obligation>),
    /// At least one addressed recipient denied — the entire envelope
    /// is denied.
    Denied,
}

fn fold_multicast(
    arc_msg: &Arc<RoutableMessage>,
    groups: &[Arc<str>],
    engine: &Arc<dyn PolicyEngine>,
    evaluator: &dyn EnvelopeEvaluator,
) -> FoldOutcome {
    let mut union: HashSet<Obligation> = HashSet::new();
    let classification = arc_msg.metadata.classification.as_ref();
    for group in groups {
        // Mirror the local-fanout membership gate: a sender that is
        // not a member of the group cannot Send to it on the local
        // path either, so the group does not contribute its
        // obligations to (or its deny against) the egress envelope.
        if !arc_msg.source.is_member_of(group) {
            continue;
        }
        let subject = AuthzSubject::from_identity(&arc_msg.source);
        let resource = AuthzResource::Group { group };
        let outcome = evaluator.evaluate_send(engine, &subject, &resource, classification);
        if !outcome.is_allow() {
            // Deny-first: any per-group deny vetoes the entire
            // envelope. The per-group `authz_denied` audit record is
            // already emitted at the local-fanout site, so the
            // helper does not duplicate it.
            return FoldOutcome::Denied;
        }
        for ob in outcome.obligations {
            let _ = union.insert(ob);
        }
    }
    FoldOutcome::Allowed(union)
}

fn fold_single(
    arc_msg: &Arc<RoutableMessage>,
    resource: AuthzResource<'_>,
    engine: &Arc<dyn PolicyEngine>,
    evaluator: &dyn EnvelopeEvaluator,
) -> FoldOutcome {
    let subject = AuthzSubject::from_identity(&arc_msg.source);
    let classification = arc_msg.metadata.classification.as_ref();
    let outcome = evaluator.evaluate_send(engine, &subject, &resource, classification);
    if !outcome.is_allow() {
        return FoldOutcome::Denied;
    }
    let mut set: HashSet<Obligation> = HashSet::new();
    for ob in outcome.obligations {
        let _ = set.insert(ob);
    }
    FoldOutcome::Allowed(set)
}

/// Engine-evaluation indirection so the helper does not need to know
/// about the router's PEP instrumentation (in-flight gauge, observer
/// callback, latency histogram). The router supplies a thin wrapper
/// that delegates to its existing `authz_evaluate_send` so every
/// envelope-rendering evaluation is observed identically to a local
/// fan-out evaluation.
///
/// Refs #849: the trait now takes the source message's
/// `Option<&ClassificationMarking>` as the fourth argument so the
/// per-group fold can drive a marking-driven Send-PEP deny on multicast
/// egress, not just on the local-fanout path.
pub(crate) trait EnvelopeEvaluator {
    fn evaluate_send(
        &self,
        engine: &Arc<dyn PolicyEngine>,
        subject: &AuthzSubject<'_>,
        resource: &AuthzResource<'_>,
        classification: Option<&rustgate_core::classification::ClassificationMarking>,
    ) -> rustgate_authz::DecisionOutcome;
}
