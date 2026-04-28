// Copyright © 2026 Roberto Chiofalo.

//! Message routing engine.
//!
//! # Authorization architecture (PEP integration)
//!
//! The router implements a two-layer Policy Enforcement Point (PEP) that
//! evaluates an optional [`PolicyEngine`] on every routed message:
//!
//! 1. **Send PEP** (`route_inner`, `send_to_group_excluding`): evaluated once
//!    per message for direct / group / broadcast destinations in `route_inner`
//!    before any state mutation (position cache, access log, dispatch).
//!    For multicast, the Send PEP runs per-group inside
//!    `send_to_group_excluding` so that per-group policy granularity is
//!    preserved on the local fanout, AND a second per-group Send pass runs
//!    on the egress path inside [`crate::egress::prepare_egress_envelope`]
//!    so external sinks (NATS, federation, HTTP, MQTT) receive a single
//!    rendered copy with the union of allow-side Send obligations
//!    applied (closes #738, refactored under #746). The subject is the
//!    *sender's* identity, the resource is the destination, and the
//!    action is [`AuthzAction::Send`]. A deny verdict drops the message
//!    outright with no observable side effect beyond the audit trail.
//!
//! 2. **Receive PEP** (`send_to_session`, `send_to_group`, `send_to_all`):
//!    evaluated once per *recipient*. The subject is the *recipient's*
//!    identity so that policies targeting a specific CN or attribute on the
//!    receive side actually take effect. A deny filters that single
//!    recipient out — other recipients in the same group or broadcast
//!    still receive the message.
//!
//! 3. **Store-forward re-evaluation** (`filter_offline_messages`): when
//!    offline messages are drained on reconnect, both the Send and Receive
//!    PEPs are re-evaluated against the *current* policy snapshot. This
//!    prevents messages stored under a previous (more permissive) policy
//!    from being delivered after permissions have been tightened.
//!
//! The legacy [`GroupAclPolicy`] path operates independently and in
//! addition to the authz engine — both must allow for a message to flow.
//! This lets operators migrate incrementally from ACLs to full RBAC/ABAC.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::Mutex;
use rustgate_authz::{
    Action as AuthzAction, Decision as AuthzDecision, Obligation, PolicyEngine,
    Resource as AuthzResource, Subject as AuthzSubject,
};
use smol_str::SmolStr;

use crate::egress::{
    EgressContext, EgressError, EnvelopeEvaluator, RecipientClass, prepare_egress_envelope,
};
use crate::obligations::{
    ObligationRateLimiter, UnknownObligationPolicy, apply_obligations_with_limiter,
    obligations_mutate_payload,
};

rustgate_core::on_callback!(
    /// Callback invoked after every authz evaluation so operators can wire
    /// the engine into metrics and audit without making `rustgate-transport`
    /// depend on `prometheus`. The server binary installs one of these via
    /// [`Router::with_authz_observer`].
    pub AuthzObserver,
    &AuthzEvent<'_>
);

rustgate_core::on_callback!(
    /// Callback invoked once per multicast message dropped because the
    /// destination group list exceeded `MAX_MULTICAST_GROUPS` (private).
    ///
    /// Wired by the server binary to feed the
    /// `rustgate_multicast_oversize_dropped_total` Prometheus counter
    /// without making `rustgate-transport` depend on `prometheus`. Closes
    /// #741: oversize-multicast drops were observable only via tracing
    /// before this callback existed, so operators could not dashboard or
    /// alert on the drop rate.
    pub OnMulticastOversizeDropped
);

rustgate_core::on_callback!(
    /// Callback invoked once per call to [`Router::route_for_egress`] after
    /// the message reached its terminal fan-out path. The first argument is
    /// a small fixed-vocabulary destination label (`"direct"`, `"group"`,
    /// `"broadcast"`, `"multicast"`); the second is the number of recipient
    /// sessions the router actually attempted to deliver to (zero on
    /// no-subscribers paths). Wired by the server binary to feed the
    /// `rustgate_router_fanout_total{destination}` counter and the
    /// `rustgate_router_fanout_subscribers` histogram. Closes #768.
    pub OnFanout,
    &'static str,
    u64
);

rustgate_core::on_callback!(
    /// Callback invoked once per recipient that the router skipped after
    /// the message was admitted into the routing pipeline. The single
    /// argument is one of the documented `reason` labels:
    /// `"no_subscribers"`, `"backpressure"`, `"acl_denied"`,
    /// `"authz_denied"`, `"obligation_failed"`. Wired by the server binary
    /// to feed the `rustgate_router_dropped_total{reason}` counter — the
    /// same `reason` vocabulary the audit-log emits, so SIEM correlation
    /// and Prometheus dashboards stay in lock-step. Closes #768.
    pub OnDropped,
    &'static str
);

rustgate_core::on_callback!(
    /// Callback invoked once per Send and Receive PEP evaluation by the
    /// router. Arguments are the small fixed-vocabulary direction label
    /// (`"send"` or `"receive"`), the decision label (`"allow"`, `"deny"`,
    /// `"fail_open"`), and the wall-clock evaluation latency in seconds.
    /// Wired by the server binary to feed the
    /// `rustgate_pep_send_decisions_total{decision}` /
    /// `rustgate_pep_receive_decisions_total{decision}` counters and the
    /// `rustgate_pep_evaluation_seconds` histogram. Closes #768.
    pub OnPepDecision,
    &'static str,
    &'static str,
    f64
);

rustgate_core::on_callback!(
    /// Callback invoked once per data-plane obligation that the router
    /// successfully applied to an outbound copy. The argument is one of
    /// the documented `kind` labels: `"mask_point"`, `"mask_payload"`,
    /// `"tag_classified"`, `"audit_extended"`, `"unknown"`. Wired by the
    /// server binary to feed the
    /// `rustgate_obligation_applied_total{kind}` counter so operators can
    /// correlate the audit-log obligation rate with the data-plane
    /// actuation rate. Closes #768.
    pub OnObligationApplied,
    &'static str
);

rustgate_core::on_callback!(
    /// Callback invoked twice per authz evaluation: once with `+1` on
    /// entry to `authz_evaluate_send` / `authz_evaluate_receive` and once
    /// with `-1` when the `AuthzEvalGuard` RAII handle drops at the end
    /// of evaluation. The signed delta lets the consumer feed a
    /// Prometheus `IntGauge` via `add` without a separate "sub" entry
    /// point. Wired by the server binary to feed the
    /// `rustgate_authz_evaluations_in_flight` gauge so operators
    /// monitoring an `ArcSwap` policy hot-reload can see the drain time
    /// of in-flight evaluations holding the previous engine `Arc`.
    /// Closes #721.
    pub OnAuthzInFlightChanged,
    i64
);

/// RAII handle that bumps the in-flight authz-evaluation gauge on
/// construction and decrements it on `Drop`. Constructed at the entry
/// of [`Router::authz_evaluate_inner`] so every `_send` / `_receive`
/// PEP site is covered without each call site duplicating the
/// increment/decrement pair — and so an early return via `?` (today
/// or in any future variant of the inner evaluator) cannot leak the
/// counter.
///
/// The `_phantom: PhantomData` field exists so `AuthzEvalGuard` cannot
/// be constructed via the struct-literal short-form from outside the
/// module — every constructor must go through [`AuthzEvalGuard::new`],
/// which is the only path that issues the `+1` to the consumer
/// callback. Closes #721.
struct AuthzEvalGuard {
    /// Pre-resolved `+1` / `-1` emitter. `None` when no callback is
    /// installed; the guard's `new` and `Drop` paths short-circuit on
    /// the empty arm so the un-wired hot path stays a single
    /// `ArcSwap::load`.
    cb: Option<OnAuthzInFlightChanged>,
    /// Marker to keep the struct-literal constructor private. See the
    /// type-level doc-comment.
    _phantom: std::marker::PhantomData<()>,
}

impl AuthzEvalGuard {
    /// Acquire the gauge slot. Loads the callback once, emits `+1` if
    /// installed, and returns a guard whose `Drop` emits the matching
    /// `-1`. The callback handle is cloned into the guard so a swap of
    /// the slot mid-evaluation cannot strand the decrement on a fresh
    /// callback that never saw the `+1` (the `Arc<dyn Fn …>` carries
    /// the original consumer through to drop).
    fn new(slot: &ArcSwap<Option<OnAuthzInFlightChanged>>) -> Self {
        let guard = slot.load();
        let cb = (**guard).as_ref().cloned();
        if let Some(ref f) = cb {
            f(1);
        }
        Self {
            cb,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl Drop for AuthzEvalGuard {
    fn drop(&mut self) {
        if let Some(ref f) = self.cb {
            f(-1);
        }
    }
}

/// Map an [`Obligation`] variant to the small fixed-vocabulary label
/// used by the `rustgate_obligation_applied_total{kind}` counter. The
/// `_` arm covers the `#[non_exhaustive]` contract on the authz crate's
/// [`Obligation`] enum: a future variant the transport build does not
/// recognise renders as `"unknown"` so cardinality stays bounded
/// regardless of which authz version is deployed. Closes #768.
pub(crate) fn obligation_kind_label(obligation: &Obligation) -> &'static str {
    match obligation {
        Obligation::MaskPoint => "mask_point",
        Obligation::MaskPayload => "mask_payload",
        Obligation::TagClassified => "tag_classified",
        Obligation::AuditExtended => "audit_extended",
        // `#[non_exhaustive]` — bucket future variants under a single
        // label so a new authz release cannot grow Prometheus
        // cardinality without an explicit transport change.
        _ => "unknown",
    }
}

/// Event emitted by the Router PEP for every authz evaluation.
#[derive(Debug)]
pub struct AuthzEvent<'a> {
    /// Action that was evaluated (Send / Receive).
    pub action: AuthzAction,
    /// Policy decision (Allow / Deny).
    pub decision: AuthzDecision,
    /// Wall-clock evaluation duration in nanoseconds.
    pub eval_nanos: u64,
    /// Matched rule id, when present.
    pub rule_id: Option<&'a str>,
    /// Stable policy identifier of the engine that produced the verdict.
    pub policy_id: &'a str,
}
use rustgate_core::audit;
use rustgate_core::identity::{GroupId, Identity};
use rustgate_core::masking::hash_cn;
use rustgate_core::message::{Destination, MessageType, RoutableMessage};
use rustgate_resilience::backpressure::{BackpressureGate, BackpressurePermit};
use rustgate_resilience::token_bucket::TokenBucket;
use tokio::sync::{RwLock, mpsc};
use tracing::{Instrument, debug, warn};

use crate::acl::GroupAclPolicy;
use crate::cache::PositionCache;
use crate::dedup::DedupCache;
use crate::store_forward::ClientQueue;

/// Access-log target. A dedicated tracing layer in the server binary
/// filters on this target and writes JSON lines to the configured sink
/// (file or stdout). The target is a constant so emission sites and the
/// subscriber filter cannot drift.
pub const ACCESS_LOG_TARGET: &str = "access";

/// Maximum number of leading payload bytes scanned when looking for a
/// CoT `uid="..."` attribute. Acts as a DoS guard against pathological
/// or oversized payloads: scan cost stays O(1) per message regardless
/// of total payload size.
const MAX_UID_SCAN_BYTES: usize = 1024;

/// Best-effort extraction of a CoT `uid="..."` attribute from a payload
/// without doing a full XML parse. Returns an empty string when the
/// payload is not CoT-shaped or no uid is present. Bounded scan over at
/// most [`MAX_UID_SCAN_BYTES`] so cost stays O(1) per message.
fn extract_cot_uid(payload: &[u8]) -> &str {
    const NEEDLE: &[u8] = b"uid=\"";
    let limit = payload.len().min(MAX_UID_SCAN_BYTES);
    let window = &payload[..limit];
    let Some(start) = window
        .windows(NEEDLE.len())
        .position(|w| w == NEEDLE)
        .map(|p| p + NEEDLE.len())
    else {
        return "";
    };
    let tail = &window[start..];
    let Some(end) = tail.iter().position(|&b| b == b'"') else {
        return "";
    };
    // Safety: we sliced from a u8 window; convert with a lossy fallback.
    std::str::from_utf8(&tail[..end]).unwrap_or("")
}

/// Emit one structured access-log event for a routed message. Cheap when
/// the access target is filtered out — the `tracing::enabled!` check is
/// O(1) against the global subscriber, and the field expressions are not
/// evaluated when no layer is interested.
fn emit_access(msg: &RoutableMessage, outcome: &'static str) {
    if !tracing::enabled!(target: ACCESS_LOG_TARGET, tracing::Level::INFO) {
        return;
    }
    let dst = match &msg.destination {
        Destination::Direct(target) => format!("direct:{}", hash_cn(&target.cn)),
        Destination::Group(group) => format!("group:{group}"),
        Destination::Broadcast => "broadcast".to_string(),
        Destination::Multicast(groups) => format!("multicast:[{}]", groups.join(",")),
    };
    let uid = extract_cot_uid(&msg.payload);
    tracing::info!(
        target: ACCESS_LOG_TARGET,
        src_cn = %msg.source.cn,
        dst = %dst,
        msg_uid = %uid,
        size = msg.payload.len(),
        proto = %msg.metadata.source_protocol,
        outcome = %outcome,
    );
}

/// Envelope wrapping an `Arc<RoutableMessage>` together with a shared
/// admission-control permit. Cloned once per recipient so the permit's
/// `Drop` fires only when the *last* session has consumed the message,
/// keeping the global queued-bytes counter pegged while downstream
/// session channels still reference the payload.
#[derive(Clone, Debug)]
pub struct RoutedMessage {
    msg: Arc<RoutableMessage>,
    // Held purely for its Drop side effect: releasing the permit returns
    // the reservation to the gate. Option so that callers without a gate
    // (tests, disabled path) pay no cost.
    _permit: Option<Arc<BackpressurePermit>>,
}

impl RoutedMessage {
    /// Wrap an `Arc<RoutableMessage>` without a backpressure permit.
    pub fn new(msg: Arc<RoutableMessage>) -> Self {
        Self { msg, _permit: None }
    }

    /// Wrap an `Arc<RoutableMessage>` with a shared backpressure permit.
    pub fn with_permit(msg: Arc<RoutableMessage>, permit: Arc<BackpressurePermit>) -> Self {
        Self {
            msg,
            _permit: Some(permit),
        }
    }

    /// Borrow the underlying `Arc<RoutableMessage>`.
    pub fn inner(&self) -> &Arc<RoutableMessage> {
        &self.msg
    }

    /// Return a copy of this envelope with authz obligations applied to
    /// its payload. When `obligations` is empty OR contains only
    /// audit-shaped obligations (via
    /// [`obligations_mutate_payload`]) this is a cheap [`Clone`] that
    /// reuses the same `Arc<RoutableMessage>`; otherwise the payload
    /// is cloned out of the `Arc`, mutated via [`apply_obligations`],
    /// and re-wrapped so other recipients whose decisions produced
    /// different obligations are not affected.
    ///
    /// Short-circuiting on audit-only obligations matters for
    /// broadcast fan-out: a policy that tags every classified delivery
    /// via `TagClassified` (but does not mask the payload) would
    /// otherwise clone the `RoutableMessage` once per recipient on a
    /// large group send, amplifying latency and allocator pressure.
    ///
    /// The backpressure permit is preserved across the rewrap so the
    /// global admission-control counter continues to reflect the
    /// message's lifetime.
    ///
    /// # Unknown obligations
    ///
    /// `unknown_policy` is forwarded to [`apply_obligations_with_limiter`].
    /// Under [`UnknownObligationPolicy::FailClosed`] an unknown variant
    /// produces [`crate::obligations::ObligationError::Unknown`] and
    /// the caller must drop this delivery rather than fall back to
    /// the unmutated payload — a stale transport against a newer
    /// policy would otherwise silently deliver bytes the policy
    /// author believed were being masked. See issue #728.
    ///
    /// `policy_id` and `rate_limiter` are forwarded to the unknown-
    /// variant audit-flood guard added in issue #769. Empty
    /// `policy_id` and `None` limiter restore pre-#769 behaviour
    /// (every encounter audited, no metric callback) and are used by
    /// callers without engine context.
    ///
    /// [`apply_obligations_with_limiter`]:
    ///     crate::obligations::apply_obligations_with_limiter
    pub(crate) fn with_obligations(
        &self,
        obligations: &[Obligation],
        unknown_policy: UnknownObligationPolicy,
        policy_id: &str,
        rate_limiter: Option<&ObligationRateLimiter>,
    ) -> Result<Self, crate::obligations::ObligationError> {
        if !obligations_mutate_payload(obligations) {
            return Ok(self.clone());
        }
        let mut msg = (*self.msg).clone();
        apply_obligations_with_limiter(
            &mut msg,
            obligations,
            unknown_policy,
            policy_id,
            rate_limiter,
        )?;
        Ok(Self {
            msg: Arc::new(msg),
            _permit: self._permit.clone(),
        })
    }
}

impl std::ops::Deref for RoutedMessage {
    type Target = RoutableMessage;
    fn deref(&self) -> &RoutableMessage {
        &self.msg
    }
}

impl From<Arc<RoutableMessage>> for RoutedMessage {
    fn from(msg: Arc<RoutableMessage>) -> Self {
        Self::new(msg)
    }
}

/// A message pending live delivery on the store-forward drain path.
///
/// Produced by [`Router::filter_offline_messages`] for every stored
/// message that survives the current ACL + authz re-evaluation.
///
/// The drain path has the same audit invariant as the live PEPs: an
/// `authz.classified_delivery` record must only be emitted when the
/// recipient actually receives the message on the wire. Emitting the
/// record from inside `filter_offline_messages` itself would lie under
/// backpressure — the caller's send loop can still fail partway
/// through, and a pre-emitted audit would falsely report delivery for
/// messages the recipient never observed.
///
/// Callers decompose this via [`into_parts`] after authorizing delivery:
///
/// ```ignore
/// for pending in router.filter_offline_messages(&identity, drained) {
///     let (msg, audit) = pending.into_parts();
///     if handle.send(Arc::new(msg)).await.is_err() {
///         break; // drop `audit` without emitting — send failed
///     }
///     audit.emit_on_delivered();
/// }
/// ```
///
/// [`into_parts`]: PendingDelivery::into_parts
#[derive(Debug)]
pub struct PendingDelivery {
    message: RoutableMessage,
    audit: Option<ClassifiedAuditCtx>,
}

impl PendingDelivery {
    /// Borrow the underlying [`RoutableMessage`] without consuming.
    pub fn message(&self) -> &RoutableMessage {
        &self.message
    }

    /// Consume the pending delivery, returning the envelope and a
    /// deferred-audit handle. The caller must invoke
    /// [`PendingAudit::emit_on_delivered`] only after a successful
    /// recipient-channel send; on failure, drop the handle without
    /// calling it so the drain-path audit trail matches on-the-wire
    /// delivery exactly.
    pub fn into_parts(self) -> (RoutableMessage, PendingAudit) {
        (self.message, PendingAudit { ctx: self.audit })
    }
}

/// Deferred audit handle paired with a [`PendingDelivery`] envelope.
///
/// Holds a snapshot of the authz engine that authorized the delivery
/// plus the fields needed to emit
/// [`rustgate_core::audit::authz_classified_delivery`]. Snapshotting the
/// engine as an `Arc<dyn PolicyEngine>` preserves the original
/// `policy_id()` across any concurrent `swap_authz` between decision
/// and delivery — the audit record must reflect the policy that
/// authorized the delivery, not whatever is current now.
///
/// `ctx` is `None` when the authorizing rule produced no
/// `TagClassified` obligation. In that case [`emit_on_delivered`] is a
/// no-op and no allocation or audit write happens on the drain path.
///
/// [`emit_on_delivered`]: PendingAudit::emit_on_delivered
#[derive(Debug)]
pub struct PendingAudit {
    ctx: Option<ClassifiedAuditCtx>,
}

impl PendingAudit {
    /// Emit the `authz.classified_delivery` audit record. Must be
    /// called exactly once after a successful send to the recipient
    /// channel; otherwise drop without calling.
    pub fn emit_on_delivered(self) {
        if let Some(ctx) = self.ctx {
            rustgate_core::audit::authz_classified_delivery(
                &ctx.sender_cn,
                &ctx.recipient_cn,
                "receive",
                ctx.resource_kind,
                &ctx.resource_id,
                ctx.rule_id.as_deref(),
                ctx.engine.policy_id(),
            );
        }
    }
}

/// Snapshot of the PEP decision context needed to emit
/// `authz.classified_delivery` after successful delivery.
///
/// The engine handle is cloned from `self.authz.load()` so the
/// audit record reflects the engine that authorized delivery even
/// if the router hot-swaps the engine between decision and send.
#[derive(Clone)]
struct ClassifiedAuditCtx {
    engine: Arc<dyn PolicyEngine>,
    /// Sender CN snapshotted at PEP-decision time. `Arc<str>` so the
    /// fanout hot path bumps a refcount instead of allocating a fresh
    /// `String` per recipient. Closes #784.
    sender_cn: Arc<str>,
    /// Recipient CN snapshotted at PEP-decision time. `Arc<str>` for
    /// the same fanout-cost reason as `sender_cn`. Closes #784.
    recipient_cn: Arc<str>,
    resource_kind: &'static str,
    resource_id: String,
    rule_id: Option<smol_str::SmolStr>,
}

// Manual Debug impl: `dyn PolicyEngine` does not derive `Debug`, so
// the derive would fail. Projecting to `policy_id()` is also safer —
// a future engine impl could accidentally `{:?}` log sensitive rule
// contents if we leaned on a blanket debug derive.
//
// CN fields are hashed via [`hash_cn`] (defense-in-depth): the audit
// path that legitimately records plaintext CNs goes through
// [`rustgate_core::audit::authz_classified_delivery`] with a dedicated
// `"audit"` tracing target. A stray `{:?}` of this struct elsewhere —
// in an operator-facing DEBUG stream, an error chain, or a future
// diagnostic — must not leak the classified-delivery identity pair.
// `resource_id` is not hashed because it is already a caller-supplied
// group name or broadcast tag, not a PII-carrying subject.
impl std::fmt::Debug for ClassifiedAuditCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClassifiedAuditCtx")
            .field("engine_policy_id", &self.engine.policy_id())
            .field("sender_cn_hash", &hash_cn(&self.sender_cn))
            .field("recipient_cn_hash", &hash_cn(&self.recipient_cn))
            .field("resource_kind", &self.resource_kind)
            .field("resource_id", &self.resource_id)
            .field("rule_id", &self.rule_id)
            .finish()
    }
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(0);

/// Default number of consecutive send failures before the circuit breaker
/// trips and disconnects the session.
pub const DEFAULT_MAX_CONSECUTIVE_DROPS: u32 = 10;

/// Capacity for the high-priority channel (Position and Alert messages).
pub const PRIORITY_CHANNEL_CAPACITY: usize = 64;

/// Capacity for the normal-priority channel (all other message types).
pub const NORMAL_CHANNEL_CAPACITY: usize = 64;

#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub id: u64,
    pub identity: Arc<Identity>,
    /// Precomputed 128-bit authz subject hash, derived once at session
    /// construction so the PEP hot path performs zero hashing over
    /// the identity on every routed message.
    subject_hash: rustgate_authz::SubjectHash,
    priority_sender: Arc<Mutex<Option<mpsc::Sender<RoutedMessage>>>>,
    normal_sender: Arc<Mutex<Option<mpsc::Sender<RoutedMessage>>>>,
    consecutive_drops: Arc<AtomicU32>,
    max_consecutive_drops: u32,
}

impl SessionHandle {
    /// Create a new session handle with dual priority channels.
    ///
    /// `priority_sender` carries Position and Alert messages (capacity 16).
    /// `normal_sender` carries all other message types (capacity 64).
    pub fn new(
        identity: Arc<Identity>,
        priority_sender: mpsc::Sender<RoutedMessage>,
        normal_sender: mpsc::Sender<RoutedMessage>,
    ) -> Self {
        let subject_hash = AuthzSubject::compute_hash(&identity);
        Self {
            id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            identity,
            subject_hash,
            priority_sender: Arc::new(Mutex::new(Some(priority_sender))),
            normal_sender: Arc::new(Mutex::new(Some(normal_sender))),
            consecutive_drops: Arc::new(AtomicU32::new(0)),
            max_consecutive_drops: DEFAULT_MAX_CONSECUTIVE_DROPS,
        }
    }

    /// Precomputed authz subject hash suitable for
    /// `rustgate_authz::Subject::with_hash` on the PEP hot path.
    pub fn subject_hash(&self) -> rustgate_authz::SubjectHash {
        self.subject_hash
    }

    /// Create a session handle with a custom circuit breaker threshold.
    ///
    /// The session is disconnected after `threshold` consecutive failed
    /// sends. Use `u32::MAX` to effectively disable the circuit breaker.
    pub fn with_drop_threshold(
        identity: Arc<Identity>,
        priority_sender: mpsc::Sender<RoutedMessage>,
        normal_sender: mpsc::Sender<RoutedMessage>,
        threshold: u32,
    ) -> Self {
        let subject_hash = AuthzSubject::compute_hash(&identity);
        Self {
            id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            identity,
            subject_hash,
            priority_sender: Arc::new(Mutex::new(Some(priority_sender))),
            normal_sender: Arc::new(Mutex::new(Some(normal_sender))),
            consecutive_drops: Arc::new(AtomicU32::new(0)),
            max_consecutive_drops: threshold,
        }
    }

    /// Returns `true` if the message type is high-priority (Position or Alert).
    fn is_priority(msg: &RoutableMessage) -> bool {
        matches!(
            msg.metadata.message_type,
            MessageType::Position | MessageType::Alert
        )
    }

    /// Send a `RoutedMessage` envelope to this session.
    ///
    /// The envelope wraps a shared `Arc<RoutableMessage>` together with
    /// an optional shared `BackpressurePermit` so that admission-control
    /// reservations stay alive until the last recipient has consumed the
    /// message from its session channel.
    ///
    /// Position and Alert messages are routed to the priority channel;
    /// all other types use the normal channel.
    ///
    /// If the circuit breaker has tripped, returns `Err` immediately.
    pub async fn send(
        &self,
        msg: impl Into<RoutedMessage>,
    ) -> Result<(), mpsc::error::SendError<RoutedMessage>> {
        let msg: RoutedMessage = msg.into();
        let sender = {
            let source = if Self::is_priority(&msg) {
                &self.priority_sender
            } else {
                &self.normal_sender
            };
            let guard = source.lock();
            match guard.as_ref() {
                Some(s) => s.clone(),
                None => return Err(mpsc::error::SendError(msg)),
            }
        };
        match sender.send(msg).await {
            Ok(()) => {
                self.consecutive_drops.store(0, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.record_failure();
                Err(e)
            }
        }
    }

    /// Non-blocking send attempt, useful when holding a lock that cannot
    /// be kept across `.await` points. Returns `true` if the message was
    /// enqueued, `false` if the channel is full, disconnected, or the
    /// circuit breaker has tripped.
    pub fn try_send(&self, msg: impl Into<RoutedMessage>) -> bool {
        let msg: RoutedMessage = msg.into();
        let source = if Self::is_priority(&msg) {
            &self.priority_sender
        } else {
            &self.normal_sender
        };

        // Hold the lock only for the try_send call, then release it
        // before the circuit breaker path to prevent AB/BA deadlock
        // with a concurrent try_send on the other channel.
        let send_ok = {
            let guard = source.lock();
            match guard.as_ref() {
                Some(s) => s.try_send(msg).is_ok(),
                None => return false,
            }
        };

        if send_ok {
            self.consecutive_drops.store(0, Ordering::Relaxed);
            true
        } else {
            let count = self.consecutive_drops.fetch_add(1, Ordering::Relaxed) + 1;
            if count >= self.max_consecutive_drops {
                warn!(
                    session = %self.identity.cn,
                    consecutive_drops = count,
                    threshold = self.max_consecutive_drops,
                    "circuit breaker tripped: disconnecting slow session"
                );
                // Always lock priority → normal to match record_failure()
                // ordering and prevent AB/BA deadlock.
                let mut priority_guard = self.priority_sender.lock();
                let mut normal_guard = self.normal_sender.lock();
                *priority_guard = None;
                *normal_guard = None;
            }
            false
        }
    }

    /// Record a send failure and trip the circuit breaker if threshold exceeded.
    fn record_failure(&self) {
        let count = self.consecutive_drops.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= self.max_consecutive_drops {
            warn!(
                session = %self.identity.cn,
                consecutive_drops = count,
                threshold = self.max_consecutive_drops,
                "circuit breaker tripped: disconnecting slow session"
            );
            let mut priority_guard = self.priority_sender.lock();
            *priority_guard = None;
            let mut normal_guard = self.normal_sender.lock();
            *normal_guard = None;
        }
    }

    /// Returns `true` if the circuit breaker has not tripped.
    pub fn is_alive(&self) -> bool {
        self.priority_sender.lock().is_some() || self.normal_sender.lock().is_some()
    }

    /// Returns `true` if the underlying channel receivers have been
    /// dropped, indicating the session write loop has exited. Distinct
    /// from a full channel: closed means the session is gone, full means
    /// it is merely slow.
    pub fn is_closed(&self) -> bool {
        let p_closed = self
            .priority_sender
            .lock()
            .as_ref()
            .is_none_or(|s| s.is_closed());
        let n_closed = self
            .normal_sender
            .lock()
            .as_ref()
            .is_none_or(|s| s.is_closed());
        p_closed && n_closed
    }
}

/// Default maximum number of groups a single CN can join.
pub const DEFAULT_MAX_GROUPS_PER_CN: usize = 128;

/// Default maximum total number of groups tracked by the router.
pub const DEFAULT_MAX_TOTAL_GROUPS: usize = 10_000;

/// Default initial capacity for the sessions map.
/// Sized to avoid early rehashing under typical deployments.
const DEFAULT_SESSION_CAPACITY: usize = 256;

/// Default initial capacity for the groups map.
const DEFAULT_GROUP_CAPACITY: usize = 64;

#[derive(Debug)]
struct State {
    /// Sessions keyed by `Arc<str>` so register/unregister reuse the
    /// session identity's CN allocation (refcount bump) rather than
    /// allocating a fresh `String`. `HashMap<Arc<str>, _>::get(&str)`
    /// still works through `Arc<str>: Borrow<str>`. Closes #784.
    sessions: HashMap<Arc<str>, SessionHandle>,
    groups: HashMap<GroupId, HashSet<Arc<str>>>,
    /// Secondary index: number of groups each CN belongs to.
    /// Maintained by `join_group`, `leave_group`, `register`, and `unregister`
    /// so that the per-CN group limit check is O(1) instead of O(G).
    cn_group_count: HashMap<Arc<str>, usize>,
    max_groups_per_cn: usize,
    max_total_groups: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            sessions: HashMap::with_capacity(DEFAULT_SESSION_CAPACITY),
            groups: HashMap::with_capacity(DEFAULT_GROUP_CAPACITY),
            cn_group_count: HashMap::with_capacity(DEFAULT_SESSION_CAPACITY),
            max_groups_per_cn: DEFAULT_MAX_GROUPS_PER_CN,
            max_total_groups: DEFAULT_MAX_TOTAL_GROUPS,
        }
    }
}

impl State {
    fn remove_from_groups(&mut self, cn: &str, groups: &std::collections::BTreeSet<GroupId>) {
        for group in groups {
            if let Some(members) = self.groups.get_mut(group) {
                if members.remove(cn) {
                    Self::decrement_cn_count(&mut self.cn_group_count, cn);
                }
                if members.is_empty() {
                    let _ = self.groups.remove(group);
                }
            }
        }
    }

    /// Decrement the per-CN group count, removing the entry when it hits 0.
    fn decrement_cn_count(cn_group_count: &mut HashMap<Arc<str>, usize>, cn: &str) {
        if let Some(count) = cn_group_count.get_mut(cn) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                let _ = cn_group_count.remove(cn);
            }
        }
    }
}

/// Maximum number of groups in a single multicast destination.
///
/// Prevents amplification DoS where a client sends one message
/// addressed to an unbounded number of groups.
const MAX_MULTICAST_GROUPS: usize = 32;

/// Configuration for SA multicast routing.
///
/// When enabled, SA events can be multicast to multiple groups
/// simultaneously using the [`Destination::Multicast`] variant.
#[derive(Debug, Clone)]
pub struct MulticastConfig {
    /// When true, SA events are automatically multicast to all groups
    /// the sender belongs to, in addition to the explicit destination.
    pub sa_auto_multicast: bool,
}

/// Per-CN position-replay rate limit (issue #724).
///
/// `Router::replay_positions` evaluates the Send + Receive PEP for every
/// cached position before delivery. A client flap-looping
/// (connect → disconnect → connect) drives the authz engine at an
/// uncapped rate proportional to `cache_size × reconnect_rate`. This
/// config caps replay events per CN with a [`TokenBucket`] so a single
/// noisy client cannot drive unbounded authz work.
///
/// Defaults are operationally permissive — `rate=100/sec, burst=200` —
/// so a normal-cadence reconnect is never limited, while flap-loop
/// attacks at 10×/sec against a 10k-position cache still get bounded
/// to 200 events/sec instead of 200,000 evals/sec.
///
/// One token represents one entire `replay_positions` invocation, not
/// one cached message: keeping the granularity at the call boundary
/// matches the attack vector (the reconnect storm) and avoids the
/// fairness pitfalls of per-message accounting.
#[derive(Debug, Clone, Copy)]
pub struct PositionReplayLimitConfig {
    /// Sustained replay events per second per CN.
    pub rate_per_sec: u32,
    /// Burst capacity. Allows short bursts above the sustained rate.
    pub burst: u32,
}

impl Default for PositionReplayLimitConfig {
    fn default() -> Self {
        Self {
            rate_per_sec: 100,
            burst: 200,
        }
    }
}

impl PositionReplayLimitConfig {
    /// Build the config from CLI knobs. A `rate_per_sec` of zero is
    /// permitted but disables sustained refill — only the initial burst
    /// will be served before the bucket empties. Operators who want to
    /// disable the limit entirely should set both fields high enough
    /// that real traffic stays under the cap (e.g. `u32::MAX`).
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self {
            rate_per_sec,
            burst,
        }
    }
}

/// The central message dispatch engine with ACL, authorization, backpressure, deduplication, and store-forward support.
pub struct Router {
    state: RwLock<State>,
    cache: PositionCache,
    acl: ArcSwap<Option<GroupAclPolicy>>,
    /// Optional RBAC/ABAC policy engine evaluated on every routed message.
    /// When `None`, the router behaves as before and only the legacy
    /// [`GroupAclPolicy`] path is consulted. When set, the engine is
    /// evaluated *in addition* to the ACL — both must allow for a
    /// message to flow.
    authz: ArcSwap<Option<Arc<dyn PolicyEngine>>>,
    /// Optional observer invoked after each authz evaluation. Kept as an
    /// `ArcSwap` so the server can install it once at startup without a
    /// lock on the hot path.
    authz_observer: ArcSwap<Option<AuthzObserver>>,
    backpressure: Option<Arc<BackpressureGate>>,
    /// Optional per-client store-and-forward disk queue. When `None`,
    /// the router behaves exactly as before: messages destined for
    /// offline CNs are dropped. When `Some`, they are persisted and
    /// drained on reconnect.
    client_queue: Option<Arc<ClientQueue>>,
    dedup: ArcSwap<Option<DedupCache>>,
    /// Optional multicast routing configuration for SA events.
    multicast_config: ArcSwap<Option<MulticastConfig>>,
    /// Optional per-tenant quota tracker. Hot-reloadable via `ArcSwap`.
    /// When `None`, no tenant-level connection limits are enforced.
    quota_tracker: ArcSwap<Option<Arc<crate::quota::TenantQuotaTracker>>>,
    /// Policy for handling authz obligations this transport build
    /// cannot actuate. Defaults to
    /// [`UnknownObligationPolicy::FailClosed`] (issue #728). The
    /// server CLI exposes an opt-out
    /// (`--authz-allow-unknown-obligations`) that flips this to
    /// [`UnknownObligationPolicy::SkipAndContinue`] for operators
    /// who need to tolerate deliberate version skew during a rolling
    /// upgrade. Plain `bool` (not `ArcSwap`) because this is a
    /// deployment decision fixed at startup, not a runtime-reloadable
    /// policy.
    unknown_obligation_policy: UnknownObligationPolicy,
    /// Per-`(policy_id, variant_name)` rate limiter that gates
    /// [`audit::authz_obligation_unknown`] emissions and feeds the
    /// `rustgate_authz_obligation_unknown_total` metric (issue #769).
    /// Defaults to a limiter with the documented per-minute cap and no
    /// metric callback. The server binary installs the metric callback
    /// during startup; the rate-limiter map persists across reloads
    /// and is pruned by `forget_policy` when the engine swaps.
    obligation_rate_limiter: Arc<ObligationRateLimiter>,
    /// Per-CN position-replay rate limit (issue #724). Each call to
    /// [`Router::replay_positions`] consumes one token from the
    /// bucket keyed by the reconnecting client's CN. The map grows
    /// lazily on first replay and is pruned on session disconnect so
    /// a CN-churning attacker cannot bloat the entry table.
    ///
    /// `DashMap` shape (issue #836): the per-CN lookup runs concurrently
    /// across every reconnecting session. The pre-#836 shape held a
    /// single `parking_lot::Mutex<HashMap>` whose critical section
    /// serialised every replay-rate check across all worker threads.
    /// Under the contended micro-bench in
    /// `benches/dedup_contention.rs` (PR #836) the
    /// `parking_lot::Mutex<HashMap>` shape collapsed from ~9.4 Melem/s
    /// at 8 workers to ~6.7 Melem/s at 16 workers, while the sharded
    /// `DashMap` held ~49 Melem/s flat. The swap is a clean drop-in
    /// here because the map is keyed entirely by CN — there is no
    /// cross-key state (no LRU, no FIFO, no per-map sweep) that would
    /// require a global lock to coordinate.
    replay_buckets: DashMap<Arc<str>, Arc<TokenBucket>>,
    /// Configuration parameters for the per-CN replay rate limiter.
    /// Plain field (not `ArcSwap`) because the bucket map carries
    /// the live state and is populated on demand from this config.
    replay_limit_config: PositionReplayLimitConfig,
    /// Optional callback fired once per multicast message dropped
    /// because the destination group list exceeded
    /// `MAX_MULTICAST_GROUPS` (private). The server binary installs this via
    /// [`Router::set_on_multicast_oversize_dropped`] to feed the
    /// `rustgate_multicast_oversize_dropped_total` Prometheus counter.
    /// Hot-reloadable via `ArcSwap` so the metrics layer can be
    /// installed and replaced after construction without any lock on
    /// the routing hot path. Closes #741.
    on_multicast_oversize_dropped: ArcSwap<Option<OnMulticastOversizeDropped>>,
    /// Optional callback fired once per [`Router::route_for_egress`]
    /// call after the message reached its terminal fan-out site. Wired
    /// by the server binary to feed the
    /// `rustgate_router_fanout_total{destination}` counter and the
    /// `rustgate_router_fanout_subscribers` histogram. Hot-reloadable
    /// via `ArcSwap`. Closes #768.
    on_fanout: ArcSwap<Option<OnFanout>>,
    /// Optional callback fired once per recipient skipped or dropped
    /// after the message was admitted. Wired by the server binary to
    /// feed the `rustgate_router_dropped_total{reason}` counter.
    /// Hot-reloadable via `ArcSwap`. Closes #768.
    on_dropped: ArcSwap<Option<OnDropped>>,
    /// Optional callback fired once per Send / Receive PEP evaluation.
    /// Wired by the server binary to feed the
    /// `rustgate_pep_send_decisions_total` /
    /// `rustgate_pep_receive_decisions_total` counters and the
    /// `rustgate_pep_evaluation_seconds` histogram. Hot-reloadable via
    /// `ArcSwap`. Closes #768.
    on_pep_decision: ArcSwap<Option<OnPepDecision>>,
    /// Optional callback fired once per data-plane obligation actually
    /// applied to an outbound message. Wired by the server binary to
    /// feed the `rustgate_obligation_applied_total{kind}` counter.
    /// Hot-reloadable via `ArcSwap`. Closes #768.
    on_obligation_applied: ArcSwap<Option<OnObligationApplied>>,
    /// Optional callback fired with `+1` on entry to
    /// `authz_evaluate_inner` and `-1` when the `AuthzEvalGuard` drops
    /// at the end of evaluation. Wired by the server binary to feed
    /// the `rustgate_authz_evaluations_in_flight` gauge so operators
    /// can observe how long in-flight evaluations continue to hold the
    /// pre-swap engine `Arc` after a hot-reload. Hot-reloadable via
    /// `ArcSwap`. Closes #721.
    on_authz_in_flight_changed: ArcSwap<Option<OnAuthzInFlightChanged>>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("state", &self.state)
            .field("cache", &self.cache)
            .field("acl", &self.acl)
            .field("authz_installed", &(**self.authz.load()).is_some())
            .field("backpressure", &self.backpressure)
            .field("client_queue", &self.client_queue)
            .field("dedup", &self.dedup)
            .field("multicast_config", &self.multicast_config)
            .field(
                "quota_tracker_installed",
                &(**self.quota_tracker.load()).is_some(),
            )
            .field("unknown_obligation_policy", &self.unknown_obligation_policy)
            .field(
                "obligation_audit_per_min",
                &self.obligation_rate_limiter.audit_per_min(),
            )
            .field("replay_limit_config", &self.replay_limit_config)
            .field(
                "on_multicast_oversize_dropped_installed",
                &(**self.on_multicast_oversize_dropped.load()).is_some(),
            )
            .field("on_fanout_installed", &(**self.on_fanout.load()).is_some())
            .field(
                "on_dropped_installed",
                &(**self.on_dropped.load()).is_some(),
            )
            .field(
                "on_pep_decision_installed",
                &(**self.on_pep_decision.load()).is_some(),
            )
            .field(
                "on_obligation_applied_installed",
                &(**self.on_obligation_applied.load()).is_some(),
            )
            .field(
                "on_authz_in_flight_changed_installed",
                &(**self.on_authz_in_flight_changed.load()).is_some(),
            )
            .finish()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
            cache: PositionCache::default(),
            acl: ArcSwap::from_pointee(None),
            authz: ArcSwap::from_pointee(None),
            authz_observer: ArcSwap::from_pointee(None),
            backpressure: None,
            client_queue: None,
            dedup: ArcSwap::from_pointee(None),
            multicast_config: ArcSwap::from_pointee(None),
            quota_tracker: ArcSwap::from_pointee(None),
            unknown_obligation_policy: UnknownObligationPolicy::default(),
            obligation_rate_limiter: Arc::new(ObligationRateLimiter::default()),
            replay_buckets: DashMap::new(),
            replay_limit_config: PositionReplayLimitConfig::default(),
            on_multicast_oversize_dropped: ArcSwap::from_pointee(None),
            on_fanout: ArcSwap::from_pointee(None),
            on_dropped: ArcSwap::from_pointee(None),
            on_pep_decision: ArcSwap::from_pointee(None),
            on_obligation_applied: ArcSwap::from_pointee(None),
            on_authz_in_flight_changed: ArcSwap::from_pointee(None),
        }
    }
}

impl Router {
    /// Create a new router with default group limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new router with custom group limits.
    ///
    /// - `max_groups_per_cn`: maximum number of groups a single CN can join
    /// - `max_total_groups`: maximum total number of groups the router tracks
    pub fn with_limits(max_groups_per_cn: usize, max_total_groups: usize) -> Self {
        Self {
            state: RwLock::new(State {
                max_groups_per_cn,
                max_total_groups,
                ..State::default()
            }),
            cache: PositionCache::default(),
            acl: ArcSwap::from_pointee(None),
            authz: ArcSwap::from_pointee(None),
            authz_observer: ArcSwap::from_pointee(None),
            backpressure: None,
            client_queue: None,
            dedup: ArcSwap::from_pointee(None),
            multicast_config: ArcSwap::from_pointee(None),
            quota_tracker: ArcSwap::from_pointee(None),
            unknown_obligation_policy: UnknownObligationPolicy::default(),
            obligation_rate_limiter: Arc::new(ObligationRateLimiter::default()),
            replay_buckets: DashMap::new(),
            replay_limit_config: PositionReplayLimitConfig::default(),
            on_multicast_oversize_dropped: ArcSwap::from_pointee(None),
            on_fanout: ArcSwap::from_pointee(None),
            on_dropped: ArcSwap::from_pointee(None),
            on_pep_decision: ArcSwap::from_pointee(None),
            on_obligation_applied: ArcSwap::from_pointee(None),
            on_authz_in_flight_changed: ArcSwap::from_pointee(None),
        }
    }

    /// Attach a global admission-control gate to the router.
    ///
    /// Every call to [`Router::route`] will acquire a byte-sized permit
    /// against the gate at entry and release it via RAII when the route
    /// operation completes, feeding the TLS accept loop's backpressure
    /// signal.
    pub fn with_backpressure(mut self, gate: Arc<BackpressureGate>) -> Self {
        self.backpressure = Some(gate);
        self
    }

    /// Reference to the router's admission-control gate, if any.
    pub fn backpressure(&self) -> Option<&Arc<BackpressureGate>> {
        self.backpressure.as_ref()
    }

    /// Create a new router with a group access control policy.
    ///
    /// Groups listed in the policy enforce per-CN send/receive permissions.
    /// Groups not listed operate in open mode (any member can send/receive).
    pub fn with_acl(acl: GroupAclPolicy) -> Self {
        let acl = if acl.is_empty() { None } else { Some(acl) };
        Self {
            state: RwLock::new(State::default()),
            cache: PositionCache::default(),
            acl: ArcSwap::from_pointee(acl),
            authz: ArcSwap::from_pointee(None),
            authz_observer: ArcSwap::from_pointee(None),
            backpressure: None,
            client_queue: None,
            dedup: ArcSwap::from_pointee(None),
            multicast_config: ArcSwap::from_pointee(None),
            quota_tracker: ArcSwap::from_pointee(None),
            unknown_obligation_policy: UnknownObligationPolicy::default(),
            obligation_rate_limiter: Arc::new(ObligationRateLimiter::default()),
            replay_buckets: DashMap::new(),
            replay_limit_config: PositionReplayLimitConfig::default(),
            on_multicast_oversize_dropped: ArcSwap::from_pointee(None),
            on_fanout: ArcSwap::from_pointee(None),
            on_dropped: ArcSwap::from_pointee(None),
            on_pep_decision: ArcSwap::from_pointee(None),
            on_obligation_applied: ArcSwap::from_pointee(None),
            on_authz_in_flight_changed: ArcSwap::from_pointee(None),
        }
    }

    /// Attach an optional client store-and-forward queue. Builder-style:
    /// ```ignore
    /// let router = Router::new().with_client_queue(queue);
    /// ```
    pub fn with_client_queue(mut self, queue: Arc<ClientQueue>) -> Self {
        self.client_queue = Some(queue);
        self
    }

    /// Access the attached client store-and-forward queue, if any.
    pub fn client_queue(&self) -> Option<&Arc<ClientQueue>> {
        self.client_queue.as_ref()
    }

    /// Create a router with custom group limits and access control policy.
    pub fn with_limits_and_acl(
        max_groups_per_cn: usize,
        max_total_groups: usize,
        acl: GroupAclPolicy,
    ) -> Self {
        let acl = if acl.is_empty() { None } else { Some(acl) };
        Self {
            state: RwLock::new(State {
                max_groups_per_cn,
                max_total_groups,
                ..State::default()
            }),
            cache: PositionCache::default(),
            acl: ArcSwap::from_pointee(acl),
            authz: ArcSwap::from_pointee(None),
            authz_observer: ArcSwap::from_pointee(None),
            backpressure: None,
            client_queue: None,
            dedup: ArcSwap::from_pointee(None),
            multicast_config: ArcSwap::from_pointee(None),
            quota_tracker: ArcSwap::from_pointee(None),
            unknown_obligation_policy: UnknownObligationPolicy::default(),
            obligation_rate_limiter: Arc::new(ObligationRateLimiter::default()),
            replay_buckets: DashMap::new(),
            replay_limit_config: PositionReplayLimitConfig::default(),
            on_multicast_oversize_dropped: ArcSwap::from_pointee(None),
            on_fanout: ArcSwap::from_pointee(None),
            on_dropped: ArcSwap::from_pointee(None),
            on_pep_decision: ArcSwap::from_pointee(None),
            on_obligation_applied: ArcSwap::from_pointee(None),
            on_authz_in_flight_changed: ArcSwap::from_pointee(None),
        }
    }

    /// Atomically replace the group access control policy.
    ///
    /// Active routing operations will continue using the previous policy
    /// until they complete; new operations see the updated policy
    /// immediately. Pass `None` to revert to open mode.
    pub fn swap_acl(&self, new_acl: Option<GroupAclPolicy>) {
        self.acl.store(Arc::new(new_acl));
    }

    /// Snapshot the current group access control policy.
    ///
    /// Returns an `Arc` to the policy currently in effect, or `None` if
    /// the router is in open mode. The snapshot is a point-in-time view;
    /// concurrent calls to [`swap_acl`](Self::swap_acl) do not affect it.
    pub fn acl_snapshot(&self) -> Arc<Option<GroupAclPolicy>> {
        self.acl.load_full()
    }

    /// Attach an RBAC/ABAC [`PolicyEngine`] to the router.
    ///
    /// The engine is evaluated on every routed message — once on the
    /// send path with [`AuthzAction::Send`], and once per recipient
    /// inside group delivery with [`AuthzAction::Receive`]. A deny
    /// verdict drops the message for that hop. The legacy
    /// [`GroupAclPolicy`] path remains active; both must allow for the
    /// message to flow.
    pub fn with_authz(self, engine: Arc<dyn PolicyEngine>) -> Self {
        self.authz.store(Arc::new(Some(engine)));
        self
    }

    /// Atomically replace the installed policy engine.
    ///
    /// Forgets any unknown-obligation rate-limit buckets owned by the
    /// previously-installed policy_id (issue #769) so map growth is
    /// bounded across reloads and a fresh policy is not pre-suppressed
    /// by the previous policy's audit-rate state. The new policy's own
    /// buckets are created lazily on first unknown-variant encounter.
    pub fn swap_authz(&self, engine: Arc<dyn PolicyEngine>) {
        let previous_policy_id = (**self.authz.load())
            .as_ref()
            .map(|e| e.policy_id().to_owned());
        self.authz.store(Arc::new(Some(engine)));
        if let Some(prev) = previous_policy_id {
            self.obligation_rate_limiter.forget_policy(&prev);
        }
    }

    /// Remove the installed policy engine, reverting to ACL-only mode.
    /// Drops any rate-limit buckets owned by the prior policy_id (issue
    /// #769).
    pub fn clear_authz(&self) {
        let previous_policy_id = (**self.authz.load())
            .as_ref()
            .map(|e| e.policy_id().to_owned());
        self.authz.store(Arc::new(None));
        if let Some(prev) = previous_policy_id {
            self.obligation_rate_limiter.forget_policy(&prev);
        }
    }

    /// Snapshot the current policy engine, if any.
    pub fn authz_snapshot(&self) -> Option<Arc<dyn PolicyEngine>> {
        self.authz.load_full().as_ref().clone()
    }

    /// Attach an observer invoked after every authz evaluation.
    ///
    /// The observer receives both Allow and Deny verdicts and the wall-clock
    /// evaluation duration, enabling metrics/audit without introducing a
    /// `prometheus` dependency on this crate.
    pub fn with_authz_observer(self, observer: AuthzObserver) -> Self {
        self.authz_observer.store(Arc::new(Some(observer)));
        self
    }

    /// Atomically replace the authz observer.
    pub fn set_authz_observer(&self, observer: Option<AuthzObserver>) {
        self.authz_observer.store(Arc::new(observer));
    }

    /// Send-PEP entry point. Evaluates the installed engine for an
    /// outbound (sender-side) decision and returns the
    /// [`DecisionOutcome`].
    ///
    /// Closes #730: split from a former `authz_evaluate(action)` so the
    /// direction is implicit in the call site. A refactor that drops or
    /// relabels the action enum can no longer silently route a Send
    /// decision through the Receive PEP — the function name *is* the
    /// PEP. The two entry points share `authz_evaluate_inner` so the
    /// observer / metric / latency instrumentation is identical between
    /// directions.
    fn authz_evaluate_send(
        &self,
        engine: &Arc<dyn PolicyEngine>,
        subject: &AuthzSubject<'_>,
        resource: &AuthzResource<'_>,
    ) -> rustgate_authz::DecisionOutcome {
        self.authz_evaluate_inner(engine, subject, resource, AuthzAction::Send)
    }

    /// Receive-PEP entry point. Evaluates the installed engine for a
    /// per-recipient (delivery-side) decision and returns the
    /// [`DecisionOutcome`].
    ///
    /// Closes #730: paired with `authz_evaluate_send`. See that
    /// function's doc-comment for the rationale.
    fn authz_evaluate_receive(
        &self,
        engine: &Arc<dyn PolicyEngine>,
        subject: &AuthzSubject<'_>,
        resource: &AuthzResource<'_>,
    ) -> rustgate_authz::DecisionOutcome {
        self.authz_evaluate_inner(engine, subject, resource, AuthzAction::Receive)
    }

    /// Shared instrumentation for the Send and Receive PEP entry
    /// points. Private — call `authz_evaluate_send` /
    /// `authz_evaluate_receive` instead so the action is
    /// type-system-anchored at the call site.
    fn authz_evaluate_inner(
        &self,
        engine: &Arc<dyn PolicyEngine>,
        subject: &AuthzSubject<'_>,
        resource: &AuthzResource<'_>,
        action: AuthzAction,
    ) -> rustgate_authz::DecisionOutcome {
        // RAII guard for the in-flight gauge (issue #721). Constructed
        // BEFORE `engine.evaluate` so the gauge reflects exactly the
        // window during which this invocation holds the engine `Arc`
        // cloned out of `self.authz` — which is the window operators
        // need to observe across an `ArcSwap` swap. Drop on every exit
        // path is automatic.
        let _in_flight = AuthzEvalGuard::new(&self.on_authz_in_flight_changed);
        let start = std::time::Instant::now();
        let outcome = engine.evaluate(subject, resource, action);
        let elapsed = start.elapsed();
        let eval_nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let observer_guard = self.authz_observer.load();
        if let Some(observer) = (**observer_guard).as_ref() {
            let ev = AuthzEvent {
                action,
                decision: outcome.decision,
                eval_nanos,
                rule_id: outcome.rule_id.as_deref(),
                policy_id: engine.policy_id(),
            };
            observer(&ev);
        }
        // Closes #768: emit per-PEP-decision metric event. The
        // direction label collapses Send and Receive arms onto a small
        // fixed vocabulary because Prometheus cardinality budgets must
        // not depend on which authz actions a particular policy
        // mentions. Federate / Publish / Subscribe (and any future
        // `#[non_exhaustive]` variants) are not exercised by the
        // router PEP today — they are still emitted here so a future
        // policy that returns one will be observable on the histogram
        // without needing a transport-side rebuild.
        let direction = match action {
            AuthzAction::Send => "send",
            AuthzAction::Receive => "receive",
            _ => "other",
        };
        let decision = match outcome.decision {
            AuthzDecision::Allow => "allow",
            AuthzDecision::Deny => "deny",
            _ => "other",
        };
        self.emit_pep_decision(direction, decision, elapsed.as_secs_f64());
        outcome
    }

    /// Emit one `authz.classified_delivery` audit record when the
    /// recipient's Receive decision carried a [`Obligation::TagClassified`].
    ///
    /// Kept as a helper so every Receive PEP site (direct, group,
    /// broadcast, multicast, offline-drain, position replay) emits the
    /// same fields in the same shape, and so future audit-shaped
    /// obligations slot in without touching each site individually.
    // justification: seven args mirror the fields the `authz_denied`
    // audit emitter consumes (obligations, engine, subject cn, recipient
    // cn, resource kind+id, optional rule id). Every Receive PEP site in
    // this file calls it on the hot path; bundling into a struct would
    // force per-call construction with no type-safety gain.
    #[allow(clippy::too_many_arguments)]
    fn audit_classified_receive(
        &self,
        obligations: &[Obligation],
        engine: &Arc<dyn PolicyEngine>,
        subject_cn: &str,
        recipient_cn: &str,
        resource_kind: &'static str,
        resource_id: &str,
        rule_id: Option<&str>,
    ) {
        if obligations
            .iter()
            .any(|o| matches!(o, Obligation::TagClassified))
        {
            rustgate_core::audit::authz_classified_delivery(
                subject_cn,
                recipient_cn,
                "receive",
                resource_kind,
                resource_id,
                rule_id,
                engine.policy_id(),
            );
        }
    }

    /// Access the position cache for SA replay.
    pub fn cache(&self) -> &PositionCache {
        &self.cache
    }

    /// Install (or replace) the cross-path deduplication cache.
    ///
    /// Pass `None` to disable dedup. When set, every routed message is
    /// checked against the cache before dispatch; duplicates are
    /// suppressed and never reach subscribers.
    pub fn set_dedup(&self, dedup: Option<DedupCache>) {
        self.dedup.store(Arc::new(dedup));
    }

    /// Snapshot of dedup cache statistics, returning `(hits, len)` if
    /// enabled. Useful for tests and operational diagnostics.
    pub fn dedup_stats(&self) -> Option<(u64, usize)> {
        let guard = self.dedup.load();
        guard.as_ref().as_ref().map(|d| (d.hits(), d.len()))
    }

    /// Configured deduplication window, in whole seconds, when a dedup
    /// cache is installed.
    ///
    /// Returns `None` when deduplication is disabled. The value is the
    /// `Duration` the cache was built with, truncated to seconds; the
    /// sub-second component is dropped because the management REST API
    /// surfaces this for human operators (who do not care about
    /// sub-second granularity) and keeping the JSON shape a plain `u64`
    /// avoids pulling `serde_with`/`humantime` into the server crate
    /// solely for one field.
    pub fn dedup_window_seconds(&self) -> Option<u64> {
        let guard = self.dedup.load();
        guard.as_ref().as_ref().map(|d| d.window().as_secs())
    }

    /// Attach a multicast configuration for SA event routing.
    ///
    /// When configured, the router can send messages to multiple groups
    /// simultaneously via [`Destination::Multicast`].
    pub fn with_multicast_config(self, config: MulticastConfig) -> Self {
        self.multicast_config.store(Arc::new(Some(config)));
        self
    }

    /// Atomically replace the multicast configuration.
    pub fn set_multicast_config(&self, config: Option<MulticastConfig>) {
        self.multicast_config.store(Arc::new(config));
    }

    /// Install (or replace) the callback fired once per multicast
    /// message dropped because the destination group list exceeded
    /// `MAX_MULTICAST_GROUPS` (private). Pass `None` to detach.
    ///
    /// Closes #741: the server binary wires this to the
    /// `rustgate_multicast_oversize_dropped_total` Prometheus counter
    /// under `#[cfg(feature = "metrics")]`. Without metrics compiled
    /// in the callback stays `None` and the existing tracing-only
    /// behaviour is preserved (operationally additive).
    pub fn set_on_multicast_oversize_dropped(&self, cb: Option<OnMulticastOversizeDropped>) {
        self.on_multicast_oversize_dropped.store(Arc::new(cb));
    }

    /// Install (or replace) the per-fanout observer.
    ///
    /// The callback fires once per [`Router::route_for_egress`] call
    /// after the router selected a terminal fan-out path. The first
    /// argument is the small fixed-vocabulary destination label
    /// (`"direct"`, `"group"`, `"broadcast"`, `"multicast"`); the
    /// second is the recipient count the router actually attempted to
    /// reach. Wired by the server binary under
    /// `#[cfg(feature = "metrics")]` to feed
    /// `rustgate_router_fanout_total{destination}` and
    /// `rustgate_router_fanout_subscribers`. Closes #768.
    pub fn set_on_fanout(&self, cb: Option<OnFanout>) {
        self.on_fanout.store(Arc::new(cb));
    }

    /// Install (or replace) the per-recipient drop observer.
    ///
    /// The callback fires once per recipient or message the router
    /// rejected after admission, with one of the documented `reason`
    /// labels. Wired by the server binary under
    /// `#[cfg(feature = "metrics")]` to feed the
    /// `rustgate_router_dropped_total{reason}` counter. Closes #768.
    pub fn set_on_dropped(&self, cb: Option<OnDropped>) {
        self.on_dropped.store(Arc::new(cb));
    }

    /// Install (or replace) the per-PEP-decision observer.
    ///
    /// The callback fires once per Send and Receive PEP evaluation
    /// with the direction label, decision label, and evaluation latency
    /// in seconds. Wired by the server binary under
    /// `#[cfg(feature = "metrics")]` to feed the
    /// `rustgate_pep_send_decisions_total` /
    /// `rustgate_pep_receive_decisions_total` counters and the
    /// `rustgate_pep_evaluation_seconds` histogram. Closes #768.
    pub fn set_on_pep_decision(&self, cb: Option<OnPepDecision>) {
        self.on_pep_decision.store(Arc::new(cb));
    }

    /// Install (or replace) the per-obligation-applied observer.
    ///
    /// The callback fires once per data-plane obligation actually
    /// applied to an outbound message (one of `"mask_point"`,
    /// `"mask_payload"`, `"tag_classified"`, `"audit_extended"`,
    /// `"unknown"`). Wired by the server binary under
    /// `#[cfg(feature = "metrics")]` to feed the
    /// `rustgate_obligation_applied_total{kind}` counter. Closes #768.
    pub fn set_on_obligation_applied(&self, cb: Option<OnObligationApplied>) {
        self.on_obligation_applied.store(Arc::new(cb));
    }

    /// Install (or replace) the in-flight authz-evaluation observer.
    ///
    /// The callback fires twice per evaluation: `+1` on entry and `-1`
    /// on exit (RAII via `AuthzEvalGuard`). The signed delta is meant
    /// to be added directly into a Prometheus `IntGauge` so the gauge
    /// value is the real-time count of in-flight evaluations holding
    /// the engine `Arc` cloned out of the router's `authz` slot.
    ///
    /// The metric is observation-only — it does NOT change reload
    /// semantics (the issue's barrier-stall option was deliberately
    /// not taken; see `docs/authorization.md` "Reload semantics" for
    /// the rationale). Operators monitoring the gauge can determine
    /// when a [`Self::swap_authz`] has fully drained the previous
    /// engine: when the gauge returns to its pre-swap baseline, every
    /// in-flight evaluation observed at the swap moment has finished.
    ///
    /// Wired by the server binary under `#[cfg(feature = "metrics")]`
    /// to feed `rustgate_authz_evaluations_in_flight`. Closes #721.
    pub fn set_on_authz_in_flight_changed(&self, cb: Option<OnAuthzInFlightChanged>) {
        self.on_authz_in_flight_changed.store(Arc::new(cb));
    }

    /// Internal helper — invoke the fanout callback if installed.
    /// Centralised so call sites stay short and the load+`is_some`
    /// pattern is identical across direct/group/broadcast/multicast
    /// fan-out paths.
    fn emit_fanout(&self, destination: &'static str, subscribers: u64) {
        let guard = self.on_fanout.load();
        if let Some(cb) = (**guard).as_ref() {
            cb(destination, subscribers);
        }
    }

    /// Internal helper — invoke the drop callback if installed.
    fn emit_dropped(&self, reason: &'static str) {
        let guard = self.on_dropped.load();
        if let Some(cb) = (**guard).as_ref() {
            cb(reason);
        }
    }

    /// Internal helper — invoke the PEP-decision callback if
    /// installed. `direction` is `"send"` or `"receive"`; `decision`
    /// is `"allow"`, `"deny"`, or `"fail_open"`; `eval_secs` is the
    /// wall-clock latency in seconds.
    fn emit_pep_decision(&self, direction: &'static str, decision: &'static str, eval_secs: f64) {
        let guard = self.on_pep_decision.load();
        if let Some(cb) = (**guard).as_ref() {
            cb(direction, decision, eval_secs);
        }
    }

    /// Internal helper — invoke the obligation-applied callback for
    /// each obligation in `obligations`. Called once per outbound copy
    /// after [`apply_obligations_with_limiter`] succeeds. Mirrors the
    /// audit emission cadence so dashboards and SIEM correlation stay
    /// consistent.
    fn emit_obligations_applied(&self, obligations: &[Obligation]) {
        let guard = self.on_obligation_applied.load();
        let Some(cb) = (**guard).as_ref() else {
            return;
        };
        for obligation in obligations {
            cb(obligation_kind_label(obligation));
        }
    }

    /// Attach a per-tenant quota tracker to the router.
    ///
    /// When installed, the router checks tenant connection limits during
    /// [`register`](Self::register) and rejects sessions that exceed
    /// the configured quota.
    pub fn with_quota_tracker(self, tracker: Arc<crate::quota::TenantQuotaTracker>) -> Self {
        self.quota_tracker.store(Arc::new(Some(tracker)));
        self
    }

    /// Atomically replace the installed quota tracker.
    pub fn swap_quota_tracker(&self, tracker: Option<Arc<crate::quota::TenantQuotaTracker>>) {
        self.quota_tracker.store(Arc::new(tracker));
    }

    /// Override the router's [`UnknownObligationPolicy`] at
    /// construction time.
    ///
    /// Defaults to [`UnknownObligationPolicy::FailClosed`] (issue
    /// #728). Pass `true` to opt into the legacy
    /// [`UnknownObligationPolicy::SkipAndContinue`] behaviour: known
    /// obligations still run but an unknown variant is skipped with
    /// an audit record and delivery continues. This is the correct
    /// choice **only** when the operator has accepted the
    /// consequences of deliberate version skew (e.g. a rolling
    /// upgrade where new authz policy is deployed ahead of the
    /// transport build).
    pub fn with_allow_unknown_obligations(mut self, allow: bool) -> Self {
        self.unknown_obligation_policy = if allow {
            UnknownObligationPolicy::SkipAndContinue
        } else {
            UnknownObligationPolicy::FailClosed
        };
        self
    }

    /// Return the router's configured [`UnknownObligationPolicy`].
    pub fn unknown_obligation_policy(&self) -> UnknownObligationPolicy {
        self.unknown_obligation_policy
    }

    /// Override the router's [`ObligationRateLimiter`] at construction
    /// time (issue #769).
    ///
    /// The default limiter caps audit emissions at
    /// [`crate::obligations::DEFAULT_UNKNOWN_OBLIGATION_AUDIT_PER_MIN`]
    /// per minute per `(policy_id, variant_name)` pair and has no
    /// metric callback. Operators with a Prometheus registry will
    /// build a limiter with [`ObligationRateLimiter::with_on_unknown`]
    /// and pass it here so the
    /// `rustgate_authz_obligation_unknown_total` counter sees every
    /// encounter regardless of the audit-rate-limit verdict.
    #[must_use]
    pub fn with_obligation_rate_limiter(mut self, limiter: Arc<ObligationRateLimiter>) -> Self {
        self.obligation_rate_limiter = limiter;
        self
    }

    /// Borrow the router's [`ObligationRateLimiter`].
    pub fn obligation_rate_limiter(&self) -> &Arc<ObligationRateLimiter> {
        &self.obligation_rate_limiter
    }

    /// Set the per-CN [`PositionReplayLimitConfig`] used by
    /// [`Router::replay_positions`] (issue #724). Reuses the existing
    /// [`TokenBucket`] primitive from `rustgate-resilience` for the
    /// per-CN gate.
    pub fn with_position_replay_limit(mut self, config: PositionReplayLimitConfig) -> Self {
        self.replay_limit_config = config;
        self
    }

    /// Return the router's configured per-CN replay rate limit.
    pub fn position_replay_limit_config(&self) -> PositionReplayLimitConfig {
        self.replay_limit_config
    }

    /// Lazily acquire (or create) the per-CN replay [`TokenBucket`].
    /// The map grows on first replay attempt for a given CN; entries
    /// are pruned on session disconnect by [`Router::unregister`] so a
    /// CN-churning attacker cannot inflate this map without bound.
    ///
    /// Uses [`DashMap::entry`] (issue #836) so the lookup-then-insert
    /// runs under a single shard lock, not a global mutex. The
    /// `or_insert_with` closure constructs the [`TokenBucket`] lazily
    /// — `dashmap` only invokes it on the vacant branch, so we do not
    /// pay the (cheap but non-zero) `TokenBucket::new` cost on the
    /// common-path return-existing case.
    fn replay_bucket_for(&self, cn: &str) -> Arc<TokenBucket> {
        if let Some(existing) = self.replay_buckets.get(cn) {
            return Arc::clone(existing.value());
        }
        let entry = self
            .replay_buckets
            .entry(Arc::<str>::from(cn))
            .or_insert_with(|| {
                Arc::new(TokenBucket::new(
                    f64::from(self.replay_limit_config.rate_per_sec),
                    Some(f64::from(self.replay_limit_config.burst)),
                ))
            });
        Arc::clone(entry.value())
    }

    /// Drop the rate-limiter bucket entry for `cn`, if any. Called from
    /// session-disconnect paths so the per-CN map does not grow without
    /// bound under a CN-churning attacker.
    fn drop_replay_bucket(&self, cn: &str) {
        let _ = self.replay_buckets.remove(cn);
    }

    /// Number of currently-tracked replay rate-limit buckets. Test-only
    /// observation used by the prune-on-disconnect regression test in
    /// issue #724.
    #[cfg(test)]
    fn replay_bucket_map_len(&self) -> usize {
        self.replay_buckets.len()
    }

    /// Snapshot the current quota tracker, if any.
    pub fn quota_tracker(&self) -> Option<Arc<crate::quota::TenantQuotaTracker>> {
        self.quota_tracker.load_full().as_ref().clone()
    }

    /// Register a session with the router.
    ///
    /// Returns `true` if the session was accepted, `false` if it was
    /// rejected by a per-tenant quota limit. When rejected, the session
    /// is not registered and a warning is emitted.
    pub async fn register(&self, handle: SessionHandle) -> bool {
        let cn = handle.identity.cn.clone();
        let new_groups = handle.identity.groups.clone();

        let mut state = self.state.write().await;

        // Per-tenant quota enforcement inside the write lock to
        // prevent TOCTOU races between concurrent connections.
        // Connections without a tenant use the default quota key.
        let quota_guard = self.quota_tracker.load();
        if let Some(ref tracker) = **quota_guard {
            let tenant_key = handle
                .identity
                .tenant
                .as_deref()
                .unwrap_or(crate::quota::DEFAULT_TENANT_KEY);
            if !tracker.check_and_record_connection(tenant_key) {
                warn!(
                    cn = %cn,
                    tenant = %tenant_key,
                    "connection rejected: tenant quota exceeded"
                );
                return false;
            }
        }

        // Clean stale group entries if this CN was previously registered
        if let Some(old) = state.sessions.remove(&cn) {
            state.remove_from_groups(&cn, &old.identity.groups);
            // Decrement quota counter for replaced session's tenant.
            let q_guard = self.quota_tracker.load();
            if let Some(ref tracker) = **q_guard {
                let old_tenant_key = old
                    .identity
                    .tenant
                    .as_deref()
                    .unwrap_or(crate::quota::DEFAULT_TENANT_KEY);
                tracker.record_disconnect(old_tenant_key);
            }
        }

        let _ = state.sessions.insert(cn.clone(), handle);

        let mut joined = 0usize;
        for group in &new_groups {
            // Enforce per-CN group limit
            if joined >= state.max_groups_per_cn {
                warn!(
                    cn = %cn,
                    limit = state.max_groups_per_cn,
                    requested = new_groups.len(),
                    "group join rejected: CN exceeded max groups per CN limit"
                );
                break;
            }

            // Enforce total group limit (only for new groups not yet tracked)
            if !state.groups.contains_key(group) && state.groups.len() >= state.max_total_groups {
                warn!(
                    cn = %cn,
                    group = %group,
                    limit = state.max_total_groups,
                    "group join rejected: router exceeded max total groups limit"
                );
                continue;
            }

            let members = state.groups.entry(group.clone()).or_default();
            if members.insert(cn.clone()) {
                *state.cn_group_count.entry(cn.clone()).or_insert(0) += 1;
            }
            joined += 1;
        }
        true
    }

    /// Remove a session only if its ID matches the currently registered one.
    /// Prevents a stale session task from evicting a replacement.
    pub async fn unregister(&self, cn: &str, session_id: u64) {
        let mut state = self.state.write().await;
        if let Some(handle) = state.sessions.get(cn)
            && handle.id != session_id
        {
            return; // A newer session owns this CN — don't touch it
        }
        if let Some(handle) = state.sessions.remove(cn) {
            state.remove_from_groups(cn, &handle.identity.groups);
            // Decrement quota counter for the disconnected tenant.
            let quota_guard = self.quota_tracker.load();
            if let Some(ref tracker) = **quota_guard {
                let tenant_key = handle
                    .identity
                    .tenant
                    .as_deref()
                    .unwrap_or(crate::quota::DEFAULT_TENANT_KEY);
                tracker.record_disconnect(tenant_key);
            }
        }
        drop(state);
        self.cache.remove(cn).await;
        // Prune the per-CN replay bucket entry (issue #724). A
        // CN-churning attacker that opens and closes thousands of
        // distinct CNs would otherwise inflate this map without bound;
        // the entry's purpose is to track in-flight rate-limit state
        // for an active session, so a graceful disconnect releases it.
        self.drop_replay_bucket(cn);
    }

    /// Dynamically add a session to a group.
    ///
    /// Used by transports with explicit subscribe semantics (e.g. MQTT
    /// SUBSCRIBE). The session must already be registered. Returns `true`
    /// if the group was joined, `false` if the session is unknown, the
    /// session ID is stale, or group limits are exceeded.
    pub async fn join_group(&self, cn: &str, session_id: u64, group: &str) -> bool {
        let mut state = self.state.write().await;

        // Verify the session exists and the caller's session_id matches.
        let Some(handle) = state.sessions.get(cn) else {
            return false;
        };
        if handle.id != session_id {
            return false;
        }

        // O(1) lookup via secondary index.
        let current_count = state.cn_group_count.get(cn).copied().unwrap_or(0);
        if current_count >= state.max_groups_per_cn {
            warn!(
                cn = %cn,
                group = %group,
                limit = state.max_groups_per_cn,
                "dynamic join rejected: CN exceeded max groups per CN limit"
            );
            return false;
        }

        // Enforce total group limit for new groups.
        if !state.groups.contains_key(group) && state.groups.len() >= state.max_total_groups {
            warn!(
                cn = %cn,
                group = %group,
                limit = state.max_total_groups,
                "dynamic join rejected: router exceeded max total groups limit"
            );
            return false;
        }

        let members = state.groups.entry(group.into()).or_default();
        let cn_arc: Arc<str> = Arc::<str>::from(cn);
        if members.insert(Arc::clone(&cn_arc)) {
            *state.cn_group_count.entry(cn_arc).or_insert(0) += 1;
        }
        true
    }

    /// Dynamically remove a session from a group.
    ///
    /// Used by transports with explicit unsubscribe semantics (e.g. MQTT
    /// UNSUBSCRIBE). The session must already be registered. Returns `true`
    /// if the session was removed from the group (or was not a member),
    /// `false` if the session is unknown or the session ID is stale.
    pub async fn leave_group(&self, cn: &str, session_id: u64, group: &str) -> bool {
        let mut state = self.state.write().await;

        let Some(handle) = state.sessions.get(cn) else {
            return false;
        };
        if handle.id != session_id {
            return false;
        }

        let mut removed = false;
        let mut empty = false;
        if let Some(members) = state.groups.get_mut(group) {
            removed = members.remove(cn);
            empty = members.is_empty();
        }
        if empty {
            let _ = state.groups.remove(group);
        }
        if removed {
            State::decrement_cn_count(&mut state.cn_group_count, cn);
        }
        true
    }

    /// Route a message to its destination (direct, group, or broadcast).
    ///
    /// Acquires a byte-sized permit from the global backpressure gate
    /// (if configured) for overall system memory protection, then
    /// dispatches to the appropriate delivery method. All per-session
    /// delivery is non-blocking: `try_send` is used for every recipient
    /// so a single slow or full session channel never blocks delivery to
    /// other sessions. Direct messages to full channels are persisted
    /// for offline redelivery; group and broadcast messages to full
    /// channels are dropped and counted.
    pub async fn route(&self, msg: RoutableMessage) {
        // Thin wrapper around [`Self::route_for_egress`] for callers that
        // do not forward messages to external sinks (NATS bridge,
        // federation, HTTP webhooks). Internal-only delivery discards the
        // post-Send-PEP form because all data-plane obligations have
        // already been baked into the per-session fanout.
        let _ = self.route_for_egress(msg).await;
    }

    /// Route a message and return the post-Send-PEP form suitable for
    /// fire-and-forget egress forwarding (NATS, federation, HTTP).
    ///
    /// Egress forwarders MUST call this method (not [`Self::route`]) and
    /// dispatch using the returned `Arc` — otherwise Send-PEP obligations
    /// such as [`rustgate_authz::Obligation::MaskPoint`] and
    /// [`rustgate_authz::Obligation::MaskPayload`] are applied to the
    /// local-fanout copy only, and the raw pre-mutation payload leaks to
    /// external sinks (e.g. unmasked coordinates reach a SIEM).
    ///
    /// Return values:
    ///
    /// - `Some(arc)` — the message was admitted, Send PEP passed, any
    ///   data-plane obligations have been applied, and local fanout has
    ///   been triggered. For Direct/Group/Broadcast destinations the
    ///   returned `Arc` wraps the same mutated [`RoutableMessage`] that
    ///   was delivered to local sessions. For Multicast destinations,
    ///   see the **Multicast egress** note below — the returned arc is
    ///   a separate post-Send-PEP copy.
    /// - `None` — the message was dropped by the router. Specifically:
    ///   cross-path dedup matched, the TTL expired before dispatch, the
    ///   Send PEP denied (audit record emitted), a multicast fanout
    ///   exceeded the internal `MAX_MULTICAST_GROUPS` cap, or multicast
    ///   egress obligation actuation failed under
    ///   [`UnknownObligationPolicy::FailClosed`]. Callers MUST skip all
    ///   egress dispatch in this case so no external sink observes a
    ///   locally-dropped message.
    ///
    /// [`UnknownObligationPolicy::FailClosed`]:
    ///     crate::obligations::UnknownObligationPolicy::FailClosed
    ///
    /// **Multicast egress** — the Send PEP runs per-group inside the
    /// multicast fanout (see `send_to_group_excluding`) so per-group
    /// policy granularity is preserved on the local fanout path. The
    /// `Arc` returned for a [`Destination::Multicast`] message is a
    /// *separate egress copy* that has the **union of allow-side Send
    /// obligations across the addressed groups** applied — if any group
    /// in the multicast list carries a `MaskPoint` (or `MaskPayload`)
    /// rule on Send, the egress copy is masked. The local fanout copy
    /// remains unmodified because each group's per-recipient delivery
    /// already applies its own Send obligations inside
    /// `send_to_group_excluding`. Closes #738.
    pub async fn route_for_egress(&self, msg: RoutableMessage) -> Option<Arc<RoutableMessage>> {
        // Two-layer flow control:
        // 1. BackpressureGate (global): limits total in-flight bytes across
        //    all sessions. Protects system memory by parking the accept loop
        //    when the high-water mark is reached.
        // 2. Per-session try_send (local): prevents a single slow consumer
        //    from blocking delivery to other sessions. Messages to full
        //    channels are persisted (direct) or dropped (group/broadcast).
        //
        // The gate does not block message routing from existing sessions —
        // it only throttles new connection acceptance.
        //
        // Acquire a byte-sized permit from the global backpressure gate
        // for this message's payload. Wrap it in `Arc` so every
        // per-recipient envelope clone shares ownership — the permit's
        // `Drop` (and thus the byte-counter release) only fires when the
        // *last* session channel has drained this message. This is the
        // property that lets slow readers actually press the gate.
        let permit: Option<Arc<BackpressurePermit>> = self
            .backpressure
            .as_ref()
            .map(|gate| Arc::new(gate.acquire(msg.payload.len())));

        let destination_label: &str = match &msg.destination {
            Destination::Direct(target) => &target.cn,
            Destination::Group(group) => group,
            Destination::Broadcast => "broadcast",
            Destination::Multicast(_) => "multicast",
        };

        let span = tracing::debug_span!(
            "route",
            source_cn = %msg.source.cn,
            destination = %destination_label,
        );

        self.route_inner(msg, permit).instrument(span).await
    }

    /// Inner routing logic, separated so the caller can `.instrument()` a span
    /// around this future without holding an `EnteredSpan` across `.await`.
    ///
    /// Returns `Some(arc_msg)` when the message was admitted and fanned
    /// out locally (the returned `Arc` is the same form every local
    /// recipient received), or `None` when the message was dropped —
    /// dedup, TTL expiry, Send-PEP deny, or oversize multicast.
    async fn route_inner(
        &self,
        msg: RoutableMessage,
        permit: Option<Arc<BackpressurePermit>>,
    ) -> Option<Arc<RoutableMessage>> {
        // Cross-path deduplication: drop the message before any
        // dispatch work if it has already been delivered via another
        // ingress path within the configured window.
        //
        // This MUST run before `PositionCache::store` below: if a
        // duplicate position report reached `store`, the SA replay
        // cache would be updated with the redundant copy and new
        // sessions would receive stale/wrong state on connect. Running
        // dedup first keeps the position cache authoritative on
        // first-arrival-wins semantics.
        {
            // INVARIANT: no `.await` may appear between `self.dedup.load()`
            // (the ArcSwap guard read below) and the end of this scope where
            // the guard drops. The guard holds an RAII reference into the
            // currently-installed `DedupCache`; an `.await` here would let a
            // SIGHUP-driven `set_dedup(...)` swap deallocate the cache while
            // we are still inside `check_message`, surfacing as a torn read
            // or a use-after-free of the underlying `parking_lot::Mutex`.
            // `check_message` is intentionally synchronous to make the
            // contract enforceable today by the borrow checker (a
            // `parking_lot::MutexGuard` is `!Send`, so any `.await` while it
            // is live would not compile). This comment is documentation for
            // the surrounding ArcSwap guard, which Rust cannot prove for us:
            // if you ever need to await inside this critical section, take
            // an owned snapshot first via `(**guard).clone()` (or move the
            // awaiting work to after the scope ends) so the guard drops
            // before the suspension point. See docs/concurrency-model.md.
            //
            // Closes #882: `check_message` (vs. the older `check_payload`)
            // binds the non-CoT key to (cn, time, payload-hash), so two
            // byte-identical non-CoT payloads (e.g. MAVLink HEARTBEATs)
            // from different senders are not collapsed into one delivery.
            let guard = self.dedup.load();
            if let Some(ref dedup) = **guard
                && dedup.check_message(&msg)
            {
                debug!(
                    source = %msg.source.cn,
                    message_type = %msg.metadata.message_type,
                    "duplicate message suppressed by cross-path dedup",
                );
                emit_access(&msg, "dedup");
                // Closes #768: dedup is a duplicate-path drop, not the
                // backpressure / authz / obligation buckets the
                // `dropped_total{reason}` counter labels. Operators who
                // want the dedup rate already have
                // `rustgate_dedup_hits_total`; do not double-count it
                // under "no_subscribers" or any other reason here.
                return None;
            }
        }

        // Drop messages that expired while waiting in the ingest pipeline
        if crate::cache::is_expired(&msg) {
            debug!(
                source = %msg.source.cn,
                message_type = %msg.metadata.message_type,
                "message expired before delivery — dropping",
            );
            emit_access(&msg, "expired");
            // Expiry has its own counter (`rustgate_messages_expired_total`)
            // — keep `dropped_total{reason}` reserved for the reasons
            // documented in the issue (no_subscribers, backpressure,
            // acl_denied, authz_denied, obligation_failed).
            return None;
        }

        // SA auto-multicast: when enabled, upgrade Group-destination SA
        // position events to Multicast targeting all groups the sender
        // belongs to. This runs before authz so per-group policy still
        // applies to the expanded destination.
        let mut msg = {
            let mc_guard = self.multicast_config.load();
            if let Some(ref config) = **mc_guard
                && config.sa_auto_multicast
                && msg.metadata.message_type == MessageType::Position
                && matches!(&msg.destination, Destination::Group(_))
                && msg.source.groups.len() > 1
            {
                let groups: Vec<Arc<str>> = msg
                    .source
                    .groups
                    .iter()
                    .map(|g| Arc::<str>::from(g.as_str()))
                    .collect();
                debug!(
                    source = %msg.source.cn,
                    groups = ?groups,
                    "SA auto-multicast: upgrading group destination to multicast",
                );
                RoutableMessage {
                    destination: Destination::Multicast(groups),
                    ..msg
                }
            } else {
                msg
            }
        };

        // Policy enforcement point: if an RBAC/ABAC engine is installed,
        // evaluate the send action before ANY state mutation (position
        // cache store, access log, dispatch). A deny verdict drops the
        // message outright and leaves no observable side effect beyond
        // the audit deny event.
        //
        // Running the PEP ahead of `cache.store` matters: a denied
        // position report must not leak into the SA replay cache, or a
        // newly connected session would receive the denied position on
        // replay even though no live session ever received it.
        //
        // The legacy `GroupAclPolicy` path in `send_to_group` still runs
        // independently — both must allow for a group message to flow,
        // which is what lets operators migrate incrementally.
        // Multicast authz is evaluated per-group inside send_to_group,
        // which already checks group membership, ACL, and per-recipient
        // authz. Evaluating a single top-level PEP here would incorrectly
        // map multicast to Broadcast, bypassing per-group policy.
        //
        // The Send obligations are collected into an outer `Vec` so the
        // cache.store below can run on the *pre-obligation* `msg` form.
        // `replay_positions` re-evaluates the Send PEP on delivery and
        // re-applies any current-policy obligations, so caching the
        // pre-mutation form gives late joiners the obligation set that
        // matches policy at replay time, not the one frozen at ingest.
        let mut send_obligations: Vec<Obligation> = Vec::new();
        // Captured alongside `send_obligations` so the per-(policy_id,
        // variant) audit-rate limiter (issue #769) keys on the engine
        // that produced the obligation list, not whichever engine is
        // current at apply time. `String` so the value survives the
        // `authz_guard` drop.
        let mut send_policy_id: String = String::new();
        {
            let authz_guard = self.authz.load();
            if let Some(engine) = (**authz_guard).as_ref() {
                match &msg.destination {
                    Destination::Multicast(_) => {
                        // Per-group Send PEP and Receive PEP both run inside
                        // send_to_group_excluding — evaluating a single
                        // top-level PEP here would incorrectly map multicast
                        // to Broadcast, bypassing per-group granularity.
                    }
                    dest => {
                        let subject = AuthzSubject::from_identity(&msg.source);
                        let resource = match dest {
                            Destination::Direct(target) => AuthzResource::Direct {
                                target_cn: &target.cn,
                            },
                            Destination::Group(group) => AuthzResource::Group { group },
                            // Broadcast is the only remaining variant here;
                            // Multicast is handled above.
                            _ => AuthzResource::Broadcast,
                        };
                        let outcome = self.authz_evaluate_send(engine, &subject, &resource);
                        if !outcome.is_allow() {
                            let (kind, id): (&'static str, &str) = match dest {
                                Destination::Direct(target) => ("direct", &target.cn),
                                Destination::Group(group) => ("group", group),
                                _ => ("broadcast", ""),
                            };
                            rustgate_core::audit::authz_denied(
                                &msg.source.cn,
                                msg.source.fingerprint.as_str(),
                                "send",
                                kind,
                                id,
                                outcome.rule_id.as_deref(),
                                engine.policy_id(),
                            );
                            emit_access(&msg, "authz_deny");
                            // Closes #768: a Send-PEP deny is the
                            // canonical "authz_denied" drop bucket.
                            self.emit_dropped("authz_denied");
                            return None;
                        }
                        // Defer application until after cache.store so the
                        // replay cache holds the pre-obligation payload.
                        send_obligations = outcome.obligations;
                        send_policy_id = engine.policy_id().to_owned();
                    }
                }
            }
        }

        // Cache position reports for SA replay to new sessions. Ordering
        // invariants:
        //
        // 1. Runs *after* the Send-PEP deny path above, so a denied
        //    position never enters the replay cache.
        // 2. Runs *before* `apply_obligations` (see block below) so the
        //    cached copy is the pre-mutation form. `replay_positions`
        //    re-evaluates the Send PEP at delivery time and re-applies
        //    any obligations from the *current* policy. Caching the
        //    post-Send-PEP form would bake in the ingest-time policy
        //    snapshot and deny operators the ability to tighten masking
        //    rules after the fact.
        if msg.metadata.message_type == MessageType::Position {
            self.cache.store(msg.clone()).await;
        }

        // Apply data-plane Send obligations to the owned `msg` *after*
        // the cache store so the replay cache keeps the pre-mutation
        // form. Audit-shaped obligations (TagClassified, AuditExtended)
        // are intentionally not emitted at Send time: the Receive PEP
        // knows the specific recipient and emits
        // `authz.classified_delivery` per delivered copy.
        //
        // On an unknown obligation variant under
        // [`UnknownObligationPolicy::FailClosed`] (the default — see
        // issue #728) `apply_obligations` returns Err and we drop the
        // message entirely: no local sessions receive it and no
        // egress forwarders are invoked. Preserving access logs as
        // `authz_obligation_failed` keeps the forensic trail.
        if !send_obligations.is_empty() {
            match apply_obligations_with_limiter(
                &mut msg,
                &send_obligations,
                self.unknown_obligation_policy,
                &send_policy_id,
                Some(&self.obligation_rate_limiter),
            ) {
                Ok(()) => {
                    // Closes #768: emit one
                    // `rustgate_obligation_applied_total{kind}` event
                    // per applied obligation. Audit-shaped variants
                    // (TagClassified, AuditExtended) are still
                    // included for parity with the audit-log emission
                    // — the metric is operationally additive and
                    // operators correlate the rate with the audit
                    // hash chain.
                    self.emit_obligations_applied(&send_obligations);
                }
                Err(e) => {
                    debug!(
                        err = %e,
                        "send-side obligation actuation failed; dropping message"
                    );
                    emit_access(&msg, "authz_obligation_failed");
                    self.emit_dropped("obligation_failed");
                    return None;
                }
            }
        }

        // Successful path: emit one access-log event per routed message.
        // Outcome is "delivered" — per-recipient drop counts (full
        // session channels) are still surfaced via the existing warn!
        // logs and metrics.
        emit_access(&msg, "delivered");

        // Wrap in Arc once so broadcast/group sends share one allocation
        // instead of cloning the full RoutableMessage per recipient. A
        // second `Arc::clone` is retained for the `route_for_egress`
        // return path so NATS/federation/HTTP forwarders dispatch the
        // *same* post-Send-PEP form that local sessions received.
        let arc_msg = Arc::new(msg);
        let envelope = match permit {
            Some(p) => RoutedMessage::with_permit(Arc::clone(&arc_msg), p),
            None => RoutedMessage::new(Arc::clone(&arc_msg)),
        };

        match envelope.destination.clone() {
            Destination::Direct(target) => {
                let subscribers = self.send_to_session(&target.cn, envelope).await;
                // Closes #768: fanout observation. `subscribers` is 1
                // for a delivered direct message, 0 for the
                // no-live-session path (which falls through to
                // store-forward and is counted separately by the
                // queue metrics).
                self.emit_fanout("direct", subscribers);
            }
            Destination::Group(group) => {
                let subscribers = self.send_to_group(&group, envelope).await;
                self.emit_fanout("group", subscribers);
            }
            Destination::Broadcast => {
                let subscribers = self.send_to_all(envelope).await;
                self.emit_fanout("broadcast", subscribers);
            }
            Destination::Multicast(ref groups) if groups.len() > MAX_MULTICAST_GROUPS => {
                warn!(
                    count = groups.len(),
                    limit = MAX_MULTICAST_GROUPS,
                    source = %envelope.source.cn,
                    "multicast group list exceeds limit, dropping message",
                );
                // Closes #741: notify the metrics callback so the
                // `rustgate_multicast_oversize_dropped_total` Prometheus
                // counter increments. The callback is a no-op when the
                // server has not installed one (e.g. metrics feature off
                // or test routers), preserving the previous tracing-only
                // behaviour.
                let cb_guard = self.on_multicast_oversize_dropped.load();
                if let Some(cb) = (**cb_guard).as_ref() {
                    cb();
                }
                // Oversize multicast is a drop: suppress egress fan-out so
                // external sinks do not observe a message that never made
                // it to any local recipient.
                return None;
            }
            Destination::Multicast(groups) => {
                let subscribers = self.send_to_multicast(&groups, envelope).await;
                self.emit_fanout("multicast", subscribers);
                // Closes #738 / #746. Local fan-out has already
                // applied per-group Send obligations to each recipient
                // copy inside `send_to_group_excluding`; the `arc_msg`
                // captured above is the *unmasked* source form. Egress
                // forwarders (NATS, federation, HTTP, MQTT) MUST receive
                // a masked copy whenever any group in the multicast
                // list carries a `MaskPoint`/`MaskPayload` Send rule —
                // otherwise the raw payload reaches an external sink
                // even though every local recipient saw a masked copy.
                //
                // The egress envelope is rendered exactly once per
                // multicast via `prepare_egress_envelope` and the
                // resulting `Arc<RoutableMessage>` is the form returned
                // to every external sink. For an N-recipient multicast
                // the obligation actuation runs once (not N times) and
                // the `egress.obligation.applied` audit cadence is
                // per-envelope, not per-recipient — closes #746.
                //
                // Deny-first across the addressed groups: if any
                // group's Send rule denies the envelope, no external
                // sink observes the message. Per-group denies on the
                // local-fanout path were already audited inside
                // `send_to_group_excluding`. The `arc_msg`-only
                // local-fanout perf carve-out is preserved:
                // `send_to_multicast` ran on the unmasked `envelope`
                // above, and per-group obligations were applied
                // recipient-side without re-clone-storming the
                // common case.
                let class = RecipientClass::Multicast(groups.clone());
                let authz_guard = self.authz.load();
                let engine_ref = (**authz_guard).as_ref();
                let ctx = EgressContext {
                    engine: engine_ref,
                    unknown_policy: self.unknown_obligation_policy,
                    rate_limiter: &self.obligation_rate_limiter,
                };
                return match prepare_egress_envelope(Arc::clone(&arc_msg), class, &ctx, self) {
                    Ok(envelope) => Some(envelope.message),
                    Err(EgressError::Denied { .. }) | Err(EgressError::ObligationFailed { .. }) => {
                        // Suppress egress fan-out when the envelope is
                        // denied or obligation actuation fail-closed.
                        // External sinks observe nothing rather than a
                        // leaked unmasked payload. The local fanout
                        // already happened above with per-group
                        // obligations applied recipient-side.
                        None
                    }
                };
            }
        }
        Some(arc_msg)
    }

    /// Drain any messages persisted for this CN while it was
    /// disconnected. The caller MUST invoke this BEFORE
    /// [`Self::register`] so that no live traffic can be delivered to
    /// the session until the returned buffered messages have been
    /// flushed to the session writer. This preserves strict FIFO across
    /// the reconnect boundary.
    ///
    /// **Important:** callers should pass the returned messages through
    /// [`Self::filter_offline_messages`] before delivery to re-check
    /// ACL and authz policies that may have changed since the messages
    /// were originally stored.
    ///
    /// Returns an empty vec if no client queue is attached or the
    /// drain fails — the caller should proceed with registration
    /// either way.
    pub async fn drain_offline_messages(&self, cn: &str) -> Vec<RoutableMessage> {
        let Some(queue) = self.client_queue.clone() else {
            return Vec::new();
        };
        let cn_owned = cn.to_string();
        // redb operations are synchronous; run on a blocking thread to
        // avoid stalling the runtime for large drains.
        let drained = tokio::task::spawn_blocking(move || queue.drain(&cn_owned)).await;
        match drained {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                // Hash the session CN before logging — the drain path is
                // invoked on every reconnect and an operator-facing log
                // stream must not accumulate plaintext client identities.
                warn!(session = %hash_cn(cn), error = %e, "client queue drain failed");
                Vec::new()
            }
            Err(e) => {
                let session = hash_cn(cn);
                let error = e.to_string();
                warn!(
                    session = %session,
                    error = %error,
                    "client queue drain task join failed"
                );
                rustgate_core::audit::store_forward_drain_panic(&session, &error);
                Vec::new()
            }
        }
    }

    /// Filter drained offline messages through the current ACL and authz
    /// policies, re-checking authorization at delivery time to prevent stale
    /// permissions from the time of storage.
    ///
    /// - **ACL filtering** applies only to [`Destination::Group`] messages
    ///   (send and receive checks against the group ACL).
    /// - **Authz filtering** applies to all destination types
    ///   ([`Destination::Direct`], [`Destination::Group`], and
    ///   [`Destination::Broadcast`]).
    ///
    /// Messages whose sender is no longer authorized to send, or whose
    /// recipient is no longer authorized to receive, are dropped with a
    /// debug log.
    ///
    /// Callers should invoke this on the output of
    /// [`Self::drain_offline_messages`] and iterate the returned
    /// [`PendingDelivery`] values: for each, call
    /// [`PendingDelivery::into_parts`], attempt delivery via the session
    /// handle, and only on success invoke
    /// [`PendingAudit::emit_on_delivered`]. Emitting audit inline here
    /// would misrepresent drops under backpressure as tagged deliveries.
    pub fn filter_offline_messages(
        &self,
        recipient_identity: &Identity,
        messages: Vec<RoutableMessage>,
    ) -> Vec<PendingDelivery> {
        if messages.len() > 1000 {
            warn!(
                cn = %hash_cn(&recipient_identity.cn),
                count = messages.len(),
                "large offline message drain — filtering may be slow",
            );
        }

        let acl_guard = self.acl.load();
        let authz_guard = self.authz.load();
        let recipient_cn = &recipient_identity.cn;

        messages
            .into_iter()
            .filter_map(|mut msg| {
                // Re-check ACL for group-destined messages.
                if let Destination::Group(ref group) = msg.destination
                    && let Some(ref acl) = **acl_guard
                {
                    if !acl.is_send_authorized(group, &msg.source.cn) {
                        // Hash sender CN: the drain path fires on every
                        // reconnect and must not accumulate plaintext
                        // identities in operator-facing debug streams.
                        debug!(
                            sender = %hash_cn(&msg.source.cn),
                            group = %group,
                            "dropping offline message: sender no longer authorized to send"
                        );
                        return None;
                    }
                    if !acl.is_receive_authorized(group, recipient_cn) {
                        debug!(
                            recipient = %hash_cn(recipient_cn),
                            group = %group,
                            "dropping offline message: recipient no longer authorized to receive"
                        );
                        return None;
                    }
                }

                // Re-check authz engine for all message types.
                let mut audit_ctx: Option<ClassifiedAuditCtx> = None;
                if let Some(ref engine) = **authz_guard {
                    // Sender Send check
                    let subject = AuthzSubject::from_identity(&msg.source);
                    let resource = match &msg.destination {
                        Destination::Direct(target) => AuthzResource::Direct {
                            target_cn: &target.cn,
                        },
                        Destination::Group(group) => AuthzResource::Group { group },
                        // Multicast messages should never be persisted
                        // (they are expanded into per-group sends at
                        // routing time). Fall back to Broadcast if one
                        // appears from pre-migration data.
                        Destination::Broadcast | Destination::Multicast(_) => {
                            AuthzResource::Broadcast
                        }
                    };
                    let send_outcome = self.authz_evaluate_send(engine, &subject, &resource);
                    if !send_outcome.is_allow() {
                        debug!(
                            sender = %hash_cn(&msg.source.cn),
                            "dropping offline message: sender no longer authorized by policy"
                        );
                        return None;
                    }

                    // Recipient Receive check
                    let recipient_subject = AuthzSubject::from_identity(recipient_identity);
                    let recv_outcome =
                        self.authz_evaluate_receive(engine, &recipient_subject, &resource);
                    if !recv_outcome.is_allow() {
                        debug!(
                            sender = %hash_cn(&msg.source.cn),
                            recipient = %hash_cn(&recipient_identity.cn),
                            "offline message filtered: recipient denied by authz",
                        );
                        return None;
                    }

                    // Apply Send obligations first (envelope-level), then
                    // stack Receive obligations on the already-adjusted
                    // copy so per-recipient masking composes with
                    // sender-side policy.
                    //
                    // Fail-closed on unknown obligation (issue #728):
                    // drop this drained record rather than deliver a
                    // partially-mutated payload. The store-forward
                    // queue is not re-updated — the message is simply
                    // removed from the pending delivery set.
                    if !send_outcome.obligations.is_empty()
                        && let Err(e) = apply_obligations_with_limiter(
                            &mut msg,
                            &send_outcome.obligations,
                            self.unknown_obligation_policy,
                            engine.policy_id(),
                            Some(&self.obligation_rate_limiter),
                        )
                    {
                        debug!(
                            err = %e,
                            sender = %hash_cn(&msg.source.cn),
                            recipient = %hash_cn(&recipient_identity.cn),
                            "offline message filtered: send obligation actuation failed"
                        );
                        return None;
                    }
                    if !recv_outcome.obligations.is_empty()
                        && let Err(e) = apply_obligations_with_limiter(
                            &mut msg,
                            &recv_outcome.obligations,
                            self.unknown_obligation_policy,
                            engine.policy_id(),
                            Some(&self.obligation_rate_limiter),
                        )
                    {
                        debug!(
                            err = %e,
                            sender = %hash_cn(&msg.source.cn),
                            recipient = %hash_cn(&recipient_identity.cn),
                            "offline message filtered: receive obligation actuation failed"
                        );
                        return None;
                    }

                    // Build deferred-audit context ONLY when a
                    // TagClassified obligation is present: that is the
                    // single obligation that produces an
                    // `authz.classified_delivery` record. Other
                    // obligations (MaskPoint, MaskPayload, AuditExtended)
                    // do not consume this path. Gating here means the
                    // common untagged drain pays zero allocations for
                    // the audit envelope.
                    //
                    // The record itself is *not* emitted here — it
                    // fires from [`PendingAudit::emit_on_delivered`]
                    // once the caller successfully hands the message
                    // off to the recipient session channel. Emitting
                    // inline would misrepresent a drain-time drop
                    // (channel full, session already gone) as a
                    // delivered tagged copy, which is forensically
                    // worse than a missing record.
                    if recv_outcome
                        .obligations
                        .iter()
                        .any(|o| matches!(o, Obligation::TagClassified))
                    {
                        let (resource_kind, resource_id) = match &msg.destination {
                            Destination::Direct(target) => ("direct", target.cn.to_string()),
                            Destination::Group(group) => ("group", group.to_string()),
                            Destination::Broadcast | Destination::Multicast(_) => {
                                ("broadcast", String::new())
                            }
                        };
                        audit_ctx = Some(ClassifiedAuditCtx {
                            engine: Arc::clone(engine),
                            sender_cn: msg.source.cn.clone(),
                            recipient_cn: recipient_identity.cn.clone(),
                            resource_kind,
                            resource_id,
                            rule_id: recv_outcome.rule_id.clone(),
                        });
                    }
                }

                Some(PendingDelivery {
                    message: msg,
                    audit: audit_ctx,
                })
            })
            .collect()
    }

    /// Legacy/test helper that drains queued offline messages and
    /// delivers them directly through a session handle. Kept for unit
    /// tests that exercise the drain path without a full session loop.
    ///
    /// # Warning
    ///
    /// This method does NOT apply ACL or authz filtering. Use
    /// [`drain_offline_messages`](Self::drain_offline_messages) +
    /// [`filter_offline_messages`](Self::filter_offline_messages) for
    /// production drain paths.
    #[cfg(test)]
    pub async fn drain_client_queue(&self, handle: &SessionHandle) -> u32 {
        let msgs = self.drain_offline_messages(&handle.identity.cn).await;
        let mut delivered = 0u32;
        for m in msgs {
            if handle.send(Arc::new(m)).await.is_ok() {
                delivered += 1;
            }
        }
        if delivered > 0 {
            debug!(
                session = %hash_cn(&handle.identity.cn),
                delivered,
                "drained client queue on reconnect"
            );
        }
        delivered
    }

    /// Replay cached positions to a newly connected session.
    /// Only replays positions from clients that share at least one group
    /// with the connecting session to enforce group-level isolation.
    ///
    /// Per-CN rate-limited (issue #724): each invocation acquires one
    /// token from a per-CN [`TokenBucket`]. When the bucket is empty
    /// the replay is skipped entirely with an audit event
    /// ([`audit::position_replay_rate_limited`]) and a warn-level log
    /// line. This bounds the authz work a single flap-looping client
    /// can drive — every reconnect would otherwise trigger
    /// `2 * cache_size` PEP evaluations, so a 10k-cache and 10×/sec
    /// reconnect = 200k authz evals/sec from one client.
    pub async fn replay_positions(&self, handle: &SessionHandle) {
        // Per-CN admission via the shared TokenBucket primitive. The
        // bucket is keyed by the reconnecting client's CN so a noisy
        // client cannot starve replay for its neighbours; per-CN
        // isolation is the security goal here. The map grows lazily on
        // first replay and is pruned on disconnect by `unregister`.
        if !self.replay_bucket_for(&handle.identity.cn).try_acquire() {
            // Pre-flight count of cached positions for the audit
            // payload. The cost is one read-lock + filter pass; the
            // alternative (estimating from `len`) would over-count
            // expired entries.
            let attempted = self.cache.get_all().await.len();
            let session_hash = hash_cn(&handle.identity.cn);
            warn!(
                session = %session_hash,
                attempted = attempted,
                rate_per_sec = self.replay_limit_config.rate_per_sec,
                burst = self.replay_limit_config.burst,
                "position replay rate-limited: per-CN bucket exhausted"
            );
            // `attempted` may exceed `u32::MAX` only on a pathological
            // cache; clamp before the audit cast to keep the field type
            // narrow without panicking.
            let attempted_u32 = u32::try_from(attempted).unwrap_or(u32::MAX);
            audit::position_replay_rate_limited(&session_hash, attempted_u32, 0);
            return;
        }
        let acl_guard = self.acl.load();
        let acl_ref: &Option<GroupAclPolicy> = &acl_guard;
        let authz_guard = self.authz.load();
        let authz: Option<&Arc<dyn PolicyEngine>> = (**authz_guard).as_ref();
        let mut dropped = 0u32;
        let mut total = 0u32;
        for mut msg in self.cache.get_all().await {
            let shared = msg
                .source
                .groups
                .intersection(&handle.identity.groups)
                .any(|g| {
                    acl_ref
                        .as_ref()
                        .is_none_or(|acl| acl.is_receive_authorized(g, &handle.identity.cn))
                });
            if !(shared || handle.identity.groups.is_empty()) {
                continue;
            }

            // Authz re-evaluation on replay. Positions enter the cache
            // at ingress time; by the time a new session connects, the
            // policy may have changed. Two PEPs run here to defend the
            // replay path:
            //
            // 1. Send PEP from the cached *sender's* identity. A policy
            //    tightening (e.g. adding `MaskPoint` on Send after the
            //    position was cached with raw coordinates) must take
            //    effect on replay — otherwise a newly connected session
            //    observes pre-tightening coordinates that were never
            //    re-masked in the cache.
            // 2. Receive PEP from the *recipient's* identity, so rules
            //    that restrict specific subscribers still apply.
            //
            // Send obligations are applied before Receive obligations so
            // sender-side masking is composed with per-recipient masking
            // (MaskPayload over MaskPoint = empty body; either order works
            // since the dispatcher is idempotent).
            //
            // The audit event is deferred until after a successful
            // `try_send` so the record reflects an actual delivery, not
            // just a policy decision for a message that got dropped on a
            // full channel.
            let (recv_obligations, recv_rule_id, engine_for_audit) = if let Some(engine) = authz {
                let sender_subject = AuthzSubject::from_identity(&msg.source);
                let resource = AuthzResource::Broadcast;
                let send_outcome = self.authz_evaluate_send(engine, &sender_subject, &resource);
                if !send_outcome.is_allow() {
                    // Sender is no longer allowed to send to this
                    // resource class under the current policy; drop
                    // the cached position entirely rather than
                    // replaying pre-deny coordinates.
                    continue;
                }
                // Fail-closed on unknown obligation (issue #728):
                // skip this cached position for this recipient
                // rather than replay a partially-mutated payload.
                if !send_outcome.obligations.is_empty()
                    && let Err(e) = apply_obligations_with_limiter(
                        &mut msg,
                        &send_outcome.obligations,
                        self.unknown_obligation_policy,
                        engine.policy_id(),
                        Some(&self.obligation_rate_limiter),
                    )
                {
                    debug!(
                        err = %e,
                        session = %hash_cn(&handle.identity.cn),
                        "position replay skipped: send obligation actuation failed"
                    );
                    continue;
                }

                let recipient_subject =
                    AuthzSubject::with_hash(&handle.identity, handle.subject_hash);
                let recv_outcome =
                    self.authz_evaluate_receive(engine, &recipient_subject, &resource);
                if !recv_outcome.is_allow() {
                    continue;
                }
                if !recv_outcome.obligations.is_empty()
                    && let Err(e) = apply_obligations_with_limiter(
                        &mut msg,
                        &recv_outcome.obligations,
                        self.unknown_obligation_policy,
                        engine.policy_id(),
                        Some(&self.obligation_rate_limiter),
                    )
                {
                    debug!(
                        err = %e,
                        session = %hash_cn(&handle.identity.cn),
                        "position replay skipped: receive obligation actuation failed"
                    );
                    continue;
                }
                (recv_outcome.obligations, recv_outcome.rule_id, Some(engine))
            } else {
                (Vec::new(), None, None)
            };

            total += 1;
            let sender_cn = msg.source.cn.clone();
            if handle.try_send(Arc::new(msg)) {
                if let Some(engine) = engine_for_audit {
                    self.audit_classified_receive(
                        &recv_obligations,
                        engine,
                        &sender_cn,
                        &handle.identity.cn,
                        "broadcast",
                        "",
                        recv_rule_id.as_deref(),
                    );
                }
            } else {
                dropped += 1;
            }
        }
        if dropped > 0 {
            warn!(
                session = %hash_cn(&handle.identity.cn),
                dropped = dropped,
                total = total,
                "messages dropped during position replay: channel full or disconnected"
            );
        }
    }

    /// Returns the number of currently registered sessions.
    pub async fn session_count(&self) -> usize {
        self.state.read().await.sessions.len()
    }

    /// Force-disconnect a single client by CN.
    ///
    /// Models the close path of [`Self::close_all_session_senders`] but
    /// targets one session. Returns `true` when a session matching `cn`
    /// was found and its writer channels were signalled to drain; `false`
    /// when no session is currently registered under that CN.
    ///
    /// CN matching is exact: the map key is the `identity.cn` recorded at
    /// [`Self::register`] time, which preserves the original casing from
    /// the client certificate subject. Callers that want case-insensitive
    /// lookup should normalize via `Router::connected_clients` first.
    ///
    /// Sessions are NOT removed from the routing map — the session task
    /// still runs `unregister` on its own exit path so `session_count`
    /// stays accurate while the writer drains. This also avoids racing
    /// with an in-flight `route_inner` that might have already looked up
    /// the `SessionHandle` before the disconnect call arrived.
    pub async fn disconnect_client(&self, cn: &str) -> bool {
        let state = self.state.read().await;
        let Some(handle) = state.sessions.get(cn) else {
            return false;
        };
        {
            let mut guard = handle.priority_sender.lock();
            let _ = guard.take();
        }
        {
            let mut guard = handle.normal_sender.lock();
            let _ = guard.take();
        }
        true
    }

    /// Close all outbound session channels so writer tasks observe `None`
    /// after draining whatever is already queued. Used during graceful
    /// shutdown: by dropping the senders held in each `SessionHandle`,
    /// each session's write loop finishes the in-flight messages and
    /// then exits cleanly. Returns the number of sessions whose senders
    /// were closed.
    ///
    /// Sessions are NOT removed from the routing map — `unregister` is
    /// still called from each session task on its own exit path. This
    /// keeps `session_count` accurate while writers are draining and
    /// avoids racing with concurrent route attempts.
    pub async fn close_all_session_senders(&self) -> usize {
        let state = self.state.read().await;
        let mut closed = 0usize;
        for handle in state.sessions.values() {
            {
                let mut guard = handle.priority_sender.lock();
                if guard.take().is_some() {
                    closed += 1;
                }
            }
            {
                let mut guard = handle.normal_sender.lock();
                let _ = guard.take();
            }
        }
        closed
    }

    /// Return a snapshot of all connected client identities.
    pub async fn connected_clients(&self) -> Vec<Arc<Identity>> {
        let state = self.state.read().await;
        state
            .sessions
            .values()
            .map(|h| Arc::clone(&h.identity))
            .collect()
    }

    /// Deliver a message to a specific session by CN.
    ///
    /// Uses non-blocking `try_send` so a slow or full session channel
    /// never blocks the routing task. When the session channel is full
    /// or closed, the message is persisted for offline delivery via the
    /// store-and-forward queue (if attached) rather than blocking. The
    /// per-session circuit breaker in `SessionHandle` will disconnect
    /// truly slow sessions after N consecutive failures.
    /// Deliver a direct message and return the number of recipients
    /// the router reached. Returns `1` on a successful in-memory
    /// `try_send`, `0` when no live session exists for the CN (the
    /// message falls through to store-and-forward), the channel is
    /// full or closed, or a Receive PEP / obligation fail-closed path
    /// drops the delivery. The number is forwarded to the
    /// `rustgate_router_fanout_subscribers` histogram so dashboards
    /// observe the actual recipient count rather than the candidate
    /// pool size.
    async fn send_to_session(&self, cn: &str, msg: RoutedMessage) -> u64 {
        let handle = {
            let state = self.state.read().await;
            state.sessions.get(cn).cloned()
        };
        match handle {
            Some(handle) => {
                // Per-recipient authz Receive PEP for direct unicast.
                // A policy rule that denies `charlie` from receiving any
                // direct message only takes effect if we evaluate here,
                // not just on the sender-side Send PEP in `route_inner`.
                //
                // When the message is persisted for offline delivery
                // below, the authz check runs again at live-delivery
                // time (on the next successful `send_to_session` path
                // after drain), which is the correct behavior: policy
                // may have changed in the interim.
                let authz_guard = self.authz.load();
                // Capture the obligations + rule_id for deferred audit so
                // a TagClassified / AuditExtended audit record is only
                // emitted when delivery actually lands on the wire. If
                // `try_send` fails and the message falls through to
                // `persist_for_offline`, the drain path re-evaluates the
                // PEP at live-delivery time and emits audit then.
                //
                // `pre_receive` holds the envelope *before* Receive-side
                // obligation mutation. If delivery fails and we fall
                // through to store-forward, we persist `pre_receive` so
                // the drain path re-evaluates the PEP from the original
                // payload — if policy has changed while the client was
                // offline (e.g. MaskPoint no longer required), drain
                // delivers the un-masked original rather than a stale
                // pre-masked copy.
                let pre_receive = msg.clone();
                let (msg, audit_ctx) = if let Some(engine) = (**authz_guard).as_ref() {
                    let subject = AuthzSubject::from_identity(&handle.identity);
                    let resource = AuthzResource::Direct { target_cn: cn };
                    let outcome = self.authz_evaluate_receive(engine, &subject, &resource);
                    if !outcome.is_allow() {
                        rustgate_core::audit::authz_denied(
                            &handle.identity.cn,
                            handle.identity.fingerprint.as_str(),
                            "receive",
                            "direct",
                            cn,
                            outcome.rule_id.as_deref(),
                            engine.policy_id(),
                        );
                        // Closes #768: Receive-PEP deny — recipient
                        // skipped, contributes to the authz_denied
                        // bucket of `dropped_total`.
                        self.emit_dropped("authz_denied");
                        return 0;
                    }
                    let sender_cn = msg.source.cn.clone();
                    // `rule_id` is only used by `audit_classified_receive`,
                    // which fires only when `TagClassified` is present.
                    // Skip cloning on the common untagged path — a hot
                    // PEP site should not allocate per recipient for
                    // audit metadata that is about to be discarded.
                    // SmolStr kept through to avoid a redundant
                    // alloc-then-drop.
                    let rule_id = if outcome
                        .obligations
                        .iter()
                        .any(|o| matches!(o, Obligation::TagClassified))
                    {
                        outcome.rule_id.clone()
                    } else {
                        None
                    };
                    // Fail-closed on unknown obligation (issue #728):
                    // drop the delivery and do NOT persist for
                    // offline replay. A stale transport cannot
                    // actuate the policy now, and it will not be
                    // able to actuate it on drain either — persisting
                    // would only defer the same fail-closed decision.
                    let msg = match msg.with_obligations(
                        &outcome.obligations,
                        self.unknown_obligation_policy,
                        engine.policy_id(),
                        Some(&self.obligation_rate_limiter),
                    ) {
                        Ok(m) => {
                            // Closes #768: data-plane obligations
                            // applied for this direct recipient.
                            self.emit_obligations_applied(&outcome.obligations);
                            m
                        }
                        Err(e) => {
                            debug!(
                                err = %e,
                                session = %cn,
                                "direct send dropped: receive obligation actuation failed"
                            );
                            self.emit_dropped("obligation_failed");
                            return 0;
                        }
                    };
                    let ctx = Some((Arc::clone(engine), outcome.obligations, rule_id, sender_cn));
                    (msg, ctx)
                } else {
                    (msg, None)
                };
                if handle.try_send(msg) {
                    if let Some((engine, obligations, rule_id, sender_cn)) = audit_ctx {
                        self.audit_classified_receive(
                            &obligations,
                            &engine,
                            &sender_cn,
                            &handle.identity.cn,
                            "direct",
                            cn,
                            rule_id.as_deref(),
                        );
                    }
                    1
                } else {
                    // Non-blocking: channel is full or closed. Persist
                    // the pre-Receive form (before `with_obligations`
                    // rewrapped the payload for this specific recipient)
                    // so the drain path sees the same bytes it would have
                    // seen if the client were online. Send-side
                    // obligations are already baked into `msg` by
                    // `route_inner`; those are idempotent under re-apply.
                    // What we must NOT persist is the Receive-side
                    // actuation, because:
                    //   1. `TagClassified` would emit `authz.classified_delivery`
                    //      for a recipient who never saw the wire message,
                    //      producing a forensic lie on replay.
                    //   2. On drain, `filter_offline_messages` re-runs
                    //      the Receive PEP against the *current* policy
                    //      snapshot — the correct point at which to
                    //      actuate and audit. Double-actuating `MaskPoint`
                    //      is harmless (already-zero coords stay zero),
                    //      but double-auditing TagClassified is not.
                    // The circuit breaker inside `try_send` disconnects
                    // truly slow sessions after N consecutive failures.
                    if handle.is_closed() {
                        warn!(session = %cn, "session channel closed, persisting for offline");
                    } else {
                        debug!(session = %cn, "session channel full, persisting for offline");
                    }
                    // Closes #768: live channel rejected the enqueue
                    // (full or closed) — counts as a backpressure-side
                    // drop even though the message survives via the
                    // store-forward queue.
                    self.emit_dropped("backpressure");
                    self.persist_for_offline(cn, &pre_receive);
                    0
                }
            }
            None => {
                // No live subscriber — persist for redelivery. The
                // authz Receive PEP runs at drain time when the session
                // reconnects; persisting a currently-denied message is
                // acceptable because policy may change before the
                // session returns.
                self.emit_dropped("no_subscribers");
                self.persist_for_offline(cn, &msg);
                0
            }
        }
    }

    /// Persist a message for later delivery to `cn`, if a client queue
    /// is attached. On error the message is dropped and a warning is
    /// logged — the queue is best-effort durability, not a blocker for
    /// live routing.
    fn persist_for_offline(&self, cn: &str, msg: &RoutableMessage) {
        let Some(queue) = self.client_queue.as_ref() else {
            warn!(
                cn = %cn,
                msg_type = %msg.metadata.message_type,
                "direct message dropped: no store-forward queue configured",
            );
            return;
        };
        match queue.enqueue(cn, msg) {
            Ok(_dropped) => {
                debug!(cn, "message persisted to client queue for offline delivery");
            }
            Err(e) => {
                warn!(cn, error = %e, "client queue enqueue failed");
            }
        }
    }

    /// Deliver a group message and return the number of recipients
    /// the router successfully reached. `0` is returned when the
    /// sender failed the ACL/authz Send gate or when the group has no
    /// eligible recipients after authz/ACL filtering. The number is
    /// fed into the `rustgate_router_fanout_subscribers` histogram so
    /// dashboards see the actual delivered count, which is what
    /// matters for capacity planning rather than the candidate pool.
    async fn send_to_group(&self, group: &str, msg: RoutedMessage) -> u64 {
        if !msg.source.is_member_of(group) {
            tracing::warn!(
                sender = %msg.source.cn,
                group = %group,
                "rejected cross-group message: sender not a member"
            );
            // Closes #768: cross-group send is an ACL-style group
            // membership rejection — bucket under "acl_denied".
            self.emit_dropped("acl_denied");
            return 0;
        }

        let acl_guard = self.acl.load();
        let acl_ref: &Option<GroupAclPolicy> = &acl_guard;

        // ACL send authorization — denies sender even if they are a group member
        if let Some(ref acl) = *acl_ref
            && !acl.is_send_authorized(group, &msg.source.cn)
        {
            tracing::warn!(
                sender = %msg.source.cn,
                group = %group,
                "rejected group message: sender not authorized to send"
            );
            self.emit_dropped("acl_denied");
            return 0;
        }

        // Snapshot the optional authz engine once so the per-recipient
        // hot path below is just a virtual call per candidate rather
        // than an atomic load per iteration.
        let authz_guard = self.authz.load();
        let authz: Option<&Arc<dyn PolicyEngine>> = (**authz_guard).as_ref();

        let mut dropped = 0u32;
        let mut total = 0u32;
        // Collect eligible (handle, obligations, rule_id) tuples so the
        // dispatch loop can fire `audit_classified_receive` only after a
        // successful `try_send`. Emitting audit inside the filter_map
        // would record "tagged delivered" for recipients whose channel
        // later rejects the enqueue — a forensic lie under backpressure.
        let eligible: Vec<(SessionHandle, Vec<Obligation>, Option<SmolStr>)> = {
            let state = self.state.read().await;
            let members = match state.groups.get(group) {
                Some(m) => m,
                None => return 0,
            };
            members
                .iter()
                .filter(|cn| *cn != &msg.source.cn)
                .filter(|cn| {
                    let allowed = acl_ref
                        .as_ref()
                        .is_none_or(|acl| acl.is_receive_authorized(group, cn));
                    if !allowed {
                        // Closes #768: per-recipient ACL deny on the
                        // group receive side. One increment per
                        // skipped CN keeps `dropped_total{reason}`
                        // operationally aligned with the audit log.
                        self.emit_dropped("acl_denied");
                    }
                    allowed
                })
                .filter_map(|cn| state.sessions.get(cn).cloned())
                // Per-recipient authz Receive check. The Subject is built
                // from the *recipient's* identity so policies that deny a
                // specific CN or attribute on receive actually take effect.
                // We yield the obligation vec + rule_id alongside the
                // handle so the dispatch loop can audit on successful
                // delivery and rewrap the envelope only when the
                // recipient's rule produced obligations.
                .filter_map(|handle| {
                    let Some(engine) = authz else {
                        return Some((handle, Vec::new(), None));
                    };
                    let subject = AuthzSubject::with_hash(&handle.identity, handle.subject_hash);
                    let resource = AuthzResource::Group { group };
                    let outcome = self.authz_evaluate_receive(engine, &subject, &resource);
                    if !outcome.is_allow() {
                        rustgate_core::audit::authz_denied(
                            &handle.identity.cn,
                            handle.identity.fingerprint.as_str(),
                            "receive",
                            "group",
                            group,
                            outcome.rule_id.as_deref(),
                            engine.policy_id(),
                        );
                        self.emit_dropped("authz_denied");
                        return None;
                    }
                    // Only capture `rule_id` when the recipient will
                    // actually consume it — `audit_classified_receive`
                    // emits only on `TagClassified`. On the untagged
                    // common path we skip the per-recipient clone.
                    // SmolStr kept through so the emission does not
                    // burn a String allocation on the audit hot path.
                    let rule_id = if outcome
                        .obligations
                        .iter()
                        .any(|o| matches!(o, Obligation::TagClassified))
                    {
                        outcome.rule_id.clone()
                    } else {
                        None
                    };
                    Some((handle, outcome.obligations, rule_id))
                })
                .collect()
        };
        let policy_id_for_obligations = authz.map(|e| e.policy_id()).unwrap_or("");
        let mut delivered: u64 = 0;
        for (handle, obligations, rule_id) in &eligible {
            total += 1;
            // Fail-closed on unknown obligation (issue #728): skip
            // this recipient. The audit event is emitted inside
            // `apply_obligations_with_limiter`; the dropped counter
            // catches the operational signal.
            let delivery = match msg.with_obligations(
                obligations,
                self.unknown_obligation_policy,
                policy_id_for_obligations,
                Some(&self.obligation_rate_limiter),
            ) {
                Ok(d) => {
                    self.emit_obligations_applied(obligations);
                    d
                }
                Err(e) => {
                    // Closes #784. Per-recipient debug logging is in
                    // a fan-out hot loop; the explicit `enabled!` gate
                    // skips the `hash_cn` call (and the format-string
                    // construction the macro would otherwise emit a
                    // closure for) when debug-level is not subscribed.
                    if tracing::enabled!(tracing::Level::DEBUG) {
                        debug!(
                            err = %e,
                            group = %group,
                            recipient = %hash_cn(&handle.identity.cn),
                            "group send skipped for recipient: obligation actuation failed"
                        );
                    }
                    dropped += 1;
                    self.emit_dropped("obligation_failed");
                    continue;
                }
            };
            if handle.try_send(delivery) {
                if let Some(engine) = authz {
                    self.audit_classified_receive(
                        obligations,
                        engine,
                        &msg.source.cn,
                        &handle.identity.cn,
                        "group",
                        group,
                        rule_id.as_deref(),
                    );
                }
                delivered += 1;
            } else {
                dropped += 1;
                self.emit_dropped("backpressure");
            }
        }
        if dropped > 0 {
            warn!(
                group = %group,
                dropped = dropped,
                total = total,
                "messages dropped during group send: channel full, disconnected, or obligation fail-closed"
            );
        }
        delivered
    }

    /// Broadcast to all connected sessions (except sender).
    ///
    /// This is intentional for SA sharing — all authenticated clients
    /// receive broadcasts regardless of group membership. Per-recipient
    /// authz Receive PEP still applies: a policy rule denying broadcast
    /// receipt to a specific subject filters that recipient out here.
    ///
    /// Uses non-blocking `try_send` per session so a single slow
    /// consumer cannot block delivery to all other recipients. Messages
    /// that fail to enqueue (channel full or closed) are dropped and
    /// counted — the per-session circuit breaker handles disconnecting
    /// persistently slow sessions.
    /// Broadcast and return the number of recipients the router
    /// successfully delivered to. Recipients filtered out by the
    /// Receive PEP, ACL, or obligation actuation are not counted —
    /// the histogram observes the actual per-fanout delivery shape,
    /// which is what capacity dashboards plot.
    async fn send_to_all(&self, msg: RoutedMessage) -> u64 {
        let targets: Vec<SessionHandle> = {
            let state = self.state.read().await;
            state
                .sessions
                .iter()
                .filter(|(cn, _)| *cn != &msg.source.cn)
                .map(|(_, handle)| handle.clone())
                .collect()
        };

        // Snapshot the authz engine once so the per-recipient loop is a
        // virtual call at worst, not an atomic load per iteration.
        let authz_guard = self.authz.load();
        let authz: Option<&Arc<dyn PolicyEngine>> = (**authz_guard).as_ref();

        let mut dropped = 0u32;
        let mut filtered = 0u32;
        let mut delivered: u64 = 0;
        for handle in &targets {
            // Stash the per-recipient audit context so the audit record
            // is only emitted after a successful try_send — otherwise a
            // channel-full delivery would produce a false-positive
            // "tagged delivered" forensic record.
            let (delivery, audit_ctx) = if let Some(engine) = authz {
                let subject = AuthzSubject::from_identity(&handle.identity);
                let resource = AuthzResource::Broadcast;
                let outcome = self.authz_evaluate_receive(engine, &subject, &resource);
                if !outcome.is_allow() {
                    rustgate_core::audit::authz_denied(
                        &handle.identity.cn,
                        handle.identity.fingerprint.as_str(),
                        "receive",
                        "broadcast",
                        "",
                        outcome.rule_id.as_deref(),
                        engine.policy_id(),
                    );
                    filtered += 1;
                    self.emit_dropped("authz_denied");
                    continue;
                }
                // Fail-closed on unknown obligation (issue #728):
                // skip this recipient. Count as dropped rather than
                // filtered because filtered is authz-denied and this
                // is post-authz.
                let delivery = match msg.with_obligations(
                    &outcome.obligations,
                    self.unknown_obligation_policy,
                    engine.policy_id(),
                    Some(&self.obligation_rate_limiter),
                ) {
                    Ok(d) => {
                        self.emit_obligations_applied(&outcome.obligations);
                        d
                    }
                    Err(e) => {
                        // Closes #784. Per-recipient debug logging
                        // in the broadcast hot loop is gated so the
                        // hash_cn call is skipped on a 1000-subscriber
                        // fanout when debug level is off.
                        if tracing::enabled!(tracing::Level::DEBUG) {
                            debug!(
                                err = %e,
                                recipient = %hash_cn(&handle.identity.cn),
                                "broadcast send skipped for recipient: obligation actuation failed"
                            );
                        }
                        dropped += 1;
                        self.emit_dropped("obligation_failed");
                        continue;
                    }
                };
                (delivery, Some((outcome.obligations, outcome.rule_id)))
            } else {
                (msg.clone(), None)
            };
            if handle.try_send(delivery) {
                if let (Some(engine), Some((obligations, rule_id))) = (authz, audit_ctx) {
                    self.audit_classified_receive(
                        &obligations,
                        engine,
                        &msg.source.cn,
                        &handle.identity.cn,
                        "broadcast",
                        "",
                        rule_id.as_deref(),
                    );
                }
                delivered += 1;
            } else {
                dropped += 1;
                self.emit_dropped("backpressure");
            }
        }
        if dropped > 0 {
            warn!(
                dropped = dropped,
                total = targets.len(),
                "messages dropped during broadcast: channel full or disconnected"
            );
        }
        if filtered > 0 {
            debug!(
                filtered = filtered,
                total = targets.len(),
                "broadcast recipients filtered by authz policy"
            );
        }
        delivered
    }

    /// Send a message to multiple groups simultaneously, returning
    /// the unique recipient count after de-duplication. Each call to
    /// [`Self::send_to_group_excluding`] increments the running total
    /// by the number of CNs it actually delivered to in that pass —
    /// CNs already present in `delivered` from an earlier group in
    /// the multicast list are not double-counted.
    async fn send_to_multicast(&self, groups: &[Arc<str>], msg: RoutedMessage) -> u64 {
        if groups.is_empty() {
            return 0;
        }

        let mut delivered: HashSet<Arc<str>> = HashSet::new();
        let mut total: u64 = 0;
        for group in groups {
            total += self
                .send_to_group_excluding(group, msg.clone(), &mut delivered)
                .await;
        }
        total
    }

    /// Deliver to a single group but skip CNs already present in
    /// `delivered`. After each successful enqueue the CN is added to
    /// the set so subsequent groups in a multicast fan-out will not
    /// deliver twice. Returns the number of recipients delivered to in
    /// this pass — the caller in [`Self::send_to_multicast`] sums
    /// these across the multicast group list to report a unique
    /// recipient count to the fanout subscribers histogram.
    async fn send_to_group_excluding(
        &self,
        group: &str,
        msg: RoutedMessage,
        delivered: &mut HashSet<Arc<str>>,
    ) -> u64 {
        if !msg.source.is_member_of(group) {
            tracing::warn!(
                sender = %msg.source.cn,
                group = %group,
                "rejected cross-group message: sender not a member"
            );
            self.emit_dropped("acl_denied");
            return 0;
        }

        let acl_guard = self.acl.load();
        let acl_ref: &Option<GroupAclPolicy> = &acl_guard;

        if let Some(ref acl) = *acl_ref
            && !acl.is_send_authorized(group, &msg.source.cn)
        {
            tracing::warn!(
                sender = %msg.source.cn,
                group = %group,
                "rejected group message: sender not authorized to send"
            );
            self.emit_dropped("acl_denied");
            return 0;
        }

        let authz_guard = self.authz.load();
        let authz: Option<&Arc<dyn PolicyEngine>> = (**authz_guard).as_ref();

        // Per-group Send PEP for multicast. The top-level Send PEP in
        // route_inner intentionally skips Multicast (it cannot represent
        // per-group granularity), so each group in the multicast fan-out
        // must evaluate the Send action independently.
        //
        // Send obligations are applied to the envelope up-front so the
        // Receive PEP loop below dispatches the Send-masked form to every
        // recipient — cheaper than rewrapping per-recipient when the
        // group's Send rule produces a `MaskPoint` or `MaskPayload`.
        let msg = if let Some(engine) = authz {
            let subject = AuthzSubject::from_identity(&msg.source);
            let resource = AuthzResource::Group { group };
            let outcome = self.authz_evaluate_send(engine, &subject, &resource);
            if !outcome.is_allow() {
                rustgate_core::audit::authz_denied(
                    &msg.source.cn,
                    msg.source.fingerprint.as_str(),
                    "send",
                    "group",
                    group,
                    outcome.rule_id.as_deref(),
                    engine.policy_id(),
                );
                self.emit_dropped("authz_denied");
                return 0;
            }
            // Fail-closed on unknown obligation (issue #728): abort
            // the whole group delivery. No recipients see the
            // message — the sender-side obligation must be actuated
            // uniformly per the policy author's intent, so fanning
            // out partial bytes would defeat the policy.
            match msg.with_obligations(
                &outcome.obligations,
                self.unknown_obligation_policy,
                engine.policy_id(),
                Some(&self.obligation_rate_limiter),
            ) {
                Ok(m) => {
                    self.emit_obligations_applied(&outcome.obligations);
                    m
                }
                Err(e) => {
                    debug!(
                        err = %e,
                        sender = %hash_cn(&msg.source.cn),
                        group = %group,
                        "group send aborted: send obligation actuation failed"
                    );
                    self.emit_dropped("obligation_failed");
                    return 0;
                }
            }
        } else {
            msg
        };

        let mut dropped = 0u32;
        let mut total = 0u32;
        let mut delivered_count: u64 = 0;
        // Collect eligible handles so the borrow on `delivered` from
        // the filter chain does not overlap with the mutable insert
        // below. We carry the rule_id alongside the obligations so the
        // dispatch loop can fire `audit_classified_receive` only after a
        // successful `try_send`.
        let eligible: Vec<(SessionHandle, Vec<Obligation>, Option<SmolStr>)> = {
            let state = self.state.read().await;
            let members = match state.groups.get(group) {
                Some(m) => m,
                None => return 0,
            };
            members
                .iter()
                .filter(|cn| *cn != &msg.source.cn)
                .filter(|cn| !delivered.contains(&***cn))
                .filter(|cn| {
                    let allowed = acl_ref
                        .as_ref()
                        .is_none_or(|acl| acl.is_receive_authorized(group, cn));
                    if !allowed {
                        self.emit_dropped("acl_denied");
                    }
                    allowed
                })
                .filter_map(|cn| state.sessions.get(cn).cloned())
                .filter_map(|handle| {
                    let Some(engine) = authz else {
                        return Some((handle, Vec::new(), None));
                    };
                    let subject = AuthzSubject::with_hash(&handle.identity, handle.subject_hash);
                    let resource = AuthzResource::Group { group };
                    let outcome = self.authz_evaluate_receive(engine, &subject, &resource);
                    if !outcome.is_allow() {
                        rustgate_core::audit::authz_denied(
                            &handle.identity.cn,
                            handle.identity.fingerprint.as_str(),
                            "receive",
                            "group",
                            group,
                            outcome.rule_id.as_deref(),
                            engine.policy_id(),
                        );
                        self.emit_dropped("authz_denied");
                        return None;
                    }
                    // See send_to_group: skip rule_id capture unless
                    // TagClassified is present so the fan-out loop does
                    // not clone per recipient for metadata that will
                    // be discarded by `audit_classified_receive`.
                    // SmolStr kept through to avoid allocating a String.
                    let rule_id = if outcome
                        .obligations
                        .iter()
                        .any(|o| matches!(o, Obligation::TagClassified))
                    {
                        outcome.rule_id.clone()
                    } else {
                        None
                    };
                    Some((handle, outcome.obligations, rule_id))
                })
                .collect()
        };
        let policy_id_for_obligations = authz.map(|e| e.policy_id()).unwrap_or("");
        for (handle, obligations, rule_id) in &eligible {
            total += 1;
            // Fail-closed on unknown obligation (issue #728): skip
            // this recipient. `delivered` is deliberately not
            // populated so a subsequent group in the multicast
            // fan-out may still attempt this CN under its own
            // per-group Receive rules — on the off chance its
            // obligation list is actuable on this transport build.
            let delivery = match msg.with_obligations(
                obligations,
                self.unknown_obligation_policy,
                policy_id_for_obligations,
                Some(&self.obligation_rate_limiter),
            ) {
                Ok(d) => {
                    self.emit_obligations_applied(obligations);
                    d
                }
                Err(e) => {
                    // Closes #784. Per-recipient debug logging in
                    // the multicast hot loop is gated so the
                    // hash_cn call is skipped on a wide multicast
                    // fanout when debug level is off.
                    if tracing::enabled!(tracing::Level::DEBUG) {
                        debug!(
                            err = %e,
                            group = %group,
                            recipient = %hash_cn(&handle.identity.cn),
                            "multicast group send skipped for recipient: obligation actuation failed"
                        );
                    }
                    dropped += 1;
                    self.emit_dropped("obligation_failed");
                    continue;
                }
            };
            if handle.try_send(delivery) {
                let _ = delivered.insert(Arc::clone(&handle.identity.cn));
                if let Some(engine) = authz {
                    self.audit_classified_receive(
                        obligations,
                        engine,
                        &msg.source.cn,
                        &handle.identity.cn,
                        "group",
                        group,
                        rule_id.as_deref(),
                    );
                }
                delivered_count += 1;
            } else {
                dropped += 1;
                self.emit_dropped("backpressure");
            }
        }
        if dropped > 0 {
            warn!(
                group = %group,
                dropped = dropped,
                total = total,
                "messages dropped during multicast group send: channel full, disconnected, or obligation fail-closed"
            );
        }
        delivered_count
    }
}

/// Wire the router's instrumented Send-PEP entry point into the egress
/// helper without exposing `authz_evaluate_send` as a public method. The
/// helper does not know about the router's PEP instrumentation
/// (in-flight gauge, observer callback, latency histogram); the trait
/// indirection lets the helper stay decoupled while every
/// envelope-rendering evaluation is observed identically to a local
/// fan-out evaluation. Closes #746.
impl EnvelopeEvaluator for Router {
    fn evaluate_send(
        &self,
        engine: &Arc<dyn PolicyEngine>,
        subject: &AuthzSubject<'_>,
        resource: &AuthzResource<'_>,
    ) -> rustgate_authz::DecisionOutcome {
        self.authz_evaluate_send(engine, subject, resource)
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_results)]
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    use super::*;

    fn make_identity(cn: &str, groups: &[&str]) -> Arc<Identity> {
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

    /// Create a dual-channel pair and return (priority_tx, normal_tx, priority_rx, normal_rx).
    #[allow(clippy::type_complexity)]
    fn make_channels(
        priority_cap: usize,
        normal_cap: usize,
    ) -> (
        mpsc::Sender<RoutedMessage>,
        mpsc::Sender<RoutedMessage>,
        mpsc::Receiver<RoutedMessage>,
        mpsc::Receiver<RoutedMessage>,
    ) {
        let (ptx, prx) = mpsc::channel(priority_cap);
        let (ntx, nrx) = mpsc::channel(normal_cap);
        (ptx, ntx, prx, nrx)
    }

    fn make_position(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
        RoutableMessage {
            source: (**source).clone(),
            destination: dest,
            payload: Bytes::from_static(b"<event/>"),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "cot".to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        }
    }

    fn make_alert(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
        RoutableMessage {
            source: (**source).clone(),
            destination: dest,
            payload: Bytes::from_static(b"<alert/>"),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "cot".to_string(),
                message_type: MessageType::Alert,
                ttl: None,
            },
        }
    }

    fn make_chat(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
        RoutableMessage {
            source: (**source).clone(),
            destination: dest,
            payload: Bytes::from_static(b"<chat/>"),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "cot".to_string(),
                message_type: MessageType::Chat,
                ttl: None,
            },
        }
    }

    #[tokio::test]
    async fn send_to_group_rejects_non_member() {
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["bravo"]);

        let (ptx_a, ntx_a, _prx_a, mut nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        // Bob sends to group "alpha" — but bob is only in "bravo".
        // The router must reject this: sender is not a member of the
        // target group, so alice (who IS in alpha) must not receive it.
        let msg = make_chat(&bob, Destination::Group("alpha".into()));
        router.route(msg).await;

        assert!(
            nrx_a.try_recv().is_err(),
            "alice must not receive: bob is not in alpha and cannot send to it"
        );
    }

    #[tokio::test]
    async fn send_to_group_allows_member() {
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        let charlie = make_identity("charlie", &["bravo"]);

        let (ptx_a, ntx_a, _prx_a, mut nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);
        let (ptx_c, ntx_c, _prx_c, mut nrx_c) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;
        router
            .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
            .await;

        // Bob sends to group "alpha" — bob IS a member
        let msg = make_chat(&bob, Destination::Group("alpha".into()));
        router.route(msg).await;

        // Alice (in alpha) receives chat on normal channel
        let received = nrx_a.try_recv().expect("alice must receive: both in alpha");
        assert_eq!(received.payload.as_ref(), b"<chat/>");
        assert_eq!(&*received.source.cn, "bob");

        // Charlie (in bravo, not alpha) must NOT receive
        assert!(
            nrx_c.try_recv().is_err(),
            "charlie must not receive: not in alpha"
        );
    }

    #[tokio::test]
    async fn replay_positions_filters_by_group() {
        let router = Router::new();

        let alpha_user = make_identity("alpha-user", &["alpha"]);
        let bravo_user = make_identity("bravo-user", &["bravo"]);

        // Cache a position from alpha_user
        let pos = make_position(&alpha_user, Destination::Broadcast);
        router.cache().store(pos).await;

        // bravo_user connects — should NOT receive alpha_user's position
        let (ptx, ntx, mut prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(bravo_user.clone(), ptx, ntx);
        router.replay_positions(&handle).await;

        assert!(
            prx.try_recv().is_err(),
            "bravo_user should not see alpha_user's position"
        );
    }

    #[tokio::test]
    async fn replay_positions_allows_shared_group() {
        let router = Router::new();

        let alice = make_identity("alice", &["alpha", "shared"]);
        let bob = make_identity("bob", &["bravo", "shared"]);

        // Cache a position from alice
        let pos = make_position(&alice, Destination::Broadcast);
        router.cache().store(pos).await;

        // Bob connects — shares "shared" group with alice
        // Position messages go to priority channel
        let (ptx, ntx, mut prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(bob.clone(), ptx, ntx);
        router.replay_positions(&handle).await;

        assert!(
            prx.try_recv().is_ok(),
            "bob should see alice's position via shared group"
        );
    }

    // -- Per-CN replay rate limit (issue #724) ---------------------------

    /// A flap-looping client must not be able to drive replay-time authz
    /// work without bound. With burst=4 and rate=0/sec, the bucket holds
    /// exactly 4 tokens and never refills; the 5th replay attempt must be
    /// rate-limited.
    #[tokio::test]
    async fn replay_positions_consumes_tokens() {
        let router = Router::new().with_position_replay_limit(PositionReplayLimitConfig::new(0, 4));

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        let pos = make_position(&alice, Destination::Broadcast);
        router.cache().store(pos).await;

        // First 4 replay invocations under bob's CN must each deliver
        // alice's cached position — burst=4 means four tokens available
        // up-front and rate=0 means no refill ever. Each call uses a
        // fresh dual-channel pair so we can observe per-attempt delivery.
        for i in 0..4 {
            let (ptx, ntx, mut prx, _nrx) = make_channels(16, 16);
            let handle = SessionHandle::new(bob.clone(), ptx, ntx);
            router.replay_positions(&handle).await;
            assert!(
                prx.try_recv().is_ok(),
                "replay attempt {i} should succeed — burst=4 covers the first four"
            );
        }

        // 5th replay must be rate-limited. The bucket has 0 tokens left
        // and rate=0 means no refill. A successful replay would queue
        // alice's position on the priority channel; a shed replay leaves
        // the channel empty.
        let (ptx, ntx, mut prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(bob.clone(), ptx, ntx);
        router.replay_positions(&handle).await;
        assert!(
            prx.try_recv().is_err(),
            "5th replay must be shed by the per-CN bucket"
        );
    }

    /// After waiting long enough for the bucket to refill, a subsequent
    /// replay must succeed. Pin the refill semantics so a regression that
    /// dropped the time-based refill (e.g. by recreating the bucket every
    /// call) would be caught here.
    #[tokio::test]
    async fn replay_positions_refills_over_time() {
        // 100/sec refill, burst=1 — drain the single token, wait 100ms (=10
        // tokens of refill, capped at 1), then verify the next replay
        // succeeds.
        let router =
            Router::new().with_position_replay_limit(PositionReplayLimitConfig::new(100, 1));

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        let pos = make_position(&alice, Destination::Broadcast);
        router.cache().store(pos).await;

        let (ptx, ntx, mut prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(bob.clone(), ptx, ntx);

        // First call drains the only token and delivers the position.
        router.replay_positions(&handle).await;
        assert!(
            prx.try_recv().is_ok(),
            "first replay must deliver alice's position"
        );

        // Immediately re-attempt: no time has passed, no refill.
        let (ptx2, ntx2, mut prx2, _nrx2) = make_channels(16, 16);
        let handle2 = SessionHandle::new(bob.clone(), ptx2, ntx2);
        router.replay_positions(&handle2).await;
        assert!(
            prx2.try_recv().is_err(),
            "second replay must be shed before any refill"
        );

        // Wait long enough for one token to refill (100/sec → 10ms per
        // token; 100ms is a generous margin against scheduler jitter).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let (ptx3, ntx3, mut prx3, _nrx3) = make_channels(16, 16);
        let handle3 = SessionHandle::new(bob.clone(), ptx3, ntx3);
        router.replay_positions(&handle3).await;
        assert!(
            prx3.try_recv().is_ok(),
            "third replay must succeed after refill window"
        );
    }

    // (Audit emission for the rate-limit path lives in
    // `tests/position_replay_rate_limit_audit.rs` — a dedicated
    // integration-test binary so the thread-local audit subscriber
    // does not race other in-process tests that also emit on the
    // `audit` target.)

    /// Per-CN isolation: one client's bucket exhaustion must not affect
    /// another client's replay. Pin this so a regression that
    /// accidentally shared a single bucket would be caught here.
    #[tokio::test]
    async fn replay_positions_per_cn_isolation() {
        let router = Router::new().with_position_replay_limit(PositionReplayLimitConfig::new(0, 1));

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        let charlie = make_identity("charlie", &["alpha"]);
        let pos = make_position(&alice, Destination::Broadcast);
        router.cache().store(pos).await;

        // Bob exhausts his bucket (burst=1, then the next call sheds).
        let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
        let handle_b1 = SessionHandle::new(bob.clone(), ptx, ntx);
        router.replay_positions(&handle_b1).await;

        let (ptx, ntx, mut prx, _nrx) = make_channels(16, 16);
        let handle_b2 = SessionHandle::new(bob.clone(), ptx, ntx);
        router.replay_positions(&handle_b2).await;
        assert!(
            prx.try_recv().is_err(),
            "bob's second replay must be shed (his bucket is empty)"
        );

        // Charlie connects with a fresh bucket: must succeed despite
        // bob's exhaustion.
        let (ptx, ntx, mut prx, _nrx) = make_channels(16, 16);
        let handle_c = SessionHandle::new(charlie.clone(), ptx, ntx);
        router.replay_positions(&handle_c).await;
        assert!(
            prx.try_recv().is_ok(),
            "charlie's first replay must succeed — his bucket is independent of bob's"
        );
    }

    /// Pin the operator-friendly default: a normal-cadence reconnect
    /// (one replay, then occasional churn) is never rate-limited. A
    /// regression that dropped the burst floor below 1 — or that picked
    /// a stricter default — would shed legitimate operator traffic.
    #[tokio::test]
    async fn replay_positions_default_rate_permissive_for_normal_use() {
        let router = Router::new(); // default config (rate=100, burst=200)

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        let pos = make_position(&alice, Destination::Broadcast);
        router.cache().store(pos).await;

        // A single replay must always deliver — the default must never
        // shed the very first reconnect.
        let (ptx, ntx, mut prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(bob.clone(), ptx, ntx);
        router.replay_positions(&handle).await;
        assert!(
            prx.try_recv().is_ok(),
            "default config must never shed the first reconnect — burst >= 1"
        );

        // Pin the default values explicitly so a future bump is at least
        // intentional.
        let cfg = router.position_replay_limit_config();
        assert_eq!(
            cfg.rate_per_sec, 100,
            "default rate_per_sec is the documented operator-safe value"
        );
        assert_eq!(
            cfg.burst, 200,
            "default burst is the documented operator-safe value"
        );
    }

    /// A CN-churning attacker must not be able to inflate the rate-limit
    /// bucket map by opening many distinct CN connections. After
    /// disconnect the bucket entry must be released; the map size must
    /// not grow without bound across a connect/disconnect cycle.
    #[tokio::test]
    async fn position_replay_rate_limit_token_bucket_pruned_on_disconnect() {
        let router = Router::new();

        // Cycle three distinct CNs through register → replay → unregister
        // and assert the map is empty afterwards. A single residual entry
        // would be acceptable in isolation, but the security invariant is
        // that disconnect *eventually* drains every bucket.
        for cn in ["alice", "bob", "charlie"] {
            let id = make_identity(cn, &["alpha"]);
            let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
            let handle = SessionHandle::new(id.clone(), ptx, ntx);
            let session_id = handle.id;
            assert!(router.register(handle).await);
            // Force a bucket entry to materialise.
            router
                .replay_positions(&{
                    let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
                    SessionHandle::new(id.clone(), ptx, ntx)
                })
                .await;
            // The bucket must exist *during* the session.
            assert!(
                router.replay_bucket_map_len() >= 1,
                "bucket entry for {cn} must be tracked while the session is registered"
            );
            router.unregister(cn, session_id).await;
        }

        assert_eq!(
            router.replay_bucket_map_len(),
            0,
            "every disconnected CN must have its replay bucket pruned — \
             a CN-churning attacker cannot inflate the map without bound"
        );
    }

    #[tokio::test]
    async fn disconnect_client_closes_senders_and_returns_true() {
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);
        let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(alice.clone(), ptx, ntx);

        let _ = router.register(handle).await;

        // Disconnect returns true and clears both sender slots. Subsequent
        // route attempts find `None` in the sender Option and give up,
        // matching the behavior of `close_all_session_senders`.
        assert!(router.disconnect_client("alice").await);

        let state = router.state.read().await;
        let handle = state.sessions.get("alice").expect("still registered");
        assert!(handle.priority_sender.lock().is_none());
        assert!(handle.normal_sender.lock().is_none());
    }

    #[tokio::test]
    async fn disconnect_client_returns_false_for_unknown_cn() {
        let router = Router::new();
        // No sessions registered — disconnect is a no-op.
        assert!(!router.disconnect_client("ghost").await);
    }

    #[tokio::test]
    async fn disconnect_client_is_case_sensitive() {
        // The session map keys on the exact CN recorded at register time,
        // which preserves the cert's original casing. A case-mismatched
        // lookup must miss rather than silently disconnect a neighbor.
        let router = Router::new();
        let alice = make_identity("Alice", &["alpha"]);
        let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
        let _ = router.register(SessionHandle::new(alice, ptx, ntx)).await;

        assert!(!router.disconnect_client("alice").await);
        assert!(router.disconnect_client("Alice").await);
    }

    #[tokio::test]
    async fn unregister_evicts_from_cache() {
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(alice.clone(), ptx, ntx);
        let session_id = handle.id;

        let _ = router.register(handle).await;

        // Cache a position
        let pos = make_position(&alice, Destination::Broadcast);
        router.cache().store(pos).await;
        assert_eq!(router.cache().len().await, 1);

        // Unregister should also evict from cache
        router.unregister("alice", session_id).await;
        assert_eq!(router.cache().len().await, 0);
    }

    #[tokio::test]
    async fn register_enforces_max_groups_per_cn() {
        let router = Router::with_limits(3, 10_000);

        // Client has 5 groups but limit is 3
        let alice = make_identity("alice", &["g1", "g2", "g3", "g4", "g5"]);
        let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
        router
            .register(SessionHandle::new(alice.clone(), ptx, ntx))
            .await;

        let state = router.state.read().await;
        // Only 3 groups should have been registered (BTreeSet is sorted, so g1, g2, g3)
        let alice_group_count = state
            .groups
            .values()
            .filter(|members| members.contains("alice"))
            .count();
        assert_eq!(
            alice_group_count, 3,
            "CN should be limited to max_groups_per_cn"
        );
    }

    #[tokio::test]
    async fn register_enforces_max_total_groups() {
        // Allow each CN to join many groups, but cap total groups at 2
        let router = Router::with_limits(128, 2);

        // First client joins 2 groups — fills the total limit
        let alice = make_identity("alice", &["g1", "g2"]);
        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 16);
        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;

        // Second client tries to join a new group — should be rejected
        let bob = make_identity("bob", &["g3"]);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let state = router.state.read().await;
        assert_eq!(state.groups.len(), 2, "total groups should be capped at 2");
        assert!(
            !state.groups.contains_key("g3"),
            "new group should be rejected when at total limit"
        );
    }

    #[tokio::test]
    async fn register_allows_joining_existing_group_at_total_limit() {
        // Total limit is 2, but joining an existing group should still work
        let router = Router::with_limits(128, 2);

        let alice = make_identity("alice", &["g1", "g2"]);
        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 16);
        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;

        // Bob joins g1 (already exists) — should succeed
        let bob = make_identity("bob", &["g1"]);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let state = router.state.read().await;
        let g1_members = state.groups.get("g1").expect("g1 should exist");
        assert!(
            g1_members.contains("bob"),
            "bob should be able to join existing group even at total limit"
        );
    }

    #[tokio::test]
    async fn connected_clients_returns_all_sessions() {
        let router = Router::new();

        assert!(router.connected_clients().await.is_empty());

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["bravo"]);

        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let clients = router.connected_clients().await;
        assert_eq!(clients.len(), 2);

        let cns: Vec<&str> = clients.iter().map(|c| &*c.cn).collect();
        assert!(cns.contains(&"alice"));
        assert!(cns.contains(&"bob"));
    }

    #[tokio::test]
    async fn circuit_breaker_trips_after_threshold() {
        let identity = make_identity("slow-client", &["alpha"]);
        // Use capacity-1 priority channel for Position messages
        let (ptx, _ntx, mut prx, _nrx) = make_channels(1, 16);
        let handle = SessionHandle::with_drop_threshold(identity, ptx, _ntx, 3);

        // Fill the priority channel with a Position message
        let msg = Arc::new(make_position(
            &make_identity("sender", &["alpha"]),
            Destination::Broadcast,
        ));
        assert!(handle.try_send(msg.clone()));

        // Next 3 attempts should fail (channel full), tripping breaker on 3rd
        assert!(!handle.try_send(msg.clone()));
        assert!(!handle.try_send(msg.clone()));
        assert!(!handle.try_send(msg.clone()));

        // Sender should be poisoned
        assert!(!handle.is_alive());
        assert!(!handle.try_send(msg.clone()));

        // Receiver should get None (sender dropped)
        let _ = prx.recv().await; // drain the one successful message
        assert!(prx.recv().await.is_none());
    }

    #[tokio::test]
    async fn circuit_breaker_resets_on_success() {
        let identity = make_identity("recovering-client", &["alpha"]);
        let (ptx, _ntx, mut prx, _nrx) = make_channels(2, 16);
        let handle = SessionHandle::with_drop_threshold(identity, ptx, _ntx, 3);

        // Fill priority channel
        let msg = Arc::new(make_position(
            &make_identity("sender", &["alpha"]),
            Destination::Broadcast,
        ));
        assert!(handle.try_send(msg.clone()));
        assert!(handle.try_send(msg.clone()));

        // Fail twice (under threshold)
        assert!(!handle.try_send(msg.clone()));
        assert!(!handle.try_send(msg.clone()));

        // Drain and succeed — should reset counter
        let _ = prx.recv().await;
        let _ = prx.recv().await;
        assert!(handle.try_send(msg.clone()));

        // Fill the remaining slot so subsequent sends fail
        assert!(handle.try_send(msg.clone()));

        // Fail twice again — should NOT trip because counter was reset
        assert!(!handle.try_send(msg.clone()));
        assert!(!handle.try_send(msg.clone()));
        assert!(handle.is_alive());
    }

    #[tokio::test]
    async fn circuit_breaker_does_not_trip_below_threshold() {
        let identity = make_identity("borderline-client", &["alpha"]);
        let (ptx, _ntx, mut prx, _nrx) = make_channels(1, 16);
        let handle = SessionHandle::with_drop_threshold(identity, ptx, _ntx, 5);

        let msg = Arc::new(make_position(
            &make_identity("sender", &["alpha"]),
            Destination::Broadcast,
        ));
        assert!(handle.try_send(msg.clone()));

        // Fail 4 times (threshold is 5)
        for _ in 0..4 {
            assert!(!handle.try_send(msg.clone()));
        }

        // Should still be alive
        assert!(handle.is_alive());

        // Drain and succeed to reset
        let _ = prx.recv().await;
        assert!(handle.try_send(msg.clone()));
        assert!(handle.is_alive());
    }

    #[tokio::test]
    async fn group_send_triggers_circuit_breaker() {
        let router = Router::new();

        let sender_id = make_identity("sender", &["ops"]);
        let slow_id = make_identity("slow", &["ops"]);

        let (ptx_sender, ntx_sender, _prx_sender, _nrx_sender) = make_channels(64, 64);
        // Normal channel capacity 1 for the slow client (chat goes to normal)
        let (ptx_slow, ntx_slow, _prx_slow, mut nrx_slow) = make_channels(16, 1);

        router
            .register(SessionHandle::new(
                sender_id.clone(),
                ptx_sender,
                ntx_sender,
            ))
            .await;
        router
            .register(SessionHandle::with_drop_threshold(
                slow_id.clone(),
                ptx_slow,
                ntx_slow,
                3,
            ))
            .await;

        // Send enough chat messages to trip the breaker on normal channel
        // Channel capacity is 1, so first message fills it, next 3 trip the breaker
        for _ in 0..5 {
            let msg = make_chat(&sender_id, Destination::Group("ops".into()));
            router.route(msg).await;
        }

        // Drain the one message that made it through
        let _ = nrx_slow.recv().await;
        // Receiver should see None (sender poisoned by circuit breaker)
        assert!(nrx_slow.recv().await.is_none());
    }

    #[tokio::test]
    async fn acl_denies_unauthorized_sender() {
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "alpha".to_string(),
            crate::acl::GroupAcl::new(
                std::collections::HashSet::from(["alice".to_string()]),
                std::collections::HashSet::from(["alice".to_string(), "bob".to_string()]),
            ),
        );
        let policy = crate::acl::GroupAclPolicy::new(groups);
        let router = Router::with_acl(policy);

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        let (ptx_a, ntx_a, _prx_a, mut nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        // Bob is a member of alpha but NOT in the send ACL
        let msg = make_chat(&bob, Destination::Group("alpha".into()));
        router.route(msg).await;

        assert!(
            nrx_a.try_recv().is_err(),
            "alice must not receive: bob is not authorized to send to alpha"
        );
    }

    #[tokio::test]
    async fn acl_allows_authorized_sender() {
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "alpha".to_string(),
            crate::acl::GroupAcl::new(
                std::collections::HashSet::from(["alice".to_string(), "bob".to_string()]),
                std::collections::HashSet::from(["alice".to_string(), "bob".to_string()]),
            ),
        );
        let policy = crate::acl::GroupAclPolicy::new(groups);
        let router = Router::with_acl(policy);

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        let (ptx_a, ntx_a, _prx_a, mut nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        // Bob is authorized to send
        let msg = make_chat(&bob, Destination::Group("alpha".into()));
        router.route(msg).await;

        assert!(
            nrx_a.try_recv().is_ok(),
            "alice must receive: bob is authorized to send to alpha"
        );
    }

    #[tokio::test]
    async fn acl_filters_unauthorized_receivers() {
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "alpha".to_string(),
            crate::acl::GroupAcl::new(
                std::collections::HashSet::from(["alice".to_string()]),
                // Only alice can receive — bob and charlie cannot
                std::collections::HashSet::from(["alice".to_string()]),
            ),
        );
        let policy = crate::acl::GroupAclPolicy::new(groups);
        let router = Router::with_acl(policy);

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        let charlie = make_identity("charlie", &["alpha"]);

        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, mut nrx_b) = make_channels(16, 16);
        let (ptx_c, ntx_c, _prx_c, mut nrx_c) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;
        router
            .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
            .await;

        // Alice sends — authorized
        let msg = make_chat(&alice, Destination::Group("alpha".into()));
        router.route(msg).await;

        assert!(
            nrx_b.try_recv().is_err(),
            "bob must not receive: not in receive ACL"
        );
        assert!(
            nrx_c.try_recv().is_err(),
            "charlie must not receive: not in receive ACL"
        );
    }

    #[tokio::test]
    async fn acl_open_when_no_policy() {
        // Router without ACL — backward compatible open mode
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        let (ptx_a, ntx_a, _prx_a, mut nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let msg = make_chat(&bob, Destination::Group("alpha".into()));
        router.route(msg).await;

        assert!(
            nrx_a.try_recv().is_ok(),
            "alice must receive: no ACL means open mode"
        );
    }

    #[tokio::test]
    async fn acl_denies_unconfigured_group_when_policy_loaded() {
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "restricted".to_string(),
            crate::acl::GroupAcl::new(
                std::collections::HashSet::from(["admin".to_string()]),
                std::collections::HashSet::from(["admin".to_string()]),
            ),
        );
        let policy = crate::acl::GroupAclPolicy::new(groups);
        let router = Router::with_acl(policy);

        let alice = make_identity("alice", &["open-group"]);
        let bob = make_identity("bob", &["open-group"]);

        let (ptx_a, ntx_a, _prx_a, mut nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        // "open-group" is not in the policy — default-deny when policy loaded.
        let msg = make_chat(&bob, Destination::Group("open-group".into()));
        router.route(msg).await;

        assert!(
            nrx_a.try_recv().is_err(),
            "alice must NOT receive: unconfigured group denied when policy loaded"
        );
    }

    #[tokio::test]
    async fn acl_broadcast_ignores_policy() {
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "alpha".to_string(),
            crate::acl::GroupAcl::new(
                std::collections::HashSet::new(), // nobody can send
                std::collections::HashSet::new(), // nobody can receive
            ),
        );
        let policy = crate::acl::GroupAclPolicy::new(groups);
        let router = Router::with_acl(policy);

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        let (ptx_a, ntx_a, _prx_a, mut nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        // Broadcast chat — should ignore ACL, goes to normal channel
        let msg = make_chat(&bob, Destination::Broadcast);
        router.route(msg).await;

        assert!(
            nrx_a.try_recv().is_ok(),
            "broadcasts must ignore group ACL policy"
        );
    }

    #[tokio::test]
    async fn acl_replay_filters_unauthorized_receivers() {
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "alpha".to_string(),
            crate::acl::GroupAcl::new(
                std::collections::HashSet::from(["alice".to_string()]),
                // Only alice can receive from alpha
                std::collections::HashSet::from(["alice".to_string()]),
            ),
        );
        let policy = crate::acl::GroupAclPolicy::new(groups);
        let router = Router::with_acl(policy);

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        // Cache a position from alice
        let pos = make_position(&alice, Destination::Broadcast);
        router.cache().store(pos).await;

        // Bob connects — member of alpha but NOT in receive ACL
        // Position messages go to priority channel
        let (ptx, ntx, mut prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(bob.clone(), ptx, ntx);
        router.replay_positions(&handle).await;

        assert!(
            prx.try_recv().is_err(),
            "bob must not receive replayed position: not in alpha receive ACL"
        );
    }

    #[tokio::test]
    async fn priority_messages_route_to_priority_channel() {
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        let (ptx_a, ntx_a, mut prx_a, mut nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        // Send a Position message (priority)
        let pos = make_position(&bob, Destination::Group("alpha".into()));
        router.route(pos).await;

        // Send an Alert message (priority)
        let alert = make_alert(&bob, Destination::Group("alpha".into()));
        router.route(alert).await;

        // Send a Chat message (normal)
        let chat = make_chat(&bob, Destination::Group("alpha".into()));
        router.route(chat).await;

        // Position and Alert should be on priority channel
        let p = prx_a
            .try_recv()
            .expect("position must arrive on priority channel");
        assert_eq!(p.metadata.message_type, MessageType::Position);

        let a = prx_a
            .try_recv()
            .expect("alert must arrive on priority channel");
        assert_eq!(a.metadata.message_type, MessageType::Alert);

        // Chat should be on normal channel
        let c = nrx_a
            .try_recv()
            .expect("chat must arrive on normal channel");
        assert_eq!(c.metadata.message_type, MessageType::Chat);

        // No more messages on either channel
        assert!(prx_a.try_recv().is_err());
        assert!(nrx_a.try_recv().is_err());
    }

    #[tokio::test]
    async fn swap_acl_atomically_replaces_policy() {
        // Start with no ACL — open mode
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        let (ptx_a, ntx_a, _prx_a, mut nrx_a) = make_channels(16, 16);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        // Open mode: bob can send to alpha
        let msg = make_chat(&bob, Destination::Group("alpha".into()));
        router.route(msg).await;
        assert!(nrx_a.try_recv().is_ok(), "alice must receive in open mode");

        // Swap in a restrictive ACL: only alice can send
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "alpha".to_string(),
            crate::acl::GroupAcl::new(
                std::collections::HashSet::from(["alice".to_string()]),
                std::collections::HashSet::from(["alice".to_string(), "bob".to_string()]),
            ),
        );
        let policy = crate::acl::GroupAclPolicy::new(groups);
        router.swap_acl(Some(policy));

        // Bob can no longer send to alpha
        let msg = make_chat(&bob, Destination::Group("alpha".into()));
        router.route(msg).await;
        assert!(
            nrx_a.try_recv().is_err(),
            "alice must NOT receive: bob is no longer authorized after swap"
        );

        // Swap back to open mode
        router.swap_acl(None);

        let msg = make_chat(&bob, Destination::Group("alpha".into()));
        router.route(msg).await;
        assert!(
            nrx_a.try_recv().is_ok(),
            "alice must receive after reverting to open mode"
        );
    }

    #[tokio::test]
    async fn swap_acl_affects_replay_positions() {
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        // Cache a position from alice
        let pos = make_position(&alice, Destination::Broadcast);
        router.cache().store(pos).await;

        // Swap in ACL: bob cannot receive from alpha
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "alpha".to_string(),
            crate::acl::GroupAcl::new(
                std::collections::HashSet::from(["alice".to_string()]),
                std::collections::HashSet::from(["alice".to_string()]),
            ),
        );
        let policy = crate::acl::GroupAclPolicy::new(groups);
        router.swap_acl(Some(policy));

        // Bob should NOT receive the replayed position
        let (ptx, ntx, mut prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(bob.clone(), ptx, ntx);
        router.replay_positions(&handle).await;

        assert!(
            prx.try_recv().is_err(),
            "bob must not receive replayed position after ACL swap"
        );
    }

    #[tokio::test]
    async fn circuit_breaker_closes_both_channels() {
        let identity = make_identity("slow-client", &["alpha"]);
        // Priority channel capacity 1, normal channel capacity 16
        let (ptx, ntx, mut prx, mut nrx) = make_channels(1, 16);
        let handle = SessionHandle::with_drop_threshold(identity, ptx, ntx, 3);

        // Fill the priority channel
        let pos = Arc::new(make_position(
            &make_identity("sender", &["alpha"]),
            Destination::Broadcast,
        ));
        assert!(handle.try_send(pos.clone()));

        // Trip the breaker on priority channel (3 consecutive failures)
        assert!(!handle.try_send(pos.clone()));
        assert!(!handle.try_send(pos.clone()));
        assert!(!handle.try_send(pos.clone()));

        // Both channels should be closed
        assert!(!handle.is_alive());

        // Normal channel should also be poisoned
        let chat = Arc::new(make_chat(
            &make_identity("sender", &["alpha"]),
            Destination::Broadcast,
        ));
        assert!(!handle.try_send(chat));

        // Drain priority and verify closed
        let _ = prx.recv().await;
        assert!(prx.recv().await.is_none());

        // Normal receiver should also see closure eventually
        // (no messages were sent to normal, but sender is dropped)
        assert!(nrx.recv().await.is_none());
    }

    #[tokio::test]
    async fn store_forward_enqueue_on_disconnect_drain_on_reconnect() {
        use tempfile::TempDir;

        use crate::store_forward::ClientQueue;

        let tmp = TempDir::new().expect("tempdir");
        let queue = Arc::new(ClientQueue::open(tmp.path(), 1_000_000).expect("open queue"));
        let router = Router::new().with_client_queue(Arc::clone(&queue));

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        // Route a direct chat to bob while bob is NOT registered.
        // The message must be persisted, not dropped.
        let chat = RoutableMessage {
            source: (*alice).clone(),
            destination: Destination::Direct((*bob).clone()),
            payload: Bytes::from_static(b"hello bob"),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "test".to_string(),
                message_type: MessageType::Chat,
                ttl: None,
            },
        };
        router.route(chat).await;

        for _ in 0..200 {
            if queue.stats("bob").depth == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(queue.stats("bob").depth, 1, "message must be queued");

        // Now bob connects — drain_client_queue must deliver the
        // buffered message to his session channel.
        let (ptx_b, ntx_b, _prx_b, mut nrx_b) = make_channels(16, 16);
        let handle = SessionHandle::new(bob.clone(), ptx_b, ntx_b);
        let _ = router.register(handle.clone()).await;
        let delivered = router.drain_client_queue(&handle).await;
        assert_eq!(delivered, 1);

        let received = nrx_b.try_recv().expect("bob receives buffered chat");
        assert_eq!(received.payload.as_ref(), b"hello bob");
        assert_eq!(queue.stats("bob").depth, 0);
    }

    #[tokio::test]
    async fn store_forward_drain_before_register_preserves_order() {
        use tempfile::TempDir;

        use crate::store_forward::ClientQueue;

        let tmp = TempDir::new().expect("tempdir");
        let queue = Arc::new(ClientQueue::open(tmp.path(), 1_000_000).expect("open queue"));
        let router = Arc::new(Router::new().with_client_queue(Arc::clone(&queue)));

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        // Three offline messages queued before reconnect.
        for i in 0..3u8 {
            let payload = Bytes::copy_from_slice(&[b'o', b'0' + i]);
            router
                .route(RoutableMessage {
                    source: (*alice).clone(),
                    destination: Destination::Direct((*bob).clone()),
                    payload,
                    metadata: Metadata {
                        received_at: SystemTime::now(),
                        source_protocol: "test".to_string(),
                        message_type: MessageType::Chat,
                        ttl: None,
                    },
                })
                .await;
        }
        // Wait for the async writer task to persist them.
        for _ in 0..200 {
            if queue.stats("bob").depth == 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(queue.stats("bob").depth, 3);

        let (ptx_b, ntx_b, _prx_b, mut nrx_b) = make_channels(32, 32);
        let handle = SessionHandle::new(bob.clone(), ptx_b, ntx_b);

        // Drain BEFORE register (the fix). Then register, then flush
        // the buffered messages, then route live traffic.
        let buffered = router.drain_offline_messages("bob").await;
        assert_eq!(buffered.len(), 3);
        let _ = router.register(handle.clone()).await;
        for m in buffered {
            handle.send(Arc::new(m)).await.expect("flush offline");
        }

        // Race three live messages immediately after registration.
        for i in 0..3u8 {
            let payload = Bytes::copy_from_slice(&[b'L', b'0' + i]);
            router
                .route(RoutableMessage {
                    source: (*alice).clone(),
                    destination: Destination::Direct((*bob).clone()),
                    payload,
                    metadata: Metadata {
                        received_at: SystemTime::now(),
                        source_protocol: "test".to_string(),
                        message_type: MessageType::Chat,
                        ttl: None,
                    },
                })
                .await;
        }

        // Expect strict offline-then-live ordering.
        let mut seen: Vec<Vec<u8>> = Vec::new();
        for _ in 0..6 {
            let m = nrx_b.recv().await.expect("receive");
            seen.push(m.payload.to_vec());
        }
        assert_eq!(
            seen,
            vec![
                b"o0".to_vec(),
                b"o1".to_vec(),
                b"o2".to_vec(),
                b"L0".to_vec(),
                b"L1".to_vec(),
                b"L2".to_vec(),
            ]
        );
    }

    #[tokio::test]
    async fn store_forward_disabled_does_not_persist() {
        // Regression: when no client queue is attached, routing to an
        // offline CN must remain a silent drop (no panic, no state).
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);
        let ghost = make_identity("ghost", &["alpha"]);
        let chat = RoutableMessage {
            source: (*alice).clone(),
            destination: Destination::Direct((*ghost).clone()),
            payload: Bytes::from_static(b"into the void"),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "test".to_string(),
                message_type: MessageType::Chat,
                ttl: None,
            },
        };
        router.route(chat).await;
        assert!(router.client_queue().is_none());
    }

    fn make_cot_chat(
        source: &Arc<Identity>,
        dest: Destination,
        payload: &'static [u8],
    ) -> RoutableMessage {
        RoutableMessage {
            source: (**source).clone(),
            destination: dest,
            payload: Bytes::from_static(payload),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "cot".to_string(),
                message_type: MessageType::Chat,
                ttl: None,
            },
        }
    }

    #[tokio::test]
    async fn cross_path_dedup_suppresses_second_arrival() {
        use crate::dedup::DedupCache;

        let router = Router::new();
        router.set_dedup(Some(DedupCache::new(
            std::time::Duration::from_secs(60),
            128,
        )));

        let alice = make_identity("alice", &[]);
        let bob = make_identity("bob", &[]);
        let (ptx, ntx, _prx, mut nrx) = make_channels(16, 16);
        router
            .register(SessionHandle::new(alice.clone(), ptx, ntx))
            .await;

        let payload: &'static [u8] =
            br#"<event uid="MSG-1" time="2024-01-01T00:00:00Z" type="a-f-G"/>"#;

        // First arrival via the "direct client" path.
        router
            .route(make_cot_chat(
                &bob,
                Destination::Direct((*alice).clone()),
                payload,
            ))
            .await;
        // Second arrival of the exact same logical message via a
        // different ingress (e.g. federation) — must be suppressed.
        router
            .route(make_cot_chat(
                &bob,
                Destination::Direct((*alice).clone()),
                payload,
            ))
            .await;

        let first = nrx.recv().await;
        assert!(first.is_some(), "alice must receive the first copy");
        assert!(
            nrx.try_recv().is_err(),
            "the duplicate must not reach the subscriber"
        );

        let stats = router.dedup_stats().expect("dedup enabled");
        assert_eq!(stats.0, 1, "exactly one duplicate should be recorded");
    }

    #[tokio::test]
    async fn cross_path_dedup_distinct_payloads_pass_through() {
        use crate::dedup::DedupCache;

        let router = Router::new();
        router.set_dedup(Some(DedupCache::new(
            std::time::Duration::from_secs(60),
            128,
        )));

        let alice = make_identity("alice", &[]);
        let bob = make_identity("bob", &[]);
        let (ptx, ntx, _prx, mut nrx) = make_channels(16, 16);
        router
            .register(SessionHandle::new(alice.clone(), ptx, ntx))
            .await;

        let p1: &'static [u8] = br#"<event uid="X" time="T" type="a-f-G">one</event>"#;
        let p2: &'static [u8] = br#"<event uid="X" time="T" type="a-f-G">two</event>"#;

        router
            .route(make_cot_chat(
                &bob,
                Destination::Direct((*alice).clone()),
                p1,
            ))
            .await;
        router
            .route(make_cot_chat(
                &bob,
                Destination::Direct((*alice).clone()),
                p2,
            ))
            .await;

        assert!(nrx.recv().await.is_some());
        assert!(nrx.recv().await.is_some());
        assert_eq!(router.dedup_stats().map(|s| s.0), Some(0));
    }

    #[tokio::test]
    async fn cross_path_dedup_disabled_by_default_passes_duplicates() {
        // Regression: with `set_dedup(None)` (the default), identical
        // messages arriving twice must BOTH be delivered — dedup must
        // not suppress anything when disabled.
        let router = Router::new();
        router.set_dedup(None);

        let alice = make_identity("alice", &[]);
        let bob = make_identity("bob", &[]);
        let (ptx, ntx, _prx, mut nrx) = make_channels(16, 16);
        router
            .register(SessionHandle::new(alice.clone(), ptx, ntx))
            .await;

        let payload: &'static [u8] =
            br#"<event uid="MSG-1" time="2024-01-01T00:00:00Z" type="a-f-G"/>"#;

        router
            .route(make_cot_chat(
                &bob,
                Destination::Direct((*alice).clone()),
                payload,
            ))
            .await;
        router
            .route(make_cot_chat(
                &bob,
                Destination::Direct((*alice).clone()),
                payload,
            ))
            .await;

        assert!(nrx.recv().await.is_some(), "first copy must arrive");
        assert!(
            nrx.recv().await.is_some(),
            "second copy must also arrive when dedup is disabled"
        );
        assert!(router.dedup_stats().is_none());
    }

    // ── Access log helpers ────────────────────────────────────────────

    #[test]
    fn extract_cot_uid_finds_attribute() {
        let payload = br#"<event uid="ANDROID-1234" time="2024" type="a-f-G"/>"#;
        assert_eq!(super::extract_cot_uid(payload), "ANDROID-1234");
    }

    #[test]
    fn extract_cot_uid_returns_empty_when_missing() {
        let payload = br#"<event time="2024" type="a-f-G"/>"#;
        assert_eq!(super::extract_cot_uid(payload), "");
    }

    #[test]
    fn extract_cot_uid_returns_empty_for_binary_payload() {
        let payload: &[u8] = &[0xBF, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(super::extract_cot_uid(payload), "");
    }

    #[test]
    fn extract_cot_uid_bounds_scan_to_max_uid_scan_bytes() {
        let mut payload = vec![b' '; super::MAX_UID_SCAN_BYTES + 64];
        payload.extend_from_slice(br#"uid="LATE""#);
        assert_eq!(super::extract_cot_uid(&payload), "");
    }

    #[test]
    fn hash_cn_is_stable_and_truncated() {
        let h = super::hash_cn("alice");
        assert_eq!(h.len(), 12);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(super::hash_cn("alice"), h);
        assert_ne!(super::hash_cn("alice"), super::hash_cn("bob"));
    }

    #[test]
    fn emit_access_direct_destination_hashes_cn_and_omits_raw() {
        let raw_cn = "super-secret-operator-007";
        let target = make_identity(raw_cn, &["alpha"]);
        let destination = Destination::Direct((*target).clone());

        // Re-derive the dst formatting the same way `emit_access` does and
        // assert it neither equals nor contains the raw CN.
        let dst_field = match &destination {
            Destination::Direct(t) => format!("direct:{}", super::hash_cn(&t.cn)),
            Destination::Group(g) => format!("group:{g}"),
            Destination::Broadcast => "broadcast".to_string(),
            Destination::Multicast(groups) => format!("multicast:[{}]", groups.join(",")),
        };
        assert!(
            !dst_field.contains(raw_cn),
            "raw CN must not appear in access log dst field, got {dst_field}"
        );
        assert_eq!(
            dst_field,
            format!("direct:{}", super::hash_cn(raw_cn)),
            "dst field must be the stable hashed token"
        );
    }

    #[test]
    fn router_uses_hash_identity_for_access_log() {
        // F-94 (#802) regression — pin that the access-log destination
        // and source CN fields go through `rustgate_core::masking::hash_cn`
        // (the public helper) rather than a crate-local copy. The router
        // imports the helper at top of file as
        // `use rustgate_core::masking::hash_cn`; this test confirms the
        // shared helper produces the same 12-char hex token the router
        // formats into the access-log line.
        let raw_cn = "alice@unit.example.test";
        let direct_via_router = format!("direct:{}", super::hash_cn(raw_cn));
        let direct_via_core = format!("direct:{}", rustgate_core::masking::hash_cn(raw_cn));
        assert_eq!(
            direct_via_router, direct_via_core,
            "router's `hash_cn` import must resolve to the shared core helper"
        );
        assert!(
            !direct_via_router.contains(raw_cn),
            "access-log dst must not contain raw CN, got {direct_via_router}"
        );
        // Documented contract: 6 bytes of SHA-256 = 12 lowercase hex chars
        // after the "direct:" prefix.
        assert_eq!(
            direct_via_router.len(),
            "direct:".len() + 12,
            "access-log dst length must equal `direct:` + 12 hex, got {direct_via_router}"
        );
    }

    // ── Dynamic group join/leave ────────────────────────────────────

    #[tokio::test]
    async fn join_group_adds_session_to_group() {
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);

        let (ptx, ntx, _prx, mut nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(alice.clone(), ptx, ntx);
        let sid = handle.id;
        let _ = router.register(handle).await;

        // Alice is in "alpha" from cert. Dynamically join "bravo".
        assert!(router.join_group("alice", sid, "bravo").await);

        // Now route a message to "bravo" from a sender who is a member.
        let bob = make_identity("bob", &["bravo"]);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let msg = make_chat(&bob, Destination::Group("bravo".into()));
        router.route(msg).await;

        // Alice should receive it via the dynamic subscription.
        let received = nrx.try_recv();
        assert!(received.is_ok(), "alice should receive bravo group message");
    }

    #[tokio::test]
    async fn leave_group_removes_session_from_group() {
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);

        let (ptx, ntx, _prx, mut nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(alice.clone(), ptx, ntx);
        let sid = handle.id;
        let _ = router.register(handle).await;

        // Dynamically join then leave "bravo".
        assert!(router.join_group("alice", sid, "bravo").await);
        assert!(router.leave_group("alice", sid, "bravo").await);

        // Route to "bravo" — alice should NOT receive it.
        let bob = make_identity("bob", &["bravo"]);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 16);
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let msg = make_chat(&bob, Destination::Group("bravo".into()));
        router.route(msg).await;

        assert!(
            nrx.try_recv().is_err(),
            "alice should not receive bravo after leaving"
        );
    }

    #[tokio::test]
    async fn join_group_rejects_stale_session_id() {
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);

        let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(alice.clone(), ptx, ntx);
        let stale_id = handle.id;
        let _ = router.register(handle).await;

        // Re-register (simulates reconnect), gets a new session ID.
        let (ptx2, ntx2, _prx2, _nrx2) = make_channels(16, 16);
        let handle2 = SessionHandle::new(alice.clone(), ptx2, ntx2);
        let _ = router.register(handle2).await;

        // Old session ID should be rejected.
        assert!(!router.join_group("alice", stale_id, "bravo").await);
    }

    #[tokio::test]
    async fn join_group_respects_per_cn_limit() {
        let router = Router::with_limits(2, 100);
        let alice = make_identity("alice", &["alpha"]);

        let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(alice.clone(), ptx, ntx);
        let sid = handle.id;
        let _ = router.register(handle).await;

        // "alpha" is already joined from cert (1/2). Join "bravo" (2/2).
        assert!(router.join_group("alice", sid, "bravo").await);
        // Third group should be rejected.
        assert!(!router.join_group("alice", sid, "charlie").await);
    }

    #[tokio::test]
    async fn join_group_respects_total_group_limit() {
        let router = Router::with_limits(128, 2);
        let alice = make_identity("alice", &["alpha"]);

        let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(alice.clone(), ptx, ntx);
        let sid = handle.id;
        let _ = router.register(handle).await;

        // "alpha" exists (1/2). Add "bravo" (2/2).
        assert!(router.join_group("alice", sid, "bravo").await);
        // Third distinct group should be rejected.
        assert!(!router.join_group("alice", sid, "charlie").await);
    }

    #[tokio::test]
    async fn leave_group_returns_false_for_unknown_session() {
        let router = Router::new();
        assert!(!router.leave_group("nonexistent", 999, "alpha").await);
    }

    // ── filter_offline_messages tests ──────────────────────────────

    #[test]
    fn offline_messages_filtered_by_acl() {
        let router = Router::new();

        // ACL: only "bob" may send to "ops"; "charlie" may receive.
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "ops".to_string(),
            crate::acl::GroupAcl::new(
                HashSet::from(["bob".to_string()]),
                HashSet::from(["charlie".to_string()]),
            ),
        );
        router
            .acl
            .store(Arc::new(Some(crate::acl::GroupAclPolicy::new(groups))));

        let alice = make_identity("alice", &["ops"]);
        let charlie = make_identity("charlie", &["ops"]);
        let msg = make_alert(&alice, Destination::Group("ops".into()));

        // alice is NOT authorized to send to "ops" → message should be filtered out.
        let result = router.filter_offline_messages(&charlie, vec![msg]);
        assert!(
            result.is_empty(),
            "message from unauthorized sender should be filtered"
        );
    }

    #[test]
    fn offline_messages_filtered_by_acl_receive() {
        let router = Router::new();

        // ACL: "alice" may send to "ops"; only "bob" may receive.
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "ops".to_string(),
            crate::acl::GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["bob".to_string()]),
            ),
        );
        router
            .acl
            .store(Arc::new(Some(crate::acl::GroupAclPolicy::new(groups))));

        let alice = make_identity("alice", &["ops"]);
        let charlie = make_identity("charlie", &["ops"]);
        let msg = make_alert(&alice, Destination::Group("ops".into()));

        // "charlie" is NOT authorized to receive from "ops".
        let result = router.filter_offline_messages(&charlie, vec![msg]);
        assert!(
            result.is_empty(),
            "message to unauthorized recipient should be filtered"
        );
    }

    #[test]
    fn offline_messages_pass_when_authorized() {
        let router = Router::new();

        // ACL: "alice" authorized to send, "bob" authorized to receive.
        let mut groups = std::collections::HashMap::new();
        groups.insert(
            "ops".to_string(),
            crate::acl::GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["bob".to_string()]),
            ),
        );
        router
            .acl
            .store(Arc::new(Some(crate::acl::GroupAclPolicy::new(groups))));

        let alice = make_identity("alice", &["ops"]);
        let bob = make_identity("bob", &["ops"]);
        let msg = make_alert(&alice, Destination::Group("ops".into()));

        // Both sender and recipient are authorized → message passes through.
        let result = router.filter_offline_messages(&bob, vec![msg]);
        assert_eq!(result.len(), 1, "authorized message should pass through");
    }

    #[test]
    fn offline_messages_pass_when_no_policy() {
        let router = Router::new();

        // No ACL policy loaded — backward compatible open mode.
        let alice = make_identity("alice", &["ops"]);
        let bob = make_identity("bob", &["ops"]);
        let msg = make_alert(&alice, Destination::Group("ops".into()));

        let result = router.filter_offline_messages(&bob, vec![msg]);
        assert_eq!(
            result.len(),
            1,
            "all messages should pass when no policy is loaded"
        );
    }

    // ── authz engine filter_offline_messages tests ─────────────────

    /// Policy engine that denies all evaluations.
    struct DenyAllEngine;

    impl PolicyEngine for DenyAllEngine {
        fn evaluate(
            &self,
            _subject: &AuthzSubject<'_>,
            _resource: &AuthzResource<'_>,
            _action: AuthzAction,
        ) -> rustgate_authz::DecisionOutcome {
            rustgate_authz::DecisionOutcome::deny()
        }

        fn policy_id(&self) -> &str {
            "test-deny-all"
        }
    }

    /// Policy engine that allows sends but denies receives.
    struct DenySendFromCnEngine {
        denied_cn: String,
    }

    impl PolicyEngine for DenySendFromCnEngine {
        fn evaluate(
            &self,
            subject: &AuthzSubject<'_>,
            _resource: &AuthzResource<'_>,
            action: AuthzAction,
        ) -> rustgate_authz::DecisionOutcome {
            if action == AuthzAction::Send && subject.cn == self.denied_cn {
                return rustgate_authz::DecisionOutcome::deny();
            }
            rustgate_authz::DecisionOutcome::allow()
        }

        fn policy_id(&self) -> &str {
            "test-deny-send-cn"
        }
    }

    #[test]
    fn offline_messages_filtered_by_authz_deny_all() {
        let router = Router::new().with_authz(Arc::new(DenyAllEngine));

        let alice = make_identity("alice", &["ops"]);
        let bob = make_identity("bob", &["ops"]);
        let msg = make_alert(&alice, Destination::Group("ops".into()));

        let result = router.filter_offline_messages(&bob, vec![msg]);
        assert!(
            result.is_empty(),
            "deny-all engine should filter all offline messages"
        );
    }

    #[test]
    fn offline_messages_filtered_by_authz_sender_denied() {
        let engine = DenySendFromCnEngine {
            denied_cn: "alice".to_string(),
        };
        let router = Router::new().with_authz(Arc::new(engine));

        let alice = make_identity("alice", &["ops"]);
        let bob = make_identity("bob", &["ops"]);
        let msg = make_alert(&alice, Destination::Group("ops".into()));

        // alice is denied for Send → message should be filtered.
        let result = router.filter_offline_messages(&bob, vec![msg]);
        assert!(
            result.is_empty(),
            "message from authz-denied sender should be filtered"
        );
    }

    #[test]
    fn offline_messages_pass_authz_when_allowed() {
        let engine = DenySendFromCnEngine {
            denied_cn: "eve".to_string(),
        };
        let router = Router::new().with_authz(Arc::new(engine));

        let alice = make_identity("alice", &["ops"]);
        let bob = make_identity("bob", &["ops"]);
        let msg = make_alert(&alice, Destination::Group("ops".into()));

        // alice is NOT denied (only "eve" is) → message should pass.
        let result = router.filter_offline_messages(&bob, vec![msg]);
        assert_eq!(
            result.len(),
            1,
            "message from allowed sender should pass authz filter"
        );
    }

    #[test]
    fn offline_messages_filtered_by_authz_recipient_denied() {
        /// Engine that allows all sends but denies receive for a specific CN.
        struct DenyReceiveEngine {
            denied_cn: String,
        }

        impl PolicyEngine for DenyReceiveEngine {
            fn evaluate(
                &self,
                subject: &AuthzSubject<'_>,
                _resource: &AuthzResource<'_>,
                action: AuthzAction,
            ) -> rustgate_authz::DecisionOutcome {
                if action == AuthzAction::Receive && subject.cn == self.denied_cn {
                    return rustgate_authz::DecisionOutcome::deny();
                }
                rustgate_authz::DecisionOutcome::allow()
            }

            fn policy_id(&self) -> &str {
                "test-deny-receive-cn"
            }
        }

        let engine = DenyReceiveEngine {
            denied_cn: "bob".to_string(),
        };
        let router = Router::new().with_authz(Arc::new(engine));

        let alice = make_identity("alice", &["ops"]);
        let bob = make_identity("bob", &["ops"]);
        let msg = make_alert(&alice, Destination::Group("ops".into()));

        // bob is denied for Receive → message should be filtered.
        let result = router.filter_offline_messages(&bob, vec![msg]);
        assert!(
            result.is_empty(),
            "message to authz-denied recipient should be filtered"
        );
    }

    // ── Destination::Direct offline message tests ──────────────────

    /// Policy engine that allows all evaluations.
    struct AllowAllEngine;

    impl PolicyEngine for AllowAllEngine {
        fn evaluate(
            &self,
            _subject: &AuthzSubject<'_>,
            _resource: &AuthzResource<'_>,
            _action: AuthzAction,
        ) -> rustgate_authz::DecisionOutcome {
            rustgate_authz::DecisionOutcome::allow()
        }

        fn policy_id(&self) -> &str {
            "test-allow-all"
        }
    }

    #[test]
    fn offline_direct_messages_pass_when_authz_allows() {
        let router = Router::new().with_authz(Arc::new(AllowAllEngine));

        let alice = make_identity("alice", &["ops"]);
        let bob = make_identity("bob", &["ops"]);
        let msg = make_alert(&alice, Destination::Direct((*bob).clone()));

        let result = router.filter_offline_messages(&bob, vec![msg]);
        assert_eq!(
            result.len(),
            1,
            "direct message should pass when authz allows"
        );
    }

    #[test]
    fn offline_direct_messages_blocked_when_authz_denies() {
        let router = Router::new().with_authz(Arc::new(DenyAllEngine));

        let alice = make_identity("alice", &["ops"]);
        let bob = make_identity("bob", &["ops"]);
        let msg = make_alert(&alice, Destination::Direct((*bob).clone()));

        let result = router.filter_offline_messages(&bob, vec![msg]);
        assert!(
            result.is_empty(),
            "direct message should be blocked when authz denies"
        );
    }

    // ── Destination::Broadcast offline message tests ───────────────

    #[test]
    fn offline_broadcast_messages_pass_when_authz_allows() {
        let router = Router::new().with_authz(Arc::new(AllowAllEngine));

        let alice = make_identity("alice", &["ops"]);
        let bob = make_identity("bob", &["ops"]);
        let msg = make_alert(&alice, Destination::Broadcast);

        let result = router.filter_offline_messages(&bob, vec![msg]);
        assert_eq!(
            result.len(),
            1,
            "broadcast message should pass when authz allows"
        );
    }

    #[test]
    fn offline_broadcast_messages_blocked_when_authz_denies() {
        let router = Router::new().with_authz(Arc::new(DenyAllEngine));

        let alice = make_identity("alice", &["ops"]);
        let bob = make_identity("bob", &["ops"]);
        let msg = make_alert(&alice, Destination::Broadcast);

        let result = router.filter_offline_messages(&bob, vec![msg]);
        assert!(
            result.is_empty(),
            "broadcast message should be blocked when authz denies"
        );
    }

    #[tokio::test]
    async fn slow_session_does_not_block_other_groups() {
        // Verify that a session with a full channel does not block
        // message delivery to sessions in other groups.
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["bravo"]);
        let sender_alpha = make_identity("sender-alpha", &["alpha"]);
        let sender_bravo = make_identity("sender-bravo", &["bravo"]);

        // Alice gets a capacity-1 normal channel (will be full after 1 msg)
        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 1);
        // Bob gets a normal channel
        let (ptx_b, ntx_b, _prx_b, mut nrx_b) = make_channels(16, 16);
        let (ptx_sa, ntx_sa, _prx_sa, _nrx_sa) = make_channels(16, 16);
        let (ptx_sb, ntx_sb, _prx_sb, _nrx_sb) = make_channels(16, 16);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;
        router
            .register(SessionHandle::new(sender_alpha.clone(), ptx_sa, ntx_sa))
            .await;
        router
            .register(SessionHandle::new(sender_bravo.clone(), ptx_sb, ntx_sb))
            .await;

        // Fill alice's normal channel
        let fill_msg = make_chat(&sender_alpha, Destination::Group("alpha".into()));
        router.route(fill_msg).await;

        // Now send more messages to alice's full group — these should
        // be dropped/persisted, NOT block the routing task.
        for _ in 0..5 {
            let msg = make_chat(&sender_alpha, Destination::Group("alpha".into()));
            router.route(msg).await;
        }

        // Send a message to bob in bravo — must arrive immediately
        let msg = make_chat(&sender_bravo, Destination::Group("bravo".into()));
        router.route(msg).await;

        let received = nrx_b
            .try_recv()
            .expect("bob must receive: slow alice must not block bravo group");
        assert_eq!(received.payload.as_ref(), b"<chat/>");
    }

    #[tokio::test]
    async fn direct_message_persisted_when_channel_full() {
        // When a direct message target's channel is full, the message
        // should be persisted to the store-forward queue rather than
        // blocking.
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue = Arc::new(
            crate::store_forward::ClientQueue::open(tmp.path(), 10 * 1024 * 1024)
                .expect("client queue"),
        );
        let router = Router::new().with_client_queue(queue.clone());

        let target = make_identity("target", &["alpha"]);
        let sender = make_identity("sender", &["alpha"]);

        // Capacity-1 normal channel for target
        let (ptx, ntx, _prx, _nrx) = make_channels(16, 1);
        let (ptx_s, ntx_s, _prx_s, _nrx_s) = make_channels(16, 16);
        router
            .register(SessionHandle::new(target.clone(), ptx, ntx))
            .await;
        router
            .register(SessionHandle::new(sender.clone(), ptx_s, ntx_s))
            .await;

        // Fill the target's normal channel
        let fill_msg = make_chat(&sender, Destination::Direct((*target).clone()));
        router.route(fill_msg).await;

        // Send another direct message — channel is full, should be
        // persisted to store-forward rather than blocking.
        let msg = make_chat(&sender, Destination::Direct((*target).clone()));
        router.route(msg).await;

        // Wait for the background writer to flush the message to the
        // database. The enqueue call above puts the message into an
        // async writer channel; we need to poll until it is persisted.
        for _ in 0..200 {
            if queue.stats("target").depth > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Verify message was persisted to the offline queue
        let queued = queue.drain("target").expect("drain");
        assert!(
            !queued.is_empty(),
            "message must be persisted for offline delivery when channel is full"
        );
    }

    #[tokio::test]
    async fn broadcast_drops_slow_session() {
        // When broadcasting, a session with a full channel should have
        // its message dropped, while fast sessions receive the message.
        let router = Router::new();

        let sender = make_identity("sender", &["alpha"]);
        let fast = make_identity("fast", &["alpha"]);
        let slow = make_identity("slow", &["alpha"]);

        let (ptx_sender, ntx_sender, _prx_sender, _nrx_sender) = make_channels(16, 16);
        let (ptx_fast, ntx_fast, _prx_fast, mut nrx_fast) = make_channels(16, 16);
        // Slow session has capacity-1 normal channel
        let (ptx_slow, ntx_slow, _prx_slow, mut nrx_slow) = make_channels(16, 1);

        router
            .register(SessionHandle::new(sender.clone(), ptx_sender, ntx_sender))
            .await;
        router
            .register(SessionHandle::new(fast.clone(), ptx_fast, ntx_fast))
            .await;
        router
            .register(SessionHandle::new(slow.clone(), ptx_slow, ntx_slow))
            .await;

        // Fill the slow session's normal channel
        let fill_msg = make_chat(&sender, Destination::Broadcast);
        router.route(fill_msg).await;

        // Broadcast again — slow session channel is full
        let msg = make_chat(&sender, Destination::Broadcast);
        router.route(msg).await;

        // Fast session should receive both broadcasts
        let r1 = nrx_fast
            .try_recv()
            .expect("fast must receive first broadcast");
        assert_eq!(r1.payload.as_ref(), b"<chat/>");
        let r2 = nrx_fast
            .try_recv()
            .expect("fast must receive second broadcast");
        assert_eq!(r2.payload.as_ref(), b"<chat/>");

        // Slow session should have received only the first message
        let r1 = nrx_slow
            .try_recv()
            .expect("slow must receive first broadcast");
        assert_eq!(r1.payload.as_ref(), b"<chat/>");
        // Second message should have been dropped
        assert!(
            nrx_slow.try_recv().is_err(),
            "slow session's second broadcast must be dropped (channel full)"
        );
    }

    #[tokio::test]
    async fn direct_message_dropped_without_store_forward() {
        // When no ClientQueue is configured, a direct message to a
        // session with a full channel must be silently dropped (not
        // persisted and not panic).
        let router = Router::new();

        let sender = make_identity("sender", &["alpha"]);
        let target = make_identity("target", &["alpha"]);

        let (ptx_s, ntx_s, _prx_s, _nrx_s) = make_channels(16, 16);
        // Capacity-1 normal channel so it fills after one chat message.
        let (ptx_t, ntx_t, _prx_t, mut nrx_t) = make_channels(16, 1);

        router
            .register(SessionHandle::new(sender.clone(), ptx_s, ntx_s))
            .await;
        router
            .register(SessionHandle::new(target.clone(), ptx_t, ntx_t))
            .await;

        // Fill the target's normal channel with the first direct message.
        let fill = make_chat(&sender, Destination::Direct((*target).clone()));
        router.route(fill).await;

        // Second direct message — channel full, no queue configured.
        // Must not panic; the message is lost.
        let overflow = make_chat(&sender, Destination::Direct((*target).clone()));
        router.route(overflow).await;

        // Only the first message should be in the channel.
        let received = nrx_t
            .try_recv()
            .expect("target must receive the first message");
        assert_eq!(received.payload.as_ref(), b"<chat/>");
        assert!(
            nrx_t.try_recv().is_err(),
            "overflow message must be dropped: no store-forward queue"
        );
        assert!(
            router.client_queue().is_none(),
            "no client queue should be attached"
        );
    }

    #[tokio::test]
    async fn broadcast_not_persisted_to_offline_queue() {
        // Broadcasts to a session with a full channel must be dropped,
        // NOT persisted to the store-forward queue.
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue = Arc::new(
            crate::store_forward::ClientQueue::open(tmp.path(), 10 * 1024 * 1024)
                .expect("client queue"),
        );
        let router = Router::new().with_client_queue(queue.clone());

        let sender = make_identity("sender", &["alpha"]);
        let slow = make_identity("slow", &["alpha"]);

        let (ptx_s, ntx_s, _prx_s, _nrx_s) = make_channels(16, 16);
        // Capacity-1 normal channel so it fills after one chat message.
        let (ptx_slow, ntx_slow, _prx_slow, mut nrx_slow) = make_channels(16, 1);

        router
            .register(SessionHandle::new(sender.clone(), ptx_s, ntx_s))
            .await;
        router
            .register(SessionHandle::new(slow.clone(), ptx_slow, ntx_slow))
            .await;

        // Fill the slow session's normal channel.
        let fill = make_chat(&sender, Destination::Broadcast);
        router.route(fill).await;

        // Broadcast again — slow session's channel is full.
        let overflow = make_chat(&sender, Destination::Broadcast);
        router.route(overflow).await;

        // Allow the background writer time to flush, if anything was
        // enqueued (it should not have been).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // The queue must be empty for the slow CN: broadcasts are
        // dropped, not persisted.
        assert_eq!(
            queue.stats("slow").depth,
            0,
            "broadcast to full channel must NOT be persisted to store-forward queue"
        );

        // Slow session received only the first broadcast.
        let received = nrx_slow
            .try_recv()
            .expect("slow must receive the first broadcast");
        assert_eq!(received.payload.as_ref(), b"<chat/>");
        assert!(
            nrx_slow.try_recv().is_err(),
            "second broadcast must be dropped for slow session"
        );
    }

    // ── SessionHandle::is_closed tests ─────────────────────────────

    #[test]
    fn is_closed_returns_false_when_receivers_alive() {
        let alice = make_identity("alice", &["ops"]);
        let (ptx, ntx, _prx, _nrx) = make_channels(4, 4);
        let handle = SessionHandle::new(alice, ptx, ntx);

        // Receivers still alive — session is open.
        assert!(
            !handle.is_closed(),
            "is_closed must return false while receivers are alive"
        );
    }

    #[test]
    fn is_closed_returns_true_when_receivers_dropped() {
        let alice = make_identity("alice", &["ops"]);
        let (ptx, ntx, prx, nrx) = make_channels(4, 4);
        let handle = SessionHandle::new(alice, ptx, ntx);

        // Drop both receivers — simulates session write loop exiting.
        drop(prx);
        drop(nrx);

        assert!(
            handle.is_closed(),
            "is_closed must return true after all receivers are dropped"
        );
    }

    #[test]
    fn is_closed_returns_true_when_senders_set_to_none() {
        let alice = make_identity("alice", &["ops"]);
        let (ptx, ntx, _prx, _nrx) = make_channels(4, 4);
        // Threshold of 1: a single failed send trips the circuit breaker.
        let handle = SessionHandle::with_drop_threshold(alice.clone(), ptx, ntx, 1);

        // Use a capacity-1 channel so the second try_send fails and trips the breaker.
        let (ptx2, ntx2, _prx2, _nrx2) = make_channels(1, 1);
        let handle2 = SessionHandle::with_drop_threshold(alice, ptx2, ntx2, 1);

        // Fill the channels (chat goes to normal channel).
        let msg = Arc::new(make_chat(
            &make_identity("sender", &[]),
            Destination::Broadcast,
        ));
        let routed = RoutedMessage::new(Arc::clone(&msg));
        handle2.try_send(routed);

        // This send should trip the circuit breaker (consecutive_drops >= 1).
        let routed2 = RoutedMessage::new(Arc::clone(&msg));
        handle2.try_send(routed2);

        assert!(
            handle2.is_closed(),
            "is_closed must return true after circuit breaker sets senders to None"
        );

        // Also verify the original handle (senders not tripped) is still open.
        assert!(!handle.is_closed(), "original handle should still be open");
    }

    // ── Multicast routing tests ────────────────────────────────────

    #[tokio::test]
    async fn multicast_delivers_to_multiple_groups() {
        let router = Router::new();
        let alice = make_identity("alice", &["alpha", "bravo"]);
        let bob = make_identity("bob", &["alpha"]);
        let charlie = make_identity("charlie", &["bravo"]);

        let (_ptx_a, _ntx_a, _prx_a, _nrx_a) = make_channels(16, 64);
        let (ptx_b, ntx_b, mut prx_b, _nrx_b) = make_channels(16, 64);
        let (ptx_c, ntx_c, mut prx_c, _nrx_c) = make_channels(16, 64);

        router
            .register(SessionHandle::new(alice.clone(), _ptx_a, _ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;
        router
            .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
            .await;

        let msg = make_position(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        );
        router.route(msg).await;

        // Bob is in alpha, should receive
        let received_b = prx_b.try_recv();
        assert!(received_b.is_ok(), "bob should receive via alpha group");

        // Charlie is in bravo, should receive
        let received_c = prx_c.try_recv();
        assert!(received_c.is_ok(), "charlie should receive via bravo group");
    }

    #[tokio::test]
    async fn multicast_empty_group_list_is_noop() {
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 64);
        let (ptx_b, ntx_b, mut prx_b, _nrx_b) = make_channels(16, 64);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let msg = make_position(&alice, Destination::Multicast(vec![]));
        router.route(msg).await;

        // Nobody should receive anything
        assert!(
            prx_b.try_recv().is_err(),
            "empty multicast should not deliver to anyone"
        );
    }

    #[tokio::test]
    async fn multicast_no_duplicate_delivery_for_overlapping_groups() {
        let router = Router::new();
        // dave is in both alpha and bravo — must receive exactly once
        let alice = make_identity("alice", &["alpha", "bravo"]);
        let dave = make_identity("dave", &["alpha", "bravo"]);

        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 64);
        let (ptx_d, ntx_d, mut prx_d, _nrx_d) = make_channels(16, 64);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(dave.clone(), ptx_d, ntx_d))
            .await;

        let msg = make_position(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        );
        router.route(msg).await;

        // dave should receive exactly once
        let first = prx_d.try_recv();
        assert!(first.is_ok(), "dave should receive one message");

        let second = prx_d.try_recv();
        assert!(
            second.is_err(),
            "dave must NOT receive a duplicate from overlapping groups"
        );
    }

    #[tokio::test]
    async fn multicast_exceeding_group_limit_is_dropped() {
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);

        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 64);
        let (ptx_b, ntx_b, mut prx_b, _nrx_b) = make_channels(16, 64);

        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let many_groups: Vec<Arc<str>> = (0..MAX_MULTICAST_GROUPS + 1)
            .map(|i| Arc::<str>::from(format!("group-{i}")))
            .collect();
        let msg = make_position(&alice, Destination::Multicast(many_groups));
        router.route(msg).await;

        // Message should be dropped, bob should not receive
        assert!(
            prx_b.try_recv().is_err(),
            "message exceeding MAX_MULTICAST_GROUPS should be dropped"
        );
    }

    #[tokio::test]
    async fn multicast_config_builder() {
        let router = Router::new().with_multicast_config(MulticastConfig {
            sa_auto_multicast: true,
        });
        let guard = router.multicast_config.load();
        let config = guard.as_ref().as_ref().expect("config should be set");
        assert!(config.sa_auto_multicast);
    }

    #[tokio::test]
    async fn multicast_oversize_packet_invokes_dropped_callback() {
        // Closes #741. Drop-callback is the integration point for the
        // `rustgate_multicast_oversize_dropped_total` Prometheus
        // counter; it MUST fire exactly once per dropped multicast
        // message that exceeds `MAX_MULTICAST_GROUPS`. The "17 MiB
        // packet" framing in the issue is shorthand — the actual
        // oversize-drop site enforces the destination group cap, not
        // a payload-byte cap, because UDP datagrams are bounded at
        // 64 KiB long before they could approach 17 MiB.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);

        let drop_count = Arc::new(AtomicUsize::new(0));
        let drop_count_cb = Arc::clone(&drop_count);
        router.set_on_multicast_oversize_dropped(Some(Arc::new(move || {
            let _ = drop_count_cb.fetch_add(1, Ordering::Relaxed);
        })));

        let (ptx, ntx, _prx, _nrx) = make_channels(16, 64);
        router
            .register(SessionHandle::new(alice.clone(), ptx, ntx))
            .await;

        let many_groups: Vec<Arc<str>> = (0..MAX_MULTICAST_GROUPS + 1)
            .map(|i| Arc::<str>::from(format!("group-{i}")))
            .collect();
        let msg = make_position(&alice, Destination::Multicast(many_groups));
        router.route(msg).await;

        assert_eq!(
            drop_count.load(Ordering::Relaxed),
            1,
            "oversize multicast must invoke the dropped callback exactly once"
        );

        // A second oversize multicast must increment again; the
        // callback is per-drop, not edge-triggered.
        let many_groups: Vec<Arc<str>> = (0..MAX_MULTICAST_GROUPS + 1)
            .map(|i| Arc::<str>::from(format!("group-{i}")))
            .collect();
        let msg = make_position(&alice, Destination::Multicast(many_groups));
        router.route(msg).await;
        assert_eq!(
            drop_count.load(Ordering::Relaxed),
            2,
            "each oversize multicast must invoke the dropped callback once",
        );
    }

    #[tokio::test]
    async fn multicast_within_limit_does_not_invoke_dropped_callback() {
        // Confirm the callback is silent on the success path —
        // anything else would inflate the dashboard with false
        // positives the moment a healthy multicast was routed.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let router = Router::new();
        let alice = make_identity("alice", &["alpha", "bravo"]);

        let drop_count = Arc::new(AtomicUsize::new(0));
        let drop_count_cb = Arc::clone(&drop_count);
        router.set_on_multicast_oversize_dropped(Some(Arc::new(move || {
            let _ = drop_count_cb.fetch_add(1, Ordering::Relaxed);
        })));

        let (ptx, ntx, _prx, _nrx) = make_channels(16, 64);
        router
            .register(SessionHandle::new(alice.clone(), ptx, ntx))
            .await;

        let msg = make_position(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        );
        router.route(msg).await;
        assert_eq!(
            drop_count.load(Ordering::Relaxed),
            0,
            "successful multicast must not invoke the dropped callback",
        );
    }

    /// Closes #746. Pin the deny-first / most-restrictive fold the new
    /// `prepare_egress_envelope` helper applies for a `Multicast`
    /// envelope: three groups, each carrying a different obligation —
    /// the rendered envelope's `applied_obligations` is the union of
    /// every allow-side group's obligations, and a single deny on any
    /// addressed group vetoes the entire envelope.
    #[tokio::test]
    async fn prepare_egress_envelope_for_multicast_uses_most_restrictive_obligations() {
        use rustgate_authz::{
            Action as AuthzAction, Decision as AuthzDecision, DecisionOutcome, Obligation,
            PolicyEngine, Resource as AuthzResource, Subject as AuthzSubject,
        };

        use crate::egress::{EgressContext, EgressError, RecipientClass, prepare_egress_envelope};

        // Per-group decision table: `alpha` allows with MaskPoint,
        // `bravo` allows with TagClassified, `charlie` allows with
        // MaskPayload. The union must contain all three.
        #[derive(Debug)]
        struct PerGroup;
        impl PolicyEngine for PerGroup {
            fn evaluate(
                &self,
                _subject: &AuthzSubject<'_>,
                resource: &AuthzResource<'_>,
                _action: AuthzAction,
            ) -> DecisionOutcome {
                let group = match resource {
                    AuthzResource::Group { group } => *group,
                    _ => "",
                };
                let obligations = match group {
                    "alpha" => vec![Obligation::MaskPoint],
                    "bravo" => vec![Obligation::TagClassified],
                    "charlie" => vec![Obligation::MaskPayload],
                    _ => Vec::new(),
                };
                DecisionOutcome {
                    decision: AuthzDecision::Allow,
                    rule_id: None,
                    obligations,
                }
            }
            fn policy_id(&self) -> &str {
                "test-746-pergroup"
            }
        }

        let alice = make_identity("alice", &["alpha", "bravo", "charlie"]);
        let router = Router::new().with_authz(Arc::new(PerGroup));

        let msg = make_position(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into(), "charlie".into()]),
        );
        let arc_msg = Arc::new(msg);

        let class =
            RecipientClass::Multicast(vec!["alpha".into(), "bravo".into(), "charlie".into()]);
        let authz_guard = router.authz.load();
        let engine_ref = (**authz_guard).as_ref();
        let ctx = EgressContext {
            engine: engine_ref,
            unknown_policy: router.unknown_obligation_policy,
            rate_limiter: &router.obligation_rate_limiter,
        };
        let envelope = prepare_egress_envelope(Arc::clone(&arc_msg), class, &ctx, &router)
            .expect("union path must succeed");

        // Every per-group obligation must surface in the union.
        let kinds: BTreeSet<&'static str> = envelope
            .applied_obligations
            .iter()
            .map(obligation_kind_label)
            .collect();
        assert!(
            kinds.contains("mask_point"),
            "MaskPoint must be in the union, got {kinds:?}"
        );
        assert!(
            kinds.contains("tag_classified"),
            "TagClassified must be in the union, got {kinds:?}"
        );
        assert!(
            kinds.contains("mask_payload"),
            "MaskPayload must be in the union, got {kinds:?}"
        );

        // Sanity: the rendered message is not the input arc — at least
        // one payload-mutating obligation was applied, so the helper
        // produced a fresh `Arc<RoutableMessage>`. (Pointer-identity
        // check; the `Arc` allocation differs even if the bytes round
        // back to the same value.)
        assert!(
            !Arc::ptr_eq(&arc_msg, &envelope.message),
            "rendered envelope must be a fresh allocation when payload-mutating obligations apply"
        );

        // Deny-first arm: a per-group deny on `bravo` vetoes the
        // entire envelope, regardless of how many other groups would
        // have allowed.
        #[derive(Debug)]
        struct DenyOnBravo;
        impl PolicyEngine for DenyOnBravo {
            fn evaluate(
                &self,
                _subject: &AuthzSubject<'_>,
                resource: &AuthzResource<'_>,
                _action: AuthzAction,
            ) -> DecisionOutcome {
                let group = match resource {
                    AuthzResource::Group { group } => *group,
                    _ => "",
                };
                if group == "bravo" {
                    DecisionOutcome {
                        decision: AuthzDecision::Deny,
                        rule_id: None,
                        obligations: Vec::new(),
                    }
                } else {
                    DecisionOutcome {
                        decision: AuthzDecision::Allow,
                        rule_id: None,
                        obligations: vec![Obligation::MaskPoint],
                    }
                }
            }
            fn policy_id(&self) -> &str {
                "test-746-deny-bravo"
            }
        }

        let router = Router::new().with_authz(Arc::new(DenyOnBravo));
        let class =
            RecipientClass::Multicast(vec!["alpha".into(), "bravo".into(), "charlie".into()]);
        let authz_guard = router.authz.load();
        let engine_ref = (**authz_guard).as_ref();
        let ctx = EgressContext {
            engine: engine_ref,
            unknown_policy: router.unknown_obligation_policy,
            rate_limiter: &router.obligation_rate_limiter,
        };
        let err = prepare_egress_envelope(Arc::clone(&arc_msg), class, &ctx, &router)
            .expect_err("any per-group deny must veto the envelope");
        assert!(
            matches!(err, EgressError::Denied { .. }),
            "deny-first arm must produce EgressError::Denied, got {err:?}"
        );
    }

    // ── Router/PEP/obligation callback tests (issue #768) ──────────

    #[tokio::test]
    async fn fanout_callback_fires_with_destination_and_subscriber_count() {
        // Closes #768. The fanout callback is the integration point
        // for the `rustgate_router_fanout_total{destination}` counter
        // and the `rustgate_router_fanout_subscribers` histogram. Pin
        // both: the destination label is the small fixed-vocabulary
        // string the metric layer rounds-trips into Prometheus
        // labels, and the subscriber count is the actual delivered
        // recipient count (post-PEP, post-ACL, post-obligation).
        use std::sync::atomic::{AtomicU64, Ordering};
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        let observed_dst = Arc::new(parking_lot::Mutex::new(String::new()));
        let observed_count = Arc::new(AtomicU64::new(u64::MAX));
        let dst_clone = Arc::clone(&observed_dst);
        let count_clone = Arc::clone(&observed_count);
        router.set_on_fanout(Some(Arc::new(move |dst: &str, count: u64| {
            *dst_clone.lock() = dst.to_string();
            count_clone.store(count, Ordering::Relaxed);
        })));
        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 64);
        let (ptx_b, ntx_b, mut prx_b, _nrx_b) = make_channels(16, 64);
        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let msg = make_position(&alice, Destination::Group("alpha".into()));
        router.route(msg).await;

        assert_eq!(*observed_dst.lock(), "group");
        assert_eq!(observed_count.load(Ordering::Relaxed), 1);
        // Bob actually received the message — proves the histogram
        // count matches the wire-level delivery.
        let _ = prx_b.try_recv().expect("bob receives the group send");
    }

    #[tokio::test]
    async fn dropped_callback_fires_with_no_subscribers_for_unknown_direct_target() {
        // Closes #768. A direct send to a CN that never registered
        // is the canonical "no_subscribers" case — the message is
        // persisted to store-forward (or discarded if no queue).
        // The metric label MUST be `no_subscribers` so dashboards
        // distinguish it from `backpressure` (live channel rejected).
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);
        let dropped = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
        let cb_dropped = Arc::clone(&dropped);
        router.set_on_dropped(Some(Arc::new(move |reason: &str| {
            cb_dropped.lock().push(reason.to_string());
        })));
        let (ptx, ntx, _prx, _nrx) = make_channels(16, 64);
        router
            .register(SessionHandle::new(alice.clone(), ptx, ntx))
            .await;

        let ghost = make_identity("ghost-cn", &[]);
        let msg = make_position(&alice, Destination::Direct((*ghost).clone()));
        router.route(msg).await;

        let reasons = dropped.lock().clone();
        assert!(
            reasons.iter().any(|r| r == "no_subscribers"),
            "expected no_subscribers reason; got {reasons:?}"
        );
    }

    #[tokio::test]
    async fn pep_decision_callback_fires_with_send_direction_on_route() {
        // Closes #768. The Send-PEP fires once per `route_inner` for
        // direct/group/broadcast destinations when an authz engine
        // is installed. Without an engine the callback is silent —
        // there is no decision to report. We use the always-allow
        // engine so the call site is exercised but the message
        // continues to fan-out, mirroring the production hot path.
        use std::sync::atomic::{AtomicUsize, Ordering};

        use rustgate_authz::{
            Action as AuthzAction, Decision as AuthzDecision, DecisionOutcome, PolicyEngine,
            Resource as AuthzResource, Subject as AuthzSubject,
        };

        #[derive(Debug)]
        struct AlwaysAllow;
        impl PolicyEngine for AlwaysAllow {
            fn evaluate(
                &self,
                _subject: &AuthzSubject<'_>,
                _resource: &AuthzResource<'_>,
                _action: AuthzAction,
            ) -> DecisionOutcome {
                DecisionOutcome {
                    decision: AuthzDecision::Allow,
                    rule_id: None,
                    obligations: Vec::new(),
                }
            }
            fn policy_id(&self) -> &str {
                "test-always-allow"
            }
        }

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        let router = Router::new().with_authz(Arc::new(AlwaysAllow));
        let send_count = Arc::new(AtomicUsize::new(0));
        let recv_count = Arc::new(AtomicUsize::new(0));
        let send_clone = Arc::clone(&send_count);
        let recv_clone = Arc::clone(&recv_count);
        router.set_on_pep_decision(Some(Arc::new(
            move |direction: &str, decision: &str, eval_secs: f64| {
                // The bridge converts AuthzDecision::Allow into the
                // documented "allow" label. Pin that contract here so
                // a regression that drifted the casing or vocabulary
                // is caught by this test.
                assert_eq!(decision, "allow");
                assert!(eval_secs >= 0.0);
                match direction {
                    "send" => {
                        let _ = send_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    "receive" => {
                        let _ = recv_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            },
        )));
        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 64);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 64);
        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let msg = make_position(&alice, Destination::Group("alpha".into()));
        router.route(msg).await;

        // For a Group destination route_inner runs Send-PEP exactly
        // once at the top level. The Receive PEP then runs inside
        // send_to_group for every eligible recipient (just bob here).
        assert!(
            send_count.load(Ordering::Relaxed) >= 1,
            "Send-PEP must have been observed at least once"
        );
        assert!(
            recv_count.load(Ordering::Relaxed) >= 1,
            "Receive-PEP must have been observed at least once"
        );
    }

    #[tokio::test]
    async fn obligation_applied_callback_fires_with_kind_label() {
        // Closes #768. Verify the obligation_applied callback fires
        // with the documented label vocabulary when the engine
        // returns a known data-plane obligation. Use TagClassified
        // so the test does not depend on the rustgate-cot mask
        // implementation — the callback fires regardless of whether
        // the obligation is audit- or data-plane-shaped.
        use rustgate_authz::{
            Action as AuthzAction, Decision as AuthzDecision, DecisionOutcome, Obligation,
            PolicyEngine, Resource as AuthzResource, Subject as AuthzSubject,
        };

        #[derive(Debug)]
        struct AllowWithTag;
        impl PolicyEngine for AllowWithTag {
            fn evaluate(
                &self,
                _subject: &AuthzSubject<'_>,
                _resource: &AuthzResource<'_>,
                _action: AuthzAction,
            ) -> DecisionOutcome {
                DecisionOutcome {
                    decision: AuthzDecision::Allow,
                    rule_id: None,
                    obligations: vec![Obligation::TagClassified],
                }
            }
            fn policy_id(&self) -> &str {
                "test-tag-classified"
            }
        }

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        let router = Router::new().with_authz(Arc::new(AllowWithTag));
        let kinds = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
        let cb_kinds = Arc::clone(&kinds);
        router.set_on_obligation_applied(Some(Arc::new(move |kind: &str| {
            cb_kinds.lock().push(kind.to_string());
        })));
        let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16, 64);
        let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16, 64);
        router
            .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
            .await;
        router
            .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
            .await;

        let msg = make_position(&alice, Destination::Group("alpha".into()));
        router.route(msg).await;

        let observed = kinds.lock().clone();
        assert!(
            observed.iter().any(|k| k == "tag_classified"),
            "expected tag_classified kind label; got {observed:?}"
        );
    }

    #[test]
    fn obligation_kind_label_maps_known_variants() {
        // Closes #768. The label vocabulary is load-bearing for
        // bounded Prometheus cardinality. Pin the exact mapping so a
        // future Obligation::Foo variant cannot silently drift onto
        // the "unknown" bucket without a deliberate transport
        // change.
        use rustgate_authz::Obligation;
        assert_eq!(obligation_kind_label(&Obligation::MaskPoint), "mask_point");
        assert_eq!(
            obligation_kind_label(&Obligation::MaskPayload),
            "mask_payload"
        );
        assert_eq!(
            obligation_kind_label(&Obligation::TagClassified),
            "tag_classified"
        );
        assert_eq!(
            obligation_kind_label(&Obligation::AuditExtended),
            "audit_extended"
        );
    }

    #[tokio::test]
    async fn router_fanout_does_not_allocate_per_recipient_cn() {
        // Closes #784. The high-fanout group send must NOT clone the
        // sender's `cn` String once per recipient. With `Arc<str>`
        // the per-recipient envelope path is a refcount bump on the
        // single underlying allocation; a regression that switched
        // `Identity.cn` back to `String` would silently allocate
        // O(N) heap copies on a 1000-subscriber broadcast.
        //
        // Pin the contract via `Arc::strong_count`: register the
        // sender, take a strong-count baseline, route ONE group
        // message to N subscribers, and observe that the strong
        // count does NOT spike by N. The Arc the test holds is the
        // sender's identity Arc, not the per-message envelope —
        // route_inner clones the source `Identity` once into the
        // RoutableMessage and into the post-PEP Arc<RoutableMessage>,
        // so a fixed small bump is expected; what we trap is the
        // O(N) regression. Keep the assertion bound generous so it
        // is not brittle to harmless internal-clone count changes —
        // the load-bearing claim is "per-recipient cost is sub-linear",
        // not "exact clone count is K".
        const SUBSCRIBERS: usize = 50;
        let router = Router::new();
        let sender = make_identity("fanout-sender", &["fanout-grp"]);

        // Pre-flight strong count on the sender's cn Arc — captured
        // before any router state mutation so the baseline is the
        // owning Identity only.
        let baseline = Arc::strong_count(&sender.cn);
        assert!(
            baseline >= 1,
            "sender.cn Arc must have at least one owner before registration"
        );

        // Register sender + N subscribers, all in `fanout-grp`.
        let (ptx_s, ntx_s, _prx_s, _nrx_s) = make_channels(16, 64);
        router
            .register(SessionHandle::new(Arc::clone(&sender), ptx_s, ntx_s))
            .await;
        let mut sub_rxs = Vec::with_capacity(SUBSCRIBERS);
        for i in 0..SUBSCRIBERS {
            let cn = format!("fanout-sub-{i}");
            let id = make_identity(&cn, &["fanout-grp"]);
            let (ptx, ntx, _prx, nrx) = make_channels(16, 64);
            router.register(SessionHandle::new(id, ptx, ntx)).await;
            sub_rxs.push(nrx);
        }

        // Route one group message; every subscriber should receive it.
        let msg = make_chat(&sender, Destination::Group("fanout-grp".into()));
        router.route(msg).await;

        // Drain so per-session channels are not pinned by buffered
        // envelopes when we read the strong count below.
        for nrx in &mut sub_rxs {
            let _ = nrx.try_recv().expect("subscriber must receive");
        }

        // Final strong count vs. baseline. The router holds the
        // sender's Identity Arc once (registration), the position
        // cache may pin one more, and the in-flight RoutedMessage
        // Arc<RoutableMessage> has been dropped now that recipients
        // have received. The load-bearing assertion: strong count
        // did NOT increase by `SUBSCRIBERS` — that would mean every
        // recipient produced a fresh owner of the cn allocation.
        let after = Arc::strong_count(&sender.cn);
        assert!(
            after < baseline + SUBSCRIBERS,
            "fan-out must not allocate per recipient: cn Arc strong_count \
             went from {baseline} → {after} for {SUBSCRIBERS} subscribers \
             (a per-recipient String clone would push it to baseline + N)"
        );
    }

    #[test]
    fn authz_eval_gauge_reflects_concurrent_evaluations() {
        // Closes #721. The in-flight gauge is the operator-visible
        // signal for "how many evaluations are still holding the
        // pre-swap engine `Arc`". Drive N concurrent evaluations
        // through threads that each hold an `AuthzEvalGuard` while
        // they wait at a shared barrier, verify the gauge reads N
        // exactly while every guard is alive, then release the
        // barrier and confirm the gauge drains back to zero.
        //
        // Driving the guard directly (rather than going through the
        // full `Router::route` pipeline) keeps the test focused on
        // the gauge contract: every entry into `authz_evaluate_inner`
        // increments and every exit decrements, regardless of which
        // PEP entry point or destination shape called it.
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicI64, Ordering};

        const N: usize = 4;
        let gauge = Arc::new(AtomicI64::new(0));
        let gauge_cb = Arc::clone(&gauge);
        let slot: Arc<ArcSwap<Option<OnAuthzInFlightChanged>>> =
            Arc::new(ArcSwap::from_pointee(Some(Arc::new(move |delta: i64| {
                let _ = gauge_cb.fetch_add(delta, Ordering::SeqCst);
            }))));

        // Two-phase barrier. Phase 1: every thread has constructed
        // its guard (and therefore emitted `+1`). Phase 2: every
        // thread is allowed to drop its guard.
        let entered = Arc::new(Barrier::new(N + 1));
        let release = Arc::new(Barrier::new(N + 1));

        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let slot = Arc::clone(&slot);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            handles.push(std::thread::spawn(move || {
                let _g = AuthzEvalGuard::new(&slot);
                entered.wait();
                release.wait();
                // Guard drops on scope exit here.
            }));
        }

        // Wait until every thread has constructed its guard. With
        // the barrier model this is deterministic — no timeouts, no
        // sleeps.
        entered.wait();
        assert_eq!(
            gauge.load(Ordering::SeqCst),
            N as i64,
            "in-flight gauge must equal the number of held guards"
        );

        // Release every thread; each guard drops and emits `-1`.
        release.wait();
        for h in handles {
            h.join().expect("worker thread must join");
        }
        assert_eq!(
            gauge.load(Ordering::SeqCst),
            0,
            "in-flight gauge must drain to 0 after every guard drops"
        );
    }

    #[test]
    fn authz_eval_gauge_decrements_on_panic_safe_path() {
        // Closes #721. The `AuthzEvalGuard` is RAII; a panic inside
        // `engine.evaluate` (or any future early-return / `?` path
        // through `authz_evaluate_inner`) MUST still release the
        // gauge slot. Verify by directly dropping a guard inside an
        // unwound scope — `catch_unwind` here is overkill because
        // `AuthzEvalGuard` is its own type, not bound to the larger
        // Router lifecycle. The guarantee we need is: if the local
        // goes out of scope for ANY reason, the `-1` fires.
        use std::sync::atomic::{AtomicI64, Ordering};

        let gauge = Arc::new(AtomicI64::new(0));
        let gauge_cb = Arc::clone(&gauge);
        let slot: ArcSwap<Option<OnAuthzInFlightChanged>> =
            ArcSwap::from_pointee(Some(Arc::new(move |delta: i64| {
                let _ = gauge_cb.fetch_add(delta, Ordering::SeqCst);
            })));

        // Normal scope exit.
        {
            let _g = AuthzEvalGuard::new(&slot);
            assert_eq!(gauge.load(Ordering::SeqCst), 1, "guard increments on new()");
        }
        assert_eq!(
            gauge.load(Ordering::SeqCst),
            0,
            "guard must decrement on Drop at scope end"
        );

        // Early-return / `?` path simulation — guard dropped before
        // a hypothetical post-evaluation step. If a future refactor
        // routes the inner evaluator through a fallible step that
        // returns `Result`, the guard's drop still runs because the
        // local is bound before the fallible call.
        fn fallible_path(
            slot: &ArcSwap<Option<OnAuthzInFlightChanged>>,
        ) -> Result<(), &'static str> {
            let _g = AuthzEvalGuard::new(slot);
            Err("simulated early return")
        }
        let res = fallible_path(&slot);
        assert!(res.is_err());
        assert_eq!(
            gauge.load(Ordering::SeqCst),
            0,
            "guard must decrement even on `?`-style early return"
        );

        // Panic path — guard.drop() runs during stack unwind.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = AuthzEvalGuard::new(&slot);
            assert_eq!(gauge.load(Ordering::SeqCst), 1);
            panic!("simulated engine.evaluate panic");
        }));
        assert!(r.is_err());
        assert_eq!(
            gauge.load(Ordering::SeqCst),
            0,
            "guard must decrement during panic unwind"
        );

        // Empty-callback path — no callback installed, no observable
        // effect on the gauge, and Drop is still safe.
        let empty: ArcSwap<Option<OnAuthzInFlightChanged>> = ArcSwap::from_pointee(None);
        {
            let _g = AuthzEvalGuard::new(&empty);
        }
        assert_eq!(
            gauge.load(Ordering::SeqCst),
            0,
            "no-callback path must not perturb a foreign gauge"
        );
    }
}
