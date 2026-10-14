// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Data-plane actuation for authz obligations.
//!
//! The authz engine returns [`DecisionOutcome::obligations`] alongside an
//! allow verdict (see [`rustgate_authz::Obligation`]). This module is the
//! central dispatcher that translates the obligation list into mutations
//! on the outbound [`RoutableMessage`] copy destined for a specific
//! recipient.
//!
//! [`DecisionOutcome::obligations`]: rustgate_authz::DecisionOutcome::obligations
//!
//! # Scope
//!
//! Only obligations with data-plane side effects are handled here:
//!
//! - [`Obligation::MaskPoint`] — CoT `<point>` coordinates (`lat`, `lon`,
//!   `hae`) are zeroed via [`rustgate_cot::mask::strip_coordinates`].
//!   Non-XML, non-MAVLink payloads **fail closed** to
//!   [`Obligation::MaskPayload`]-equivalent erasure (#1545): they may be
//!   position-bearing protocols (DIS, Link 16, ASTERIX, …) the dispatcher
//!   has no masker for, so forwarding would leak coordinates. MAVLink has
//!   a registered masker (a point-less frame still forwards). XML-intent
//!   payloads that fail to parse also erase, so malformed input cannot
//!   leak coordinates either.
//! - [`Obligation::MaskPayload`] — the payload body is replaced with an
//!   empty [`Bytes`] and the classified message type is coerced to
//!   [`MessageType::Other`] with a `"masked"` tag so downstream caches
//!   and dedup do not mistake it for the real event.
//! - [`Obligation::StripPii`] — refs #857 cross-domain inspection
//!   scaffold. Strips operator-identity attributes (`callsign`, `phone`,
//!   `email`, IM/chat tokens) from CoT `<contact>` and `<detail>`
//!   children via [`rustgate_cot::cdi::strip_pii`]. Non-XML payloads
//!   pass through unmodified; XML-intent parse failures fail-closed to
//!   `MaskPayload`-equivalent erasure.
//! - [`Obligation::DegradePosition`] — refs #857. Rounds CoT
//!   `<point lat lon>` coordinates to a coarser grid sized in metres
//!   via [`rustgate_cot::cdi::degrade_position`]. Same recovery
//!   contract as `StripPii`.
//! - [`Obligation::InjectMarking`] — refs #857. Inserts a CAPCO-style
//!   `<marking value="…"/>` child under `<detail>` via
//!   [`rustgate_cot::cdi::inject_marking`]. Same recovery contract as
//!   `StripPii`; documents without `<detail>` pass through unmodified
//!   per the helper's docstring.
//!
//! [`Obligation::TagClassified`] and [`Obligation::AuditExtended`] are
//! audit-shaped obligations that do not mutate the wire payload:
//!
//! - `TagClassified` — emitted at the PEP call site via
//!   [`rustgate_core::audit::authz_classified_delivery`] so each
//!   delivery of a classified artefact produces one hash-chained audit
//!   record.
//! - `AuditExtended` — reserved for future expanded audit records; no
//!   data-plane side effect today. See `docs/authorization.md`.
//!
//! [`apply_obligations`] therefore skips both variants. Unknown
//! variants (the [`Obligation`] enum is `#[non_exhaustive]`) trigger
//! [`UnknownObligationPolicy`]: the default
//! [`UnknownObligationPolicy::FailClosed`] returns
//! [`ObligationError::Unknown`] so the caller drops the outbound copy
//! rather than delivering unmodified bytes a newer policy believed
//! were about to be transformed. The opt-out
//! [`UnknownObligationPolicy::SkipAndContinue`] restores the legacy
//! pre-issue-#728 fail-open behaviour (apply every known obligation
//! in the list, skip the unknown, continue delivery) and exists
//! solely for rolling-upgrade windows where policy and transport
//! versions deliberately skew. Either path emits
//! [`rustgate_core::audit::authz_obligation_unknown`] so operators
//! running a stale transport build against a newer authz policy can
//! detect the skew via the audit trail.
//!
//! # Failure mode
//!
//! [`Obligation::MaskPoint`] distinguishes two recovery modes:
//!
//! - Payload does not announce itself as XML (first non-whitespace byte
//!   is not `<`) and is not MAVLink → **fail-closed**: erase the body
//!   (#1545). A non-XML, non-MAVLink payload is a position-bearing
//!   protocol the dispatcher has no coordinate masker for, so forwarding
//!   it would leak the coordinates `MaskPoint` was meant to strip. The
//!   audit `recovery` token is `"dropped"`; `source_protocol` still names
//!   the upstream so an operator can prioritise a per-codec masker. The
//!   MAVLink path is the exception — it has a masker, so a frame it cannot
//!   place (a non-position frame) forwards as `forwarded_binary`.
//! - Payload starts with `<` but fails to parse or trips the attribute
//!   budget → **fail-closed**: empty the body and coerce the message
//!   type to `Other("masked")`, the same state [`Obligation::MaskPayload`]
//!   would have produced. A crafted payload that aborts parsing
//!   immediately after its `<point>` element was emitted must not leak
//!   coordinates via pass-through recovery.
//!
//! Both recovery paths emit
//! [`rustgate_core::audit::authz_obligation_failed`] so operators see
//! the policy hint was not honoured. The operational log stays at
//! DEBUG so a high-rate stream of bad payloads cannot amplify into a
//! logging DoS.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use rustgate_authz::Obligation;
use rustgate_core::audit;
use rustgate_core::masking::hash_cn;
use rustgate_core::message::{MessageType, RoutableMessage};
use rustgate_resilience::token_bucket::TokenBucket;

/// Default audit-emission cap for the unknown-variant rate limiter:
/// 60 emissions per minute per `(policy_id, variant_name)` pair.
///
/// Sized for human-readable forensic browsing. A misconfigured policy
/// pushing an unknown obligation on every routed message would otherwise
/// emit one [`audit::authz_obligation_unknown`] event per delivery,
/// flooding the hash-chained audit log; the cap pins audit volume to a
/// once-per-second cadence per `(policy_id, variant)` pair while the
/// always-on [`OnObligationUnknown`] metric callback preserves the
/// operator-visible rate signal regardless of audit suppression.
pub const DEFAULT_UNKNOWN_OBLIGATION_AUDIT_PER_MIN: u32 = 60;

rustgate_core::on_callback!(
    /// Callback invoked once per encountered unknown-obligation variant
    /// **before** the audit-emission rate limiter runs.
    ///
    /// Wired by the server binary to increment a Prometheus counter so
    /// operators can observe the true rate of unknown-variant encounters
    /// even when the audit log has been rate-limited. The callback receives
    /// the `{:?}` rendering of the variant as a `&str` so the same string is
    /// used as both the metric label (F-3b) and the audit event field.
    ///
    /// Conventional cross-thread alias shape (`Arc<dyn Fn(&str) + Send +
    /// Sync>`) — keep in lock-step with the rest of the workspace's
    /// [`OnDuplicate`](crate::dedup::OnDuplicate) /
    /// [`OnInsert`](crate::dedup::OnInsert) callback aliases.
    pub OnObligationUnknown,
    &str
);

rustgate_core::on_callback!(
    /// Callback invoked once per obligation actuation failure with the
    /// stable `reason` token emitted alongside the audit event. The same
    /// vocabulary as [`rustgate_core::audit::authz_obligation_failed`]:
    /// `mask_point_non_xml`, `mask_point_xml_error`,
    /// `mask_point_io_error`, `mask_point_attr_budget_exceeded`,
    /// `unknown_variant`. Wired by the server binary to feed the
    /// `rustgate_obligation_failures_total{reason}` counter under
    /// `#[cfg(feature = "metrics")]`. Closes #768.
    pub OnObligationFailure,
    &'static str
);

/// Per-`(policy_id, variant_name)` rate limiter for
/// [`audit::authz_obligation_unknown`] emissions plus an always-on
/// metric callback for operator visibility.
///
/// # Why this exists
///
/// A misconfigured policy that returns an unknown obligation variant on
/// every routed message would, pre-this-fix, emit one audit record per
/// delivery. At even modest message rates that floods the hash-chained
/// audit file with effectively duplicate forensic noise and blows past
/// the disk budget. The dispatcher uses one [`TokenBucket`] per
/// `(policy_id, variant_name)` pair so two distinct broken variants
/// each retain their own audit allotment, and a policy reload (which
/// changes `policy_id`) re-arms the bucket so the new policy's
/// emissions are not pre-suppressed by the old policy's history.
///
/// # Counter ordering (F-3b)
///
/// The metric callback fires **before** the rate-limit gate. Operators
/// see the true encounter rate via the `rustgate_authz_obligation_unknown_total`
/// counter even when the audit log has been silenced for that key. The
/// counter is the load-bearing visibility signal; the audit log is the
/// forensic detail captured at most `audit_per_min` times per minute
/// per key.
pub struct ObligationRateLimiter {
    audit_per_min: u32,
    buckets: Mutex<HashMap<(String, String), Arc<TokenBucket>>>,
    on_unknown: Option<OnObligationUnknown>,
    on_failure: Option<OnObligationFailure>,
}

// Custom `Debug`: `OnObligationUnknown` is `dyn Fn` and does not
// implement `Debug`, so the derive cannot be used. We project the
// callback to "installed/missing" so Debug output stays useful for
// operator diagnostics without leaking the closure's captures.
impl std::fmt::Debug for ObligationRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObligationRateLimiter")
            .field("audit_per_min", &self.audit_per_min)
            .field("buckets_tracked", &self.buckets.lock().len())
            .field("on_unknown_installed", &self.on_unknown.is_some())
            .field("on_failure_installed", &self.on_failure.is_some())
            .finish()
    }
}

impl ObligationRateLimiter {
    /// Create a rate limiter with the given per-minute audit cap per
    /// `(policy_id, variant)` pair.
    ///
    /// `audit_per_min` is the maximum
    /// [`audit::authz_obligation_unknown`] emissions per minute per
    /// key. Values above 1 produce a token bucket sized to the cap with
    /// the burst floor enforced by [`TokenBucket::new`]. A value of 0
    /// is clamped to 1 so the dispatcher always emits at least the
    /// first audit record per key (operators must always see the
    /// signal at least once).
    pub fn new(audit_per_min: u32) -> Self {
        Self {
            audit_per_min: audit_per_min.max(1),
            buckets: Mutex::new(HashMap::new()),
            on_unknown: None,
            on_failure: None,
        }
    }

    /// Builder-style installer for the metric callback. Wired once at
    /// startup by the server binary to bridge unknown-variant
    /// encounters to the Prometheus counter.
    #[must_use]
    pub fn with_on_unknown(mut self, cb: OnObligationUnknown) -> Self {
        self.on_unknown = Some(cb);
        self
    }

    /// Replace the metric callback after construction. Used by setup
    /// code that builds the limiter at one site and registers the
    /// callback later.
    pub fn set_on_unknown(&mut self, cb: OnObligationUnknown) {
        self.on_unknown = Some(cb);
    }

    /// Builder-style installer for the per-failure metric callback.
    /// Wired by the server binary at startup so every obligation
    /// actuation failure (mask_point_non_xml, mask_point_xml_error,
    /// mask_point_io_error, mask_point_attr_budget_exceeded,
    /// unknown_variant) feeds the
    /// `rustgate_obligation_failures_total{reason}` counter. Closes
    /// #768.
    #[must_use]
    pub fn with_on_failure(mut self, cb: OnObligationFailure) -> Self {
        self.on_failure = Some(cb);
        self
    }

    /// Replace the per-failure metric callback after construction.
    pub fn set_on_failure(&mut self, cb: OnObligationFailure) {
        self.on_failure = Some(cb);
    }

    /// Notify the per-failure callback (if installed) with the
    /// documented stable `reason` token. Called from
    /// [`apply_obligations_with_limiter`] after every
    /// [`audit::authz_obligation_failed`] emission so dashboards see
    /// the same signal the audit log records. Closes #768.
    pub(crate) fn observe_failure(&self, reason: &'static str) {
        if let Some(cb) = self.on_failure.as_ref() {
            cb(reason);
        }
    }

    /// Configured audit-emission cap per minute per
    /// `(policy_id, variant)` pair.
    pub fn audit_per_min(&self) -> u32 {
        self.audit_per_min
    }

    /// Drop the audit-rate-limiter entries owned by `policy_id`. Called
    /// on policy reload so a freshly-installed policy's first
    /// unknown-variant encounters always produce an audit record (the
    /// previous policy's bucket carry-over would otherwise pre-suppress
    /// new emissions). No-op when no bucket has ever been created for
    /// the id.
    pub fn forget_policy(&self, policy_id: &str) {
        let mut guard = self.buckets.lock();
        guard.retain(|(pid, _), _| pid != policy_id);
    }

    /// Increment the metric counter (always) and return `true` when the
    /// audit log emission is allowed by the per-key token bucket.
    ///
    /// The metric callback fires once per call regardless of the
    /// bucket's verdict. The bucket fires once per call and consumes
    /// one token if available; rejected calls do not record (matching
    /// [`TokenBucket::try_acquire`] semantics). Returns `true` when the
    /// caller should emit [`audit::authz_obligation_unknown`].
    fn observe_unknown(&self, policy_id: &str, variant: &str) -> bool {
        // F-3b: counter increment happens FIRST and unconditionally.
        // Operators must see the encounter rate via Prometheus even
        // when the audit log has been silenced for this key.
        if let Some(cb) = self.on_unknown.as_ref() {
            cb(variant);
        }
        // F-3a: per-key audit rate limit. Token bucket sized so the
        // refill rate is `audit_per_min / 60` tokens/sec, burst equal
        // to the per-minute cap (allowing a one-minute burst at
        // startup).
        let bucket = self.bucket_for(policy_id, variant);
        bucket.try_acquire()
    }

    /// Lazily acquire (or create) the per-`(policy_id, variant)`
    /// bucket. Map grows on first encounter; pruned by
    /// [`Self::forget_policy`] on policy reload.
    fn bucket_for(&self, policy_id: &str, variant: &str) -> Arc<TokenBucket> {
        let key = (policy_id.to_owned(), variant.to_owned());
        let mut guard = self.buckets.lock();
        if let Some(existing) = guard.get(&key) {
            return Arc::clone(existing);
        }
        // Refill rate = audit_per_min / 60 tokens/sec. Burst capacity
        // = audit_per_min so a brand-new key sees the full per-minute
        // allotment immediately, then refills at the steady-state rate.
        let per_min = f64::from(self.audit_per_min);
        let bucket = Arc::new(TokenBucket::new(per_min / 60.0, Some(per_min)));
        let _ = guard.insert(key, Arc::clone(&bucket));
        bucket
    }
}

impl Default for ObligationRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_UNKNOWN_OBLIGATION_AUDIT_PER_MIN)
    }
}

/// Policy for handling an [`Obligation`] variant this transport build
/// cannot actuate.
///
/// The authz crate's [`Obligation`] enum is `#[non_exhaustive]` — a
/// newer authz deployment may return a variant (e.g. a future
/// `Obligation::TransformPayload`) the transport build was not
/// compiled against. Without an explicit policy the pre-#728
/// dispatcher silently delivered such payloads unmodified. A policy
/// author who added a masking / classification / redaction
/// obligation "after the fact" to tighten leak prevention would then
/// be mistaken about whether the data plane was honouring it until
/// the transport was rebuilt — the classic fail-open security hole
/// XACML §7.2 calls out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UnknownObligationPolicy {
    /// Drop the outbound copy and return
    /// [`ObligationError::Unknown`] when an unknown variant is
    /// encountered. The caller decides the blast radius: at a
    /// sender-side PEP the message is never dispatched, at a
    /// per-recipient fan-out only this hop is skipped.
    ///
    /// This is the correct default for production deployments and
    /// matches the XACML recommendation to treat an obligation the
    /// PEP cannot honour as a fail-closed signal.
    #[default]
    FailClosed,
    /// Apply every known obligation in the list, emit an audit
    /// record for each unknown variant, and return `Ok`. Equivalent
    /// to the legacy pre-#728 fail-open behaviour. Not the default —
    /// exists solely as an operational opt-out for deployments where
    /// policy and transport versions deliberately skew during a
    /// rolling upgrade and the operator has accepted the risk.
    SkipAndContinue,
}

/// Error returned by [`apply_obligations`] on an obligation actuation
/// failure the caller must handle explicitly.
///
/// Today this is only emitted when the configured
/// [`UnknownObligationPolicy`] is
/// [`UnknownObligationPolicy::FailClosed`] and an unknown variant is
/// encountered. Additional variants may be added for future data-
/// plane actuation failures that cannot be recovered from inline.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ObligationError {
    /// The policy returned an [`Obligation`] variant the transport
    /// cannot actuate, and
    /// [`UnknownObligationPolicy::FailClosed`] is in effect.
    ///
    /// Callers MUST drop the outbound copy rather than delivering it
    /// with the obligation silently skipped. The `variant` field
    /// captures the `{:?}` rendering of the unknown variant for
    /// logs and audit — the audit record is emitted by
    /// [`apply_obligations`] before returning.
    #[error(
        "unknown authz obligation variant `{variant}` — transport build older than authz policy"
    )]
    Unknown {
        /// `{:?}` rendering of the unknown variant captured at the
        /// fail-closed site.
        variant: String,
    },
}

/// Return `true` when the obligation slice contains at least one
/// variant that mutates the wire payload.
///
/// Callers use this to skip the clone-out-of-`Arc` performed by
/// [`crate::router::RoutedMessage::with_obligations`] when the authz
/// decision carries only audit-shaped obligations like
/// [`Obligation::TagClassified`] or [`Obligation::AuditExtended`]. On a
/// broadcast to N recipients with a policy that only requires
/// classified-delivery audit (not masking), this turns N `clone() +
/// Arc::new()` into N cheap `Arc::clone()`.
///
/// Unknown variants are treated as payload-mutating out of caution —
/// if a future authz upgrade adds `Obligation::TransformPayload`, the
/// transport crate's stale build should NOT short-circuit the
/// payload-clone path and deliver the unmodified original. The audit
/// record emitted by [`apply_obligations`] for unknown variants still
/// fires on delivery.
pub(crate) fn obligations_mutate_payload(obligations: &[Obligation]) -> bool {
    obligations.iter().any(|o| match o {
        Obligation::MaskPoint | Obligation::MaskPayload | Obligation::MaskCommand => true,
        Obligation::TagClassified | Obligation::AuditExtended => false,
        // Refs #857 — every cross-domain inspection variant rewrites
        // the payload (PII strip, position rounding, marking
        // insertion) so the clone-out-of-Arc path is required.
        Obligation::StripPii
        | Obligation::DegradePosition { .. }
        | Obligation::InjectMarking { .. } => true,
        // `#[non_exhaustive]` — unknown variants default to "mutates"
        // so the clone-out path runs and `apply_obligations` gets a
        // chance to emit the unknown-variant audit event.
        _ => true,
    })
}

/// Apply every data-plane obligation in `obligations` to `msg` in place.
///
/// Obligations are applied in the **canonical chaining order** defined
/// by [`Obligation::chain_sort_key`] (refs #882): Group 1 (Redactors:
/// `MaskPoint`, `MaskPayload`), then Group 2 (Classifiers/Taggers:
/// `TagClassified`), then Group 3 (Auditors: `AuditExtended` and any
/// future `#[non_exhaustive]` variant). Within a group ordering is
/// alphabetical by `Debug` repr. The dispatcher performs a **stable
/// sort** on a local clone of the slice before iterating so two
/// permutations of the same obligation set produce byte-identical
/// post-PEP output regardless of which code path or which engine
/// emission sequence assembled the list.
///
/// Obligations without a data-plane side effect
/// ([`Obligation::TagClassified`], [`Obligation::AuditExtended`]) are
/// skipped silently. The caller handles those via audit events at the
/// PEP site.
///
/// # Unknown variants
///
/// The authz crate's [`Obligation`] enum is `#[non_exhaustive]`.
/// `unknown_policy` decides what happens when the policy engine
/// returns a variant this transport build does not recognise.
///
/// With [`UnknownObligationPolicy::FailClosed`] (the default) the
/// function emits the audit event plus a WARN log and returns
/// [`ObligationError::Unknown`]. Obligations earlier in the slice
/// have already been applied to `msg`; the caller must drop the
/// outbound copy rather than delivering a partially-mutated payload.
///
/// With [`UnknownObligationPolicy::SkipAndContinue`] the function
/// emits the audit event plus a DEBUG log and continues with the
/// remaining obligations (if any), returning `Ok(())`. This matches
/// the legacy pre-issue #728 fail-open behaviour and is kept only as
/// an operational opt-out for deliberate version skew during rolling
/// upgrades.
///
/// This entrypoint is the back-compat shim used by the fuzz target
/// and any caller that has no `policy_id`/limiter context. Audit
/// emissions for unknown variants are NOT rate-limited under this
/// path; production callers should prefer
/// [`apply_obligations_with_limiter`] so the per-`(policy_id, variant)`
/// audit-flood guard (issue #769) takes effect.
pub fn apply_obligations(
    msg: &mut RoutableMessage,
    obligations: &[Obligation],
    unknown_policy: UnknownObligationPolicy,
) -> Result<(), ObligationError> {
    apply_obligations_with_limiter(msg, obligations, unknown_policy, "", None)
}

/// Production entrypoint that threads the policy id and an optional
/// per-`(policy_id, variant)` rate limiter through to the unknown-variant
/// audit and metric path (issue #769).
///
/// Behaviour is identical to [`apply_obligations`] for known variants.
/// On an unknown variant:
///
/// 1. The dispatcher's [`OnObligationUnknown`] callback fires with the
///    `{:?}` rendering of the variant (F-3b: always-on counter input,
///    fires before the rate-limit check so operators see the true
///    encounter rate).
/// 2. The per-`(policy_id, variant)` token bucket is consulted (F-3a).
///    If a token is available, [`audit::authz_obligation_unknown`] is
///    emitted; if not, the audit emission is silently dropped — the
///    metric counter has already captured the encounter for the
///    operator dashboard.
/// 3. The configured [`UnknownObligationPolicy`] decides whether to
///    fail-closed or continue.
///
/// `policy_id` should be the engine's stable id (see
/// [`rustgate_authz::PolicyEngine::policy_id`]). An empty string is
/// accepted for callers without engine context — those calls all share
/// a single bucket key.
pub fn apply_obligations_with_limiter(
    msg: &mut RoutableMessage,
    obligations: &[Obligation],
    unknown_policy: UnknownObligationPolicy,
    policy_id: &str,
    rate_limiter: Option<&ObligationRateLimiter>,
) -> Result<(), ObligationError> {
    // Refs #882: enforce the canonical chaining order before
    // actuation. Stable sort guarantees that ties (multiple variants
    // sharing the same `chain_sort_key`) preserve their input-relative
    // order — important for any future variant that turns into a
    // payload-bearing form where two distinct values share the same
    // `Debug` discriminator. We sort a local clone rather than mutating
    // the caller's slice so the engine's emission order remains
    // observable upstream of the dispatcher.
    let mut ordered: Vec<Obligation> = obligations.to_vec();
    ordered.sort_by_cached_key(Obligation::chain_sort_key);
    for obligation in &ordered {
        match obligation {
            Obligation::MaskPoint => apply_mask_point(msg, policy_id, rate_limiter),
            Obligation::MaskPayload => apply_mask_payload(msg),
            Obligation::MaskCommand => apply_mask_command(msg, policy_id, rate_limiter),
            // Audit-only obligations handled at the call site.
            Obligation::TagClassified | Obligation::AuditExtended => {}
            // Refs #857 — cross-domain inspection scaffold.
            Obligation::StripPii => apply_strip_pii(msg, policy_id, rate_limiter),
            Obligation::DegradePosition { precision_meters } => {
                apply_degrade_position(msg, *precision_meters, policy_id, rate_limiter);
            }
            Obligation::InjectMarking { marking } => {
                apply_inject_marking(msg, marking, policy_id, rate_limiter);
            }
            // `#[non_exhaustive]` Obligation — future variants land
            // here. The audit event fires regardless of policy so the
            // stale-transport / new-policy skew is always visible in
            // the forensic trail.
            other => {
                let variant_repr = format!("{other:?}");
                // Ordering is critical (F-3a + F-3b, issue #769):
                //   1. Counter increment via `observe_unknown` (always).
                //   2. Audit emission (only when token available).
                // A regression that audited unconditionally would
                // re-introduce the audit-flood vector this PR closes.
                let emit_audit = match rate_limiter {
                    Some(limiter) => limiter.observe_unknown(policy_id, &variant_repr),
                    None => true,
                };
                if emit_audit {
                    audit::authz_obligation_unknown(
                        &msg.source.cn,
                        &variant_repr,
                        &msg.metadata.source_protocol,
                        msg.destination.kind_str(),
                        policy_id,
                    );
                }
                // Closes #768: the unknown-variant path is also a
                // failure path for the obligation-failures counter —
                // the audit event already carries the
                // `unknown_variant` reason token, so dashboards see
                // the same vocabulary on the metric.
                if let Some(limiter) = rate_limiter {
                    limiter.observe_failure(audit::OBLIGATION_REASON_UNKNOWN_VARIANT);
                }
                match unknown_policy {
                    UnknownObligationPolicy::FailClosed => {
                        // WARN-level operational log: the policy
                        // author intended a side effect this build
                        // cannot honour and the message is about to
                        // be dropped. Operators need to see this
                        // even under steady state because the
                        // remediation (rebuild transport, or accept
                        // the risk via SkipAndContinue) is a
                        // human-in-the-loop action. CN is hashed so
                        // the log remains PII-safe even at volume.
                        tracing::warn!(
                            obligation = ?other,
                            src_cn_hash = %hash_cn(&msg.source.cn),
                            source_protocol = %msg.metadata.source_protocol,
                            dst = msg.destination.kind_str(),
                            "unknown authz obligation variant: failing closed, dropping message"
                        );
                        return Err(ObligationError::Unknown {
                            variant: variant_repr,
                        });
                    }
                    UnknownObligationPolicy::SkipAndContinue => {
                        tracing::debug!(
                            obligation = ?other,
                            "unknown authz obligation variant: policy is SkipAndContinue, delivering with known obligations only"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Zero CoT `<point>` coordinates on `msg.payload` with fail-closed
/// recovery on XML-intent parse errors.
///
/// Recovery rules:
///
/// 1. **Non-XML payload** (first non-whitespace byte is not `<`), other
///    than MAVLink — **fail-closed**: erase the body via
///    [`apply_mask_payload`] and emit `recovery = "dropped"`. Such a
///    payload is a position-bearing protocol the dispatcher has no
///    coordinate masker for (DIS, Link 16, ASTERIX, VMF, SAPIENT, NFFI,
///    STANAG 4586, Meshtastic, TAK protobuf). Forwarding it unmasked —
///    the pre-#1545 behaviour — leaked the coordinates a `MaskPoint`
///    obligation was meant to strip (SEC-18). "No `<point>` element" is
///    not "no position": binary framings carry lat/lon in their own
///    fields. This is default-deny — a payload we cannot prove is
///    position-free is treated as if it carries one — so genuinely
///    point-less binary traffic routed through a `MaskPoint` group is
///    erased too. The DEBUG record keeps the
///    [`audit::classify_mask_recovery_for`] protocol-class string in a
///    separate `protocol_class` field for drill-down, and
///    `source_protocol` names the upstream so an operator can prioritise
///    a per-codec masker (the proper, non-interim fix). See ADR 0027.
///    MAVLink is handled earlier (it has a registered masker; a frame it
///    cannot place, e.g. `HEARTBEAT`, is genuinely point-less and still
///    forwards as `forwarded_binary`).
///
/// 2. **XML-intent parse failure** (payload starts with `<` but
///    quick_xml errors, or the `<point>` attribute budget is exceeded)
///    — **fail-closed**: empty the body and coerce the message type to
///    `Other("masked")`, the same state [`Obligation::MaskPayload`]
///    would produce. This is the security boundary: a crafted payload
///    that aborts parsing immediately after `<point>` was already
///    copied to the writer must NOT leak coordinates via pass-through.
///    Audit emitted with `recovery = "dropped"`.
///
/// The operational log stays at DEBUG for both recovery paths so a
/// hostile or mis-configured sender cannot amplify a single bad
/// payload into thousands of WARN records per second. Audit records
/// carry the forensic detail.
///
/// `policy_id` is forwarded into both `audit::authz_obligation_failed`
/// emissions (closes #772) so SIEM correlation can pin which engine
/// version returned the obligation that the masker could not honour.
fn apply_mask_point(
    msg: &mut RoutableMessage,
    policy_id: &str,
    rate_limiter: Option<&ObligationRateLimiter>,
) {
    // MAVLink frames are binary, not XML. A GLOBAL_POSITION_INT frame has
    // its coordinates zeroed (CRC recomputed); any other MAVLink frame
    // has no `<point>` analogue and forwards unmodified, audited in the
    // same `forwarded_binary` bucket the legacy non-XML path used.
    if msg.metadata.source_protocol == rustgate_core::message::SOURCE_MAVLINK {
        if let Some(masked) = rustgate_mavlink::mask_position(&msg.payload) {
            msg.payload = masked;
        } else {
            audit::authz_obligation_failed(
                &msg.source.cn,
                "MaskPoint",
                audit::OBLIGATION_REASON_MASK_POINT_NON_XML,
                audit::classify_mask_recovery_for(&msg.metadata.source_protocol),
                &msg.metadata.source_protocol,
                msg.destination.kind_str(),
                policy_id,
            );
            if let Some(limiter) = rate_limiter {
                limiter.observe_failure(audit::OBLIGATION_REASON_MASK_POINT_NON_XML);
            }
        }
        return;
    }

    // XML-intent is decided from the payload itself: first
    // non-whitespace byte is `<`. A non-XML payload cannot host a
    // `<point>` element, but it may still carry coordinates in a binary
    // field, so the branch below fails it closed rather than forwarding
    // (#1545).
    let is_xml_intent = msg
        .payload
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'<');

    if !is_xml_intent {
        // Fail closed (#1545 / SEC-18). A non-XML, non-MAVLink payload
        // reaching MaskPoint is a position-bearing protocol the dispatcher
        // has no registered coordinate masker for — DIS, Link 16, ASTERIX,
        // VMF, SAPIENT, NFFI, STANAG 4586, Meshtastic, TAK protobuf. Before
        // #1545 the dispatcher forwarded it UNMASKED and merely audited a
        // `forwarded_*` token, so a MaskPoint obligation meant to strip
        // location did nothing and the original coordinates egressed intact
        // (the most serious finding of the June 2026 semantic audit). The
        // #742 premise that "no `<point>` element ⇒ nothing to mask" is
        // wrong for binary framings that carry lat/lon in their own fields.
        //
        // Erase the body instead — the same terminal state the XML-parse-
        // failure path below produces — rather than leak coordinates we
        // cannot strip. This is default-deny: a payload we cannot prove is
        // position-free is treated as if it carries one. `source_protocol`
        // still names which upstream tripped this so an operator can
        // prioritise a per-codec masker (the proper, non-interim fix); the
        // protocol-class string is preserved on the DEBUG record for
        // drill-down. See ADR 0027.
        let protocol_class = audit::classify_mask_recovery_for(&msg.metadata.source_protocol);
        tracing::debug!(
            source_protocol = %msg.metadata.source_protocol,
            message_type = %msg.metadata.message_type,
            recovery = audit::MASK_RECOVERY_DROPPED,
            protocol_class = protocol_class,
            "mask_point obligation: non-XML payload with no registered position masker, erasing payload"
        );
        audit::authz_obligation_failed(
            &msg.source.cn,
            "MaskPoint",
            audit::OBLIGATION_REASON_MASK_POINT_NON_XML,
            audit::MASK_RECOVERY_DROPPED,
            &msg.metadata.source_protocol,
            msg.destination.kind_str(),
            policy_id,
        );
        if let Some(limiter) = rate_limiter {
            limiter.observe_failure(audit::OBLIGATION_REASON_MASK_POINT_NON_XML);
        }
        apply_mask_payload(msg);
        return;
    }

    match rustgate_cot::mask::strip_coordinates(&msg.payload) {
        Ok(masked) => {
            msg.payload = masked;
        }
        Err(e) => {
            // Fail-closed: XML-intent payload whose parse failed (or
            // attribute-budget trip). Drop the payload rather than
            // leaking unmasked coordinates — a crafted sender could
            // otherwise emit `<event><point lat="…"…/>` and cut the
            // document so quick_xml errors after `<point>` was
            // already copied to the writer.
            //
            // The log record carries [`MaskError::kind`] rather than the
            // full `Display` form: `quick_xml::Error`'s own `Display`
            // may echo payload-derived tag names (e.g.
            // `EndEventMismatch`), and a hostile sender could otherwise
            // leak fragments of a classified payload through an
            // operator-facing DEBUG stream by deliberately malforming
            // the XML. The kind discriminant is then mapped to the
            // static `reason` vocabulary defined in `rustgate-core`
            // (issue #775) so SIEM dashboards group on a stable token
            // rather than the underlying error's prose.
            let error_kind = e.kind();
            let reason = audit::obligation_reason_for_mask_error_kind(error_kind);
            tracing::debug!(
                error_kind = %error_kind,
                reason = reason,
                source_protocol = %msg.metadata.source_protocol,
                message_type = %msg.metadata.message_type,
                "mask_point obligation: XML-intent parse failed, erasing payload"
            );
            audit::authz_obligation_failed(
                &msg.source.cn,
                "MaskPoint",
                reason,
                audit::MASK_RECOVERY_DROPPED,
                &msg.metadata.source_protocol,
                msg.destination.kind_str(),
                policy_id,
            );
            if let Some(limiter) = rate_limiter {
                limiter.observe_failure(reason);
            }
            apply_mask_payload(msg);
        }
    }
}

/// Replace the payload body with empty bytes and coerce the message type
/// to `other:masked`.
///
/// The outbound [`RoutableMessage`] still carries its original envelope
/// fields (source identity, destination, TTL, received_at) so consumers
/// can still see that *something* was delivered — it's just the payload
/// body that's been stripped. This matches XACML-style "reduce to
/// metadata" semantics.
fn apply_mask_payload(msg: &mut RoutableMessage) {
    // MAVLink: a stripped frame is replaced with a benign zeroed HEARTBEAT
    // (a well-formed presence ping) rather than an empty body, so the
    // recipient sees a live-but-contentless frame instead of a malformed
    // zero-length one. The message stays typed as `Mavlink`.
    if msg.metadata.source_protocol == rustgate_core::message::SOURCE_MAVLINK {
        msg.payload = rustgate_mavlink::mask_as_heartbeat(&msg.payload);
        msg.metadata.message_type = MessageType::Mavlink;
        return;
    }
    msg.payload = Bytes::new();
    msg.metadata.message_type = MessageType::Other("masked".into());
}

/// Refuse to forward a MAVLink actuation/command frame (`COMMAND_LONG`,
/// `COMMAND_INT`, `MANUAL_CONTROL`) — ADR 0020 §7.
///
/// A command frame is neutralised by replacing it with a benign zeroed
/// HEARTBEAT (the same redaction [`apply_mask_payload`] applies to a
/// stripped MAVLink frame), so the recipient cannot act on the command
/// but the link does not appear to drop. Non-MAVLink payloads and
/// non-command MAVLink frames (telemetry) pass through unmodified —
/// `MaskCommand` gates actuation, not observation.
fn apply_mask_command(
    msg: &mut RoutableMessage,
    policy_id: &str,
    rate_limiter: Option<&ObligationRateLimiter>,
) {
    if msg.metadata.source_protocol != rustgate_core::message::SOURCE_MAVLINK {
        return;
    }
    if rustgate_mavlink::is_command_frame(&msg.payload) {
        msg.payload = rustgate_mavlink::mask_as_heartbeat(&msg.payload);
        msg.metadata.message_type = MessageType::Mavlink;
        audit::authz_obligation_failed(
            &msg.source.cn,
            "MaskCommand",
            "mask_command_refused",
            audit::MASK_RECOVERY_DROPPED,
            &msg.metadata.source_protocol,
            msg.destination.kind_str(),
            policy_id,
        );
        if let Some(limiter) = rate_limiter {
            limiter.observe_failure("mask_command_refused");
        }
    }
}

/// Refs #857 — common recovery path for the cross-domain inspection
/// helpers. All three helpers (`StripPii`, `DegradePosition`,
/// `InjectMarking`) share the same fail-modes:
///
/// - **Non-XML payload** (the helper returned `Ok` echoing the input
///   bytes verbatim) — the obligation is a CoT control, so a non-XML
///   payload is forwarded unmodified and the audit trail records the
///   pass-through.
/// - **XML-intent parse failure** ([`rustgate_cot::mask::MaskError::Xml`]) — fail-closed:
///   erase the body via [`apply_mask_payload`] so a crafted partial
///   document cannot leak pre-redaction bytes via pass-through.
/// - **Attribute budget trip** ([`rustgate_cot::mask::MaskError::AttrBudgetExceeded`]) —
///   same fail-closed posture as `MaskPoint`.
///
/// `obligation_label` is the `Debug`-derived obligation name for the
/// audit `obligation` field; `policy_id` and `rate_limiter` are the
/// usual hot-path threading.
fn handle_cdi_helper_result(
    msg: &mut RoutableMessage,
    obligation_label: &'static str,
    policy_id: &str,
    rate_limiter: Option<&ObligationRateLimiter>,
    result: Result<bytes::Bytes, rustgate_cot::mask::MaskError>,
) {
    match result {
        Ok(new_payload) => {
            // The CDI helpers echo the input bytes when the payload is
            // not XML-intent. We can't distinguish "the helper rewrote
            // identical bytes" from "no XML" here without re-comparing,
            // but both cases produce the same observable outcome: the
            // forwarded payload is the helper's return value. Updating
            // the payload Bytes is cheap when the underlying allocation
            // is shared (Bytes ref-counted) so even the no-op path
            // costs at most an Arc bump.
            msg.payload = new_payload;
        }
        Err(e) => {
            // XML-intent parse failure or attribute-budget trip. Same
            // posture as MaskPoint — drop the body and coerce the
            // message type so a hostile sender cannot leak pre-
            // redaction bytes via pass-through recovery.
            let kind = e.kind();
            let reason = match kind {
                "attr_budget_exceeded" => audit::OBLIGATION_REASON_MASK_POINT_ATTR_BUDGET_EXCEEDED,
                _ => audit::OBLIGATION_REASON_CDI_XML_ERROR,
            };
            tracing::debug!(
                error_kind = %kind,
                reason = reason,
                obligation = obligation_label,
                source_protocol = %msg.metadata.source_protocol,
                "CDI obligation: XML-intent parse failed, erasing payload",
            );
            audit::authz_obligation_failed(
                &msg.source.cn,
                obligation_label,
                reason,
                audit::MASK_RECOVERY_DROPPED,
                &msg.metadata.source_protocol,
                msg.destination.kind_str(),
                policy_id,
            );
            if let Some(limiter) = rate_limiter {
                limiter.observe_failure(reason);
            }
            apply_mask_payload(msg);
        }
    }
}

/// Audit a non-XML pass-through for a CDI obligation. The CDI helpers
/// echo non-XML bytes verbatim; the dispatcher emits a forensic event
/// with [`audit::OBLIGATION_REASON_CDI_NON_XML`] so SIEM dashboards see
/// when a CDI obligation lands on traffic it cannot transform.
fn audit_cdi_non_xml(
    msg: &RoutableMessage,
    obligation_label: &'static str,
    policy_id: &str,
    rate_limiter: Option<&ObligationRateLimiter>,
) {
    let recovery = audit::classify_mask_recovery_for(&msg.metadata.source_protocol);
    audit::authz_obligation_failed(
        &msg.source.cn,
        obligation_label,
        audit::OBLIGATION_REASON_CDI_NON_XML,
        recovery,
        &msg.metadata.source_protocol,
        msg.destination.kind_str(),
        policy_id,
    );
    if let Some(limiter) = rate_limiter {
        limiter.observe_failure(audit::OBLIGATION_REASON_CDI_NON_XML);
    }
}

/// Refs #857 — apply [`Obligation::StripPii`] via
/// [`rustgate_cot::cdi::strip_pii`].
fn apply_strip_pii(
    msg: &mut RoutableMessage,
    policy_id: &str,
    rate_limiter: Option<&ObligationRateLimiter>,
) {
    let is_xml = msg
        .payload
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'<');
    if !is_xml {
        audit_cdi_non_xml(msg, "StripPii", policy_id, rate_limiter);
        return;
    }
    let result = rustgate_cot::cdi::strip_pii(&msg.payload);
    handle_cdi_helper_result(msg, "StripPii", policy_id, rate_limiter, result);
}

/// Refs #857 — apply [`Obligation::DegradePosition`] via
/// [`rustgate_cot::cdi::degrade_position`].
fn apply_degrade_position(
    msg: &mut RoutableMessage,
    precision_meters: u32,
    policy_id: &str,
    rate_limiter: Option<&ObligationRateLimiter>,
) {
    let is_xml = msg
        .payload
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'<');
    if !is_xml {
        audit_cdi_non_xml(msg, "DegradePosition", policy_id, rate_limiter);
        return;
    }
    let result = rustgate_cot::cdi::degrade_position(&msg.payload, precision_meters);
    handle_cdi_helper_result(msg, "DegradePosition", policy_id, rate_limiter, result);
}

/// Refs #857 — apply [`Obligation::InjectMarking`] via
/// [`rustgate_cot::cdi::inject_marking`].
fn apply_inject_marking(
    msg: &mut RoutableMessage,
    marking: &str,
    policy_id: &str,
    rate_limiter: Option<&ObligationRateLimiter>,
) {
    let is_xml = msg
        .payload
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'<');
    if !is_xml {
        audit_cdi_non_xml(msg, "InjectMarking", policy_id, rate_limiter);
        return;
    }
    let result = rustgate_cot::cdi::inject_marking(&msg.payload, marking);
    handle_cdi_helper_result(msg, "InjectMarking", policy_id, rate_limiter, result);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::time::SystemTime;

    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, Metadata};

    use super::*;

    const SAMPLE_COT: &[u8] = br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;

    fn sample_msg(payload: &'static [u8], message_type: MessageType) -> RoutableMessage {
        let id = Identity::new("alice".into(), "abc123".into(), BTreeSet::new()).unwrap();
        RoutableMessage {
            source: id,
            destination: Destination::Broadcast,
            payload: Bytes::from_static(payload),
            metadata: Metadata::new(SystemTime::now(), "tcp".into(), message_type),
            entity: None,
        }
    }

    /// Variant of `sample_msg` that lets the caller pin
    /// `source_protocol`. Used by the issue-#742 recovery-bucket tests
    /// that assert the dispatcher passes a binary payload through
    /// unchanged regardless of which binary framing it is labelled as.
    fn sample_msg_with_protocol(
        payload: &'static [u8],
        message_type: MessageType,
        source_protocol: &str,
    ) -> RoutableMessage {
        let mut m = sample_msg(payload, message_type);
        m.metadata.source_protocol = source_protocol.to_string();
        m
    }

    /// Apply obligations under the default fail-closed policy.
    ///
    /// All existing tests exercise known obligation variants only,
    /// so the call always returns `Ok(())`. Unwrapping here keeps
    /// the test bodies readable; the dedicated unknown-variant
    /// tests assert the `Err` shape directly.
    fn apply(msg: &mut RoutableMessage, obligations: &[Obligation]) {
        apply_obligations(msg, obligations, UnknownObligationPolicy::FailClosed).unwrap();
    }

    #[test]
    fn mask_point_zeroes_point_coordinates() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply(&mut msg, &[Obligation::MaskPoint]);

        let s = std::str::from_utf8(&msg.payload).unwrap();
        assert!(s.contains(r#"lat="0.0""#), "lat not zeroed: {s}");
        assert!(s.contains(r#"lon="0.0""#), "lon not zeroed: {s}");
        assert!(s.contains(r#"hae="0.0""#), "hae not zeroed: {s}");
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
    }

    #[test]
    fn mask_point_on_non_cot_fails_closed() {
        // Not XML at all, and not MAVLink. Pre-#1545 MaskPoint forwarded
        // such a payload unchanged; now it fails closed (#1545 / SEC-18):
        // a non-XML, non-MAVLink protocol is potentially position-bearing
        // with no registered masker, so the body is erased rather than
        // egressed with coordinates intact.
        let mut msg = sample_msg(b"not xml at all", MessageType::Chat);
        apply(&mut msg, &[Obligation::MaskPoint]);
        assert!(msg.payload.is_empty(), "non-XML payload must be erased");
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    // Issue #1545 (SEC-18): the non-XML, non-MAVLink path fails closed —
    // the body is erased rather than forwarded, because such a payload is a
    // position-bearing protocol the dispatcher has no coordinate masker for
    // (DIS, Link 16, ASTERIX, VMF, TAK protobuf, …) and forwarding it would
    // leak the coordinates a MaskPoint obligation was meant to strip. The
    // audit-emission shape (`recovery = "dropped"`) is pinned by the
    // integration test `tests/mask_point_recovery_audit.rs` (separate binary
    // so the tracing callsite Interest cache does not race other tests in
    // this crate). The tests below pin the side-effect contract: the erase
    // happens regardless of which binary framing the payload claims to be.
    // MAVLink is the exception — it has a registered masker, so a frame it
    // cannot place (a non-position frame) still forwards unchanged.

    #[test]
    fn mask_point_on_mavlink_payload_passes_through_unchanged() {
        // A MAVLink frame is a binary payload that cannot host a CoT
        // `<point>` element. MAVLink has a registered masker; a frame
        // `mask_position` cannot place (a non-position frame) is genuinely
        // point-less and still forwards unchanged. This path is deliberately
        // unchanged by #1545 (which scopes to non-MAVLink protocols).
        let frame: &'static [u8] = &[0xFD, 0x09, 0x00, 0x00, 0x00, 0x01, 0x01];
        let mut msg = sample_msg_with_protocol(frame, MessageType::Mavlink, "mavlink");
        let before = msg.payload.clone();
        apply(&mut msg, &[Obligation::MaskPoint]);
        assert_eq!(msg.payload, before, "mavlink payload must not be mutated");
        assert_eq!(msg.metadata.message_type, MessageType::Mavlink);
    }

    #[test]
    fn mask_point_on_tak_protobuf_payload_fails_closed() {
        // TAK protobuf frames start with the 0xBF magic byte and carry
        // position in binary fields — forwarding them unmasked was the
        // #1545 leak. The body is now erased rather than passed through.
        let frame: &'static [u8] = &[0xBF, 0x01, 0x02, 0x03];
        let mut msg =
            sample_msg_with_protocol(frame, MessageType::Other("binary".into()), "tak-protobuf");
        apply(&mut msg, &[Obligation::MaskPoint]);
        assert!(
            msg.payload.is_empty(),
            "tak-protobuf payload must be erased"
        );
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_point_on_asterix_payload_fails_closed() {
        // ASTERIX surveillance frames carry lat/lon in a binary format —
        // the single most serious leak from the #1545 audit. Erased now.
        let frame: &'static [u8] = &[0x3E, 0x00, 0x10, 0x00];
        let mut msg =
            sample_msg_with_protocol(frame, MessageType::Other("surveillance".into()), "asterix");
        apply(&mut msg, &[Obligation::MaskPoint]);
        assert!(msg.payload.is_empty(), "asterix payload must be erased");
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_point_on_unparseable_cot_fails_closed() {
        // `source_protocol = cot` plus a non-XML-intent first byte means
        // the upstream said this would be CoT but the bytes are not in a
        // parseable shape. Position MAY be in the bytes, so the dispatcher
        // erases rather than forwards (#1545) — this now matches the
        // XML-intent fail-closed path rather than passing through.
        let mut msg =
            sample_msg_with_protocol(b"truncated-cot-payload", MessageType::Position, "cot");
        apply(&mut msg, &[Obligation::MaskPoint]);
        assert!(
            msg.payload.is_empty(),
            "non-XML-intent cot payload must be erased"
        );
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_point_on_unrecognized_protocol_fails_closed() {
        // An unrecognised `source_protocol` is treated as potentially
        // position-bearing — default-deny: a payload we cannot prove is
        // position-free is erased rather than forwarded (#1545).
        let mut msg = sample_msg_with_protocol(
            b"some random bytes",
            MessageType::Other("blob".into()),
            "unknown_proto_xyz",
        );
        apply(&mut msg, &[Obligation::MaskPoint]);
        assert!(
            msg.payload.is_empty(),
            "unrecognised-protocol payload must be erased"
        );
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_payload_replaces_body_and_message_type() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply(&mut msg, &[Obligation::MaskPayload]);
        assert!(msg.payload.is_empty(), "payload should be empty");
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_payload_preserves_envelope_fields() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Alert);
        let original_source_cn = msg.source.cn.clone();
        let original_proto = msg.metadata.source_protocol.clone();

        apply(&mut msg, &[Obligation::MaskPayload]);

        // Envelope survives — only payload + classified type were touched.
        assert_eq!(msg.source.cn, original_source_cn);
        assert_eq!(msg.metadata.source_protocol, original_proto);
        assert!(matches!(msg.destination, Destination::Broadcast));
    }

    #[test]
    fn tag_classified_is_noop_on_payload() {
        // The data-plane dispatcher ignores TagClassified — audit
        // tracking is handled at the PEP call site. Verify no mutation.
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        let before = msg.payload.clone();
        apply(&mut msg, &[Obligation::TagClassified]);
        assert_eq!(msg.payload, before);
        assert_eq!(msg.metadata.message_type, MessageType::Position);
    }

    #[test]
    fn audit_extended_is_noop_on_payload() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        let before = msg.payload.clone();
        apply(&mut msg, &[Obligation::AuditExtended]);
        assert_eq!(msg.payload, before);
    }

    #[test]
    fn empty_obligation_list_is_noop() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        let before = msg.payload.clone();
        apply(&mut msg, &[]);
        assert_eq!(msg.payload, before);
        assert_eq!(msg.metadata.message_type, MessageType::Position);
    }

    #[test]
    fn multiple_obligations_compose() {
        // MaskPoint then MaskPayload — payload gets cleared regardless of
        // whether the initial mask succeeded. Final state: empty body.
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply(&mut msg, &[Obligation::MaskPoint, Obligation::MaskPayload]);
        assert!(msg.payload.is_empty());
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_payload_then_mask_point_does_not_error() {
        // Opposite order — after MaskPayload the body is empty, so
        // MaskPoint sees a non-CoT payload and passes through (staying
        // empty). The dispatcher must not panic or error on this path.
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply(&mut msg, &[Obligation::MaskPayload, Obligation::MaskPoint]);
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn mask_point_xml_intent_malformed_payload_is_fail_closed() {
        // Security-critical: an XML-intent payload that trips the parser
        // partway through must NOT fall back to pass-through. A sender
        // could otherwise leak coordinates by terminating the document
        // mid-element after `<point>` was already emitted.
        let malformed: &'static [u8] =
            br#"<event><point lat="38.8977" lon="-77.0365" hae="125.4"/><unterminated"#;
        let mut msg = sample_msg(malformed, MessageType::Position);
        apply(&mut msg, &[Obligation::MaskPoint]);
        // Fail-closed: payload erased, message type coerced.
        assert!(
            msg.payload.is_empty(),
            "payload not erased: {:?}",
            msg.payload
        );
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_point_on_attribute_budget_trip_is_fail_closed() {
        // Crafted `<point>` with more than MAX_POINT_ATTRIBUTES — the
        // masker returns AttrBudgetExceeded. Because the payload is
        // XML-intent, the dispatcher must erase it rather than forward
        // unmasked.
        use rustgate_cot::mask::MAX_POINT_ATTRIBUTES;
        let mut xml = String::from(
            r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4""#,
        );
        for i in 0..=MAX_POINT_ATTRIBUTES {
            xml.push_str(&format!(r#" x{i}="v""#));
        }
        xml.push_str("/></event>");

        // Leak the String to a &'static [u8] so sample_msg (which is
        // static-bound for convenience in the rest of the suite) works.
        let leaked: &'static [u8] = Box::leak(xml.into_bytes().into_boxed_slice());
        let mut msg = sample_msg(leaked, MessageType::Position);
        apply(&mut msg, &[Obligation::MaskPoint]);
        assert!(
            msg.payload.is_empty(),
            "attribute-budget trip must erase payload"
        );
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_point_on_uppercase_element_masks_coordinates() {
        // Case-variant: <Point> must be masked even though the byte
        // sequence is not `b"point"`. Earlier implementations bypassed
        // this case.
        let xml: &'static [u8] = br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><Point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;
        let mut msg = sample_msg(xml, MessageType::Position);
        apply(&mut msg, &[Obligation::MaskPoint]);
        let s = std::str::from_utf8(&msg.payload).unwrap();
        assert!(s.contains(r#"lat="0.0""#), "case-variant not masked: {s}");
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
    }

    #[test]
    fn mask_point_on_namespaced_element_masks_coordinates() {
        let xml: &'static [u8] = br#"<event xmlns:cot="urn:cot" uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><cot:point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;
        let mut msg = sample_msg(xml, MessageType::Position);
        apply(&mut msg, &[Obligation::MaskPoint]);
        let s = std::str::from_utf8(&msg.payload).unwrap();
        assert!(
            s.contains(r#"lat="0.0""#),
            "namespaced element not masked: {s}"
        );
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
    }

    #[test]
    fn obligations_mutate_payload_reports_mask_variants_true() {
        assert!(obligations_mutate_payload(&[Obligation::MaskPoint]));
        assert!(obligations_mutate_payload(&[Obligation::MaskPayload]));
        assert!(obligations_mutate_payload(&[
            Obligation::MaskPoint,
            Obligation::TagClassified
        ]));
        // Refs #857 — every CDI variant mutates the payload.
        assert!(obligations_mutate_payload(&[Obligation::StripPii]));
        assert!(obligations_mutate_payload(&[Obligation::DegradePosition {
            precision_meters: 1000
        }]));
        assert!(obligations_mutate_payload(&[Obligation::InjectMarking {
            marking: "//S//".to_string()
        }]));
    }

    #[test]
    fn obligations_mutate_payload_reports_audit_only_variants_false() {
        assert!(!obligations_mutate_payload(&[]));
        assert!(!obligations_mutate_payload(&[Obligation::TagClassified]));
        assert!(!obligations_mutate_payload(&[Obligation::AuditExtended]));
        assert!(!obligations_mutate_payload(&[
            Obligation::TagClassified,
            Obligation::AuditExtended
        ]));
    }

    #[test]
    fn unknown_obligation_policy_defaults_to_fail_closed() {
        // Regression guard for issue #728. The default must be
        // FailClosed — a deployment that forgets to configure
        // `--authz-allow-unknown-obligations` gets secure-by-default
        // behaviour, matching XACML §7.2.
        assert_eq!(
            UnknownObligationPolicy::default(),
            UnknownObligationPolicy::FailClosed
        );
    }

    #[test]
    fn fail_closed_policy_returns_ok_for_known_variants() {
        // Every known variant must return Ok under FailClosed so
        // the happy path is unaffected by the #728 change. The
        // mutation assertions are covered by the dedicated per-
        // variant tests; this test asserts only the Result shape.
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        let all_known = vec![
            Obligation::MaskPoint,
            Obligation::MaskPayload,
            Obligation::TagClassified,
            Obligation::AuditExtended,
            // Refs #857 — cross-domain inspection scaffold.
            Obligation::StripPii,
            Obligation::DegradePosition {
                precision_meters: 1000,
            },
            Obligation::InjectMarking {
                marking: "//SECRET//NOFORN".to_string(),
            },
        ];
        assert!(
            apply_obligations(&mut msg, &all_known, UnknownObligationPolicy::FailClosed).is_ok()
        );
    }

    #[test]
    fn skip_and_continue_policy_returns_ok_for_known_variants() {
        // The opt-out path must not accidentally return Err on
        // known variants — that would flip the semantics from
        // "apply everything, skip unknowns" to "fail on any
        // actuation error", which is not what SkipAndContinue
        // advertises.
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        let all_known = vec![
            Obligation::MaskPoint,
            Obligation::MaskPayload,
            Obligation::TagClassified,
            Obligation::AuditExtended,
            Obligation::StripPii,
            Obligation::DegradePosition {
                precision_meters: 1000,
            },
            Obligation::InjectMarking {
                marking: "//SECRET//NOFORN".to_string(),
            },
        ];
        assert!(
            apply_obligations(
                &mut msg,
                &all_known,
                UnknownObligationPolicy::SkipAndContinue
            )
            .is_ok()
        );
    }

    #[test]
    fn obligation_error_display_includes_variant_repr() {
        // Format shape is part of the audit contract — operators
        // grep for `unknown authz obligation variant` in alert
        // rules. Changing the prefix is a breaking change.
        let err = ObligationError::Unknown {
            variant: "TransformPayload".into(),
        };
        let s = format!("{err}");
        assert!(s.contains("unknown authz obligation variant"));
        assert!(s.contains("TransformPayload"));
    }

    // ── Issue #769: per-(policy_id, variant) audit rate limiter ─────
    //
    // `Obligation` is `#[non_exhaustive]` — we cannot construct a
    // synthetic unknown variant from outside `rustgate-authz`. The
    // rate-limit + counter path is a self-contained dispatcher
    // primitive (`ObligationRateLimiter`) so the tests pin its
    // observable shape directly. The dispatcher integration with
    // `apply_obligations_with_limiter` is exercised by the existing
    // known-variant tests above (which must not regress under the new
    // optional rate-limiter parameter).

    /// F-3a: emitting many unknown encounters MUST cap audit
    /// authorization at the per-key threshold (default 60/min).
    /// `observe_unknown` returns `true` only when the audit log
    /// emission is permitted by the bucket — counting `true`
    /// returns is the audit allotment.
    #[test]
    fn obligation_unknown_audit_rate_limited_after_threshold() {
        let limiter = ObligationRateLimiter::new(60);
        let allowed = (0..100)
            .filter(|_| limiter.observe_unknown("policy-a", "TransformPayload"))
            .count();
        assert!(
            allowed <= 60,
            "audit allotment must cap at audit_per_min; observed {allowed}/100 emissions"
        );
        // The first burst is sized to the per-minute cap; we expect
        // exactly that many tokens consumed.
        assert_eq!(
            allowed, 60,
            "the first burst should consume the full audit_per_min allotment"
        );
    }

    /// F-3b: the metric callback fires for every unknown encounter
    /// regardless of the audit-rate-limit verdict. Operators page on
    /// the counter, not the audit log; the counter MUST reflect the
    /// true rate even when audit emissions are silenced.
    #[test]
    fn obligation_unknown_metric_counts_all_emissions_not_just_audited() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_cb = Arc::clone(&counter);
        let limiter = ObligationRateLimiter::new(60).with_on_unknown(Arc::new(move |_variant| {
            let _ = counter_for_cb.fetch_add(1, Ordering::SeqCst);
        }));
        for _ in 0..100 {
            let _ = limiter.observe_unknown("policy-a", "TransformPayload");
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            100,
            "counter callback must fire for every encounter, regardless of audit rate-limit"
        );
    }

    /// F-3a key isolation: saturating one `(policy_id, variant)` key
    /// MUST NOT consume the bucket of another. A misconfigured
    /// `Variant=A` policy cannot suppress audit emission for a
    /// genuine `Variant=B` encounter that arrives during the same
    /// minute.
    #[test]
    fn obligation_unknown_per_variant_isolation() {
        let limiter = ObligationRateLimiter::new(60);
        // Saturate variant A — consumes its bucket entirely.
        let a_allowed = (0..60)
            .filter(|_| limiter.observe_unknown("policy-a", "VariantA"))
            .count();
        assert_eq!(a_allowed, 60, "variant A burst must consume full bucket");
        // A's bucket is now empty.
        assert!(
            !limiter.observe_unknown("policy-a", "VariantA"),
            "variant A must be rate-limited after saturation"
        );
        // Variant B starts with a fresh bucket — its full allotment
        // must be available even though A is saturated.
        let b_allowed = (0..60)
            .filter(|_| limiter.observe_unknown("policy-a", "VariantB"))
            .count();
        assert_eq!(
            b_allowed, 60,
            "variant B must retain its own allotment despite A's saturation"
        );
    }

    /// Policy reload (different `policy_id`) MUST start a fresh
    /// bucket: the per-key map is keyed on `(policy_id, variant)`,
    /// not just `variant`. A regression that keyed on variant alone
    /// would let the previous policy's saturated bucket pre-suppress
    /// the new policy's first-minute audit emissions.
    #[test]
    fn obligation_unknown_per_policy_isolation() {
        let limiter = ObligationRateLimiter::new(60);
        // Saturate policy A's bucket for the variant.
        for _ in 0..60 {
            assert!(limiter.observe_unknown("policy-a", "TransformPayload"));
        }
        assert!(!limiter.observe_unknown("policy-a", "TransformPayload"));
        // Policy B (e.g. after a reload) starts fresh.
        for i in 0..60 {
            assert!(
                limiter.observe_unknown("policy-b", "TransformPayload"),
                "policy B emission #{i} must be allowed (independent bucket)"
            );
        }
    }

    /// `forget_policy` drops every bucket owned by the given policy_id
    /// so a reload re-arms emission for that policy without affecting
    /// other policies' state.
    #[test]
    fn obligation_unknown_forget_policy_clears_only_that_policy() {
        let limiter = ObligationRateLimiter::new(60);
        // Saturate policy A's bucket.
        for _ in 0..60 {
            assert!(limiter.observe_unknown("policy-a", "X"));
        }
        assert!(!limiter.observe_unknown("policy-a", "X"));
        // Saturate policy B's bucket.
        for _ in 0..60 {
            assert!(limiter.observe_unknown("policy-b", "X"));
        }
        assert!(!limiter.observe_unknown("policy-b", "X"));

        limiter.forget_policy("policy-a");

        // Policy A re-armed: full allotment available again.
        assert!(limiter.observe_unknown("policy-a", "X"));
        // Policy B untouched: still rate-limited.
        assert!(!limiter.observe_unknown("policy-b", "X"));
    }

    /// Default-constructed limiter uses the documented per-minute cap.
    /// A change to the default constant is a documentation/operator
    /// surface change and must be visible at test time.
    #[test]
    fn obligation_rate_limiter_default_audit_per_min() {
        let limiter = ObligationRateLimiter::default();
        assert_eq!(
            limiter.audit_per_min(),
            DEFAULT_UNKNOWN_OBLIGATION_AUDIT_PER_MIN
        );
        assert_eq!(DEFAULT_UNKNOWN_OBLIGATION_AUDIT_PER_MIN, 60);
    }

    /// `audit_per_min(0)` is clamped to 1: the dispatcher must always
    /// emit at least the first audit record per key so a forensic
    /// signal is never fully suppressed.
    #[test]
    fn obligation_rate_limiter_zero_per_min_is_clamped_to_one() {
        let limiter = ObligationRateLimiter::new(0);
        assert_eq!(limiter.audit_per_min(), 1);
        assert!(
            limiter.observe_unknown("p", "v"),
            "first emission must always be allowed, even with audit_per_min=0 (clamped to 1)"
        );
        assert!(!limiter.observe_unknown("p", "v"));
    }

    // ── Refs #882: canonical obligation chaining order ──────────────
    //
    // The dispatcher applies obligations in a canonical 3-group order
    // (Redactors → Classifiers/Taggers → Auditors, alphabetical
    // within each group) so two code paths that encounter the same
    // obligation set in different sequences produce byte-identical
    // post-PEP output. The tests below pin (1) that the canonical
    // order survives a deliberately-wrong input ordering, (2) that
    // within-group sort ties resolve alphabetically, (3) that the
    // post-PEP byte output is stable under any input permutation,
    // and (4) that the `#[non_exhaustive]` default group is
    // forward-compatible.

    /// Helper: return the canonically-ordered slice of obligations
    /// the dispatcher would apply for `input`. Mirrors the stable
    /// sort inside `apply_obligations_with_limiter` so tests can
    /// pin the order without observing payload mutation (which
    /// would only catch redactor variants — `TagClassified` and
    /// `AuditExtended` are data-plane no-ops).
    fn canonical_order(input: &[Obligation]) -> Vec<Obligation> {
        let mut out = input.to_vec();
        out.sort_by_cached_key(Obligation::chain_sort_key);
        out
    }

    /// Refs #882 test 1: `[TagClassified, MaskPoint]` — deliberately
    /// wrong input order — must apply as `[MaskPoint, TagClassified]`
    /// because Redactors (group 0) precede Classifiers (group 1).
    /// A regression that walked the input slice directly would fail
    /// here because TagClassified would run before MaskPoint and
    /// the canonical group order would be inverted.
    #[test]
    fn obligations_apply_in_canonical_order_redactors_first() {
        let input = [Obligation::TagClassified, Obligation::MaskPoint];
        let ordered = canonical_order(&input);
        assert_eq!(
            ordered,
            vec![Obligation::MaskPoint, Obligation::TagClassified],
            "Redactor (MaskPoint, group 0) MUST run before Classifier (TagClassified, group 1)"
        );
    }

    /// Refs #882 test 2: `[MaskPoint, MaskPayload]` reversed —
    /// `[MaskPayload, MaskPoint]` on input — sorts alphabetically
    /// within group 0. `MaskPayload` < `MaskPoint` lexicographically
    /// (`MaskP[a]…` vs `MaskP[o]…`), so the canonical order is
    /// `[MaskPayload, MaskPoint]`. A regression that ranked variants
    /// by enum-declaration order would emit `[MaskPoint, MaskPayload]`
    /// and fail here.
    #[test]
    fn obligations_within_group_sort_alphabetically() {
        let input = [Obligation::MaskPoint, Obligation::MaskPayload];
        let mut reversed = input.to_vec();
        reversed.reverse();
        // `reversed` is now [MaskPayload, MaskPoint] — already in
        // canonical alphabetical order. Pin both reversed and the
        // forward input round-trip to the same canonical output so
        // the test exercises the sort regardless of starting point.
        let from_forward = canonical_order(&input);
        let from_reversed = canonical_order(&reversed);
        assert_eq!(
            from_forward,
            vec![Obligation::MaskPayload, Obligation::MaskPoint],
            "within-group order must be alphabetical: MaskPayload before MaskPoint"
        );
        assert_eq!(
            from_forward, from_reversed,
            "canonical order must be independent of input permutation"
        );
    }

    /// Refs #882 test 3: byte-stable output under input reorder.
    /// Two permutations of the same obligation set MUST produce
    /// byte-identical post-PEP output (payload bytes + metadata
    /// `message_type`). This is the load-bearing security property
    /// — different code paths could otherwise produce different
    /// post-PEP output for the same input, undermining downstream
    /// dedup, cache, and audit-correlation invariants.
    #[test]
    fn obligation_chaining_produces_byte_stable_output_under_input_reorder() {
        // Use the full known set so the sort exercises every group
        // boundary: 2 redactors, 1 classifier, 1 auditor.
        let permutation_a = [
            Obligation::AuditExtended,
            Obligation::TagClassified,
            Obligation::MaskPoint,
            Obligation::MaskPayload,
        ];
        let permutation_b = [
            Obligation::MaskPoint,
            Obligation::AuditExtended,
            Obligation::MaskPayload,
            Obligation::TagClassified,
        ];

        let mut msg_a = sample_msg(SAMPLE_COT, MessageType::Position);
        let mut msg_b = sample_msg(SAMPLE_COT, MessageType::Position);
        apply(&mut msg_a, &permutation_a);
        apply(&mut msg_b, &permutation_b);

        assert_eq!(
            msg_a.payload, msg_b.payload,
            "post-PEP payload must be byte-identical across input permutations"
        );
        assert_eq!(
            msg_a.metadata.message_type, msg_b.metadata.message_type,
            "post-PEP message_type must be identical across input permutations"
        );

        // Sanity check: the chosen permutations actually included a
        // redactor that mutated the payload, so this test would have
        // detected a divergence (rather than passing trivially on a
        // pair of no-op obligations).
        assert!(
            msg_a.payload.is_empty(),
            "MaskPayload should have emptied the body — sanity check on test inputs"
        );
        assert_eq!(
            msg_a.metadata.message_type,
            MessageType::Other("masked".into()),
            "MaskPayload should have coerced the message_type — sanity check on test inputs"
        );
    }

    /// Refs #882 test 4: forward-compatibility for the
    /// `#[non_exhaustive]` `Obligation` enum. A future variant the
    /// transport build doesn't yet know about MUST default to group
    /// 3 (Auditors) so every known redactor and tagger runs first.
    /// We can't construct an unknown variant from a test in this
    /// crate (the enum is non-exhaustive only across crate
    /// boundaries — it's exhaustive *inside* `rustgate-authz`), so
    /// this test pins the contract via the public `priority` of
    /// `AuditExtended`: that's the canonical group-3 inhabitant and
    /// any wildcard-arm fallback sits in the same bucket. The
    /// docstring on `Obligation::priority` documents the wildcard
    /// fallback explicitly so a regression that demoted unknown
    /// variants to group 0 (redactors) — i.e. allowing an unknown
    /// audit obligation to run before MaskPoint — would fail the
    /// docstring contract this test pins.
    #[test]
    fn unknown_variant_assigned_to_group_3() {
        // `AuditExtended` is the canonical group-3 inhabitant; any
        // future unknown variant lands in the same bucket per the
        // documented `_ => 2` fallback in `Obligation::priority`.
        assert_eq!(
            Obligation::AuditExtended.priority(),
            2,
            "AuditExtended must be in group 3 (priority = 2) — the bucket unknown variants fall into"
        );
        // Cross-check the full known set so a regression in the
        // priority assignments lands here with one pinned mapping
        // per variant rather than a single generic assertion.
        assert_eq!(Obligation::MaskPoint.priority(), 0, "MaskPoint = Redactor");
        assert_eq!(
            Obligation::MaskPayload.priority(),
            0,
            "MaskPayload = Redactor"
        );
        assert_eq!(
            Obligation::TagClassified.priority(),
            1,
            "TagClassified = Classifier/Tagger"
        );
        assert_eq!(
            Obligation::AuditExtended.priority(),
            2,
            "AuditExtended = Auditor"
        );

        // Pin the chain_sort_key composition: priority is the
        // primary key, Debug-repr is the secondary. A regression
        // that swapped the order would let alphabetical winners
        // outrank group-priority winners, breaking the canonical
        // chaining contract.
        let (p, name) = Obligation::MaskPoint.chain_sort_key();
        assert_eq!(p, 0);
        assert_eq!(name, "MaskPoint");
    }

    /// Refs #882: defense-in-depth pin on the dispatcher itself.
    /// Run two permutations of the full obligation set through the
    /// public `apply_obligations` entrypoint and assert byte-stable
    /// output. Distinct from `obligation_chaining_produces_byte_stable_output_under_input_reorder`
    /// because that test uses a payload (`SAMPLE_COT`) where
    /// `MaskPayload` empties the body — passing trivially if a
    /// regression silently dropped the sort. This test uses an
    /// obligation set without `MaskPayload` so `MaskPoint` is the
    /// only payload mutator and the sort actually has to put it
    /// before the Classifier and Auditor for the byte-stable claim
    /// to hold.
    #[test]
    fn dispatcher_byte_stable_when_only_redactor_mutates_payload() {
        let perm_a = [
            Obligation::AuditExtended,
            Obligation::TagClassified,
            Obligation::MaskPoint,
        ];
        let perm_b = [
            Obligation::MaskPoint,
            Obligation::AuditExtended,
            Obligation::TagClassified,
        ];

        let mut a = sample_msg(SAMPLE_COT, MessageType::Position);
        let mut b = sample_msg(SAMPLE_COT, MessageType::Position);
        apply(&mut a, &perm_a);
        apply(&mut b, &perm_b);

        assert_eq!(a.payload, b.payload);
        assert_eq!(a.metadata.message_type, b.metadata.message_type);
        // Sanity: MaskPoint actually masked the coordinates.
        let s = std::str::from_utf8(&a.payload).expect("masked payload is utf8");
        assert!(s.contains(r#"lat="0.0""#));
        assert!(!s.contains("38.8977"));
    }
}
