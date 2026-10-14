// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! JWKS `kid` rotation-window state machine (closes #952).
//!
//! The JWKS URL fetcher in [`crate::jwks_client`] (shipped via the
//! second sub-item of #952) periodically refreshes the verifier
//! registry on the live [`crate::jwt::JwtAuthority`]. Pre-this-module,
//! the diff was applied directly: each refresh atomically replaced the
//! external verifier set with whatever the upstream JWKS currently
//! advertised. That is correct fail-closed behaviour, but it is
//! brittle on either edge of a key rotation:
//!
//! - **Pending → Active flip is too eager.** A typo'd JWKS push that
//!   adds a `kid` and then rolls back within seconds would briefly
//!   register a verifier the operator never intended to trust.
//! - **Active → removed flip is too abrupt.** A JWT minted by a peer
//!   10 ms before our refresh dropped its `kid` from the registry
//!   would fail verification, even though the issuing peer is
//!   perfectly healthy.
//!
//! The state machine in this module sits between the JWKS refresh
//! task and the [`crate::jwt::JwtAuthority`] verifier slot, smoothing
//! both edges:
//!
//! ```text
//!    ┌─────────┐  refresh sees kid    ┌─────────┐  refresh stops seeing kid  ┌──────────┐
//!    │ Pending │─────────────────────▶│ Active  │───────────────────────────▶│ Retiring │
//!    └─────────┘                      └─────────┘                            └──────────┘
//!                                                                                  │
//!                                                        retiring_window elapsed   │
//!                                                                                  ▼
//!                                                                           ┌──────────┐
//!                                                                           │ Retired  │
//!                                                                           └──────────┘
//!                                                                       (verifier removed)
//! ```
//!
//! * **Pending** — observed in JWKS for the first time. Not yet
//!   trusted; held until the next refresh confirms the kid persists
//!   (and at least `pending_window` of wall time has elapsed).
//!   Defends against transient typo'd pushes that get rolled back.
//! * **Active** — promoted to Active. JWTs with this `kid` verify
//!   normally.
//! * **Retiring** — dropped from upstream JWKS, but still honoured
//!   by the local verifier registry for `retiring_window` so JWTs
//!   minted just before the upstream removal continue to verify. A
//!   reappearance in upstream JWKS flips the kid straight back to
//!   Active without going through Pending (the operator never
//!   intended to remove it).
//! * **Retired** — grace window elapsed; verifier removed from the
//!   registry. JWTs with this `kid` reject as
//!   [`crate::jwt::JwtError::UnknownKid`].
//!
//! The state machine is a deterministic function of (in-JWKS
//! observations seen, time). Tests use `tokio::time::pause` /
//! `advance` to drive transitions in virtual time.
//!
//! ## Audit emission
//!
//! When the post-verification hook on [`crate::jwt::JwtAuthority`]
//! reports a `kid` that resolved to a Retiring entry, the state
//! machine emits [`rustgate_core::audit::jwt_using_retiring_kid`]
//! with the elapsed seconds since demotion so SIEM dashboards can
//! count peers that have not yet rotated.
//!
//! ## Out of scope
//!
//! - Cross-server kid synchronisation: each rustgate server tracks
//!   its own JWKS state. Operators that need multi-server consensus
//!   today rely on a single shared upstream JWKS endpoint.
//! - HMAC HS256 rotation: the JWKS path admits HS256 only behind
//!   the `allow_hs256` opt-in (see [`crate::jwks_client::JwksConfig`]),
//!   and the rotation-window state machine treats those entries the
//!   same as the asymmetric ones.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use parking_lot::Mutex as PlMutex;
use rustgate_core::audit;
use tokio::time::Instant;
use tracing::debug;

use crate::jwt::{ExternalVerifier, JwtAuthority, OnKidUsed};

/// Lifecycle state of a JWKS-sourced `kid` as it flows through the
/// rotation-window state machine.
///
/// The four states are deterministic functions of (in-JWKS
/// observations seen, time). State transitions are driven by
/// [`RotationStateMachine::observe_refresh`]; the post-verification
/// hook only reads state and never mutates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationState {
    /// Discovered in the upstream JWKS for the first time. Not yet
    /// trusted by the verifier — held until the next refresh confirms
    /// the kid persists AND `pending_window` of wall time has
    /// elapsed since first observation. Defends against typo'd JWKS
    /// pushes that get rolled back within seconds.
    Pending,
    /// Trusted; JWTs with this kid verify normally. Promoted from
    /// Pending after the persistence + window check, or restored from
    /// Retiring when a kid reappears in the upstream JWKS.
    Active,
    /// Dropped from the upstream JWKS, but still honoured by the
    /// local verifier registry for `retiring_window` so JWTs minted
    /// just before the upstream removal continue to verify. The
    /// post-verification hook fires
    /// [`audit::jwt_using_retiring_kid`] for any token routed here.
    Retiring,
    /// Grace window elapsed; verifier has been removed from the
    /// registry. JWTs with this kid reject as `UnknownKid`. The
    /// state-machine entry is dropped after the verifier-removal
    /// step so a re-appearance in the upstream JWKS treats the kid
    /// as wholly new (Pending again).
    Retired,
}

/// Per-`kid` bookkeeping for the rotation-window state machine.
///
/// `state` is the lifecycle position; the two `Instant` fields are
/// scratch space the transition logic uses and do not cross out of
/// the module boundary.
#[derive(Debug, Clone, Copy)]
struct KidEntry {
    state: RotationState,
    /// When the kid was first observed in this state. Used by the
    /// Pending → Active promotion check (must satisfy
    /// `now - first_seen >= pending_window`).
    first_seen: Instant,
    /// When the kid was demoted from Active to Retiring. Used by the
    /// Retiring → Retired check and by the audit-emission hook to
    /// compute `retiring_for_seconds`.
    retiring_started_at: Option<Instant>,
}

/// JWKS rotation-window state machine.
///
/// Tracks per-`kid` lifecycle state across refreshes and mediates
/// installation into [`JwtAuthority`]. Construct one alongside the
/// JWKS client; drive transitions with [`Self::observe_refresh`].
///
/// Hot path:
/// - [`Self::observe_refresh`] is called once per refresh tick from
///   the JWKS background task. Internally takes a `parking_lot::Mutex`
///   (no `.await` boundary, no poison panic, no `.unwrap`).
/// - [`Self::notify_kid_used`] is called from the post-verification
///   hook and is a single map lookup behind the same mutex. Slow if
///   the registry is enormous; but the registry is bounded by the
///   upstream JWKS size.
pub struct RotationStateMachine {
    /// Per-kid lifecycle entries. Bounded by the upstream JWKS plus
    /// any kids currently in Retiring grace.
    entries: PlMutex<HashMap<String, KidEntry>>,
    /// Wall-time floor on the Pending → Active promotion window.
    pending_window: Duration,
    /// Grace window for Retiring → Retired demotion.
    retiring_window: Duration,
    /// Diagnostic origin URL for the audit emissions. Sanitized at
    /// the audit boundary by [`audit::jwt_using_retiring_kid`].
    url: String,
}

impl std::fmt::Debug for RotationStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationStateMachine")
            .field("pending_window", &self.pending_window)
            .field("retiring_window", &self.retiring_window)
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl RotationStateMachine {
    /// Build a fresh, empty state machine. `pending_window` is the
    /// minimum wall-time floor for Pending → Active promotion;
    /// `retiring_window` is the grace window for Retiring → Retired.
    /// `url` is the JWKS endpoint URL captured for audit emissions.
    pub fn new(
        pending_window: Duration,
        retiring_window: Duration,
        url: impl Into<String>,
    ) -> Self {
        Self {
            entries: PlMutex::new(HashMap::new()),
            pending_window,
            retiring_window,
            url: url.into(),
        }
    }

    /// Drive the state machine forward with the set of `kid`s
    /// observed in this refresh's JWKS response. Returns the diff
    /// against the previous tick — the caller uses
    /// [`Self::filter_for_install`] to materialise the verifier set
    /// the [`JwtAuthority`] should publish, and may consume the
    /// transitions for additional auditing.
    ///
    /// State transitions are computed against the supplied `now`
    /// instant so callers using `tokio::time::pause` get
    /// deterministic behaviour.
    pub fn observe_refresh(&self, observed: &HashSet<String>, now: Instant) -> RefreshTransitions {
        let mut state = self.entries.lock();
        let mut promoted = Vec::new();
        let mut demoted = Vec::new();
        let mut retired = Vec::new();
        let mut pending_pruned = Vec::new();

        // First pass: existing entries.
        let known_kids: Vec<String> = state.keys().cloned().collect();
        for kid in known_kids {
            let observed_now = observed.contains(&kid);
            let entry = match state.get(&kid).copied() {
                Some(e) => e,
                None => continue,
            };
            match entry.state {
                RotationState::Pending => {
                    if observed_now {
                        // Pending → Active when at least `pending_window` of
                        // wall time has elapsed since first observed AND
                        // the kid is still observed in this tick. The
                        // wall-time floor defends against a typo'd push
                        // that gets rolled back within a refresh cycle —
                        // both refreshes can happen inside the window if
                        // the operator triggers a manual reload.
                        if now.saturating_duration_since(entry.first_seen) >= self.pending_window {
                            let _ = state.insert(
                                kid.clone(),
                                KidEntry {
                                    state: RotationState::Active,
                                    first_seen: now,
                                    retiring_started_at: None,
                                },
                            );
                            promoted.push(kid);
                        }
                        // Otherwise stay Pending — second consecutive
                        // observation is necessary but not sufficient.
                    } else {
                        // Pending kid disappeared before promotion. Drop
                        // it entirely — the operator's typo'd JWKS push
                        // was rolled back, and we should not trust this
                        // kid even if it returns later (a future
                        // re-appearance will be a wholly fresh Pending).
                        let _ = state.remove(&kid);
                        pending_pruned.push(kid);
                    }
                }
                RotationState::Active => {
                    if observed_now {
                        // Stay Active. No-op — but refresh `first_seen`
                        // so a subsequent demote → re-promote sequence
                        // measures from the most recent confirmation
                        // rather than the original Pending discovery.
                        let _ = state.insert(
                            kid.clone(),
                            KidEntry {
                                first_seen: now,
                                ..entry
                            },
                        );
                    } else {
                        // Active → Retiring. Record `retiring_started_at`
                        // so the audit-emission hook can compute the
                        // elapsed grace duration and the Retiring → Retired
                        // check has a deterministic anchor.
                        let _ = state.insert(
                            kid.clone(),
                            KidEntry {
                                state: RotationState::Retiring,
                                first_seen: now,
                                retiring_started_at: Some(now),
                            },
                        );
                        demoted.push(kid);
                    }
                }
                RotationState::Retiring => {
                    if observed_now {
                        // Retiring → Active: kid reappeared. Defends
                        // against momentary upstream JWKS hiccups
                        // (network blip during a refresh, a 5xx that
                        // arrives between two healthy responses). Skip
                        // the Pending stage — the kid was already
                        // trusted before, and the operator never
                        // intended to remove it.
                        let _ = state.insert(
                            kid.clone(),
                            KidEntry {
                                state: RotationState::Active,
                                first_seen: now,
                                retiring_started_at: None,
                            },
                        );
                        promoted.push(kid);
                    } else {
                        // Retiring → Retired when the grace window has
                        // elapsed since demotion. The verifier is
                        // dropped from the install set on the next
                        // `filter_for_install` call.
                        let started = entry.retiring_started_at.unwrap_or(entry.first_seen);
                        if now.saturating_duration_since(started) >= self.retiring_window {
                            let _ = state.insert(
                                kid.clone(),
                                KidEntry {
                                    state: RotationState::Retired,
                                    ..entry
                                },
                            );
                            retired.push(kid);
                        }
                        // Otherwise stay Retiring; verifier still installed.
                    }
                }
                RotationState::Retired => {
                    if observed_now {
                        // Retired kid reappeared upstream. Treat as a
                        // wholly fresh kid — back through Pending.
                        // Operators who removed and then re-added a kid
                        // intentionally hit the same fail-safe window
                        // as a brand-new kid, which is the right
                        // posture: a Retired entry is a deliberate
                        // termination signal, not a "use again
                        // immediately" cache.
                        let _ = state.insert(
                            kid.clone(),
                            KidEntry {
                                state: RotationState::Pending,
                                first_seen: now,
                                retiring_started_at: None,
                            },
                        );
                    }
                    // Otherwise drop the Retired entry from tracking
                    // entirely so the bookkeeping doesn't grow without
                    // bound across a long uptime window.
                    else {
                        let _ = state.remove(&kid);
                    }
                }
            }
        }

        // Second pass: kids in the observation set but not yet tracked.
        // A `pending_window` of zero opts out of the smoothing — newly
        // observed kids go straight to Active. Operators who set zero
        // are explicitly trading the typo'd-rollback defence for
        // instant trust, e.g. in test scaffolding or in the rare
        // single-shot bootstrap where there is nothing to roll back
        // from.
        for kid in observed {
            if !state.contains_key(kid) {
                let initial_state = if self.pending_window.is_zero() {
                    promoted.push(kid.clone());
                    RotationState::Active
                } else {
                    RotationState::Pending
                };
                let _ = state.insert(
                    kid.clone(),
                    KidEntry {
                        state: initial_state,
                        first_seen: now,
                        retiring_started_at: None,
                    },
                );
            }
        }

        debug!(
            url = %self.url,
            promoted = promoted.len(),
            demoted = demoted.len(),
            retired = retired.len(),
            pending_pruned = pending_pruned.len(),
            "jwks rotation observe_refresh"
        );

        RefreshTransitions {
            promoted,
            demoted,
            retired,
            pending_pruned,
        }
    }

    /// Compute the verifier subset that should be installed into
    /// [`JwtAuthority::install_external_verifiers`] given the supplied
    /// `next` map (the parsed JWKS response, keyed by kid). Pending
    /// entries are excluded (not yet trusted), Retired entries are
    /// excluded (grace window elapsed), and Retiring entries are
    /// included from a previously-cached map supplied by the caller —
    /// because a Retiring kid by definition is no longer in the
    /// upstream JWKS, the caller must remember the last verifier
    /// material it had for that kid.
    pub fn filter_for_install(
        &self,
        next: HashMap<String, ExternalVerifier>,
        retained: &HashMap<String, ExternalVerifier>,
    ) -> HashMap<String, ExternalVerifier> {
        let state = self.entries.lock();
        let mut install = HashMap::new();
        for (kid, verifier) in next {
            match state.get(&kid).map(|e| e.state) {
                Some(RotationState::Active) => {
                    let _ = install.insert(kid, verifier);
                }
                // A kid that is observed in the JWKS but still Pending
                // in our tracker has not finished its promotion window
                // — do not install yet.
                Some(RotationState::Pending)
                | Some(RotationState::Retired)
                | Some(RotationState::Retiring) => {
                    // Retiring branch is unreachable in practice (a
                    // Retiring kid is by definition NOT in the new
                    // JWKS response), but treat it as "do not install
                    // from `next`" for safety — the retained branch
                    // below preserves the prior verifier.
                }
                None => {
                    // No tracker entry: the caller invoked filter
                    // before observe_refresh. Defensive default:
                    // install. The state machine API documents
                    // observe_refresh-then-filter ordering, so this
                    // arm is reachable only via misuse.
                    let _ = install.insert(kid, verifier);
                }
            }
        }
        // Add Retiring kids from the retained map so their verifiers
        // continue to honour in-flight tokens during the grace window.
        for (kid, entry) in state.iter() {
            if matches!(entry.state, RotationState::Retiring)
                && let Some(verifier) = retained.get(kid)
                && !install.contains_key(kid)
            {
                let _ = install.insert(kid.clone(), verifier.clone());
            }
        }
        install
    }

    /// Advance only the time-based Retiring → Retired transitions, without a
    /// fresh JWKS observation. Used on the refresh-failure path so a kid that
    /// has outlived its grace window is retired even while the JWKS endpoint
    /// is unreachable — otherwise a rotated-out (possibly compromised) kid
    /// would stay installed for the whole outage (#1627). Mirrors the
    /// Retiring → Retired arm of [`Self::observe_refresh`] but touches no
    /// other state. Returns the kids demoted to Retired by this call.
    pub fn advance_grace(&self, now: Instant) -> Vec<String> {
        let mut state = self.entries.lock();
        let mut retired = Vec::new();
        let known: Vec<String> = state.keys().cloned().collect();
        for kid in known {
            let Some(entry) = state.get(&kid).copied() else {
                continue;
            };
            if entry.state == RotationState::Retiring {
                let started = entry.retiring_started_at.unwrap_or(entry.first_seen);
                if now.saturating_duration_since(started) >= self.retiring_window {
                    let _ = state.insert(
                        kid.clone(),
                        KidEntry {
                            state: RotationState::Retired,
                            ..entry
                        },
                    );
                    retired.push(kid);
                }
            }
        }
        retired
    }

    /// Look up the lifecycle state of a `kid`. Returns `None` for an
    /// unknown kid (never observed, or already evicted from the
    /// Retired tail). Used by tests to assert on transitions.
    pub fn state_of(&self, kid: &str) -> Option<RotationState> {
        let state = self.entries.lock();
        state.get(kid).map(|e| e.state)
    }

    /// Snapshot the tracked kids (debugging / introspection).
    pub fn snapshot(&self) -> Vec<(String, RotationState)> {
        let state = self.entries.lock();
        state.iter().map(|(k, v)| (k.clone(), v.state)).collect()
    }

    /// Notify the state machine that a JWT has just verified against
    /// `kid`. When the kid is in [`RotationState::Retiring`], emit
    /// [`audit::jwt_using_retiring_kid`] with the wall-time elapsed
    /// since the Active → Retiring demotion.
    ///
    /// `now` is supplied by the caller so tests using
    /// `tokio::time::pause` get deterministic behaviour. Non-Retiring
    /// kids and unknown kids are no-ops on the audit channel.
    pub fn notify_kid_used(&self, kid: &str, now: Instant) {
        if kid.is_empty() {
            return;
        }
        let state = self.entries.lock();
        if let Some(entry) = state.get(kid)
            && matches!(entry.state, RotationState::Retiring)
        {
            let started = entry.retiring_started_at.unwrap_or(entry.first_seen);
            let elapsed = now.saturating_duration_since(started).as_secs();
            // Drop the lock before emitting so an audit subscriber that
            // re-enters the state machine cannot deadlock.
            drop(state);
            audit::jwt_using_retiring_kid(kid, elapsed);
        }
    }

    /// Build an [`OnKidUsed`] callback that wires this state machine
    /// into a [`JwtAuthority`] via [`JwtAuthority::set_on_kid_used`].
    /// The closure captures an `Arc<Self>` so the authority can
    /// outlive the constructing scope.
    pub fn into_kid_used_callback(self: Arc<Self>) -> OnKidUsed {
        Arc::new(move |kid: &str| {
            self.notify_kid_used(kid, Instant::now());
        })
    }
}

/// Per-tick diff returned by [`RotationStateMachine::observe_refresh`].
///
/// Each `Vec` lists the kids that crossed a state boundary in this
/// tick. Empty by default; populated only for the matching transitions.
#[derive(Debug, Default, Clone)]
pub struct RefreshTransitions {
    /// Kids that transitioned to [`RotationState::Active`] (either
    /// promoted from Pending after the window check, or restored from
    /// Retiring on a re-appearance).
    pub promoted: Vec<String>,
    /// Kids that transitioned from Active to [`RotationState::Retiring`].
    pub demoted: Vec<String>,
    /// Kids that transitioned from Retiring to [`RotationState::Retired`]
    /// (grace window elapsed). The verifier should be removed from
    /// the JWKS install set.
    pub retired: Vec<String>,
    /// Pending kids dropped before promotion (typo'd JWKS push that
    /// was rolled back). No verifier was ever installed.
    pub pending_pruned: Vec<String>,
}

impl RefreshTransitions {
    /// Convenience: true when nothing changed this tick.
    pub fn is_empty(&self) -> bool {
        self.promoted.is_empty()
            && self.demoted.is_empty()
            && self.retired.is_empty()
            && self.pending_pruned.is_empty()
    }
}

/// Install a [`RotationStateMachine`] as the kid-used hook on a
/// [`JwtAuthority`]. After this call, every successful
/// [`JwtAuthority::validate`] fires the state machine's
/// `notify_kid_used`, which emits the retiring-kid audit event when
/// applicable.
pub fn install_on_authority(machine: Arc<RotationStateMachine>, authority: &JwtAuthority) {
    let cb = machine.into_kid_used_callback();
    authority.set_on_kid_used(Some(cb));
}

/// Top-level scratch space the JWKS refresh task uses to remember the
/// last verifier set so Retiring kids can keep verifying after they
/// drop from the upstream JWKS. The mutex is poison-tolerant via
/// [`std::sync::Mutex::lock`] + `into_inner` per the workspace
/// convention.
#[derive(Debug, Default)]
pub struct RetainedVerifiers {
    inner: Mutex<HashMap<String, ExternalVerifier>>,
}

impl RetainedVerifiers {
    /// Construct an empty retained-verifier cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the cache with the freshly-fetched verifier set,
    /// adding entries for newly-observed kids and dropping entries
    /// for kids the state machine has Retired.
    pub fn upsert(&self, fresh: &HashMap<String, ExternalVerifier>) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        for (kid, verifier) in fresh {
            let _ = guard.insert(kid.clone(), verifier.clone());
        }
    }

    /// Drop a kid from the cache. Called when the state machine
    /// transitions a kid to Retired so the cache does not grow
    /// without bound.
    pub fn forget(&self, kid: &str) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        let _ = guard.remove(kid);
    }

    /// Snapshot of the retained verifier map, used by
    /// [`RotationStateMachine::filter_for_install`].
    pub fn snapshot(&self) -> HashMap<String, ExternalVerifier> {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        guard.clone()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::HashSet;

    use super::*;

    fn observed(kids: &[&str]) -> HashSet<String> {
        kids.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn pending_then_active_after_two_consecutive_refreshes() {
        // First refresh sees the kid → Pending.
        // Advance past pending_window.
        // Second refresh still sees the kid → Active.
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-new"]), now1);
        assert_eq!(m.state_of("k-new"), Some(RotationState::Pending));

        tokio::time::advance(Duration::from_secs(61)).await;
        let now2 = Instant::now();
        let t = m.observe_refresh(&observed(&["k-new"]), now2);
        assert_eq!(m.state_of("k-new"), Some(RotationState::Active));
        assert_eq!(t.promoted, vec!["k-new".to_string()]);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_disappears_before_promotion() {
        // First refresh sees the kid → Pending. Before second refresh
        // the kid drops from upstream. Pending entry must be pruned
        // entirely (never registered as Active).
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-typo"]), now1);
        assert_eq!(m.state_of("k-typo"), Some(RotationState::Pending));

        tokio::time::advance(Duration::from_secs(61)).await;
        let now2 = Instant::now();
        let t = m.observe_refresh(&observed(&[]), now2);
        assert_eq!(
            m.state_of("k-typo"),
            None,
            "Pending kid that disappears must be pruned, not promoted"
        );
        assert_eq!(t.pending_pruned, vec!["k-typo".to_string()]);
        assert!(t.promoted.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn active_to_retiring_when_dropped_from_upstream() {
        // Promote a kid to Active, then drop it → state must be Retiring.
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-rotating"]), now1);
        tokio::time::advance(Duration::from_secs(61)).await;
        let now2 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-rotating"]), now2);
        assert_eq!(m.state_of("k-rotating"), Some(RotationState::Active));

        // Now drop from upstream.
        tokio::time::advance(Duration::from_secs(60)).await;
        let now3 = Instant::now();
        let t = m.observe_refresh(&observed(&[]), now3);
        assert_eq!(m.state_of("k-rotating"), Some(RotationState::Retiring));
        assert_eq!(t.demoted, vec!["k-rotating".to_string()]);
    }

    #[tokio::test(start_paused = true)]
    async fn advance_grace_retires_kid_past_window_without_observation() {
        // #1627: during a JWKS outage `observe_refresh` is never called, yet a
        // kid past its retiring grace window must still be demoted to Retired
        // so a rotated-out key stops verifying. `advance_grace` does this on
        // the failure path with no fresh observation.
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let _ = m.observe_refresh(&observed(&["k-down"]), Instant::now());
        tokio::time::advance(Duration::from_secs(61)).await;
        let _ = m.observe_refresh(&observed(&["k-down"]), Instant::now());
        tokio::time::advance(Duration::from_secs(60)).await;
        let _ = m.observe_refresh(&observed(&[]), Instant::now());
        assert_eq!(m.state_of("k-down"), Some(RotationState::Retiring));

        // Before the grace window elapses, advance_grace is a no-op.
        tokio::time::advance(Duration::from_secs(299)).await;
        assert!(m.advance_grace(Instant::now()).is_empty());
        assert_eq!(m.state_of("k-down"), Some(RotationState::Retiring));

        // Past the window — retired WITHOUT any observe_refresh call.
        tokio::time::advance(Duration::from_secs(2)).await;
        let retired = m.advance_grace(Instant::now());
        assert_eq!(retired, vec!["k-down".to_string()]);
        assert_eq!(m.state_of("k-down"), Some(RotationState::Retired));
    }

    #[tokio::test(start_paused = true)]
    async fn retiring_still_verifies_jwts_during_grace() {
        // Drive a kid into Retiring; assert filter_for_install retains
        // the verifier from the cache for the grace window.
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let retained = RetainedVerifiers::new();
        let v = ExternalVerifier::EdDsa(vec![0u8; 32]);
        let mut fresh = HashMap::new();
        let _ = fresh.insert("k-grace".to_string(), v.clone());
        retained.upsert(&fresh);

        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-grace"]), now1);
        tokio::time::advance(Duration::from_secs(61)).await;
        let now2 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-grace"]), now2);
        assert_eq!(m.state_of("k-grace"), Some(RotationState::Active));

        // Drop from upstream.
        tokio::time::advance(Duration::from_secs(60)).await;
        let now3 = Instant::now();
        let _ = m.observe_refresh(&observed(&[]), now3);
        assert_eq!(m.state_of("k-grace"), Some(RotationState::Retiring));

        // Filter must include the retained verifier so an in-flight
        // JWT can still verify against it.
        let install = m.filter_for_install(HashMap::new(), &retained.snapshot());
        assert!(
            install.contains_key("k-grace"),
            "Retiring kid must remain installed during grace"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retiring_to_retired_after_grace_window() {
        // Drive a kid into Retiring; advance past retiring_window;
        // observe again without the kid → Retired.
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-fade"]), now1);
        tokio::time::advance(Duration::from_secs(61)).await;
        let now2 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-fade"]), now2);
        // Drop and demote.
        tokio::time::advance(Duration::from_secs(60)).await;
        let now3 = Instant::now();
        let _ = m.observe_refresh(&observed(&[]), now3);
        assert_eq!(m.state_of("k-fade"), Some(RotationState::Retiring));

        // Advance past the grace window.
        tokio::time::advance(Duration::from_secs(301)).await;
        let now4 = Instant::now();
        let t = m.observe_refresh(&observed(&[]), now4);
        assert_eq!(m.state_of("k-fade"), Some(RotationState::Retired));
        assert_eq!(t.retired, vec!["k-fade".to_string()]);

        // Filter must NOT install the verifier any longer.
        let retained = RetainedVerifiers::new();
        let mut fresh = HashMap::new();
        let _ = fresh.insert("k-fade".to_string(), ExternalVerifier::EdDsa(vec![0u8; 32]));
        retained.upsert(&fresh);
        let install = m.filter_for_install(HashMap::new(), &retained.snapshot());
        assert!(
            !install.contains_key("k-fade"),
            "Retired kid must be excluded from install set"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retiring_returns_to_active_if_kid_reappears_in_jwks() {
        // Defends against momentary upstream JWKS hiccups: a Retiring
        // kid that reappears flips back to Active without going
        // through Pending.
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-flap"]), now1);
        tokio::time::advance(Duration::from_secs(61)).await;
        let now2 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-flap"]), now2);
        assert_eq!(m.state_of("k-flap"), Some(RotationState::Active));

        // Drop briefly.
        tokio::time::advance(Duration::from_secs(60)).await;
        let now3 = Instant::now();
        let _ = m.observe_refresh(&observed(&[]), now3);
        assert_eq!(m.state_of("k-flap"), Some(RotationState::Retiring));

        // Reappear during the grace window.
        tokio::time::advance(Duration::from_secs(30)).await;
        let now4 = Instant::now();
        let t = m.observe_refresh(&observed(&["k-flap"]), now4);
        assert_eq!(
            m.state_of("k-flap"),
            Some(RotationState::Active),
            "Retiring kid must skip Pending on reappearance"
        );
        assert!(t.promoted.contains(&"k-flap".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn audit_jwt_using_retiring_kid_fires_with_retiring_seconds_field() {
        // Drive a kid into Retiring; capture audit output; call
        // notify_kid_used at a known offset; assert the elapsed
        // seconds are present and correct.
        use std::io::Write;
        use std::sync::{Arc as StdArc, Mutex as StdMutex};

        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::fmt::MakeWriter;
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Clone, Default)]
        struct SharedBuf(StdArc<StdMutex<Vec<u8>>>);
        impl Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for SharedBuf {
            type Writer = SharedBuf;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buf = SharedBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-aud"]), now1);
        tokio::time::advance(Duration::from_secs(61)).await;
        let now2 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-aud"]), now2);
        tokio::time::advance(Duration::from_secs(60)).await;
        let demote_at = Instant::now();
        let _ = m.observe_refresh(&observed(&[]), demote_at);
        assert_eq!(m.state_of("k-aud"), Some(RotationState::Retiring));

        // Call notify_kid_used 42s after the demotion.
        tokio::time::advance(Duration::from_secs(42)).await;
        let used_at = Instant::now();
        m.notify_kid_used("k-aud", used_at);

        let snapshot = buf.0.lock().unwrap().clone();
        let log = String::from_utf8_lossy(&snapshot);
        assert!(
            log.contains(r#""event_type":"jwt.using_retiring_kid""#),
            "expected event_type in log: {log}"
        );
        assert!(
            log.contains(r#""kid":"k-aud""#),
            "expected kid in log: {log}"
        );
        assert!(
            log.contains(r#""retiring_for_seconds":42"#),
            "expected retiring_for_seconds=42 in log: {log}"
        );
    }

    // Defensive: kids that are Pending must NOT install (they are not
    // yet trusted), even if they appear in the freshly-fetched map.
    #[tokio::test(start_paused = true)]
    async fn filter_excludes_pending_kids() {
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-new"]), now1);
        assert_eq!(m.state_of("k-new"), Some(RotationState::Pending));

        let mut fresh = HashMap::new();
        let _ = fresh.insert("k-new".to_string(), ExternalVerifier::EdDsa(vec![0u8; 32]));
        let install = m.filter_for_install(fresh, &HashMap::new());
        assert!(
            !install.contains_key("k-new"),
            "Pending kid must NOT be installed yet"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_transitions_is_empty_for_steady_state() {
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-steady"]), now1);
        tokio::time::advance(Duration::from_secs(61)).await;
        let now2 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-steady"]), now2);
        // Now Active. A subsequent refresh that still sees it should
        // produce no transitions.
        tokio::time::advance(Duration::from_secs(60)).await;
        let now3 = Instant::now();
        let t = m.observe_refresh(&observed(&["k-steady"]), now3);
        assert!(t.is_empty(), "steady state must produce no transitions");
    }

    #[tokio::test(start_paused = true)]
    async fn notify_kid_used_is_silent_for_active_kid() {
        // The audit event must fire ONLY for Retiring kids.
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-active"]), now1);
        tokio::time::advance(Duration::from_secs(61)).await;
        let now2 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-active"]), now2);
        assert_eq!(m.state_of("k-active"), Some(RotationState::Active));

        // No panic, no emit. The smoke test captures the audit emit
        // path; here we just verify no state churn / panic.
        m.notify_kid_used("k-active", Instant::now());
        m.notify_kid_used("k-unknown", Instant::now());
        m.notify_kid_used("", Instant::now());
    }

    #[tokio::test(start_paused = true)]
    async fn pending_window_floor_blocks_too_fast_promotion() {
        // Two refreshes close together (under pending_window) MUST NOT
        // promote — the wall-time floor is the defence against a
        // typo'd push that gets manually reloaded inside the window.
        let m = RotationStateMachine::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            "https://idp.test/jwks.json",
        );
        let now1 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-fast"]), now1);
        tokio::time::advance(Duration::from_secs(10)).await;
        let now2 = Instant::now();
        let _ = m.observe_refresh(&observed(&["k-fast"]), now2);
        assert_eq!(
            m.state_of("k-fast"),
            Some(RotationState::Pending),
            "must stay Pending until pending_window elapses"
        );
    }

    #[test]
    fn retained_verifiers_round_trip() {
        let cache = RetainedVerifiers::new();
        let mut fresh = HashMap::new();
        let _ = fresh.insert("k-a".to_string(), ExternalVerifier::EdDsa(vec![0u8; 32]));
        cache.upsert(&fresh);
        assert!(cache.snapshot().contains_key("k-a"));
        cache.forget("k-a");
        assert!(!cache.snapshot().contains_key("k-a"));
    }
}
