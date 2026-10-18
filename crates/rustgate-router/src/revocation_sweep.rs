// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Mid-session revocation sweep (ADR 0025, piece 3).
//!
//! Client certificates are verified only at the TLS handshake, so a
//! long-lived session would otherwise survive both a later revocation and the
//! certificate's own expiry. [`RevocationSweeper`] periodically checks every
//! registered session and asks the ones whose certificate is now revoked or
//! expired to disconnect, through [`SessionHandle::request_evict`].
//!
//! - **Revoked:** the session's `(issuer CN, serial)` is in the current
//!   [`RevokedSet`], supplied by a [`RevokedSetFn`] (the TLS layer's CRL
//!   store). Matching is issuer-scoped.
//! - **Expired:** the certificate's `notAfter` is in the past. Skipped for a
//!   tick when [`ClockGuard`] sees the wall clock step relative to monotonic
//!   time, so a clock jump cannot mass-evict valid sessions.
//!
//! Each eviction emits a `session.evicted` audit event. The sweep is off by
//! default; `rustgate-server` starts it only when
//! `--revocation-sweep-interval` is non-zero.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustgate_core::identity::Identity;
use rustgate_core::masking::hash_cn;
use rustgate_core::revocation::{RevokedSet, cert_not_after};
use rustgate_core::tasks::SubsystemHandle;
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::router::{Router, SessionHandle};

/// Supplies the current revoked set on each sweep tick.
pub type RevokedSetFn = Arc<dyn Fn() -> Arc<RevokedSet> + Send + Sync>;

/// Wall-clock drift relative to monotonic time, per tick, beyond which the
/// expiry check is skipped for that tick.
pub const CLOCK_SKEW_TOLERANCE: Duration = Duration::from_secs(30);

/// Why a session was evicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictReason {
    /// The certificate is listed on a loaded CRL.
    Revoked,
    /// The certificate's `notAfter` has passed.
    Expired,
}

impl EvictReason {
    /// Stable token used in the `session.evicted` audit event.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

/// Decide whether one session must be evicted.
///
/// `now_unix` is the current wall-clock time in Unix seconds. `check_expiry`
/// is `false` on a tick where the clock guard tripped; revocation is still
/// checked because it does not depend on the clock.
#[must_use]
pub fn decide(
    identity: &Identity,
    revoked: &RevokedSet,
    now_unix: i64,
    check_expiry: bool,
) -> Option<EvictReason> {
    if revoked.is_revoked(identity) {
        return Some(EvictReason::Revoked);
    }
    if check_expiry && cert_not_after(identity).is_some_and(|not_after| not_after < now_unix) {
        return Some(EvictReason::Expired);
    }
    None
}

/// Detects a wall-clock step between sweep ticks.
///
/// Compares how far the wall clock moved with how far monotonic time moved
/// since the previous tick. A difference beyond the tolerance means the wall
/// clock was set (forward or backward), so wall-clock expiry decisions for
/// that tick are not trusted.
#[derive(Debug)]
pub struct ClockGuard {
    tolerance: Duration,
    last: Option<(Instant, SystemTime)>,
}

impl ClockGuard {
    /// A guard with the given tolerance.
    #[must_use]
    pub fn new(tolerance: Duration) -> Self {
        Self {
            tolerance,
            last: None,
        }
    }

    /// Record a tick at `(mono, wall)`. Returns `Err(drift_secs)` when the
    /// wall clock drifted more than the tolerance since the previous tick;
    /// the first tick always passes.
    pub fn check(&mut self, mono: Instant, wall: SystemTime) -> Result<(), i64> {
        let previous = self.last.replace((mono, wall));
        let Some((last_mono, last_wall)) = previous else {
            return Ok(());
        };
        let mono_elapsed = signed_secs(mono.saturating_duration_since(last_mono));
        let wall_elapsed = match wall.duration_since(last_wall) {
            Ok(d) => signed_secs(d),
            Err(e) => signed_secs(e.duration()).saturating_neg(),
        };
        let drift = wall_elapsed.saturating_sub(mono_elapsed);
        if drift.unsigned_abs() > self.tolerance.as_secs() {
            Err(drift)
        } else {
            Ok(())
        }
    }
}

fn signed_secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

/// Current wall-clock time in Unix seconds, or `None` before the epoch (a
/// clock that far off is not trusted for expiry).
fn unix_now(wall: SystemTime) -> Option<i64> {
    wall.duration_since(UNIX_EPOCH).ok().map(signed_secs)
}

/// Periodically evicts sessions whose certificate is revoked or expired.
pub struct RevocationSweeper {
    router: Arc<Router>,
    revoked: Option<RevokedSetFn>,
    clock: ClockGuard,
    /// Sessions already asked to disconnect. A session stays registered
    /// until its teardown finishes (an MQTT 5 DISCONNECT write is bounded by
    /// `WRITE_TIMEOUT`), so without this every tick would signal and audit it
    /// again.
    signalled: HashSet<u64>,
}

impl std::fmt::Debug for RevocationSweeper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationSweeper")
            .field("has_revoked_source", &self.revoked.is_some())
            .field("clock", &self.clock)
            .field("signalled", &self.signalled.len())
            .finish_non_exhaustive()
    }
}

impl RevocationSweeper {
    /// A sweeper over `router`'s sessions. With `revoked = None` (no
    /// refreshable CRL source) only expiry is enforced.
    #[must_use]
    pub fn new(router: Arc<Router>, revoked: Option<RevokedSetFn>) -> Self {
        Self {
            router,
            revoked,
            clock: ClockGuard::new(CLOCK_SKEW_TOLERANCE),
            signalled: HashSet::new(),
        }
    }

    /// Run one sweep and return the sessions newly asked to disconnect. A
    /// session signalled by an earlier sweep is not signalled again.
    pub async fn sweep_once(&mut self) -> Vec<(SessionHandle, EvictReason)> {
        let wall = SystemTime::now();
        let clock_ok = match self.clock.check(Instant::now(), wall) {
            Ok(()) => true,
            Err(drift) => {
                warn!(
                    drift_secs = drift,
                    "wall clock stepped; skipping certificate-expiry eviction this sweep"
                );
                rustgate_core::audit::revocation_sweep_clock_skew(drift);
                false
            }
        };
        let now = unix_now(wall);
        let check_expiry = clock_ok && now.is_some();
        let now = now.unwrap_or(0);
        let revoked = self
            .revoked
            .as_ref()
            .map_or_else(|| Arc::new(RevokedSet::new()), |f| f());

        let handles = self.router.session_handles().await;
        // Forget sessions that have since unregistered, so the set stays
        // bounded by the live session count.
        let live: HashSet<u64> = handles.iter().map(|h| h.id).collect();
        self.signalled.retain(|id| live.contains(id));

        let mut evicted = Vec::new();
        for handle in handles {
            if self.signalled.contains(&handle.id) {
                continue;
            }
            if let Some(reason) = decide(&handle.identity, &revoked, now, check_expiry) {
                info!(
                    cn = %hash_cn(&handle.identity.cn),
                    session_id = handle.id,
                    reason = reason.as_str(),
                    "evicting session"
                );
                rustgate_core::audit::session_evicted(
                    &handle.identity.cn,
                    handle.id,
                    reason.as_str(),
                );
                handle.request_evict();
                let _ = self.signalled.insert(handle.id);
                evicted.push((handle, reason));
            }
        }
        evicted
    }

    /// Run [`sweep_once`](Self::sweep_once) every `interval` until stopped.
    /// The first sweep runs one `interval` after start.
    #[must_use]
    pub fn spawn(mut self, interval: Duration) -> SubsystemHandle {
        let shutdown = Arc::new(Notify::new());
        let stop = Arc::clone(&shutdown);
        let task = tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = stop.notified() => break,
                    _ = ticker.tick() => {
                        let _ = self.sweep_once().await;
                    }
                }
            }
        });
        SubsystemHandle::new(shutdown, task)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::{BTreeMap, BTreeSet};

    use rustgate_core::identity::AttrValue;
    use rustgate_core::revocation::{ATTR_CERT_NOT_AFTER, ATTR_CERT_SERIAL, ATTR_ISSUER_CN};

    use super::*;

    fn identity(cn: &str, issuer: &str, serial: &str, not_after: Option<i64>) -> Identity {
        let mut attrs = BTreeMap::new();
        let _ = attrs.insert(ATTR_ISSUER_CN.into(), AttrValue::Str(issuer.into()));
        let _ = attrs.insert(ATTR_CERT_SERIAL.into(), AttrValue::Str(serial.into()));
        if let Some(t) = not_after {
            let _ = attrs.insert(ATTR_CERT_NOT_AFTER.into(), AttrValue::Int(t));
        }
        Identity::new(cn.into(), "fp".into(), BTreeSet::new())
            .unwrap()
            .with_attributes(attrs)
    }

    fn revoked(entries: &[(&str, &[u8])]) -> RevokedSet {
        let mut set = RevokedSet::new();
        for (issuer, serial) in entries {
            set.insert(issuer, serial);
        }
        set
    }

    #[test]
    fn decide_evicts_revoked_and_expired_only() {
        let set = revoked(&[("CA", &[0x01])]);
        let now = 1_000;
        assert_eq!(
            decide(&identity("a", "CA", "01", Some(5_000)), &set, now, true),
            Some(EvictReason::Revoked)
        );
        assert_eq!(
            decide(&identity("b", "CA", "02", Some(999)), &set, now, true),
            Some(EvictReason::Expired)
        );
        assert_eq!(
            decide(&identity("c", "CA", "02", Some(5_000)), &set, now, true),
            None
        );
        // No notAfter recorded: never evicted for expiry.
        assert_eq!(
            decide(&identity("d", "CA", "02", None), &set, now, true),
            None
        );
    }

    #[test]
    fn decide_is_issuer_scoped() {
        let set = revoked(&[("CA One", &[0x01])]);
        assert_eq!(
            decide(&identity("a", "CA Two", "01", None), &set, 0, true),
            None
        );
    }

    #[test]
    fn decide_skips_expiry_but_not_revocation_when_clock_untrusted() {
        let set = revoked(&[("CA", &[0x01])]);
        assert_eq!(
            decide(&identity("b", "CA", "02", Some(1)), &set, 1_000, false),
            None
        );
        assert_eq!(
            decide(&identity("a", "CA", "01", Some(1)), &set, 1_000, false),
            Some(EvictReason::Revoked)
        );
    }

    #[test]
    fn clock_guard_trips_on_wall_clock_steps() {
        let mut guard = ClockGuard::new(Duration::from_secs(30));
        let mono = Instant::now();
        let wall = UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(guard.check(mono, wall), Ok(()), "first tick always passes");
        // Normal tick: both clocks advance 60s.
        assert_eq!(
            guard.check(
                mono + Duration::from_secs(60),
                wall + Duration::from_secs(60)
            ),
            Ok(())
        );
        // Wall clock jumps forward a day while only 60s of real time passed.
        assert!(
            guard
                .check(
                    mono + Duration::from_secs(120),
                    wall + Duration::from_secs(86_460)
                )
                .is_err()
        );
        // Wall clock steps backward.
        assert!(
            guard
                .check(
                    mono + Duration::from_secs(180),
                    wall + Duration::from_secs(80_000)
                )
                .is_err()
        );
        // Small jitter within tolerance is fine.
        assert_eq!(
            guard.check(
                mono + Duration::from_secs(240),
                wall + Duration::from_secs(80_070)
            ),
            Ok(())
        );
    }

    fn handle_for(identity: Identity) -> SessionHandle {
        let (ptx, _prx) = tokio::sync::mpsc::channel(4);
        let (ntx, _nrx) = tokio::sync::mpsc::channel(4);
        SessionHandle::new(Arc::new(identity), ptx, ntx)
    }

    async fn signalled(handle: &SessionHandle) -> bool {
        let signal = handle.evict_signal();
        tokio::time::timeout(Duration::from_millis(50), signal.notified())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn sweep_once_signals_only_revoked_and_expired_sessions() {
        let router = Arc::new(Router::new());
        let far = 4_000_000_000;
        let revoked_h = handle_for(identity("revoked", "CA", "01", Some(far)));
        let expired_h = handle_for(identity("expired", "CA", "03", Some(1)));
        let valid_h = handle_for(identity("valid", "CA", "02", Some(far)));
        for h in [&revoked_h, &expired_h, &valid_h] {
            assert!(router.register(h.clone()).await);
        }
        let set = Arc::new(revoked(&[("CA", &[0x01])]));
        let source: RevokedSetFn = Arc::new(move || Arc::clone(&set));
        let mut sweeper = RevocationSweeper::new(Arc::clone(&router), Some(source));

        let mut evicted: Vec<_> = sweeper
            .sweep_once()
            .await
            .into_iter()
            .map(|(h, r)| (h.identity.cn.to_string(), r))
            .collect();
        evicted.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            evicted,
            vec![
                ("expired".to_string(), EvictReason::Expired),
                ("revoked".to_string(), EvictReason::Revoked),
            ]
        );
        assert!(signalled(&revoked_h).await);
        assert!(signalled(&expired_h).await);
        assert!(!signalled(&valid_h).await);
    }

    #[tokio::test]
    async fn a_displaced_session_for_the_same_cn_is_still_swept() {
        // A second connection with the same certificate replaces the first in
        // the CN-keyed session map, but the first stays connected. Both must
        // be evicted once the certificate is revoked.
        let router = Arc::new(Router::new());
        let far = 4_000_000_000;
        let first = handle_for(identity("alice", "CA", "01", Some(far)));
        let second = handle_for(identity("alice", "CA", "01", Some(far)));
        assert!(router.register(first.clone()).await);
        assert!(router.register(second.clone()).await);

        let set = Arc::new(revoked(&[("CA", &[0x01])]));
        let source: RevokedSetFn = Arc::new(move || Arc::clone(&set));
        let mut sweeper = RevocationSweeper::new(Arc::clone(&router), Some(source));
        assert_eq!(sweeper.sweep_once().await.len(), 2);
        assert!(signalled(&first).await);
        assert!(signalled(&second).await);

        // The displaced session leaving does not drop the current one.
        router.unregister("alice", first.id).await;
        assert_eq!(router.session_handles().await.len(), 1);
        router.unregister("alice", second.id).await;
        assert!(router.session_handles().await.is_empty());
    }

    #[tokio::test]
    async fn a_session_still_tearing_down_is_signalled_once() {
        let router = Arc::new(Router::new());
        let expired_h = handle_for(identity("expired", "CA", "03", Some(1)));
        assert!(router.register(expired_h.clone()).await);
        let mut sweeper = RevocationSweeper::new(Arc::clone(&router), None);
        assert_eq!(sweeper.sweep_once().await.len(), 1);
        // Still registered on the next tick: not signalled or audited again.
        assert!(sweeper.sweep_once().await.is_empty());

        // Once it unregisters, its id is forgotten.
        router
            .unregister(&expired_h.identity.cn, expired_h.id)
            .await;
        assert!(sweeper.sweep_once().await.is_empty());
        assert!(sweeper.signalled.is_empty());
    }

    #[tokio::test]
    async fn evicting_a_stale_handle_does_not_touch_its_replacement() {
        // The signal is per session: a sweep that acted on an old snapshot
        // of "alice" must not disconnect the session that replaced it.
        let far = 4_000_000_000;
        let old = handle_for(identity("alice", "CA", "01", Some(far)));
        let replacement = handle_for(identity("alice", "CA", "01", Some(far)));
        assert_ne!(old.id, replacement.id);
        old.request_evict();
        assert!(signalled(&old).await);
        assert!(!signalled(&replacement).await);
    }

    #[tokio::test]
    async fn without_a_revoked_source_only_expiry_is_enforced() {
        let router = Arc::new(Router::new());
        let expired_h = handle_for(identity("expired", "CA", "03", Some(1)));
        assert!(router.register(expired_h.clone()).await);
        let mut sweeper = RevocationSweeper::new(Arc::clone(&router), None);
        let evicted = sweeper.sweep_once().await;
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].1, EvictReason::Expired);
    }

    #[test]
    fn evict_reason_tokens_are_stable() {
        assert_eq!(EvictReason::Revoked.as_str(), "revoked");
        assert_eq!(EvictReason::Expired.as_str(), "expired");
    }
}
