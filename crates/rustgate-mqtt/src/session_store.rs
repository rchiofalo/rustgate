// Copyright © 2026 Roberto Chiofalo.

//! In-memory MQTT session retention store.
//!
//! MQTT 5.0 §4.1 Session State + §3.1.2.11.2 Session Expiry Interval.
//! Stores per-client subscription state across disconnect → reconnect
//! windows so a client that requested non-zero `Session Expiry
//! Interval` and reconnects with `clean_start = 0` within the window
//! sees its subscriptions restored without having to re-issue
//! SUBSCRIBE.
//!
//! # Out of scope (intentionally — see PR description)
//!
//! - **Inflight QoS 1 / QoS 2 message persistence** — the QoS 2
//!   four-step's PUBLISH/PUBREL inflight state (#1161) lives in the
//!   read loop and is dropped on disconnect; restoring it would
//!   require also persisting the inbound publish-bookkeeping which
//!   is a separate piece of state. A future PR can extend the
//!   `RetainedSession` struct with an `inflight_qos2` field.
//! - **Broker-restart persistence** — the store is in-memory only.
//!   A future PR can layer a `redb`-backed implementation behind a
//!   trait if operators need cross-restart durability; the in-memory
//!   path stays the default for tactical deployments where broker
//!   uptime is the load-bearing assumption.
//! - **Will-message timing for non-zero session expiry** — MQTT 5.0
//!   §3.1.2.5 says the broker MUST delay publishing the will until
//!   either the session ends OR `Will Delay Interval` elapses,
//!   whichever comes first. This PR continues to publish the will
//!   on disconnect (the existing behaviour) which is technically
//!   only spec-compliant for `Will Delay Interval = 0`. A separate
//!   PR adds the delay timer.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// One per-filter subscription saved from a previous session.
///
/// Subscriptions are saved post-validation: the topic filter has
/// already been resolved to a `group` name and the operator's
/// authorization gate has passed. Storing the resolved group rather
/// than the original filter means restoration doesn't have to re-run
/// the topic-prefix-strip / wildcard-policy / authz pipeline that
/// might have been reconfigured between disconnect and reconnect —
/// the saved state reflects what was authorized at the time the
/// SUBSCRIBE was accepted, which matches the MQTT 5.0 §4.1 contract
/// that a stored session preserves the authorisations granted to
/// the client at SUBSCRIBE time.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RetainedSubscription {
    /// Resolved group name (post-prefix-strip, post-validation).
    pub(crate) group: String,
    /// Maximum QoS the subscriber requested for this filter.
    /// Stored as the `mqttbytes::QoS`-equivalent `u8` value
    /// (`0`, `1`, or `2`) so the store has no dependency on the
    /// `mqttbytes` enum and a future protocol-version migration
    /// stays decoupled.
    pub(crate) qos: u8,
}

/// Saved per-client session state.
///
/// Created when a session ends with a non-zero
/// `Session Expiry Interval`; consumed (and removed from the store)
/// when the same client reconnects with `clean_start = 0` within the
/// expiry window.
#[derive(Debug, Clone)]
pub(crate) struct RetainedSession {
    pub(crate) subscriptions: Vec<RetainedSubscription>,
    /// Wall-clock instant the session was saved. The session is
    /// considered expired when `saved_at + expiry_secs` has passed.
    /// Uses [`Instant`] (monotonic) rather than [`std::time::SystemTime`]
    /// so a wall-clock jump between disconnect and reconnect cannot
    /// drop a session prematurely or extend it.
    pub(crate) saved_at: Instant,
    /// Negotiated expiry from the disconnecting CONNECT (clamped to
    /// the operator's configured maximum). Special value
    /// `u32::MAX` means "never expires" per MQTT 5.0 §3.1.2.11.2;
    /// the reaper treats it as a sentinel and never drops it (only
    /// the hard `max_retained_sessions` cap evicts).
    pub(crate) expiry_secs: u32,
}

impl RetainedSession {
    /// Returns true if the session has passed its expiry window.
    /// `expiry_secs == u32::MAX` is the spec's "never expires"
    /// sentinel and always returns false here — the reaper never
    /// drops these; only the hard session-count cap evicts them
    /// under memory pressure.
    pub(crate) fn is_expired(&self, now: Instant) -> bool {
        if self.expiry_secs == u32::MAX {
            return false;
        }
        let elapsed = now.saturating_duration_since(self.saved_at);
        elapsed >= Duration::from_secs(u64::from(self.expiry_secs))
    }
}

/// In-memory store for retained MQTT sessions, keyed by client id.
///
/// All operations take `&self` and lock internally; the store is
/// `Send + Sync` and shared via `Arc` between accept loop, per-
/// session tasks, and the background reaper. Internal locking uses
/// `parking_lot::Mutex` (no poisoning, no `.unwrap()` on lock,
/// short critical sections — the per-session save/take is O(1) and
/// the reaper sweep is O(n) over the retained-session set which is
/// bounded by `max_sessions`).
#[derive(Debug)]
pub(crate) struct SessionStore {
    inner: Mutex<HashMap<String, RetainedSession>>,
    max_sessions: usize,
}

impl SessionStore {
    /// Build a new store with the given hard cap on retained sessions.
    ///
    /// `max_sessions = 0` is a legal "retention disabled" sentinel — the
    /// store accepts no saves and `take` always returns None, so a
    /// deployment that opts out of retention pays only the cost of an
    /// empty `HashMap` and a cheap branch on each save attempt.
    pub(crate) fn new(max_sessions: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            max_sessions,
        })
    }

    /// Returns true if retention is enabled (i.e. `max_sessions > 0`).
    pub(crate) fn is_enabled(&self) -> bool {
        self.max_sessions > 0
    }

    /// Save a session. Returns `true` if the entry was inserted (or
    /// replaced an existing one for the same client_id), `false` if
    /// the store was full and no eviction was possible.
    ///
    /// Eviction policy when the store is full and the client_id is
    /// not already present: the oldest (lowest `saved_at`) entry is
    /// evicted. This is a conservative LRU-by-disconnect-time —
    /// fairer than refusing the new session, which would punish the
    /// most recent disconnects (typically the most operationally
    /// important — the client just left, so the operator is more
    /// likely to be debugging it).
    ///
    /// A `client_id` already present in the store is overwritten
    /// regardless of the cap — the previous session is implicitly
    /// retired by the new one. This matches the MQTT 5.0 §3.1.4
    /// "Server takeover" semantics that say a new connection from
    /// the same client_id MUST take over from the existing session.
    pub(crate) fn save(&self, client_id: String, session: RetainedSession) -> bool {
        if self.max_sessions == 0 {
            return false;
        }
        let mut guard = self.inner.lock();
        if let std::collections::hash_map::Entry::Occupied(mut e) = guard.entry(client_id.clone()) {
            // Overwrite — server takeover; cap doesn't apply. The
            // `let _ = ...` discards the prior value's `RetainedSession`
            // — we intentionally ignore the previous entry's contents
            // because the new session supersedes it per §3.1.4.
            let _ = e.insert(session);
            return true;
        }
        if guard.len() >= self.max_sessions {
            // Evict the oldest entry to make room. Find it first so
            // the borrow-checker is happy across the remove.
            if let Some(oldest_id) = guard
                .iter()
                .min_by_key(|(_, s)| s.saved_at)
                .map(|(id, _)| id.clone())
            {
                let _ = guard.remove(&oldest_id);
            } else {
                // Shouldn't happen — len > 0 implies at least one entry —
                // but the iterator min could in principle return None on
                // an inconsistent state (e.g. a future change to the
                // backing map). Fail closed: refuse the save rather than
                // panic.
                return false;
            }
        }
        let _ = guard.insert(client_id, session);
        true
    }

    /// Take a saved session, removing it from the store.
    ///
    /// Returns `None` if no session exists for this client_id, or if
    /// the saved session has expired (in which case the expired
    /// entry is also removed as a side effect — the take path is
    /// the natural place to opportunistically reap stale entries
    /// without waiting for the background reaper sweep).
    pub(crate) fn take(&self, client_id: &str) -> Option<RetainedSession> {
        if self.max_sessions == 0 {
            return None;
        }
        let mut guard = self.inner.lock();
        let session = guard.remove(client_id)?;
        if session.is_expired(Instant::now()) {
            // Don't return an expired session; just drop it. The
            // caller treats this exactly like a fresh client_id.
            return None;
        }
        Some(session)
    }

    /// Reap expired sessions. Returns the number of entries dropped.
    ///
    /// Called periodically by the background reaper task. The sweep
    /// holds the lock for O(n) where n is the number of retained
    /// sessions — capped at `max_sessions` so worst-case is bounded.
    pub(crate) fn reap_expired(&self) -> usize {
        if self.max_sessions == 0 {
            return 0;
        }
        let now = Instant::now();
        let mut guard = self.inner.lock();
        let before = guard.len();
        guard.retain(|_, session| !session.is_expired(now));
        before - guard.len()
    }

    /// Number of currently-retained sessions. Mainly useful for
    /// metrics + tests; the reaper also uses it to decide whether
    /// to log a sweep result.
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    fn make_session(secs: u32, age_secs: u64) -> RetainedSession {
        RetainedSession {
            subscriptions: vec![RetainedSubscription {
                group: "alpha".into(),
                qos: 1,
            }],
            saved_at: Instant::now() - Duration::from_secs(age_secs),
            expiry_secs: secs,
        }
    }

    #[test]
    fn store_with_zero_max_sessions_is_disabled() {
        // The "retention disabled" sentinel: max_sessions=0 means
        // every save fails and every take returns None. Operators
        // who don't want retention pay only a cheap-branch cost.
        let store = SessionStore::new(0);
        assert!(!store.is_enabled());
        assert!(!store.save("alice".into(), make_session(60, 0)));
        assert!(store.take("alice").is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn save_and_take_round_trips_subscriptions() {
        let store = SessionStore::new(8);
        let session = RetainedSession {
            subscriptions: vec![
                RetainedSubscription {
                    group: "alpha".into(),
                    qos: 1,
                },
                RetainedSubscription {
                    group: "bravo".into(),
                    qos: 0,
                },
            ],
            saved_at: Instant::now(),
            expiry_secs: 60,
        };
        assert!(store.save("client-1".into(), session.clone()));
        assert_eq!(store.len(), 1);

        let restored = store.take("client-1").expect("session present");
        assert_eq!(restored.subscriptions, session.subscriptions);
        assert_eq!(store.len(), 0, "take must remove the entry");

        // Second take returns None — the session is gone.
        assert!(store.take("client-1").is_none());
    }

    #[test]
    fn take_drops_expired_session() {
        // A session whose expiry has already passed must NOT be
        // returned by take; drop it transparently. Otherwise a
        // client reconnecting an hour after a 30-second expiry
        // would resume a session it had no spec-defined right to
        // resume, defeating the point of the expiry mechanism.
        let store = SessionStore::new(8);
        let session = make_session(10, 60); // 10s expiry, saved 60s ago
        assert!(store.save("zombie".into(), session));
        assert!(
            store.take("zombie").is_none(),
            "expired session must not resume"
        );
    }

    #[test]
    fn never_expires_sentinel_survives_take() {
        // u32::MAX is the spec's "never expires" sentinel; the
        // entry must survive any age. Pin that the take path
        // honors it (the reaper test below pins the reaper side).
        let store = SessionStore::new(8);
        let session = make_session(u32::MAX, 86_400 * 7); // 7 days old
        assert!(store.save("forever".into(), session));
        assert!(store.take("forever").is_some());
    }

    #[test]
    fn reap_expired_drops_only_expired_entries() {
        let store = SessionStore::new(8);
        store.save("expired-1".into(), make_session(10, 60));
        store.save("expired-2".into(), make_session(10, 60));
        store.save("alive".into(), make_session(3600, 5));
        store.save("immortal".into(), make_session(u32::MAX, 86_400 * 30));

        let dropped = store.reap_expired();
        assert_eq!(dropped, 2);
        assert_eq!(store.len(), 2);
        assert!(store.take("alive").is_some());
        assert!(store.take("immortal").is_some());
    }

    #[test]
    fn save_overwrites_existing_client_id_regardless_of_cap() {
        // MQTT 5.0 §3.1.4 server-takeover: a new connection from
        // the same client_id retires the previous session. The
        // store mirrors this — overwriting an existing entry is
        // not subject to the eviction cap (the previous entry is
        // implicitly retired, so the count doesn't grow).
        let store = SessionStore::new(2);
        let initial = RetainedSession {
            subscriptions: vec![RetainedSubscription {
                group: "old".into(),
                qos: 0,
            }],
            saved_at: Instant::now(),
            expiry_secs: 60,
        };
        let updated = RetainedSession {
            subscriptions: vec![RetainedSubscription {
                group: "new".into(),
                qos: 2,
            }],
            saved_at: Instant::now(),
            expiry_secs: 60,
        };
        store.save("alice".into(), initial);
        store.save("bob".into(), make_session(60, 0)); // store now full

        // Overwriting "alice" must succeed even though store is at cap.
        assert!(store.save("alice".into(), updated.clone()));
        assert_eq!(store.len(), 2);

        let restored = store.take("alice").expect("alice still present");
        assert_eq!(restored.subscriptions[0].group, "new");
    }

    #[test]
    fn save_at_capacity_evicts_oldest() {
        // When a NEW client_id arrives at a full store, evict the
        // oldest by `saved_at`. Pin both the eviction outcome and
        // the LRU choice — a regression that evicted the newest
        // would punish recent disconnects.
        let store = SessionStore::new(2);
        let now = Instant::now();
        store.save(
            "oldest".into(),
            RetainedSession {
                subscriptions: Vec::new(),
                saved_at: now - Duration::from_secs(120),
                expiry_secs: 600,
            },
        );
        store.save(
            "middle".into(),
            RetainedSession {
                subscriptions: Vec::new(),
                saved_at: now - Duration::from_secs(60),
                expiry_secs: 600,
            },
        );
        // Store is full. Add a new entry — "oldest" must be evicted.
        assert!(store.save(
            "newest".into(),
            RetainedSession {
                subscriptions: Vec::new(),
                saved_at: now,
                expiry_secs: 600,
            }
        ));
        assert_eq!(store.len(), 2);
        assert!(
            store.take("oldest").is_none(),
            "LRU eviction must drop the oldest entry"
        );
    }

    #[test]
    fn is_expired_treats_max_u32_as_never() {
        let session = make_session(u32::MAX, 86_400 * 365); // 1 year
        assert!(
            !session.is_expired(Instant::now()),
            "u32::MAX expiry sentinel must never expire (§3.1.2.11.2)"
        );
    }

    #[test]
    fn is_expired_uses_monotonic_clock_via_instant() {
        // Pin that we use Instant (monotonic), not SystemTime
        // (wall-clock). A session saved with Instant::now() and
        // checked against an Instant in the future cannot be
        // tricked by a wall-clock jump (NTP slew, manual clock
        // change, leap seconds). The test exercises the contract
        // type-wise; the field type itself enforces it.
        let session = make_session(60, 30); // 60s expiry, 30s old
        assert!(!session.is_expired(Instant::now()));
        let session = make_session(60, 90); // 60s expiry, 90s old → expired
        assert!(session.is_expired(Instant::now()));
    }

    #[test]
    fn store_is_send_sync_for_arc_sharing() {
        // The store must be Send + Sync to be wrapped in Arc and
        // shared across the accept loop, per-session tasks, and
        // the background reaper. A future refactor that introduced
        // a non-Send field would break this contract; pin it here
        // with a static assertion.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SessionStore>();
        assert_send_sync::<Arc<SessionStore>>();
    }
}
