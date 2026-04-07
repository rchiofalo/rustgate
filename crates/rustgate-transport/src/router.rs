//! Message routing engine.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rustgate_core::identity::{GroupId, Identity};
use rustgate_core::message::{Destination, MessageType, RoutableMessage};
use tokio::sync::{RwLock, mpsc};
use tracing::{Instrument, debug, warn};

use crate::acl::GroupAclPolicy;
use crate::backpressure::{BackpressureGate, BackpressurePermit};
use crate::cache::PositionCache;
use crate::dedup::DedupCache;

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
        Self {
            id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            identity,
            priority_sender: Arc::new(Mutex::new(Some(priority_sender))),
            normal_sender: Arc::new(Mutex::new(Some(normal_sender))),
            consecutive_drops: Arc::new(AtomicU32::new(0)),
            max_consecutive_drops: DEFAULT_MAX_CONSECUTIVE_DROPS,
        }
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
        Self {
            id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            identity,
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
        let mut guard = source.lock();
        let sender = match guard.as_ref() {
            Some(s) => s,
            None => return false,
        };
        match sender.try_send(msg) {
            Ok(()) => {
                self.consecutive_drops.store(0, Ordering::Relaxed);
                true
            }
            Err(_) => {
                let count = self.consecutive_drops.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= self.max_consecutive_drops {
                    warn!(
                        session = %self.identity.cn,
                        consecutive_drops = count,
                        threshold = self.max_consecutive_drops,
                        "circuit breaker tripped: disconnecting slow session"
                    );
                    *guard = None;
                    // Also close the other channel
                    let other = if Arc::ptr_eq(source, &self.priority_sender) {
                        &self.normal_sender
                    } else {
                        &self.priority_sender
                    };
                    let mut other_guard = other.lock();
                    *other_guard = None;
                }
                false
            }
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
    sessions: HashMap<String, SessionHandle>,
    groups: HashMap<GroupId, HashSet<String>>,
    max_groups_per_cn: usize,
    max_total_groups: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            sessions: HashMap::with_capacity(DEFAULT_SESSION_CAPACITY),
            groups: HashMap::with_capacity(DEFAULT_GROUP_CAPACITY),
            max_groups_per_cn: DEFAULT_MAX_GROUPS_PER_CN,
            max_total_groups: DEFAULT_MAX_TOTAL_GROUPS,
        }
    }
}

impl State {
    fn remove_from_groups(&mut self, cn: &str, groups: &std::collections::BTreeSet<GroupId>) {
        for group in groups {
            if let Some(members) = self.groups.get_mut(group) {
                let _ = members.remove(cn);
                if members.is_empty() {
                    let _ = self.groups.remove(group);
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct Router {
    state: RwLock<State>,
    cache: PositionCache,
    acl: ArcSwap<Option<GroupAclPolicy>>,
    backpressure: Option<Arc<BackpressureGate>>,
    dedup: ArcSwap<Option<DedupCache>>,
}

impl Default for Router {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
            cache: PositionCache::default(),
            acl: ArcSwap::from_pointee(None),
            backpressure: None,
            dedup: ArcSwap::from_pointee(None),
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
            backpressure: None,
            dedup: ArcSwap::from_pointee(None),
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
            backpressure: None,
            dedup: ArcSwap::from_pointee(None),
        }
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
            backpressure: None,
            dedup: ArcSwap::from_pointee(None),
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

    pub async fn register(&self, handle: SessionHandle) {
        let cn = handle.identity.cn.clone();
        let new_groups = handle.identity.groups.clone();

        let mut state = self.state.write().await;

        // Clean stale group entries if this CN was previously registered
        if let Some(old) = state.sessions.remove(&cn) {
            state.remove_from_groups(&cn, &old.identity.groups);
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

            let _ = state
                .groups
                .entry(group.clone())
                .or_default()
                .insert(cn.clone());
            joined += 1;
        }
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
        }
        drop(state);
        self.cache.remove(cn).await;
    }

    pub async fn route(&self, msg: RoutableMessage) {
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

        let destination_label = match &msg.destination {
            Destination::Direct(target) => target.cn.as_str(),
            Destination::Group(group) => group.as_ref(),
            Destination::Broadcast => "broadcast",
        };

        let span = tracing::debug_span!(
            "route",
            source_cn = %msg.source.cn,
            destination = %destination_label,
        );

        self.route_inner(msg, permit).instrument(span).await;
    }

    /// Inner routing logic, separated so the caller can `.instrument()` a span
    /// around this future without holding an `EnteredSpan` across `.await`.
    async fn route_inner(&self, msg: RoutableMessage, permit: Option<Arc<BackpressurePermit>>) {
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
            let guard = self.dedup.load();
            if let Some(ref dedup) = **guard
                && dedup.check_payload(&msg.payload)
            {
                debug!(
                    source = %msg.source.cn,
                    message_type = %msg.metadata.message_type,
                    "duplicate message suppressed by cross-path dedup",
                );
                return;
            }
        }

        // Cache position reports for SA replay to new sessions
        if msg.metadata.message_type == MessageType::Position {
            self.cache.store(msg.clone()).await;
        }

        // Drop messages that expired while waiting in the ingest pipeline
        if crate::cache::is_expired(&msg) {
            debug!(
                source = %msg.source.cn,
                message_type = %msg.metadata.message_type,
                "message expired before delivery — dropping",
            );
            return;
        }

        // Wrap in Arc once so broadcast/group sends share one allocation
        // instead of cloning the full RoutableMessage per recipient.
        let arc_msg = Arc::new(msg);
        let envelope = match permit {
            Some(p) => RoutedMessage::with_permit(arc_msg, p),
            None => RoutedMessage::new(arc_msg),
        };

        match envelope.destination.clone() {
            Destination::Direct(target) => {
                self.send_to_session(&target.cn, envelope).await;
            }
            Destination::Group(group) => {
                self.send_to_group(&group, envelope).await;
            }
            Destination::Broadcast => {
                self.send_to_all(envelope).await;
            }
        }
    }

    /// Replay cached positions to a newly connected session.
    /// Only replays positions from clients that share at least one group
    /// with the connecting session to enforce group-level isolation.
    pub async fn replay_positions(&self, handle: &SessionHandle) {
        let acl_guard = self.acl.load();
        let acl_ref: &Option<GroupAclPolicy> = &acl_guard;
        let mut dropped = 0u32;
        let mut total = 0u32;
        for msg in self.cache.get_all().await {
            let shared = msg
                .source
                .groups
                .intersection(&handle.identity.groups)
                .any(|g| {
                    acl_ref
                        .as_ref()
                        .is_none_or(|acl| acl.is_receive_authorized(g, &handle.identity.cn))
                });
            if shared || handle.identity.groups.is_empty() {
                total += 1;
                if handle.send(Arc::new(msg)).await.is_err() {
                    dropped += 1;
                }
            }
        }
        if dropped > 0 {
            warn!(
                session = %handle.identity.cn,
                dropped = dropped,
                total = total,
                "messages dropped during position replay: channel full or disconnected"
            );
        }
    }

    pub async fn session_count(&self) -> usize {
        self.state.read().await.sessions.len()
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

    async fn send_to_session(&self, cn: &str, msg: RoutedMessage) {
        let handle = {
            let state = self.state.read().await;
            state.sessions.get(cn).cloned()
        };
        if let Some(handle) = handle
            && handle.send(msg).await.is_err()
        {
            warn!(
                session = %cn,
                "message dropped: session channel full or disconnected"
            );
        }
    }

    async fn send_to_group(&self, group: &str, msg: RoutedMessage) {
        if !msg.source.is_member_of(group) {
            tracing::warn!(
                sender = %msg.source.cn,
                group = %group,
                "rejected cross-group message: sender not a member"
            );
            return;
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
            return;
        }

        let mut dropped = 0u32;
        let mut total = 0u32;
        {
            let state = self.state.read().await;
            let members = match state.groups.get(group) {
                Some(m) => m,
                None => return,
            };
            for handle in members
                .iter()
                .filter(|cn| *cn != &msg.source.cn)
                .filter(|cn| {
                    acl_ref
                        .as_ref()
                        .is_none_or(|acl| acl.is_receive_authorized(group, cn))
                })
                .filter_map(|cn| state.sessions.get(cn))
            {
                total += 1;
                if !handle.try_send(msg.clone()) {
                    dropped += 1;
                }
            }
            // `msg` is dropped at end of scope: the original envelope
            // clone held by `route_inner` is released here so the permit
            // count reflects only the surviving recipient clones that
            // now live inside the session mpsc channels.
        }
        if dropped > 0 {
            warn!(
                group = %group,
                dropped = dropped,
                total = total,
                "messages dropped during group send: channel full or disconnected"
            );
        }
    }

    /// Broadcast to all connected sessions (except sender).
    /// This is intentional for SA sharing — all authenticated clients
    /// receive broadcasts regardless of group membership.
    async fn send_to_all(&self, msg: RoutedMessage) {
        let targets: Vec<SessionHandle> = {
            let state = self.state.read().await;
            state
                .sessions
                .iter()
                .filter(|(cn, _)| *cn != &msg.source.cn)
                .map(|(_, handle)| handle.clone())
                .collect()
        };

        let mut dropped = 0u32;
        for handle in &targets {
            if handle.send(msg.clone()).await.is_err() {
                dropped += 1;
            }
        }
        if dropped > 0 {
            warn!(
                dropped = dropped,
                total = targets.len(),
                "messages dropped during broadcast: channel full or disconnected"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_results)]

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
        let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
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
        let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
        router.route(msg).await;

        // Alice (in alpha) receives chat on normal channel
        let received = nrx_a.try_recv().expect("alice must receive: both in alpha");
        assert_eq!(received.payload.as_ref(), b"<chat/>");
        assert_eq!(received.source.cn, "bob");

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

    #[tokio::test]
    async fn unregister_evicts_from_cache() {
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let (ptx, ntx, _prx, _nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(alice.clone(), ptx, ntx);
        let session_id = handle.id;

        router.register(handle).await;

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

        let cns: Vec<&str> = clients.iter().map(|c| c.cn.as_str()).collect();
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
            let msg = make_chat(&sender_id, Destination::Group("ops".to_string()));
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
        let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
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
        let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
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
        let msg = make_chat(&alice, Destination::Group("alpha".to_string()));
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

        let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
        router.route(msg).await;

        assert!(
            nrx_a.try_recv().is_ok(),
            "alice must receive: no ACL means open mode"
        );
    }

    #[tokio::test]
    async fn acl_open_for_unconfigured_group() {
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

        // "open-group" is not in the policy — should allow freely
        let msg = make_chat(&bob, Destination::Group("open-group".to_string()));
        router.route(msg).await;

        assert!(
            nrx_a.try_recv().is_ok(),
            "alice must receive: open-group has no ACL"
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
        let pos = make_position(&bob, Destination::Group("alpha".to_string()));
        router.route(pos).await;

        // Send an Alert message (priority)
        let alert = make_alert(&bob, Destination::Group("alpha".to_string()));
        router.route(alert).await;

        // Send a Chat message (normal)
        let chat = make_chat(&bob, Destination::Group("alpha".to_string()));
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
        let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
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
        let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
        router.route(msg).await;
        assert!(
            nrx_a.try_recv().is_err(),
            "alice must NOT receive: bob is no longer authorized after swap"
        );

        // Swap back to open mode
        router.swap_acl(None);

        let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
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
}
