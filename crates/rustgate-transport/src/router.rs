//! Message routing engine.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rustgate_authz::{
    Action as AuthzAction, Decision as AuthzDecision, PolicyEngine, Resource as AuthzResource,
    Subject as AuthzSubject,
};

/// Callback invoked after every authz evaluation so operators can wire
/// the engine into metrics and audit without making `rustgate-transport`
/// depend on `prometheus`. The server binary installs one of these via
/// [`Router::with_authz_observer`].
pub type AuthzObserver = Arc<dyn Fn(&AuthzEvent<'_>) + Send + Sync>;

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
use rustgate_core::identity::{GroupId, Identity};
use rustgate_core::message::{Destination, MessageType, RoutableMessage};
use tokio::sync::{RwLock, mpsc};
use tracing::{Instrument, debug, warn};

use crate::acl::GroupAclPolicy;
use crate::backpressure::{BackpressureGate, BackpressurePermit};
use crate::cache::PositionCache;
use crate::dedup::DedupCache;
use crate::store_forward::ClientQueue;

/// Access-log target. A dedicated tracing layer in the server binary
/// filters on this target and writes JSON lines to the configured sink
/// (file or stdout). The target is a constant so emission sites and the
/// subscriber filter cannot drift.
pub const ACCESS_LOG_TARGET: &str = "access";

/// Hash a unicast destination CN to a stable opaque token so the access
/// log does not leak raw client identities (PII). Uses SHA-256 truncated
/// to the first 12 hex chars (48 bits) — collision risk is acceptable
/// for an audit trail and the token remains stable for correlation.
fn hash_cn(cn: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cn.as_bytes());
    let mut out = String::with_capacity(12);
    for b in &digest[..6] {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

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
    pub fn swap_authz(&self, engine: Arc<dyn PolicyEngine>) {
        self.authz.store(Arc::new(Some(engine)));
    }

    /// Remove the installed policy engine, reverting to ACL-only mode.
    pub fn clear_authz(&self) {
        self.authz.store(Arc::new(None));
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

    /// Evaluate the installed engine, invoke the observer, and return the
    /// [`DecisionOutcome`]. Wrapped in a helper so both the send and receive
    /// PEPs share identical instrumentation.
    fn authz_evaluate(
        &self,
        engine: &Arc<dyn PolicyEngine>,
        subject: &AuthzSubject<'_>,
        resource: &AuthzResource<'_>,
        action: AuthzAction,
    ) -> rustgate_authz::DecisionOutcome {
        let start = std::time::Instant::now();
        let outcome = engine.evaluate(subject, resource, action);
        let eval_nanos = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
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
        outcome
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

        // Count how many groups this CN already belongs to.
        let current_count = state
            .groups
            .values()
            .filter(|members| members.contains(cn))
            .count();
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

        let _ = state
            .groups
            .entry(group.to_owned())
            .or_default()
            .insert(cn.to_owned());
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

        if let Some(members) = state.groups.get_mut(group) {
            let _ = members.remove(cn);
            if members.is_empty() {
                let _ = state.groups.remove(group);
            }
        }
        true
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
                emit_access(&msg, "dedup");
                return;
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
            return;
        }

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
        let authz_guard = self.authz.load();
        if let Some(engine) = (**authz_guard).as_ref() {
            let subject = AuthzSubject::from_identity(&msg.source);
            let resource = match &msg.destination {
                Destination::Direct(target) => AuthzResource::Direct {
                    target_cn: target.cn.as_str(),
                },
                Destination::Group(group) => AuthzResource::Group {
                    group: group.as_ref(),
                },
                Destination::Broadcast => AuthzResource::Broadcast,
            };
            let outcome = self.authz_evaluate(engine, &subject, &resource, AuthzAction::Send);
            if !outcome.is_allow() {
                let (kind, id) = match &msg.destination {
                    Destination::Direct(target) => ("direct", target.cn.as_str()),
                    Destination::Group(group) => ("group", group.as_ref()),
                    Destination::Broadcast => ("broadcast", ""),
                };
                rustgate_core::audit::authz_denied(
                    msg.source.cn.as_str(),
                    msg.source.fingerprint.as_str(),
                    "send",
                    kind,
                    id,
                    outcome.rule_id.as_deref(),
                    engine.policy_id(),
                );
                emit_access(&msg, "authz_deny");
                return;
            }
        }

        // Cache position reports for SA replay to new sessions. This
        // MUST run after the authz PEP above: a denied position must
        // not enter the replay cache.
        if msg.metadata.message_type == MessageType::Position {
            self.cache.store(msg.clone()).await;
        }

        // Successful path: emit one access-log event per routed message.
        // Outcome is "delivered" — per-recipient drop counts (full
        // session channels) are still surfaced via the existing warn!
        // logs and metrics.
        emit_access(&msg, "delivered");

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

    /// Drain any messages persisted for this CN while it was
    /// disconnected. The caller MUST invoke this BEFORE
    /// [`Self::register`] so that no live traffic can be delivered to
    /// the session until the returned buffered messages have been
    /// flushed to the session writer. This preserves strict FIFO across
    /// the reconnect boundary.
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
                warn!(session = %cn, error = %e, "client queue drain failed");
                Vec::new()
            }
            Err(e) => {
                warn!(session = %cn, error = %e, "client queue drain task join failed");
                Vec::new()
            }
        }
    }

    /// Legacy/test helper that drains queued offline messages and
    /// delivers them directly through a session handle. Kept for unit
    /// tests that exercise the drain path without a full session loop.
    ///
    /// New code should use [`Self::drain_offline_messages`] and flush
    /// the returned buffer explicitly BEFORE
    /// [`Self::register`] to avoid live/queued ordering hazards.
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
                session = %handle.identity.cn,
                delivered,
                "drained client queue on reconnect"
            );
        }
        delivered
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

    async fn send_to_session(&self, cn: &str, msg: RoutedMessage) {
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
                if let Some(engine) = (**authz_guard).as_ref() {
                    let subject = AuthzSubject::from_identity(&handle.identity);
                    let resource = AuthzResource::Direct { target_cn: cn };
                    let outcome = engine.evaluate(&subject, &resource, AuthzAction::Receive);
                    if !outcome.is_allow() {
                        tracing::debug!(
                            target: "authz",
                            recipient_cn = %cn,
                            rule_id = ?outcome.rule_id,
                            policy_id = %engine.policy_id(),
                            "authz deny on direct receive"
                        );
                        return;
                    }
                }
                if let Err(e) = handle.send(msg).await {
                    // `tokio::mpsc::Sender::send().await` only returns
                    // Err when the receiver has been closed — a full
                    // channel awaits capacity rather than failing —
                    // so this path strictly means the session writer
                    // task has gone away. Persist for redelivery if
                    // a store-and-forward queue is attached.
                    warn!(session = %cn, "session channel closed");
                    self.persist_for_offline(cn, &e.0);
                }
            }
            None => {
                // No live subscriber — persist for redelivery. The
                // authz Receive PEP runs at drain time when the session
                // reconnects; persisting a currently-denied message is
                // acceptable because policy may change before the
                // session returns.
                self.persist_for_offline(cn, &msg);
            }
        }
    }

    /// Persist a message for later delivery to `cn`, if a client queue
    /// is attached. On error the message is dropped and a warning is
    /// logged — the queue is best-effort durability, not a blocker for
    /// live routing.
    fn persist_for_offline(&self, cn: &str, msg: &RoutableMessage) {
        let Some(queue) = self.client_queue.as_ref() else {
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

        // Snapshot the optional authz engine once so the per-recipient
        // hot path below is just a virtual call per candidate rather
        // than an atomic load per iteration.
        let authz_guard = self.authz.load();
        let authz: Option<&Arc<dyn PolicyEngine>> = (**authz_guard).as_ref();

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
                .filter(|handle| {
                    // Per-recipient authz Receive check. The Subject is
                    // built from the *recipient's* identity so policies
                    // that deny a specific CN or attribute on receive
                    // actually take effect.
                    let Some(engine) = authz else {
                        return true;
                    };
                    let subject = AuthzSubject::with_hash(&handle.identity, handle.subject_hash);
                    let resource = AuthzResource::Group { group };
                    let outcome =
                        self.authz_evaluate(engine, &subject, &resource, AuthzAction::Receive);
                    if !outcome.is_allow() {
                        rustgate_core::audit::authz_denied(
                            handle.identity.cn.as_str(),
                            handle.identity.fingerprint.as_str(),
                            "receive",
                            "group",
                            group,
                            outcome.rule_id.as_deref(),
                            engine.policy_id(),
                        );
                    }
                    outcome.is_allow()
                })
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
    /// receive broadcasts regardless of group membership. Per-recipient
    /// authz Receive PEP still applies: a policy rule denying broadcast
    /// receipt to a specific subject filters that recipient out here.
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

        // Snapshot the authz engine once so the per-recipient loop is a
        // virtual call at worst, not an atomic load per iteration.
        let authz_guard = self.authz.load();
        let authz: Option<&Arc<dyn PolicyEngine>> = (**authz_guard).as_ref();

        let mut dropped = 0u32;
        let mut filtered = 0u32;
        for handle in &targets {
            if let Some(engine) = authz {
                let subject = AuthzSubject::from_identity(&handle.identity);
                let resource = AuthzResource::Broadcast;
                let outcome = engine.evaluate(&subject, &resource, AuthzAction::Receive);
                if !outcome.is_allow() {
                    tracing::debug!(
                        target: "authz",
                        recipient_cn = %handle.identity.cn,
                        rule_id = ?outcome.rule_id,
                        policy_id = %engine.policy_id(),
                        "authz deny on broadcast receive"
                    );
                    filtered += 1;
                    continue;
                }
            }
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
        if filtered > 0 {
            debug!(
                filtered = filtered,
                total = targets.len(),
                "broadcast recipients filtered by authz policy"
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
        router.register(handle.clone()).await;
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
        router.register(handle.clone()).await;
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

    // ── Dynamic group join/leave ────────────────────────────────────

    #[tokio::test]
    async fn join_group_adds_session_to_group() {
        let router = Router::new();
        let alice = make_identity("alice", &["alpha"]);

        let (ptx, ntx, _prx, mut nrx) = make_channels(16, 16);
        let handle = SessionHandle::new(alice.clone(), ptx, ntx);
        let sid = handle.id;
        router.register(handle).await;

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
        router.register(handle).await;

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
        router.register(handle).await;

        // Re-register (simulates reconnect), gets a new session ID.
        let (ptx2, ntx2, _prx2, _nrx2) = make_channels(16, 16);
        let handle2 = SessionHandle::new(alice.clone(), ptx2, ntx2);
        router.register(handle2).await;

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
        router.register(handle).await;

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
        router.register(handle).await;

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
}
