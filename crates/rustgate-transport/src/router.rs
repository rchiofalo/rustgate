//! Message routing engine.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustgate_core::identity::{GroupId, Identity};
use rustgate_core::message::{Destination, MessageType, RoutableMessage};
use tokio::sync::{RwLock, mpsc};
use tracing::warn;

use crate::cache::PositionCache;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub id: u64,
    pub identity: Arc<Identity>,
    sender: mpsc::Sender<RoutableMessage>,
}

impl SessionHandle {
    pub fn new(identity: Arc<Identity>, sender: mpsc::Sender<RoutableMessage>) -> Self {
        Self {
            id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            identity,
            sender,
        }
    }

    pub async fn send(
        &self,
        msg: RoutableMessage,
    ) -> Result<(), mpsc::error::SendError<RoutableMessage>> {
        self.sender.send(msg).await
    }
}

/// Default maximum number of groups a single CN can join.
pub const DEFAULT_MAX_GROUPS_PER_CN: usize = 128;

/// Default maximum total number of groups tracked by the router.
pub const DEFAULT_MAX_TOTAL_GROUPS: usize = 10_000;

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
            sessions: HashMap::new(),
            groups: HashMap::new(),
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
}

impl Default for Router {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
            cache: PositionCache::default(),
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
        }
    }

    /// Access the position cache for SA replay.
    pub fn cache(&self) -> &PositionCache {
        &self.cache
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
        // Cache position reports for SA replay to new sessions
        if msg.metadata.message_type == MessageType::Position {
            self.cache.store(msg.clone()).await;
        }

        match msg.destination {
            Destination::Direct(ref target) => {
                let cn = target.cn.clone();
                self.send_to_session(&cn, msg).await;
            }
            Destination::Group(ref group) => {
                self.send_to_group(group, &msg).await;
            }
            Destination::Broadcast => {
                self.send_to_all(&msg).await;
            }
        }
    }

    /// Replay cached positions to a newly connected session.
    /// Only replays positions from clients that share at least one group
    /// with the connecting session to enforce group-level isolation.
    pub async fn replay_positions(&self, handle: &SessionHandle) {
        let mut dropped = 0u32;
        let mut total = 0u32;
        for msg in self.cache.get_all().await {
            let shared = msg
                .source
                .groups
                .intersection(&handle.identity.groups)
                .next()
                .is_some();
            if shared || handle.identity.groups.is_empty() {
                total += 1;
                if handle.send(msg).await.is_err() {
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

    async fn send_to_session(&self, cn: &str, msg: RoutableMessage) {
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

    async fn send_to_group(&self, group: &str, msg: &RoutableMessage) {
        if !msg.source.is_member_of(group) {
            tracing::warn!(
                sender = %msg.source.cn,
                group = %group,
                "rejected cross-group message: sender not a member"
            );
            return;
        }

        let targets: Vec<SessionHandle> = {
            let state = self.state.read().await;
            let members = match state.groups.get(group) {
                Some(m) => m,
                None => return,
            };
            members
                .iter()
                .filter(|cn| *cn != &msg.source.cn)
                .filter_map(|cn| state.sessions.get(cn).cloned())
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
                group = %group,
                dropped = dropped,
                total = targets.len(),
                "messages dropped during group send: channel full or disconnected"
            );
        }
    }

    /// Broadcast to all connected sessions (except sender).
    /// This is intentional for SA sharing — all authenticated clients
    /// receive broadcasts regardless of group membership.
    async fn send_to_all(&self, msg: &RoutableMessage) {
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
    use std::collections::BTreeSet;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    use super::*;

    fn make_identity(cn: &str, groups: &[&str]) -> Arc<Identity> {
        Arc::new(Identity {
            cn: cn.to_string(),
            fingerprint: format!("{cn}-fp"),
            groups: groups
                .iter()
                .map(|g| g.to_string())
                .collect::<BTreeSet<_>>(),
        })
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

        let (tx_a, mut rx_a) = mpsc::channel(16);
        let (tx_b, _rx_b) = mpsc::channel(16);

        router
            .register(SessionHandle::new(alice.clone(), tx_a))
            .await;
        router.register(SessionHandle::new(bob.clone(), tx_b)).await;

        // Bob sends to group "alpha" — but bob is only in "bravo".
        // The router must reject this: sender is not a member of the
        // target group, so alice (who IS in alpha) must not receive it.
        let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
        router.route(msg).await;

        assert!(
            rx_a.try_recv().is_err(),
            "alice must not receive: bob is not in alpha and cannot send to it"
        );
    }

    #[tokio::test]
    async fn send_to_group_allows_member() {
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        let charlie = make_identity("charlie", &["bravo"]);

        let (tx_a, mut rx_a) = mpsc::channel(16);
        let (tx_b, _rx_b) = mpsc::channel(16);
        let (tx_c, mut rx_c) = mpsc::channel(16);

        router
            .register(SessionHandle::new(alice.clone(), tx_a))
            .await;
        router.register(SessionHandle::new(bob.clone(), tx_b)).await;
        router
            .register(SessionHandle::new(charlie.clone(), tx_c))
            .await;

        // Bob sends to group "alpha" — bob IS a member
        let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
        router.route(msg).await;

        // Alice (in alpha) receives with correct payload
        let received = rx_a.try_recv().expect("alice must receive: both in alpha");
        assert_eq!(received.payload.as_ref(), b"<chat/>");
        assert_eq!(received.source.cn, "bob");

        // Charlie (in bravo, not alpha) must NOT receive
        assert!(
            rx_c.try_recv().is_err(),
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
        let (tx, mut rx) = mpsc::channel(16);
        let handle = SessionHandle::new(bravo_user.clone(), tx);
        router.replay_positions(&handle).await;

        assert!(
            rx.try_recv().is_err(),
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
        let (tx, mut rx) = mpsc::channel(16);
        let handle = SessionHandle::new(bob.clone(), tx);
        router.replay_positions(&handle).await;

        assert!(
            rx.try_recv().is_ok(),
            "bob should see alice's position via shared group"
        );
    }

    #[tokio::test]
    async fn unregister_evicts_from_cache() {
        let router = Router::new();

        let alice = make_identity("alice", &["alpha"]);
        let (tx, _rx) = mpsc::channel(16);
        let handle = SessionHandle::new(alice.clone(), tx);
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
        let (tx, _rx) = mpsc::channel(16);
        router.register(SessionHandle::new(alice.clone(), tx)).await;

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
        let (tx_a, _rx_a) = mpsc::channel(16);
        router
            .register(SessionHandle::new(alice.clone(), tx_a))
            .await;

        // Second client tries to join a new group — should be rejected
        let bob = make_identity("bob", &["g3"]);
        let (tx_b, _rx_b) = mpsc::channel(16);
        router.register(SessionHandle::new(bob.clone(), tx_b)).await;

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
        let (tx_a, _rx_a) = mpsc::channel(16);
        router
            .register(SessionHandle::new(alice.clone(), tx_a))
            .await;

        // Bob joins g1 (already exists) — should succeed
        let bob = make_identity("bob", &["g1"]);
        let (tx_b, _rx_b) = mpsc::channel(16);
        router.register(SessionHandle::new(bob.clone(), tx_b)).await;

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

        let (tx_a, _rx_a) = mpsc::channel(16);
        let (tx_b, _rx_b) = mpsc::channel(16);

        router
            .register(SessionHandle::new(alice.clone(), tx_a))
            .await;
        router.register(SessionHandle::new(bob.clone(), tx_b)).await;

        let clients = router.connected_clients().await;
        assert_eq!(clients.len(), 2);

        let cns: Vec<&str> = clients.iter().map(|c| c.cn.as_str()).collect();
        assert!(cns.contains(&"alice"));
        assert!(cns.contains(&"bob"));
    }
}
