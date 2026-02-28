//! Message routing engine.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{RwLock, mpsc};

use rustgate_core::identity::{GroupId, Identity};
use rustgate_core::message::{Destination, MessageType, RoutableMessage};

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

#[derive(Debug, Default)]
struct State {
    sessions: HashMap<String, SessionHandle>,
    groups: HashMap<GroupId, HashSet<String>>,
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

#[derive(Debug, Default)]
pub struct Router {
    state: RwLock<State>,
    cache: PositionCache,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
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
        for group in &new_groups {
            let _ = state
                .groups
                .entry(group.clone())
                .or_default()
                .insert(cn.clone());
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

    /// Replay all cached positions to a newly connected session.
    pub async fn replay_positions(&self, handle: &SessionHandle) {
        for msg in self.cache.get_all().await {
            let _ = handle.send(msg).await;
        }
    }

    pub async fn session_count(&self) -> usize {
        self.state.read().await.sessions.len()
    }

    async fn send_to_session(&self, cn: &str, msg: RoutableMessage) {
        let handle = {
            let state = self.state.read().await;
            state.sessions.get(cn).cloned()
        };
        if let Some(handle) = handle {
            let _ = handle.send(msg).await;
        }
    }

    async fn send_to_group(&self, group: &str, msg: &RoutableMessage) {
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

        for handle in &targets {
            let _ = handle.send(msg.clone()).await;
        }
    }

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

        for handle in &targets {
            let _ = handle.send(msg.clone()).await;
        }
    }
}
