//! Message routing engine.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};

use rustgate_core::identity::{GroupId, Identity};
use rustgate_core::message::{Destination, RoutableMessage};

#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub identity: Arc<Identity>,
    sender: mpsc::Sender<RoutableMessage>,
}

impl SessionHandle {
    pub fn new(identity: Arc<Identity>, sender: mpsc::Sender<RoutableMessage>) -> Self {
        Self { identity, sender }
    }

    pub async fn send(&self, msg: RoutableMessage) -> Result<(), mpsc::error::SendError<RoutableMessage>> {
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
}

impl Router {
    pub fn new() -> Self {
        Self::default()
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
            let _ = state.groups.entry(group.clone()).or_default().insert(cn.clone());
        }
    }

    pub async fn unregister(&self, cn: &str) {
        let mut state = self.state.write().await;
        if let Some(handle) = state.sessions.remove(cn) {
            state.remove_from_groups(cn, &handle.identity.groups);
        }
    }

    pub async fn route(&self, msg: RoutableMessage) {
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
            members.iter()
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
            state.sessions.iter()
                .filter(|(cn, _)| *cn != &msg.source.cn)
                .map(|(_, handle)| handle.clone())
                .collect()
        };

        for handle in &targets {
            let _ = handle.send(msg.clone()).await;
        }
    }
}
