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

#[derive(Debug)]
pub struct Router {
    state: RwLock<State>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }

    pub async fn register(&self, handle: SessionHandle) {
        let cn = handle.identity.cn.clone();
        let identity_groups = handle.identity.groups.clone();

        let mut state = self.state.write().await;
        let _ = state.sessions.insert(cn.clone(), handle);
        for group in &identity_groups {
            let _ = state.groups.entry(group.clone()).or_default().insert(cn.clone());
        }
    }

    pub async fn unregister(&self, cn: &str) {
        let mut state = self.state.write().await;
        let handle = state.sessions.remove(cn);

        if let Some(handle) = handle {
            for group in &handle.identity.groups {
                if let Some(members) = state.groups.get_mut(group) {
                    let _ = members.remove(cn);
                    if members.is_empty() {
                        let _ = state.groups.remove(group);
                    }
                }
            }
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
        let state = self.state.read().await;
        if let Some(handle) = state.sessions.get(cn) {
            let _ = handle.send(msg).await;
        }
    }

    async fn send_to_group(&self, group: &str, msg: &RoutableMessage) {
        let state = self.state.read().await;
        let members = match state.groups.get(group) {
            Some(m) => m.clone(),
            None => return,
        };
        drop(state);

        let state = self.state.read().await;
        for cn in &members {
            if cn == &msg.source.cn {
                continue;
            }
            if let Some(handle) = state.sessions.get(cn) {
                let _ = handle.send(msg.clone()).await;
            }
        }
    }

    async fn send_to_all(&self, msg: &RoutableMessage) {
        let state = self.state.read().await;
        for (cn, handle) in state.sessions.iter() {
            if cn == &msg.source.cn {
                continue;
            }
            let _ = handle.send(msg.clone()).await;
        }
    }
}
