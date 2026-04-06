//! REST API for managing the group access control policy at runtime.
//!
//! Mounted under `/api/acl/` on the metrics HTTP server (gated by the
//! `metrics` feature, mirroring the federation REST API). All endpoints
//! return JSON envelopes of the form `{"data": ...}` for success and
//! `{"error": "..."}` for failures.
//!
//! ## Routes
//!
//! - `GET    /api/acl/groups`         — list current ACL rules
//! - `PUT    /api/acl/groups/{group}` — upsert a single group entry
//! - `DELETE /api/acl/groups/{group}` — remove a single group entry
//! - `POST   /api/acl/reload`         — re-read the on-disk ACL file
//!
//! Mutations rebuild the full [`GroupAclPolicy`] from the in-memory
//! source-of-truth and atomically install it on the [`Router`] via
//! [`Router::swap_acl`]. Calling `POST /api/acl/reload` re-reads the
//! configured ACL file and replaces both the in-memory state and the
//! router policy — any pending in-memory edits not yet persisted to
//! disk are therefore discarded by a reload.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Response, StatusCode};
use rustgate_transport::Router;
use serde::Serialize;

use crate::acl_config::{GroupAclEntry, GroupAclFile};
use crate::acl_reloader::AclReloader;

/// Shared state for the ACL REST API.
///
/// Holds the in-memory source-of-truth for the current ACL configuration
/// (so PUT/DELETE round-trip cleanly), a handle to the [`Router`] for
/// atomic policy swaps, and an optional [`AclReloader`] used by the
/// reload endpoint.
pub struct AclApiState {
    pub current: Arc<RwLock<GroupAclFile>>,
    pub router: Arc<Router>,
    pub reloader: Option<Arc<AclReloader>>,
}

impl std::fmt::Debug for AclApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AclApiState").finish()
    }
}

#[derive(Serialize)]
struct SuccessResponse<T: Serialize> {
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

fn internal_error_response() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from("internal server error")));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

fn json_ok<T: Serialize>(data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&SuccessResponse { data }).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&ErrorResponse { error: message }).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Convert an in-memory [`GroupAclFile`] into a runtime [`GroupAclPolicy`].
fn build_policy(file: &GroupAclFile) -> rustgate_transport::GroupAclPolicy {
    let mut groups = HashMap::with_capacity(file.groups.len());
    for (group_id, entry) in &file.groups {
        let _ = groups.insert(
            group_id.clone(),
            rustgate_transport::GroupAcl::with_deny(
                entry.send.clone(),
                entry.receive.clone(),
                entry.deny_send.clone(),
                entry.deny_receive.clone(),
            ),
        );
    }
    rustgate_transport::GroupAclPolicy::new(groups)
}

/// Atomically install the current in-memory file as the router policy.
fn install_current(state: &AclApiState) -> Result<(), &'static str> {
    let file = state
        .current
        .read()
        .map_err(|_| "ACL state lock poisoned")?;
    let policy = build_policy(&file);
    let new_acl = if policy.is_empty() {
        None
    } else {
        Some(policy)
    };
    state.router.swap_acl(new_acl);
    Ok(())
}

/// Handle an ACL API request.
///
/// Returns `None` if `path` is outside `/api/acl/`, allowing the caller
/// to fall through to other handlers.
pub fn handle_request(
    method: &Method,
    path: &str,
    body: &[u8],
    state: &AclApiState,
) -> Option<Response<Full<Bytes>>> {
    if !path.starts_with("/api/acl/") {
        return None;
    }
    let sub_path = &path["/api/acl/".len()..];
    Some(route(method, sub_path, body, state))
}

fn route(
    method: &Method,
    sub_path: &str,
    body: &[u8],
    state: &AclApiState,
) -> Response<Full<Bytes>> {
    match (method, sub_path) {
        (&Method::GET, "groups") => list_groups(state),
        (&Method::PUT, path) if path.starts_with("groups/") => {
            let group = &path["groups/".len()..];
            if group.is_empty() || group.contains('/') {
                return json_error(StatusCode::BAD_REQUEST, "invalid group id");
            }
            put_group(state, group, body)
        }
        (&Method::DELETE, path) if path.starts_with("groups/") => {
            let group = &path["groups/".len()..];
            if group.is_empty() || group.contains('/') {
                return json_error(StatusCode::BAD_REQUEST, "invalid group id");
            }
            delete_group(state, group)
        }
        (&Method::POST, "reload") => reload(state),
        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    }
}

fn list_groups(state: &AclApiState) -> Response<Full<Bytes>> {
    match state.current.read() {
        Ok(file) => json_ok(&*file),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "ACL state lock poisoned"),
    }
}

fn put_group(state: &AclApiState, group: &str, body: &[u8]) -> Response<Full<Bytes>> {
    let entry: GroupAclEntry = match serde_json::from_slice(body) {
        Ok(e) => e,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    {
        let mut file = match state.current.write() {
            Ok(f) => f,
            Err(_) => {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "ACL state lock poisoned");
            }
        };
        let _ = file.groups.insert(group.to_string(), entry);
    }
    if let Err(e) = install_current(state) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    tracing::info!(
        target: "audit",
        event_type = "acl.api_upsert",
        group = %group,
        "ACL group upserted via REST API"
    );
    match state.current.read() {
        Ok(file) => json_ok(&*file),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "ACL state lock poisoned"),
    }
}

fn delete_group(state: &AclApiState, group: &str) -> Response<Full<Bytes>> {
    {
        let mut file = match state.current.write() {
            Ok(f) => f,
            Err(_) => {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "ACL state lock poisoned");
            }
        };
        if file.groups.remove(group).is_none() {
            return json_error(StatusCode::NOT_FOUND, "group not found");
        }
    }
    if let Err(e) = install_current(state) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    tracing::info!(
        target: "audit",
        event_type = "acl.api_delete",
        group = %group,
        "ACL group deleted via REST API"
    );
    json_ok(&serde_json::json!({"deleted": group}))
}

fn reload(state: &AclApiState) -> Response<Full<Bytes>> {
    let Some(reloader) = state.reloader.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ACL hot-reload is not configured",
        );
    };
    match reloader.reload() {
        Ok(swapped) => json_ok(&serde_json::json!({"reloaded": true, "changed": swapped})),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::HashSet;

    use super::*;

    fn make_state() -> AclApiState {
        let mut file = GroupAclFile::default();
        let _ = file.groups.insert(
            "alpha".to_string(),
            GroupAclEntry {
                send: HashSet::from(["alice".to_string()]),
                receive: HashSet::from(["alice".to_string(), "bob".to_string()]),
                deny_send: HashSet::new(),
                deny_receive: HashSet::new(),
            },
        );
        AclApiState {
            current: Arc::new(RwLock::new(file)),
            router: Arc::new(Router::new()),
            reloader: None,
        }
    }

    fn body_string(resp: Response<Full<Bytes>>) -> String {
        use std::pin::Pin;
        use std::task::{Context, Wake};

        use http_body::Body;

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }

        let (_, mut body) = resp.into_parts();
        let waker = Arc::new(NoopWaker).into();
        let mut cx = Context::from_waker(&waker);

        let mut buf = bytes::BytesMut::new();
        while let std::task::Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx)
        {
            if let Ok(data) = frame.into_data() {
                buf.extend_from_slice(&data);
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    #[test]
    fn non_acl_path_returns_none() {
        let state = make_state();
        assert!(handle_request(&Method::GET, "/healthz", &[], &state).is_none());
        assert!(handle_request(&Method::GET, "/api/federation/foo", &[], &state).is_none());
    }

    #[test]
    fn unknown_acl_path_returns_404() {
        let state = make_state();
        let resp = handle_request(&Method::GET, "/api/acl/unknown", &[], &state).expect("handled");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn list_groups_returns_current_state() {
        let state = make_state();
        let resp = handle_request(&Method::GET, "/api/acl/groups", &[], &state).expect("handled");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp);
        assert!(body.contains("alpha"));
        assert!(body.contains("alice"));
    }

    #[test]
    fn put_group_adds_new_entry_and_swaps_router() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "send": ["carol"],
            "receive": ["carol"],
            "deny_send": ["mallory"]
        }))
        .unwrap();

        let resp =
            handle_request(&Method::PUT, "/api/acl/groups/bravo", &body, &state).expect("handled");
        assert_eq!(resp.status(), StatusCode::OK);

        // In-memory state must contain the new group.
        let file = state.current.read().unwrap();
        assert!(file.groups.contains_key("bravo"));
        assert!(file.groups["bravo"].deny_send.contains("mallory"));
        drop(file);

        // Router must reflect it.
        let snap = state.router.acl_snapshot();
        let policy = snap.as_ref().as_ref().expect("policy installed");
        assert!(!policy.is_send_authorized("bravo", "mallory"));
        assert!(policy.is_send_authorized("bravo", "carol"));
    }

    #[test]
    fn put_group_updates_existing_entry() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "send": ["alice", "bob"],
            "receive": ["alice", "bob"]
        }))
        .unwrap();
        let resp =
            handle_request(&Method::PUT, "/api/acl/groups/alpha", &body, &state).expect("handled");
        assert_eq!(resp.status(), StatusCode::OK);
        let file = state.current.read().unwrap();
        assert!(file.groups["alpha"].send.contains("bob"));
    }

    #[test]
    fn put_group_invalid_json_rejected() {
        let state = make_state();
        let resp = handle_request(&Method::PUT, "/api/acl/groups/bravo", b"not json", &state)
            .expect("handled");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn put_group_empty_id_rejected() {
        let state = make_state();
        let resp =
            handle_request(&Method::PUT, "/api/acl/groups/", b"{}", &state).expect("handled");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn delete_group_removes_entry() {
        let state = make_state();
        let resp =
            handle_request(&Method::DELETE, "/api/acl/groups/alpha", &[], &state).expect("handled");
        assert_eq!(resp.status(), StatusCode::OK);
        let file = state.current.read().unwrap();
        assert!(!file.groups.contains_key("alpha"));
        // After deleting the only group, the router reverts to open mode (None).
        let snap = state.router.acl_snapshot();
        assert!(snap.as_ref().is_none());
    }

    #[test]
    fn delete_group_not_found() {
        let state = make_state();
        let resp = handle_request(&Method::DELETE, "/api/acl/groups/missing", &[], &state)
            .expect("handled");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn reload_without_reloader_returns_503() {
        let state = make_state();
        let resp = handle_request(&Method::POST, "/api/acl/reload", &[], &state).expect("handled");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn reload_invokes_reloader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acl.json");
        std::fs::write(
            &path,
            r#"{"groups":{"gamma":{"send":["dave"],"receive":["dave"]}}}"#,
        )
        .unwrap();

        let router = Arc::new(Router::new());
        let initial_hash = AclReloader::compute_hash(b"");
        let reloader = AclReloader::new(path.clone(), Arc::clone(&router), initial_hash);

        let state = AclApiState {
            current: Arc::new(RwLock::new(GroupAclFile::default())),
            router: Arc::clone(&router),
            reloader: Some(Arc::clone(&reloader)),
        };

        let resp = handle_request(&Method::POST, "/api/acl/reload", &[], &state).expect("handled");
        assert_eq!(resp.status(), StatusCode::OK);

        // Router should now have the gamma policy installed.
        let snap = router.acl_snapshot();
        let policy = snap.as_ref().as_ref().expect("policy installed");
        assert!(policy.is_send_authorized("gamma", "dave"));
        assert!(!policy.is_send_authorized("gamma", "eve"));
    }

    #[test]
    fn put_then_list_round_trips() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "send": ["x"],
            "receive": ["y"],
            "deny_send": ["z"],
            "deny_receive": ["w"]
        }))
        .unwrap();
        let _ =
            handle_request(&Method::PUT, "/api/acl/groups/delta", &body, &state).expect("handled");

        let resp = handle_request(&Method::GET, "/api/acl/groups", &[], &state).expect("handled");
        let s = body_string(resp);
        assert!(s.contains("delta"));
        assert!(s.contains("deny_send"));
        assert!(s.contains("\"z\""));
    }
}
