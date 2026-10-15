// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
//! Mutations rebuild the full [`rustgate_router::GroupAclPolicy`] from the in-memory
//! source-of-truth and atomically install it on the [`Router`] via
//! [`Router::swap_acl`]. Calling `POST /api/acl/reload` re-reads the
//! configured ACL file and replaces both the in-memory state and the
//! router policy — any pending in-memory edits not yet persisted to
//! disk are therefore discarded by a reload.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Response, StatusCode};
use rustgate_router::Router;
use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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
    /// On-disk ACL file to rewrite atomically when mutations succeed.
    /// The API is only registered when both this path and a token file
    /// are configured, so handlers can assume it is always set.
    pub file_path: PathBuf,
    /// Bearer token required on every `/api/acl/` request. Stored as
    /// raw bytes so we can use constant-time comparison.
    /// Wrapped in [`Zeroizing`] so the token is wiped from memory on drop.
    pub auth_token: Zeroizing<Vec<u8>>,
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

/// Convert an in-memory [`GroupAclFile`] into a runtime [`rustgate_router::GroupAclPolicy`].
///
/// CN strings are normalized to ASCII lowercase for case-insensitive
/// matching per RFC 5280 §7.1.
fn build_policy(file: &GroupAclFile) -> rustgate_router::GroupAclPolicy {
    let mut groups = HashMap::with_capacity(file.groups.len());
    for (group_id, entry) in &file.groups {
        let _ = groups.insert(
            group_id.clone(),
            rustgate_router::GroupAcl::with_deny(
                entry.send.iter().map(|s| s.to_ascii_lowercase()).collect(),
                entry
                    .receive
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                entry
                    .deny_send
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                entry
                    .deny_receive
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
            ),
        );
    }
    rustgate_router::GroupAclPolicy::new(groups)
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

/// Human-readable description of the [`valid_group_id`] rules, reused
/// as the error body returned to clients that submit a malformed group
/// name. Embedded in the API response so operators can self-correct
/// without consulting the source.
const GROUP_ID_RULES: &str = "group id must be 1–128 bytes, contain only ASCII alphanumeric or \
                              `_`, `.`, `:`, `-`, and must not use the reserved `__*__` form \
                              (e.g. `__plaintext__`, `__ANON__`) — those names are reserved for \
                              transport-layer synthetic groups and cannot appear in an \
                              operator-authored ACL policy";

/// Validate a group identifier against a strict allow list of characters.
///
/// Permitted: ASCII alphanumeric (`a-z`, `A-Z`, `0-9`) plus the
/// punctuation characters `_`, `.`, `:`, `-`. Length must be in
/// `1..=128` bytes.
///
/// The ASCII-only restriction is deliberate defense-in-depth, not an
/// arbitrary simplification. ACL group names flow through several
/// downstream consumers that each assume an ASCII byte representation:
///
/// * Router ACL lookup in [`rustgate_router::GroupAclPolicy`] is a
///   case-insensitive ASCII comparison.
/// * Client-certificate OU extraction parses comma-separated ASCII
///   strings out of X.509 RDNs.
/// * NATS subject tokens strip non-ASCII in
///   `rustgate_nats::publisher::sanitize_nats_token`, so a non-ASCII
///   group name accepted here would lose characters there and land in
///   a different subject.
/// * Structured-logging field values render inconsistently across log
///   collectors when non-ASCII bytes are present.
///
/// Rejecting non-ASCII at ingress guarantees a single canonical byte
/// form, which blocks Unicode-equivalence spoofing (e.g. submitting
/// Cyrillic `а` (U+0430) where a Latin `a` is expected to impersonate
/// another group).
///
/// The 128-byte cap matches the `MAX_CN_LENGTH` convention in
/// `rustgate_tls::extract` and bounds the worst-case memory
/// footprint of the in-memory ACL map.
///
/// ## Reserved-sentinel namespace
///
/// Names matching the `__*__` sentinel shape are rejected via
/// [`rustgate_core::constants::is_reserved_group_id`]. Those names are
/// reserved for transport-layer synthetic groups (plaintext sessions,
/// anonymous federation ingress, tenant-quota fallback); a policy
/// keyed by one of them would either shadow the synthetic group's
/// meaning at the PEP or — in the `__plaintext__` case — silently
/// apply an operator ACL entry to every anonymous plaintext session
/// the server accepted, broadcasting to a population the operator did
/// not enumerate. Rejecting at ingress prevents the configuration
/// mistake from reaching the router.
fn valid_group_id(group: &str) -> bool {
    let len = group.len();
    if !(1..=128).contains(&len) {
        return false;
    }
    if rustgate_core::constants::is_reserved_group_id(group) {
        return false;
    }
    group
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

/// Minimum bearer token length in bytes.
///
/// Tokens shorter than this are rejected at configuration time to
/// prevent weak credentials. 32 bytes provides 256 bits of entropy
/// when the token is random, comfortably above brute-force thresholds.
pub const MIN_TOKEN_LEN: usize = 32;

/// Maximum bearer token length in bytes.
///
/// Prevents unbounded-length tokens that would waste memory in
/// constant-time comparison and storage.
pub const MAX_TOKEN_LEN: usize = 256;

/// Validate that a bearer token's length is within acceptable bounds.
///
/// Returns `Ok(())` when the token is between [`MIN_TOKEN_LEN`] and
/// [`MAX_TOKEN_LEN`] bytes (inclusive). Called at startup to reject
/// misconfigured token files before the API server binds.
///
/// The `label` parameter is used in error messages to identify which
/// token failed validation (e.g. "ACL API" or "metrics bearer").
pub fn validate_bearer_token_length(token: &[u8], label: &str) -> Result<(), String> {
    let len = token.len();
    if len < MIN_TOKEN_LEN {
        return Err(format!(
            "{label} token too short ({len} bytes, minimum {MIN_TOKEN_LEN})"
        ));
    }
    if len > MAX_TOKEN_LEN {
        return Err(format!(
            "{label} token too long ({len} bytes, maximum {MAX_TOKEN_LEN})"
        ));
    }
    Ok(())
}

/// Constant-time check of the supplied bearer token against the configured one.
fn auth_ok(header: Option<&str>, expected: &[u8]) -> bool {
    let Some(raw) = header else {
        return false;
    };
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    token.as_bytes().ct_eq(expected).into()
}

/// Handle an ACL API request.
///
/// Returns `None` if `path` is outside `/api/acl/`, allowing the caller
/// to fall through to other handlers. All `/api/acl/` routes require a
/// valid `Authorization: Bearer <token>` header; missing or mismatched
/// tokens yield a 401 response.
pub fn handle_request(
    method: &Method,
    path: &str,
    authorization: Option<&str>,
    body: &[u8],
    state: &AclApiState,
) -> Option<Response<Full<Bytes>>> {
    if !path.starts_with("/api/acl/") {
        return None;
    }
    if !auth_ok(authorization, &state.auth_token) {
        return Some(json_error(StatusCode::UNAUTHORIZED, "unauthorized"));
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
            if !valid_group_id(group) {
                return json_error(StatusCode::BAD_REQUEST, GROUP_ID_RULES);
            }
            put_group(state, group, body)
        }
        (&Method::DELETE, path) if path.starts_with("groups/") => {
            let group = &path["groups/".len()..];
            if !valid_group_id(group) {
                return json_error(StatusCode::BAD_REQUEST, GROUP_ID_RULES);
            }
            delete_group(state, group)
        }
        (&Method::POST, "reload") => reload(state),
        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    }
}

/// Atomically persist the in-memory ACL state to disk.
///
/// Writes to `<path>.tmp`, fsyncs, then renames over the target so
/// concurrent readers (and the hot reloader) never see a partial file.
fn persist_current(state: &AclApiState) -> Result<(), String> {
    use std::io::Write;

    let file = state
        .current
        .read()
        .map_err(|_| "ACL state lock poisoned".to_string())?;
    let json = serde_json::to_vec_pretty(&*file).map_err(|e| format!("serialize ACL file: {e}"))?;
    drop(file);

    let mut tmp = state.file_path.clone();
    let mut name = tmp
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(".tmp");
    tmp.set_file_name(name);

    {
        let mut f =
            std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(&json)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &state.file_path)
        .map_err(|e| format!("rename {}: {e}", state.file_path.display()))?;
    Ok(())
}

/// Persist the current in-memory ACL and, if a reloader is wired in,
/// update its stored SHA-256 hash so the next background poll does not
/// re-detect the same change.
fn persist_and_sync_hash(state: &AclApiState) -> Result<(), String> {
    persist_current(state)?;
    if let Some(reloader) = state.reloader.as_ref() {
        match std::fs::read(&state.file_path) {
            Ok(bytes) => reloader.set_hash(AclReloader::compute_hash(&bytes)),
            Err(e) => {
                return Err(format!(
                    "re-read {} for hash sync: {e}",
                    state.file_path.display()
                ));
            }
        }
    }
    Ok(())
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
    if let Err(e) = persist_and_sync_hash(state) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e);
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
    if let Err(e) = persist_and_sync_hash(state) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e);
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

    const TEST_TOKEN: &str = "s3cret-token";
    const TEST_AUTH: Option<&str> = Some("Bearer s3cret-token");

    fn make_state_with_dir(dir: &std::path::Path) -> AclApiState {
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
        let path = dir.join("acl.json");
        // Seed the file so persistence round-trips work.
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        AclApiState {
            current: Arc::new(RwLock::new(file)),
            router: Arc::new(Router::new()),
            reloader: None,
            file_path: path,
            auth_token: Zeroizing::new(TEST_TOKEN.as_bytes().to_vec()),
        }
    }

    fn make_state() -> (tempfile::TempDir, AclApiState) {
        let dir = tempfile::tempdir().unwrap();
        let state = make_state_with_dir(dir.path());
        (dir, state)
    }

    fn body_string(resp: Response<Full<Bytes>>) -> String {
        use std::pin::Pin;
        use std::task::{Context, Waker};

        use http_body::Body;

        let (_, mut body) = resp.into_parts();
        let mut cx = Context::from_waker(Waker::noop());

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
        let (_d, state) = make_state();
        assert!(handle_request(&Method::GET, "/healthz", TEST_AUTH, &[], &state).is_none());
        assert!(
            handle_request(&Method::GET, "/api/federation/foo", TEST_AUTH, &[], &state).is_none()
        );
    }

    #[test]
    fn unknown_acl_path_returns_404() {
        let (_d, state) = make_state();
        let resp = handle_request(&Method::GET, "/api/acl/unknown", TEST_AUTH, &[], &state)
            .expect("handled");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn list_groups_returns_current_state() {
        let (_d, state) = make_state();
        let resp = handle_request(&Method::GET, "/api/acl/groups", TEST_AUTH, &[], &state)
            .expect("handled");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp);
        assert!(body.contains("alpha"));
        assert!(body.contains("alice"));
    }

    #[test]
    fn missing_token_returns_401() {
        let (_d, state) = make_state();
        let resp =
            handle_request(&Method::GET, "/api/acl/groups", None, &[], &state).expect("handled");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn wrong_token_returns_401() {
        let (_d, state) = make_state();
        let resp = handle_request(
            &Method::GET,
            "/api/acl/groups",
            Some("Bearer not-the-token"),
            &[],
            &state,
        )
        .expect("handled");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn malformed_authorization_header_returns_401() {
        let (_d, state) = make_state();
        let resp = handle_request(
            &Method::GET,
            "/api/acl/groups",
            Some("Basic s3cret-token"),
            &[],
            &state,
        )
        .expect("handled");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn put_group_adds_new_entry_and_swaps_router() {
        let (_d, state) = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "send": ["carol"],
            "receive": ["carol"],
            "deny_send": ["mallory"]
        }))
        .unwrap();

        let resp = handle_request(
            &Method::PUT,
            "/api/acl/groups/bravo",
            TEST_AUTH,
            &body,
            &state,
        )
        .expect("handled");
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

        // Persistence: the on-disk file should now include the new group.
        let on_disk = std::fs::read_to_string(&state.file_path).unwrap();
        assert!(on_disk.contains("bravo"));
        assert!(on_disk.contains("mallory"));
    }

    #[test]
    fn put_group_updates_existing_entry() {
        let (_d, state) = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "send": ["alice", "bob"],
            "receive": ["alice", "bob"]
        }))
        .unwrap();
        let resp = handle_request(
            &Method::PUT,
            "/api/acl/groups/alpha",
            TEST_AUTH,
            &body,
            &state,
        )
        .expect("handled");
        assert_eq!(resp.status(), StatusCode::OK);
        let file = state.current.read().unwrap();
        assert!(file.groups["alpha"].send.contains("bob"));
    }

    #[test]
    fn put_group_invalid_json_rejected() {
        let (_d, state) = make_state();
        let resp = handle_request(
            &Method::PUT,
            "/api/acl/groups/bravo",
            TEST_AUTH,
            b"not json",
            &state,
        )
        .expect("handled");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn put_group_empty_id_rejected() {
        let (_d, state) = make_state();
        let resp = handle_request(&Method::PUT, "/api/acl/groups/", TEST_AUTH, b"{}", &state)
            .expect("handled");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn put_group_invalid_chars_rejected() {
        let (_d, state) = make_state();
        // Space is not in the allow list.
        let resp = handle_request(
            &Method::PUT,
            "/api/acl/groups/has space",
            TEST_AUTH,
            b"{}",
            &state,
        )
        .expect("handled");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Reserved-sentinel group ids must be rejected at the REST API
    /// boundary so a live `PUT` cannot sneak `__plaintext__` past the
    /// same guardrail the file-based loader enforces. See issue #749
    /// and `GroupAclFile::validate_operator_policy` for the rationale.
    #[test]
    fn put_group_rejects_plaintext_sentinel() {
        let (_d, state) = make_state();
        let resp = handle_request(
            &Method::PUT,
            "/api/acl/groups/__plaintext__",
            TEST_AUTH,
            br#"{"send":["alice"]}"#,
            &state,
        )
        .expect("handled");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp);
        assert!(
            body.contains("reserved"),
            "error body must mention the reservation: {body}"
        );
        // The in-memory file must not have been mutated — fail-closed.
        let file = state.current.read().unwrap();
        assert!(!file.groups.contains_key("__plaintext__"));
    }

    #[test]
    fn put_group_rejects_arbitrary_sentinel_shape() {
        let (_d, state) = make_state();
        let resp = handle_request(
            &Method::PUT,
            "/api/acl/groups/__anything__",
            TEST_AUTH,
            b"{}",
            &state,
        )
        .expect("handled");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A DELETE against a reserved name must also be rejected — not
    /// because a sentinel entry could exist (the put path rejects it
    /// first) but so the surface area stays symmetric and a probe
    /// against the name returns the same deterministic signal.
    #[test]
    fn delete_group_rejects_sentinel_shape() {
        let (_d, state) = make_state();
        let resp = handle_request(
            &Method::DELETE,
            "/api/acl/groups/__plaintext__",
            TEST_AUTH,
            &[],
            &state,
        )
        .expect("handled");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn delete_group_removes_entry() {
        let (_d, state) = make_state();
        let resp = handle_request(
            &Method::DELETE,
            "/api/acl/groups/alpha",
            TEST_AUTH,
            &[],
            &state,
        )
        .expect("handled");
        assert_eq!(resp.status(), StatusCode::OK);
        let file = state.current.read().unwrap();
        assert!(!file.groups.contains_key("alpha"));
        // After deleting the only group, the router reverts to open mode (None).
        let snap = state.router.acl_snapshot();
        assert!(snap.as_ref().is_none());
    }

    #[test]
    fn delete_group_not_found() {
        let (_d, state) = make_state();
        let resp = handle_request(
            &Method::DELETE,
            "/api/acl/groups/missing",
            TEST_AUTH,
            &[],
            &state,
        )
        .expect("handled");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn reload_without_reloader_returns_503() {
        let (_d, state) = make_state();
        let resp = handle_request(&Method::POST, "/api/acl/reload", TEST_AUTH, &[], &state)
            .expect("handled");
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
            file_path: path.clone(),
            auth_token: Zeroizing::new(TEST_TOKEN.as_bytes().to_vec()),
        };

        let resp = handle_request(&Method::POST, "/api/acl/reload", TEST_AUTH, &[], &state)
            .expect("handled");
        assert_eq!(resp.status(), StatusCode::OK);

        // Router should now have the gamma policy installed.
        let snap = router.acl_snapshot();
        let policy = snap.as_ref().as_ref().expect("policy installed");
        assert!(policy.is_send_authorized("gamma", "dave"));
        assert!(!policy.is_send_authorized("gamma", "eve"));
    }

    #[test]
    fn put_then_list_round_trips() {
        let (_d, state) = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "send": ["x"],
            "receive": ["y"],
            "deny_send": ["z"],
            "deny_receive": ["w"]
        }))
        .unwrap();
        let _ = handle_request(
            &Method::PUT,
            "/api/acl/groups/delta",
            TEST_AUTH,
            &body,
            &state,
        )
        .expect("handled");

        let resp = handle_request(&Method::GET, "/api/acl/groups", TEST_AUTH, &[], &state)
            .expect("handled");
        let s = body_string(resp);
        assert!(s.contains("delta"));
        assert!(s.contains("deny_send"));
        assert!(s.contains("\"z\""));
    }

    #[test]
    fn token_length_rejects_too_short() {
        let short = vec![b'a'; MIN_TOKEN_LEN - 1];
        let err = validate_bearer_token_length(&short, "ACL API").unwrap_err();
        assert!(err.contains("too short"), "got: {err}");
        assert!(err.contains("ACL API"), "got: {err}");
    }

    #[test]
    fn token_length_rejects_too_long() {
        let long = vec![b'a'; MAX_TOKEN_LEN + 1];
        let err = validate_bearer_token_length(&long, "ACL API").unwrap_err();
        assert!(err.contains("too long"), "got: {err}");
    }

    #[test]
    fn token_length_accepts_min_boundary() {
        let token = vec![b'a'; MIN_TOKEN_LEN];
        assert!(validate_bearer_token_length(&token, "ACL API").is_ok());
    }

    #[test]
    fn token_length_accepts_max_boundary() {
        let token = vec![b'a'; MAX_TOKEN_LEN];
        assert!(validate_bearer_token_length(&token, "ACL API").is_ok());
    }

    #[test]
    fn token_length_accepts_mid_range() {
        let token = vec![b'a'; 64];
        assert!(validate_bearer_token_length(&token, "ACL API").is_ok());
    }

    #[test]
    fn token_length_uses_custom_label() {
        let short = vec![b'a'; MIN_TOKEN_LEN - 1];
        let err = validate_bearer_token_length(&short, "metrics bearer").unwrap_err();
        assert!(err.contains("metrics bearer"), "got: {err}");
    }
}
