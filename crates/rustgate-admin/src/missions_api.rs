// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! REST API for the lightweight TAK Data Packages endpoint.
//!
//! Defines the request handler that the admin HTTP server will mount
//! under `/api/packages/` once the dispatcher is widened to call it
//! (see the [`MissionsApiHandler`] type alias for the shape). All
//! endpoints require a valid `Authorization: Bearer <token>` header
//! — the bearer-token discipline mirrors [`crate::acl_api`] so a
//! single operator-managed token controls every mutating REST
//! surface on the admin port.
//!
//! ## Wiring status (Feature 17 of #860, MVP)
//!
//! This PR introduces the handler, the [`MissionsApiState`] shared
//! state, and the [`MissionsApiHandler`] type alias. The dispatcher
//! in [`crate::server::serve`] still routes only `/api/federation/`,
//! `/api/acl/`, and `/api/cert/`-family paths; the
//! `/api/packages/` branch lands in a follow-up PR alongside the
//! `--missions-store-path` and `--missions-token-file` CLI flags
//! that will populate the `OnceLock`. The handler is publicly
//! exported so the follow-up can compose without further changes
//! to this module.
//!
//! ## Routes
//!
//! - `POST   /api/packages`        — upload (multipart/form-data, ZIP)
//! - `GET    /api/packages`        — list (JSON array of package metadata)
//! - `GET    /api/packages/{hash}` — download body by SHA-256 hash
//! - `DELETE /api/packages/{hash}` — remove
//!
//! Success responses use the same `{"data": ...}` envelope as
//! [`crate::acl_api`]; failures use `{"error": "..."}`. The download
//! endpoint is the lone exception — it returns the raw ZIP body with
//! `Content-Type: application/zip` so TAK clients can stream the body
//! directly into their package importer.
//!
//! See [`rustgate_missions`] for the on-disk store, the manifest
//! parser, and the integrity-tag layer this handler delegates to.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::CONTENT_TYPE;
use hyper::{Method, Response, StatusCode};
use rustgate_missions::{
    MissionsError, PackageStore, extract_boundary, extract_multipart_field,
    extract_multipart_filename, parse_manifest_xml,
};
use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Shared state for the missions REST API.
///
/// Held via [`std::sync::OnceLock`] in the admin server so the
/// dispatcher can route requests once the operator wires the store
/// in. Mirrors [`crate::AclApiState`] in shape so the registration
/// boilerplate at the call site stays identical.
pub struct MissionsApiState {
    /// Package store backing the four endpoints. Cheap to clone —
    /// the inner state is `Arc<...>` inside the store.
    pub store: PackageStore,
    /// Bearer token required on every request. Stored as raw bytes
    /// so we can use [`subtle::ConstantTimeEq`] for comparison.
    /// Wrapped in [`Zeroizing`] so the token is wiped from memory on
    /// drop, matching the discipline used by `acl_api`.
    pub auth_token: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for MissionsApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MissionsApiState").finish()
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
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&ErrorResponse { error: message }).unwrap_or_default();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

fn auth_ok(header: Option<&str>, expected: &[u8]) -> bool {
    let Some(raw) = header else {
        return false;
    };
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    token.as_bytes().ct_eq(expected).into()
}

/// Map a [`MissionsError`] to an HTTP status code and a client-safe
/// error string. The full chain is logged at debug; the response
/// body never leaks filesystem paths or internal hash details.
fn map_error(err: &MissionsError) -> (StatusCode, String) {
    match err {
        MissionsError::EmptyUpload => (StatusCode::BAD_REQUEST, "empty upload".to_string()),
        MissionsError::InvalidHash => (
            StatusCode::BAD_REQUEST,
            "invalid hash format (expected 64 lowercase hex chars)".to_string(),
        ),
        MissionsError::PackageTooLarge { actual, limit } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("package size {actual} exceeds per-package cap {limit}"),
        ),
        MissionsError::CapacityExceeded {
            actual,
            current,
            limit,
        } => (
            StatusCode::INSUFFICIENT_STORAGE,
            format!(
                "store capacity {limit} exceeded by {actual}-byte upload (current usage: {current})"
            ),
        ),
        MissionsError::NotFound { hash } => {
            (StatusCode::NOT_FOUND, format!("package {hash} not found"))
        }
        MissionsError::Manifest(msg) => {
            (StatusCode::BAD_REQUEST, format!("manifest invalid: {msg}"))
        }
        MissionsError::Hmac(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "package integrity verification failed".to_string(),
        ),
        MissionsError::Io { .. } | MissionsError::Json(_) | MissionsError::Config(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error".to_string(),
        ),
    }
}

/// Top-level dispatch entrypoint registered with the admin server's
/// `/api/packages/` routing slot.
///
/// Returns `None` only when `path` falls outside the prefix the
/// caller asked us to handle — the dispatcher uses that to keep its
/// fallthrough behaviour aligned with the other API handlers
/// (`acl_api`, federation API, mgmt API). Inside the prefix, every
/// outcome is a fully-formed `Response<Full<Bytes>>`.
pub async fn handle_request(
    method: &Method,
    path: &str,
    authorization: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
    state: &MissionsApiState,
) -> Option<Response<Full<Bytes>>> {
    if path != "/api/packages" && !path.starts_with("/api/packages/") {
        return None;
    }
    if !auth_ok(authorization, &state.auth_token) {
        return Some(json_error(StatusCode::UNAUTHORIZED, "unauthorized"));
    }

    let sub_path = if path == "/api/packages" {
        ""
    } else {
        // Safe — path starts with "/api/packages/".
        &path["/api/packages/".len()..]
    };

    Some(route(method, sub_path, content_type, body, state).await)
}

async fn route(
    method: &Method,
    sub_path: &str,
    content_type: Option<&str>,
    body: &[u8],
    state: &MissionsApiState,
) -> Response<Full<Bytes>> {
    match (method, sub_path) {
        (&Method::GET, "") => list_packages(state).await,
        (&Method::POST, "") => upload_package(state, content_type, body).await,
        (&Method::GET, hash) => download_package(state, hash).await,
        (&Method::DELETE, hash) => delete_package(state, hash).await,
        _ => json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    }
}

async fn list_packages(state: &MissionsApiState) -> Response<Full<Bytes>> {
    match state.store.list().await {
        Ok(items) => json_ok(&items),
        Err(e) => {
            let (status, msg) = map_error(&e);
            tracing::debug!(error = %e, "list packages failed");
            json_error(status, &msg)
        }
    }
}

async fn upload_package(
    state: &MissionsApiState,
    content_type: Option<&str>,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if body.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "empty request body");
    }

    // Two acceptable upload shapes:
    //  1. multipart/form-data with a `file` field — the canonical
    //     TAK client form. We extract the field bytes via the shared
    //     `rustgate_enrollment::datapackage` helpers.
    //  2. raw application/zip body — the simpler curl-friendly path,
    //     handy for ops scripts and integration tests.
    let (zip_bytes, name): (&[u8], String) =
        if let Some(ct) = content_type.filter(|ct| ct.starts_with("multipart/form-data")) {
            let Some(boundary) = extract_boundary(ct).map(|s| s.to_string()) else {
                return json_error(StatusCode::BAD_REQUEST, "missing multipart boundary");
            };
            let Some(zip) = extract_multipart_field(body, &boundary, "file") else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "multipart body missing `file` field",
                );
            };
            let filename = extract_multipart_filename(body, &boundary)
                .unwrap_or_else(|| "package.zip".to_string());
            (zip, filename)
        } else {
            (body, "package.zip".to_string())
        };

    if zip_bytes.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "empty package body");
    }

    // Best-effort manifest validation. We do not unzip the body —
    // doing so would pull in a ZIP parser for what is essentially a
    // hint. Instead we look for the literal MANIFEST/manifest.xml
    // bytes inside the body and parse the surrounding XML window. A
    // well-formed TAK package always carries the manifest as a top-
    // level entry, so the heuristic is sound enough to reject
    // outright-broken uploads while not blocking valid ones whose
    // manifest happens to be compressed.
    if let Some(span) = locate_manifest_window(zip_bytes)
        && let Err(e) = parse_manifest_xml(span)
    {
        tracing::debug!(error = %e, "uploaded package has unparseable manifest");
        // Best-effort only: log and continue. A future strict-mode
        // CLI flag can promote this to a hard reject.
    }

    let creator_uid = "admin-api"; // bearer-token principal — TODO future: per-token identity
    match state.store.upload(zip_bytes, &name, creator_uid).await {
        Ok(meta) => json_ok(&meta),
        Err(e) => {
            let (status, msg) = map_error(&e);
            tracing::debug!(error = %e, "upload failed");
            json_error(status, &msg)
        }
    }
}

async fn download_package(state: &MissionsApiState, hash: &str) -> Response<Full<Bytes>> {
    match state.store.download(hash).await {
        Ok((meta, bytes)) => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, meta.mime_type)
            .header(
                "content-disposition",
                format!("attachment; filename=\"{}\"", meta.name),
            )
            .body(Full::new(Bytes::from(bytes)))
            .unwrap_or_else(|_| internal_error_response()),
        Err(e) => {
            let (status, msg) = map_error(&e);
            tracing::debug!(hash = %hash, error = %e, "download failed");
            json_error(status, &msg)
        }
    }
}

async fn delete_package(state: &MissionsApiState, hash: &str) -> Response<Full<Bytes>> {
    match state.store.delete(hash).await {
        Ok(meta) => {
            tracing::info!(
                target: "audit",
                event_type = "missions.package_deleted",
                hash = %meta.hash,
                name = %meta.name,
                "data package deleted via REST API"
            );
            json_ok(&meta)
        }
        Err(e) => {
            let (status, msg) = map_error(&e);
            tracing::debug!(hash = %hash, error = %e, "delete failed");
            json_error(status, &msg)
        }
    }
}

/// Best-effort search for a manifest XML window inside a ZIP body.
///
/// We do not invoke a ZIP parser — pulling one in just to validate
/// a hint is more dependency surface than the validation is worth.
/// Instead we scan for the `<MissionPackageManifest` open tag and
/// the matching `</MissionPackageManifest>` close. If both are
/// present (the common case for an uncompressed manifest entry, and
/// for some default ZIP encoders that store XML uncompressed), we
/// hand the window to the manifest parser. Compressed-manifest
/// uploads return `None`, which the upload path treats as
/// "validation skipped" rather than rejecting.
fn locate_manifest_window(zip_bytes: &[u8]) -> Option<&[u8]> {
    let open_needle = b"<MissionPackageManifest";
    let close_needle = b"</MissionPackageManifest>";
    let start = find_subslice(zip_bytes, open_needle)?;
    let close_rel = find_subslice(&zip_bytes[start..], close_needle)?;
    let end = start + close_rel + close_needle.len();
    Some(&zip_bytes[start..end])
}

/// Linear search for `needle` inside `haystack`. The byte volumes
/// here are bounded by the per-package cap so the O(N·M) bound is
/// acceptable; bringing in `memchr` for one call site would not
/// pay back the dependency cost.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Type-erased handler shape registered with the admin server's
/// `/api/packages/` routing slot. The dispatcher in `server.rs`
/// stores this in an `Arc<OnceLock<…>>` so the package store can be
/// wired in after the metrics server starts listening.
pub type MissionsApiHandler = Arc<
    dyn Fn(
            &hyper::Method,
            &str,
            Option<&str>,
            Option<&str>,
            &[u8],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<Response<Full<Bytes>>>> + Send>,
        > + Send
        + Sync,
>;

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use http_body_util::BodyExt;
    use rustgate_missions::StoreLimits;
    use tempfile::TempDir;

    use super::*;

    fn token() -> Vec<u8> {
        b"missions-api-test-token-padding-32b".to_vec()
    }

    async fn build_state() -> (TempDir, MissionsApiState) {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::new(
            dir.path().to_path_buf(),
            b"missions-api-integrity-key-32-bytes".to_vec(),
            StoreLimits::default(),
        )
        .await
        .unwrap();
        let state = MissionsApiState {
            store,
            auth_token: Zeroizing::new(token()),
        };
        (dir, state)
    }

    async fn body_text(resp: Response<Full<Bytes>>) -> (StatusCode, String) {
        let status = resp.status();
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&collected).to_string())
    }

    #[tokio::test]
    async fn unauthorized_without_bearer_token() {
        let (_dir, state) = build_state().await;
        let resp = handle_request(&Method::GET, "/api/packages", None, None, b"", &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unauthorized_with_wrong_token() {
        let (_dir, state) = build_state().await;
        let resp = handle_request(
            &Method::GET,
            "/api/packages",
            Some("Bearer not-the-right-token-padding-32b"),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn fallthrough_for_non_missions_path() {
        let (_dir, state) = build_state().await;
        let resp = handle_request(&Method::GET, "/api/acl/groups", None, None, b"", &state).await;
        assert!(resp.is_none(), "non-missions path must yield None");
    }

    #[tokio::test]
    async fn empty_listing() {
        let (_dir, state) = build_state().await;
        let resp = handle_request(
            &Method::GET,
            "/api/packages",
            Some(&format!("Bearer {}", String::from_utf8(token()).unwrap())),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        let (status, body) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"data\":[]"));
    }

    #[tokio::test]
    async fn raw_zip_upload_then_list_then_download() {
        let (_dir, state) = build_state().await;
        let auth = format!("Bearer {}", String::from_utf8(token()).unwrap());
        let body = b"PK\x03\x04zip-pretend-body";
        let resp = handle_request(
            &Method::POST,
            "/api/packages",
            Some(&auth),
            Some("application/zip"),
            body,
            &state,
        )
        .await
        .unwrap();
        let (status, json) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.contains("\"hash\":"));

        // Pull the hash out of the response by simple substring
        // search — keeps the test free of a JSON dep.
        let hash_start = json.find("\"hash\":\"").unwrap() + "\"hash\":\"".len();
        let hash_end = hash_start + 64;
        let hash = &json[hash_start..hash_end];

        let resp = handle_request(
            &Method::GET,
            "/api/packages",
            Some(&auth),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        let (status, json) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.contains(hash));

        let resp = handle_request(
            &Method::GET,
            &format!("/api/packages/{hash}"),
            Some(&auth),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let (_, downloaded) = body_text(resp).await;
        assert!(downloaded.contains("zip-pretend-body"));
    }

    #[tokio::test]
    async fn delete_round_trip() {
        let (_dir, state) = build_state().await;
        let auth = format!("Bearer {}", String::from_utf8(token()).unwrap());
        let _ = state
            .store
            .upload(b"to-delete", "x.zip", "op")
            .await
            .unwrap();
        let listed = state.store.list().await.unwrap();
        let hash = listed[0].hash.clone();

        let resp = handle_request(
            &Method::DELETE,
            &format!("/api/packages/{hash}"),
            Some(&auth),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = handle_request(
            &Method::DELETE,
            &format!("/api/packages/{hash}"),
            Some(&auth),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invalid_hash_returns_400() {
        let (_dir, state) = build_state().await;
        let auth = format!("Bearer {}", String::from_utf8(token()).unwrap());
        let resp = handle_request(
            &Method::GET,
            "/api/packages/not-a-hash",
            Some(&auth),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unsupported_method_returns_405() {
        let (_dir, state) = build_state().await;
        let auth = format!("Bearer {}", String::from_utf8(token()).unwrap());
        let resp = handle_request(
            &Method::PATCH,
            "/api/packages",
            Some(&auth),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn locate_manifest_window_extracts_xml_blob() {
        let body = b"PKzip-prefix\n<MissionPackageManifest version=\"2\"><Configuration></Configuration><Contents><Content zipEntry=\"a.kml\"/></Contents></MissionPackageManifest>\n--ZIP-TAIL--";
        let span = locate_manifest_window(body).unwrap();
        assert!(span.starts_with(b"<MissionPackageManifest"));
        assert!(span.ends_with(b"</MissionPackageManifest>"));
    }

    #[test]
    fn locate_manifest_window_returns_none_when_absent() {
        assert!(locate_manifest_window(b"raw-zip-bytes-no-manifest").is_none());
    }
}
