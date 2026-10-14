// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Certificate revocation and CRL endpoint handlers.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};

use super::util::{build_response, redact_paths};
use crate::auth::Credentials;
use crate::revocation::RevocationStore;

/// Handle `POST /api/revoke` — revoke a certificate by serial number.
///
/// Requires Basic auth credentials. Request body is JSON:
/// ```json
/// {"serial": "aabbccdd", "reason": "key_compromise"}
/// ```
///
/// Supported reasons: `key_compromise`, `ca_compromise`, `affiliation_changed`,
/// `superseded`, `cessation_of_operation`, `privilege_withdrawn`, or `unspecified`.
#[tracing::instrument(
    name = "enrollment.revoke",
    level = "info",
    skip_all,
    fields(peer = %rustgate_core::masking::mask_ip(&peer.to_string())),
)]
pub(crate) async fn handle_revoke<B>(
    req: Request<B>,
    peer: std::net::SocketAddr,
    credentials: &Credentials,
    revocation: &RevocationStore,
) -> Response<Full<Bytes>>
where
    B: hyper::body::Body,
    B::Data: bytes::Buf,
{
    // Validate Basic Auth
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(username) = credentials.validate(auth_header) else {
        let masked = rustgate_core::masking::mask_ip(&peer.to_string());
        rustgate_core::audit::enrollment_auth_failed(&masked);
        return build_response(
            StatusCode::UNAUTHORIZED,
            "text/plain",
            Bytes::from("unauthorized"),
        );
    };

    // Read body
    use http_body_util::BodyExt;
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("failed to read request body"),
            );
        }
    };

    // Parse JSON
    let request: RevokeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            // Full error (may carry file context) stays server-side for
            // triage; the client-facing copy has any filesystem path
            // redacted so shared logs cannot leak deployment topology.
            tracing::warn!(error = %e, "revoke request body was not valid JSON");
            let safe = redact_paths(&e.to_string());
            return build_response(
                StatusCode::BAD_REQUEST,
                "application/json",
                Bytes::from(format!(r#"{{"error":"invalid JSON: {safe}"}}"#)),
            );
        }
    };

    if request.serial.is_empty() {
        return build_response(
            StatusCode::BAD_REQUEST,
            "application/json",
            Bytes::from(r#"{"error":"serial is required"}"#),
        );
    }

    // Validate serial is hex-only to prevent JSON injection in responses.
    if !request.serial.chars().all(|c| c.is_ascii_hexdigit()) {
        return build_response(
            StatusCode::BAD_REQUEST,
            "application/json",
            Bytes::from(r#"{"error":"serial must be hex characters only"}"#),
        );
    }

    // Perform revocation
    match revocation
        .revoke(&request.serial, &request.reason, username)
        .await
    {
        Ok(true) => build_response(
            StatusCode::OK,
            "application/json",
            Bytes::from(format!(
                r#"{{"status":"revoked","serial":"{}"}}"#,
                request.serial
            )),
        ),
        Ok(false) => build_response(
            StatusCode::OK,
            "application/json",
            Bytes::from(format!(
                r#"{{"status":"already_revoked","serial":"{}"}}"#,
                request.serial
            )),
        ),
        Err(e) => {
            // Full error (may embed the revocation DB path via io::Error)
            // is logged server-side; the client sees a path-redacted copy.
            tracing::error!(error = %e, serial = %request.serial, "revocation failed");
            let safe = redact_paths(&e.to_string());
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                Bytes::from(format!(r#"{{"error":"revocation failed: {safe}"}}"#)),
            )
        }
    }
}

/// Handle `GET /api/crl` — serve the current CRL as PEM.
pub(crate) async fn handle_crl(revocation: &RevocationStore) -> Response<Full<Bytes>> {
    match revocation.crl_pem().await {
        Ok(pem) => build_response(StatusCode::OK, "application/x-pem-file", Bytes::from(pem)),
        Err(e) => {
            tracing::error!(error = %e, "CRL generation failed");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                Bytes::from("CRL generation failed"),
            )
        }
    }
}

/// Handle `GET /api/revoked` — list all revoked certificates.
pub(crate) async fn handle_list_revoked(revocation: &RevocationStore) -> Response<Full<Bytes>> {
    let entries = revocation.list_revoked().await;
    match serde_json::to_vec(&entries) {
        Ok(json) => build_response(StatusCode::OK, "application/json", Bytes::from(json)),
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize revoked entries");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                Bytes::from(r#"{"error":"serialization failed"}"#),
            )
        }
    }
}

/// JSON body for `POST /api/revoke`.
///
/// Uses `deny_unknown_fields` to reject API requests containing
/// unexpected keys — a typo like `"sereal"` produces an explicit
/// `400 Bad Request` instead of silently parsing as a missing-field
/// error or, worse, a body where the typo is ignored and the missing
/// field defaults somewhere downstream (#815, F-136).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
    serial: String,
    #[serde(default = "default_reason")]
    reason: String,
}

fn default_reason() -> String {
    "unspecified".to_string()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use http_body_util::BodyExt;
    use hyper::StatusCode;

    use super::*;
    use crate::revocation::RevocationStore;

    async fn collect_body(resp: Response<Full<Bytes>>) -> (StatusCode, Option<String>, Bytes) {
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        (status, content_type, bytes)
    }

    async fn fresh_store() -> (tempfile::TempDir, RevocationStore) {
        let ca = rustgate_test_utils::certs::TestCa::new("Revoke Handler Test CA");
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("revocations.json");
        let store = RevocationStore::new(db_path, &ca.cert_pem, &ca.key_pem)
            .await
            .unwrap();
        (dir, store)
    }

    fn basic_auth_header(user: &str, pass: &str) -> String {
        format!(
            "Basic {}",
            rustgate_core::b64::encode(format!("{user}:{pass}"))
        )
    }

    /// Build a `Request<Full<Bytes>>` for `handle_revoke`. The handler is
    /// generic over the body type, so a `Full`-bodied request stands in
    /// for the production `Incoming` body (which has no public constructor
    /// and cannot be built in a unit test).
    fn revoke_request_with_body(auth: &str, body: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(hyper::Method::POST)
            .uri("/api/revoke")
            .header(hyper::header::AUTHORIZATION, auth)
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }

    /// End-to-end split-surface guarantee at the handler boundary
    /// (F-149, #1526). `serde_json`'s `deny_unknown_fields` error echoes
    /// the offending field name verbatim, so a request body carrying an
    /// unknown field whose name is a filesystem path drives a genuine
    /// path fragment into the error string. The client-facing JSON
    /// response must still signal failure correctly (HTTP 400, well-formed
    /// JSON, still names "invalid JSON") but must NOT contain any `/`
    /// path fragment — `handle_revoke` routes the error through
    /// `redact_paths` before rendering. The full, unredacted error stays
    /// server-side via `tracing::warn!` per the split-surface policy.
    ///
    /// This is non-vacuous: without the redaction call, the raw serde
    /// error `unknown field `/etc/rustgate/ca.key`, expected …` would put
    /// a `/`-rooted path straight into the body (asserted below via the
    /// `raw` control string).
    #[tokio::test]
    async fn handle_revoke_response_redacts_path_from_error_body() {
        let (_dir, store) = fresh_store().await;
        let creds = crate::auth::Credentials::new(
            "admin".to_string(),
            zeroize::Zeroizing::new("secret".to_string()),
        );
        let auth = basic_auth_header("admin", "secret");
        // Unknown field name IS an absolute path; deny_unknown_fields will
        // echo it into the serde error.
        let leaky_field = "/etc/rustgate/ca.key";
        let body = format!(r#"{{"serial":"deadbeef","{leaky_field}":"x"}}"#);
        let req = revoke_request_with_body(&auth, &body);
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 4444));

        // Control: the raw (un-redacted) serde error really does carry the
        // path, so the no-slash assertion below is meaningful.
        let raw = match serde_json::from_slice::<RevokeRequest>(body.as_bytes()) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("unknown field must fail to parse"),
        };
        assert!(
            raw.contains(leaky_field),
            "precondition: raw serde error must embed the path, got: {raw}"
        );

        let resp = handle_revoke(req, peer, &creds, &store).await;
        let (status, content_type, resp_body) = collect_body(resp).await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a bad body must still surface as a 400 — redaction does not swallow the failure"
        );
        assert_eq!(content_type.as_deref(), Some("application/json"));
        let body_str = std::str::from_utf8(&resp_body).expect("utf8 body");
        assert!(
            body_str.contains("invalid JSON"),
            "client message must still name the failure mode: {body_str}"
        );
        assert!(
            !body_str.contains('/'),
            "client response must not leak any filesystem path fragment: {body_str}"
        );
        // The response must still be well-formed JSON despite redaction.
        let parsed: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("error response must be valid JSON");
        assert!(
            parsed.get("error").and_then(|v| v.as_str()).is_some(),
            "error response must carry a string `error` field: {body_str}"
        );
    }

    #[tokio::test]
    async fn handle_crl_returns_pem_with_correct_content_type() {
        let (_dir, store) = fresh_store().await;

        let resp = handle_crl(&store).await;
        let (status, content_type, body) = collect_body(resp).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("application/x-pem-file"));
        let body_str = std::str::from_utf8(&body).expect("utf8 CRL PEM");
        assert!(
            body_str.contains("-----BEGIN X509 CRL-----"),
            "CRL PEM missing begin marker: {body_str}"
        );
        assert!(
            body_str.contains("-----END X509 CRL-----"),
            "CRL PEM missing end marker: {body_str}"
        );
    }

    #[tokio::test]
    async fn handle_crl_reflects_newly_revoked_serial() {
        let (_dir, store) = fresh_store().await;
        let newly = store
            .revoke("deadbeef", "key_compromise", "admin")
            .await
            .unwrap();
        assert!(newly);

        let resp = handle_crl(&store).await;
        let (status, _, body) = collect_body(resp).await;
        assert_eq!(status, StatusCode::OK);
        let pem = std::str::from_utf8(&body).expect("utf8");

        // Decode the PEM body to DER and confirm the revoked serial is
        // present. Matching on the raw PEM would be unsafe — base64 output
        // is not stable across re-encodings.
        let der_lines: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = rustgate_core::b64::decode(der_lines.trim()).expect("base64 CRL body");
        let (_, crl) =
            x509_parser::parse_x509_crl(&der).expect("parseable CRL DER from handler output");
        let serials: Vec<String> = crl
            .iter_revoked_certificates()
            .map(|entry| format!("{:x}", entry.user_certificate))
            .collect();
        assert!(
            serials.iter().any(|s| s == "deadbeef"),
            "expected deadbeef in revoked serials, got {serials:?}"
        );
    }

    #[tokio::test]
    async fn handle_list_revoked_returns_empty_array_when_no_revocations() {
        let (_dir, store) = fresh_store().await;

        let resp = handle_list_revoked(&store).await;
        let (status, content_type, body) = collect_body(resp).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("application/json"));
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
        assert_eq!(
            parsed.as_array().expect("JSON array").len(),
            0,
            "expected empty array, got {parsed}"
        );
    }

    #[tokio::test]
    async fn handle_list_revoked_returns_entries_with_expected_fields() {
        let (_dir, store) = fresh_store().await;
        let _ = store
            .revoke("aabbcc", "superseded", "operator")
            .await
            .unwrap();
        let _ = store
            .revoke("112233", "key_compromise", "admin")
            .await
            .unwrap();

        let resp = handle_list_revoked(&store).await;
        let (status, _, body) = collect_body(resp).await;
        assert_eq!(status, StatusCode::OK);

        let parsed: Vec<serde_json::Value> =
            serde_json::from_slice(&body).expect("JSON array of entries");
        assert_eq!(parsed.len(), 2);

        // Map by serial so we don't rely on HashMap iteration order.
        let mut by_serial: std::collections::HashMap<String, &serde_json::Value> =
            std::collections::HashMap::new();
        for entry in &parsed {
            let serial = entry["serial"].as_str().expect("serial str").to_string();
            let _ = by_serial.insert(serial, entry);
        }

        let aabbcc = by_serial.get("aabbcc").expect("aabbcc present");
        assert_eq!(aabbcc["reason"], "superseded");
        assert_eq!(aabbcc["revoked_by"], "operator");
        assert!(
            aabbcc["revoked_at"].as_u64().is_some(),
            "revoked_at should be a unix timestamp integer"
        );

        let t112233 = by_serial.get("112233").expect("112233 present");
        assert_eq!(t112233["reason"], "key_compromise");
        assert_eq!(t112233["revoked_by"], "admin");
    }

    #[test]
    fn revoke_request_uses_default_reason_when_absent() {
        let parsed: RevokeRequest =
            serde_json::from_str(r#"{"serial":"aa"}"#).expect("parses with default reason");
        assert_eq!(parsed.serial, "aa");
        assert_eq!(parsed.reason, "unspecified");
    }

    #[test]
    fn revoke_request_honours_explicit_reason() {
        let parsed: RevokeRequest =
            serde_json::from_str(r#"{"serial":"bb","reason":"cessation_of_operation"}"#)
                .expect("parses with explicit reason");
        assert_eq!(parsed.serial, "bb");
        assert_eq!(parsed.reason, "cessation_of_operation");
    }

    #[test]
    fn default_reason_is_unspecified() {
        assert_eq!(default_reason(), "unspecified");
    }

    /// Pin that `RevokeRequest::deserialize` rejects unknown JSON keys
    /// — without `deny_unknown_fields`, a typo like `"sereal"` would be
    /// silently ignored and the request would fail downstream with the
    /// less actionable "missing serial" error instead of pointing at
    /// the actual mistake (#815, F-136).
    #[test]
    fn revoke_request_rejects_unknown_field() {
        let json = r#"{"serial":"aa","sereal":"bb"}"#;
        let result: Result<RevokeRequest, _> = serde_json::from_str(json);
        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("typo'd `sereal` must be rejected by deny_unknown_fields"),
        };
        assert!(
            err.contains("unknown field") && err.contains("sereal"),
            "error should name the offending field: {err}"
        );
    }
}
