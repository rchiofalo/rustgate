// Copyright © 2026 Roberto Chiofalo.

//! Certificate revocation and CRL endpoint handlers.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};

use super::util::build_response;
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
pub(crate) async fn handle_revoke(
    req: Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    credentials: &Credentials,
    revocation: &RevocationStore,
) -> Response<Full<Bytes>> {
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
            return build_response(
                StatusCode::BAD_REQUEST,
                "application/json",
                Bytes::from(format!(r#"{{"error":"invalid JSON: {e}"}}"#)),
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
            tracing::error!(error = %e, serial = %request.serial, "revocation failed");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                Bytes::from(format!(r#"{{"error":"revocation failed: {e}"}}"#)),
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

#[derive(serde::Deserialize)]
struct RevokeRequest {
    serial: String,
    #[serde(default = "default_reason")]
    reason: String,
}

fn default_reason() -> String {
    "unspecified".to_string()
}
