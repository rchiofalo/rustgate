//! CSR signing request handlers (v1 and v2 endpoints).

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode};

use super::util::{build_response, extract_param};
use crate::auth::Credentials;
use crate::ratelimit::RateLimiter;
use crate::response;
use crate::server::RateLimitCallback;
use crate::signing::CsrSigner;

/// Handle the `/Marti/api/tls/config` endpoint.
pub(crate) fn handle_tls_config(signer: &CsrSigner) -> Response<Full<Bytes>> {
    let xml = response::tls_config_xml(signer.organization());
    build_response(StatusCode::OK, "application/xml", Bytes::from(xml))
}

/// signClient v1 — returns a PKCS#12 (.p12) bundle for legacy clients.
///
/// Same auth and CSR flow as v2, but the response is a binary PKCS#12
/// bundle containing the signed client cert and CA cert, encrypted with
/// the standard password ("atakatak").
pub(crate) async fn handle_sign_client_v1(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    signer: &CsrSigner,
    credentials: &Credentials,
    sign_limiter: &RateLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
) -> Response<Full<Bytes>> {
    // Rate limit before doing any work
    if !sign_limiter.check(peer.ip()) {
        let masked_peer = rustgate_core::masking::mask_ip(&peer.to_string());
        tracing::warn!(peer = %masked_peer, "CSR signing rate limited");
        rustgate_core::audit::rate_limit_triggered(
            &masked_peer,
            "/Marti/api/tls/signClient",
            sign_limiter.max_requests(),
        );
        if let Some(cb) = on_rate_limit {
            cb();
        }
        return build_response(
            StatusCode::TOO_MANY_REQUESTS,
            "text/plain",
            Bytes::from("rate limit exceeded"),
        );
    }

    // Validate Basic Auth
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(username) = credentials.validate(auth_header) else {
        let masked_peer = rustgate_core::masking::mask_ip(&peer.to_string());
        rustgate_core::audit::enrollment_auth_failed(&masked_peer);
        let mut resp = build_response(
            StatusCode::UNAUTHORIZED,
            "text/plain",
            Bytes::from("unauthorized"),
        );
        let _ = resp.headers_mut().insert(
            "WWW-Authenticate",
            hyper::header::HeaderValue::from_static("Basic realm=\"rustgate-enrollment\""),
        );
        return resp;
    };

    let client_uid: String = req
        .uri()
        .query()
        .and_then(|q| extract_param(q, "clientUID").or_else(|| extract_param(q, "clientUid")))
        .unwrap_or_default()
        .chars()
        .take(128)
        .collect();

    // Read body (64KB limit)
    let limited = Limited::new(req.into_body(), 65536);
    let body = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("CSR too large or unreadable"),
            );
        }
    };

    let csr_text = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => {
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("request body is not valid UTF-8"),
            );
        }
    };

    let signed_der = match signer.sign_csr(csr_text, username) {
        Ok(der) => der,
        Err(e) => {
            rustgate_core::audit::enrollment_sign_failed(username, &client_uid, &e.to_string());
            tracing::warn!(
                error = %e,
                username = %username,
                client_uid = %client_uid,
                "CSR signing failed"
            );
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("failed to sign CSR"),
            );
        }
    };

    let p12 = match crate::pkcs12::build_p12_bundle(&signed_der, signer.ca_cert_der()) {
        Ok(bundle) => bundle,
        Err(e) => {
            tracing::warn!(
                error = %e,
                username = %username,
                client_uid = %client_uid,
                "PKCS#12 bundle creation failed"
            );
            return build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                Bytes::from("failed to create PKCS#12 bundle"),
            );
        }
    };

    rustgate_core::audit::enrollment_signed(username, &client_uid);
    rustgate_core::audit::enrollment_certificate_issued(username, &client_uid, "pkcs12");
    tracing::info!(
        username = %username,
        client_uid = %client_uid,
        format = "pkcs12",
        "signed client certificate (v1)"
    );

    build_response(StatusCode::OK, "application/x-pkcs12", Bytes::from(p12))
}

/// signClient v2 — returns signed certificate as JSON or XML.
pub(crate) async fn handle_sign_client_v2(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    signer: &CsrSigner,
    credentials: &Credentials,
    sign_limiter: &RateLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
) -> Response<Full<Bytes>> {
    // Rate limit before doing any work
    if !sign_limiter.check(peer.ip()) {
        let masked_peer = rustgate_core::masking::mask_ip(&peer.to_string());
        tracing::warn!(peer = %masked_peer, "CSR signing rate limited");
        rustgate_core::audit::rate_limit_triggered(
            &masked_peer,
            "/Marti/api/tls/signClient/v2",
            sign_limiter.max_requests(),
        );
        if let Some(cb) = on_rate_limit {
            cb();
        }
        return build_response(
            StatusCode::TOO_MANY_REQUESTS,
            "text/plain",
            Bytes::from("rate limit exceeded"),
        );
    }

    // Validate Basic Auth
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(username) = credentials.validate(auth_header) else {
        let masked_peer = rustgate_core::masking::mask_ip(&peer.to_string());
        rustgate_core::audit::enrollment_auth_failed(&masked_peer);
        let mut resp = build_response(
            StatusCode::UNAUTHORIZED,
            "text/plain",
            Bytes::from("unauthorized"),
        );
        let _ = resp.headers_mut().insert(
            "WWW-Authenticate",
            hyper::header::HeaderValue::from_static("Basic realm=\"rustgate-enrollment\""),
        );
        return resp;
    };

    // Extract clientUID from query params (optional, for logging).
    // Truncated to 128 bytes to prevent log injection / bloat.
    let client_uid: String = req
        .uri()
        .query()
        .and_then(|q| extract_param(q, "clientUID").or_else(|| extract_param(q, "clientUid")))
        .unwrap_or_default()
        .chars()
        .take(128)
        .collect();

    // Content negotiation (check before consuming body)
    let wants_xml = req
        .headers()
        .get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/xml"));

    // Read body with enforced size limit (64KB max for a CSR).
    // Limited wraps the body stream so oversized payloads are rejected
    // before being fully buffered — prevents OOM from large requests.
    let limited = Limited::new(req.into_body(), 65536);
    let body = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("CSR too large or unreadable"),
            );
        }
    };

    let csr_text = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => {
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("request body is not valid UTF-8"),
            );
        }
    };

    // Sign the CSR — CN is set to the authenticated username,
    // not whatever the CSR claims, to prevent impersonation.
    let signed_der = match signer.sign_csr(csr_text, username) {
        Ok(der) => der,
        Err(e) => {
            rustgate_core::audit::enrollment_sign_failed(username, &client_uid, &e.to_string());
            tracing::warn!(
                error = %e,
                username = %username,
                client_uid = %client_uid,
                "CSR signing failed"
            );
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("failed to sign CSR"),
            );
        }
    };

    let (content_type, body) = if wants_xml {
        (
            "application/xml",
            response::xml_response(&signed_der, signer.ca_cert_der()),
        )
    } else {
        (
            "application/json",
            response::json_response(&signed_der, signer.ca_cert_der()),
        )
    };

    rustgate_core::audit::enrollment_signed(username, &client_uid);
    rustgate_core::audit::enrollment_certificate_issued(username, &client_uid, "v2");
    tracing::info!(
        username = %username,
        client_uid = %client_uid,
        format = %content_type,
        "signed client certificate"
    );

    build_response(StatusCode::OK, content_type, Bytes::from(body))
}
