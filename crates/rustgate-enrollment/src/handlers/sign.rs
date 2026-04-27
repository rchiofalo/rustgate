// Copyright © 2026 Roberto Chiofalo.

//! CSR signing request handlers (v1 and v2 endpoints).

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode};
use rustgate_core::sanitize::sanitize_for_log;
use rustgate_resilience::SlidingWindowLimiter;

use super::util::{build_response, extract_param};
use crate::auth::Credentials;
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
    sign_limiter: &SlidingWindowLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
) -> Response<Full<Bytes>> {
    // Rate limit before doing any work. The SlidingWindowLimiter
    // emits the structured `security.rate_limited` audit event
    // internally on rejection (with `endpoint = self.category()`
    // = "request"), so the previous explicit caller-side audit
    // call is no longer needed.
    if sign_limiter.is_limited(peer.ip()) {
        let masked_peer = rustgate_core::masking::mask_ip(&peer.to_string());
        tracing::warn!(peer = %masked_peer, "CSR signing rate limited");
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

    // `client_uid` is attacker-controlled query-param bytes (truncated
    // to 128 chars but not stripped of CR/LF or other control
    // characters). Sanitize once here for use in structured-log fields;
    // the audit emissions are sanitized at the audit boundary (#1197).
    let client_uid_log = sanitize_for_log(&client_uid);

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
                client_uid = %client_uid_log,
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
                client_uid = %client_uid_log,
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
        client_uid = %client_uid_log,
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
    sign_limiter: &SlidingWindowLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
) -> Response<Full<Bytes>> {
    // Rate limit before doing any work. Audit emission lives inside
    // `SlidingWindowLimiter` (category = "request"); no caller-side
    // call is needed.
    if sign_limiter.is_limited(peer.ip()) {
        let masked_peer = rustgate_core::masking::mask_ip(&peer.to_string());
        tracing::warn!(peer = %masked_peer, "CSR signing rate limited");
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
    // Truncation alone does not neutralize CR/LF or other control
    // characters, so sanitize before use in structured-log fields.
    // (Audit emission paths are sanitized at the audit boundary by
    // #1197; this is operational defense-in-depth for the tracing
    // call sites.)
    let client_uid_log = sanitize_for_log(&client_uid);

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
                client_uid = %client_uid_log,
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
        client_uid = %client_uid_log,
        format = %content_type,
        "signed client certificate"
    );

    build_response(StatusCode::OK, content_type, Bytes::from(body))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::sync::OnceLock;

    use http_body_util::BodyExt;

    use super::*;

    /// Build a signer over a shared in-process CA.
    ///
    /// The CA keypair is cached in a `OnceLock` because `TestCa::new` runs
    /// ed25519/ECDSA key generation, which is orders of magnitude slower
    /// than anything we are actually pinning in this module. Reusing the
    /// same CA across every test keeps the file under ~100 ms.
    fn signer_with_org(org: &str) -> CsrSigner {
        static CA: OnceLock<(String, String)> = OnceLock::new();
        let (cert_pem, key_pem) = CA.get_or_init(|| {
            let ca = rustgate_test_utils::certs::TestCa::new("Test CA");
            (ca.cert_pem, ca.key_pem)
        });
        CsrSigner::from_pem(cert_pem, key_pem, org).expect("build signer")
    }

    /// Collect a `Response<Full<Bytes>>` body to `Bytes` without losing
    /// the status/header context (the caller can still inspect those
    /// before passing the response in).
    async fn collect_body(resp: Response<Full<Bytes>>) -> Bytes {
        resp.into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes()
    }

    /// `/Marti/api/tls/config` is TAK's unauthenticated preflight — the
    /// client hits it before it has any credentials to compute a CSR. If
    /// the handler ever returns anything other than `200 OK`, clients
    /// silently fail enrollment with no auth challenge to guide the
    /// operator. Pinning the status code separately from the body lets a
    /// regression on one surface fail loudly without masking the other.
    #[tokio::test]
    async fn handle_tls_config_returns_200_ok() {
        let signer = signer_with_org("MyOrg");
        let resp = handle_tls_config(&signer);
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "tls/config must return 200 — TAK clients abort enrollment on any other status"
        );
    }

    /// TAK clients dispatch the response on the exact Content-Type value;
    /// a drift to `text/xml` (RFC 3023 legacy synonym and a common
    /// editor-autocomplete typo) or an added `; charset=UTF-8` suffix has
    /// been observed to break specific client builds. Nail the header to
    /// `application/xml` verbatim.
    #[tokio::test]
    async fn handle_tls_config_sets_content_type_application_xml() {
        let signer = signer_with_org("MyOrg");
        let resp = handle_tls_config(&signer);
        let ct = resp
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(
            ct, "application/xml",
            "Content-Type must be the exact literal `application/xml` — no text/xml, no charset"
        );
    }

    /// The only reason `handle_tls_config` takes a `&CsrSigner` rather
    /// than a plain config struct is to pull the organization string at
    /// response time. A refactor that hardcodes the org or pulls it from
    /// a separate source would silently decouple the config knob from the
    /// response. Verify the configured org actually makes it into the
    /// body.
    #[tokio::test]
    async fn handle_tls_config_body_contains_signer_organization_name() {
        let signer = signer_with_org("Alpha-Company");
        let resp = handle_tls_config(&signer);
        let body = collect_body(resp).await;
        let text = std::str::from_utf8(&body).expect("response must be UTF-8 XML");
        assert!(
            text.contains("Alpha-Company"),
            "handler must thread signer.organization() into the response body; got: {text}"
        );
    }

    /// A regression that accidentally returns JSON, a plain string, or a
    /// truncated fragment would pass the `application/xml` content-type
    /// pin (if the header is set at the same point) but still break TAK
    /// parsers. Anchor the body to the `<?xml` prolog so any format drift
    /// fails loudly instead of producing garbled-but-typed output.
    #[tokio::test]
    async fn handle_tls_config_body_starts_with_xml_declaration() {
        let signer = signer_with_org("MyOrg");
        let resp = handle_tls_config(&signer);
        let body = collect_body(resp).await;
        let text = std::str::from_utf8(&body).expect("response must be UTF-8 XML");
        assert!(
            text.starts_with("<?xml"),
            "body must begin with the XML prolog so TAK parsers lock onto version/encoding: {text}"
        );
    }

    /// The handler delegates to `response::tls_config_xml`, which in turn
    /// calls `xml_escape` on the organization string. A future refactor
    /// that inlines the XML with `format!` and skips escaping would
    /// produce malformed XML whenever an operator's org name contains `&`
    /// — and in the worst case it would open an XML-injection vector
    /// (closing the `value="…"` attribute and injecting arbitrary
    /// `<nameEntry>` children the server never intended). Pin the
    /// delegation by picking an org value with both `&` and `<`; the raw
    /// form must not appear and the escaped form must.
    #[tokio::test]
    async fn handle_tls_config_escapes_xml_special_characters_in_organization() {
        let signer = signer_with_org("A&B<C");
        let resp = handle_tls_config(&signer);
        let body = collect_body(resp).await;
        let text = std::str::from_utf8(&body).expect("response must be UTF-8 XML");
        assert!(
            !text.contains("A&B<C"),
            "raw unescaped organization must not appear — would break XML parsers and permit injection: {text}"
        );
        assert!(
            text.contains("A&amp;B&lt;C"),
            "organization must be XML-escaped (& → &amp;, < → &lt;) for parser safety: {text}"
        );
    }
}
