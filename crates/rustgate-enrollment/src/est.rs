// Copyright © 2026 Roberto Chiofalo.

//! EST (RFC 7030) enrollment endpoint handlers.
//!
//! Implements the Enrollment over Secure Transport protocol endpoints:
//!
//! - `GET  /.well-known/est/cacerts`        — CA certificate distribution
//! - `POST /.well-known/est/simpleenroll`   — initial certificate enrollment
//! - `POST /.well-known/est/simplereenroll` — certificate re-enrollment
//! - `GET  /.well-known/est/csrattrs`       — CSR attributes guidance
//!
//! All responses use the formats specified in RFC 7030 as clarified by
//! RFC 8951: DER-encoded structures, base64 per RFC 4648 Section 4.

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use rustgate_core::b64;
use rustgate_resilience::SlidingWindowLimiter;

use crate::auth::Credentials;
use crate::cms_bag;
use crate::error::EnrollmentError;
use crate::handlers::util::build_response;
use crate::server::RateLimitCallback;
use crate::signing::CsrSigner;

/// Content type for PKCS#7 certs-only responses (RFC 7030 §4.1.2).
const CT_PKCS7_CERTS_ONLY: &str = "application/pkcs7-mime; smime-type=certs-only";

/// Content type for CSR attributes responses.
const CT_CSR_ATTRS: &str = "application/csrattrs";

/// Content type for PKCS#10 CSR requests.
const CT_PKCS10: &str = "application/pkcs10";

// ---------------------------------------------------------------------------
// GET /.well-known/est/cacerts
// ---------------------------------------------------------------------------

/// Handle `GET /.well-known/est/cacerts`.
///
/// Returns the CA certificate chain as a PKCS#7 certs-only bag,
/// base64-encoded per RFC 7030. No authentication required.
pub fn handle_cacerts(signer: &CsrSigner) -> Response<Full<Bytes>> {
    match cms_bag::build_certs_only_base64(&[signer.ca_cert_der()]) {
        Ok(body) => build_response(StatusCode::OK, CT_PKCS7_CERTS_ONLY, Bytes::from(body)),
        Err(e) => {
            tracing::error!(error = %e, "EST /cacerts: failed to build PKCS#7 bag");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                Bytes::from("internal error building CA certificate response"),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// POST /.well-known/est/simpleenroll
// ---------------------------------------------------------------------------

/// Handle `POST /.well-known/est/simpleenroll`.
///
/// Accepts a base64-encoded PKCS#10 CSR, signs it with the CA, and returns
/// the issued certificate (plus CA chain) as a PKCS#7 certs-only bag.
///
/// Requires HTTP Basic authentication and is rate-limited per IP.
pub async fn handle_simpleenroll(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    signer: &CsrSigner,
    credentials: &Credentials,
    sign_limiter: &SlidingWindowLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
) -> Response<Full<Bytes>> {
    let (body, username) = match validate_and_read_body(
        req,
        peer,
        credentials,
        sign_limiter,
        on_rate_limit,
        "simpleenroll",
    )
    .await
    {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    sign_and_respond(&body, signer, username, &peer, "simpleenroll")
}

// ---------------------------------------------------------------------------
// POST /.well-known/est/simplereenroll
// ---------------------------------------------------------------------------

/// Handle `POST /.well-known/est/simplereenroll`.
///
/// Re-enrollment requires identity continuity: the CSR subject CN must match
/// the authenticated username (case-insensitive). This prevents a client from
/// escalating identity by requesting a certificate with a different CN.
///
/// Per RFC 7030, strict implementations should authenticate via TLS client
/// cert; we use HTTP Basic auth as a pragmatic fallback. The authenticated
/// username serves as the client's current identity.
pub async fn handle_simplereenroll(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    signer: &CsrSigner,
    credentials: &Credentials,
    sign_limiter: &SlidingWindowLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
) -> Response<Full<Bytes>> {
    let (body, username) = match validate_and_read_body(
        req,
        peer,
        credentials,
        sign_limiter,
        on_rate_limit,
        "simplereenroll",
    )
    .await
    {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    // Verify identity continuity: the CSR's subject CN must match the
    // authenticated username. This prevents identity escalation where a
    // client re-enrolls with a different CN than their current identity.
    match extract_csr_cn(&body) {
        Ok(Some(csr_cn)) => {
            if !csr_cn.eq_ignore_ascii_case(username) {
                tracing::warn!(
                    client_cn = %username,
                    requested_cn = %csr_cn,
                    "re-enrollment identity mismatch: client cannot change CN",
                );
                return build_response(
                    StatusCode::FORBIDDEN,
                    "text/plain",
                    Bytes::from(
                        "re-enrollment identity mismatch: CSR subject CN must match authenticated identity",
                    ),
                );
            }
        }
        Ok(None) => {
            tracing::warn!("EST /simplereenroll: CSR has no subject CN");
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("CSR must contain a subject CN for re-enrollment"),
            );
        }
        Err(e) => {
            tracing::debug!(error = %e, "EST /simplereenroll: failed to parse CSR subject");
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("unable to extract identity from CSR"),
            );
        }
    }

    sign_and_respond(&body, signer, username, &peer, "simplereenroll")
}

// ---------------------------------------------------------------------------
// GET /.well-known/est/csrattrs
// ---------------------------------------------------------------------------

/// Handle `GET /.well-known/est/csrattrs`.
///
/// Returns an empty CSR attributes response (HTTP 204), indicating the
/// server has no specific requirements for CSR fields. This is valid per
/// RFC 7030 Section 4.5.2.
///
/// Future versions may return specific attributes (key type, extensions)
/// to guide client CSR generation.
pub fn handle_csrattrs() -> Response<Full<Bytes>> {
    // 204 No Content: no specific CSR attributes required.
    // The CsrSigner overrides the subject anyway, so there's nothing
    // meaningful to request from the client.
    let _ = CT_CSR_ATTRS; // referenced for documentation, used when we return attributes
    build_response(StatusCode::NO_CONTENT, "", Bytes::new())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Common auth, content-type, and body-reading logic shared by both
/// enrollment endpoints. Returns the raw body bytes and authenticated
/// username, or an early-return HTTP error response.
async fn validate_and_read_body<'a>(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    credentials: &'a Credentials,
    sign_limiter: &SlidingWindowLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
    endpoint: &str,
) -> Result<(Vec<u8>, &'a str), Response<Full<Bytes>>> {
    // Rate limit check (before auth to prevent work amplification).
    // The SlidingWindowLimiter emits the structured audit event
    // internally on rejection (category = "request").
    if sign_limiter.is_limited(peer.ip()) {
        if let Some(cb) = on_rate_limit {
            cb();
        }
        return Err(build_response(
            StatusCode::TOO_MANY_REQUESTS,
            "text/plain",
            Bytes::from("rate limit exceeded"),
        ));
    }

    // Authentication.
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let username = match credentials.validate(auth_header) {
        Some(u) => u,
        None => {
            return Err(build_response_with_www_auth(
                StatusCode::UNAUTHORIZED,
                "text/plain",
                Bytes::from("authentication required"),
            ));
        }
    };

    // Read and validate Content-Type.
    let content_type = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with(CT_PKCS10) {
        return Err(build_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "text/plain",
            Bytes::from(format!(
                "expected Content-Type: {CT_PKCS10}, got: {content_type}"
            )),
        ));
    }

    // Read request body (base64-encoded DER CSR).
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, endpoint = %endpoint, "EST: failed to read body");
            return Err(build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("failed to read request body"),
            ));
        }
    };

    Ok((body, username))
}

/// Shared CSR signing and response-building logic for both enrollment endpoints.
///
/// Handles PEM decoding, CSR signing, audit logging, and PKCS#7 certs-only
/// response construction. Called by both `handle_simpleenroll` and
/// `handle_simplereenroll` after their respective validation steps.
fn sign_and_respond(
    body: &[u8],
    signer: &CsrSigner,
    username: &str,
    peer: &SocketAddr,
    endpoint: &str,
) -> Response<Full<Bytes>> {
    // Decode base64 → DER, then wrap in PEM for CsrSigner.
    let csr_pem = match decode_pkcs10_to_pem(body) {
        Ok(pem) => pem,
        Err(e) => {
            tracing::debug!(error = %e, endpoint = %endpoint, "EST: invalid CSR encoding");
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("invalid CSR format"),
            );
        }
    };

    // Sign the CSR.
    let signed_der = match signer.sign_csr(&csr_pem, username) {
        Ok(der) => der,
        Err(e) => {
            tracing::warn!(error = %e, endpoint = %endpoint, "EST: CSR signing failed");
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("unable to process CSR"),
            );
        }
    };

    let masked_peer = rustgate_core::masking::mask_ip(&peer.to_string());
    rustgate_core::audit::enrollment_signed(username, &masked_peer);
    tracing::info!(
        username = %username,
        peer = %masked_peer,
        endpoint = %endpoint,
        "EST certificate issued"
    );

    // Build PKCS#7 certs-only bag with [client cert, CA cert].
    match cms_bag::build_certs_only_base64(&[&signed_der, signer.ca_cert_der()]) {
        Ok(body) => build_response(StatusCode::OK, CT_PKCS7_CERTS_ONLY, Bytes::from(body)),
        Err(e) => {
            tracing::error!(error = %e, endpoint = %endpoint, "EST: failed to build response");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                Bytes::from("internal error building enrollment response"),
            )
        }
    }
}

/// OID for commonName (CN): 2.5.4.3 (RFC 4519).
const OID_COMMON_NAME: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");

/// Extract the subject CN from a base64-encoded PKCS#10 CSR body.
///
/// Decodes the base64, parses the DER as a PKCS#10 `CertReq`, and iterates
/// through the subject RDN sequence to find the CN attribute. Returns `None`
/// if the subject has no CN attribute.
fn extract_csr_cn(body: &[u8]) -> Result<Option<String>, EnrollmentError> {
    use der::{Decode as _, Tagged as _};

    // Strip whitespace and decode base64 → DER.
    let cleaned: String = body
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| *b as char)
        .collect();

    let der_bytes =
        b64::decode(&cleaned).map_err(|e| EnrollmentError::Csr(format!("invalid base64: {e}")))?;

    let csr = x509_cert::request::CertReq::from_der(&der_bytes)
        .map_err(|e| EnrollmentError::Csr(format!("failed to parse CSR: {e}")))?;

    // Walk the subject RDN sequence looking for CN (OID 2.5.4.3).
    for rdn in &csr.info.subject.0 {
        for atav in rdn.0.iter() {
            if atav.oid == OID_COMMON_NAME {
                // CN values are typically UTF8String or PrintableString.
                let cn = match atav.value.tag() {
                    der::Tag::Utf8String => der::asn1::Utf8StringRef::try_from(&atav.value)
                        .map(|s| s.as_str().to_string())
                        .map_err(|e| {
                            EnrollmentError::Csr(format!("failed to decode CN as UTF-8: {e}"))
                        })?,
                    der::Tag::PrintableString => {
                        der::asn1::PrintableStringRef::try_from(&atav.value)
                            .map(|s| s.as_str().to_string())
                            .map_err(|e| {
                                EnrollmentError::Csr(format!(
                                    "failed to decode CN as PrintableString: {e}"
                                ))
                            })?
                    }
                    tag => {
                        return Err(EnrollmentError::Csr(format!(
                            "unexpected CN value tag: {tag:?}"
                        )));
                    }
                };
                return Ok(Some(cn));
            }
        }
    }

    Ok(None)
}

/// Decode a base64-encoded PKCS#10 CSR body into PEM format for `CsrSigner`.
///
/// EST sends the CSR as base64 of DER (no PEM headers). We decode the
/// base64, then wrap the raw DER in PEM headers so `CsrSigner::sign_csr`
/// can parse it. Tolerates whitespace (CR, LF, spaces, tabs) in the input
/// per RFC 8951.
fn decode_pkcs10_to_pem(body: &[u8]) -> Result<String, EnrollmentError> {
    // Strip whitespace (RFC 8951 requires tolerance).
    let cleaned: String = body
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| *b as char)
        .collect();

    if cleaned.is_empty() {
        return Err(EnrollmentError::Csr("empty CSR body".into()));
    }

    // Validate the base64 decodes (catch malformed input early).
    let _ =
        b64::decode(&cleaned).map_err(|e| EnrollmentError::Csr(format!("invalid base64: {e}")))?;

    // Wrap in PEM headers for CsrSigner (which expects PEM or raw base64).
    Ok(format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{cleaned}\n-----END CERTIFICATE REQUEST-----"
    ))
}

/// Maximum CSR body size (64 KiB). CSRs are typically < 4 KiB; this
/// matches the limit used by the Marti `/signClient` endpoints.
const MAX_CSR_BODY: usize = 65536;

/// Read the full request body as bytes, enforcing a size limit.
async fn read_body(req: Request<hyper::body::Incoming>) -> Result<Vec<u8>, EnrollmentError> {
    use http_body_util::{BodyExt as _, Limited};

    let limited = Limited::new(req.into_body(), MAX_CSR_BODY);
    let collected = limited
        .collect()
        .await
        .map_err(|e| EnrollmentError::Io(std::io::Error::other(e)))?;

    Ok(collected.to_bytes().to_vec())
}

/// Build a 401 response with the `WWW-Authenticate: Basic` header.
fn build_response_with_www_auth(
    status: StatusCode,
    content_type: &str,
    body: Bytes,
) -> Response<Full<Bytes>> {
    let mut resp = build_response(status, content_type, body);
    let _ = resp.headers_mut().insert(
        hyper::header::WWW_AUTHENTICATE,
        hyper::header::HeaderValue::from_static("Basic realm=\"est\""),
    );
    resp
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    /// Generate a CSR as base64-encoded DER (EST wire format).
    fn generate_csr_b64(cn: &str) -> String {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;

        let csr = params.serialize_request(&key).unwrap();
        b64::encode(csr.der())
    }

    #[test]
    fn extract_cn_from_csr() {
        let b64 = generate_csr_b64("alice");
        let cn = extract_csr_cn(b64.as_bytes()).unwrap();
        assert_eq!(cn, Some("alice".to_string()));
    }

    #[test]
    fn extract_cn_preserves_case() {
        let b64 = generate_csr_b64("Alice");
        let cn = extract_csr_cn(b64.as_bytes()).unwrap();
        assert_eq!(cn, Some("Alice".to_string()));
    }

    #[test]
    fn extract_cn_returns_none_for_empty_subject() {
        use rcgen::{CertificateParams, DistinguishedName, KeyPair};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        // Empty DN — no CN attribute.
        params.distinguished_name = DistinguishedName::new();

        let csr = params.serialize_request(&key).unwrap();
        let encoded = b64::encode(csr.der());
        let cn = extract_csr_cn(encoded.as_bytes()).unwrap();
        assert_eq!(cn, None);
    }

    #[test]
    fn extract_cn_rejects_invalid_base64() {
        let result = extract_csr_cn(b"!!!not-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn extract_cn_rejects_invalid_der() {
        let encoded = b64::encode(b"not a valid CSR");
        let result = extract_csr_cn(encoded.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn reenroll_identity_match_case_insensitive() {
        let b64 = generate_csr_b64("Alice");
        let cn = extract_csr_cn(b64.as_bytes()).unwrap().unwrap();
        // Case-insensitive comparison as used in handle_simplereenroll.
        assert!(cn.eq_ignore_ascii_case("alice"));
        assert!(cn.eq_ignore_ascii_case("ALICE"));
        assert!(cn.eq_ignore_ascii_case("Alice"));
        assert!(!cn.eq_ignore_ascii_case("bob"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Module constants — pin the RFC 7030 / RFC 4519 / operational tokens so
    // a silent edit to the top-of-file strings surfaces here rather than as a
    // wire-level interop break with iTAK / ATAK / third-party EST clients.
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn content_type_constants_pin_rfc7030_wire_tokens() {
        assert_eq!(
            CT_PKCS7_CERTS_ONLY, "application/pkcs7-mime; smime-type=certs-only",
            "RFC 7030 §4.1.2 + §4.2.3 response content-type",
        );
        assert_eq!(CT_CSR_ATTRS, "application/csrattrs", "RFC 7030 §4.5.2");
        assert_eq!(CT_PKCS10, "application/pkcs10", "RFC 7030 §4.2.1");
    }

    #[test]
    fn oid_common_name_is_2_5_4_3_per_rfc4519() {
        // The CN OID is the load-bearing discriminator in extract_csr_cn's
        // RDN walk — a silent edit that pointed OID_COMMON_NAME at, say, the
        // OU or O OID (2.5.4.11 / 2.5.4.10) would make re-enrollment accept
        // every CSR regardless of subject CN, defeating the identity-
        // continuity check in handle_simplereenroll. This test fails loudly
        // on that class of regression rather than letting it slip past the
        // `extract_cn_from_csr` happy-path test (which would still pass
        // because rcgen emits the CN under the correct OID — it's the
        // *lookup* side that matters).
        assert_eq!(
            OID_COMMON_NAME.as_bytes(),
            der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3").as_bytes(),
        );
    }

    #[test]
    fn max_csr_body_is_64_kib_matching_marti_sign_client_limit() {
        // 64 KiB — CSRs are typically < 4 KiB. A silent bump to, say, 1 MiB
        // would open a DoS amplification window where an unauthenticated IP
        // could force the server to allocate 1 MiB per request before
        // surfacing the 401 (rate-limit fires before auth, body-read fires
        // after auth, but the `Limited` cap is applied at the hyper layer
        // regardless of success/failure).
        assert_eq!(MAX_CSR_BODY, 65_536);
    }

    // ────────────────────────────────────────────────────────────────────────
    // handle_cacerts — public unauthenticated endpoint that anchors every
    // EST client's trust decision at enrollment time. Happy path must
    // preserve the RFC 7030 §4.1.2 shape exactly.
    // ────────────────────────────────────────────────────────────────────────

    fn test_signer() -> CsrSigner {
        let ca = rustgate_test_utils::certs::TestCa::new("Test CA");
        CsrSigner::from_pem(&ca.cert_pem, &ca.key_pem, "TestOrg").expect("signer")
    }

    async fn collect_body(resp: Response<Full<Bytes>>) -> Bytes {
        http_body_util::BodyExt::collect(resp.into_body())
            .await
            .expect("collect body")
            .to_bytes()
    }

    #[tokio::test]
    async fn handle_cacerts_returns_200_pkcs7_certs_only_with_ca_bag() {
        let signer = test_signer();
        let resp = handle_cacerts(&signer);

        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert_eq!(ct, CT_PKCS7_CERTS_ONLY);

        // Body is base64 of a PKCS#7 SignedData certs-only bag. We don't
        // re-parse the full structure here (cms_bag has its own round-trip
        // coverage) but we pin that the bag decodes cleanly as ASCII base64
        // and is non-empty — a regression that emitted raw DER or an empty
        // body would still pass the status-only assertion but break every
        // RFC 7030 client.
        let body = collect_body(resp).await;
        assert!(!body.is_empty(), "body must be non-empty");
        assert!(
            body.iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'='),
            "body must be base64 (no PEM headers, no whitespace)",
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // handle_csrattrs — minimal RFC 7030 §4.5.2 compliance: 204 No Content
    // with **no** Content-Type header (build_response's `!content_type
    // .is_empty()` guard is the load-bearing branch here).
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn handle_csrattrs_returns_204_with_empty_body_and_no_content_type_header() {
        let resp = handle_csrattrs();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(
            !resp.headers().contains_key(hyper::header::CONTENT_TYPE),
            "RFC 7030 §4.5.2: 204 response must omit Content-Type — build_response's \
             empty-CT guard is what pins this",
        );
        let body = collect_body(resp).await;
        assert!(body.is_empty(), "204 body must be empty");
    }

    // ────────────────────────────────────────────────────────────────────────
    // decode_pkcs10_to_pem — the base64-to-PEM wrapper that feeds CsrSigner.
    // RFC 8951 requires tolerance of CR/LF/tab/space in the input; empty
    // bodies must be rejected up-front so downstream PEM parsing surfaces
    // the root cause rather than a confusing "empty cert" error.
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn decode_pkcs10_to_pem_wraps_clean_base64_in_pem_headers() {
        let b64 = generate_csr_b64("alice");
        let pem = decode_pkcs10_to_pem(b64.as_bytes()).expect("wrap ok");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"));
        assert!(pem.ends_with("\n-----END CERTIFICATE REQUEST-----"));
        assert!(pem.contains(&b64), "body must contain the original base64");
    }

    #[test]
    fn decode_pkcs10_to_pem_rejects_empty_body_with_csr_error() {
        let err = decode_pkcs10_to_pem(b"").expect_err("empty body must error");
        match err {
            EnrollmentError::Csr(msg) => assert!(
                msg.contains("empty"),
                "error message should mention empty body, got {msg:?}",
            ),
            other => panic!("expected EnrollmentError::Csr, got {other:?}"),
        }
    }

    #[test]
    fn decode_pkcs10_to_pem_rejects_whitespace_only_body_as_empty() {
        // After stripping CR/LF/tab/space per RFC 8951, a whitespace-only
        // body is indistinguishable from an actually-empty body — the
        // cleaned string is "" and the empty guard fires.
        let err = decode_pkcs10_to_pem(b" \t\r\n \t").expect_err("whitespace-only must error");
        match err {
            EnrollmentError::Csr(msg) => assert!(msg.contains("empty")),
            other => panic!("expected EnrollmentError::Csr, got {other:?}"),
        }
    }

    #[test]
    fn decode_pkcs10_to_pem_rejects_malformed_base64_with_csr_error() {
        // `!!!` is not a valid base64 alphabet character — the b64::decode
        // validator must surface an error *before* the PEM wrapper runs,
        // so the downstream CsrSigner never sees the garbage.
        let err = decode_pkcs10_to_pem(b"!!!not-base64!!!").expect_err("bad b64 must error");
        match err {
            EnrollmentError::Csr(msg) => assert!(
                msg.contains("invalid base64"),
                "message should mention invalid base64, got {msg:?}",
            ),
            other => panic!("expected EnrollmentError::Csr, got {other:?}"),
        }
    }

    #[test]
    fn decode_pkcs10_to_pem_strips_whitespace_per_rfc_8951() {
        // RFC 8951 requires EST servers to tolerate line-wrapped base64
        // (CR, LF, tab, space). Insert a mix of all four whitespace classes
        // and assert the resulting PEM body carries the un-wrapped base64.
        let b64 = generate_csr_b64("alice");
        let mid = b64.len() / 2;
        let wrapped = format!("{}\r\n \t{}", &b64[..mid], &b64[mid..]);
        let pem = decode_pkcs10_to_pem(wrapped.as_bytes()).expect("wrap ok");
        // Body between PEM headers must be the un-wrapped b64 string,
        // exactly — a regression that failed to strip one of CR/LF/tab/
        // space would leave the character embedded and break the round-
        // trip.
        let inner = pem
            .strip_prefix("-----BEGIN CERTIFICATE REQUEST-----\n")
            .unwrap()
            .strip_suffix("\n-----END CERTIFICATE REQUEST-----")
            .unwrap();
        assert_eq!(inner, b64);
    }

    // ────────────────────────────────────────────────────────────────────────
    // extract_csr_cn — the identity-continuity anchor for re-enrollment.
    // Existing suite covers UTF8String CNs and invalid inputs; these tests
    // additionally pin (a) RFC 8951 whitespace tolerance (same contract as
    // decode_pkcs10_to_pem — both helpers independently strip), and (b) the
    // RDN walk finding a CN at a non-first position in a multi-attribute
    // subject (the `for rdn in &csr.info.subject.0` iteration is otherwise
    // only exercised on the CN-at-first-RDN happy path).
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn extract_csr_cn_tolerates_whitespace_in_body_per_rfc_8951() {
        let b64 = generate_csr_b64("alice");
        let mid = b64.len() / 2;
        let wrapped = format!("{}\r\n \t{}", &b64[..mid], &b64[mid..]);
        let cn = extract_csr_cn(wrapped.as_bytes()).expect("extract ok");
        assert_eq!(cn, Some("alice".to_string()));
    }

    #[test]
    fn extract_csr_cn_finds_cn_in_multi_rdn_subject() {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        // Push non-CN attributes before the CN so the RDN walk has to
        // iterate past them — a regression that stopped after the first
        // RDN would miss the CN and return None, breaking re-enrollment
        // identity continuity for any client whose CSR tooling emits
        // subjects in non-CN-first order.
        dn.push(DnType::OrganizationName, "TestOrg");
        dn.push(DnType::OrganizationalUnitName, "Ops");
        dn.push(DnType::CommonName, "bob");
        params.distinguished_name = dn;

        let csr = params.serialize_request(&key).unwrap();
        let encoded = b64::encode(csr.der());
        let cn = extract_csr_cn(encoded.as_bytes()).unwrap();
        assert_eq!(cn, Some("bob".to_string()));
    }

    // ────────────────────────────────────────────────────────────────────────
    // build_response_with_www_auth — the 401-response builder that every
    // unauthenticated caller hits. RFC 7235 requires a `WWW-Authenticate`
    // header on 401; RFC 7617 scopes the Basic realm. Both are pinned so
    // a future refactor cannot drop the header or re-scope the realm
    // silently (curl / wget / browser clients use the realm to disambiguate
    // between per-service credential stores).
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn build_response_with_www_auth_sets_basic_realm_est_header() {
        let resp = build_response_with_www_auth(
            StatusCode::UNAUTHORIZED,
            "text/plain",
            Bytes::from_static(b"authentication required"),
        );
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let wa = resp
            .headers()
            .get(hyper::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .expect("WWW-Authenticate must be present on 401");
        assert_eq!(wa, "Basic realm=\"est\"");
    }

    #[tokio::test]
    async fn build_response_with_www_auth_preserves_status_content_type_and_body() {
        // Helper is status-agnostic so a future refactor reusing it for
        // 407 (Proxy-Authenticate) or a different error code stays working
        // — pin the full contract, not just the 401 happy path.
        let resp = build_response_with_www_auth(
            StatusCode::FORBIDDEN,
            "text/plain",
            Bytes::from_static(b"denied"),
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain"),
        );
        assert!(
            resp.headers().contains_key(hyper::header::WWW_AUTHENTICATE),
            "WWW-Authenticate is always added, regardless of status",
        );
        let body = collect_body(resp).await;
        assert_eq!(&body[..], b"denied");
    }
}
