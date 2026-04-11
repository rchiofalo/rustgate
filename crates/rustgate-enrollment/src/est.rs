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

use crate::auth::Credentials;
use crate::cms_bag;
use crate::error::EnrollmentError;
use crate::handlers::util::build_response;
use crate::ratelimit::RateLimiter;
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
    sign_limiter: &RateLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
) -> Response<Full<Bytes>> {
    // Rate limit check (before auth to prevent work amplification).
    if !sign_limiter.check(peer.ip()) {
        if let Some(cb) = on_rate_limit {
            cb();
        }
        return build_response(
            StatusCode::TOO_MANY_REQUESTS,
            "text/plain",
            Bytes::from("rate limit exceeded"),
        );
    }

    // Authentication.
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let username = match credentials.validate(auth_header) {
        Some(u) => u,
        None => {
            return build_response_with_www_auth(
                StatusCode::UNAUTHORIZED,
                "text/plain",
                Bytes::from("authentication required"),
            );
        }
    };

    // Read and validate Content-Type.
    let content_type = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with(CT_PKCS10) {
        return build_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "text/plain",
            Bytes::from(format!(
                "expected Content-Type: {CT_PKCS10}, got: {content_type}"
            )),
        );
    }

    // Read request body (base64-encoded DER CSR).
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "EST /simpleenroll: failed to read body");
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("failed to read request body"),
            );
        }
    };

    // Decode base64 → DER, then wrap in PEM for CsrSigner.
    let csr_pem = match decode_pkcs10_to_pem(&body) {
        Ok(pem) => pem,
        Err(e) => {
            tracing::debug!(error = %e, "EST /simpleenroll: invalid CSR encoding");
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
            tracing::warn!(error = %e, "EST /simpleenroll: CSR signing failed");
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
        "EST certificate issued via /simpleenroll"
    );

    // Build PKCS#7 certs-only bag with [client cert, CA cert].
    match cms_bag::build_certs_only_base64(&[&signed_der, signer.ca_cert_der()]) {
        Ok(body) => build_response(StatusCode::OK, CT_PKCS7_CERTS_ONLY, Bytes::from(body)),
        Err(e) => {
            tracing::error!(error = %e, "EST /simpleenroll: failed to build response");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                Bytes::from("internal error building enrollment response"),
            )
        }
    }
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
    sign_limiter: &RateLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
) -> Response<Full<Bytes>> {
    // Rate limit check (before auth to prevent work amplification).
    if !sign_limiter.check(peer.ip()) {
        if let Some(cb) = on_rate_limit {
            cb();
        }
        return build_response(
            StatusCode::TOO_MANY_REQUESTS,
            "text/plain",
            Bytes::from("rate limit exceeded"),
        );
    }

    // Authentication.
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let username = match credentials.validate(auth_header) {
        Some(u) => u,
        None => {
            return build_response_with_www_auth(
                StatusCode::UNAUTHORIZED,
                "text/plain",
                Bytes::from("authentication required"),
            );
        }
    };

    // Read and validate Content-Type.
    let content_type = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with(CT_PKCS10) {
        return build_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "text/plain",
            Bytes::from(format!(
                "expected Content-Type: {CT_PKCS10}, got: {content_type}"
            )),
        );
    }

    // Read request body (base64-encoded DER CSR).
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "EST /simplereenroll: failed to read body");
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("failed to read request body"),
            );
        }
    };

    // Decode base64 → DER, then wrap in PEM for CsrSigner.
    let csr_pem = match decode_pkcs10_to_pem(&body) {
        Ok(pem) => pem,
        Err(e) => {
            tracing::debug!(error = %e, "EST /simplereenroll: invalid CSR encoding");
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("invalid CSR format"),
            );
        }
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

    // Sign the CSR.
    let signed_der = match signer.sign_csr(&csr_pem, username) {
        Ok(der) => der,
        Err(e) => {
            tracing::warn!(error = %e, "EST /simplereenroll: CSR signing failed");
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
        "EST certificate issued via /simplereenroll"
    );

    // Build PKCS#7 certs-only bag with [client cert, CA cert].
    match cms_bag::build_certs_only_base64(&[&signed_der, signer.ca_cert_der()]) {
        Ok(body) => build_response(StatusCode::OK, CT_PKCS7_CERTS_ONLY, Bytes::from(body)),
        Err(e) => {
            tracing::error!(error = %e, "EST /simplereenroll: failed to build response");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                Bytes::from("internal error building enrollment response"),
            )
        }
    }
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

    let der_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cleaned)
        .map_err(|e| EnrollmentError::Csr(format!("invalid base64: {e}")))?;

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
    use base64::Engine as _;
    let _ = base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| EnrollmentError::Csr(format!("invalid base64: {e}")))?;

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
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, csr.der())
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
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, csr.der());
        let cn = extract_csr_cn(b64.as_bytes()).unwrap();
        assert_eq!(cn, None);
    }

    #[test]
    fn extract_cn_rejects_invalid_base64() {
        let result = extract_csr_cn(b"!!!not-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn extract_cn_rejects_invalid_der() {
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"not a valid CSR",
        );
        let result = extract_csr_cn(b64.as_bytes());
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
}
