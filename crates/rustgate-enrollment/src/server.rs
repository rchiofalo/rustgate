//! HTTPS enrollment server.
//!
//! Runs a hyper HTTP/1.1 server over tokio-rustls (server-only TLS, no client
//! cert requirement). Routes the Marti-compatible enrollment endpoints.

use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Maximum time for TLS handshake before the connection is dropped.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time for an HTTP connection (from handshake complete to response sent).
const HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

use crate::auth::Credentials;
use crate::error::EnrollmentError;
use crate::response;
use crate::signing::CsrSigner;

/// HTTPS enrollment server for TAK client certificate provisioning.
#[derive(Debug)]
pub struct EnrollmentServer {
    signer: Arc<CsrSigner>,
    credentials: Arc<Credentials>,
}

impl EnrollmentServer {
    pub fn new(signer: CsrSigner, credentials: Credentials) -> Self {
        Self {
            signer: Arc::new(signer),
            credentials: Arc::new(credentials),
        }
    }

    /// Run the enrollment HTTPS server.
    ///
    /// Binds to `bind_addr` with server-only TLS (no client cert verification).
    /// This is a long-running future that processes requests until dropped.
    pub async fn run(
        self,
        bind_addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), EnrollmentError> {
        let tls_config = build_server_tls_config(cert_pem, key_pem)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(EnrollmentError::Io)?;

        tracing::info!(addr = %bind_addr, "enrollment server listening");

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::debug!(error = %e, "TCP accept error");
                    continue;
                }
            };

            let acceptor = acceptor.clone();
            let signer = Arc::clone(&self.signer);
            let credentials = Arc::clone(&self.credentials);

            drop(tokio::spawn(async move {
                let tls_stream = match tokio::time::timeout(
                    TLS_HANDSHAKE_TIMEOUT,
                    acceptor.accept(stream),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        tracing::debug!(peer = %peer, error = %e, "TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(peer = %peer, "TLS handshake timed out");
                        return;
                    }
                };

                let io = TokioIo::new(tls_stream);

                let service = service_fn(move |req| {
                    let signer = Arc::clone(&signer);
                    let credentials = Arc::clone(&credentials);
                    async move { handle_request(req, &signer, &credentials).await }
                });

                let conn = http1::Builder::new().serve_connection(io, service);
                if let Err(e) = tokio::time::timeout(HTTP_CONNECTION_TIMEOUT, conn).await {
                    tracing::debug!(peer = %peer, error = %e, "HTTP connection timed out");
                }
            }));
        }
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    signer: &CsrSigner,
    credentials: &Credentials,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    let method = req.method();

    let response = match (method, path) {
        (&Method::GET, "/Marti/api/tls/config") => handle_tls_config(signer),

        (&Method::POST, "/Marti/api/tls/signClient/v2") => {
            handle_sign_client_v2(req, signer, credentials).await
        }

        (&Method::GET, "/Marti/api/tls/profile/enrollment") => {
            build_response(StatusCode::NO_CONTENT, "", Bytes::new())
        }

        _ => build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("not found"),
        ),
    };

    Ok(response)
}

fn handle_tls_config(signer: &CsrSigner) -> Response<Full<Bytes>> {
    let xml = response::tls_config_xml(signer.organization());
    build_response(StatusCode::OK, "application/xml", Bytes::from(xml))
}

async fn handle_sign_client_v2(
    req: Request<hyper::body::Incoming>,
    signer: &CsrSigner,
    credentials: &Credentials,
) -> Response<Full<Bytes>> {
    // Validate Basic Auth
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(username) = credentials.validate(auth_header) else {
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

    tracing::info!(
        username = %username,
        client_uid = %client_uid,
        format = %content_type,
        "signed client certificate"
    );

    build_response(StatusCode::OK, content_type, Bytes::from(body))
}

fn build_response(status: StatusCode, content_type: &str, body: Bytes) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(status);
    if !content_type.is_empty() {
        builder = builder.header("Content-Type", content_type);
    }
    builder
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("internal error"))))
}

fn extract_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key { Some(v.to_string()) } else { None }
    })
}

fn build_server_tls_config(
    cert_pem: &str,
    key_pem: &str,
) -> Result<rustls::ServerConfig, EnrollmentError> {
    // Parse server certs
    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| EnrollmentError::Tls(format!("failed to parse server certs: {e}")))?;

    if certs.is_empty() {
        return Err(EnrollmentError::Tls(
            "no certificates found in server PEM".to_string(),
        ));
    }

    // Parse server key
    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| EnrollmentError::Tls(format!("failed to parse server key: {e}")))?
        .ok_or_else(|| EnrollmentError::Tls("no private key found in server PEM".to_string()))?;

    // Server-only TLS (no client cert requirement)
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.clone_key())
        .map_err(|e| EnrollmentError::Tls(format!("invalid server certificate: {e}")))?;

    Ok(config)
}
