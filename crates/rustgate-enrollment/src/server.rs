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

/// Maximum concurrent connections to the enrollment server.
/// Bounds resource usage from connection floods against the
/// unauthenticated TLS endpoint.
const MAX_ENROLLMENT_CONNECTIONS: usize = 64;

/// Maximum time for TLS handshake before the connection is dropped.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time for an HTTP connection (from handshake complete to response sent).
const HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

use crate::auth::Credentials;
use crate::contacts::ContactsProvider;
use crate::datapackage::DataPackageStore;
use crate::error::EnrollmentError;
use crate::ratelimit::RateLimiter;
use crate::response;
use crate::signing::CsrSigner;

/// Maximum CSR signing requests per IP per minute.
const SIGN_RATE_LIMIT: usize = 10;

/// Rate limit window for CSR signing.
const SIGN_RATE_WINDOW: Duration = Duration::from_secs(60);

/// HTTPS enrollment server for TAK client certificate provisioning.
pub struct EnrollmentServer {
    signer: Arc<CsrSigner>,
    credentials: Arc<Credentials>,
    contacts_provider: Option<ContactsProvider>,
    packages: Option<Arc<DataPackageStore>>,
    sign_limiter: Arc<RateLimiter>,
}

impl std::fmt::Debug for EnrollmentServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentServer")
            .field("signer", &self.signer)
            .field("credentials", &self.credentials)
            .field("contacts_provider", &self.contacts_provider.is_some())
            .field("packages", &self.packages.is_some())
            .finish()
    }
}

impl EnrollmentServer {
    pub fn new(signer: CsrSigner, credentials: Credentials) -> Self {
        Self {
            signer: Arc::new(signer),
            credentials: Arc::new(credentials),
            contacts_provider: None,
            packages: None,
            sign_limiter: Arc::new(RateLimiter::new(SIGN_RATE_LIMIT, SIGN_RATE_WINDOW)),
        }
    }

    /// Set the contacts provider for Marti API compatibility endpoints.
    pub fn with_contacts_provider(mut self, provider: ContactsProvider) -> Self {
        self.contacts_provider = Some(provider);
        self
    }

    /// Enable data package storage at the given store.
    pub fn with_packages(mut self, store: DataPackageStore) -> Self {
        self.packages = Some(Arc::new(store));
        self
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

        let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_ENROLLMENT_CONNECTIONS));
        tracing::info!(addr = %bind_addr, "enrollment server listening");

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::debug!(error = %e, "TCP accept error");
                    continue;
                }
            };

            let permit = match Arc::clone(&conn_limit).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(peer = %peer, "enrollment connection rejected: limit reached");
                    drop(stream);
                    continue;
                }
            };

            let acceptor = acceptor.clone();
            let signer = Arc::clone(&self.signer);
            let credentials = Arc::clone(&self.credentials);
            let contacts = self.contacts_provider.clone();
            let packages = self.packages.clone();
            let sign_limiter = Arc::clone(&self.sign_limiter);

            drop(tokio::spawn(async move {
                let _permit = permit;
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
                    let contacts = contacts.clone();
                    let packages = packages.clone();
                    let sign_limiter = Arc::clone(&sign_limiter);
                    async move {
                        handle_request(
                            req,
                            peer,
                            &signer,
                            &credentials,
                            contacts.as_ref(),
                            packages.as_deref(),
                            &sign_limiter,
                        )
                        .await
                    }
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
    peer: SocketAddr,
    signer: &CsrSigner,
    credentials: &Credentials,
    contacts: Option<&ContactsProvider>,
    packages: Option<&DataPackageStore>,
    sign_limiter: &RateLimiter,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    let method = req.method();

    let response = match (method, path) {
        (&Method::GET, "/Marti/api/tls/config") => handle_tls_config(signer),

        (&Method::POST, "/Marti/api/tls/signClient") => {
            handle_sign_client_v1(req, peer, signer, credentials, sign_limiter).await
        }

        (&Method::POST, "/Marti/api/tls/signClient/v2") => {
            handle_sign_client_v2(req, peer, signer, credentials, sign_limiter).await
        }

        (&Method::GET, "/Marti/api/tls/profile/enrollment") => {
            build_response(StatusCode::NO_CONTENT, "", Bytes::new())
        }

        (&Method::GET, "/Marti/api/version/config") => handle_version_config(),

        (&Method::GET, "/Marti/api/contacts/all") => handle_contacts_all(contacts).await,

        (&Method::GET, "/Marti/api/clientEndPoints") => handle_client_endpoints(contacts).await,

        (&Method::POST, "/Marti/sync/upload") => {
            handle_package_upload(req, credentials, packages).await
        }

        (&Method::GET, "/Marti/sync/content") => handle_package_download(req, packages).await,

        (&Method::GET, "/Marti/sync/search") => handle_package_search(req, packages).await,

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

/// signClient v1 — returns a PKCS#12 (.p12) bundle for legacy TAK clients.
///
/// Same auth and CSR flow as v2, but the response is a binary PKCS#12
/// bundle containing the signed client cert and CA cert, encrypted with
/// the standard TAK password ("atakatak").
async fn handle_sign_client_v1(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    signer: &CsrSigner,
    credentials: &Credentials,
    sign_limiter: &RateLimiter,
) -> Response<Full<Bytes>> {
    // Rate limit before doing any work
    if !sign_limiter.check(peer.ip()) {
        tracing::warn!(peer = %peer, "CSR signing rate limited");
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
        rustgate_core::audit::enrollment_auth_failed(&peer.to_string());
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
    tracing::info!(
        username = %username,
        client_uid = %client_uid,
        format = "pkcs12",
        "signed client certificate (v1)"
    );

    build_response(StatusCode::OK, "application/x-pkcs12", Bytes::from(p12))
}

async fn handle_sign_client_v2(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    signer: &CsrSigner,
    credentials: &Credentials,
    sign_limiter: &RateLimiter,
) -> Response<Full<Bytes>> {
    // Rate limit before doing any work
    if !sign_limiter.check(peer.ip()) {
        tracing::warn!(peer = %peer, "CSR signing rate limited");
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
        rustgate_core::audit::enrollment_auth_failed(&peer.to_string());
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
    tracing::info!(
        username = %username,
        client_uid = %client_uid,
        format = %content_type,
        "signed client certificate"
    );

    build_response(StatusCode::OK, content_type, Bytes::from(body))
}

fn handle_version_config() -> Response<Full<Bytes>> {
    let version = env!("CARGO_PKG_VERSION");
    let body = serde_json::json!({
        "version": "3",
        "type": "ServerConfig",
        "data": {
            "version": version,
            "api": "3",
            "hostname": "rustgate",
        },
        "nodeId": "rustgate"
    });
    build_response(
        StatusCode::OK,
        "application/json",
        Bytes::from(body.to_string()),
    )
}

async fn handle_contacts_all(contacts: Option<&ContactsProvider>) -> Response<Full<Bytes>> {
    let contacts = match contacts {
        Some(provider) => provider().await,
        None => Vec::new(),
    };
    let body = serde_json::to_string(&contacts).unwrap_or_else(|_| "[]".to_string());
    build_response(StatusCode::OK, "application/json", Bytes::from(body))
}

async fn handle_client_endpoints(contacts: Option<&ContactsProvider>) -> Response<Full<Bytes>> {
    let contacts = match contacts {
        Some(provider) => provider().await,
        None => Vec::new(),
    };

    // clientEndPoints wraps the contact list in a Marti-compatible envelope
    let endpoints: Vec<serde_json::Value> = contacts
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "uid": c.uid,
                "callsign": c.callsign,
                "lastStatus": c.last_status,
            })
        })
        .collect();

    let body = serde_json::json!({
        "version": "3",
        "type": "com.bbn.marti.remote.ClientEndpoint",
        "data": endpoints,
        "nodeId": "rustgate"
    });
    build_response(
        StatusCode::OK,
        "application/json",
        Bytes::from(body.to_string()),
    )
}

async fn handle_package_upload(
    req: Request<hyper::body::Incoming>,
    credentials: &Credentials,
    packages: Option<&DataPackageStore>,
) -> Response<Full<Bytes>> {
    let Some(store) = packages else {
        return build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("data package storage not configured"),
        );
    };

    // Require Basic Auth for uploads
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

    let content_type_hdr = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Read body (limit to 50 MiB + overhead for multipart headers)
    let limited = Limited::new(req.into_body(), 52_428_800);
    let body = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("upload too large"),
            );
        }
    };

    // Extract file data from multipart body or use raw body
    let (file_data, filename) =
        if let Some(boundary) = crate::datapackage::extract_boundary(&content_type_hdr) {
            let name = crate::datapackage::extract_multipart_filename(&body, boundary)
                .unwrap_or_else(|| "upload.zip".to_string());
            let data = crate::datapackage::extract_multipart_field(&body, boundary, "assetfile")
                .unwrap_or(&body);
            (data.to_vec(), name)
        } else {
            (body.to_vec(), "upload.zip".to_string())
        };

    match store.upload(&file_data, &filename, username).await {
        Ok(meta) => {
            let json = serde_json::json!({
                "Hash": meta.hash,
                "Name": meta.name,
                "Size": meta.size,
            });
            build_response(
                StatusCode::OK,
                "application/json",
                Bytes::from(json.to_string()),
            )
        }
        Err(e) => {
            tracing::warn!(error = %e, "data package upload failed");
            build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("upload failed"),
            )
        }
    }
}

async fn handle_package_download(
    req: Request<hyper::body::Incoming>,
    packages: Option<&DataPackageStore>,
) -> Response<Full<Bytes>> {
    let Some(store) = packages else {
        return build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("data package storage not configured"),
        );
    };

    let hash = req
        .uri()
        .query()
        .and_then(|q| extract_param(q, "hash"))
        .unwrap_or_default();

    if hash.is_empty() {
        return build_response(
            StatusCode::BAD_REQUEST,
            "text/plain",
            Bytes::from("missing hash parameter"),
        );
    }

    match store.download(&hash).await {
        Ok((_meta, data)) => build_response(
            StatusCode::OK,
            "application/x-zip-compressed",
            Bytes::from(data),
        ),
        Err(_) => build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("package not found"),
        ),
    }
}

async fn handle_package_search(
    req: Request<hyper::body::Incoming>,
    packages: Option<&DataPackageStore>,
) -> Response<Full<Bytes>> {
    let Some(store) = packages else {
        return build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("data package storage not configured"),
        );
    };

    let keyword = req
        .uri()
        .query()
        .and_then(|q| extract_param(q, "keyword"))
        .unwrap_or_default();

    match store.search(&keyword).await {
        Ok(results) => {
            let json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string());
            build_response(StatusCode::OK, "application/json", Bytes::from(json))
        }
        Err(e) => {
            tracing::warn!(error = %e, "data package search failed");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                Bytes::from("search failed"),
            )
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::ContactInfo;

    fn mock_contacts_provider(contacts: Vec<ContactInfo>) -> ContactsProvider {
        Arc::new(move || {
            let contacts = contacts.clone();
            Box::pin(async move { contacts })
        })
    }

    async fn collect_body(resp: Response<Full<Bytes>>) -> Bytes {
        http_body_util::BodyExt::collect(resp.into_body())
            .await
            .expect("collect body")
            .to_bytes()
    }

    #[tokio::test]
    async fn version_config_returns_json() {
        let resp = handle_version_config();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");

        assert_eq!(parsed["version"], "3");
        assert_eq!(parsed["type"], "ServerConfig");
        assert_eq!(parsed["nodeId"], "rustgate");
        assert!(parsed["data"]["version"].as_str().is_some());
        assert_eq!(parsed["data"]["api"], "3");
    }

    #[tokio::test]
    async fn contacts_all_empty_without_provider() {
        let resp = handle_contacts_all(None).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&bytes).expect("valid JSON");
        assert!(parsed.is_empty());
    }

    #[tokio::test]
    async fn contacts_all_returns_connected_clients() {
        let provider = mock_contacts_provider(vec![
            ContactInfo {
                uid: "alpha-1".into(),
                callsign: "Alpha One".into(),
                groups: vec!["Team-A".into()],
                last_status: "Connected".into(),
            },
            ContactInfo {
                uid: "bravo-2".into(),
                callsign: "Bravo Two".into(),
                groups: vec!["Team-B".into()],
                last_status: "Connected".into(),
            },
        ]);

        let resp = handle_contacts_all(Some(&provider)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["uid"], "alpha-1");
        assert_eq!(parsed[0]["callsign"], "Alpha One");
        assert_eq!(parsed[0]["lastStatus"], "Connected");
        assert_eq!(parsed[1]["uid"], "bravo-2");
    }

    #[tokio::test]
    async fn client_endpoints_empty_without_provider() {
        let resp = handle_client_endpoints(None).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(parsed["version"], "3");
        assert_eq!(parsed["type"], "com.bbn.marti.remote.ClientEndpoint");
        assert!(parsed["data"].as_array().expect("data array").is_empty());
    }

    #[tokio::test]
    async fn client_endpoints_returns_envelope() {
        let provider = mock_contacts_provider(vec![ContactInfo {
            uid: "test-uid".into(),
            callsign: "TestCall".into(),
            groups: vec!["Alpha".into()],
            last_status: "Connected".into(),
        }]);

        let resp = handle_client_endpoints(Some(&provider)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = collect_body(resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(parsed["version"], "3");
        assert_eq!(parsed["nodeId"], "rustgate");

        let data = parsed["data"].as_array().expect("data array");
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["uid"], "test-uid");
        assert_eq!(data[0]["callsign"], "TestCall");
    }
}
