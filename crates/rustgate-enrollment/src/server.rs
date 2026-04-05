//! HTTPS enrollment server.
//!
//! Runs a hyper HTTP/1.1 server over tokio-rustls (server-only TLS, no client
//! cert requirement). Routes the Marti-compatible enrollment endpoints.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
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

use rustgate_core::constants::HANDSHAKE_TIMEOUT;

/// Maximum time for an HTTP connection (from handshake complete to response sent).
/// Higher than the default `HTTP_CONNECTION_TIMEOUT` (15s) because enrollment
/// involves CSR signing and PKCS#12 generation which can be slow.
const HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

use crate::auth::Credentials;
use crate::contacts::ContactsProvider;
use crate::datapackage::DataPackageStore;
use crate::error::EnrollmentError;
use crate::handlers::util::build_response;
use crate::handlers::{api, packages, sign};
use crate::ratelimit::RateLimiter;
use crate::signing::CsrSigner;

/// Maximum CSR signing requests per IP per minute.
const SIGN_RATE_LIMIT: usize = 10;

/// Rate limit window for CSR signing.
const SIGN_RATE_WINDOW: Duration = Duration::from_secs(60);

/// HTTPS enrollment server for client certificate provisioning.
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

        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            EnrollmentError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to bind enrollment server to {bind_addr}: {e}"),
            ))
        })?;

        let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_ENROLLMENT_CONNECTIONS));
        tracing::info!(addr = %bind_addr, "enrollment server listening");

        // No separate prune task needed — the sliding-window rate limiter
        // lazily cleans stale entries on each check() call.

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
                    HANDSHAKE_TIMEOUT,
                    acceptor.accept(stream),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        let masked_peer = rustgate_core::masking::mask_ip(&peer.to_string());
                        tracing::debug!(peer = %masked_peer, error = %e, "TLS handshake failed");
                        rustgate_core::audit::tls_handshake_failed(
                            &masked_peer,
                            &e.to_string(),
                            "enrollment_accept",
                        );
                        return;
                    }
                    Err(_) => {
                        let masked_peer = rustgate_core::masking::mask_ip(&peer.to_string());
                        tracing::debug!(peer = %masked_peer, "TLS handshake timed out");
                        rustgate_core::audit::tls_handshake_failed(
                            &masked_peer,
                            "timeout",
                            "enrollment_accept",
                        );
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

/// Route an incoming HTTP request to the appropriate handler.
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
        (&Method::GET, "/Marti/api/tls/config") => sign::handle_tls_config(signer),

        (&Method::POST, "/Marti/api/tls/signClient") => {
            sign::handle_sign_client_v1(req, peer, signer, credentials, sign_limiter).await
        }

        (&Method::POST, "/Marti/api/tls/signClient/v2") => {
            sign::handle_sign_client_v2(req, peer, signer, credentials, sign_limiter).await
        }

        (&Method::GET, "/Marti/api/tls/profile/enrollment") => {
            build_response(StatusCode::NO_CONTENT, "", Bytes::new())
        }

        (&Method::GET, "/Marti/api/version/config") => api::handle_version_config(),

        (&Method::GET, "/Marti/api/contacts/all") => api::handle_contacts_all(contacts).await,

        (&Method::GET, "/Marti/api/clientEndPoints") => {
            api::handle_client_endpoints(contacts).await
        }

        (&Method::GET, "/Marti/api/device/profile/connection") => {
            api::handle_device_profile(req, packages).await
        }

        (&Method::GET, "/Marti/api/groups/all") => api::handle_groups_all(),

        (&Method::GET, "/Marti/api/missions") => api::handle_missions(),

        (&Method::POST, "/Marti/sync/upload") => {
            packages::handle_package_upload(req, credentials, packages).await
        }

        (&Method::GET, "/Marti/sync/content") => {
            packages::handle_package_download(req, packages).await
        }

        (&Method::GET, "/Marti/sync/search") => {
            packages::handle_package_search(req, packages).await
        }

        _ => build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("not found"),
        ),
    };

    Ok(response)
}

/// Build a server-only TLS configuration for the enrollment HTTPS endpoint.
fn build_server_tls_config(
    cert_pem: &str,
    key_pem: &str,
) -> Result<rustls::ServerConfig, EnrollmentError> {
    use rustls_pki_types::pem::PemObject;

    // Parse server certs
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| EnrollmentError::Tls(format!("failed to parse server certs: {e}")))?;

    if certs.is_empty() {
        return Err(EnrollmentError::Tls(
            "no certificates found in server PEM".to_string(),
        ));
    }

    // Parse server key
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| EnrollmentError::Tls(format!("failed to parse server key: {e}")))?;

    // Server-only TLS (no client cert requirement)
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.clone_key())
        .map_err(|e| EnrollmentError::Tls(format!("invalid server certificate: {e}")))?;

    Ok(config)
}
