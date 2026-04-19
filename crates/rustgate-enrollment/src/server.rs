// Copyright © 2026 Roberto Chiofalo.

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
use rustgate_core::net::configure_tactical_socket;

/// Maximum time for an HTTP connection on the enrollment server.
///
/// Intentionally higher than the workspace default
/// [`rustgate_core::constants::HTTP_CONNECTION_TIMEOUT`] (15s) because enrollment
/// involves CSR signing and PKCS#12 generation which can be slow. Named
/// distinctly from the core constant to avoid shadowing ambiguity.
const ENROLLMENT_HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

use crate::auth::Credentials;
use crate::contacts::ContactsProvider;
use crate::datapackage::DataPackageStore;
use crate::error::EnrollmentError;
use crate::handlers::util::build_response;
use crate::handlers::{api, packages, revoke, sign};
use crate::ratelimit::RateLimiter;
use crate::revocation::RevocationStore;
use crate::signing::CsrSigner;

/// Default maximum CSR signing requests per IP per minute.
pub const DEFAULT_SIGN_RATE_LIMIT: usize = 10;

/// Default rate limit window for CSR signing.
pub const DEFAULT_SIGN_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Callback fired when a CSR signing request is rejected by the
/// per-IP rate limiter. Wired by the server binary to a Prometheus
/// counter; left unset in tests and embedders that do not need it.
pub type RateLimitCallback = Arc<dyn Fn() + Send + Sync>;

/// HTTPS enrollment server for client certificate provisioning.
pub struct EnrollmentServer {
    signer: Arc<CsrSigner>,
    credentials: Arc<Credentials>,
    contacts_provider: Option<ContactsProvider>,
    packages: Option<Arc<DataPackageStore>>,
    revocation: Option<Arc<RevocationStore>>,
    sign_limiter: Arc<RateLimiter>,
    on_rate_limit: Option<RateLimitCallback>,
    /// Whether EST (RFC 7030) endpoints are enabled at runtime.
    #[cfg(feature = "est")]
    est_enabled: bool,
}

impl std::fmt::Debug for EnrollmentServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentServer")
            .field("signer", &self.signer)
            .field("credentials", &self.credentials)
            .field("contacts_provider", &self.contacts_provider.is_some())
            .field("packages", &self.packages.is_some())
            .field("revocation", &self.revocation.is_some())
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
            revocation: None,
            sign_limiter: Arc::new(RateLimiter::new(
                DEFAULT_SIGN_RATE_LIMIT,
                DEFAULT_SIGN_RATE_WINDOW,
            )),
            on_rate_limit: None,
            #[cfg(feature = "est")]
            est_enabled: false,
        }
    }

    /// Override the per-IP CSR signing rate limit.
    ///
    /// `max_requests` is the maximum number of CSR signing requests permitted
    /// from any single IP within `window`. Wired from the
    /// `--enrollment-rate-limit` CLI flag in the server binary.
    pub fn with_rate_limit(mut self, max_requests: usize, window: Duration) -> Self {
        self.sign_limiter = Arc::new(RateLimiter::new(max_requests, window));
        self
    }

    /// Register a callback fired whenever a CSR signing request is
    /// rejected for exceeding the per-IP rate limit. Used by the server
    /// binary to increment a Prometheus counter.
    pub fn with_rate_limit_callback(mut self, cb: RateLimitCallback) -> Self {
        self.on_rate_limit = Some(cb);
        self
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

    /// Enable certificate revocation and CRL generation.
    pub fn with_revocation(mut self, store: RevocationStore) -> Self {
        self.revocation = Some(Arc::new(store));
        self
    }

    /// Enable EST (RFC 7030) enrollment endpoints.
    ///
    /// When enabled, the server responds to `/.well-known/est/` paths
    /// for CA certificate distribution and CSR-based enrollment.
    #[cfg(feature = "est")]
    pub fn with_est(mut self) -> Self {
        self.est_enabled = true;
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

            // Shared TCP tactical-socket tuning — keepalive kills dead
            // NAT middleboxes so they do not hold slots in the connection
            // semaphore, and `TCP_NODELAY` avoids the 40 ms Nagle+DELACK
            // penalty on small enrollment request/response exchanges.
            configure_tactical_socket(&stream);

            let permit = match Arc::clone(&conn_limit).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    let masked_peer = rustgate_core::masking::mask_ip(&peer.to_string());
                    tracing::warn!(
                        peer = %masked_peer,
                        "enrollment connection rejected: limit reached"
                    );
                    rustgate_core::audit::connection_rejected(
                        peer,
                        "enrollment connection limit reached",
                    );
                    drop(stream);
                    continue;
                }
            };

            let acceptor = acceptor.clone();
            let signer = Arc::clone(&self.signer);
            let credentials = Arc::clone(&self.credentials);
            let contacts = self.contacts_provider.clone();
            let packages = self.packages.clone();
            let revocation = self.revocation.clone();
            let sign_limiter = Arc::clone(&self.sign_limiter);
            let on_rate_limit = self.on_rate_limit.clone();
            #[cfg(feature = "est")]
            let est_enabled = self.est_enabled;

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
                    let revocation = revocation.clone();
                    let sign_limiter = Arc::clone(&sign_limiter);
                    let on_rate_limit = on_rate_limit.clone();
                    async move {
                        handle_request(
                            req,
                            peer,
                            &signer,
                            &credentials,
                            contacts.as_ref(),
                            packages.as_deref(),
                            revocation.as_deref(),
                            &sign_limiter,
                            on_rate_limit.as_ref(),
                            #[cfg(feature = "est")]
                            est_enabled,
                        )
                        .await
                    }
                });

                let conn = http1::Builder::new().serve_connection(io, service);
                if let Err(e) = tokio::time::timeout(ENROLLMENT_HTTP_CONNECTION_TIMEOUT, conn).await
                {
                    tracing::debug!(peer = %peer, error = %e, "HTTP connection timed out");
                }
            }));
        }
    }
}

/// Route an incoming HTTP request to the appropriate handler.
#[allow(clippy::too_many_arguments)]
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    signer: &CsrSigner,
    credentials: &Credentials,
    contacts: Option<&ContactsProvider>,
    packages: Option<&DataPackageStore>,
    revocation: Option<&RevocationStore>,
    sign_limiter: &RateLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
    #[cfg(feature = "est")] est_enabled: bool,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // EST endpoints (RFC 7030) — route /.well-known/est/ paths when enabled.
    // Checked before borrowing path so we can move `req` into the handler.
    #[cfg(feature = "est")]
    if est_enabled && req.uri().path().starts_with("/.well-known/est/") {
        let path = req.uri().path().to_owned();
        return Ok(route_est(
            req,
            peer,
            signer,
            credentials,
            sign_limiter,
            on_rate_limit,
            &path,
        )
        .await);
    }

    let path = req.uri().path();
    let method = req.method();

    let response = match (method, path) {
        (&Method::GET, "/Marti/api/tls/config") => sign::handle_tls_config(signer),

        (&Method::POST, "/Marti/api/tls/signClient") => {
            sign::handle_sign_client_v1(req, peer, signer, credentials, sign_limiter, on_rate_limit)
                .await
        }

        (&Method::POST, "/Marti/api/tls/signClient/v2") => {
            sign::handle_sign_client_v2(req, peer, signer, credentials, sign_limiter, on_rate_limit)
                .await
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

        (&Method::POST, "/api/revoke") => match revocation {
            Some(store) => revoke::handle_revoke(req, peer, credentials, store).await,
            None => build_response(
                StatusCode::NOT_FOUND,
                "text/plain",
                Bytes::from("revocation not enabled"),
            ),
        },

        (&Method::GET, "/api/crl") => match revocation {
            Some(store) => revoke::handle_crl(store).await,
            None => build_response(
                StatusCode::NOT_FOUND,
                "text/plain",
                Bytes::from("revocation not enabled"),
            ),
        },

        (&Method::GET, "/api/revoked") => match revocation {
            Some(store) => revoke::handle_list_revoked(store).await,
            None => build_response(
                StatusCode::NOT_FOUND,
                "text/plain",
                Bytes::from("revocation not enabled"),
            ),
        },

        _ => build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("not found"),
        ),
    };

    Ok(response)
}

/// Route EST (RFC 7030) requests to the appropriate handler.
///
/// Called only when `est_enabled` is true and the path starts with
/// `/.well-known/est/`. Handles both unlabeled and labeled paths.
#[cfg(feature = "est")]
async fn route_est(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    signer: &CsrSigner,
    credentials: &Credentials,
    sign_limiter: &RateLimiter,
    on_rate_limit: Option<&RateLimitCallback>,
    path: &str,
) -> Response<Full<Bytes>> {
    use crate::est;

    // Strip the EST prefix, supporting optional labels:
    //   /.well-known/est/cacerts          → operation = "cacerts"
    //   /.well-known/est/my-ca/cacerts    → operation = "cacerts" (label = "my-ca")
    let suffix = path.strip_prefix("/.well-known/est/").unwrap_or("");

    // The operation is the last path segment.
    let operation = suffix.rsplit('/').next().unwrap_or(suffix);
    let method = req.method().clone();

    match (method.as_ref(), operation) {
        ("GET", "cacerts") => est::handle_cacerts(signer),
        ("POST", "simpleenroll") => {
            est::handle_simpleenroll(req, peer, signer, credentials, sign_limiter, on_rate_limit)
                .await
        }
        ("POST", "simplereenroll") => {
            est::handle_simplereenroll(req, peer, signer, credentials, sign_limiter, on_rate_limit)
                .await
        }
        ("GET", "csrattrs") => est::handle_csrattrs(),
        _ => build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("unknown EST operation"),
        ),
    }
}

/// Build a server-only TLS configuration for the enrollment HTTPS endpoint.
fn build_server_tls_config(
    cert_pem: &str,
    key_pem: &str,
) -> Result<rustls::ServerConfig, EnrollmentError> {
    // Shared PEM helpers from `rustgate_core::pem` — `parse_certs`
    // rejects empty inputs for us, so we skip the extra is_empty check.
    let certs = rustgate_core::pem::parse_certs(cert_pem.as_bytes())
        .map_err(|e| EnrollmentError::Tls(format!("failed to parse server certs: {e}")))?;
    let key = rustgate_core::pem::parse_key(key_pem.as_bytes())
        .map_err(|e| EnrollmentError::Tls(format!("failed to parse server key: {e}")))?;

    // Server-only TLS (no client cert requirement)
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.clone_key())
        .map_err(|e| EnrollmentError::Tls(format!("invalid server certificate: {e}")))?;

    Ok(config)
}
