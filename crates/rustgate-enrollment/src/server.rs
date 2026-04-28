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
use rustgate_core::tasks::spawn_background;

/// Maximum time for an HTTP connection on the enrollment server.
///
/// Intentionally higher than the workspace default
/// [`rustgate_core::constants::HTTP_CONNECTION_TIMEOUT`] (15s) because enrollment
/// involves CSR signing and PKCS#12 generation which can be slow. Named
/// distinctly from the core constant to avoid shadowing ambiguity.
const ENROLLMENT_HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

use rustgate_resilience::SlidingWindowLimiter;

use crate::auth::Credentials;
use crate::contacts::ContactsProvider;
use crate::datapackage::DataPackageStore;
use crate::error::EnrollmentError;
use crate::handlers::util::build_response;
use crate::handlers::{api, packages, revoke, sign};
use crate::revocation::RevocationStore;
use crate::signing::CsrSigner;

/// Default maximum CSR signing requests per IP per minute.
pub const DEFAULT_SIGN_RATE_LIMIT: usize = 10;

/// Default rate limit window for CSR signing.
pub const DEFAULT_SIGN_RATE_WINDOW: Duration = Duration::from_secs(60);

rustgate_core::on_callback!(
    /// Callback fired when a CSR signing request is rejected by the
    /// per-IP rate limiter. Wired by the server binary to a Prometheus
    /// counter; left unset in tests and embedders that do not need it.
    pub RateLimitCallback
);

/// HTTPS enrollment server for client certificate provisioning.
pub struct EnrollmentServer {
    signer: Arc<CsrSigner>,
    credentials: Arc<Credentials>,
    contacts_provider: Option<ContactsProvider>,
    packages: Option<Arc<DataPackageStore>>,
    revocation: Option<Arc<RevocationStore>>,
    sign_limiter: Arc<SlidingWindowLimiter>,
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
            sign_limiter: Arc::new(SlidingWindowLimiter::new(
                DEFAULT_SIGN_RATE_LIMIT,
                DEFAULT_SIGN_RATE_WINDOW,
                "request",
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
        self.sign_limiter = Arc::new(SlidingWindowLimiter::new(max_requests, window, "request"));
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
    ///
    /// # TLS is non-negotiable (issue #767 / F-40)
    ///
    /// PKCS#12 enrollment responses contain **unencrypted** certificate
    /// bags integrity-protected only by an HMAC-SHA1 MAC under the
    /// standardized `"atakatak"` password (see
    /// [`crate::pkcs12`] module docs). Anyone who captures a bundle on
    /// the wire recovers the full client certificate chain. TLS is the
    /// only real confidentiality boundary on this endpoint.
    ///
    /// This function therefore refuses to start if `cert_pem` or
    /// `key_pem` is empty/whitespace — an explicit precondition check
    /// rather than letting the downstream TLS builder return a generic
    /// "failed to parse server certs" error. EST (RFC 7030) over
    /// plaintext is similarly impossible: the EST handlers share this
    /// same listener, so if the TLS config is present the EST endpoints
    /// also ride on TLS; if the preflight check rejects the config,
    /// nothing starts at all.
    pub async fn run(
        self,
        bind_addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), EnrollmentError> {
        // F-40 precondition: reject a plaintext/empty TLS config outright.
        // `build_server_tls_config` would also reject empty inputs via
        // `parse_certs` / `parse_key`, but its error message ("failed to
        // parse server certs") does not communicate the security rationale
        // — the operator sees a parser error rather than "P12 enrollment
        // REQUIRES TLS, refusing to start". See module-level docs on
        // `crate::pkcs12` for why the confidentiality boundary is TLS and
        // not the PFX password.
        if cert_pem.trim().is_empty() || key_pem.trim().is_empty() {
            return Err(EnrollmentError::Config(
                "enrollment server requires TLS (non-empty cert_pem and key_pem): \
                 PKCS#12 bundles contain unencrypted certificate bags protected \
                 only by a publicly-known standardized password, so the TLS \
                 channel is the real confidentiality boundary. Refusing to start \
                 without TLS."
                    .to_string(),
            ));
        }
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

            spawn_background("enrollment-conn", async move {
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
            });
        }
    }
}

/// Route an incoming HTTP request to the appropriate handler.
// justification: request plus every pluggable provider (signer, credentials,
// contacts, packages, revocation, rate limiter, rate-limit callback, EST
// gate) is needed here — none of them is optional on the dispatch path, and
// bundling them into a struct would just shift the positional-args problem
// to that struct's construction with no type-safety gain.
#[allow(clippy::too_many_arguments)]
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    signer: &CsrSigner,
    credentials: &Credentials,
    contacts: Option<&ContactsProvider>,
    packages: Option<&DataPackageStore>,
    revocation: Option<&RevocationStore>,
    sign_limiter: &SlidingWindowLimiter,
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
    sign_limiter: &SlidingWindowLimiter,
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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    //! Unit tests for `EnrollmentServer`'s builder, `Debug` redaction,
    //! module-level constants, and the F-40 TLS preflight in `run()`.
    //!
    //! Full integration coverage lives in
    //! `tests/server_integration.rs` and `tests/est_integration.rs`.

    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustgate_test_utils::certs::TestCa;
    use zeroize::Zeroizing;

    use super::*;
    use crate::auth::Credentials;
    use crate::signing::CsrSigner;

    /// Build a minimal `EnrollmentServer` for structural tests.
    /// Uses `TestCa` to produce a real signer — `CsrSigner::from_pem`
    /// parses the CA cert + key so we cannot stub those in from thin air.
    fn build_server_for_tests() -> EnrollmentServer {
        let ca = TestCa::new("test-ca");
        let signer =
            CsrSigner::from_pem(&ca.cert_pem, &ca.key_pem, "test-org").expect("build signer");
        let creds = Credentials::new("admin".to_string(), Zeroizing::new("secret".to_string()));
        EnrollmentServer::new(signer, creds)
    }

    #[test]
    fn new_default_config_has_no_optional_providers_and_uses_documented_rate_limits() {
        // `EnrollmentServer::new` is the base constructor every deployment
        // path calls before layering optional features via `with_*`. Three
        // invariants must hold on the fresh struct:
        //   1. All optional providers are `None` — a refactor that
        //      accidentally populated one of them with a default stub
        //      (say, an in-memory `DataPackageStore`) would silently
        //      expose `/Marti/sync/*` endpoints on every enrollment
        //      server, defeating the "explicitly opt-in" builder model.
        //   2. The sign_limiter uses `DEFAULT_SIGN_RATE_LIMIT` (10) and
        //      `DEFAULT_SIGN_RATE_WINDOW` (60s) — the CLI's
        //      `--enrollment-rate-limit` flag omission relies on these.
        //   3. Neither rate-limit callback is wired — a refactor that
        //      pre-populated `on_rate_limit` with a no-op closure would
        //      change the behaviour of `with_rate_limit_callback` from
        //      "override None" to "replace existing" and break every
        //      test that relies on the None-to-Some transition.
        let server = build_server_for_tests();

        assert!(
            server.contacts_provider.is_none(),
            "contacts_provider must default to None"
        );
        assert!(server.packages.is_none(), "packages must default to None");
        assert!(
            server.revocation.is_none(),
            "revocation must default to None"
        );
        assert!(
            server.on_rate_limit.is_none(),
            "on_rate_limit must default to None"
        );
        assert_eq!(
            server.sign_limiter.max(),
            DEFAULT_SIGN_RATE_LIMIT,
            "default sign_limiter.max must match DEFAULT_SIGN_RATE_LIMIT"
        );
        assert_eq!(
            server.sign_limiter.window(),
            DEFAULT_SIGN_RATE_WINDOW,
            "default sign_limiter.window must match DEFAULT_SIGN_RATE_WINDOW"
        );
        assert_eq!(
            server.sign_limiter.category(),
            "request",
            "enrollment limiter audit category must be `request` post-#798"
        );
    }

    #[test]
    fn debug_impl_elides_sensitive_fields_and_reports_optional_provider_bools() {
        // The manual `Debug` impl exists precisely because a derived
        // `Debug` would render the `Arc<CsrSigner>` (which transitively
        // holds a private key) and the `Arc<Credentials>` (which holds
        // the HTTP Basic auth password inside a `Zeroizing<String>`
        // whose `Debug` delegates to the inner `String`). The manual
        // impl must:
        //   - Render a field named `signer` and `credentials` (operators
        //     rely on tracing::debug!(?server, …) to confirm presence)
        //     but their values may contain inner types' Debug output —
        //     that is acceptable because `CsrSigner`/`Credentials` each
        //     redact their own secrets internally.
        //   - Render `contacts_provider: true|false`, `packages:
        //     true|false`, `revocation: true|false` so the on-call can
        //     see which features are wired without leaking the actual
        //     provider state (endpoints, connection pools, redb
        //     handles).
        //   - Not contain any of the password bytes.
        //
        // The password chosen below is an unambiguous sentinel that
        // would definitely appear in a naive derived-Debug output.
        let ca = TestCa::new("test-ca");
        let signer =
            CsrSigner::from_pem(&ca.cert_pem, &ca.key_pem, "test-org").expect("build signer");
        let creds = Credentials::new(
            "admin".to_string(),
            Zeroizing::new("UNIQUE-SENTINEL-PASSWORD-42".to_string()),
        );
        let server = EnrollmentServer::new(signer, creds);

        let rendered = format!("{server:?}");
        assert!(
            rendered.starts_with("EnrollmentServer {"),
            "Debug output must start with the struct name: {rendered}"
        );
        assert!(
            rendered.contains("contacts_provider: false"),
            "contacts_provider must render as bool false when unset: {rendered}"
        );
        assert!(
            rendered.contains("packages: false"),
            "packages must render as bool false when unset: {rendered}"
        );
        assert!(
            rendered.contains("revocation: false"),
            "revocation must render as bool false when unset: {rendered}"
        );
        assert!(
            !rendered.contains("UNIQUE-SENTINEL-PASSWORD-42"),
            "Debug output leaked the password bytes — \
             Credentials::Debug should redact: {rendered}"
        );
    }

    #[test]
    fn with_rate_limit_overrides_default_max_requests_and_window() {
        // The `--enrollment-rate-limit` CLI flag wires through to
        // `with_rate_limit(max_requests, window)`; this test pins that
        // the override actually reaches the sign_limiter rather than
        // being dropped on the floor. A regression that e.g. swapped
        // the argument order or forgot to reassign `self.sign_limiter`
        // would leave the defaults in place and silently under-enforce
        // a strict operator-configured limit.
        let server = build_server_for_tests().with_rate_limit(7, Duration::from_secs(30));

        assert_eq!(server.sign_limiter.max(), 7);
        assert_eq!(server.sign_limiter.window(), Duration::from_secs(30));
        assert_eq!(
            server.sign_limiter.category(),
            "request",
            "category label must be preserved across rebuilds"
        );
    }

    #[test]
    fn module_constants_pin_documented_defaults_and_limits() {
        // Four module-level constants drive operator-visible behaviour
        // and must not drift without an explicit CHANGELOG note:
        //   - DEFAULT_SIGN_RATE_LIMIT (10) — public, exposed via CLI
        //     default; a lower value would false-reject legitimate
        //     deployments, a higher value would weaken DoS protection.
        //   - DEFAULT_SIGN_RATE_WINDOW (60s) — public, paired with the
        //     above; the units matter for "10/min" to remain the
        //     documented semantics.
        //   - MAX_ENROLLMENT_CONNECTIONS (64) — private, caps the
        //     `tokio::sync::Semaphore` that the accept loop pulls from
        //     so a SYN flood against the unauthenticated TLS endpoint
        //     cannot exhaust memory. Doubling this is cheap; halving
        //     it could false-reject legitimate fleet refreshes.
        //   - ENROLLMENT_HTTP_CONNECTION_TIMEOUT (30s) — private,
        //     intentionally 2x the workspace-wide
        //     `HTTP_CONNECTION_TIMEOUT` because CSR signing +
        //     PKCS#12 generation can take seconds and the CI test
        //     harness routinely runs under slow-disk conditions; a
        //     drift to 15s would flake integration tests and trip
        //     real slow-CA deployments.
        assert_eq!(DEFAULT_SIGN_RATE_LIMIT, 10);
        assert_eq!(DEFAULT_SIGN_RATE_WINDOW, Duration::from_secs(60));
        assert_eq!(MAX_ENROLLMENT_CONNECTIONS, 64);
        assert_eq!(ENROLLMENT_HTTP_CONNECTION_TIMEOUT, Duration::from_secs(30));
        // Cross-check the documented "2x HTTP_CONNECTION_TIMEOUT"
        // relationship so a bump of the core constant without a
        // corresponding reconsideration here trips this assert.
        assert!(
            ENROLLMENT_HTTP_CONNECTION_TIMEOUT > rustgate_core::constants::HTTP_CONNECTION_TIMEOUT,
            "enrollment timeout must remain higher than core HTTP_CONNECTION_TIMEOUT \
             (CSR signing + PKCS#12 is slow)"
        );
    }

    #[tokio::test]
    async fn run_rejects_both_empty_cert_and_key_pem_with_f40_security_preflight() {
        // F-40 (issue #767): PKCS#12 enrollment bundles protect the
        // cert bag with a publicly-known standardized password
        // ("atakatak"), so the TLS channel is the real confidentiality
        // boundary. The server refuses to start without TLS so an
        // operator cannot accidentally run plaintext enrollment (which
        // would silently leak full client cert chains to any passive
        // observer). This test pins the empty-string rejection path
        // and the distinctive error message that tells the operator
        // *why* — a regression that collapsed the message into a
        // generic "config error" would leave the operator chasing a
        // parser bug.
        let server = build_server_for_tests();
        let bind = "127.0.0.1:0".parse().unwrap();
        let err = server
            .run(bind, "", "")
            .await
            .expect_err("empty pem must fail");
        match err {
            EnrollmentError::Config(msg) => {
                assert!(
                    msg.contains("requires TLS"),
                    "error must cite the F-40 rationale 'requires TLS': {msg}"
                );
                assert!(
                    msg.contains("PKCS#12"),
                    "error must mention PKCS#12 so operator understands why: {msg}"
                );
            }
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_rejects_whitespace_only_cert_pem_with_f40_security_preflight() {
        // The preflight uses `.trim().is_empty()` so a whitespace-only
        // file (a common "accidentally fed in an empty env var via
        // shell heredoc" mistake) is still rejected. A regression that
        // dropped the `trim()` call would silently accept such inputs
        // and let them fall through to `rustgate_core::pem::parse_certs`
        // whose error message does not communicate the F-40 security
        // rationale.
        let ca = TestCa::new("test-ca");
        let signer =
            CsrSigner::from_pem(&ca.cert_pem, &ca.key_pem, "test-org").expect("build signer");
        let creds = Credentials::new("admin".to_string(), Zeroizing::new("secret".to_string()));
        let server = EnrollmentServer::new(signer, creds);

        let bind = "127.0.0.1:0".parse().unwrap();
        let err = server
            .run(bind, "  \n\t  ", &ca.key_pem)
            .await
            .expect_err("whitespace-only cert_pem must fail the F-40 preflight");
        match err {
            EnrollmentError::Config(msg) => {
                assert!(msg.contains("requires TLS"), "expected F-40 message: {msg}");
            }
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_rejects_whitespace_only_key_pem_with_f40_security_preflight() {
        // Symmetric to the cert-side whitespace test: empty-after-trim
        // on the key side must also fail the F-40 preflight. Without
        // this, an operator who fed an empty `--enrollment-key` file
        // would see the generic rustls "failed to parse server key"
        // error and not understand the confidentiality rationale for
        // the refusal.
        let ca = TestCa::new("test-ca");
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
        let signer =
            CsrSigner::from_pem(&ca.cert_pem, &ca.key_pem, "test-org").expect("build signer");
        let creds = Credentials::new("admin".to_string(), Zeroizing::new("secret".to_string()));
        let server = EnrollmentServer::new(signer, creds);

        let bind = "127.0.0.1:0".parse().unwrap();
        let err = server
            .run(bind, &server_cert.cert_pem, "\t\n   \n")
            .await
            .expect_err("whitespace-only key_pem must fail the F-40 preflight");
        match err {
            EnrollmentError::Config(msg) => {
                assert!(msg.contains("requires TLS"), "expected F-40 message: {msg}");
            }
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn with_rate_limit_callback_wires_none_to_some_transition_for_prometheus_fan_out() {
        // `with_rate_limit_callback(cb)` should move the callback from
        // `None` to `Some(Arc<dyn Fn>)`. This is the transition the
        // server binary relies on to wire the
        // `rustgate_enrollment_rate_limit_total` Prometheus counter —
        // a regression that failed to store the callback, or stored a
        // no-op wrapper rather than the caller's Arc, would silently
        // drop every rate-limit metric. The test does not assert the
        // callback is *invoked* on a real rate-limit hit (that is the
        // integration test's job) — it proves only that the `None →
        // Some` wiring happens and that the stored handle is the same
        // `Arc` (via strong-count bookkeeping).
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cb = Arc::clone(&counter);
        let cb: RateLimitCallback = Arc::new(move || {
            let _ = counter_cb.fetch_add(1, Ordering::Relaxed);
        });
        let strong_before = Arc::strong_count(&cb);

        let server = build_server_for_tests().with_rate_limit_callback(Arc::clone(&cb));

        assert!(
            server.on_rate_limit.is_some(),
            "with_rate_limit_callback must transition on_rate_limit to Some"
        );
        // One Arc clone lives on the server, one here in `cb` — strong
        // count must have grown by exactly 1.
        assert_eq!(
            Arc::strong_count(&cb),
            strong_before + 1,
            "with_rate_limit_callback must store the caller's Arc, not wrap it"
        );

        // Firing the stored callback must reach the caller's counter.
        let stored = server.on_rate_limit.as_ref().expect("stored callback");
        stored();
        stored();
        assert_eq!(
            counter.load(Ordering::Relaxed),
            2,
            "stored callback must invoke the caller's closure"
        );
    }
}
