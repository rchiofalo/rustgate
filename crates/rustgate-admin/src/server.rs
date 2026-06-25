// Copyright © 2026 Roberto Chiofalo.

//! HTTP listener and request dispatcher for the admin/metrics server.
//!
//! This module owns the long-running [`serve`] task: it binds the TCP
//! listener, applies tactical-socket tuning, gates connection count, and
//! routes incoming requests across the Prometheus exposition endpoint,
//! the Kubernetes-style probes, and three optional REST handlers
//! (federation, ACL, mgmt) registered via type-erased
//! [`OnceLock`]-backed slots.
//!
//! The dependency-check helpers ([`HealthState`], [`ReadinessState`],
//! [`DependencyCheck`], [`ReadinessReport`]) live here too so the
//! readiness probe can inspect the TLS cert reloader, NATS publisher,
//! federation manager, and HTTP egress publisher without forcing the
//! admin crate to take an `async-nats` / `tonic` dep — the optional
//! feature flags (`nats`, `federation`, `http`) gate just enough of the
//! type system to call helper methods on those subsystem handles.
//!
//! `cert_expiry_seconds` lives here (rather than in the server-side
//! Prometheus surface) because it is updated as a side effect of
//! [`ReadinessState::check`] and only this module touches it.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use prometheus::{Encoder, IntGauge, Opts, TextEncoder};
use rustgate_core::constants::HTTP_CONNECTION_TIMEOUT;
use rustgate_core::net::configure_tactical_socket;
use rustgate_core::tasks::spawn_background;
use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Type-erased federation API handler.
///
/// When set, the metrics server delegates requests under `/api/federation/`
/// to this handler. Returns `None` for unrecognized paths so the caller can
/// fall through to 404.
#[cfg(feature = "federation")]
pub type FedApiHandler =
    Arc<dyn Fn(&hyper::Method, &str, &[u8]) -> Option<Response<Full<Bytes>>> + Send + Sync>;

/// Type-erased ACL API handler.
///
/// When set, the metrics server delegates requests under `/api/acl/`
/// to this handler. Returns `None` for unrecognized paths so the caller
/// can fall through to 404.
pub type AclApiHandler = Arc<
    dyn Fn(&hyper::Method, &str, Option<&str>, &[u8]) -> Option<Response<Full<Bytes>>>
        + Send
        + Sync,
>;

/// Type-erased video stream catalog API handler.
///
/// When set, the metrics server delegates `GET /api/video/streams`
/// to this handler. Returns `None` for unrecognized paths so the
/// caller can fall through to 404. Wired by the server binary under
/// `--features video` (closes #862).
#[cfg(feature = "video")]
pub type VideoApiHandler =
    Arc<dyn Fn(&hyper::Method, &str, &[u8]) -> Option<Response<Full<Bytes>>> + Send + Sync>;

/// Type-erased correlation engine API handler.
///
/// When set, the metrics server delegates
/// `GET /api/correlation/fused-entities` to this handler. Returns
/// `None` for unrecognized paths so the caller can fall through to
/// 404. Wired by the server binary under `--features correlation`
/// (closes #848). The shape mirrors the video catalog handler — sync
/// `Fn`, no `auth` parameter (the snapshot endpoint is read-only and
/// unauthenticated by default; operators that need auth wrap the
/// metrics endpoint in their reverse proxy).
#[cfg(feature = "correlation")]
pub type CorrelationApiHandler =
    Arc<dyn Fn(&hyper::Method, &str, &[u8]) -> Option<Response<Full<Bytes>>> + Send + Sync>;

/// Type-erased management API handler.
///
/// When set, the metrics server delegates requests under `/api/cert/`,
/// `/api/crl/`, `/api/dedup/`, `/api/clients/`, `/api/dlq/`,
/// `/api/reload`, and `/api/drain` to this handler. Returns `None`
/// when the path does not match any management-API route so the
/// caller can fall through to the next handler or the default 404.
///
/// Unlike `AclApiHandler`, the management API exposes mutating
/// endpoints (`POST /api/clients/{cn}/disconnect`, `POST /api/reload`,
/// `POST /api/drain`) that need to `.await` on the router or the
/// reload path. The handler returns a boxed `Future` so the
/// dispatcher in [`serve`] can await without forcing the inner
/// handler to `block_on` a runtime.
pub type MgmtApiHandler = Arc<
    dyn Fn(
            &hyper::Method,
            &str,
            Option<&str>,
            &[u8],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<Response<Full<Bytes>>>> + Send>,
        > + Send
        + Sync,
>;

/// Type-erased expanded-management-API handler (closes #875). When set,
/// the metrics server delegates requests under `/api/config`,
/// `/api/config/reload`, `/api/clients`, `/api/clients/{cn}`,
/// `/api/metrics/summary`, `/api/store-forward`, `/api/audit/verify`,
/// and `/api/version` to this handler. Returns `None` when the path
/// does not match any management-API route so the caller can fall
/// through to the next handler or the default 404.
///
/// Distinct from [`MgmtApiHandler`] (which owns the legacy
/// `/api/cert/*`, `/api/dlq/*`, `/api/reload`, `/api/drain`,
/// `/api/v1/*`, and `/api/clients/{cn}/disconnect` surface) — both
/// can be registered on the same metrics server side-by-side.
#[cfg(feature = "management-api")]
pub type ManagementApiHandler = Arc<
    dyn Fn(
            &hyper::Method,
            &str,
            Option<&str>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<Response<Full<Bytes>>>> + Send>,
        > + Send
        + Sync,
>;

/// Default maximum concurrent connections to the metrics HTTP server.
/// Bounds memory usage from connection floods against the unauthenticated
/// HTTP endpoint (the TLS listener has its own separate limit).
///
/// Used as the default value for `--metrics-max-connections` in the CLI
/// and by test helpers.
pub const DEFAULT_MAX_HTTP_CONNECTIONS: usize = 128;

// ── Admin-owned metrics ─────────────────────────────────────────────

static CERT_EXPIRY_SECONDS: OnceLock<IntGauge> = OnceLock::new();

/// Register the admin-owned Prometheus metrics with the default registry.
///
/// Currently a single gauge — `rustgate_cert_expiry_seconds` — that the
/// readiness probe maintains as a side effect of
/// [`ReadinessState::check`]. Server orchestration calls this from the
/// `MetricsRegistry` ladder alongside every other crate's `init()`.
pub fn init() -> prometheus::Result<()> {
    register_metrics(prometheus::default_registry())
}

/// Register admin metrics with the given Prometheus registry. Useful for
/// tests that want an isolated registry, or for orchestration code that
/// wires the admin metrics into a non-default registry.
pub fn register_metrics(registry: &prometheus::Registry) -> prometheus::Result<()> {
    let cert_expiry = IntGauge::with_opts(Opts::new(
        "rustgate_cert_expiry_seconds",
        "Seconds remaining until the active server leaf certificate's notAfter \
         (negative if already expired). Refreshed on every /ready dependency poll \
         and after every cert hot-reload. Alert on <604800 (7d) for rotation SLO.",
    ))?;
    registry.register(Box::new(cert_expiry.clone()))?;
    let _ = CERT_EXPIRY_SECONDS.set(cert_expiry);
    Ok(())
}

/// Returns the server-cert expiry gauge. Updated as a side effect of
/// the TLS dependency check inside [`ReadinessState::check`].
///
/// The value is `notAfter - now` in seconds and can be negative once
/// the cert has expired.
pub fn cert_expiry_seconds() -> &'static IntGauge {
    CERT_EXPIRY_SECONDS.get_or_init(|| {
        IntGauge::with_opts(Opts::new("rustgate_cert_expiry_seconds", "fallback"))
            .expect("fallback gauge construction never fails")
    })
}

// ── HTTP server ─────────────────────────────────────────────────────

/// Fallback response when `Response::builder()` unexpectedly fails.
fn internal_error_response() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from("internal server error")));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

/// Differentiated health probe state for Kubernetes-style probes.
///
/// Three independent flags expose distinct lifecycle stages:
///
/// - `live` — process is alive. Flipped to `true` once the metrics server
///   starts handling requests; never flipped back. A failing liveness
///   probe instructs the orchestrator to restart the pod.
/// - `ready` — instance can serve traffic. Flipped to `true` after the
///   listener is bound and core subsystems (ACL, federation if enabled)
///   have completed initial wiring. Flipped back to `false` during
///   graceful shutdown so load balancers stop routing new traffic.
/// - `started` — one-shot initial warmup complete. Flipped exactly once
///   after the server enters its accept loop and never reset. The startup
///   probe gives slow-starting pods extra grace before liveness/readiness
///   checks begin in earnest.
#[derive(Debug)]
pub struct HealthState {
    live: AtomicBool,
    ready: AtomicBool,
    started: AtomicBool,
}

impl HealthState {
    /// Create a new `HealthState`. All flags start as `false`; callers
    /// flip them as the corresponding lifecycle stage completes.
    pub fn new() -> Self {
        Self {
            live: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            started: AtomicBool::new(false),
        }
    }

    /// Mark the process as live. Idempotent.
    pub fn set_live(&self, v: bool) {
        self.live.store(v, Ordering::Release);
    }

    /// Mark the instance as ready (or not) to serve traffic.
    pub fn set_ready(&self, v: bool) {
        self.ready.store(v, Ordering::Release);
    }

    /// Mark initial startup as complete. One-shot — typically called once
    /// after the accept loop is entered.
    ///
    /// Prefer [`HealthState::mark_started`] for the typical
    /// "transition false → true exactly once" use case. This setter is
    /// retained for tests and other edge cases that need to construct a
    /// specific state, but production code paths must not call it with
    /// `false` after startup has been observed.
    #[doc(hidden)]
    pub fn set_started(&self, v: bool) {
        self.started.store(v, Ordering::Release);
    }

    /// One-shot transition of the `started` flag from `false` to `true`.
    ///
    /// Returns `true` if this call performed the transition, `false` if
    /// the flag was already set. Implemented with `compare_exchange` so
    /// concurrent callers race safely and the flag can never regress to
    /// `false` once observed as `true`.
    pub fn mark_started(&self) -> bool {
        let result =
            self.started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
        debug_assert!(
            result.is_ok() || result == Err(true),
            "started flag must never regress",
        );
        result.is_ok()
    }

    /// Returns `true` once the process loop is reachable.
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    /// Returns `true` when the instance can serve traffic.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Returns `true` once initial warmup has completed.
    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Readiness dependency checks ────────────────────────────────────

/// Status of an individual dependency check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Dependency is healthy.
    Ok,
    /// Dependency is reachable but in a degraded state.
    Degraded,
    /// Dependency is unreachable or broken.
    Unhealthy,
}

/// Result of a single readiness dependency check.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyCheck {
    pub status: CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl DependencyCheck {
    fn ok() -> Self {
        Self {
            status: CheckStatus::Ok,
            message: None,
        }
    }

    fn degraded(msg: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Degraded,
            message: Some(msg.into()),
        }
    }

    fn unhealthy(msg: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Unhealthy,
            message: Some(msg.into()),
        }
    }
}

/// Aggregate readiness report returned as structured JSON from the
/// `/readyz` and `/health/ready` endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessReport {
    pub status: CheckStatus,
    pub checks: std::collections::BTreeMap<String, DependencyCheck>,
}

/// Optional dependency handles used by readiness checks.
///
/// The metrics server holds an `Arc<ReadinessState>` and inspects each
/// registered dependency when `/readyz` or `/health/ready` is hit.
/// Fields that are `None` are skipped — the corresponding check is not
/// included in the report.
pub struct ReadinessState {
    /// TLS certificate reloader — checked for cert existence and expiry.
    pub cert_reloader: Option<Arc<rustgate_tls::CertReloader>>,

    /// NATS publisher — checked for connection state via
    /// `NatsPublisher::is_connected`.
    #[cfg(feature = "nats")]
    pub nats_publisher: std::sync::Mutex<Option<rustgate_nats::NatsPublisher>>,

    /// Federation manager — checked for connected peer count.
    #[cfg(feature = "federation")]
    pub federation_manager: std::sync::Mutex<
        Option<Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>>,
    >,

    /// HTTP egress publisher — checked for circuit breaker health.
    #[cfg(feature = "http")]
    pub http_publisher: std::sync::Mutex<Option<rustgate_http::HttpPublisher>>,

    /// Optional pre-scrape hook invoked before encoding `/metrics`.
    /// Server orchestration uses this to refresh the jemalloc gauge set
    /// (so Prometheus sees current memory values rather than stale
    /// cached counters). Stored on `ReadinessState` so callers can wire
    /// it once at construction without expanding the [`serve`]
    /// signature; the field is otherwise unrelated to dependency
    /// checking.
    pub pre_scrape: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for ReadinessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadinessState")
            .field("cert_reloader", &self.cert_reloader.is_some())
            .field("pre_scrape", &self.pre_scrape.is_some())
            .finish()
    }
}

impl ReadinessState {
    /// Create a new empty readiness state with no dependencies registered.
    pub fn new() -> Self {
        Self {
            cert_reloader: None,
            #[cfg(feature = "nats")]
            nats_publisher: std::sync::Mutex::new(None),
            #[cfg(feature = "federation")]
            federation_manager: std::sync::Mutex::new(None),
            #[cfg(feature = "http")]
            http_publisher: std::sync::Mutex::new(None),
            pre_scrape: None,
        }
    }

    /// Register a NATS publisher for readiness checking.
    #[cfg(feature = "nats")]
    pub fn set_nats_publisher(&self, publisher: rustgate_nats::NatsPublisher) {
        if let Ok(mut guard) = self.nats_publisher.lock() {
            *guard = Some(publisher);
        }
    }

    /// Register a federation manager for readiness checking.
    #[cfg(feature = "federation")]
    pub fn set_federation_manager(
        &self,
        mgr: Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>,
    ) {
        if let Ok(mut guard) = self.federation_manager.lock() {
            *guard = Some(mgr);
        }
    }

    /// Register an HTTP publisher for readiness checking.
    #[cfg(feature = "http")]
    pub fn set_http_publisher(&self, publisher: rustgate_http::HttpPublisher) {
        if let Ok(mut guard) = self.http_publisher.lock() {
            *guard = Some(publisher);
        }
    }

    /// Run all registered dependency checks and return a structured report.
    ///
    /// The aggregate status is the worst individual status:
    /// - All `Ok` -> `Ok`
    /// - Any `Degraded` (no `Unhealthy`) -> `Degraded`
    /// - Any `Unhealthy` -> `Unhealthy`
    pub fn check(&self) -> ReadinessReport {
        let mut checks = std::collections::BTreeMap::new();

        // TLS certificate validity
        if let Some(ref reloader) = self.cert_reloader {
            let _ = checks.insert("tls".to_string(), check_tls_cert(reloader));
        }

        // NATS connection state
        #[cfg(feature = "nats")]
        if let Ok(guard) = self.nats_publisher.lock()
            && let Some(ref publisher) = *guard
        {
            let _ = checks.insert("nats".to_string(), check_nats(publisher));
        }

        // Federation peer connectivity
        #[cfg(feature = "federation")]
        if let Ok(guard) = self.federation_manager.lock()
            && let Some(ref mgr) = *guard
        {
            let _ = checks.insert("federation".to_string(), check_federation(mgr));
        }

        // HTTP egress circuit breaker health
        #[cfg(feature = "http")]
        if let Ok(guard) = self.http_publisher.lock()
            && let Some(ref publisher) = *guard
        {
            let _ = checks.insert("http".to_string(), check_http(publisher));
        }

        let status = aggregate_status(checks.values());
        ReadinessReport { status, checks }
    }
}

impl Default for ReadinessState {
    fn default() -> Self {
        Self::new()
    }
}

/// Check TLS certificate validity by parsing the end-entity cert and
/// comparing its `notBefore`/`notAfter` fields against the current time.
pub(crate) fn check_tls_cert(reloader: &rustgate_tls::CertReloader) -> DependencyCheck {
    let Some(certified_key) = reloader.certified_key() else {
        return DependencyCheck::unhealthy("certificate not loaded");
    };

    let Some(ee_cert_der) = certified_key.cert.first() else {
        return DependencyCheck::unhealthy("certificate chain is empty");
    };

    let Ok((_rem, cert)) = x509_parser::parse_x509_certificate(ee_cert_der.as_ref()) else {
        return DependencyCheck::unhealthy("failed to parse certificate");
    };

    let validity = cert.validity();
    let now = x509_parser::time::ASN1Time::now();

    let not_after_ts = validity.not_after.timestamp();
    let now_ts = now.timestamp();
    let remaining_secs = not_after_ts - now_ts;
    cert_expiry_seconds().set(remaining_secs);

    if now < validity.not_before {
        return DependencyCheck::unhealthy("certificate not yet valid");
    }
    if now > validity.not_after {
        return DependencyCheck::unhealthy("certificate has expired");
    }

    // Warn if the certificate expires within 7 days.
    let seven_days_secs: i64 = 7 * 24 * 60 * 60;
    if remaining_secs < seven_days_secs {
        let days = remaining_secs / (24 * 60 * 60);
        return DependencyCheck::degraded(format!("certificate expires in {days} day(s)"));
    }

    DependencyCheck::ok()
}

/// Check NATS connection state via `NatsPublisher` helper methods,
/// avoiding a direct dependency on `async-nats` in this crate.
#[cfg(feature = "nats")]
fn check_nats(publisher: &rustgate_nats::NatsPublisher) -> DependencyCheck {
    if publisher.is_connected() {
        DependencyCheck::ok()
    } else if publisher.is_pending() {
        DependencyCheck::degraded("NATS connection pending")
    } else {
        DependencyCheck::unhealthy("NATS disconnected")
    }
}

/// Check federation peer connectivity.
#[cfg(feature = "federation")]
fn check_federation(
    mgr: &Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>,
) -> DependencyCheck {
    let Ok(guard) = mgr.try_read() else {
        // Lock contention during reconfiguration; report degraded rather
        // than blocking the health endpoint.
        return DependencyCheck::degraded("federation manager busy");
    };
    let total = guard.peer_count();
    let connected = guard.connected_peer_count();

    if total == 0 {
        // No peers configured — federation is effectively idle; this is not
        // an error condition.
        return DependencyCheck::ok();
    }

    if connected == 0 {
        return DependencyCheck::unhealthy(format!("0/{total} peers connected"));
    }
    if connected < total {
        return DependencyCheck::degraded(format!("{connected}/{total} peers connected"));
    }
    DependencyCheck::ok()
}

/// Check HTTP egress circuit breaker health.
///
/// Reports degraded when any target has an open circuit breaker,
/// and unhealthy only when ALL circuits are open.
#[cfg(feature = "http")]
fn check_http(publisher: &rustgate_http::HttpPublisher) -> DependencyCheck {
    if publisher.is_healthy() {
        DependencyCheck::ok()
    } else {
        DependencyCheck::degraded("one or more HTTP target circuits open")
    }
}

/// Aggregate individual check statuses into the worst-case overall status.
fn aggregate_status<'a>(checks: impl Iterator<Item = &'a DependencyCheck>) -> CheckStatus {
    let mut worst = CheckStatus::Ok;
    for c in checks {
        match c.status {
            CheckStatus::Unhealthy => return CheckStatus::Unhealthy,
            CheckStatus::Degraded => worst = CheckStatus::Degraded,
            CheckStatus::Ok => {}
        }
    }
    worst
}

fn probe_response(
    ok: bool,
    ok_body: &'static str,
    fail_body: &'static str,
) -> Response<Full<Bytes>> {
    if ok {
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(ok_body)))
            .unwrap_or_else(|_| internal_error_response())
    } else {
        Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Full::new(Bytes::from(fail_body)))
            .unwrap_or_else(|_| internal_error_response())
    }
}

/// Constant-time check of a supplied bearer token against the expected value.
///
/// Returns `true` when the `Authorization` header is present, starts with
/// `Bearer `, and the remainder matches `expected` in constant time.
fn metrics_auth_ok(header: Option<&str>, expected: &[u8]) -> bool {
    let Some(raw) = header else {
        return false;
    };
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    token.as_bytes().ct_eq(expected).into()
}

/// Build a structured JSON readiness response that includes dependency
/// check results alongside the base `ready` flag from `HealthState`.
///
/// When `HealthState::is_ready()` is `false` (e.g. during graceful
/// shutdown), the overall status is forced to `unhealthy` regardless of
/// individual check outcomes. Otherwise the aggregate status reflects
/// the worst individual check.
///
/// Returns HTTP 200 for `ok` or `degraded`, 503 for `unhealthy`.
fn readiness_response(health: &HealthState, readiness: &ReadinessState) -> Response<Full<Bytes>> {
    let mut report = readiness.check();

    // Override aggregate status when the base readiness flag is off
    // (graceful shutdown or not yet ready).
    if !health.is_ready() {
        report.status = CheckStatus::Unhealthy;
    }

    let status_code = match report.status {
        CheckStatus::Ok | CheckStatus::Degraded => StatusCode::OK,
        CheckStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    match serde_json::to_string(&report) {
        Ok(body) => Response::builder()
            .status(status_code)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| internal_error_response()),
        Err(_) => internal_error_response(),
    }
}

fn handle_request(
    req: Request<hyper::body::Incoming>,
    health: Arc<HealthState>,
    readiness: Arc<ReadinessState>,
    metrics_token: Option<Arc<Zeroizing<Vec<u8>>>>,
    router_slot: RouterSlot,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    match req.uri().path() {
        // Liveness: process loop is reachable. Returns 200 once the
        // metrics server is up; orchestrators interpret a non-200 as
        // "restart the pod".
        "/health/live" => Ok(probe_response(health.is_live(), "ok", "not live")),

        // Readiness: returns structured JSON with dependency checks.
        // HTTP 200 for ok/degraded, 503 for unhealthy.
        "/health/ready" => Ok(readiness_response(&health, &readiness)),

        // Startup: initial warmup complete. Allows slow-starting pods to
        // delay liveness/readiness checks during boot.
        "/health/startup" => Ok(probe_response(health.is_started(), "ok", "starting")),

        // Authz health: compile warnings from the installed policy
        // engine, if any. Returns a JSON object so operators can
        // inspect warnings without scraping logs.
        "/health/authz" => Ok(authz_health_response(router_slot.get())),

        // Legacy aliases — kept for backwards compatibility. `/healthz`
        // mirrors `/health/live` and `/readyz` mirrors `/health/ready`.
        "/healthz" => Ok(probe_response(health.is_live(), "ok", "not live")),

        // Legacy alias — `/readyz` mirrors `/health/ready` (structured
        // readiness with dependency checks).
        "/readyz" => Ok(readiness_response(&health, &readiness)),

        "/metrics" => {
            // When a metrics token is configured, require valid auth.
            if let Some(ref expected) = metrics_token {
                let auth = req
                    .headers()
                    .get(hyper::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok());
                if !metrics_auth_ok(auth, expected) {
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(hyper::header::WWW_AUTHENTICATE, "Bearer")
                        .body(Full::new(Bytes::from("unauthorized")))
                        .unwrap_or_else(|_| internal_error_response()));
                }
            }

            // Fire the optional pre-scrape hook (e.g. jemalloc stat
            // refresh) so Prometheus sees current values rather than
            // whatever was cached at last gather.
            if let Some(ref hook) = readiness.pre_scrape {
                hook();
            }

            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = Vec::new();
            if encoder.encode(&metric_families, &mut buffer).is_err() {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("metrics encoding failed")))
                    .unwrap_or_else(|_| internal_error_response()));
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", encoder.format_type())
                .body(Full::new(Bytes::from(buffer)))
                .unwrap_or_else(|_| internal_error_response()))
        }

        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found")))
            .unwrap_or_else(|_| internal_error_response())),
    }
}

/// Build a JSON response for the `/health/authz` endpoint.
///
/// When a policy engine is installed, returns:
/// ```json
/// {
///     "policy_id": "<sha256>",
///     "compile_warnings": ["warning 1", "warning 2"]
/// }
/// ```
///
/// When no engine is installed, returns:
/// ```json
/// {
///     "policy_id": null,
///     "compile_warnings": []
/// }
/// ```
fn authz_health_response(router: Option<&Arc<rustgate_router::Router>>) -> Response<Full<Bytes>> {
    /// Typed response for `/health/authz` — serialized via `serde_json`
    /// to guarantee RFC 8259-compliant escaping of all string values.
    #[derive(serde::Serialize)]
    struct AuthzHealth<'a> {
        policy_id: Option<&'a str>,
        compile_warnings: &'a [String],
    }

    let (policy_id, warnings): (Option<String>, Vec<String>) = match router {
        Some(r) => match r.authz_snapshot() {
            Some(engine) => {
                let id = engine.policy_id().to_string();
                let w = engine
                    .compile_warnings()
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                (Some(id), w)
            }
            None => (None, Vec::new()),
        },
        None => (None, Vec::new()),
    };

    let resp = AuthzHealth {
        policy_id: policy_id.as_deref(),
        compile_warnings: &warnings,
    };

    let body = serde_json::to_string(&resp).unwrap_or_else(|_| String::from("{}"));

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Type alias for the router reference shared with the metrics server.
///
/// Populated via `OnceLock` after the router is constructed (which happens
/// after `start_metrics` spawns the HTTP server). Requests that arrive
/// before the slot is filled return an empty warnings list.
pub type RouterSlot = Arc<OnceLock<Arc<rustgate_router::Router>>>;

/// Serve Prometheus metrics and health endpoints at the given address.
///
/// Routes:
/// - `GET /metrics`        — Prometheus text format (optionally authenticated)
/// - `GET /health/live`    — Kubernetes liveness probe
/// - `GET /health/ready`   — Kubernetes readiness probe (structured JSON
///   with dependency checks)
/// - `GET /health/startup` — Kubernetes startup probe
/// - `GET /health/authz`   — Authz engine compile warnings (JSON)
/// - `GET /healthz`        — Deprecated alias for `/health/live`
/// - `GET /readyz`         — Deprecated alias for `/health/ready`
///
/// When `metrics_token` is `Some`, requests to `/metrics` must present a
/// valid `Authorization: Bearer <token>` header; missing or mismatched
/// tokens yield a 401 response. When `None`, `/metrics` is served without
/// authentication for backward compatibility.
///
/// The server is hardened against unauthenticated abuse:
/// - Connection count bounded by `max_http_connections`
/// - Per-connection timeout of `HTTP_CONNECTION_TIMEOUT`
/// - Header read timeout of 5 seconds
// justification: the metrics/admin server needs every pluggable surface
// wired into one long-running task (bind, health, readiness, optional
// federation API, ACL API, bearer token, hot-reloadable router slot, conn
// cap). This is called once from the setup path; a builder would just move
// the fan-in upstream without reducing the number of live inputs.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    bind: SocketAddr,
    health: Arc<HealthState>,
    readiness: Arc<ReadinessState>,
    #[cfg(feature = "federation")] fed_api: Arc<OnceLock<FedApiHandler>>,
    acl_api: Arc<OnceLock<AclApiHandler>>,
    mgmt_api: Arc<OnceLock<MgmtApiHandler>>,
    #[cfg(feature = "management-api")] management_api: Arc<OnceLock<ManagementApiHandler>>,
    #[cfg(feature = "video")] video_api: Arc<OnceLock<VideoApiHandler>>,
    #[cfg(feature = "correlation")] correlation_api: Arc<OnceLock<CorrelationApiHandler>>,
    #[cfg(feature = "missions")] missions_api: Arc<OnceLock<crate::MissionsApiHandler>>,
    metrics_token: Option<Arc<Zeroizing<Vec<u8>>>>,
    router_slot: RouterSlot,
    max_http_connections: usize,
) -> Result<(), crate::error::AdminServerError> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|source| crate::error::AdminServerError::Bind { addr: bind, source })?;
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(max_http_connections));
    // The metrics server is up — the process loop is reachable, so the
    // liveness flag may flip on. Readiness/startup remain controlled by
    // the main server lifecycle.
    health.set_live(true);
    tracing::info!(addr = %bind, "metrics server started");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(source) => {
                // A transient accept() error (EMFILE/ENFILE under fd pressure,
                // ECONNABORTED, …) must NOT permanently kill the metrics/health
                // server: /healthz backs the liveness probe, so bailing here can
                // cascade into the orchestrator killing an otherwise-healthy pod
                // (#1503). Log, back off briefly so a persistent condition
                // does not hot-spin the loop, and keep serving — matching the
                // continue-on-error behaviour of the data-plane listeners.
                tracing::warn!(
                    addr = %bind,
                    error = %source,
                    "metrics server accept() error; backing off and continuing"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        // Apply shared TCP tactical-socket tuning so dead NAT middleboxes
        // and half-open scrapers are detected instead of hanging the
        // connection semaphore, and small metrics request/response pairs
        // are not penalized by Nagle+DELACK.
        configure_tactical_socket(&stream);

        let permit = match Arc::clone(&conn_limit).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                drop(stream);
                continue;
            }
        };

        let io = hyper_util::rt::TokioIo::new(stream);
        let health = Arc::clone(&health);
        let readiness = Arc::clone(&readiness);
        #[cfg(feature = "federation")]
        let fed_api = Arc::clone(&fed_api);
        let acl_api = Arc::clone(&acl_api);
        let mgmt_api = Arc::clone(&mgmt_api);
        #[cfg(feature = "management-api")]
        let management_api = Arc::clone(&management_api);
        #[cfg(feature = "video")]
        let video_api = Arc::clone(&video_api);
        #[cfg(feature = "correlation")]
        let correlation_api = Arc::clone(&correlation_api);
        #[cfg(feature = "missions")]
        let missions_api = Arc::clone(&missions_api);
        let metrics_token = metrics_token.clone();
        let router_slot = Arc::clone(&router_slot);
        spawn_background("metrics-http-conn", async move {
            let _permit = permit;
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .serve_connection(
                    io,
                    service_fn(move |req: Request<hyper::body::Incoming>| {
                        let health = Arc::clone(&health);
                        let readiness = Arc::clone(&readiness);
                        #[cfg(feature = "federation")]
                        let fed_api = Arc::clone(&fed_api);
                        let acl_api = Arc::clone(&acl_api);
                        let mgmt_api = Arc::clone(&mgmt_api);
                        #[cfg(feature = "management-api")]
                        let management_api = Arc::clone(&management_api);
                        #[cfg(feature = "video")]
                        let video_api = Arc::clone(&video_api);
                        #[cfg(feature = "correlation")]
                        let correlation_api = Arc::clone(&correlation_api);
                        #[cfg(feature = "missions")]
                        let missions_api = Arc::clone(&missions_api);
                        let metrics_token = metrics_token.clone();
                        let router_slot = Arc::clone(&router_slot);
                        async move {
                            // Delegate /api/federation/ paths to the federation handler
                            #[cfg(feature = "federation")]
                            if req.uri().path().starts_with("/api/federation/") {
                                if let Some(handler) = fed_api.get() {
                                    let method = req.method().clone();
                                    let path = req.uri().path().to_string();
                                    let body = http_body_util::BodyExt::collect(req.into_body())
                                        .await
                                        .map(|b| b.to_bytes())
                                        .unwrap_or_default();
                                    if let Some(resp) = handler(&method, &path, &body) {
                                        return Ok(resp);
                                    }
                                }
                                return Ok(Response::builder()
                                    .status(StatusCode::SERVICE_UNAVAILABLE)
                                    .body(Full::new(Bytes::from("federation API not ready")))
                                    .unwrap_or_else(|_| internal_error_response()));
                            }
                            // Delegate /api/video/* paths to the video catalog handler.
                            // Closes #862. The handler is sync because the
                            // catalog read path is non-blocking; matches the
                            // shape of the `FedApiHandler` slot above.
                            #[cfg(feature = "video")]
                            if req.uri().path().starts_with("/api/video/")
                                && let Some(handler) = video_api.get()
                            {
                                let method = req.method().clone();
                                let path = req.uri().path().to_string();
                                let body = http_body_util::BodyExt::collect(req.into_body())
                                    .await
                                    .map(|b| b.to_bytes())
                                    .unwrap_or_default();
                                if let Some(resp) = handler(&method, &path, &body) {
                                    return Ok(resp);
                                }
                                return Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from("not found")))
                                    .unwrap_or_else(|_| internal_error_response()));
                            }
                            // Delegate /api/correlation/* paths to the
                            // correlation engine snapshot handler. Closes
                            // #848. Sync `Fn` because the engine snapshot
                            // is non-blocking — same shape as the video
                            // catalog block above.
                            #[cfg(feature = "correlation")]
                            if req.uri().path().starts_with("/api/correlation/")
                                && let Some(handler) = correlation_api.get()
                            {
                                let method = req.method().clone();
                                let path = req.uri().path().to_string();
                                let body = http_body_util::BodyExt::collect(req.into_body())
                                    .await
                                    .map(|b| b.to_bytes())
                                    .unwrap_or_default();
                                if let Some(resp) = handler(&method, &path, &body) {
                                    return Ok(resp);
                                }
                                return Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from("not found")))
                                    .unwrap_or_else(|_| internal_error_response()));
                            }
                            // Delegate /api/packages and /api/packages/{hash}
                            // to the TAK data-package handler (#860). The
                            // handler is async (it `.await`s the on-disk
                            // package store) and bearer-token authenticated;
                            // it owns the multipart/raw-zip upload, listing,
                            // download, and delete surface. Unlike the
                            // read-only video/correlation slots, this one
                            // needs the `Authorization` and `Content-Type`
                            // headers, so both are threaded through. The
                            // handler returns its own structured
                            // 401/404/405 envelopes; a `None` here means the
                            // path fell outside the prefix, so fall through
                            // to the bare 404 like the slots above.
                            #[cfg(feature = "missions")]
                            if (req.uri().path() == "/api/packages"
                                || req.uri().path().starts_with("/api/packages/"))
                                && let Some(handler) = missions_api.get()
                            {
                                let method = req.method().clone();
                                let path = req.uri().path().to_string();
                                let auth = req
                                    .headers()
                                    .get(hyper::header::AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .map(|s| s.to_string());
                                let content_type = req
                                    .headers()
                                    .get(hyper::header::CONTENT_TYPE)
                                    .and_then(|v| v.to_str().ok())
                                    .map(|s| s.to_string());
                                let body = http_body_util::BodyExt::collect(req.into_body())
                                    .await
                                    .map(|b| b.to_bytes())
                                    .unwrap_or_default();
                                if let Some(resp) = handler(
                                    &method,
                                    &path,
                                    auth.as_deref(),
                                    content_type.as_deref(),
                                    &body,
                                )
                                .await
                                {
                                    return Ok(resp);
                                }
                                return Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from("not found")))
                                    .unwrap_or_else(|_| internal_error_response()));
                            }
                            // Delegate /api/acl/ paths to the ACL management handler
                            if req.uri().path().starts_with("/api/acl/")
                                && let Some(handler) = acl_api.get()
                            {
                                let method = req.method().clone();
                                let path = req.uri().path().to_string();
                                let auth = req
                                    .headers()
                                    .get(hyper::header::AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .map(|s| s.to_string());
                                let body = http_body_util::BodyExt::collect(req.into_body())
                                    .await
                                    .map(|b| b.to_bytes())
                                    .unwrap_or_default();
                                if let Some(resp) = handler(&method, &path, auth.as_deref(), &body)
                                {
                                    return Ok(resp);
                                }
                                return Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from("not found")))
                                    .unwrap_or_else(|_| internal_error_response()));
                            }
                            // Delegate the expanded management-API
                            // routes (closes #875) to the dedicated
                            // handler before falling through to the
                            // legacy `mgmt_api` slot. The two surfaces
                            // do not overlap: the expanded API owns
                            // bare `/api/clients`, `/api/clients/{cn}`
                            // (read-only detail), `/api/config*`,
                            // `/api/audit/verify`, `/api/version`,
                            // `/api/store-forward`, and
                            // `/api/metrics/summary`; the legacy slot
                            // continues to own `/api/clients/{cn}/disconnect`,
                            // `/api/cert/*`, `/api/dlq/*`, `/api/reload`,
                            // `/api/drain`, and `/api/v1/*`.
                            #[cfg(feature = "management-api")]
                            {
                                let path_str = req.uri().path();
                                if crate::management_api::handles_path(path_str)
                                    && let Some(handler) = management_api.get()
                                {
                                    let method = req.method().clone();
                                    let path = path_str.to_string();
                                    let auth = req
                                        .headers()
                                        .get(hyper::header::AUTHORIZATION)
                                        .and_then(|v| v.to_str().ok())
                                        .map(|s| s.to_string());
                                    if let Some(resp) =
                                        handler(&method, &path, auth.as_deref()).await
                                    {
                                        return Ok(resp);
                                    }
                                }
                            }
                            // Delegate /api/cert/, /api/crl/, /api/dedup/,
                            // /api/clients/, /api/dlq/, /api/v1/, /api/reload,
                            // and /api/drain paths to the management handler.
                            // Runs before the generic handler so unknown
                            // suffixes under these prefixes produce the
                            // handler's structured 401/404/405 envelope
                            // rather than the bare 404 below. The handler
                            // is async because disconnect/reload/drain
                            // need to `.await` on the router and reload
                            // futures. `/api/v1/` was added in #902 for
                            // versioned endpoints (`/api/v1/crl`,
                            // `/api/v1/dedup/stats`).
                            {
                                let path_str = req.uri().path();
                                if (path_str.starts_with("/api/cert/")
                                    || path_str.starts_with("/api/crl/")
                                    || path_str.starts_with("/api/dedup/")
                                    || path_str.starts_with("/api/clients/")
                                    || path_str.starts_with("/api/dlq/")
                                    || path_str.starts_with("/api/v1/")
                                    || path_str == "/api/reload"
                                    || path_str == "/api/drain")
                                    && let Some(handler) = mgmt_api.get()
                                {
                                    let method = req.method().clone();
                                    let path = path_str.to_string();
                                    let auth = req
                                        .headers()
                                        .get(hyper::header::AUTHORIZATION)
                                        .and_then(|v| v.to_str().ok())
                                        .map(|s| s.to_string());
                                    let body = http_body_util::BodyExt::collect(req.into_body())
                                        .await
                                        .map(|b| b.to_bytes())
                                        .unwrap_or_default();
                                    if let Some(resp) =
                                        handler(&method, &path, auth.as_deref(), &body).await
                                    {
                                        return Ok(resp);
                                    }
                                    return Ok(Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(Full::new(Bytes::from("not found")))
                                        .unwrap_or_else(|_| internal_error_response()));
                                }
                            }
                            // If no ACL handler is registered, fall
                            // through to the generic request handler,
                            // which returns 404 for unknown paths.
                            handle_request(req, health, readiness, metrics_token, router_slot)
                        }
                    }),
                );
            match tokio::time::timeout(HTTP_CONNECTION_TIMEOUT, conn).await {
                Ok(Err(e)) => tracing::debug!(error = %e, "metrics connection error"),
                Err(_) => tracing::debug!("metrics connection timed out"),
                Ok(Ok(())) => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    /// SEC-5: `CertReloader` now reads the key via the shared secrets gate,
    /// which rejects group/other-readable keys. Test keys must be owner-only
    /// (`0o600`) or the reloader fails with `PermissionsTooOpen`.
    fn write_key_secure(path: &std::path::Path, contents: &str) {
        std::fs::write(path, contents).expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod key 0600");
        }
    }

    #[test]
    fn internal_error_response_returns_500() {
        let resp = internal_error_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn metrics_auth_ok_rejects_missing_header() {
        assert!(!metrics_auth_ok(None, b"s3cret-token-for-metrics-test1"));
    }

    #[test]
    fn metrics_auth_ok_rejects_wrong_scheme() {
        assert!(!metrics_auth_ok(
            Some("Basic s3cret-token-for-metrics-test1"),
            b"s3cret-token-for-metrics-test1"
        ));
    }

    #[test]
    fn metrics_auth_ok_rejects_wrong_token() {
        assert!(!metrics_auth_ok(
            Some("Bearer wrong-token-value-padding-xxxx"),
            b"s3cret-token-for-metrics-test1"
        ));
    }

    #[test]
    fn metrics_auth_ok_accepts_correct_token() {
        assert!(metrics_auth_ok(
            Some("Bearer s3cret-token-for-metrics-test1"),
            b"s3cret-token-for-metrics-test1"
        ));
    }

    #[test]
    fn readiness_state_no_deps_returns_ok() {
        let state = ReadinessState::new();
        let report = state.check();
        assert_eq!(report.status, CheckStatus::Ok);
        assert!(report.checks.is_empty());
    }

    #[test]
    fn readiness_report_serializes_to_json() {
        let state = ReadinessState::new();
        let report = state.check();
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["status"], "ok");
        assert!(parsed["checks"].is_object());
    }

    #[test]
    fn aggregate_status_all_ok() {
        let checks = [DependencyCheck::ok(), DependencyCheck::ok()];
        assert_eq!(aggregate_status(checks.iter()), CheckStatus::Ok);
    }

    #[test]
    fn aggregate_status_degraded_wins_over_ok() {
        let checks = [DependencyCheck::ok(), DependencyCheck::degraded("slow")];
        assert_eq!(aggregate_status(checks.iter()), CheckStatus::Degraded);
    }

    #[test]
    fn aggregate_status_unhealthy_wins_over_degraded() {
        let checks = [
            DependencyCheck::degraded("slow"),
            DependencyCheck::unhealthy("down"),
            DependencyCheck::ok(),
        ];
        assert_eq!(aggregate_status(checks.iter()), CheckStatus::Unhealthy);
    }

    #[test]
    fn aggregate_status_empty_is_ok() {
        let checks: [DependencyCheck; 0] = [];
        assert_eq!(aggregate_status(checks.iter()), CheckStatus::Ok);
    }

    #[test]
    fn check_status_json_variants() {
        assert_eq!(
            serde_json::to_string(&CheckStatus::Ok).expect("ser"),
            "\"ok\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Degraded).expect("ser"),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Unhealthy).expect("ser"),
            "\"unhealthy\""
        );
    }

    #[test]
    fn dependency_check_ok_omits_message() {
        let check = DependencyCheck::ok();
        let json = serde_json::to_string(&check).expect("ser");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["status"], "ok");
        assert!(v.get("message").is_none());
    }

    #[test]
    fn dependency_check_degraded_includes_message() {
        let check = DependencyCheck::degraded("expiring soon");
        let json = serde_json::to_string(&check).expect("ser");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["message"], "expiring soon");
    }

    #[test]
    fn dependency_check_unhealthy_includes_message() {
        let check = DependencyCheck::unhealthy("cert expired");
        let json = serde_json::to_string(&check).expect("ser");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["status"], "unhealthy");
        assert_eq!(v["message"], "cert expired");
    }

    #[test]
    fn tls_check_with_valid_cert() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("test-ca");
        let server = ca.issue_server_cert("test-server", &["localhost"]);

        let dir = tempfile::tempdir().expect("tmpdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &server.cert_pem).expect("write cert");
        write_key_secure(&key_path, &server.key_pem);

        let reloader = rustgate_tls::CertReloader::new(&cert_path, &key_path).expect("reloader");
        let check = check_tls_cert(&reloader);
        assert_eq!(check.status, CheckStatus::Ok);
    }

    #[test]
    fn tls_check_with_expired_cert() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("test-ca");
        let expired = ca.issue_expired_client_cert("expired-server", &[]);

        let dir = tempfile::tempdir().expect("tmpdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &expired.cert_pem).expect("write cert");
        write_key_secure(&key_path, &expired.key_pem);

        let reloader = rustgate_tls::CertReloader::new(&cert_path, &key_path).expect("reloader");
        let check = check_tls_cert(&reloader);
        assert_eq!(check.status, CheckStatus::Unhealthy);
        assert!(check.message.as_deref().unwrap_or("").contains("expired"));
    }

    #[test]
    fn tls_check_degraded_for_near_expiry_cert() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("test-ca");
        // Certificate expires in 3 days — below the 7-day degraded threshold.
        let near_expiry = ca.issue_near_expiry_server_cert("expiring-server", &["localhost"], 3);

        let dir = tempfile::tempdir().expect("tmpdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &near_expiry.cert_pem).expect("write cert");
        write_key_secure(&key_path, &near_expiry.key_pem);

        let reloader = rustgate_tls::CertReloader::new(&cert_path, &key_path).expect("reloader");
        let check = check_tls_cert(&reloader);
        assert_eq!(
            check.status,
            CheckStatus::Degraded,
            "cert expiring in 3 days should be degraded, got: {:?}",
            check
        );
        let msg = check.message.as_deref().unwrap_or("");
        assert!(
            msg.contains("expires"),
            "message should mention expiry: {msg}"
        );
    }

    #[test]
    fn readiness_response_unhealthy_when_not_ready() {
        let health = HealthState::new();
        let readiness = ReadinessState::new();
        // health.is_ready() defaults to false, so readiness should be unhealthy.
        let resp = readiness_response(&health, &readiness);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn readiness_response_ok_when_ready_no_deps() {
        let health = HealthState::new();
        health.set_ready(true);
        let readiness = ReadinessState::new();
        let resp = readiness_response(&health, &readiness);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn cert_expiry_gauge_set_to_positive_remaining_seconds_for_valid_cert() {
        use rustgate_test_utils::certs::TestCa;

        let registry = prometheus::Registry::new();
        // Use a fresh registry so the test does not depend on a global init.
        // Lazily allocate the gauge for this test by calling `cert_expiry_seconds()`,
        // which falls back to an unregistered gauge when init has not been
        // called against the default registry.
        let _ = registry; // keep the local around to suppress unused warnings on some toolchains

        let ca = TestCa::new("test-ca");
        let server = ca.issue_server_cert("valid-server", &["localhost"]);

        let dir = tempfile::tempdir().expect("tmpdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &server.cert_pem).expect("write cert");
        write_key_secure(&key_path, &server.key_pem);

        let reloader = rustgate_tls::CertReloader::new(&cert_path, &key_path).expect("reloader");
        let _ = check_tls_cert(&reloader);
        assert!(
            cert_expiry_seconds().get() > 0,
            "fresh test cert must have positive remaining seconds"
        );
    }

    #[test]
    fn cert_expiry_gauge_negative_after_expired_cert_check() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("test-ca");
        let expired = ca.issue_expired_client_cert("expired-server", &[]);

        let dir = tempfile::tempdir().expect("tmpdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &expired.cert_pem).expect("write cert");
        write_key_secure(&key_path, &expired.key_pem);

        let reloader = rustgate_tls::CertReloader::new(&cert_path, &key_path).expect("reloader");
        let _ = check_tls_cert(&reloader);
        assert!(
            cert_expiry_seconds().get() < 0,
            "expired cert must drive the gauge negative for alert rules"
        );
    }

    #[test]
    fn cert_expiry_gauge_registered_under_documented_name() {
        // Use a private registry so the test is hermetic — it does not
        // depend on what other tests have registered globally.
        let registry = prometheus::Registry::new();
        register_metrics(&registry).expect("register");
        let families = registry.gather();
        let family = families
            .iter()
            .find(|mf| mf.name() == "rustgate_cert_expiry_seconds")
            .expect("rustgate_cert_expiry_seconds must be registered");
        assert_eq!(family.get_metric().len(), 1);
    }
}
