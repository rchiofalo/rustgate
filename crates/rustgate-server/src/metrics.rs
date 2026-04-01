//! Prometheus metrics for rustgate.
//!
//! Exposes counters, gauges, and labels covering connection lifecycle,
//! message routing, NATS bridge, and protocol negotiation. All metrics
//! are registered with the default Prometheus registry and served at
//! `/metrics` via a lightweight hyper HTTP server.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Opts, TextEncoder};
use rustgate_core::constants::HTTP_CONNECTION_TIMEOUT;

/// Type-erased federation API handler.
///
/// When set, the metrics server delegates requests under `/api/federation/`
/// to this handler. Returns `None` for unrecognized paths so the caller can
/// fall through to 404.
#[cfg(feature = "federation")]
pub type FedApiHandler =
    Arc<dyn Fn(&hyper::Method, &str, &[u8]) -> Option<Response<Full<Bytes>>> + Send + Sync>;

/// Maximum concurrent connections to the metrics HTTP server.
/// Bounds memory usage from connection floods against the unauthenticated
/// HTTP endpoint (the TLS listener has its own separate limit).
const MAX_HTTP_CONNECTIONS: usize = 128;

// ── Metric statics ──────────────────────────────────────────────────

static CONNECTIONS_ACCEPTED: OnceLock<IntCounter> = OnceLock::new();
static CONNECTIONS_ACTIVE: OnceLock<IntGauge> = OnceLock::new();
static CONNECTIONS_REJECTED: OnceLock<IntCounter> = OnceLock::new();
static ACCEPT_ERRORS: OnceLock<IntCounter> = OnceLock::new();

static MESSAGES_RECEIVED: OnceLock<IntCounter> = OnceLock::new();
static MESSAGES_DROPPED: OnceLock<IntCounter> = OnceLock::new();
static MESSAGES_ROUTED: OnceLock<IntCounterVec> = OnceLock::new();
static SESSIONS_ACTIVE: OnceLock<IntGauge> = OnceLock::new();

static NATS_PUBLISHES: OnceLock<IntCounter> = OnceLock::new();

static NEGOTIATIONS: OnceLock<IntCounterVec> = OnceLock::new();

// ── Fallback constructors ───────────────────────────────────────────
//
// When `init()` has not been called, accessor functions lazily create
// an unregistered metric via `OnceLock::get_or_init()`. These helpers
// construct the fallback without `unwrap()` or `expect()`.

fn fallback_counter(name: &str, help: &str) -> IntCounter {
    match IntCounter::with_opts(Opts::new(name, help)) {
        Ok(c) => c,
        // Hardcoded metric names are always valid; this branch is unreachable.
        // If prometheus is fundamentally broken, abort cleanly rather than panic.
        Err(_) => std::process::abort(),
    }
}

fn fallback_gauge(name: &str, help: &str) -> IntGauge {
    match IntGauge::with_opts(Opts::new(name, help)) {
        Ok(g) => g,
        Err(_) => std::process::abort(),
    }
}

fn fallback_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    match IntCounterVec::new(Opts::new(name, help), labels) {
        Ok(cv) => cv,
        Err(_) => std::process::abort(),
    }
}

// ── Registration ────────────────────────────────────────────────────

/// Register all metrics with the default Prometheus registry.
/// Must be called once at startup before any metrics are recorded.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let connections_accepted = IntCounter::with_opts(Opts::new(
        "rustgate_connections_accepted_total",
        "Total TLS connections accepted",
    ))?;
    registry.register(Box::new(connections_accepted.clone()))?;
    let _ = CONNECTIONS_ACCEPTED.set(connections_accepted);

    let connections_active = IntGauge::with_opts(Opts::new(
        "rustgate_connections_active",
        "Currently active TLS connections",
    ))?;
    registry.register(Box::new(connections_active.clone()))?;
    let _ = CONNECTIONS_ACTIVE.set(connections_active);

    let connections_rejected = IntCounter::with_opts(Opts::new(
        "rustgate_connections_rejected_total",
        "Connections rejected due to limit",
    ))?;
    registry.register(Box::new(connections_rejected.clone()))?;
    let _ = CONNECTIONS_REJECTED.set(connections_rejected);

    let accept_errors = IntCounter::with_opts(Opts::new(
        "rustgate_accept_errors_total",
        "TLS accept errors",
    ))?;
    registry.register(Box::new(accept_errors.clone()))?;
    let _ = ACCEPT_ERRORS.set(accept_errors);

    let messages_received = IntCounter::with_opts(Opts::new(
        "rustgate_messages_received_total",
        "Total CoT messages received from clients",
    ))?;
    registry.register(Box::new(messages_received.clone()))?;
    let _ = MESSAGES_RECEIVED.set(messages_received);

    let messages_dropped = IntCounter::with_opts(Opts::new(
        "rustgate_messages_dropped_total",
        "Messages dropped due to per-client rate limiting",
    ))?;
    registry.register(Box::new(messages_dropped.clone()))?;
    let _ = MESSAGES_DROPPED.set(messages_dropped);

    let messages_routed = IntCounterVec::new(
        Opts::new(
            "rustgate_messages_routed_total",
            "Messages routed by destination type",
        ),
        &["destination"],
    )?;
    registry.register(Box::new(messages_routed.clone()))?;
    let _ = MESSAGES_ROUTED.set(messages_routed);

    let sessions_active = IntGauge::with_opts(Opts::new(
        "rustgate_sessions_active",
        "Registered sessions in the router",
    ))?;
    registry.register(Box::new(sessions_active.clone()))?;
    let _ = SESSIONS_ACTIVE.set(sessions_active);

    let nats_publishes = IntCounter::with_opts(Opts::new(
        "rustgate_nats_publishes_total",
        "Messages published to NATS",
    ))?;
    registry.register(Box::new(nats_publishes.clone()))?;
    let _ = NATS_PUBLISHES.set(nats_publishes);

    let negotiations = IntCounterVec::new(
        Opts::new(
            "rustgate_negotiations_total",
            "Protocol negotiations by result",
        ),
        &["result"],
    )?;
    registry.register(Box::new(negotiations.clone()))?;
    let _ = NEGOTIATIONS.set(negotiations);

    Ok(())
}

// ── Accessor functions ──────────────────────────────────────────────
//
// Each accessor returns a reference to the registered metric. If
// `init()` has not been called, `get_or_init()` lazily creates an
// unregistered metric that absorbs increments without effect. This
// eliminates panics from initialization-order races without adding
// Option propagation to every call site.

pub fn connections_accepted() -> &'static IntCounter {
    CONNECTIONS_ACCEPTED
        .get_or_init(|| fallback_counter("rustgate_connections_accepted_total", "fallback"))
}

pub fn connections_active() -> &'static IntGauge {
    CONNECTIONS_ACTIVE.get_or_init(|| fallback_gauge("rustgate_connections_active", "fallback"))
}

pub fn connections_rejected() -> &'static IntCounter {
    CONNECTIONS_REJECTED
        .get_or_init(|| fallback_counter("rustgate_connections_rejected_total", "fallback"))
}

pub fn accept_errors() -> &'static IntCounter {
    ACCEPT_ERRORS.get_or_init(|| fallback_counter("rustgate_accept_errors_total", "fallback"))
}

pub fn messages_received() -> &'static IntCounter {
    MESSAGES_RECEIVED
        .get_or_init(|| fallback_counter("rustgate_messages_received_total", "fallback"))
}

pub fn messages_dropped() -> &'static IntCounter {
    MESSAGES_DROPPED.get_or_init(|| fallback_counter("rustgate_messages_dropped_total", "fallback"))
}

pub fn messages_routed() -> &'static IntCounterVec {
    MESSAGES_ROUTED.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_messages_routed_total",
            "fallback",
            &["destination"],
        )
    })
}

pub fn sessions_active() -> &'static IntGauge {
    SESSIONS_ACTIVE.get_or_init(|| fallback_gauge("rustgate_sessions_active", "fallback"))
}

pub fn nats_publishes() -> &'static IntCounter {
    NATS_PUBLISHES.get_or_init(|| fallback_counter("rustgate_nats_publishes_total", "fallback"))
}

#[allow(dead_code)] // only used when `proto` feature enables TAK negotiation
pub fn negotiations() -> &'static IntCounterVec {
    NEGOTIATIONS.get_or_init(|| {
        fallback_counter_vec("rustgate_negotiations_total", "fallback", &["result"])
    })
}

// ── HTTP server ─────────────────────────────────────────────────────

/// Fallback response when `Response::builder()` unexpectedly fails.
fn internal_error_response() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from("internal server error")));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

fn handle_request(
    req: Request<hyper::body::Incoming>,
    ready: Arc<AtomicBool>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    match req.uri().path() {
        "/healthz" => Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("ok")))
            .unwrap_or_else(|_| internal_error_response())),

        "/readyz" => {
            if ready.load(Ordering::Acquire) {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from("ok")))
                    .unwrap_or_else(|_| internal_error_response()))
            } else {
                Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Full::new(Bytes::from("not ready")))
                    .unwrap_or_else(|_| internal_error_response()))
            }
        }

        "/metrics" => {
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

/// Serve Prometheus metrics and health endpoints at the given address.
///
/// Routes:
/// - `GET /metrics` — Prometheus text format
/// - `GET /healthz` — Liveness probe (always 200)
/// - `GET /readyz`  — Readiness probe (200 when ready, 503 during shutdown)
///
/// The server is hardened against unauthenticated abuse:
/// - Connection count bounded by [`MAX_HTTP_CONNECTIONS`]
/// - Per-connection timeout of [`HTTP_CONNECTION_TIMEOUT`]
/// - Header read timeout of 5 seconds
pub async fn serve(
    bind: SocketAddr,
    ready: Arc<AtomicBool>,
    #[cfg(feature = "federation")] fed_api: Arc<OnceLock<FedApiHandler>>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_HTTP_CONNECTIONS));
    tracing::info!(addr = %bind, "metrics server started");

    loop {
        let (stream, _) = listener.accept().await?;

        let permit = match Arc::clone(&conn_limit).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                drop(stream);
                continue;
            }
        };

        let io = hyper_util::rt::TokioIo::new(stream);
        let ready = Arc::clone(&ready);
        #[cfg(feature = "federation")]
        let fed_api = Arc::clone(&fed_api);
        drop(tokio::spawn(async move {
            let _permit = permit;
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .serve_connection(
                    io,
                    service_fn(move |req: Request<hyper::body::Incoming>| {
                        let ready = Arc::clone(&ready);
                        #[cfg(feature = "federation")]
                        let fed_api = Arc::clone(&fed_api);
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
                            handle_request(req, ready)
                        }
                    }),
                );
            match tokio::time::timeout(HTTP_CONNECTION_TIMEOUT, conn).await {
                Ok(Err(e)) => tracing::debug!(error = %e, "metrics connection error"),
                Err(_) => tracing::debug!("metrics connection timed out"),
                Ok(Ok(())) => {}
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use super::*;

    static INIT: Once = Once::new();

    fn ensure_init() {
        INIT.call_once(|| {
            init().expect("metrics init failed");
        });
    }

    #[test]
    fn fallback_constructors_do_not_panic() {
        // Verify fallback helpers produce valid metrics without panicking.
        let c = super::fallback_counter("test_counter", "test");
        c.inc();
        assert_eq!(c.get(), 1);

        let g = super::fallback_gauge("test_gauge", "test");
        g.inc();
        g.dec();
        assert_eq!(g.get(), 0);

        let cv = super::fallback_counter_vec("test_vec", "test", &["label"]);
        cv.with_label_values(&["x"]).inc();
        assert_eq!(cv.with_label_values(&["x"]).get(), 1);
    }

    #[test]
    fn init_registers_all_metrics() {
        ensure_init();

        let _ = connections_accepted();
        let _ = connections_active();
        let _ = connections_rejected();
        let _ = accept_errors();
        let _ = messages_received();
        let _ = messages_routed();
        let _ = sessions_active();
        let _ = nats_publishes();
        let _ = negotiations();
    }

    #[test]
    fn counter_increments() {
        ensure_init();

        let before = connections_accepted().get();
        connections_accepted().inc();
        assert_eq!(connections_accepted().get(), before + 1);
    }

    #[test]
    fn gauge_inc_dec() {
        ensure_init();

        let before = connections_active().get();
        connections_active().inc();
        assert_eq!(connections_active().get(), before + 1);
        connections_active().dec();
        assert_eq!(connections_active().get(), before);
    }

    #[test]
    fn counter_vec_labels() {
        ensure_init();

        let before = messages_routed().with_label_values(&["broadcast"]).get();
        messages_routed().with_label_values(&["broadcast"]).inc();
        assert_eq!(
            messages_routed().with_label_values(&["broadcast"]).get(),
            before + 1
        );
    }

    #[tokio::test]
    async fn serve_health_and_metrics_endpoints() {
        ensure_init();

        let ready = Arc::new(AtomicBool::new(true));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        let server_ready = Arc::clone(&ready);
        drop(tokio::spawn(async move {
            let _ = serve(
                addr,
                server_ready,
                #[cfg(feature = "federation")]
                Arc::new(OnceLock::new()),
            )
            .await;
        }));

        tokio::time::sleep(Duration::from_millis(50)).await;

        // /healthz always returns 200
        let (status, body) = http_get(addr, "/healthz").await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok");

        // /readyz returns 200 when ready
        let (status, body) = http_get(addr, "/readyz").await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok");

        // /readyz returns 503 after marking not ready
        ready.store(false, Ordering::Release);
        let (status, body) = http_get(addr, "/readyz").await;
        assert_eq!(status, 503);
        assert_eq!(body, "not ready");

        // /metrics returns Prometheus text
        let (status, body) = http_get(addr, "/metrics").await;
        assert_eq!(status, 200);
        assert!(body.contains("rustgate_connections_accepted_total"));

        // Unknown path returns 404
        let (status, _) = http_get(addr, "/unknown").await;
        assert_eq!(status, 404);
    }

    /// Minimal HTTP GET using raw TCP. Returns (status_code, body).
    async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");

        let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.expect("write");

        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await.expect("read");
        let response = String::from_utf8_lossy(&buf);

        let status_line = response.lines().next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();

        (status, body)
    }

    #[test]
    fn internal_error_response_returns_500() {
        let resp = internal_error_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
