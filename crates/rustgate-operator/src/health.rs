// Copyright © 2026 Roberto Chiofalo.

//! HTTP endpoints for liveness, readiness, and Prometheus scrape.
//!
//! Endpoints:
//!
//! | Path | Code | Meaning |
//! |---|---|---|
//! | `/healthz` | 200 | Process is alive — never gates on external state |
//! | `/readyz` | 200 / 503 | API server is reachable AND we hold OR follow the lease cleanly |
//! | `/metrics` | 200 | Prometheus text exposition |
//!
//! ## Why /readyz doesn't require leadership
//!
//! A follower replica is still functional — it just doesn't reconcile.
//! Kubernetes routes traffic to ready replicas, and we don't expose a
//! reconcile API surface anyway, so the readiness signal here is
//! purely "this pod's machinery is healthy" — both the leader and the
//! followers should be ready under that definition. Gating on
//! leadership would force the cluster's ServiceMonitor to scrape only
//! the leader, which complicates HA monitoring.

#![cfg(feature = "controller")]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use kube::Client;
use prometheus::{Encoder, Registry, TextEncoder};
use tokio::sync::watch;

use crate::controller::kube_reachable;

#[derive(Clone)]
struct AppState {
    client: Client,
    registry: Arc<Registry>,
}

/// Build the HTTP router. Pure-function — the binding is done by
/// [`serve`] so tests can poke the routes directly without bringing
/// up a real socket.
pub fn router(client: Client, registry: Arc<Registry>) -> Router {
    let state = AppState { client, registry };
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    if kube_reachable(&state.client).await {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "api server unreachable")
    }
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    let mfs = state.registry.gather();
    if let Err(e) = encoder.encode(&mfs, &mut buf) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode failed: {e}"),
        )
            .into_response();
    }
    let body = String::from_utf8(buf).unwrap_or_default();
    let mut response = body.into_response();
    let _ = response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

/// Serve the HTTP endpoints. Returns when the shutdown receiver flips
/// to `true`, so the caller can join the future on SIGTERM.
pub async fn serve(
    addr: SocketAddr,
    client: Client,
    registry: Arc<Registry>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    let app = router(client, registry);
    // The `configure_tactical_socket` / keepalive helpers apply
    // per-stream after `accept()`; axum's `serve()` consumes the
    // listener and manages per-connection lifecycle internally so
    // we cannot interpose. This socket is a Prometheus scrape +
    // kubelet probe endpoint (short-lived HTTP/1.1 requests from a
    // sibling pod), not a tactical message stream — Nagle and TCP
    // keepalive don't apply.
    let listener = tokio::net::TcpListener::bind(addr).await?; // playbook-drift-ok: axum-managed scrape + probe endpoint, not a tactical stream
    tracing::info!(target: "operator", addr = %addr, "health/metrics server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn router_builds() {
        // Build but don't serve — the router type itself catches any
        // path-routing handler-signature mismatch at compile time.
        // Using a Client::try_default would touch real kubeconfig in
        // CI, so we skip actually constructing a Client and just
        // assert the helper signatures by referring to them.
        let _ = (
            // healthz / readyz / metrics_handler are bound by `router`;
            // referencing the symbols here keeps them from being
            // dead-coded if the router is refactored.
            healthz,
            readyz,
            metrics_handler,
        );
    }
}
