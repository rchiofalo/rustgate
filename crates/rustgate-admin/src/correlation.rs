// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Admin HTTP handler for the multi-sensor track correlation engine.
//!
//! Closes #848. The server binary constructs a
//! [`rustgate_correlation::CorrelationEngine`], wires its
//! [`router_callback`](rustgate_correlation::router_callback) into
//! the router's `OnRouted` slot, and registers the handler returned
//! by [`handler`] under `GET /api/correlation/fused-entities`. The
//! endpoint returns the live snapshot of fused entities as JSON.
//!
//! The handler is sync because the engine's `snapshot()` path is
//! non-blocking — it iterates the underlying DashMap and clones
//! each fused entity without any async I/O.

use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Method, Response, StatusCode};
use rustgate_correlation::CorrelationEngine;

/// Build the hyper request handler closure for
/// `GET /api/correlation/fused-entities`.
///
/// Returns `None` for any path / method that does not match so the
/// caller can fall through to the next dispatcher. The shape mirrors
/// the existing `VideoApiHandler` (sync `Fn` — the snapshot read path
/// is non-blocking).
pub fn handler(
    engine: Arc<CorrelationEngine>,
) -> impl Fn(&Method, &str, &[u8]) -> Option<Response<Full<Bytes>>> + Send + Sync + 'static {
    move |method: &Method, path: &str, _body: &[u8]| -> Option<Response<Full<Bytes>>> {
        if path != "/api/correlation/fused-entities" {
            return None;
        }
        if method != Method::GET {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("allow", "GET")
                .body(Full::new(Bytes::from("method not allowed")))
                .ok();
        }
        let snapshot = engine.snapshot();
        let body = serde_json::to_vec(&snapshot).ok()?;
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .ok()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn handler_returns_json_array() {
        use http_body_util::BodyExt;
        let engine = Arc::new(CorrelationEngine::new());
        let h = handler(Arc::clone(&engine));
        let resp =
            h(&Method::GET, "/api/correlation/fused-entities", b"").expect("handler matched");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }

    #[test]
    fn handler_returns_none_for_other_paths() {
        let engine = Arc::new(CorrelationEngine::new());
        let h = handler(engine);
        assert!(h(&Method::GET, "/api/other", b"").is_none());
    }

    #[test]
    fn handler_rejects_non_get() {
        let engine = Arc::new(CorrelationEngine::new());
        let h = handler(engine);
        let resp = h(&Method::POST, "/api/correlation/fused-entities", b"").expect("matched");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
