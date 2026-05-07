// Copyright © 2026 Roberto Chiofalo.

//! Prometheus metrics for the WebSocket transport (issue #771).
//!
//! Coverage focus is the in-crate observation surface that
//! `rustgate-server` cannot reach without a callback hop and so was
//! previously unmeasured: live connection gauge, per-direction message
//! counter, RFC 7692 `permessage-deflate` negotiation outcome counter
//! (pairs with #884), and the RFC 6455 §1.9 subprotocol selection
//! counter.
//!
//! The pre-existing `rustgate_ws_connections_total` and
//! `rustgate_ws_connections_rejected_total` in
//! `rustgate-server::metrics` (connection-attempt counters) stay in
//! the server crate so their dashboards do not break — this module is
//! purely additive on top of that surface.
//!
//! Follows the workspace `OnceLock` + `init()` + accessor pattern
//! documented in `rules/shared-infrastructure.md`. Accessors return a
//! `&'static` reference and lazily build an unregistered fallback when
//! [`init`] has not been called.
//!
//! Gated behind the `metrics` feature; the no-features build does not
//! pull in `prometheus`.

use std::sync::OnceLock;

use prometheus::{IntCounterVec, IntGauge, Opts};
use rustgate_metrics::{fallback_counter_vec, fallback_gauge};

// ── Static slots ────────────────────────────────────────────────────

static ACTIVE_CONNECTIONS: OnceLock<IntGauge> = OnceLock::new();
static MESSAGES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static COMPRESSION_NEGOTIATED_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static SUBPROTOCOL_SELECTED_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

// ── Registration ────────────────────────────────────────────────────

/// Register WebSocket crate-side metrics with the default Prometheus
/// registry.
///
/// Must be called once at startup. Returns the underlying registry
/// error on duplicate registration.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let active_connections = IntGauge::with_opts(Opts::new(
        "rustgate_ws_active_connections",
        "Live authenticated WebSocket connections currently handled by \
         the listener. Sibling of the connection-attempt counters in \
         `rustgate-server::metrics`: those count attempts, this gauge \
         is the steady-state count after handshake completion. A \
         persistent gap between successful handshakes and this gauge \
         is the operator signal that connections are dying without \
         reaching the read loop.",
    ))?;
    registry.register(Box::new(active_connections.clone()))?;
    let _ = ACTIVE_CONNECTIONS.set(active_connections);

    let messages_total = IntCounterVec::new(
        Opts::new(
            "rustgate_ws_messages_total",
            "WebSocket data messages handled by the listener, labelled \
             by `direction = in | out`. Counts text and binary frames \
             post-decompression for compressed sessions. Control frames \
             (Ping / Pong / Close) are excluded — they are not \
             observable to the application layer.",
        ),
        &["direction"],
    )?;
    registry.register(Box::new(messages_total.clone()))?;
    let _ = MESSAGES_TOTAL.set(messages_total);

    let compression_negotiated_total = IntCounterVec::new(
        Opts::new(
            "rustgate_ws_compression_negotiated_total",
            "RFC 7692 `permessage-deflate` negotiation outcomes per \
             session, labelled by `result`. The label vocabulary is \
             bounded at the call site: `enabled` (server accepted the \
             client's offer — the session has a \
             `negotiated_compression` value); `disabled` (server is \
             configured `CompressionConfig::Disabled` — operator \
             kill-switch for CRIME/BREACH-style worries — and so the \
             session-level negotiation never ran); `not_offered` \
             (server is enabled but the client either presented no \
             offer or presented an offer that did not fit the \
             operator-configured envelope, so the session reports no \
             `negotiated_compression`). Pairs with #884 — the result \
             label vocabulary tracks what that issue documents on the \
             negotiation surface.",
        ),
        &["result"],
    )?;
    registry.register(Box::new(compression_negotiated_total.clone()))?;
    let _ = COMPRESSION_NEGOTIATED_TOTAL.set(compression_negotiated_total);

    let subprotocol_selected_total = IntCounterVec::new(
        Opts::new(
            "rustgate_ws_subprotocol_selected_total",
            "RFC 6455 §1.9 subprotocol selections per handshake, \
             labelled by `subprotocol`. The label vocabulary is bounded \
             at startup by the server's configured \
             `supported_subprotocols` list; a `none` token surfaces a \
             handshake where no client offer matched the server \
             allow-list. Lenient-mode handshakes that complete without \
             a header still increment under `none` so the counter \
             aggregates the full handshake population.",
        ),
        &["subprotocol"],
    )?;
    registry.register(Box::new(subprotocol_selected_total.clone()))?;
    let _ = SUBPROTOCOL_SELECTED_TOTAL.set(subprotocol_selected_total);

    Ok(())
}

// ── Accessors ───────────────────────────────────────────────────────

/// Live authenticated WebSocket connections gauge.
pub fn active_connections() -> &'static IntGauge {
    ACTIVE_CONNECTIONS.get_or_init(|| fallback_gauge("rustgate_ws_active_connections", "fallback"))
}

/// Per-direction message counter.
pub fn messages_total() -> &'static IntCounterVec {
    MESSAGES_TOTAL.get_or_init(|| {
        fallback_counter_vec("rustgate_ws_messages_total", "fallback", &["direction"])
    })
}

/// RFC 7692 compression-negotiation outcome counter.
pub fn compression_negotiated_total() -> &'static IntCounterVec {
    COMPRESSION_NEGOTIATED_TOTAL.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_ws_compression_negotiated_total",
            "fallback",
            &["result"],
        )
    })
}

/// Subprotocol-selection counter.
pub fn subprotocol_selected_total() -> &'static IntCounterVec {
    SUBPROTOCOL_SELECTED_TOTAL.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_ws_subprotocol_selected_total",
            "fallback",
            &["subprotocol"],
        )
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accessors_work_without_init() {
        let _ = active_connections();
        let _ = messages_total();
        let _ = compression_negotiated_total();
        let _ = subprotocol_selected_total();
    }

    #[test]
    fn active_connections_inc_dec_round_trip() {
        let g = active_connections();
        let before = g.get();
        g.inc();
        assert_eq!(g.get(), before + 1);
        g.dec();
        assert_eq!(g.get(), before);
    }

    #[test]
    fn messages_total_in_label_independent_of_out_label() {
        let counter = messages_total();
        let in_c = counter
            .get_metric_with_label_values(&["in"])
            .expect("in label");
        let out_c = counter
            .get_metric_with_label_values(&["out"])
            .expect("out label");
        let in_before = in_c.get();
        let out_before = out_c.get();
        in_c.inc();
        // in moves but out stays put.
        assert_eq!(in_c.get(), in_before + 1);
        assert_eq!(out_c.get(), out_before);
    }

    #[test]
    fn compression_negotiated_increments_per_outcome() {
        let counter = compression_negotiated_total();
        for outcome in &["enabled", "disabled", "not_offered"] {
            if let Ok(child) = counter.get_metric_with_label_values(&[outcome]) {
                child.inc();
                assert!(child.get() >= 1);
            }
        }
    }

    #[test]
    fn subprotocol_selected_increments_for_known_label() {
        let counter = subprotocol_selected_total();
        if let Ok(child) = counter.get_metric_with_label_values(&["none"]) {
            child.inc();
            assert!(child.get() >= 1);
        }
    }

    #[test]
    fn accessors_return_same_static_instance() {
        assert!(std::ptr::eq(active_connections(), active_connections()));
        assert!(std::ptr::eq(messages_total(), messages_total()));
        assert!(std::ptr::eq(
            compression_negotiated_total(),
            compression_negotiated_total()
        ));
        assert!(std::ptr::eq(
            subprotocol_selected_total(),
            subprotocol_selected_total()
        ));
    }
}
